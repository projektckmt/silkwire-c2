//go:build !windows
// +build !windows

package main

// init is called automatically before main()
// On non-Windows platforms, no special stealth initialization is needed
func init() {
	// No-op on Unix-like systems
	// Unix processes are already "backgrounded" if run with & or nohup
}

// SetProcessPriority is a no-op on non-Windows platforms
func SetProcessPriority() error {
	// Unix: use nice/renice or setpriority syscall if needed
	return nil
}

// EnableDebugPrivilege is a no-op on non-Windows platforms
func EnableDebugPrivilege() error {
	// Unix: requires root or CAP_SYS_PTRACE capability
	return nil
}
