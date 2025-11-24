//go:build !windows
// +build !windows

package main

// checkWindowsUserActivity stub for non-Windows platforms
func checkWindowsUserActivity() bool {
	// On non-Windows platforms, assume user activity
	return true
}
