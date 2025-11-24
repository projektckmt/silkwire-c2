//go:build windows
// +build windows

package main

import (
	"syscall"
	"unsafe"
)

// checkWindowsUserActivity checks for user activity on Windows
func checkWindowsUserActivity() bool {
	// Use GetLastInputInfo API to check for recent user input
	kernel32 := syscall.NewLazyDLL(deobfStr("kernel32"))
	user32 := syscall.NewLazyDLL("user32.dll")

	getTickCount := kernel32.NewProc("GetTickCount")
	getLastInputInfo := user32.NewProc("GetLastInputInfo")

	type LASTINPUTINFO struct {
		cbSize uint32
		dwTime uint32
	}

	var lii LASTINPUTINFO
	lii.cbSize = uint32(unsafe.Sizeof(lii))

	// Get current tick count
	currentTick, _, _ := getTickCount.Call()

	// Get last input info
	ret, _, _ := getLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if ret == 0 {
		return false // API call failed
	}

	// Check if input was recent (within last 30 seconds)
	timeSinceLastInput := uint32(currentTick) - lii.dwTime
	recentInputThreshold := uint32(30 * 1000) // 30 seconds in milliseconds

	return timeSinceLastInput < recentInputThreshold
}
