//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	user32Clipboard               = syscall.NewLazyDLL("user32.dll")
	kernel32Clipboard             = syscall.NewLazyDLL("kernel32.dll")
	openClipboard        = user32Clipboard.NewProc("OpenClipboard")
	closeClipboard       = user32Clipboard.NewProc("CloseClipboard")
	getClipboardData     = user32Clipboard.NewProc("GetClipboardData")
	globalLock           = kernel32Clipboard.NewProc("GlobalLock")
	globalUnlock         = kernel32Clipboard.NewProc("GlobalUnlock")
	isClipboardFormatAvailable = user32Clipboard.NewProc("IsClipboardFormatAvailable")
)

const (
	CF_TEXT = 1
	CF_UNICODETEXT = 13
)

// getClipboardContent retrieves the current clipboard text content on Windows
func getClipboardContent() (string, error) {
	// Open clipboard
	r1, _, err := openClipboard.Call(0)
	if r1 == 0 {
		return "", fmt.Errorf("failed to open clipboard: %v", err)
	}
	defer closeClipboard.Call()

	// Check if unicode text is available
	r1, _, _ = isClipboardFormatAvailable.Call(CF_UNICODETEXT)
	if r1 == 0 {
		// Try ASCII text
		r1, _, _ = isClipboardFormatAvailable.Call(CF_TEXT)
		if r1 == 0 {
			return "", nil // No text in clipboard
		}
		return getClipboardASCII()
	}

	return getClipboardUnicode()
}

func getClipboardUnicode() (string, error) {
	// Get clipboard data handle
	hMem, _, err := getClipboardData.Call(CF_UNICODETEXT)
	if hMem == 0 {
		return "", fmt.Errorf("failed to get clipboard data: %v", err)
	}

	// Lock memory
	pMem, _, err := globalLock.Call(hMem)
	if pMem == 0 {
		return "", fmt.Errorf("failed to lock global memory: %v", err)
	}
	defer globalUnlock.Call(hMem)

	// Convert to Go string
	text := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(pMem))[:])
	return text, nil
}

func getClipboardASCII() (string, error) {
	// Get clipboard data handle
	hMem, _, err := getClipboardData.Call(CF_TEXT)
	if hMem == 0 {
		return "", fmt.Errorf("failed to get clipboard data: %v", err)
	}

	// Lock memory
	pMem, _, err := globalLock.Call(hMem)
	if pMem == 0 {
		return "", fmt.Errorf("failed to lock global memory: %v", err)
	}
	defer globalUnlock.Call(hMem)

	// Convert to Go string
	text := ""
	ptr := (*byte)(unsafe.Pointer(pMem))
	for i := 0; ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)))
		if b == 0 {
			break
		}
		text += string(b)
	}
	return text, nil
}
