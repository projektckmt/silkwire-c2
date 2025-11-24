//go:build !windows
// +build !windows

package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// getClipboardContent retrieves the current clipboard text content on Unix-like systems
func getClipboardContent() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getClipboardLinux()
	case "darwin":
		return getClipboardMacOS()
	default:
		return "", fmt.Errorf("clipboard monitoring not supported on %s", runtime.GOOS)
	}
}

// getClipboardLinux retrieves clipboard content on Linux using xclip or xsel
func getClipboardLinux() (string, error) {
	// Try xclip first
	cmd := exec.Command("xclip", "-selection", "clipboard", "-o")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err == nil {
		return strings.TrimSpace(out.String()), nil
	}

	// Try xsel as fallback
	cmd = exec.Command("xsel", "--clipboard", "--output")
	out.Reset()
	cmd.Stdout = &out
	err = cmd.Run()
	if err == nil {
		return strings.TrimSpace(out.String()), nil
	}

	// Try wl-paste for Wayland
	cmd = exec.Command("wl-paste")
	out.Reset()
	cmd.Stdout = &out
	err = cmd.Run()
	if err == nil {
		return strings.TrimSpace(out.String()), nil
	}

	return "", fmt.Errorf("no clipboard tool available (xclip, xsel, or wl-paste required)")
}

// getClipboardMacOS retrieves clipboard content on macOS using pbpaste
func getClipboardMacOS() (string, error) {
	cmd := exec.Command("pbpaste")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to get clipboard content: %v", err)
	}
	return strings.TrimSpace(out.String()), nil
}
