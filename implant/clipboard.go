// clipboard.go - Cross-platform clipboard monitoring
package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"
)

// ClipboardEntry represents a captured clipboard entry
type ClipboardEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Content   string    `json:"content"`
	Format    string    `json:"format"`
}

// MonitorClipboard monitors clipboard for the specified duration and returns captured data
func MonitorClipboard(durationSec int) (string, error) {
	if durationSec <= 0 {
		durationSec = 30 // Default 30 seconds
	}

	entries := []ClipboardEntry{}
	lastContent := ""
	
	startTime := time.Now()
	endTime := startTime.Add(time.Duration(durationSec) * time.Second)

	logDebug(fmt.Sprintf("Starting clipboard monitoring for %d seconds on %s", durationSec, runtime.GOOS))

	for time.Now().Before(endTime) {
		content, err := getClipboardContent()
		if err != nil {
			// Continue monitoring even if one read fails
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// Only record if content changed
		if content != lastContent && content != "" {
			entry := ClipboardEntry{
				Timestamp: time.Now(),
				Content:   content,
				Format:    "text",
			}
			entries = append(entries, entry)
			lastContent = content
			logDebug(fmt.Sprintf("Clipboard change detected: %d chars", len(content)))
		}

		time.Sleep(500 * time.Millisecond) // Check every 500ms
	}

	// Return results as JSON
	if len(entries) == 0 {
		return "No clipboard changes detected during monitoring period", nil
	}

	result := map[string]interface{}{
		"entries":      entries,
		"total_count":  len(entries),
		"duration_sec": durationSec,
		"platform":     runtime.GOOS,
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal clipboard data: %v", err)
	}

	return string(jsonData), nil
}

// GetCurrentClipboard returns the current clipboard content
func GetCurrentClipboard() (string, error) {
	content, err := getClipboardContent()
	if err != nil {
		return "", err
	}

	result := map[string]interface{}{
		"timestamp": time.Now(),
		"content":   content,
		"format":    "text",
		"platform":  runtime.GOOS,
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal clipboard data: %v", err)
	}

	return string(jsonData), nil
}
