// screenshot.go - Cross-platform screenshot capture using github.com/kbinani/screenshot
package main

import (
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kbinani/screenshot"
)

// CaptureScreenshot captures a screenshot and saves it to a file, returning the file path
func CaptureScreenshot() (string, error) {
	logDebug("Capturing screenshot...")

	startTime := time.Now()

	// Get the number of active displays
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return "", fmt.Errorf("no active displays found")
	}

	// Capture the primary display (display 0)
	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %v", err)
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	var screenshotPath string

	if runtime.GOOS == "windows" {
		screenshotPath = filepath.Join(os.Getenv("TEMP"), fmt.Sprintf("screenshot_%s.png", timestamp))
	} else {
		screenshotPath = filepath.Join("/tmp", fmt.Sprintf("screenshot_%s.png", timestamp))
	}

	// Create and save the file
	file, err := os.Create(screenshotPath)
	if err != nil {
		return "", fmt.Errorf("failed to create screenshot file: %v", err)
	}
	defer file.Close()

	// Encode to PNG
	err = png.Encode(file, img)
	if err != nil {
		os.Remove(screenshotPath)
		return "", fmt.Errorf("failed to encode screenshot: %v", err)
	}

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %v", err)
	}

	duration := time.Since(startTime)

	// Create result structure for proper JSON encoding
	resultData := struct {
		Status            string `json:"status"`
		Timestamp         string `json:"timestamp"`
		ImageFormat       string `json:"image_format"`
		ImageSizeBytes    int64  `json:"image_size_bytes"`
		CaptureDurationMs int64  `json:"capture_duration_ms"`
		Dimensions        struct {
			Width  int `json:"width"`
			Height int `json:"height"`
		} `json:"dimensions"`
		FilePath      string `json:"file_path"`
		DisplayCount  int    `json:"display_count"`
		DisplayBounds string `json:"display_bounds"`
	}{
		Status:            "success",
		Timestamp:         time.Now().Format(time.RFC3339),
		ImageFormat:       "png",
		ImageSizeBytes:    fileInfo.Size(),
		CaptureDurationMs: duration.Milliseconds(),
		FilePath:          screenshotPath,
		DisplayCount:      n,
		DisplayBounds:     fmt.Sprintf("%v", bounds),
	}
	resultData.Dimensions.Width = img.Bounds().Dx()
	resultData.Dimensions.Height = img.Bounds().Dy()

	// Marshal to JSON with proper escaping
	resultJSON, err := json.MarshalIndent(resultData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %v", err)
	}

	logDebug(fmt.Sprintf("Screenshot saved: %dx%d, %d bytes, took %dms, path: %s",
		img.Bounds().Dx(), img.Bounds().Dy(), fileInfo.Size(), duration.Milliseconds(), screenshotPath))

	return string(resultJSON), nil
}
