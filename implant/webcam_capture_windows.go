//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// captureWebcamPhotoImpl captures a photo from webcam on Windows
func captureWebcamPhotoImpl() ([]byte, error) {
	// Use ffmpeg to capture from DirectShow device
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("webcam_%d.jpg", time.Now().Unix()))
	defer os.Remove(tempFile)

	// Try ffmpeg first
	cmd := exec.Command("ffmpeg",
		"-f", "dshow",           // DirectShow (Windows)
		"-i", "video=0",         // First video device
		"-frames:v", "1",        // Capture 1 frame
		"-y",                    // Overwrite
		tempFile,
	)

	err := cmd.Run()
	if err != nil {
		// Fallback: try with specific device listing
		return captureWebcamWithDeviceList()
	}

	// Read captured image
	data, err := os.ReadFile(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read captured image: %v", err)
	}

	return data, nil
}

// captureWebcamVideoImpl captures video from webcam on Windows
func captureWebcamVideoImpl(durationSec int) ([]byte, error) {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("webcam_%d.mp4", time.Now().Unix()))
	defer os.Remove(tempFile)

	// Use ffmpeg to capture video
	cmd := exec.Command("ffmpeg",
		"-f", "dshow",           // DirectShow (Windows)
		"-i", "video=0",         // First video device
		"-t", fmt.Sprintf("%d", durationSec), // Duration
		"-vcodec", "libx264",    // H.264 codec
		"-preset", "ultrafast",  // Fast encoding
		"-y",                    // Overwrite
		tempFile,
	)

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to capture video: %v (is ffmpeg installed?)", err)
	}

	// Read captured video
	data, err := os.ReadFile(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read captured video: %v", err)
	}

	return data, nil
}

// captureWebcamWithDeviceList tries to capture with automatic device detection
func captureWebcamWithDeviceList() ([]byte, error) {
	// List available devices
	cmd := exec.Command("ffmpeg", "-list_devices", "true", "-f", "dshow", "-i", "dummy")
	output, _ := cmd.CombinedOutput()
	
	logDebug(fmt.Sprintf("DirectShow devices: %s", string(output)))

	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("webcam_%d.jpg", time.Now().Unix()))
	defer os.Remove(tempFile)

	// Try common device names
	deviceNames := []string{
		"Integrated Camera",
		"USB Camera",
		"HD Webcam",
		"Webcam",
	}

	for _, deviceName := range deviceNames {
		cmd := exec.Command("ffmpeg",
			"-f", "dshow",
			"-i", fmt.Sprintf("video=%s", deviceName),
			"-frames:v", "1",
			"-y",
			tempFile,
		)

		err := cmd.Run()
		if err == nil {
			data, err := os.ReadFile(tempFile)
			if err == nil {
				return data, nil
			}
		}
	}

	return nil, fmt.Errorf("no webcam device found or ffmpeg not installed")
}
