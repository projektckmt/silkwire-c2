//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// captureWebcamPhotoImpl captures a photo from webcam on Unix-like systems
func captureWebcamPhotoImpl() ([]byte, error) {
	switch runtime.GOOS {
	case "linux":
		return captureWebcamPhotoLinux()
	case "darwin":
		return captureWebcamPhotoMacOS()
	default:
		return nil, fmt.Errorf("webcam capture not supported on %s", runtime.GOOS)
	}
}

// captureWebcamVideoImpl captures video from webcam on Unix-like systems
func captureWebcamVideoImpl(durationSec int) ([]byte, error) {
	switch runtime.GOOS {
	case "linux":
		return captureWebcamVideoLinux(durationSec)
	case "darwin":
		return captureWebcamVideoMacOS(durationSec)
	default:
		return nil, fmt.Errorf("webcam capture not supported on %s", runtime.GOOS)
	}
}

// captureWebcamPhotoLinux captures a photo on Linux using ffmpeg or fswebcam
func captureWebcamPhotoLinux() ([]byte, error) {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("webcam_%d.jpg", time.Now().Unix()))
	defer os.Remove(tempFile)

	// Try ffmpeg first
	cmd := exec.Command("ffmpeg",
		"-f", "v4l2",            // Video4Linux2
		"-i", "/dev/video0",     // Default video device
		"-frames:v", "1",        // Capture 1 frame
		"-y",                    // Overwrite
		tempFile,
	)

	err := cmd.Run()
	if err == nil {
		data, err := os.ReadFile(tempFile)
		if err == nil {
			return data, nil
		}
	}

	// Fallback: try fswebcam
	cmd = exec.Command("fswebcam",
		"-r", "640x480",         // Resolution
		"--no-banner",           // No banner
		"--jpeg", "85",          // JPEG quality
		tempFile,
	)

	err = cmd.Run()
	if err == nil {
		data, err := os.ReadFile(tempFile)
		if err == nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("failed to capture webcam photo (tried ffmpeg, fswebcam)")
}

// captureWebcamVideoLinux captures video on Linux using ffmpeg
func captureWebcamVideoLinux(durationSec int) ([]byte, error) {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("webcam_%d.mp4", time.Now().Unix()))
	defer os.Remove(tempFile)

	cmd := exec.Command("ffmpeg",
		"-f", "v4l2",            // Video4Linux2
		"-i", "/dev/video0",     // Default video device
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

	data, err := os.ReadFile(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read captured video: %v", err)
	}

	return data, nil
}

// captureWebcamPhotoMacOS captures a photo on macOS using imagesnap or ffmpeg
func captureWebcamPhotoMacOS() ([]byte, error) {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("webcam_%d.jpg", time.Now().Unix()))
	defer os.Remove(tempFile)

	// Try imagesnap first (Mac-specific tool)
	cmd := exec.Command("imagesnap", "-w", "1", tempFile)
	err := cmd.Run()
	if err == nil {
		data, err := os.ReadFile(tempFile)
		if err == nil {
			return data, nil
		}
	}

	// Fallback: try ffmpeg with avfoundation
	cmd = exec.Command("ffmpeg",
		"-f", "avfoundation",    // macOS AVFoundation
		"-i", "0",               // First video device
		"-frames:v", "1",        // Capture 1 frame
		"-y",                    // Overwrite
		tempFile,
	)

	err = cmd.Run()
	if err == nil {
		data, err := os.ReadFile(tempFile)
		if err == nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("failed to capture webcam photo (tried imagesnap, ffmpeg)")
}

// captureWebcamVideoMacOS captures video on macOS using ffmpeg
func captureWebcamVideoMacOS(durationSec int) ([]byte, error) {
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("webcam_%d.mp4", time.Now().Unix()))
	defer os.Remove(tempFile)

	cmd := exec.Command("ffmpeg",
		"-f", "avfoundation",    // macOS AVFoundation
		"-i", "0",               // First video device
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

	data, err := os.ReadFile(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read captured video: %v", err)
	}

	return data, nil
}
