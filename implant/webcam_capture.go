// webcam_capture.go - Cross-platform webcam capture
package main

import (
	"encoding/base64"
	"fmt"
	"time"
)

// CaptureWebcam captures from the webcam (photo or video)
func CaptureWebcam(durationSec int, format string) (string, error) {
	if format == "" {
		format = "photo"
	}

	if format != "photo" && format != "video" {
		return "", fmt.Errorf("invalid format: %s (must be 'photo' or 'video')", format)
	}

	if durationSec <= 0 {
		if format == "photo" {
			durationSec = 0 // Instant capture
		} else {
			durationSec = 5 // Default 5 seconds for video
		}
	}

	if durationSec > 300 {
		durationSec = 300 // Max 5 minutes
	}

	logDebug(fmt.Sprintf("Starting webcam capture: format=%s, duration=%ds", format, durationSec))

	startTime := time.Now()
	var data []byte
	var err error
	var mimeType string

	if format == "photo" {
		data, err = platformCaptureWebcamPhoto()
		mimeType = "image/jpeg"
	} else {
		data, err = platformCaptureWebcamVideo(durationSec)
		mimeType = "video/mp4"
	}

	if err != nil {
		return "", fmt.Errorf("failed to capture from webcam: %v", err)
	}

	duration := time.Since(startTime)

	// Encode to base64
	base64Data := base64.StdEncoding.EncodeToString(data)

	// Return metadata and base64 data
	result := fmt.Sprintf(`{
  "status": "success",
  "timestamp": "%s",
  "capture_type": "%s",
  "mime_type": "%s",
  "duration_seconds": %d,
  "data_size_bytes": %d,
  "capture_duration_ms": %d,
  "data": "%s"
}`,
		time.Now().Format(time.RFC3339),
		format,
		mimeType,
		durationSec,
		len(data),
		duration.Milliseconds(),
		base64Data,
	)

	logDebug(fmt.Sprintf("Webcam capture complete: %d bytes, took %dms", len(data), duration.Milliseconds()))

	return result, nil
}

// Platform-specific functions implemented in separate files
func platformCaptureWebcamPhoto() ([]byte, error) {
	return captureWebcamPhotoImpl()
}

func platformCaptureWebcamVideo(durationSec int) ([]byte, error) {
	return captureWebcamVideoImpl(durationSec)
}
