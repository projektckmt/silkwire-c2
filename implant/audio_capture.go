// audio_capture.go - Cross-platform audio capture from microphone
package main

import (
	"encoding/base64"
	"fmt"
	"time"
)

// CaptureAudio records audio from the microphone for the specified duration
func CaptureAudio(durationSec int) (string, error) {
	if durationSec <= 0 {
		durationSec = 5 // Default 5 seconds
	}

	if durationSec > 300 {
		durationSec = 300 // Max 5 minutes to prevent huge files
	}

	logDebug(fmt.Sprintf("Starting audio capture for %d seconds", durationSec))
	
	startTime := time.Now()
	audioData, sampleRate, err := platformCaptureAudio(durationSec)
	if err != nil {
		return "", fmt.Errorf("failed to capture audio: %v", err)
	}

	duration := time.Since(startTime)

	// Encode to base64
	base64Audio := base64.StdEncoding.EncodeToString(audioData)

	// Return metadata and base64 audio
	result := fmt.Sprintf(`{
  "status": "success",
  "timestamp": "%s",
  "audio_format": "wav",
  "duration_seconds": %d,
  "sample_rate": %d,
  "audio_size_bytes": %d,
  "capture_duration_ms": %d,
  "audio_data": "%s"
}`,
		time.Now().Format(time.RFC3339),
		durationSec,
		sampleRate,
		len(audioData),
		duration.Milliseconds(),
		base64Audio,
	)

	logDebug(fmt.Sprintf("Audio captured: %d bytes, %d Hz, took %dms",
		len(audioData), sampleRate, duration.Milliseconds()))

	return result, nil
}

// platformCaptureAudio is implemented in platform-specific files
// Returns: audio data (WAV format), sample rate, error
func platformCaptureAudio(durationSec int) ([]byte, int, error) {
	return captureAudioPlatform(durationSec)
}
