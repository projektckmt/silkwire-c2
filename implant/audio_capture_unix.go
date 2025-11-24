//go:build !windows
// +build !windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"runtime"
)

// captureAudioPlatform captures audio on Unix-like systems
func captureAudioPlatform(durationSec int) ([]byte, int, error) {
	switch runtime.GOOS {
	case "linux":
		return captureAudioLinux(durationSec)
	case "darwin":
		return captureAudioMacOS(durationSec)
	default:
		return nil, 0, fmt.Errorf("audio capture not supported on %s", runtime.GOOS)
	}
}

// captureAudioLinux captures audio on Linux using arecord or sox
func captureAudioLinux(durationSec int) ([]byte, int, error) {
	const sampleRate = 44100

	// Try arecord (ALSA)
	cmd := exec.Command("arecord",
		"-f", "S16_LE",          // 16-bit signed little-endian
		"-c", "1",               // Mono
		"-r", "44100",           // 44.1kHz sample rate
		"-d", fmt.Sprintf("%d", durationSec), // Duration
		"-t", "wav",             // WAV format
		"-",                     // Output to stdout
	)

	output, err := cmd.Output()
	if err == nil {
		return output, sampleRate, nil
	}

	// Fallback: try sox
	cmd = exec.Command("sox",
		"-d",                    // Default input device
		"-t", "wav",             // Output format
		"-r", "44100",           // Sample rate
		"-c", "1",               // Channels
		"-b", "16",              // Bit depth
		"-",                     // Output to stdout
		"trim", "0", fmt.Sprintf("%d", durationSec),
	)

	output, err = cmd.Output()
	if err == nil {
		return output, sampleRate, nil
	}

	// Fallback: try ffmpeg
	cmd = exec.Command("ffmpeg",
		"-f", "alsa",            // ALSA input
		"-i", "default",         // Default device
		"-t", fmt.Sprintf("%d", durationSec), // Duration
		"-f", "wav",             // Output format
		"-ar", "44100",          // Sample rate
		"-ac", "1",              // Mono
		"-",                     // Output to stdout
	)

	output, err = cmd.Output()
	if err == nil {
		return output, sampleRate, nil
	}

	return nil, 0, fmt.Errorf("no audio capture tool available (tried arecord, sox, ffmpeg)")
}

// captureAudioMacOS captures audio on macOS using sox or ffmpeg
func captureAudioMacOS(durationSec int) ([]byte, int, error) {
	const sampleRate = 44100

	// Try sox first
	cmd := exec.Command("sox",
		"-d",                    // Default input device
		"-t", "wav",             // Output format
		"-r", "44100",           // Sample rate
		"-c", "1",               // Channels
		"-b", "16",              // Bit depth
		"-",                     // Output to stdout
		"trim", "0", fmt.Sprintf("%d", durationSec),
	)

	output, err := cmd.Output()
	if err == nil {
		return output, sampleRate, nil
	}

	// Fallback: try ffmpeg with avfoundation
	cmd = exec.Command("ffmpeg",
		"-f", "avfoundation",    // macOS audio framework
		"-i", ":0",              // Default audio device
		"-t", fmt.Sprintf("%d", durationSec), // Duration
		"-f", "wav",             // Output format
		"-ar", "44100",          // Sample rate
		"-ac", "1",              // Mono
		"-",                     // Output to stdout
	)

	output, err = cmd.Output()
	if err == nil {
		return output, sampleRate, nil
	}

	return nil, 0, fmt.Errorf("no audio capture tool available (tried sox, ffmpeg)")
}

// createWAVFile creates a proper WAV file with headers (duplicate from Windows for compilation)
func createWAVFileUnix(pcmData []byte, sampleRate, channels, bitsPerSample int) []byte {
	var buf bytes.Buffer

	dataSize := len(pcmData)
	fileSize := 36 + dataSize

	// RIFF header
	buf.WriteString("RIFF")
	binary.Write(&buf, binary.LittleEndian, uint32(fileSize))
	buf.WriteString("WAVE")

	// fmt chunk
	buf.WriteString("fmt ")
	binary.Write(&buf, binary.LittleEndian, uint32(16)) // Chunk size
	binary.Write(&buf, binary.LittleEndian, uint16(1))  // Audio format (PCM)
	binary.Write(&buf, binary.LittleEndian, uint16(channels))
	binary.Write(&buf, binary.LittleEndian, uint32(sampleRate))
	binary.Write(&buf, binary.LittleEndian, uint32(sampleRate*channels*bitsPerSample/8)) // Byte rate
	binary.Write(&buf, binary.LittleEndian, uint16(channels*bitsPerSample/8))            // Block align
	binary.Write(&buf, binary.LittleEndian, uint16(bitsPerSample))

	// data chunk
	buf.WriteString("data")
	binary.Write(&buf, binary.LittleEndian, uint32(dataSize))
	buf.Write(pcmData)

	return buf.Bytes()
}
