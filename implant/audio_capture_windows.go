//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	winmm              = syscall.NewLazyDLL("winmm.dll")
	waveInOpen         = winmm.NewProc("waveInOpen")
	waveInPrepareHeader = winmm.NewProc("waveInPrepareHeader")
	waveInAddBuffer    = winmm.NewProc("waveInAddBuffer")
	waveInStart        = winmm.NewProc("waveInStart")
	waveInStop         = winmm.NewProc("waveInStop")
	waveInUnprepareHeader = winmm.NewProc("waveInUnprepareHeader")
	waveInClose        = winmm.NewProc("waveInClose")
	waveInReset        = winmm.NewProc("waveInReset")
)

const (
	WAVE_FORMAT_PCM = 1
	WAVE_MAPPER     = 0xFFFFFFFF
)

type WAVEFORMATEX struct {
	WFormatTag      uint16
	NChannels       uint16
	NSamplesPerSec  uint32
	NAvgBytesPerSec uint32
	NBlockAlign     uint16
	WBitsPerSample  uint16
	CbSize          uint16
}

type WAVEHDR struct {
	LpData          uintptr
	DwBufferLength  uint32
	DwBytesRecorded uint32
	DwUser          uintptr
	DwFlags         uint32
	DwLoops         uint32
	LpNext          uintptr
	Reserved        uintptr
}

// captureAudioPlatform captures audio on Windows using WaveIn API
func captureAudioPlatform(durationSec int) ([]byte, int, error) {
	const (
		sampleRate   = 44100
		channels     = 1 // Mono
		bitsPerSample = 16
	)

	// Setup wave format
	waveFormat := WAVEFORMATEX{
		WFormatTag:      WAVE_FORMAT_PCM,
		NChannels:       channels,
		NSamplesPerSec:  sampleRate,
		NAvgBytesPerSec: sampleRate * channels * bitsPerSample / 8,
		NBlockAlign:     channels * bitsPerSample / 8,
		WBitsPerSample:  bitsPerSample,
		CbSize:          0,
	}

	// Open wave input device
	var hWaveIn uintptr
	ret, _, _ := waveInOpen.Call(
		uintptr(unsafe.Pointer(&hWaveIn)),
		WAVE_MAPPER,
		uintptr(unsafe.Pointer(&waveFormat)),
		0,
		0,
		0,
	)

	if ret != 0 {
		return nil, 0, fmt.Errorf("waveInOpen failed with code %d", ret)
	}
	defer waveInClose.Call(hWaveIn)

	// Calculate buffer size (1 second chunks)
	bufferSize := int(sampleRate * channels * bitsPerSample / 8)
	numBuffers := durationSec

	// Allocate buffers
	allData := make([]byte, 0, bufferSize*numBuffers)
	
	for i := 0; i < numBuffers; i++ {
		buffer := make([]byte, bufferSize)
		
		waveHdr := WAVEHDR{
			LpData:         uintptr(unsafe.Pointer(&buffer[0])),
			DwBufferLength: uint32(bufferSize),
		}

		// Prepare header
		ret, _, _ = waveInPrepareHeader.Call(
			hWaveIn,
			uintptr(unsafe.Pointer(&waveHdr)),
			unsafe.Sizeof(waveHdr),
		)
		if ret != 0 {
			continue
		}

		// Add buffer
		ret, _, _ = waveInAddBuffer.Call(
			hWaveIn,
			uintptr(unsafe.Pointer(&waveHdr)),
			unsafe.Sizeof(waveHdr),
		)

		// Start recording (only on first iteration)
		if i == 0 {
			waveInStart.Call(hWaveIn)
		}

		// Wait for buffer to fill (simplified - should use events)
		sleepMilliseconds(1000)

		// Unprepare header
		waveInUnprepareHeader.Call(
			hWaveIn,
			uintptr(unsafe.Pointer(&waveHdr)),
			unsafe.Sizeof(waveHdr),
		)

		// Collect recorded data
		allData = append(allData, buffer[:waveHdr.DwBytesRecorded]...)
	}

	// Stop recording
	waveInStop.Call(hWaveIn)
	waveInReset.Call(hWaveIn)

	// Create WAV file format
	wavData := createWAVFile(allData, sampleRate, channels, bitsPerSample)

	return wavData, int(sampleRate), nil
}

// createWAVFile creates a proper WAV file with headers
func createWAVFile(pcmData []byte, sampleRate, channels, bitsPerSample int) []byte {
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

// sleepMilliseconds is a helper to sleep for specified milliseconds
func sleepMilliseconds(ms int) {
	kernel32Sleep := syscall.NewLazyDLL("kernel32.dll").NewProc("Sleep")
	kernel32Sleep.Call(uintptr(ms))
}
