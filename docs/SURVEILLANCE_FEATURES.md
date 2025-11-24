# Surveillance Features Documentation

## Overview
This document describes the newly implemented surveillance features in the Silkwire C2 framework. These features provide comprehensive monitoring and data collection capabilities for security research and testing.

## Features Added

### 1. Clipboard Monitoring
**Command:** `clipboard [duration]`

**Description:**
Monitors the target's clipboard for changes over a specified duration and captures all clipboard content updates.

**Usage:**
```bash
clipboard          # Monitor for 30 seconds (default)
clipboard 60       # Monitor for 60 seconds
clipboard 120      # Monitor for 2 minutes
```

**Output:**
- JSON format with array of clipboard entries
- Each entry includes timestamp, content, and format
- Summary of total captures

**Platform Support:**
- Windows: Native Win32 API (OpenClipboard, GetClipboardData)
- Linux: xclip, xsel, or wl-paste (Wayland)
- macOS: pbpaste command

**Implementation Files:**
- `implant/clipboard.go` - Core logic
- `implant/clipboard_windows.go` - Windows-specific implementation
- `implant/clipboard_unix.go` - Linux/macOS implementation

---

### 2. Enhanced Keylogger
**Command:** `keylog <start|stop>`

**Description:**
Captures all keystrokes with window title and process context tracking. Runs in background until stopped.

**Usage:**
```bash
keylog start       # Start keylogger
keylog stop        # Stop and retrieve captured data
```

**Features:**
- Real-time keystroke capture
- Active window title tracking
- Process name identification
- Special key conversion ([ENTER], [BACKSPACE], etc.)
- Window summary statistics

**Output:**
- JSON format with keystroke entries
- Each entry includes: timestamp, key, window title, process name
- Summary by window/application
- Maximum 10,000 entries cached

**Platform Support:**
- Windows: SetWindowsHookEx keyboard hook (WH_KEYBOARD_LL)
- Linux: X11 window tracking (requires elevated privileges for full functionality)
- macOS: Accessibility API integration

**Implementation Files:**
- `implant/keylogger.go` - Core keylogger logic
- `implant/keylogger_windows.go` - Windows hook implementation
- `implant/keylogger_unix.go` - Unix/Linux implementation

---

### 3. Screenshot Capture
**Command:** `screenshot`

**Description:**
Captures a screenshot of the target system's primary display and automatically downloads it to the console machine.

**Usage:**
```bash
screenshot         # Capture and download screenshot
```

**Workflow:**
1. Command sent to target implant
2. Screenshot captured on target system
3. Saved to temporary file on target
4. File automatically downloaded to console machine
5. Saved as `screenshot_<session-id>_<timestamp>.png` in current directory

**Output:**
- Progress indicator during capture and download
- Local file path where screenshot was saved
- Screenshot metadata (dimensions, size, capture time)

**File Locations:**
- Target temp file: `%TEMP%\screenshot_YYYYMMDD_HHMMSS.png` (Windows) or `/tmp/screenshot_YYYYMMDD_HHMMSS.png` (Linux/macOS)
- Console local file: `screenshot_<session-id>_YYYYMMDD_HHMMSS.png`

**Example Output:**
```
[*] Capturing screenshot...
[+] Screenshot saved on target: C:\Temp\screenshot_20251020_143022.png
[*] Downloading screenshot to screenshot_e87b7b0f_20251020_143022.png...
[+] Successfully downloaded file to screenshot_e87b7b0f_20251020_143022.png (1.2 MB)
```

**Platform Support:**
- Windows: GDI BitBlt API for direct screen capture
- Linux: scrot, ImageMagick import, or gnome-screenshot
- macOS: screencapture command

**Implementation Files:**
- `implant/screenshot.go` - Core logic
- `implant/screenshot_windows.go` - Windows GDI implementation
- `implant/screenshot_unix.go` - Linux/macOS command-line tools

---

### 4. Audio Capture
**Command:** `audio [duration]`

**Description:**
Records audio from the target's default microphone device for a specified duration.

**Usage:**
```bash
audio              # Record 5 seconds (default)
audio 10           # Record 10 seconds
audio 30           # Record 30 seconds
```

**Parameters:**
- Duration: 1-300 seconds (max 5 minutes)
- Sample Rate: 44.1kHz
- Format: WAV (PCM)
- Channels: Mono

**Output:**
- JSON format with metadata and audio data
- Includes: format, duration, sample rate, size
- Base64-encoded WAV audio data

**Decoding Audio:**
```bash
# Extract base64 data from JSON and decode
echo "<base64_data>" | base64 -d > recording.wav
```

**Platform Support:**
- Windows: WaveIn API for microphone access
- Linux: arecord (ALSA), sox, or ffmpeg
- macOS: sox or ffmpeg with AVFoundation

**Implementation Files:**
- `implant/audio_capture.go` - Core logic
- `implant/audio_capture_windows.go` - Windows WaveIn API
- `implant/audio_capture_unix.go` - Linux/macOS audio tools

**File Sizes:**
- Approximately 5MB per minute of mono audio at 44.1kHz

---

### 5. Webcam Capture
**Command:** `webcam <photo|video> [duration]`

**Description:**
Captures photo or video from the target's default webcam device.

**Usage:**
```bash
webcam photo           # Capture a photo
webcam video           # Record 5 seconds (default)
webcam video 10        # Record 10 seconds
webcam video 30        # Record 30 seconds
```

**Parameters:**
- Format: photo (JPEG) or video (MP4)
- Video Duration: 1-60 seconds (max 1 minute)

**Output:**
- JSON format with metadata and media data
- Includes: media type, size, format, duration
- Base64-encoded JPEG or MP4 data

**Decoding Media:**
```bash
# For photos
echo "<base64_data>" | base64 -d > webcam.jpg

# For videos
echo "<base64_data>" | base64 -d > webcam.mp4
```

**Platform Support:**
- Windows: DirectShow (requires ffmpeg)
- Linux: Video4Linux (requires ffmpeg)
- macOS: AVFoundation (requires ffmpeg)

**Requirements:**
- ffmpeg must be installed on the target system
- Webcam device must be available
- May require camera access permissions

**Implementation Files:**
- `implant/webcam_capture.go` - Core logic
- `implant/webcam_capture_windows.go` - Windows DirectShow
- `implant/webcam_capture_unix.go` - Linux/macOS ffmpeg integration

**File Sizes:**
- Photos: ~100-500KB
- Videos: ~1-5MB per 10 seconds

---

## Protocol Changes

### New Command Types (proto/c2.proto)
```protobuf
CLIPBOARD_MONITOR = 40;     // Monitor clipboard for duration
KEYLOG_START = 41;          // Start keylogger
KEYLOG_STOP = 42;           // Stop keylogger and retrieve logs
SCREENSHOT_CAPTURE = 43;    // Capture screenshot
AUDIO_CAPTURE = 44;         // Record audio from microphone
WEBCAM_CAPTURE = 45;        // Capture from webcam (photo/video)
```

---

## Console Commands

All surveillance commands are available in session mode (after using `use <session-id>` command):

### Command List
1. `clipboard [duration]` - Monitor clipboard
2. `keylog <start|stop>` - Keylogger control
3. `screenshot` - Capture screenshot
4. `audio [duration]` - Record audio
5. `webcam <photo|video> [duration]` - Webcam capture

### Help Documentation
Each command has detailed help available:
```bash
help clipboard
help keylog
help screenshot
help audio
help webcam
```

---

## Security Considerations

### OPSEC (Operational Security)

**Clipboard Monitoring:**
- Low detection risk
- No visual indicators
- Minimal CPU usage

**Keylogger:**
- Medium detection risk on Windows (keyboard hooks can be detected)
- Runs continuously until stopped
- Higher privilege requirements on Linux/macOS
- May trigger security software alerts

**Screenshot:**
- Low detection risk
- Single capture operation
- Large data transfer (1-5MB)
- May be visible in task manager briefly

**Audio Capture:**
- High detection risk
- May trigger microphone access indicators
- OS-level permissions required
- Visible LED indicators on some hardware

**Webcam:**
- High detection risk
- Camera activity LED will typically activate
- OS-level permissions required
- Large data transfer for videos

### Recommendations

1. **Test in controlled environment first**
2. **Use short durations to minimize exposure**
3. **Monitor for security software alerts**
4. **Consider network bandwidth for large captures**
5. **Clean up captured data promptly**
6. **Use TLS/encryption for data transmission**

---

## Testing

### Basic Testing Commands
```bash
# Start server and implant
make run-server        # Terminal 1
make run-client        # Terminal 2
make run-console       # Terminal 3

# In console
sessions
use <session-id>

# Test clipboard
clipboard 10

# Test keylogger
keylog start
# Type something...
keylog stop

# Test screenshot
screenshot

# Test audio (requires microphone)
audio 5

# Test webcam (requires camera)
webcam photo
webcam video 5
```

### Decoding Captured Data
```bash
# Extract JSON output and decode
# Replace <base64_data> with actual data from JSON response

# Screenshot
echo "<base64_data>" | base64 -d > screenshot.png

# Audio
echo "<base64_data>" | base64 -d > audio.wav

# Webcam photo
echo "<base64_data>" | base64 -d > webcam.jpg

# Webcam video
echo "<base64_data>" | base64 -d > webcam.mp4
```

---

## Troubleshooting

### Common Issues

**Clipboard - "No clipboard tool available"**
- Solution: Install xclip, xsel, or wl-paste on Linux

**Keylogger - Permissions Error**
- Solution: Windows requires no special permissions; Linux/macOS may need elevated privileges

**Screenshot - Failed to capture**
- Solution: Ensure display is active; check for display manager on Linux

**Audio - No audio device**
- Solution: Verify microphone is connected and not in use by another application

**Webcam - ffmpeg not found**
- Solution: Install ffmpeg on the target system

### Debug Mode
Enable debug logging in implant to see detailed error messages:
```go
// In implant/main.go
DebugMode = true
```

---

## Future Enhancements

Potential improvements:
- [ ] Multi-monitor screenshot support
- [ ] Selective window screenshot capture
- [ ] Audio device selection
- [ ] Webcam device selection and resolution control
- [ ] Real-time streaming instead of batch capture
- [ ] Compression for large media files
- [ ] Encrypted data transmission
- [ ] Clipboard format support (images, files)

---

## File Summary

### Core Implementation
- `implant/clipboard.go` - Clipboard monitoring core
- `implant/keylogger.go` - Keylogger core with window tracking
- `implant/screenshot.go` - Screenshot capture core
- `implant/audio_capture.go` - Audio recording core
- `implant/webcam_capture.go` - Webcam capture core

### Platform-Specific (Windows)
- `implant/clipboard_windows.go`
- `implant/keylogger_windows.go`
- `implant/screenshot_windows.go`
- `implant/audio_capture_windows.go`
- `implant/webcam_capture_windows.go`

### Platform-Specific (Unix/Linux/macOS)
- `implant/clipboard_unix.go`
- `implant/keylogger_unix.go`
- `implant/screenshot_unix.go`
- `implant/audio_capture_unix.go`
- `implant/webcam_capture_unix.go`

### Console Integration
- `console/main.go` - Cobra command definitions
- `console/commands.go` - Command execution logic

### Protocol
- `proto/c2.proto` - Protobuf definitions with new command types

---

## Credits

Surveillance features implemented for the Silkwire C2 Framework.
All features designed for security research and authorized testing only.

**Use responsibly and legally.**
