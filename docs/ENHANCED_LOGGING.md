# Enhanced Server Logging

This document describes the enhanced logging features added to the silkwire C2 server.

## Overview

The server logging has been significantly enhanced to provide more detailed operational information, security insights, and debugging capabilities.

## Enhanced Log Categories

### 1. Implant Generation Logging

**Before:**
```
INFO[2025-08-20 13:26:56] Generating implant for listener: lst_1755714416655677017, OS: linux, Arch: amd64, Format: exe 
INFO[2025-08-20 13:26:58] Successfully generated implant: calmsnake_linux_amd64 (17585620 bytes)
```

**After:**
```
INFO[2025-08-20 13:26:56] Generating implant for listener: lst_1755714416655677017, OS: linux, Arch: amd64, Format: exe
INFO[2025-08-20 13:26:56] Implant generation options: debug=true, garble=true, evasion=true
INFO[2025-08-20 13:26:56] Implant build configuration: garble=true, evasion=true
INFO[2025-08-20 13:26:56] Target configuration: 192.168.1.100:8443 (HTTPS transport)
INFO[2025-08-20 13:26:58] Implant compilation completed in 2.1s
INFO[2025-08-20 13:26:58] Successfully generated implant: calmsnake_linux_amd64 (17.2 MB, 17585620 bytes)
INFO[2025-08-20 13:26:58] Implant metadata: beacon_interval=60s, jitter=10%, session_key=a1b2c3d4...
```

### 2. Session Activity Logging

**Before:**
```
INFO[2025-08-20 13:27:00] Heartbeat from 818d5abe
```

**After:**
```
INFO[2025-08-20 13:26:45] New implant registration: 818d5abe (admin@workstation01)
INFO[2025-08-20 13:26:45] Registration details: OS=windows, Arch=amd64, PID=4172, Process=svchost.exe, Version=1.0.0
INFO[2025-08-20 13:27:00] Heartbeat from 818d5abe (admin@workstation01)
```

### 3. Command Execution Logging

**Before:**
```
INFO[2025-08-20 13:27:15] Task queued for 818d5abe: ls -la
INFO[2025-08-20 13:27:16] Command result: ID=cmd_1755714436123456789, Success=true, Output=total 24...
```

**After:**
```
INFO[2025-08-20 13:27:15] Sending command to 818d5abe: dir (ID: cmd_1755714436123456789, Type: SHELL)
INFO[2025-08-20 13:27:15] Task queued for 818d5abe: dir (ID: cmd_1755714436123456789, Type: SHELL)
INFO[2025-08-20 13:27:16] Command result: ID=cmd_1755714436123456789, Success=true, Output: Volume in drive C has no label... (356 more chars)
```

### 4. File Transfer Logging

**Before:**
```
INFO[2025-08-20 13:28:00] File upload completed: document.pdf (2048576 bytes)
INFO[2025-08-20 13:28:30] File download requested: /etc/passwd
```

**After:**
```
INFO[2025-08-20 13:28:00] File upload completed: document.pdf (2.0 MB, 2048576 bytes) from implant
INFO[2025-08-20 13:28:30] File download requested: /etc/passwd (implant requesting file from server)
```

### 5. PTY Session Logging

**New logging for PTY sessions:**
```
INFO[2025-08-20 13:29:00] PTY session started: pty_1755714540987654321 for implant 818d5abe (terminal size: 80x24)
INFO[2025-08-20 13:31:15] PTY session closed: pty_1755714540987654321 for implant 818d5abe
```

### 6. Listener Management Logging

**New detailed listener logging:**
```
INFO[2025-08-20 13:25:00] Starting new listener: 0.0.0.0:8443 (LISTENER_HTTPS)
INFO[2025-08-20 13:25:01] Listener successfully started: 0.0.0.0:8443 (ID: lst_1755714301234567890, Type: LISTENER_HTTPS)
```

## Key Improvements

### 1. **Build Configuration Visibility**
- Shows all enabled security/evasion options
- Displays garble usage and compilation time
- Includes target server configuration

### 2. **File Size Formatting**
- Automatic KB/MB formatting for better readability
- Shows both human-readable and exact byte counts

### 3. **Command Context**
- Includes command arguments in logging
- Shows command types and IDs for tracking
- Truncates long output with continuation indicators

### 4. **Session Identification**
- Enhanced heartbeat logging with user@hostname context
- Detailed registration information including process details

### 5. **Security Monitoring**
- PTY session tracking for interactive access
- File transfer monitoring with direction indicators
- Listener activity with security transport types

### 6. **Error Handling**
- More descriptive error messages
- Build failure timing information
- Clear distinction between warnings and errors

## Log Level Usage

- **INFO**: Normal operational events, successful operations
- **WARN**: Command failures, non-critical issues  
- **ERROR**: System errors, build failures, connection issues

## Benefits

1. **Enhanced Security Monitoring**: Track all implant activities with detailed context
2. **Better Debugging**: Comprehensive build and execution information
3. **Operational Insights**: Clear visibility into C2 infrastructure usage
4. **Performance Tracking**: Build times and file transfer metrics
5. **Audit Trail**: Complete record of all C2 operations

## Configuration

The enhanced logging uses the existing logrus configuration. Log level can be adjusted in `server/main.go`:

```go
logrus.SetLevel(logrus.InfoLevel)  // Current default
logrus.SetLevel(logrus.DebugLevel) // For verbose debugging
logrus.SetLevel(logrus.WarnLevel)  // For minimal logging
```

## Dependencies

For garble obfuscation features to work properly, ensure garble is installed:

```bash
# Install using the Makefile (recommended)
make tools

# Or install manually
go install mvdan.cc/garble@latest
```

Note: Garble is already included as a dependency in go.mod, so `go mod download` will fetch it, but it needs to be installed as a binary to be used during compilation.

All enhanced logging maintains backward compatibility while providing significantly more operational visibility.