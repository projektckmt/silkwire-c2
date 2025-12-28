//go:build darwin
// +build darwin

package main

import (
	"encoding/json"
	"fmt"
)

// InjectShellcode is not supported on Darwin
func (i *Implant) InjectShellcode(pid int, shellcode []byte) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"status": "error",
		"error":  "Shellcode injection not supported on macOS",
	})
}

// MigrateProcess is not supported on Darwin
func (i *Implant) MigrateProcess(targetPID int) ([]byte, error) {
	return nil, fmt.Errorf("process migration not supported on macOS")
}

// PtraceInject is not supported on Darwin
func (i *Implant) PtraceInject(pid int, shellcode []byte) ([]byte, error) {
	return nil, fmt.Errorf("ptrace injection not supported on macOS")
}

// LDPreloadInject is not supported on Darwin
func (i *Implant) LDPreloadInject(targetBinary string, shellcode []byte) ([]byte, error) {
	return nil, fmt.Errorf("LD_PRELOAD injection not supported on macOS")
}

// MemfdCreate is not supported on Darwin
func (i *Implant) MemfdCreate(name string, data []byte) (int, error) {
	return 0, fmt.Errorf("memfd_create not supported on macOS")
}

// ForkAndInject is not supported on Darwin
func (i *Implant) ForkAndInject(shellcode []byte) ([]byte, error) {
	return nil, fmt.Errorf("fork injection not supported on macOS")
}
