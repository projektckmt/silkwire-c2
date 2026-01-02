//go:build linux && arm
// +build linux,arm

package main

import (
	"encoding/json"
	"fmt"
)

// InjectShellcode is limited on Linux ARM (32-bit)
func (i *Implant) InjectShellcode(pid int, shellcode []byte) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"status": "error",
		"error":  "Shellcode injection not yet implemented for ARM",
	})
}

// MigrateProcess is not implemented on ARM
func (i *Implant) MigrateProcess(targetPID int) ([]byte, error) {
	return nil, fmt.Errorf("process migration not implemented on ARM")
}

// PtraceInject is not implemented on ARM
func (i *Implant) PtraceInject(pid int, shellcode []byte) ([]byte, error) {
	return nil, fmt.Errorf("ptrace injection not implemented on ARM")
}

// LDPreloadInject is not implemented on ARM
func (i *Implant) LDPreloadInject(targetBinary string, shellcode []byte) ([]byte, error) {
	return nil, fmt.Errorf("LD_PRELOAD injection not implemented on ARM")
}

// MemfdCreate is not implemented on ARM
func (i *Implant) MemfdCreate(name string, data []byte) (int, error) {
	return 0, fmt.Errorf("memfd_create not implemented on ARM")
}

// ForkAndInject is not implemented on ARM
func (i *Implant) ForkAndInject(shellcode []byte) ([]byte, error) {
	return nil, fmt.Errorf("fork injection not implemented on ARM")
}
