//go:build !windows
// +build !windows

package main

import (
	"encoding/json"
	"fmt"
	pb "silkwire/proto"
)

// ExecuteAssembly is not supported on non-Windows platforms
func (i *Implant) ExecuteAssembly(assemblyBytes []byte, args []string, options *pb.ExecuteAssemblyOptions) ([]byte, error) {
	result := map[string]interface{}{
		"status": "error",
		"error":  ".NET assembly execution is only supported on Windows",
	}
	return json.Marshal(result)
}

// ExecuteAssemblyInProcess is not supported on non-Windows platforms
func (i *Implant) ExecuteAssemblyInProcess(assemblyBytes []byte, args []string, options *pb.ExecuteAssemblyOptions) ([]byte, error) {
	result := map[string]interface{}{
		"status": "error",
		"error":  ".NET assembly execution is only supported on Windows",
	}
	return json.Marshal(result)
}

// ExecuteInMemoryPowerShell is not supported on non-Windows platforms
func (i *Implant) ExecuteInMemoryPowerShell(script string) ([]byte, error) {
	return nil, fmt.Errorf("PowerShell execution is only supported on Windows")
}

// LoadCLR is not supported on non-Windows platforms
func LoadCLR() error {
	return fmt.Errorf("CLR is only available on Windows")
}

// InjectAssemblyIntoProcess is not supported on non-Windows platforms
func (i *Implant) InjectAssemblyIntoProcess(pid int, assemblyBytes []byte, args []string) ([]byte, error) {
	return nil, fmt.Errorf(".NET injection is only supported on Windows")
}
