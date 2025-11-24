//go:build !windows
// +build !windows

package main

import (
	"fmt"

	pb "silkwire/proto"
)

func (i *Implant) ExecuteShellcode(shellcode []byte, options *pb.ExecuteShellcodeOptions) ([]byte, error) {
	return nil, fmt.Errorf("execute-shellcode is not implemented on this platform")
}

func (i *Implant) ExecutePE(shellcode []byte, options *pb.ExecutePEOptions) ([]byte, error) {
	return nil, fmt.Errorf("execute-pe is not implemented on this platform")
}
