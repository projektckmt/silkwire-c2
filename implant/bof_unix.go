//go:build !windows
// +build !windows

package main

import (
	"fmt"

	pb "silkwire/proto"
)

// ExecuteBOF is a stub for non-Windows platforms
// BOF (Beacon Object Files) are Windows COFF files and cannot be executed on Unix systems
func (i *Implant) ExecuteBOF(bofBytes []byte, options *pb.BOFOptions) ([]byte, error) {
	return nil, fmt.Errorf("BOF execution is only supported on Windows platforms")
}
