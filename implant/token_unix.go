//go:build !windows
// +build !windows

package main

import (
	"fmt"
)

// ListTokens - not supported on Unix
func (i *Implant) ListTokens() ([]byte, error) {
	return nil, fmt.Errorf("token manipulation is only supported on Windows")
}

// StealToken - not supported on Unix
func (i *Implant) StealToken(pid uint32) ([]byte, error) {
	return nil, fmt.Errorf("token manipulation is only supported on Windows")
}

// ImpersonateToken - not supported on Unix
func (i *Implant) ImpersonateToken(tokenID string) ([]byte, error) {
	return nil, fmt.Errorf("token manipulation is only supported on Windows")
}

// RevertToken - not supported on Unix
func (i *Implant) RevertToken() ([]byte, error) {
	return nil, fmt.Errorf("token manipulation is only supported on Windows")
}

// MakeToken - not supported on Unix
func (i *Implant) MakeToken(domain, username, password string) ([]byte, error) {
	return nil, fmt.Errorf("token manipulation is only supported on Windows")
}
