package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	pb "silkwire/proto"

	"golang.org/x/term"
)

// startLocalPtyShell sets the local terminal into raw mode and forwards stdin
// to the target session as commands, while streaming results back, similar to ssh.
// This is a best-effort emulation over the existing request/response channel.
func (oc *OperatorConsole) startLocalPtyShell(implantID string) {
	if oc.client == nil {
		fmt.Printf("%s Not connected to server; PTY requires server connection.\n", colorize("[*]", colorBlue))
		return
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("%s Not a TTY. Falling back to line mode.\n", colorize("[*]", colorBlue))
		return
	}

	// Open PTY stream to server
	stream, err := oc.client.PTYStream(context.Background())
	if err != nil {
		fmt.Printf("%s Failed to open PTY stream: %v\n", colorize("[*]", colorBlue), err)
		return
	}

	// Determine current terminal size
	cols, rows := 80, 24
	if c, r, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		cols, rows = c, r
	}

	// Send open
	if err := stream.Send(&pb.PTYClientMessage{Msg: &pb.PTYClientMessage_Open{Open: &pb.PTYOpen{ImplantId: implantID, Shell: "", Cols: int32(cols), Rows: int32(rows)}}}); err != nil {
		fmt.Printf("%s Failed to send PTY open: %v\n", colorize("[*]", colorBlue), err)
		return
	}

	// Put local terminal into raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Printf("%s Failed to enter raw mode: %v\n", colorize("[*]", colorBlue), err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Printf("%s Press ~. to exit\r\n\n", colorize("[*]", colorBlue))

	// Handle SIGWINCH → send resize
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	// Receiver: stream PTY output to stdout
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			srvMsg, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				if strings.Contains(err.Error(), "no active stream for implant") {
					fmt.Printf("\r\n%s Stream disconnected. Implant may be reconnecting...\r\n", colorize("[*]", colorYellow))
				} else {
					fmt.Printf("\r\n%s PTY recv error: %v\r\n", colorize("[*]", colorBlue), err)
				}
				return
			}
			switch m := srvMsg.Msg.(type) {
			case *pb.PTYServerMessage_Output:
				if m.Output != nil && len(m.Output.Data) > 0 {
					os.Stdout.Write(m.Output.Data)
				}
			case *pb.PTYServerMessage_Closed:
				return
			case *pb.PTYServerMessage_Error:
				if m.Error != nil {
					fmt.Printf("\r\n%s PTY error: %s\r\n", colorize("[*]", colorBlue), m.Error.Message)
				}
				return
			}
		}
	}()

	// Reader for stdin bytes
	in := bufio.NewReader(os.Stdin)

	for {
		// Exit if PTY stream ended remotely
		select {
		case <-done:
			return
		default:
		}

		// Non-blocking check for resize
		select {
		case <-sigCh:
			if c, r, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
				_ = stream.Send(&pb.PTYClientMessage{Msg: &pb.PTYClientMessage_Resize{Resize: &pb.PTYResize{Cols: int32(c), Rows: int32(r)}}})
			}
		case <-done:
			return
		default:
		}

		r, _, err := in.ReadRune()
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("\r\n%s Input error: %v\r\n", colorize("[*]", colorBlue), err)
			break
		}

		// ssh-like escape: ~.
		if r == '~' {
			next, _, nerr := in.ReadRune()
			if nerr == nil && next == '.' {
				_ = stream.Send(&pb.PTYClientMessage{Msg: &pb.PTYClientMessage_Close{Close: &pb.PTYClose{}}})
				<-done
				fmt.Print("\r\n[exit]\r\n")
				return
			}
			// Not an escape sequence; send both characters
			_ = stream.Send(&pb.PTYClientMessage{Msg: &pb.PTYClientMessage_Input{Input: &pb.PTYInput{Data: []byte("~")}}})
			if nerr == nil {
				_ = stream.Send(&pb.PTYClientMessage{Msg: &pb.PTYClientMessage_Input{Input: &pb.PTYInput{Data: []byte(string(next))}}})
			}
			continue
		}

		// Send each rune as bytes
		_ = stream.Send(&pb.PTYClientMessage{Msg: &pb.PTYClientMessage_Input{Input: &pb.PTYInput{Data: []byte(string(r))}}})
	}
}
