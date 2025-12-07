package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	pb "silkwire/proto"

	linerpkg "github.com/peterh/liner"
	rfconsole "github.com/reeflective/console"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Using standard logrus TextFormatter for simple, clean output

// Session represents an active implant session
type Session struct {
	ImplantID     string
	SessionToken  string
	Codename      string
	Hostname      string
	Username      string
	OS            string
	Arch          string
	ProcessName   string
	PID           int32
	NetworkIfaces []string
	LastSeen      time.Time
	Created       time.Time
	Transport     string // Transport type: "HTTP", "HTTPS", "mTLS"
	RemoteAddr    string // Remote connection address
}

// C2Server represents the server state for console operations
type C2Server struct {
	sessions    map[string]*Session
	sessionsMux sync.RWMutex
	taskQueues  map[string]chan *pb.Task
	queuesMux   sync.RWMutex
	streams     map[string]pb.C2Service_BeaconStreamServer
	streamsMux  sync.RWMutex
}

// NewC2Server creates a new C2Server instance
func NewC2Server() *C2Server {
	return &C2Server{
		sessions:   make(map[string]*Session),
		taskQueues: make(map[string]chan *pb.Task),
		streams:    make(map[string]pb.C2Service_BeaconStreamServer),
	}
}

// QueueTask queues a task for an implant
func (s *C2Server) QueueTask(implantID string, task *pb.Task) error {
	s.queuesMux.RLock()
	taskQueue, exists := s.taskQueues[implantID]
	s.queuesMux.RUnlock()

	if !exists {
		return fmt.Errorf("implant not found: %s", implantID)
	}

	select {
	case taskQueue <- task:
		return nil
	default:
		return fmt.Errorf("task queue full for implant: %s", implantID)
	}
}

// SendCommandMessage sends a command via stream if available (local server method)
func (s *C2Server) SendCommandMessage(implantID string, cmd *pb.CommandMessage) error {
	s.streamsMux.RLock()
	stream, exists := s.streams[implantID]
	s.streamsMux.RUnlock()

	if !exists {
		return fmt.Errorf("no active stream for implant: %s", implantID)
	}

	return stream.Send(cmd)
}

// OperatorConsole represents the main console interface
type OperatorConsole struct {
	client pb.C2ServiceClient
	conn   *grpc.ClientConn
	server *C2Server // Reference to server for direct operations

	// Enhanced console features
	commandHistory       []string
	notifications        chan string
	autoRefresh          bool
	notificationsEnabled bool
	lastActivity         time.Time
	// Prompt stability and notifications
	pendingNotifications []string
	notifMux             sync.Mutex
	line                 *linerpkg.State
	consoleApp           *rfconsole.Console

	// Session discovery for notifications
	knownSessions     map[string]struct{}
	knownSessionsInfo map[string]*Session // Store session info for loss detection

	// Track if close has been called
	closed   bool
	closeMux sync.Mutex

	// Session event stream for real-time notifications
	eventStream    pb.C2Service_SessionEventStreamClient
	eventStreamMux sync.Mutex

	// inSession flag to disable main console notifications during session
	inSession    bool
	inSessionMux sync.Mutex

	// Grace period to avoid duplicate session lost notifications (session-specific)
	sessionGracePeriod map[string]time.Time
}

// ShellSession represents an active shell session with an implant
type ShellSession struct {
	ImplantID string
	Hostname  string
	Username  string
	OS        string
}

// NewOperatorConsole creates a new operator console instance
func NewOperatorConsole(serverAddr string, server *C2Server) (*OperatorConsole, error) {
	// Connect to gRPC server
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	creds := credentials.NewTLS(config)

	// Increase client-side message size limits to handle large generated payloads
	conn, err := grpc.Dial(
		serverAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(64<<20),
			grpc.MaxCallSendMsgSize(64<<20),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	oc := &OperatorConsole{
		client:               pb.NewC2ServiceClient(conn),
		conn:                 conn,
		server:               server,
		commandHistory:       make([]string, 0, 100),
		notifications:        make(chan string, 100),
		knownSessions:        make(map[string]struct{}),
		knownSessionsInfo:    make(map[string]*Session),
		sessionGracePeriod:   make(map[string]time.Time),
		autoRefresh:          true,
		notificationsEnabled: true, // Always enabled
		lastActivity:         time.Now(),
	}

	// Initialize liner for input handling
	line := linerpkg.NewLiner()
	line.SetCtrlCAborts(true)
	oc.line = line

	// Configure logrus to only show WARN and ERROR, suppress INFO
	logrus.SetLevel(logrus.WarnLevel)

	// Start session event stream for real-time notifications
	oc.startEventStream()

	return oc, nil
}

// Close closes the operator console connection
func (oc *OperatorConsole) Close() {
	oc.closeMux.Lock()
	defer oc.closeMux.Unlock()

	if oc.closed {
		return
	}
	oc.closed = true

	if oc.line != nil {
		oc.line.Close()
	}

	// Close event stream if active
	oc.eventStreamMux.Lock()
	if oc.eventStream != nil {
		oc.eventStream.CloseSend()
		oc.eventStream = nil
	}
	oc.eventStreamMux.Unlock()

	if oc.conn != nil {
		oc.conn.Close()
	}
	close(oc.notifications)
}

// GetSessions retrieves all active sessions
func (oc *OperatorConsole) GetSessions() ([]*Session, error) {
	if oc.client != nil {
		req := &pb.SessionListRequest{}
		resp, err := oc.client.ListSessions(context.Background(), req)
		if err != nil {
			return nil, fmt.Errorf("failed to get sessions: %v", err)
		}

		sessions := make([]*Session, len(resp.Sessions))
		for i, s := range resp.Sessions {
			// Determine transport type from protobuf field
			transport := s.Transport
			if transport == "" {
				transport = "unknown"
			}

			// For remote address, we should get this from the server connection context
			// For now, we'll show "server-side" since NetworkInterfaces are local to the implant
			remoteAddr := "server-side"

			sessions[i] = &Session{
				ImplantID:     s.ImplantId,
				SessionToken:  "", // Not available in SessionInfo
				Codename:      s.Codename,
				Hostname:      s.Hostname,
				Username:      s.Username,
				OS:            s.Os,
				Arch:          s.Arch,
				ProcessName:   s.ProcessName,
				PID:           s.Pid,
				NetworkIfaces: s.NetworkInterfaces,
				LastSeen:      time.Unix(s.LastSeen, 0),
				Created:       time.Unix(s.Created, 0),
				Transport:     transport,
				RemoteAddr:    remoteAddr,
			}
		}
		return sessions, nil
	}

	// Fallback to local server if available (demo mode)
	if oc.server != nil {
		oc.server.sessionsMux.RLock()
		defer oc.server.sessionsMux.RUnlock()

		sessions := make([]*Session, 0, len(oc.server.sessions))
		for _, s := range oc.server.sessions {
			sessions = append(sessions, s)
		}
		return sessions, nil
	}

	return nil, fmt.Errorf("no connection available")
}

// GetImplantBuilds retrieves all implant builds
func (oc *OperatorConsole) GetImplantBuilds() ([]*pb.ImplantBuildInfo, error) {
	if oc.client != nil {
		req := &pb.ImplantBuildsListRequest{}
		resp, err := oc.client.ListImplantBuilds(context.Background(), req)
		if err != nil {
			return nil, fmt.Errorf("failed to get implant builds: %v", err)
		}
		return resp.Builds, nil
	}

	return nil, fmt.Errorf("no connection available")
}

// FindSessionByPartialID finds a session by partial ID match
func (oc *OperatorConsole) FindSessionByPartialID(partialID string) (*Session, error) {
	sessions, err := oc.GetSessions()
	if err != nil {
		return nil, err
	}

	var matches []*Session
	for _, session := range sessions {
		if len(session.ImplantID) >= len(partialID) &&
			session.ImplantID[:len(partialID)] == partialID {
			matches = append(matches, session)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no session found matching '%s'", partialID)
	} else if len(matches) > 1 {
		return nil, fmt.Errorf("multiple sessions match '%s' - be more specific", partialID)
	}

	return matches[0], nil
}

// AddToHistory adds a command to the command history
func (oc *OperatorConsole) AddToHistory(command string) {
	if command == "" {
		return
	}

	// Avoid duplicates at the end of history
	if len(oc.commandHistory) > 0 && oc.commandHistory[len(oc.commandHistory)-1] == command {
		return
	}

	oc.commandHistory = append(oc.commandHistory, command)

	// Keep only last 100 commands
	if len(oc.commandHistory) > 100 {
		oc.commandHistory = oc.commandHistory[1:]
	}

	// Add to liner history as well
	if oc.line != nil {
		oc.line.AppendHistory(command)
	}
}

// findImplantID finds a full implant ID from a partial match
func (oc *OperatorConsole) findImplantID(partial string) string {
	var matches []string

	// Try to get sessions from server via gRPC first
	if oc.client != nil {
		resp, err := oc.client.ListSessions(context.Background(), &pb.SessionListRequest{})
		if err == nil {
			for _, session := range resp.Sessions {
				if strings.HasPrefix(strings.ToLower(session.ImplantId), strings.ToLower(partial)) {
					matches = append(matches, session.ImplantId)
				}
			}
		}
	}

	// Handle multiple matches
	if len(matches) == 0 {
		return ""
	}

	if len(matches) == 1 {
		return matches[0]
	}

	// Multiple matches - show them to the user
	fmt.Printf("Multiple implants match '%s':\n", partial)
	for i, match := range matches {
		displayID := match
		if len(displayID) > 8 {
			displayID = displayID[:8] + "..."
		}
		fmt.Printf("  %d: %s\n", i+1, displayID)
	}
	fmt.Printf("Please be more specific.\n")

	return ""
}

// ListSessions displays all active sessions
func (oc *OperatorConsole) ListSessions() {
	sessions, err := oc.GetSessions()
	if err != nil {
		fmt.Printf("Failed to get sessions: %v\n", err)
		return
	}
	printSessionsTable(sessions)
}

// StartSessionInteractiveMode starts an interactive session mode for a specific implant
func (oc *OperatorConsole) StartSessionInteractiveMode(implantID string) {
	// Validate session exists and get codename
	var sessionExists bool
	var codename string
	if oc.client != nil {
		resp, err := oc.client.ListSessions(context.Background(), &pb.SessionListRequest{})
		if err == nil {
			for _, session := range resp.Sessions {
				if session.ImplantId == implantID {
					sessionExists = true
					codename = session.Codename
					break
				}
			}
		}
	}

	if !sessionExists {
		fmt.Printf("Session not found: %s\n", implantID)
		return
	}

	// Start session console as a subprocess that can exit cleanly
	oc.startSessionSubprocess(implantID, codename)
}

// startSessionSubprocess starts a subprocess for dedicated session interaction
func (oc *OperatorConsole) startSessionSubprocess(implantID, codename string) {
	// Set grace period BEFORE entering session to suppress all notifications about this session
	oc.notifMux.Lock()
	oc.sessionGracePeriod[implantID] = time.Now().Add(5 * time.Minute) // Long grace period while in session
	oc.notifMux.Unlock()

	// Set inSession flag to disable main console notifications
	oc.inSessionMux.Lock()
	oc.inSession = true
	oc.inSessionMux.Unlock()

	// Defer resetting the flag and restarting event stream
	defer func() {
		oc.inSessionMux.Lock()
		oc.inSession = false
		oc.inSessionMux.Unlock()

		// Clear any pending notifications that were queued during session
		oc.notifMux.Lock()
		oc.pendingNotifications = nil
		// Extend grace period after exiting to catch any race conditions
		oc.sessionGracePeriod[implantID] = time.Now().Add(5 * time.Second)
		oc.notifMux.Unlock()

		// Event stream goroutine will automatically resume when inSession becomes false

		// Give event stream time to settle and discard any stale events
		time.Sleep(200 * time.Millisecond)

		// Final clear of any notifications about the session we just exited
		oc.notifMux.Lock()
		filtered := make([]string, 0)
		for _, notif := range oc.pendingNotifications {
			// Filter out notifications about the session we just exited
			if !strings.Contains(notif, implantID[:8]) {
				filtered = append(filtered, notif)
			}
		}
		oc.pendingNotifications = filtered
		oc.notifMux.Unlock()
	}()

	// Event stream will automatically pause when inSession becomes true

	// Create a command to start this same program but in session mode
	args := []string{"session-subprocess", implantID, codename, serverAddrFlag}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set environment variables to pass session context
	cmd.Env = append(os.Environ(),
		"SILKWIRE_SESSION_MODE=true",
		"SILKWIRE_SESSION_ID="+implantID,
		"SILKWIRE_SESSION_CODENAME="+codename,
	)

	// Run the subprocess
	err := cmd.Run()
	if err != nil {
		// Check if it's a clean exit (exit code 0)
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() != 0 {
				fmt.Printf("Session process exited with error: %v\n", err)
			}
		} else {
			fmt.Printf("Failed to start session process: %v\n", err)
		}
	}
}

// executeSessionCommand executes a command in a specific session context
func (oc *OperatorConsole) executeSessionCommand(implantID, command string) {
	// This is a wrapper around handleSessionCommand to provide consistent interface
	oc.handleSessionCommand(implantID, command)
}

// startEventStream establishes a session event stream for real-time notifications
func (oc *OperatorConsole) startEventStream() {
	oc.eventStreamMux.Lock()
	if oc.eventStream != nil {
		oc.eventStreamMux.Unlock()
		return // Already running
	}
	oc.eventStreamMux.Unlock()

	if oc.client == nil {
		return // Skip if not connected to server
	}

	go func() {
		for {
			// Check if console is closed
			oc.closeMux.Lock()
			if oc.closed {
				oc.closeMux.Unlock()
				return
			}
			oc.closeMux.Unlock()

			// Check if in a session (don't run event stream during session)
			oc.inSessionMux.Lock()
			inSession := oc.inSession
			oc.inSessionMux.Unlock()

			if inSession {
				// Wait a bit and check again instead of exiting
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Start event stream
			req := &pb.SessionEventStreamRequest{}
			stream, err := oc.client.SessionEventStream(context.Background(), req)
			if err != nil {
				logrus.Warnf("Failed to establish event stream: %v", err)
				time.Sleep(5 * time.Second) // Retry after delay
				continue
			}

			logrus.Info("Session event stream established")
			oc.eventStreamMux.Lock()
			oc.eventStream = stream
			oc.eventStreamMux.Unlock()

			// Handle incoming events
			for {
				event, err := stream.Recv()
				if err != nil {
					// Add disconnection notification (only if not graceful shutdown)
					oc.notifMux.Lock()
					if !oc.closed {
						oc.pendingNotifications = append(oc.pendingNotifications, "Session event stream disconnected")
					}
					oc.notifMux.Unlock()
					break
				}
				oc.handleSessionEvent(event)
			}

			oc.eventStreamMux.Lock()
			oc.eventStream = nil
			oc.eventStreamMux.Unlock()

			// Add reconnection notification (less frequent to avoid spam)
			oc.notifMux.Lock()
			if !oc.closed {
				oc.pendingNotifications = append(oc.pendingNotifications, "Reconnecting to session event stream...")
			}
			oc.notifMux.Unlock()
			time.Sleep(2 * time.Second) // Brief delay before reconnect
		}
	}()
}

// handleSessionEvent processes incoming session events from the server
func (oc *OperatorConsole) handleSessionEvent(event *pb.SessionEvent) {
	// Notifications are always enabled

	session := event.Session
	if session == nil {
		return
	}

	var notification string

	switch event.EventType {
	case pb.SessionEvent_SESSION_ESTABLISHED:
		// Check if session is already known to prevent duplicates
		oc.notifMux.Lock()
		if _, exists := oc.knownSessions[session.ImplantId]; exists {
			oc.notifMux.Unlock()
			return
		}

		// Format the detailed notification
		notification = fmt.Sprintf(
			"New session %s via %s (%s) as %s (pid: %d)",
			colorize(session.ImplantId[:8], colorGreen),
			colorize(strings.ToUpper(session.Transport), colorCyan),
			colorize(session.Hostname, colorYellow),
			colorize(session.Username, colorMagenta),
			session.Pid,
		)

		// Update known sessions to prevent duplicate notifications from polling
		oc.knownSessions[session.ImplantId] = struct{}{}
		oc.knownSessionsInfo[session.ImplantId] = &Session{
			ImplantID:     session.ImplantId,
			Codename:      session.Codename,
			Hostname:      session.Hostname,
			Username:      session.Username,
			OS:            session.Os,
			Arch:          session.Arch,
			ProcessName:   session.ProcessName,
			PID:           session.Pid,
			NetworkIfaces: session.NetworkInterfaces,
			LastSeen:      time.Unix(session.LastSeen, 0),
			Created:       time.Unix(session.Created, 0),
			Transport:     session.Transport,
		}
		oc.pendingNotifications = append(oc.pendingNotifications, notification)
		oc.notifMux.Unlock()

	case pb.SessionEvent_SESSION_LOST:
		// Suppress notification if within grace period for this specific session
		oc.notifMux.Lock()
		gracePeriod, hasGracePeriod := oc.sessionGracePeriod[session.ImplantId]
		oc.notifMux.Unlock()

		if hasGracePeriod && time.Now().Before(gracePeriod) {
			logrus.Debugf("Suppressing SESSION_LOST notification for %s (grace period active)", session.ImplantId[:8])
			return
		}

		// Remove from known sessions first (before generating notification)
		oc.notifMux.Lock()

		// Check if session is still in known sessions (deduplication)
		if _, exists := oc.knownSessions[session.ImplantId]; !exists {
			// Already processed this loss event, skip
			logrus.Debugf("Skipping duplicate SESSION_LOST event for %s", session.ImplantId[:8])
			oc.notifMux.Unlock()
			return
		}

		delete(oc.knownSessions, session.ImplantId)
		delete(oc.knownSessionsInfo, session.ImplantId)
		delete(oc.sessionGracePeriod, session.ImplantId) // Clean up grace period

		notification = fmt.Sprintf(
			"Session %s lost (last seen %s ago)",
			colorize(session.ImplantId[:8], colorRed),
			formatDuration(time.Since(time.Unix(session.LastSeen, 0))),
		)

		logrus.Infof("Queuing SESSION_LOST notification: %s", notification)
		oc.pendingNotifications = append(oc.pendingNotifications, notification)
		oc.notifMux.Unlock()

	case pb.SessionEvent_SESSION_UPDATED:
		notification = fmt.Sprintf("Session updated: %s@%s (%s)", session.Username, session.Hostname, session.ImplantId[:8])

		// Update known sessions info
		oc.notifMux.Lock()
		oc.knownSessionsInfo[session.ImplantId] = &Session{
			ImplantID:     session.ImplantId,
			Codename:      session.Codename,
			Hostname:      session.Hostname,
			Username:      session.Username,
			OS:            session.Os,
			Arch:          session.Arch,
			ProcessName:   session.ProcessName,
			PID:           session.Pid,
			NetworkIfaces: session.NetworkInterfaces,
			LastSeen:      time.Unix(session.LastSeen, 0),
			Created:       time.Unix(session.Created, 0),
			Transport:     session.Transport,
		}
		oc.pendingNotifications = append(oc.pendingNotifications, notification)
		oc.notifMux.Unlock()

	case pb.SessionEvent_TASK_COMPLETED:
		// Task completed notification
		notification = fmt.Sprintf("Task Completed: %s", event.Message)
		// Add to pending notifications
		oc.notifMux.Lock()
		oc.pendingNotifications = append(oc.pendingNotifications, notification)
		oc.notifMux.Unlock()

	default:
		return // Unknown event type
	}
}

func (oc *OperatorConsole) pauseEventStream() {
	oc.eventStreamMux.Lock()
	defer oc.eventStreamMux.Unlock()
	if oc.eventStream != nil {
		oc.eventStream.CloseSend()
		oc.eventStream = nil
	}
}

func (oc *OperatorConsole) resumeEventStream() {
	oc.inSessionMux.Lock()
	inSession := oc.inSession
	oc.inSessionMux.Unlock()

	if !inSession {
		go oc.startEventStream()
	}
}
