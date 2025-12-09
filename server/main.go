package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	pb "silkwire/proto"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// HackerRedFormatter is a custom logrus formatter with red hacker aesthetics
type HackerRedFormatter struct{}

func (f *HackerRedFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// ANSI color codes
	const (
		red       = "\033[31m"
		brightRed = "\033[91m"
		darkRed   = "\033[38;5;52m"
		reset     = "\033[0m"
		bold      = "\033[1m"
		dim       = "\033[2m"
	)

	timestamp := entry.Time.Format("2006-01-02 15:04:05")

	var levelColor string
	var levelSymbol string

	switch entry.Level {
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = brightRed
		levelSymbol = "[!]"
	case logrus.WarnLevel:
		levelColor = red
		levelSymbol = "[~]"
	case logrus.InfoLevel:
		levelColor = red
		levelSymbol = "[+]"
	default:
		levelColor = darkRed
		levelSymbol = "[*]"
	}

	// Format: [TIME] [SYMBOL] MESSAGE
	output := fmt.Sprintf("%s[%s]%s %s%s%s %s%s%s\n",
		dim+darkRed, timestamp, reset,
		bold+levelColor, levelSymbol, reset,
		red, entry.Message, reset,
	)

	return []byte(output), nil
}

func main() {
	// Configure Logrus with red hacker theme
	logrus.SetFormatter(&HackerRedFormatter{})
	logrus.SetLevel(logrus.InfoLevel)

	// Display banner
	banner := `
  ███████ ██      ██ ██   ██ ██     ██ ██ ██████  ███████
  ██      ██      ██ ██  ██  ██     ██ ██ ██   ██ ██
  ███████ ██      ██ █████   ██  █  ██ ██ ██████  █████
       ██ ██      ██ ██  ██  ██ ███ ██ ██ ██   ██ ██
  ███████ ███████ ██ ██   ██  ███ ███  ██ ██   ██ ███████
`
	// Print banner in red
	fmt.Printf("\033[31m%s\033[0m\n", banner)
	fmt.Printf("\033[31m  Silkwire C2 Framework - Server\033[0m\n")
	fmt.Printf("\033[2m\033[31m  Advanced Command & Control Infrastructure\033[0m\n\n")

	// Initialize database
	db, err := NewDatabase("c2_server.db")
	if err != nil {
		logrus.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	logrus.Info("Database initialized successfully")

	// Initialize CA manager for persistent certificate management
	caManager, err := NewCAManager("ca", "localhost:8443")
	if err != nil {
		logrus.Fatalf("Failed to initialize CA manager: %v", err)
	}
	logrus.Info("CA manager initialized for persistent certificates")

	// Load or generate persistent CA-signed server certificate
	cert, err := caManager.LoadOrGenerateServerCertificate("server", ":8443")
	if err != nil {
		logrus.Fatalf("Failed to load/generate server certificate: %v", err)
	}
	logrus.Info("Server certificate loaded (persistent, CA-signed)")

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, // For research - in production use mutual TLS
	})

	// Configure keepalive enforcement for long-term connection persistence
	kaep := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second, // Allow pings every 5 seconds minimum
		PermitWithoutStream: true,            // Allow pings even when no active RPCs
	}

	kasp := keepalive.ServerParameters{
		Time:    10 * time.Second, // Ping client if no activity for 10 seconds
		Timeout: 5 * time.Second,  // Wait 5 seconds for ping ack before closing connection
	}

	// Create gRPC server with TLS and keepalive
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),
		grpc.MaxRecvMsgSize(64<<20),
		grpc.MaxSendMsgSize(64<<20),
	)

	// Register C2 service
	c2Server := NewC2Server(db, caManager)
	pb.RegisterC2ServiceServer(s, c2Server)

	// Start server
	lis, err := net.Listen("tcp", ":8443")
	if err != nil {
		logrus.Fatalf("Failed to listen: %v", err)
	}

	logrus.Info("C2 Server starting on :8443 with TLS and SQLite persistence")
	if err := s.Serve(lis); err != nil {
		logrus.Fatalf("Failed to serve: %v", err)
	}
}