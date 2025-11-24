package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Generate secure session token
func generateSessionToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Validate session token from metadata
func (s *C2Server) validateSession(ctx context.Context) (*Session, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no metadata provided")
	}

	tokens := md.Get("session-token")
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no session token provided")
	}

	implantIDs := md.Get("implant-id")
	if len(implantIDs) == 0 {
		return nil, fmt.Errorf("no implant ID provided")
	}

	s.sessionsMux.RLock()
	session, exists := s.sessions[implantIDs[0]]
	s.sessionsMux.RUnlock()

	if !exists || session.SessionToken != tokens[0] {
		return nil, fmt.Errorf("invalid session")
	}

	// Update last seen in both memory and database
	session.LastSeen = time.Now()
	s.db.UpdateSessionLastSeen(session.ImplantID, session.LastSeen)
	return session, nil
}

// detectTransportType determines the transport type based on the gRPC connection
func (s *C2Server) detectTransportType(ctx context.Context) string {
	// Check if we can get peer info from the context
	if peer, ok := peer.FromContext(ctx); ok {
		switch authInfo := peer.AuthInfo.(type) {
		case credentials.TLSInfo:
			// It's a TLS connection
			if len(authInfo.State.PeerCertificates) > 0 {
				// Client provided certificates - this is mTLS
				return "mTLS"
			}
			// TLS without client certificates - this is HTTPS
			return "HTTPS"
		default:
			// No TLS - this is HTTP
			return "HTTP"
		}
	}

	// Fallback - couldn't determine transport type
	return "unknown"
}
