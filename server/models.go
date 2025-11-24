package main

import (
	"time"

	"gorm.io/gorm"
)

// DBSession represents a session record in the database
type DBSession struct {
	gorm.Model
	ImplantID     string `gorm:"uniqueIndex;not null"`
	SessionToken  string `gorm:"not null"`
	Codename      string
	Hostname      string
	Username      string
	OS            string
	Arch          string
	ProcessName   string
	PID           int32
	NetworkIfaces string // JSON encoded []string
	LastSeen      time.Time
	Transport     string // "streaming", "polling", "unknown"
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// DBCommand represents a command record in the database
type DBCommand struct {
	gorm.Model
	CommandID string `gorm:"uniqueIndex;not null"`
	ImplantID string `gorm:"not null"`
	Type      string
	Command   string
	Args      string // JSON encoded []string
	Data      []byte
	Timeout   int32
	Status    string // "pending", "sent", "completed", "failed"
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DBCommandResult represents a command result record in the database
type DBCommandResult struct {
	gorm.Model
	CommandID string `gorm:"uniqueIndex;not null"`
	ImplantID string `gorm:"not null"`
	Success   bool
	Output    string
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DBListener represents a listener record in the database
type DBListener struct {
	gorm.Model
	ListenerID string `gorm:"uniqueIndex;not null"`
	Address    string `gorm:"not null"`
	Type       string
	CertFile   string // Certificate file path
	KeyFile    string // Key file path
	CaFile     string // CA file path
	StartedAt  time.Time
	StoppedAt  *time.Time
	Status     string // "running", "stopped"
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// DBTask represents a task record in the database
type DBTask struct {
	gorm.Model
	TaskID    string `gorm:"uniqueIndex;not null"`
	ImplantID string `gorm:"not null"`
	Type      string
	Command   string
	Args      string // JSON encoded []string
	Data      []byte
	Timeout   int32
	Status    string // "queued", "sent", "completed", "failed"
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DBImplantBuild represents a record of generated implants with obfuscation details
type DBImplantBuild struct {
	gorm.Model
	BuildID          string `gorm:"uniqueIndex;not null"`
	ListenerID       string `gorm:"not null"`
	Filename         string
	Codename         string
	OS               string
	Arch             string
	Format           string
	ObfuscationLevel int
	ObfuscationTechs string // JSON encoded array of techniques applied
	BuildTime        time.Duration
	FileSize         int64
	SHA256Hash       string
	Debug            bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
