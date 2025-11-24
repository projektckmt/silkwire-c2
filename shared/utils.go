package shared

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"
)

// GenerateID generates a random hex ID
func GenerateID(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateSessionToken generates a secure session token
func GenerateSessionToken() string {
	return GenerateID(32)
}

// GenerateImplantID generates a unique implant identifier
func GenerateImplantID() string {
	return GenerateID(4)
}

// GenerateCommandID generates a unique command identifier
func GenerateCommandID() string {
	return fmt.Sprintf("cmd_%d", time.Now().UnixNano())
}

// FormatDuration formats a duration for human-readable display
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	} else {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

var adjectives = []string{
	"Ancient", "Arctic", "Bold", "Brave", "Bright", "Calm", "Clever", "Cold",
	"Cool", "Crimson", "Dark", "Deep", "Dense", "Dim", "Distant", "Dry",
	"Electric", "Epic", "Fast", "Fierce", "Final", "Fire", "Fleet", "Frozen",
	"Ghost", "Giant", "Golden", "Gray", "Green", "Heavy", "Hidden", "High",
	"Iron", "Laser", "Light", "Lone", "Lost", "Loud", "Magic", "Mega",
	"Metal", "Micro", "Neon", "Night", "Noble", "North", "Nuclear", "Ocean",
	"Omega", "Pale", "Prime", "Pure", "Quick", "Quiet", "Rapid", "Red",
	"Royal", "Sacred", "Shadow", "Sharp", "Silent", "Silver", "Sky", "Smooth",
	"Solar", "Sonic", "Space", "Steel", "Stone", "Storm", "Swift", "Toxic",
	"Ultra", "Void", "War", "White", "Wild", "Wind", "Winter", "Zero",
}

var nouns = []string{
	"Alpha", "Angel", "Arrow", "Axe", "Bear", "Beast", "Bird", "Blade",
	"Bolt", "Comet", "Crow", "Crown", "Dragon", "Eagle", "Echo", "Falcon",
	"Fire", "Flame", "Fox", "Ghost", "Hawk", "Hunter", "Ice", "Jaguar",
	"Knight", "Lance", "Lightning", "Lion", "Moon", "Phoenix", "Raven", "River",
	"Rocket", "Saber", "Serpent", "Shadow", "Shield", "Snake", "Spark", "Spear",
	"Spider", "Star", "Stone", "Storm", "Sun", "Sword", "Thunder", "Tiger",
	"Titan", "Torch", "Tower", "Viper", "Warrior", "Wave", "Wind", "Wolf",
	"Warden", "Wraith", "Zephyr", "Fury", "Frost", "Gale", "Guardian", "Hammer",
}

// GenerateCodename generates a unique military-style codename for sessions
func GenerateCodename() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	
	// Use the random bytes to select adjective and noun
	adjIdx := int(bytes[0])%len(adjectives) + int(bytes[1])%len(adjectives)
	adjIdx = int(math.Abs(float64(adjIdx))) % len(adjectives)
	
	nounIdx := int(bytes[2])%len(nouns) + int(bytes[3])%len(nouns)
	nounIdx = int(math.Abs(float64(nounIdx))) % len(nouns)

	return strings.ToUpper(fmt.Sprintf("%s%s", adjectives[adjIdx], nouns[nounIdx]))
}
