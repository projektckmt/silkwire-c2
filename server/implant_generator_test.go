package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"silkwire/shared"
)

// TestImplantConfig represents test data for implant configuration
// Note: This struct is kept for potential future use but not currently utilized
// in the current test implementation which uses inline test cases instead

// setupTestEnvironment creates a temporary directory structure for testing
func setupTestEnvironment(t *testing.T) (string, func()) {
	t.Helper()

	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "implant_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create mock implant directory structure
	implantDir := filepath.Join(tempDir, "implant")
	if err := os.MkdirAll(implantDir, 0755); err != nil {
		t.Fatalf("Failed to create implant dir: %v", err)
	}

	// Create mock template files
	createMockTemplateFiles(t, implantDir)

	// Create mock dependencies
	createMockDependencies(t, tempDir)

	// Change to test directory
	originalWd, _ := os.Getwd()
	os.Chdir(tempDir)

	// Return cleanup function
	cleanup := func() {
		os.Chdir(originalWd)
		os.RemoveAll(tempDir)
	}

	return tempDir, cleanup
}

// createMockTemplateFiles creates mock template files for testing
func createMockTemplateFiles(t *testing.T, implantDir string) {
	t.Helper()

	// Create main.go template
	mainGoContent := `package main

import (
	"fmt"
	"silkwire/proto"
	"silkwire/shared"
)

func main() {
	fmt.Println("Implant started")
	fmt.Println("Server: {{.ServerAddr}}:{{.Port}}")
	fmt.Println("Transport: {{.Transport}}")
	fmt.Println("Session Key: {{.SessionKey}}")
	fmt.Println("Listener ID: {{.ListenerID}}")
	fmt.Println("Beacon Interval: {{.BeaconInterval}}")
	fmt.Println("Jitter: {{.JitterPercent}}%")
}`

	if err := os.WriteFile(filepath.Join(implantDir, "main.go"), []byte(mainGoContent), 0644); err != nil {
		t.Fatalf("Failed to create main.go: %v", err)
	}

	// Create implant.go template
	implantGoContent := `package main

import (
	"context"
	"time"
)

type Implant struct {
	ServerAddr string
	Port       int
	Transport  string
	SessionKey string
	ListenerID string
	BeaconInterval int32
	JitterPercent  int32
	Debug      bool
}

func NewImplant() *Implant {
	return &Implant{
		ServerAddr: "{{.ServerAddr}}",
		Port:       {{.Port}},
		Transport:  "{{.Transport}}",
		SessionKey: "{{.SessionKey}}",
		ListenerID: "{{.ListenerID}}",
		BeaconInterval: {{.BeaconInterval}},
		JitterPercent:  {{.JitterPercent}},
		Debug:         {{.Debug}},
	}
}

func (i *Implant) Run(ctx context.Context) error {
	// Mock implant implementation
	return nil
}`

	if err := os.WriteFile(filepath.Join(implantDir, "implant.go"), []byte(implantGoContent), 0644); err != nil {
		t.Fatalf("Failed to create implant.go: %v", err)
	}

	// Create go.mod for implant
	goModContent := `module silkwire/implant

go 1.24.4

require (
	silkwire/proto v0.0.0
	silkwire/shared v0.0.0
)

replace silkwire/proto => ../proto
replace silkwire/shared => ../shared
`

	if err := os.WriteFile(filepath.Join(implantDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to create go.mod: %v", err)
	}
}

// createMockDependencies creates mock shared and proto directories
func createMockDependencies(t *testing.T, tempDir string) {
	t.Helper()

	// Create shared directory
	sharedDir := filepath.Join(tempDir, "shared")
	if err := os.MkdirAll(sharedDir, 0755); err != nil {
		t.Fatalf("Failed to create shared dir: %v", err)
	}

	// Create utils.go
	utilsContent := `package shared

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func GenerateID(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func GenerateImplantID() string {
	return GenerateID(4)
}

func GenerateCodename() string {
	return "TestCodename"
}
`

	if err := os.WriteFile(filepath.Join(sharedDir, "utils.go"), []byte(utilsContent), 0644); err != nil {
		t.Fatalf("Failed to create utils.go: %v", err)
	}

	// Create types.go
	typesContent := `package shared

type Config struct {
	Debug bool
}
`

	if err := os.WriteFile(filepath.Join(sharedDir, "types.go"), []byte(typesContent), 0644); err != nil {
		t.Fatalf("Failed to create types.go: %v", err)
	}

	// Create proto directory
	protoDir := filepath.Join(tempDir, "proto")
	if err := os.MkdirAll(protoDir, 0755); err != nil {
		t.Fatalf("Failed to create proto dir: %v", err)
	}

	// Create mock proto files
	c2pbContent := `package proto

type C2Request struct {
	SessionID string
	Command   string
}

type C2Response struct {
	SessionID string
	Result    string
}
`

	if err := os.WriteFile(filepath.Join(protoDir, "c2.pb.go"), []byte(c2pbContent), 0644); err != nil {
		t.Fatalf("Failed to create c2.pb.go: %v", err)
	}

	grpcContent := `package proto

// Mock gRPC definitions
type C2ServiceClient interface {
	Execute(req *C2Request) (*C2Response, error)
}
`

	if err := os.WriteFile(filepath.Join(protoDir, "c2_grpc.pb.go"), []byte(grpcContent), 0644); err != nil {
		t.Fatalf("Failed to create c2_grpc.pb.go: %v", err)
	}

	// Create go.mod files for dependencies
	sharedGoMod := `module silkwire/shared

go 1.24.4
`
	if err := os.WriteFile(filepath.Join(sharedDir, "go.mod"), []byte(sharedGoMod), 0644); err != nil {
		t.Fatalf("Failed to create shared go.mod: %v", err)
	}

	protoGoMod := `module silkwire/proto

go 1.24.4
`
	if err := os.WriteFile(filepath.Join(protoDir, "go.mod"), []byte(protoGoMod), 0644); err != nil {
		t.Fatalf("Failed to create proto go.mod: %v", err)
	}

	// Create main project go.mod
	mainGoMod := `module silkwire

go 1.24.4

require (
	silkwire/proto v0.0.0
	silkwire/shared v0.0.0
)

replace silkwire/proto => ./proto
replace silkwire/shared => ./shared
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(mainGoMod), 0644); err != nil {
		t.Fatalf("Failed to create main go.mod: %v", err)
	}
}

// TestNewImplantGenerator tests the constructor
func TestNewImplantGenerator(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "creates generator with correct paths",
			test: func(t *testing.T) {
				ig := NewImplantGenerator()

				if ig == nil {
					t.Fatal("NewImplantGenerator returned nil")
				}

				if ig.templateDir == "" {
					t.Error("templateDir should not be empty")
				}

				if ig.outputDir == "" {
					t.Error("outputDir should not be empty")
				}

				if !strings.Contains(ig.outputDir, "generated") {
					t.Errorf("outputDir should contain 'generated', got: %s", ig.outputDir)
				}
			},
		},
		{
			name: "resolves template directory correctly",
			test: func(t *testing.T) {
				ig := NewImplantGenerator()

				// Should find the implant directory
				if !strings.HasSuffix(ig.templateDir, "implant") {
					t.Errorf("Expected templateDir to end with 'implant', got: %s", ig.templateDir)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

// TestImplantConfigDefaults tests configuration validation and defaults
func TestImplantConfigDefaults(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name     string
		config   *ImplantConfig
		expected map[string]interface{}
	}{
		{
			name: "sets default beacon interval",
			config: &ImplantConfig{
				ServerAddr: "127.0.0.1",
				Port:       8080,
				Transport:  "HTTPS",
			},
			expected: map[string]interface{}{
				"BeaconInterval": int32(60),
				"JitterPercent":  int32(10),
				"MaxRetries":     int32(3),
			},
		},
		{
			name: "preserves custom values",
			config: &ImplantConfig{
				ServerAddr:     "192.168.1.1",
				Port:           9090,
				Transport:      "HTTP",
				BeaconInterval: 30,
				JitterPercent:  20,
				MaxRetries:     5,
			},
			expected: map[string]interface{}{
				"BeaconInterval": int32(30),
				"JitterPercent":  int32(20),
				"MaxRetries":     int32(5),
			},
		},
		{
			name: "generates session key and listener ID",
			config: &ImplantConfig{
				ServerAddr: "127.0.0.1",
				Port:       8080,
				Transport:  "HTTPS",
			},
			expected: map[string]interface{}{
				"SessionKeyNotEmpty":  true,
				"ListenerIDNotEmpty":  true,
				"ListenerIDHasPrefix": "lst_",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the config to avoid modifying the original
			config := *tt.config

			// Set defaults (this happens in GenerateImplant)
			if config.SessionKey == "" {
				config.SessionKey = "test_session_key"
			}
			if config.ListenerID == "" {
				config.ListenerID = "lst_" + shared.GenerateImplantID()
			}
			if config.BeaconInterval == 0 {
				config.BeaconInterval = 120
			}
			if config.JitterPercent == 0 {
				config.JitterPercent = 10
			}
			if config.MaxRetries == 0 {
				config.MaxRetries = 1000 // Very high retry count for persistence
			}

			// Check expected values
			for key, expected := range tt.expected {
				switch key {
				case "BeaconInterval":
					if config.BeaconInterval != expected.(int32) {
						t.Errorf("Expected BeaconInterval %d, got %d", expected.(int32), config.BeaconInterval)
					}
				case "JitterPercent":
					if config.JitterPercent != expected.(int32) {
						t.Errorf("Expected JitterPercent %d, got %d", expected.(int32), config.JitterPercent)
					}
				case "MaxRetries":
					if config.MaxRetries != expected.(int32) {
						t.Errorf("Expected MaxRetries %d, got %d", expected.(int32), config.MaxRetries)
					}
				case "SessionKeyNotEmpty":
					if config.SessionKey == "" {
						t.Error("SessionKey should not be empty")
					}
				case "ListenerIDNotEmpty":
					if config.ListenerID == "" {
						t.Error("ListenerID should not be empty")
					}
				case "ListenerIDHasPrefix":
					if !strings.HasPrefix(config.ListenerID, expected.(string)) {
						t.Errorf("ListenerID should start with %s, got %s", expected.(string), config.ListenerID)
					}
				}
			}
		})
	}
}

// TestGenerateFullSourceFiles tests template processing
func TestGenerateFullSourceFiles(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	config := &ImplantConfig{
		ServerAddr:     "192.168.1.100",
		Port:           9443,
		Transport:      "HTTPS",
		SessionKey:     "test_session_key_12345",
		ListenerID:     "lst_test123",
		BeaconInterval: 45,
		JitterPercent:  15,
		MaxRetries:     2,
		OS:             "linux",
		Arch:           "amd64",
		Debug:          true,
	}

	sourceFiles, err := ig.generateFullSourceFiles(config)
	if err != nil {
		t.Fatalf("generateFullSourceFiles failed: %v", err)
	}

	tests := []struct {
		name     string
		filename string
		test     func(t *testing.T, content []byte)
	}{
		{
			name:     "generates main.go with correct substitutions",
			filename: "main.go",
			test: func(t *testing.T, content []byte) {
				contentStr := string(content)

				expectedSubstitutions := map[string]string{
					"192.168.1.100":          "ServerAddr",
					"9443":                   "Port",
					"HTTPS":                  "Transport",
					"test_session_key_12345": "SessionKey",
					"lst_test123":            "ListenerID",
					"45":                     "BeaconInterval",
					"15":                     "JitterPercent",
				}

				for expected, field := range expectedSubstitutions {
					if !strings.Contains(contentStr, expected) {
						t.Errorf("Expected %s substitution for %s not found in main.go", expected, field)
					}
				}
			},
		},
		{
			name:     "generates implant.go with correct substitutions",
			filename: "implant.go",
			test: func(t *testing.T, content []byte) {
				contentStr := string(content)

				if !strings.Contains(contentStr, "192.168.1.100") {
					t.Error("ServerAddr substitution not found in implant.go")
				}

				if !strings.Contains(contentStr, "9443") {
					t.Error("Port substitution not found in implant.go")
				}
			},
		},
		{
			name:     "corrects import paths",
			filename: "main.go",
			test: func(t *testing.T, content []byte) {
				contentStr := string(content)

				// Should use corrected import path
				if strings.Contains(contentStr, "silkwire/proto/c2pb") {
					t.Error("Import path should be corrected to silkwire/proto")
				}

				if !strings.Contains(contentStr, "silkwire/proto") {
					t.Error("Expected corrected import path silkwire/proto")
				}
			},
		},
		{
			name:     "formats go source correctly",
			filename: "main.go",
			test: func(t *testing.T, content []byte) {
				// Basic syntax check - should not contain template syntax
				contentStr := string(content)
				if strings.Contains(contentStr, "{{") || strings.Contains(contentStr, "}}") {
					t.Error("Template syntax should be resolved")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, exists := sourceFiles[tt.filename]
			if !exists {
				t.Fatalf("Expected file %s not generated", tt.filename)
			}

			tt.test(t, content)
		})
	}

	// Test that test files are excluded
	for filename := range sourceFiles {
		if strings.HasSuffix(filename, "_test.go") {
			t.Errorf("Test file %s should be excluded", filename)
		}
	}
}

// TestGenerateFilename tests filename generation
func TestGenerateFilename(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	tests := []struct {
		name   string
		config *ImplantConfig
		test   func(t *testing.T, filename string)
	}{
		{
			name: "generates filename with OS and arch",
			config: &ImplantConfig{
				OS:   "windows",
				Arch: "amd64",
			},
			test: func(t *testing.T, filename string) {
				if !strings.Contains(filename, "windows") {
					t.Error("Filename should contain OS")
				}
				if !strings.Contains(filename, "amd64") {
					t.Error("Filename should contain arch")
				}
				if !strings.Contains(filename, "_") {
					t.Error("Filename should contain separators")
				}
			},
		},
		{
			name: "generates unique filenames",
			config: &ImplantConfig{
				OS:   "linux",
				Arch: "arm64",
			},
			test: func(t *testing.T, filename string) {
				// Generate another filename and ensure they're different
				filename2 := ig.generateFilename(&ImplantConfig{
					OS:   "linux",
					Arch: "arm64",
				})
				if filename == filename2 {
					t.Error("Generated filenames should be unique")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := ig.generateFilename(tt.config)
			if filename == "" {
				t.Fatal("Generated filename should not be empty")
			}
			tt.test(t, filename)
		})
	}
}

// TestGetExecutableExtension tests platform-specific extensions
func TestGetExecutableExtension(t *testing.T) {
	ig := &ImplantGenerator{}

	tests := []struct {
		os       string
		expected string
	}{
		{"windows", ".exe"},
		{"linux", ""},
		{"darwin", ""},
		{"freebsd", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("OS_%s", tt.os), func(t *testing.T) {
			ext := ig.getExecutableExtension(tt.os)
			if ext != tt.expected {
				t.Errorf("Expected extension %s for OS %s, got %s", tt.expected, tt.os, ext)
			}
		})
	}
}

// TestShouldUseEnhancedObfuscation tests obfuscation detection
func TestShouldUseEnhancedObfuscation(t *testing.T) {
	ig := &ImplantGenerator{}

	tests := []struct {
		name     string
		config   *ImplantConfig
		expected bool
	}{
		{
			name:     "no obfuscation",
			config:   &ImplantConfig{},
			expected: false,
		},
		{
			name: "obfuscation level set",
			config: &ImplantConfig{
				ObfuscationLevel: 2,
			},
			expected: true,
		},
		{
			name: "string obfuscation enabled",
			config: &ImplantConfig{
				StringObfuscation: true,
			},
			expected: true,
		},
		{
			name: "advanced evasion enabled",
			config: &ImplantConfig{
				ProcessHollowing: true,
			},
			expected: true,
		},
		{
			name: "multiple features enabled",
			config: &ImplantConfig{
				APIObfuscation:     true,
				NetworkObfuscation: true,
				SandboxEvasion:     true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ig.shouldUseEnhancedObfuscation(tt.config)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestListGeneratedImplants tests listing functionality
func TestListGeneratedImplants(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	// Create output directory
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	// Create some test files
	testFiles := []string{
		"implant_test.exe",
		"test.dll",
		"payload.so",
		"shellcode.bin",
		"other.txt", // Should be excluded
	}

	for _, file := range testFiles {
		path := filepath.Join(ig.outputDir, file)
		if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	implants, err := ig.ListGeneratedImplants()
	if err != nil {
		t.Fatalf("ListGeneratedImplants failed: %v", err)
	}

	expectedFiles := []string{"implant_test.exe", "test.dll", "payload.so", "shellcode.bin"}

	if len(implants) != len(expectedFiles) {
		t.Errorf("Expected %d implants, got %d", len(expectedFiles), len(implants))
	}

	for _, expected := range expectedFiles {
		found := false
		for _, actual := range implants {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected file %s not found in results", expected)
		}
	}

	// Should not include other.txt
	for _, actual := range implants {
		if actual == "other.txt" {
			t.Error("other.txt should not be included in implant list")
		}
	}
}

// TestCleanupGenerated tests cleanup functionality
func TestCleanupGenerated(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	// Create output directory
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	// Create test files with different ages
	oldFile := filepath.Join(ig.outputDir, "old_implant.exe")
	newFile := filepath.Join(ig.outputDir, "new_implant.exe")

	// Create old file
	if err := os.WriteFile(oldFile, []byte("old"), 0644); err != nil {
		t.Fatalf("Failed to create old file: %v", err)
	}

	// Create new file
	if err := os.WriteFile(newFile, []byte("new"), 0644); err != nil {
		t.Fatalf("Failed to create new file: %v", err)
	}

	// Manually set old file's modification time
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatalf("Failed to set old file time: %v", err)
	}

	// Cleanup files older than 1 hour
	err := ig.CleanupGenerated(1 * time.Hour)
	if err != nil {
		t.Fatalf("CleanupGenerated failed: %v", err)
	}

	// Old file should be removed
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("Old file should have been removed")
	}

	// New file should still exist
	if _, err := os.Stat(newFile); err != nil {
		t.Error("New file should still exist")
	}
}

// TestCopyImplantDependencies tests dependency copying
func TestCopyImplantDependencies(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	// Create output directory
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	err := ig.copyImplantDependencies()
	if err != nil {
		t.Fatalf("copyImplantDependencies failed: %v", err)
	}

	// Check that go.mod was copied
	goModPath := filepath.Join(ig.outputDir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		t.Error("go.mod should be copied")
	}

	// Check that proto directory was created
	protoDir := filepath.Join(ig.outputDir, "proto")
	if _, err := os.Stat(protoDir); err != nil {
		t.Error("proto directory should be created")
	}

	// Check that shared directory was created
	sharedDir := filepath.Join(ig.outputDir, "shared")
	if _, err := os.Stat(sharedDir); err != nil {
		t.Error("shared directory should be created")
	}

	// Check specific files
	requiredFiles := []string{
		"proto/c2.pb.go",
		"proto/c2_grpc.pb.go",
		"shared/utils.go",
		"shared/types.go",
	}

	for _, file := range requiredFiles {
		path := filepath.Join(ig.outputDir, file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("Required file %s should be copied", file)
		}
	}
}

// TestErrorHandling tests various error conditions
func TestErrorHandling(t *testing.T) {
	tempDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "invalid template directory",
			test: func(t *testing.T) {
				ig := &ImplantGenerator{
					templateDir: "/nonexistent/directory",
					outputDir:   tempDir,
				}

				config := &ImplantConfig{
					ServerAddr: "127.0.0.1",
					Port:       8080,
					Transport:  "HTTPS",
				}

				_, err := ig.generateFullSourceFiles(config)
				if err == nil {
					t.Error("Expected error for invalid template directory")
				}
			},
		},
		{
			name: "read-only output directory",
			test: func(t *testing.T) {
				readOnlyDir := filepath.Join(tempDir, "readonly")
				if err := os.MkdirAll(readOnlyDir, 0444); err != nil {
					t.Skipf("Cannot create read-only directory: %v", err)
				}

				ig := &ImplantGenerator{
					templateDir: filepath.Join(tempDir, "implant"),
					outputDir:   readOnlyDir,
				}

				config := &ImplantConfig{
					ServerAddr: "127.0.0.1",
					Port:       8080,
					Transport:  "HTTPS",
					Format:     "source",
				}

				_, err := ig.GenerateImplant(config)
				if err == nil {
					t.Error("Expected error for read-only output directory")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

// TestGenerateImplantIntegration tests the complete implant generation flow
func TestGenerateImplantIntegration(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	tests := []struct {
		name   string
		config *ImplantConfig
		test   func(t *testing.T, result string, err error)
	}{
		{
			name: "basic source generation",
			config: &ImplantConfig{
				ServerAddr: "192.168.1.1",
				Port:       8443,
				Transport:  "HTTPS",
				OS:         "linux",
				Arch:       "amd64",
				Format:     "source",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("GenerateImplant failed: %v", err)
				}

				if result == "" {
					t.Error("Result should not be empty")
				}

				if !strings.HasSuffix(result, "main.go") {
					t.Error("Result should point to main.go for source format")
				}
			},
		},
		{
			name: "with obfuscation options",
			config: &ImplantConfig{
				ServerAddr:        "10.0.0.1",
				Port:              9000,
				Transport:         "HTTP",
				OS:                "windows",
				Arch:              "amd64",
				Format:            "source",
				StringObfuscation: true,
				AntiVM:            true,
				AntiDebug:         true,
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("GenerateImplant with obfuscation failed: %v", err)
				}

				if result == "" {
					t.Error("Result should not be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ig.GenerateImplant(tt.config)
			tt.test(t, result, err)
		})
	}
}

// Benchmark tests for performance
func BenchmarkGenerateImplant(b *testing.B) {
	_, cleanup := setupTestEnvironment(&testing.T{})
	defer cleanup()

	ig := NewImplantGenerator()
	config := &ImplantConfig{
		ServerAddr: "127.0.0.1",
		Port:       8080,
		Transport:  "HTTPS",
		OS:         "linux",
		Arch:       "amd64",
		Format:     "source",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ig.GenerateImplant(config)
		if err != nil {
			b.Fatalf("GenerateImplant failed: %v", err)
		}
	}
}

func BenchmarkGenerateFullSourceFiles(b *testing.B) {
	_, cleanup := setupTestEnvironment(&testing.T{})
	defer cleanup()

	ig := NewImplantGenerator()
	config := &ImplantConfig{
		ServerAddr: "127.0.0.1",
		Port:       8080,
		Transport:  "HTTPS",
		OS:         "linux",
		Arch:       "amd64",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ig.generateFullSourceFiles(config)
		if err != nil {
			b.Fatalf("generateFullSourceFiles failed: %v", err)
		}
	}
}
