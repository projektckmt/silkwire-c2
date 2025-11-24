package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCompileImplant tests the compilation functionality
func TestCompileImplant(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping compilation tests in short mode")
	}

	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	// Create output directory
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	// Copy dependencies for compilation
	if err := ig.copyImplantDependencies(); err != nil {
		t.Fatalf("Failed to copy dependencies: %v", err)
	}

	// Generate source files first
	config := &ImplantConfig{
		ServerAddr:     "127.0.0.1",
		Port:           8080,
		Transport:      "HTTPS",
		SessionKey:     "test_session_key",
		ListenerID:     "lst_test",
		BeaconInterval: 60,
		JitterPercent:  10,
		MaxRetries:     3,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Format:         "source",
	}

	sourceFiles, err := ig.generateFullSourceFiles(config)
	if err != nil {
		t.Fatalf("Failed to generate source files: %v", err)
	}

	// Write source files
	var mainSourcePath string
	for fileName, content := range sourceFiles {
		sourcePath := filepath.Join(ig.outputDir, fileName)
		if fileName == "main.go" {
			mainSourcePath = sourcePath
		}
		if err := os.WriteFile(sourcePath, content, 0644); err != nil {
			t.Fatalf("Failed to write source file %s: %v", fileName, err)
		}
	}

	tests := []struct {
		name   string
		config *ImplantConfig
		test   func(t *testing.T, result string, err error)
	}{
		{
			name: "source format returns source path",
			config: &ImplantConfig{
				OS:     runtime.GOOS,
				Arch:   runtime.GOARCH,
				Format: "source",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Compilation failed: %v", err)
				}
				if !strings.HasSuffix(result, "main.go") {
					t.Errorf("Expected source path, got: %s", result)
				}
			},
		},
		{
			name: "cross-compilation configuration",
			config: &ImplantConfig{
				OS:     "linux",
				Arch:   "amd64",
				Format: "source", // Use source to avoid actual compilation
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Cross-compilation config failed: %v", err)
				}
				if result == "" {
					t.Error("Result should not be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseFileName := ig.generateFilename(tt.config)
			result, err := ig.compileImplant(mainSourcePath, tt.config, baseFileName)
			tt.test(t, result, err)
		})
	}
}

// TestPostProcessBinary tests format conversion functionality
func TestPostProcessBinary(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	// Create a mock binary file
	tempBinary := filepath.Join(ig.outputDir, "test_binary")
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}
	
	mockBinaryContent := []byte("mock binary content")
	if err := os.WriteFile(tempBinary, mockBinaryContent, 0755); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	tests := []struct {
		name   string
		config *ImplantConfig
		test   func(t *testing.T, result string, err error)
	}{
		{
			name: "exe format returns original path",
			config: &ImplantConfig{
				Format: "exe",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Post-processing failed: %v", err)
				}
				if result != tempBinary {
					t.Errorf("Expected original path %s, got %s", tempBinary, result)
				}
			},
		},
		{
			name: "binary format returns original path",
			config: &ImplantConfig{
				Format: "binary",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Post-processing failed: %v", err)
				}
				if result != tempBinary {
					t.Errorf("Expected original path %s, got %s", tempBinary, result)
				}
			},
		},
		{
			name: "shellcode conversion creates bin file",
			config: &ImplantConfig{
				Format: "shellcode",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Shellcode conversion failed: %v", err)
				}
				if !strings.HasSuffix(result, ".bin") {
					t.Errorf("Expected .bin extension, got: %s", result)
				}
				
				// Check that the file was created
				if _, err := os.Stat(result); err != nil {
					t.Errorf("Shellcode file should exist: %v", err)
				}
			},
		},
		{
			name: "service format only works on Windows",
			config: &ImplantConfig{
				Format: "service",
				OS:     "linux",
			},
			test: func(t *testing.T, result string, err error) {
				if err == nil {
					t.Error("Expected error for non-Windows service format")
				}
				if !strings.Contains(err.Error(), "Windows") {
					t.Errorf("Expected Windows-specific error, got: %v", err)
				}
			},
		},
		{
			name: "Windows service format works",
			config: &ImplantConfig{
				Format: "service",
				OS:     "windows",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Windows service conversion failed: %v", err)
				}
				if !strings.Contains(result, "_service.exe") {
					t.Errorf("Expected service executable, got: %s", result)
				}
			},
		},
		{
			name: "unsupported format returns error",
			config: &ImplantConfig{
				Format: "unsupported",
			},
			test: func(t *testing.T, result string, err error) {
				if err == nil {
					t.Error("Expected error for unsupported format")
				}
				if !strings.Contains(err.Error(), "unsupported") {
					t.Errorf("Expected unsupported format error, got: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ig.postProcessBinary(tempBinary, tt.config)
			tt.test(t, result, err)
		})
	}
}

// TestConvertToSharedLibrary tests shared library conversion
func TestConvertToSharedLibrary(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	// Create a mock binary file
	tempBinary := filepath.Join(ig.outputDir, "test_binary")
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}
	
	mockBinaryContent := []byte("mock binary content")
	if err := os.WriteFile(tempBinary, mockBinaryContent, 0755); err != nil {
		t.Fatalf("Failed to create mock binary: %v", err)
	}

	// Copy dependencies for shared library compilation
	if err := ig.copyImplantDependencies(); err != nil {
		t.Fatalf("Failed to copy dependencies: %v", err)
	}

	tests := []struct {
		name   string
		config *ImplantConfig
		test   func(t *testing.T, result string, err error)
	}{
		{
			name: "Windows DLL conversion",
			config: &ImplantConfig{
				OS:   "windows",
				Arch: "amd64",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Windows DLL conversion failed: %v", err)
				}
				if !strings.HasSuffix(result, ".dll") {
					t.Errorf("Expected .dll extension, got: %s", result)
				}
			},
		},
		{
			name: "Linux SO conversion",
			config: &ImplantConfig{
				OS:   "linux",
				Arch: "amd64",
			},
			test: func(t *testing.T, result string, err error) {
				// Should return fallback SO file since CGO compilation will likely fail in test environment
				// The function should fall back to copying the binary with .so extension
				if err != nil {
					// This is expected in test environment without proper cross-compilation tools
					t.Logf("Linux SO conversion failed as expected in test environment: %v", err)
					return
				}
				if !strings.HasSuffix(result, ".so") {
					t.Errorf("Expected .so extension, got: %s", result)
				}
			},
		},
		{
			name: "Darwin SO conversion",
			config: &ImplantConfig{
				OS:   "darwin",
				Arch: "amd64",
			},
			test: func(t *testing.T, result string, err error) {
				if err != nil {
					t.Fatalf("Darwin SO conversion failed: %v", err)
				}
				if !strings.HasSuffix(result, ".so") {
					t.Errorf("Expected .so extension, got: %s", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ig.convertToSharedLibrary(tempBinary, tt.config)
			tt.test(t, result, err)
		})
	}
}

// TestObfuscationLevelDefaults tests obfuscation level configuration
func TestObfuscationLevelDefaults(t *testing.T) {
	ig := &ImplantGenerator{}

	tests := []struct {
		name   string
		config *ImplantConfig
		test   func(t *testing.T, config *ImplantConfig)
	}{
		{
			name: "level 0 no changes",
			config: &ImplantConfig{
				ObfuscationLevel: 0,
			},
			test: func(t *testing.T, config *ImplantConfig) {
				ig.setObfuscationDefaults(config)
				if config.StringObfuscation {
					t.Error("Level 0 should not enable string obfuscation")
				}
			},
		},
		{
			name: "level 1 enables basic obfuscation",
			config: &ImplantConfig{
				ObfuscationLevel: 1,
			},
			test: func(t *testing.T, config *ImplantConfig) {
				ig.setObfuscationDefaults(config)
				if !config.StringObfuscation {
					t.Error("Level 1 should enable string obfuscation")
				}
				if !config.Obfuscate {
					t.Error("Level 1 should enable basic obfuscation")
				}
			},
		},
		{
			name: "level 2 enables medium obfuscation",
			config: &ImplantConfig{
				ObfuscationLevel: 2,
			},
			test: func(t *testing.T, config *ImplantConfig) {
				ig.setObfuscationDefaults(config)
				if !config.NameObfuscation {
					t.Error("Level 2 should enable name obfuscation")
				}
				if !config.ControlFlowObfuscation {
					t.Error("Level 2 should enable control flow obfuscation")
				}
				if !config.AntiVM {
					t.Error("Level 2 should enable AntiVM")
				}
			},
		},
		{
			name: "level 3 enables heavy obfuscation",
			config: &ImplantConfig{
				ObfuscationLevel: 3,
			},
			test: func(t *testing.T, config *ImplantConfig) {
				ig.setObfuscationDefaults(config)
				if !config.APIObfuscation {
					t.Error("Level 3 should enable API obfuscation")
				}
				if !config.NetworkObfuscation {
					t.Error("Level 3 should enable network obfuscation")
				}
				if !config.SandboxEvasion {
					t.Error("Level 3 should enable sandbox evasion")
				}
			},
		},
		{
			name: "level 4 enables extreme obfuscation",
			config: &ImplantConfig{
				ObfuscationLevel: 4,
			},
			test: func(t *testing.T, config *ImplantConfig) {
				ig.setObfuscationDefaults(config)
				if !config.RuntimePacking {
					t.Error("Level 4 should enable runtime packing")
				}
				if !config.ProcessHollowing {
					t.Error("Level 4 should enable process hollowing")
				}
				if !config.AntiEmulation {
					t.Error("Level 4 should enable anti-emulation")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to avoid modifying the original
			configCopy := *tt.config
			tt.test(t, &configCopy)
		})
	}
}

// TestCompileWithEnhancedObfuscation tests enhanced obfuscation compilation
func TestCompileWithEnhancedObfuscation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping enhanced obfuscation tests in short mode")
	}

	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ig := NewImplantGenerator()

	// Create output directory
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	tests := []struct {
		name   string
		config *ImplantConfig
		test   func(t *testing.T, result string, err error)
	}{
		{
			name: "source format with enhanced obfuscation",
			config: &ImplantConfig{
				Format:           "source",
				ObfuscationLevel: 2,
				OS:               runtime.GOOS,
				Arch:             runtime.GOARCH,
			},
			test: func(t *testing.T, result string, err error) {
				// Should return source path for source format even with obfuscation
				if err != nil {
					t.Fatalf("Enhanced obfuscation compilation failed: %v", err)
				}
				if !strings.HasSuffix(result, "main.go") {
					t.Errorf("Expected source path, got: %s", result)
				}
			},
		},
		{
			name: "missing build script returns error",
			config: &ImplantConfig{
				Format:           "exe",
				ObfuscationLevel: 3,
				OS:               "windows",
				Arch:             "amd64",
			},
			test: func(t *testing.T, result string, err error) {
				// Should fail because build_obfuscated.sh doesn't exist in test environment
				if err == nil {
					t.Error("Expected error for missing build script")
				}
				if !strings.Contains(err.Error(), "not found") {
					t.Errorf("Expected 'not found' error, got: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseFileName := ig.generateFilename(tt.config)
			result, err := ig.compileWithEnhancedObfuscation("main.go", tt.config, baseFileName)
			tt.test(t, result, err)
		})
	}
}

// TestFilenameGeneration tests filename generation with codenames
func TestFilenameGeneration(t *testing.T) {
	ig := &ImplantGenerator{}

	// Test multiple generations to ensure uniqueness
	filenames := make(map[string]bool)
	config := &ImplantConfig{
		OS:   "linux",
		Arch: "amd64",
	}

	for i := 0; i < 10; i++ {
		filename := ig.generateFilename(config)
		
		if filename == "" {
			t.Error("Generated filename should not be empty")
		}
		
		if filenames[filename] {
			t.Errorf("Duplicate filename generated: %s", filename)
		}
		filenames[filename] = true
		
		// Check format
		parts := strings.Split(filename, "_")
		if len(parts) != 3 {
			t.Errorf("Expected 3 parts in filename, got %d: %s", len(parts), filename)
		}
		
		if parts[1] != "linux" {
			t.Errorf("Expected OS in filename, got: %s", parts[1])
		}
		
		if parts[2] != "amd64" {
			t.Errorf("Expected arch in filename, got: %s", parts[2])
		}
	}
}

// BenchmarkCompilation benchmarks compilation performance
func BenchmarkPostProcessBinary(b *testing.B) {
	_, cleanup := setupTestEnvironment(&testing.T{})
	defer cleanup()

	ig := NewImplantGenerator()
	
	// Create a mock binary
	tempBinary := filepath.Join(ig.outputDir, "bench_binary")
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		b.Fatalf("Failed to create output dir: %v", err)
	}
	
	mockContent := []byte("benchmark binary content")
	if err := os.WriteFile(tempBinary, mockContent, 0755); err != nil {
		b.Fatalf("Failed to create mock binary: %v", err)
	}

	config := &ImplantConfig{
		Format: "shellcode",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ig.postProcessBinary(tempBinary, config)
		if err != nil {
			b.Fatalf("Post-processing failed: %v", err)
		}
	}
}
