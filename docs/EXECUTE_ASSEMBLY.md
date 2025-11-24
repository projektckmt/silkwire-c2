# Execute-Assembly Feature

## Overview

Silkwire's **execute-assembly** feature enables in-memory execution of .NET assemblies on compromised Windows systems without writing files to disk. This implementation is inspired by Sliver's approach and provides two execution modes for flexibility and operational security.

## Execution Modes

### 1. Standard Mode (Sacrificial Process)

**Default behavior** - Spawns a sacrificial process and injects the assembly for maximum stability.

**Characteristics:**
- ✅ Safe: Won't crash the implant if assembly exits or throws exceptions
- ✅ Stable: Isolated from implant process
- ⚠️ More detectable: Creates process relationships
- ⚠️ Visible: Shows up in process tree

**Default sacrificial process:** `C:\Windows\System32\notepad.exe`

### 2. In-Process Mode

Execute assembly directly within the implant process for stealth.

**Characteristics:**
- ✅ Stealthier: No new processes spawned
- ✅ Less detectable: No suspicious parent/child relationships
- ⚠️ Risky: Assembly crashes/exits will kill the implant
- ⚠️ ETW may detect .NET CLR loading

**Usage:** Add `-i` or `--in-process` flag

## Architecture

### Server-Side Processing

1. **Donut Conversion**: Server converts .NET assembly to position-independent shellcode using go-donut
   - Reduces implant size (no need for Donut library on target)
   - Shellcode includes CLR bootstrap loader
   - Supports both EXE and DLL assemblies

2. **Bypass Integration**: Automatic AMSI and ETW bypasses enabled by default
   - AMSI bypass prevents signature detection
   - ETW bypass evades event tracing

3. **gRPC Transmission**: Shellcode sent to implant via encrypted gRPC channel

### Implant-Side Execution

**Standard Mode:**
1. Spawn sacrificial process (suspended)
2. Inject Donut shellcode into process memory
3. Resume process to execute assembly
4. Capture stdout/stderr
5. Return results to operator

**In-Process Mode:**
1. Allocate RWX memory in implant process
2. Copy Donut shellcode to memory
3. Create thread to execute shellcode
4. Capture stdout/stderr via pipe redirection
5. Return results to operator

## Usage Examples

### Basic Execution

```bash
# Execute Seatbelt with system enumeration
execute-assembly Seatbelt.exe -group=system

# Execute SharpHound for BloodHound
execute-assembly SharpHound.exe -c All
```

### In-Process Mode (Stealthier)

```bash
# Execute in implant process (stealthier but riskier)
execute-assembly -i SharpHound.exe -c All

# In-process with custom runtime
execute-assembly -i --runtime v4.0.30319 Rubeus.exe kerberoast
```

### Custom Sacrificial Process

```bash
# Use cmd.exe as sacrificial process
execute-assembly -p C:\Windows\System32\cmd.exe Seatbelt.exe

# Use Windows binary for better blending
execute-assembly -p C:\Windows\System32\mmc.exe SharpUp.exe
```

### PPID Spoofing

```bash
# Make assembly appear as child of explorer.exe (PID 1234)
execute-assembly --ppid 1234 Rubeus.exe kerberoast

# Combine PPID spoofing with custom process
execute-assembly --ppid 1234 -p C:\Windows\System32\svchost.exe SharpDPAPI.exe
```

### DLL Assembly Execution

```bash
# Execute DLL with specific class and method
execute-assembly --class MyNamespace.MyClass --method Run assembly.dll

# DLL with arguments
execute-assembly --class Utils --method Execute -p notepad.exe tool.dll arg1 arg2
```

### Advanced Options

```bash
# Custom AppDomain name
execute-assembly --appdomain "MyDomain" assembly.exe

# Disable AMSI bypass (not recommended)
execute-assembly --no-amsi Rubeus.exe

# Disable ETW bypass
execute-assembly --no-etw SharpHound.exe

# Specify .NET runtime version
execute-assembly --runtime v2.0.50727 legacy-tool.exe
```

## Command-Line Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-i, --in-process` | Execute in implant process (stealth mode) | `-i` |
| `-p, --process <path>` | Custom sacrificial process | `-p C:\Windows\System32\cmd.exe` |
| `--ppid <pid>` | Parent process ID for spoofing | `--ppid 1234` |
| `-c, --class <name>` | Class name for DLL assemblies | `-c MyNamespace.MyClass` |
| `-m, --method <name>` | Method name for DLL assemblies | `-m Execute` |
| `--appdomain <name>` | Custom AppDomain name | `--appdomain "MyDomain"` |
| `--runtime <version>` | .NET runtime version | `--runtime v4.0.30319` |
| `--no-amsi` | Disable AMSI bypass | `--no-amsi` |
| `--no-etw` | Disable ETW bypass | `--no-etw` |

## Technical Details

### Donut Configuration

**Server-side conversion** (`server/donut.go`):
- Architecture: x64 (x86 support can be added)
- Module Type: Auto-detected (EXE vs DLL)
- Compression: Enabled (reduces shellcode size)
- Entropy: Default encryption
- ExitOpt: 0 (prevents process termination)

### Output Capture

Both execution modes capture:
- **stdout**: Standard output from assembly
- **stderr**: Error output
- Timeout: 120 seconds default
- Pipe-based redirection for real-time capture

### Process Injection Techniques

**Standard Mode:**
- `VirtualAllocEx` for memory allocation
- `WriteProcessMemory` for shellcode writing
- `CreateRemoteThread` for execution
- Process creation flags: `CREATE_SUSPENDED`

**PPID Spoofing:**
- Uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`
- Requires `EXTENDED_STARTUPINFO_PRESENT` flag
- Opens handle to target parent process
- Updates process attribute list before creation

**In-Process Mode:**
- `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`
- Thread creation with shellcode entry point
- Pipe redirection for stdout/stderr

## Operational Security Considerations

### Standard Mode Detection Vectors

1. **Process Relationships**: Suspicious parent/child chains
   - Mitigation: Use PPID spoofing with legitimate parent
   
2. **Short-Lived Processes**: notepad.exe spawning and dying quickly
   - Mitigation: Use custom process that makes sense in environment
   
3. **Memory Signatures**: RWX memory regions with .NET artifacts
   - Mitigation: Built-in obfuscation, consider custom allocations
   
4. **AppDomains**: .NET domains not backed by files
   - Mitigation: Use in-process mode or custom AppDomain names

### In-Process Mode Detection Vectors

1. **CLR Loading**: .NET runtime loaded in unexpected process
   - Mitigation: Limited; ETW can detect this
   
2. **ETW Events**: .NET provider subscriptions
   - Mitigation: ETW bypass enabled by default
   
3. **AMSI Scanning**: Assembly content inspection
   - Mitigation: AMSI bypass enabled by default

## Compatible Tools

Silkwire execute-assembly works with most offensive .NET tools:

### Reconnaissance
- **Seatbelt**: System enumeration
- **SharpHound**: BloodHound data collection
- **SharpView**: Active Directory enumeration

### Credential Access
- **Rubeus**: Kerberos attacks
- **SharpDPAPI**: DPAPI secret extraction
- **SharpChrome**: Browser credential harvesting

### Privilege Escalation
- **SharpUp**: Privilege escalation checks
- **Watson**: Patch enumeration

### Lateral Movement
- **SharpWMI**: WMI command execution
- **SharpRDP**: RDP session management

### Persistence
- **SharPersist**: Persistence mechanism installation

## Troubleshooting

### Assembly Fails to Execute

**Symptoms**: No output or error message
**Solutions**:
- Check .NET version compatibility (use `--runtime` flag)
- Try in-process mode if sacrificial process fails
- Verify assembly is not corrupted

### Implant Crashes (In-Process Mode)

**Symptoms**: Implant session dies after execute-assembly
**Cause**: Assembly called `Environment.Exit()` or threw unhandled exception
**Solution**: Use standard mode (sacrificial process) instead

### AMSI Detection

**Symptoms**: Assembly blocked or detected
**Solutions**:
- Ensure AMSI bypass is enabled (default)
- Obfuscate assembly before execution
- Use different execution technique

### Output Not Captured

**Symptoms**: Command succeeds but no output
**Cause**: Assembly may write to different stream or file
**Solutions**:
- Check if assembly has verbose/debug flags
- Try different assembly version
- Review assembly source if available

## Comparison with Sliver

| Feature | Silkwire | Sliver |
|---------|----------|--------|
| In-process execution | ✅ Yes | ✅ Yes |
| Sacrificial process | ✅ Yes | ✅ Yes |
| PPID spoofing | ✅ Yes | ✅ Yes |
| DLL execution | ✅ Yes | ✅ Yes |
| Server-side Donut | ✅ Yes | ✅ Yes |
| AMSI bypass | ✅ Yes | ✅ Yes |
| ETW bypass | ✅ Yes | ✅ Yes |
| Custom process | ✅ Yes | ✅ Yes |
| AppDomain naming | ✅ Yes | ✅ Yes |
| Output capture | ✅ Yes | ✅ Yes |

## Implementation Files

- **Protobuf**: `proto/c2.proto` - Execute-assembly message definitions
- **Server Donut**: `server/donut.go` - Assembly to shellcode conversion
- **Server Handler**: `server/handlers.go` - Command routing
- **Implant Windows**: `implant/dotnet_windows.go` - Windows execution logic
- **Implant Injection**: `implant/injection_windows.go` - PPID spoofing
- **Console**: `console/commands.go` - Operator interface

## References

- [Donut Project](https://github.com/TheWover/donut) - Position-independent code generator
- [go-donut](https://github.com/Binject/go-donut) - Go implementation used by Silkwire
- [Sliver](https://github.com/BishopFox/sliver) - Inspiration for implementation
- [GhostPack](https://github.com/GhostPack) - Offensive .NET tool suite
