# Sacrificial Process Execute-Assembly Implementation

## Overview

This document describes the Sacrificial Process Execute-Assembly implementation in SilkWire, which follows the same approach as Merlin C2 for executing .NET assemblies in an isolated sacrificial process.

## Implementation Status

✅ **COMPLETE** - Full Merlin-style sacrificial process execute-assembly is implemented

## Key Components

### 1. Shellcode Injection via CreateRemoteThread (`implant/injection_windows.go`)

**Function:** `SpawnInjectAndWait()` (lines 3611-3911)

This function implements the standard Merlin/Donut injection technique:

```
Process Flow:
1. CreateProcess with SUSPENDED flag + pipe handles for I/O
2. VirtualAllocEx - Allocate RW memory in target process
3. WriteProcessMemory - Write Donut shellcode to allocated memory
4. VirtualProtectEx - Change memory protection to PAGE_EXECUTE_READ
5. CreateRemoteThread - Create new thread starting at shellcode address
6. ResumeThread - Resume the main process thread (for normal process behavior)
7. WaitForSingleObject - Wait for process completion (5 min timeout)
8. Capture output from pipes asynchronously
```

**Why CreateRemoteThread instead of Entry Point Hijacking:**
- CreateRemoteThread provides a clean thread context that Donut expects
- Entry point hijacking can cause ACCESS_VIOLATION with Donut shellcode
- This is the standard approach used by Merlin C2 and other frameworks
- More compatible with CLR loading and .NET assembly execution

**Alternative Technique Available:**
The `hijackEntryPoint()` function (lines 3914-4033) implements entry point hijacking
but is not used for execute-assembly due to Donut compatibility issues.

### 2. Process Creation with Output Capture (`implant/injection_windows.go`)

**Function:** `SpawnInjectAndWait()` (lines 3613-3893)

This function creates the sacrificial process with proper I/O redirection:

```
1. Create anonymous pipes for STDOUT/STDERR
2. Configure StartupInfo with STARTF_USESTDHANDLES
3. Create suspended process (with optional PPID spoofing)
4. Close write ends of pipes in parent
5. Allocate memory in child process (RW)
6. Write Donut shellcode to allocated memory
7. Change memory protection to RX (better OPSEC)
8. Create remote thread pointing to shellcode (Merlin approach)
9. Start async goroutines to read pipes (prevents deadlock)
10. Resume main thread (allows normal process behavior)
11. Wait for process completion (5 minute timeout)
12. Collect all output from pipe channels
13. Return output + exit code
```

### 3. Default Configuration (`implant/dotnet_windows.go`)

**Function:** `ExecuteAssemblySacrificial()` (lines 46-137)

- **Default Sacrificial Process:** `C:\Windows\System32\dllhost.exe`
  - COM Surrogate Host - legitimately hosts external code
  - Frequently spawned by Windows
  - Compatible with Donut shellcode and CLR hosting
  - Same choice as Merlin C2

- **Execution Flow:**
  ```
  Server → Donut Shellcode → Implant → Sacrificial Process → CLR → Assembly
  ```

### 4. Pipe Output Handling

**Asynchronous Reading Strategy:**
- Goroutines start reading pipes BEFORE process resumes
- Prevents pipe buffer overflow (which would block the sacrificial process)
- Buffered channels (100 slots) for chunk collection
- Waits for both STDOUT and STDERR goroutines to complete
- Collects all data after process exits

## Windows API Calls Used

| API Function | Purpose |
|--------------|---------|
| `CreateProcess` / `CreateProcessW` | Create suspended sacrificial process |
| `CreatePipe` | Create anonymous pipes for I/O redirection |
| `VirtualAllocEx` | Allocate RW memory in target process |
| `WriteProcessMemory` | Write Donut shellcode to target process |
| `VirtualProtectEx` | Change memory protection (RW → RX for OPSEC) |
| `CreateRemoteThread` | Create thread to execute shellcode (Merlin method) |
| `ResumeThread` | Resume suspended main thread |
| `WaitForSingleObject` | Wait for process completion (5 min timeout) |
| `GetExitCodeProcess` | Get process exit code |
| `ReadFile` | Read from pipes (STDOUT/STDERR) asynchronously |

## Comparison with Merlin C2

| Feature | Merlin | SilkWire | Status |
|---------|--------|----------|--------|
| CreateRemoteThread Injection | ✓ | ✓ | ✅ Implemented |
| Anonymous Pipes | ✓ | ✓ | ✅ Implemented |
| PPID Spoofing Support | ✓ | ✓ | ✅ Implemented |
| Async Pipe Reading | ✓ | ✓ | ✅ Implemented |
| Process Timeout | ✓ | ✓ | ✅ 5 minute timeout |
| Donut Shellcode Support | ✓ | ✓ | ✅ Full compatibility |
| Default Process | dllhost.exe | dllhost.exe | ✅ Matches Merlin |
| Output Capture | ✓ | ✓ | ✅ STDOUT/STDERR |

## Memory Layout

```
Sacrificial Process Memory Space:
┌─────────────────────────────────────┐
│ PE Headers (Original Binary)        │
│ - DOS Header ("MZ")                 │
│ - NT Headers ("PE")                 │
│ - Optional Header                   │
├─────────────────────────────────────┤
│ Modified Entry Point                │ ← Hijacked!
│ - Trampoline (12 bytes x64)         │ → Jumps to shellcode
│ - mov rax, <addr>; jmp rax          │
├─────────────────────────────────────┤
│ Allocated Memory (RX)               │ ← VirtualAllocEx
│ - Donut Shellcode                   │
│ - CLR Loader                        │
│ - AMSI/ETW bypass (if enabled)      │
├─────────────────────────────────────┤
│ CLR Runtime (loaded by Donut)       │
│ - mscoree.dll                       │
│ - mscorlib.dll                      │
│ - .NET Framework assemblies         │
├─────────────────────────────────────┤
│ User .NET Assembly                  │ ← Loaded by CLR
│ - Loaded into default AppDomain     │
│ - Executes Main() or specified      │
│   entry point                       │
└─────────────────────────────────────┘
```

## Execution Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Server (assembly.go)                                         │
│ - Receives .NET assembly from operator                      │
│ - Converts to Donut shellcode (go-donut)                    │
│ - Sends shellcode to implant                                │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Implant (dotnet_windows.go)                                 │
│ - ExecuteAssemblySacrificial()                              │
│ - Receives Donut shellcode                                  │
│ - Calls SpawnInjectAndWait()                                │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Injection (injection_windows.go)                            │
│ - SpawnInjectAndWait()                                      │
│   1. Create pipes for STDOUT/STDERR                         │
│   2. CreateProcess(SUSPENDED, INHERIT_HANDLES)              │
│   3. VirtualAllocEx + WriteProcessMemory                    │
│   4. VirtualProtectEx (→ PAGE_EXECUTE_READ)                 │
│   5. hijackEntryPoint()                                     │
│      - Read PEB → ImageBase                                 │
│      - Read PE headers                                      │
│      - Overwrite entry point with trampoline                │
│   6. Start async pipe readers                               │
│   7. ResumeThread()                                         │
│   8. WaitForSingleObject() + read output                    │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Sacrificial Process (dllhost.exe)                           │
│ - Starts execution at hijacked entry point                  │
│ - Jumps to Donut shellcode                                  │
│ - Donut:                                                    │
│   1. Unpacks/decrypts .NET assembly                         │
│   2. Loads CLR (mscoree.dll)                                │
│   3. Creates AppDomain                                      │
│   4. Loads assembly bytes                                   │
│   5. Invokes entry point (Main)                             │
│   6. Output → inherited STDOUT handle → pipe                │
│ - Process exits                                             │
└────────────────┬─────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Output Collection                                           │
│ - Async goroutines collect pipe data                        │
│ - Converts to string                                        │
│ - Returns to server                                         │
└──────────────────────────────────────────────────────────────┘
```

## Features

### ✅ Process Isolation
- Assembly runs in separate process (dllhost.exe)
- If assembly crashes, implant survives
- Process can be killed without affecting implant

### ✅ Output Capture
- STDOUT and STDERR both captured via anonymous pipes
- Asynchronous reading prevents deadlocks
- All output returned to operator

### ✅ PPID Spoofing (Optional)
- Can specify parent process ID
- Uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`
- Makes process tree look legitimate

### ✅ Operational Security
- Uses common Windows process (dllhost.exe)
- Entry point hijacking is stealthier than CreateRemoteThread
- Handles inherited properly for output redirection
- 5-minute timeout prevents hung processes

## Troubleshooting

### No Output Captured

**Possible Causes:**
1. Wrong sacrificial process (use dllhost.exe, not WerFault.exe)
2. Donut shellcode not configured for console output
3. Process crashing before output (check exit code)

**Solution:**
- Use `dllhost.exe` (now the default)
- Ensure Donut is created with proper settings on server
- Check exit code in response (0xC0000005 = ACCESS_VIOLATION)

### Process Crashes (0xC0000005)

**Possible Causes:**
1. Incompatible sacrificial process
2. Memory protection issues
3. DEP/ASLR conflicts

**Solution:**
- Use recommended processes: dllhost.exe, notepad.exe, svchost.exe
- Ensure shellcode is position-independent (Donut handles this)
- Try different sacrificial process via `SacrificialProcess` option

### Timeout Errors

**Possible Causes:**
1. Assembly takes longer than 5 minutes
2. Assembly is waiting for input
3. Pipe deadlock (should not happen with async reading)

**Solution:**
- Check assembly doesn't require user input
- Consider extending timeout in code
- Verify assembly completes in reasonable time

## Security Considerations

### Detection Vectors

| Detection Method | Risk | Mitigation |
|-----------------|------|------------|
| Process creation monitoring | Medium | Use common processes, vary targets |
| Suspended process detection | High | Entry point hijacking is quick |
| Parent-child anomalies | Medium | Use PPID spoofing |
| Memory scanning | Medium | Donut handles encryption |
| API call hooking | High | Unavoidable for this technique |
| CLR in unexpected process | Medium | dllhost.exe often loads .NET |

### Best Practices

1. **Vary sacrificial process** - Don't always use the same binary
2. **Use PPID spoofing** - Make process tree look legitimate
3. **Limit frequency** - Don't execute assemblies repeatedly
4. **Choose appropriate parent** - Match environment (explorer.exe, etc.)
5. **Monitor for crashes** - Failed executions leave artifacts

## References

- Merlin C2: https://github.com/Ne0nd0g/merlin
- Donut Shellcode: https://github.com/TheWover/donut
- Entry Point Hijacking: https://www.ired.team/offensive-security/code-injection-process-injection/entry-point-hijacking
- Process Injection: https://attack.mitre.org/techniques/T1055/

## Files Modified

- `implant/injection_windows.go` - Entry point hijacking + process creation
- `implant/dotnet_windows.go` - High-level execute-assembly interface
- Added: `PROCESS_BASIC_INFORMATION` structure
- Added: `procNtQueryInformationProcess` API
- Added: `encoding/binary` import for trampoline creation

## Testing

To test the implementation:

```bash
# On server console
execute-assembly Seatbelt.exe -group=system
execute-assembly SharpHound.exe -c All
```

Expected output should show assembly execution results in the console.

