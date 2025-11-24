# ExecuteAssembly Debugging Steps

## Current Problem
- Exit code: `3221225477` = `0xC0000005` = `STATUS_ACCESS_VIOLATION`
- Shellcode crashes immediately (within 1 second)
- No output captured (0 bytes)
- Shellcode size: 624216 bytes (consistent across runs)

## Root Cause Analysis

### Issue #1: Missing Stack Alignment Prologue
**Status**: Fixed in code, but needs verification

The x64 Windows ABI requires 16-byte stack alignment. Without the prologue, any Windows API call will crash.

**Expected**: Shellcode should be 624224 bytes (624216 + 8 bytes prologue)
**Actual**: Still 624216 bytes → Server not using new code

### Issue #2: Server Not Restarted
**Evidence**: 
- No server-side logs visible
- Shellcode size unchanged
- Missing debug output from `ConvertAssemblyToShellcode`

### Issue #3: Potential Architecture Mismatch
notepad.exe on Windows x64 is a 64-bit process. Need to verify:
- Donut is generating x64 shellcode
- Implant arch is correctly detected
- No x86/x64 mismatch

## Debugging Steps

### Step 1: Verify Server Restart
```bash
# Kill any running server
pkill -9 silkwire-server

# Rebuild server
cd /home/kali/silkwire
go build -o server/silkwire-server ./server

# Start server with debug logging
cd server
./silkwire-server --debug
```

### Step 2: Test Donut Conversion Locally
```bash
# Test donut conversion with a simple assembly
go run test_donut.go /path/to/assembly.exe
```

Expected output should show:
- Assembly size
- Donut shellcode size (without prologue)
- Final shellcode size (WITH 8-byte prologue)
- The sizes should differ by exactly 8 bytes

### Step 3: Check Server Logs
When running execute-assembly, you MUST see these server logs:
```
Server-side Donut conversion for assembly Seatbelt.exe (...)
Execute-assembly: Auto-selected Donut arch 'x64' for implant ...
ConvertAssemblyToShellcode: Starting server-side donut conversion
ConvertAssemblyToShellcode: Assembly size=... bytes
ConvertAssemblyToShellcode: Using x64 architecture (default)
ConvertAssemblyToShellcode: Conversion successful, shellcode size=... (+8 bytes prologue)
Assembly converted to shellcode: ... bytes -> ... bytes
```

If you DON'T see these logs → server is using old code or logs are disabled

### Step 4: Verify Shellcode Header
The first 8 bytes should be the stack alignment prologue:
```
48 83 E4 F0 48 83 C4 08
```

If missing → stack alignment fix didn't apply

### Step 5: Alternative Injection Method
If stack alignment doesn't fix it, try:
1. Resume main thread after injection
2. Use QueueUserAPC instead of CreateRemoteThread
3. Use RtlCreateUserThread instead
4. Test with a simpler assembly (Hello World)

### Step 6: Test with Simple Assembly
Create a minimal test case:
```csharp
using System;
class Program {
    static void Main() {
        Console.WriteLine("Hello from Donut!");
    }
}
```

Compile and test with this simple program first.

## Quick Fixes to Try

### Fix #1: Ensure Stack Alignment (CRITICAL)
File: `/home/kali/silkwire/server/donut.go` ✓ (Already applied)

### Fix #2: Add Debug Logging to Implant
Add this to taskrunner_windows.go to dump shellcode header:

```go
// After injection, log first 32 bytes of shellcode for verification
logDebug(fmt.Sprintf("Shellcode header (first 32 bytes): % x", data[:min(32, len(data))]))
```

### Fix #3: Try Resuming Main Thread
Add after CreateRemoteThread:

```go
// Resume main thread (might be needed for CLR initialization)
var suspendCount uint32
ret, _, _ := procResumeThread.Call(uintptr(mainThreadHandle), uintptr(unsafe.Pointer(&suspendCount)))
logDebug(fmt.Sprintf("Resumed main thread, suspend count was: %d", suspendCount))
```

### Fix #4: Try Without Suspension
Test by creating process normally (not suspended):

```go
suspended := false  // Change from true
```

This might help isolate if the issue is suspension-related.

## Expected Behavior After Fix

1. Shellcode size increases by 8 bytes (624216 → 624224)
2. No more STATUS_ACCESS_VIOLATION crashes
3. Assembly executes and produces output
4. Exit code should be 0 (success) or assembly's actual exit code

## If Still Failing

Try these alternative approaches:

1. **In-Process Mode**: Use CLR hosting instead of sacrificial process
2. **Different Host Process**: Try `svchost.exe` or `dllhost.exe` instead of notepad.exe
3. **Manual .NET Test**: Verify assembly runs normally outside of Donut
4. **Shellcode Test**: Use a shellcode testing tool to verify Donut output
5. **Older Donut Version**: Try go-donut v1.0.0 instead of latest

## Common Mistakes

❌ Forgetting to restart server after rebuild
❌ Not enabling debug logging
❌ Using x86 shellcode on x64 process
❌ Missing RWX permissions on injected memory
❌ Not waiting for CLR initialization
❌ Killing process too early

## Success Criteria

✓ Server logs show shellcode conversion
✓ Shellcode size = assembly_size + ~5200 + 8 bytes
✓ First 8 bytes = `48 83 E4 F0 48 83 C4 08`
✓ Thread exit code = 0
✓ Output captured > 0 bytes
✓ Assembly output visible in response


