# Donut ExecuteAssembly Troubleshooting Guide

## Current Status

### Problem
- Donut shellcode crashes with `0xC0000005` (ACCESS_VIOLATION)
- Crash happens immediately (within 1 second)
- No output captured (0 bytes)
- Consistent across all attempts

### Configuration (Now Matching Sliver Exactly)

**Server-side (`server/donut.go`):**
```go
✅ config.Bypass = 3
✅ config.Runtime = "v4.0.30319"
✅ config.Format = 1
✅ config.Arch = X64 (auto-detected)
✅ config.Entropy = 3
✅ config.Unicode = 0
✅ config.ExitOpt = 1
✅ config.Thread = 0
✅ config.Type = DONUT_MODULE_NET_EXE
✅ Stack alignment prologue prepended (8 bytes)
```

**Implant-side (`implant/taskrunner_windows.go`):**
```go
✅ Process created suspended
✅ rwxPages = false (RW → write → RX)
✅ CreateRemoteThread for execution
✅ Output capture via stdout/stderr buffers
```

### What We've Tried

1. ❌ Stack alignment prologue (added/removed/re-added)
2. ❌ Encryption settings (Entropy 1 vs 3)
3. ❌ Process suspension (suspended vs running)
4. ❌ Memory permissions (RWX vs RX)
5. ❌ All configuration parameters matching Sliver

### Analysis

The crash is happening in the **Donut loader stub**, not the .NET assembly itself, because:
- Crashes within 1 second (too fast for CLR initialization)
- No partial output
- Consistent behavior regardless of assembly

## Possible Root Causes

### 1. go-donut Library Bug
**Current version:** `v0.0.0-20220908180326-fcdcc35d591c` (Sept 2022)

**Evidence:**
- Old version (2+ years old)
- May have bugs fixed in newer versions
- May be incompatible with current Windows versions

**Test:**
```bash
# Update to latest go-donut
go get -u github.com/Binject/go-donut@latest
go mod tidy
```

### 2. Windows Version Incompatibility
The Donut loader might not work on your specific Windows version.

**Check:**
```cmd
# On target Windows machine
ver
systeminfo | findstr /B /C:"OS Version"
```

### 3. .NET Framework Missing/Incompatible
Donut requires .NET Framework 4.0+ to be installed.

**Check:**
```cmd
# On target Windows machine
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Version
```

### 4. AMSI/Defender Blocking
Even with Bypass=3, security software might be killing the process.

**Test:**
```powershell
# On target Windows machine (as admin)
Set-MpPreference -DisableRealtimeMonitoring $true
```

### 5. Architecture Mismatch
notepad.exe on x64 Windows is 64-bit, but maybe there's a mismatch somewhere.

**Verify:**
```go
// In server logs, confirm:
"Execute-assembly: Auto-selected Donut arch 'x64'"
```

## Recommended Next Steps

### Step 1: Test In-Process CLR Mode (Bypass Donut Entirely)

This will tell us if the assembly itself works.

**On operator:**
```bash
execute-assembly --in-process Seatbelt.exe
```

**Expected outcomes:**
- ✅ **Works**: Problem is definitely Donut-related
- ❌ **Fails**: Problem is broader (CLR, permissions, assembly itself)

### Step 2: Test with Minimal Assembly

Create a simple "Hello World" .NET assembly:

```csharp
using System;
class Program {
    static void Main(string[] args) {
        Console.WriteLine("Hello from Donut!");
        Console.WriteLine("Args: " + string.Join(", ", args));
    }
}
```

Compile:
```bash
csc /out:HelloWorld.exe /target:exe HelloWorld.cs
```

Test:
```bash
execute-assembly HelloWorld.exe test args
```

### Step 3: Update go-donut Library

```bash
cd /home/kali/silkwire
go get github.com/Binject/go-donut@latest
go mod tidy
go build -o server/silkwire-server ./server
```

### Step 4: Test with Donut CLI Directly

Install standalone Donut and generate shellcode manually:

```bash
# Install donut CLI
git clone https://github.com/TheWover/donut
cd donut
make

# Generate shellcode
./donut -a 2 -f 1 -o seatbelt.bin Seatbelt.exe

# Test size
ls -lh seatbelt.bin
```

Compare the size with your generated shellcode. If dramatically different, there's a generation issue.

### Step 5: Check for EDR/AV

The process might be getting killed by security software before it even starts.

**Test:**
1. Disable Windows Defender
2. Disable any EDR/AV
3. Try again

### Step 6: Try Different Sacrificial Process

Instead of notepad.exe, try:
- `cmd.exe`
- `powershell.exe`
- `rundll32.exe`
- `dllhost.exe`

```bash
execute-assembly --process C:\Windows\System32\cmd.exe Seatbelt.exe
```

### Step 7: Debug with x32dbg/WinDbg

Attach a debugger to the sacrificial process to see exactly where it crashes.

**Steps:**
1. Modify code to add `time.Sleep(10 * time.Second)` after process creation
2. Attach x32dbg to the suspended notepad.exe
3. Set breakpoint at the injected shellcode address (logged as 0x...)
4. Step through to see where it crashes

## Alternative: Use In-Process Mode Exclusively

If Donut continues to fail, you can:

1. **Disable sacrificial mode entirely**
2. **Always use in-process CLR hosting**
3. **Accept the risk of assembly crashes killing implant**

**Benefits:**
- No Donut dependency
- Faster execution
- More reliable
- Better for trusted assemblies

**Drawbacks:**
- Assembly crash kills implant
- Less isolated
- Can't use PPID spoofing

**Implementation:**
```go
// In server/handlers.go, force in-process mode
if req.Command.Type == pb.CommandType_EXECUTE_ASSEMBLY {
    req.Command.ExecuteAssemblyOptions.InProcess = true
}
```

## Questions to Answer

1. **Does in-process CLR mode work?**
   - If YES → Donut issue
   - If NO → CLR/assembly issue

2. **Does a minimal Hello World assembly work?**
   - If YES → Seatbelt-specific issue
   - If NO → Fundamental Donut problem

3. **Does updating go-donut fix it?**
   - Check for newer versions with bug fixes

4. **Does it work on a different Windows version?**
   - Test on Windows 10 vs Windows 11 vs Windows Server

5. **Does standalone Donut CLI work?**
   - If YES → go-donut library issue
   - If NO → Donut itself doesn't work on this system

## Success Criteria

✅ Thread exit code = 0 (or assembly's exit code)
✅ Output captured > 0 bytes
✅ No ACCESS_VIOLATION crash
✅ Assembly output visible in response

## If All Else Fails

1. **Use in-process mode exclusively** (safest bet)
2. **Report bug to go-donut maintainers** with full details
3. **Try original Donut project** (C version) and wrap it
4. **Implement alternative .NET loader** (e.g., direct CLR hosting in injected code)

## Logs to Collect for Bug Report

If reporting to go-donut:

```
1. go-donut version
2. Target Windows version (ver, systeminfo)
3. .NET Framework version
4. Minimal reproducer (HelloWorld.exe)
5. Generated shellcode (hex dump of first 256 bytes)
6. Crash dump if available
7. Full error logs from both server and implant
```

## Contact

If you get it working or find the root cause, please document it for others!


