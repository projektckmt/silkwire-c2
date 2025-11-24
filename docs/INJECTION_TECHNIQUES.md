# Advanced Injection Techniques

This document describes all process injection techniques implemented in Silkwire's Windows implant.

## Overview

Silkwire implements 7 advanced process injection techniques for Windows targets:

1. **Classic Shellcode Injection** - Remote thread creation
2. **DLL Injection** - LoadLibrary-based injection
3. **Process Hollowing** - RunPE technique
4. **Reflective DLL Injection** - Memory-only DLL loading
5. **APC Injection** - Asynchronous Procedure Call queuing
6. **Atom Bombing** - Global atom table abuse
7. **Spawn and Inject** - Sacrificial process creation

## Technique Details

### 1. Classic Shellcode Injection (`InjectShellcode`)

**Method:** Direct shellcode injection with remote thread creation

**Steps:**
1. Open target process with `PROCESS_ALL_ACCESS`
2. Allocate RWX memory in target with `VirtualAllocEx`
3. Write shellcode with `WriteProcessMemory`
4. Create remote thread at shellcode address with `CreateRemoteThread`

**Advantages:**
- Simple and reliable
- Works on most processes
- Fast execution

**Disadvantages:**
- Easily detected by AV/EDR
- RWX memory is suspicious
- Remote thread creation triggers alerts

**Usage:**
```go
shellcode := []byte{0x90, 0x90, 0xC3} // Your shellcode
result, err := implant.InjectShellcode(targetPID, shellcode)
```

---

### 2. DLL Injection (`InjectDLL`)

**Method:** Classic DLL injection via LoadLibraryA

**Steps:**
1. Open target process
2. Allocate memory for DLL path string
3. Write DLL path to target memory
4. Get address of `LoadLibraryA` from kernel32.dll
5. Create remote thread pointing to LoadLibraryA with DLL path as parameter

**Advantages:**
- Loads full DLL with exports
- DLL runs in target process context
- Can use DllMain for initialization

**Disadvantages:**
- DLL must be on disk (detectable)
- LoadLibraryA call is monitored
- Leaves artifacts in module list

**Usage:**
```go
result, err := implant.InjectDLL(targetPID, "C:\\path\\to\\payload.dll")
```

---

### 3. Process Hollowing (`ProcessHollowing`)

**Method:** RunPE technique - hollow out legitimate process and replace with payload

**Steps:**
1. Parse payload PE headers (DOS + NT headers)
2. Create target process in suspended state
3. Get thread context and PEB address
4. Read original image base from PEB
5. Unmap original executable with `NtUnmapViewOfSection`
6. Allocate memory for payload (preferred base or anywhere)
7. Write PE headers to target
8. Write all sections from payload
9. Perform base relocations if needed
10. Update thread context entry point
11. Update PEB image base
12. Resume main thread

**Advantages:**
- Executes under legitimate process name
- Full PE loading with all features
- Very stealthy when done correctly

**Disadvantages:**
- Complex implementation
- May fail if preferred base is taken
- Some EDR detect context manipulation

**Usage:**
```go
payloadBytes, _ := os.ReadFile("payload.exe")
result, err := implant.ProcessHollowing("C:\\Windows\\System32\\svchost.exe", payloadBytes)
```

---

### 4. Reflective DLL Injection (`ReflectiveDLLInjection`)

**Method:** Load DLL from memory without touching disk or using LoadLibrary

**Steps:**
1. Parse DLL PE headers
2. Allocate memory in target process for entire DLL
3. Write PE headers to target
4. Write all sections to target
5. Perform base relocations
6. Resolve imports manually by:
   - Loading import DLLs in our process
   - Getting function addresses
   - Writing addresses to target's IAT
7. Generate bootstrap shellcode to call DllMain
8. Execute bootstrap via remote thread
9. Clean up bootstrap shellcode

**Advantages:**
- No disk artifacts
- Bypasses LoadLibrary hooks
- Full DLL functionality from memory
- Very stealthy

**Disadvantages:**
- Complex IAT resolution
- May fail with complex import chains
- Requires valid DLL with proper PE structure

**Usage:**
```go
dllBytes, _ := os.ReadFile("payload.dll")
result, err := implant.ReflectiveDLLInjection(targetPID, dllBytes)
```

---

### 5. APC Injection (`QueueUserAPC`)

**Method:** Queue Asynchronous Procedure Call to target thread

**Steps:**
1. Allocate RWX memory in target process
2. Write shellcode to memory
3. Open target thread with `THREAD_SET_CONTEXT`
4. Queue APC with `QueueUserAPC` pointing to shellcode
5. APC executes when thread enters alertable wait state

**Enhanced Version (`QueueUserAPCMultiple`):**
- Enumerates all threads in target process
- Queues APC to multiple threads for higher success rate

**Advantages:**
- No remote thread creation
- Executes in context of existing thread
- Less suspicious than CreateRemoteThread

**Disadvantages:**
- Only executes in alertable wait states
- May never execute if thread doesn't wait
- Timing is unpredictable

**Usage:**
```go
// Single thread
result, err := implant.QueueUserAPC(targetPID, threadID, shellcode)

// Multiple threads (better success rate)
result, err := implant.QueueUserAPCMultiple(targetPID, shellcode)
```

---

### 6. Atom Bombing (`AtomBombingInjection`)

**Method:** Use global atom tables to smuggle shellcode

**Steps:**
1. Allocate RWX memory in target for final shellcode
2. Split shellcode into 255-byte chunks (atom size limit)
3. Create global atoms with `GlobalAddAtomA` for each chunk
4. Allocate memory for atom-reader shellcode
5. Generate shellcode that calls `GlobalGetAtomNameA` to reconstruct payload
6. Write atom-reader shellcode to target
7. Enumerate target threads
8. Queue APC to execute atom-reader shellcode
9. Atom-reader retrieves atoms and writes to final shellcode location
10. Clean up atoms after execution

**Advantages:**
- Very stealthy - uses OS feature not monitored
- No direct shellcode writing
- Bypasses memory scanning
- Works across sessions

**Disadvantages:**
- Complex multi-stage process
- Still needs APC injection
- Timing issues with cleanup
- Limited payload size per atom

**Usage:**
```go
result, err := implant.AtomBombingInjection(targetPID, shellcode)
```

---

### 7. Spawn and Inject (`SpawnAndInject`)

**Method:** Create sacrificial process and inject into it

**Steps:**
1. Create new process in suspended state (default: notepad.exe)
2. Inject shellcode using classic injection
3. Resume process to execute payload

**Advantages:**
- Complete control over target process
- Can choose benign-looking process
- No existing process manipulation

**Disadvantages:**
- Creates new process (observable)
- Parent-child relationship may be suspicious
- Suspended process may trigger alerts

**Usage:**
```go
result, err := implant.SpawnAndInject("C:\\Windows\\System32\\notepad.exe", shellcode)
```

---

## Detection Evasion Strategies

### Memory Permissions
- **Problem:** RWX memory is highly suspicious
- **Solution:** Use RW for writing, then change to RX with `VirtualProtectEx`

### Thread Creation
- **Problem:** `CreateRemoteThread` is heavily monitored
- **Solution:** Use APC injection or hijack existing threads

### Import Resolution
- **Problem:** LoadLibrary calls are hooked
- **Solution:** Use reflective loading with manual IAT resolution

### Timing
- **Problem:** Immediate execution is suspicious
- **Solution:** Queue to existing threads, use alertable waits

## Usage in Command Flow

These techniques are exposed through the implant's command system:

```protobuf
message CommandMessage {
  enum CommandType {
    INJECT_SHELLCODE = 20;
    INJECT_DLL = 21;
    PROCESS_HOLLOW = 22;
    REFLECTIVE_DLL = 23;
    APC_INJECT = 24;
    ATOM_BOMB = 25;
  }
}
```

## Best Practices

1. **Reconnaissance First:** Enumerate processes and threads before injection
2. **Choose Wisely:** Select injection method based on target and environment
3. **Layered Approach:** Combine techniques (e.g., process hollow + reflective DLL)
4. **Clean Up:** Remove artifacts and free memory when done
5. **Error Handling:** Always have fallback methods
6. **OPSEC:** Consider parent process, timing, and memory patterns

## References

- **Process Hollowing:** Classic RunPE technique from 2010+
- **Reflective DLL Injection:** Stephen Fewer's technique
- **APC Injection:** Documented in Windows Internals
- **Atom Bombing:** Discovered by enSilo researchers (2016)

## Implementation Files

- `implant/injection_windows.go` - All injection techniques
- `proto/c2.proto` - Command definitions
- `implant/commands.go` - Command handlers
