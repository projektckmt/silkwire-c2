# Process Migration - Production Implementation

## Overview

The `MigrateProcess` function has been fully implemented for production use. It enables the implant to migrate itself from the current process to a target process, allowing the operator to move execution to a more stable or less-monitored process.

## How It Works

### Migration Strategy

The implementation uses a **full PE injection** approach:

1. **Read Self**: Read the entire implant executable from disk
2. **Parse PE**: Validate and parse PE headers
3. **Architecture Check**: Verify target process matches implant architecture (32/64-bit)
4. **Allocate Memory**: Allocate memory in target process for the full executable
5. **Write Headers & Sections**: Write PE headers and all sections to target
6. **Perform Relocations**: Fix up addresses if base address differs from preferred
7. **Resolve Imports**: Resolve all IAT entries for dependencies
8. **Set Protections**: Apply proper memory protections (RWX, RW, etc.)
9. **Bootstrap**: Create shellcode to properly initialize the migrated implant
10. **Execute**: Create remote thread to execute the bootstrap
11. **Terminate**: Schedule self-termination after migration succeeds

## Usage

### Console Command

```bash
# Migrate to a specific process by PID
migrate <pid>

# Example: Migrate to notepad.exe (PID 1234)
migrate 1234
```

### Finding Target Processes

```bash
# List running processes (if ps command is implemented)
ps

# Common stable processes for migration:
# - explorer.exe (Windows Explorer - very stable)
# - svchost.exe (Windows Service Host - common, many instances)
# - RuntimeBroker.exe (Windows Runtime Broker)
# - SearchIndexer.exe (Windows Search)
# - dllhost.exe (COM Surrogate)
```

## Migration Process Details

### Step-by-Step Breakdown

1. **Self-Reading**
   ```go
   exePath := getExecutablePath()  // Get our own path
   implantBytes := os.ReadFile(exePath)  // Read entire executable
   ```

2. **PE Validation**
   - Checks for MZ signature (0x5A4D)
   - Verifies PE signature (0x4550)
   - Validates NT headers offset

3. **Architecture Verification**
   ```go
   // Ensures target process matches implant bitness
   IsWow64Process(hProcess, &targetIs64Bit)
   // IMAGE_FILE_MACHINE_AMD64 = 0x8664 for x64
   ```

4. **Memory Allocation**
   ```go
   // Allocate full image size in target
   virtualAllocEx(hProcess, 0, imageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
   ```

5. **Section Writing**
   - Writes PE headers first
   - Iterates through all sections (.text, .data, .rdata, etc.)
   - Writes each section to its virtual address

6. **Base Relocation**
   ```go
   // If allocated base != preferred base
   delta := int64(remoteBase) - int64(preferredBase)
   performMigrationRelocation(hProcess, implantBytes, ntHeaders, remoteBase, delta)
   ```
   - Fixes up all address references in the code
   - Handles both 32-bit and 64-bit relocations

7. **Import Resolution**
   ```go
   resolveImports(hProcess, implantBytes, ntHeaders, remoteBase)
   ```
   - Loads all required DLLs (kernel32.dll, ntdll.dll, etc.)
   - Resolves function addresses
   - Writes addresses to Import Address Table (IAT)

8. **Bootstrap Execution**
   ```asm
   ; x64 shellcode that:
   push registers          ; Save state
   and rsp, 0xFFFFFFF0    ; Align stack
   sub rsp, 0x20          ; Allocate shadow space
   mov rcx, imageBase     ; hInstance parameter
   xor rdx, rdx           ; hPrevInstance = NULL
   xor r8, r8             ; lpCmdLine = NULL
   xor r9, r9             ; nCmdShow = 0
   mov rax, entryPoint    ; Load entry point
   call rax               ; Execute!
   ```

9. **Self-Termination**
   ```go
   go func() {
       time.Sleep(2 * time.Second)  // Wait for response to send
       os.Exit(0)                   // Graceful exit
   }()
   ```

## Advanced Features

### Memory Protection Setting

The implementation sets proper memory protections based on PE section characteristics:

- **`.text` section**: `PAGE_EXECUTE_READWRITE` (code)
- **`.data` section**: `PAGE_READWRITE` (writable data)
- **`.rdata` section**: `PAGE_READWRITE` (read-only data, but kept RW for compatibility)

### Architecture Safety

The migration will **fail gracefully** if:
- Target process is 32-bit and implant is 64-bit (or vice versa)
- Target process cannot be opened (insufficient permissions)
- Memory allocation fails in target
- Import resolution fails

### Relocation Handling

Supports both relocation types:
- **IMAGE_REL_BASED_DIR64** (type 10): 64-bit absolute address
- **IMAGE_REL_BASED_HIGHLOW** (type 3): 32-bit absolute address

## Response Format

```json
{
  "status": "success",
  "method": "process_migration",
  "original_pid": 1234,
  "target_pid": 5678,
  "migrated_base": "0x7ff600000000",
  "entry_point": "0x7ff600001000",
  "bootstrap_address": "0x7ff700000000",
  "thread_id": 9012,
  "implant_size": 1048576,
  "note": "Implant migrated successfully. Original process will terminate."
}
```

## Best Practices

### Choosing Target Processes

**Good Targets:**
- Long-running system processes
- Processes with network activity (normal for communication)
- Processes running with appropriate privileges
- Multiple instances available (svchost.exe)

**Bad Targets:**
- Protected processes (PPL - Protected Process Light)
- Anti-malware/EDR processes (will be detected)
- Critical system processes (csrss.exe, lsass.exe - may cause BSoD)
- Short-lived processes (will die soon after migration)

### Timing

**When to Migrate:**
- Initial implant dropped by dropper needs stability
- Current process about to exit
- Detected in current process
- Need higher/lower privileges
- Need to blend into normal system activity

**When NOT to Migrate:**
- Stable, privileged process already
- Target has EDR hooks
- Migration itself may trigger alerts
- Frequent migrations increase detection risk

## Operational Security

### Detection Vectors

1. **Memory Injection Detection**
   - EDR may detect `VirtualAllocEx` + `WriteProcessMemory` pattern
   - Mitigation: Use with obfuscation, vary timing

2. **Behavioral Analysis**
   - Unusual network activity from target process
   - Mitigation: Choose processes that normally have network activity

3. **Thread Creation**
   - `CreateRemoteThread` is heavily monitored
   - Mitigation: Consider alternative execution methods (APC, thread hijacking)

4. **Process Access**
   - Opening process with `PROCESS_ALL_ACCESS` may alert
   - Mitigation: Use minimal required permissions

### Evasion Tips

1. **Delay Migration**
   ```bash
   # Don't migrate immediately on execution
   sleep 60  # Wait for environment to settle
   migrate 1234
   ```

2. **Validate Target**
   - Ensure target has network access
   - Check target isn't monitored
   - Verify target will live long enough

3. **Clean Exit**
   - Original process exits cleanly (not crashed)
   - No orphaned handles or resources
   - Response sent before termination

## Troubleshooting

### Migration Failed: Access Denied

**Cause**: Insufficient permissions to open target process

**Solution**:
- Run implant with admin privileges
- Choose target with same or lower integrity level
- Enable `SeDebugPrivilege` (automatic in implant)

### Migration Failed: Architecture Mismatch

**Cause**: Trying to inject 64-bit implant into 32-bit process (or vice versa)

**Solution**:
- Verify target architecture before migration
- Build implants for both architectures
- Use `ps` or similar to check process architecture

### Migration Succeeded but No Connection

**Cause**: Migrated process can't reach C2 server

**Solution**:
- Check target process has network access
- Verify firewall rules allow target process
- Ensure target isn't sandboxed/restricted

### Original Process Still Running

**Cause**: Self-termination failed or was disabled

**Solution**:
- Check for errors in goroutine
- Verify `os.Exit(0)` isn't blocked
- May need manual termination

## Technical Details

### Memory Layout

```
Target Process Memory:
┌─────────────────────────┐
│ PE Headers              │ ← remoteBase
├─────────────────────────┤
│ .text (Code)            │
├─────────────────────────┤
│ .data (Data)            │
├─────────────────────────┤
│ .rdata (Read-only)      │
├─────────────────────────┤
│ IAT (Import Table)      │
├─────────────────────────┤
│ [Other Sections]        │
├─────────────────────────┤
│ Bootstrap Shellcode     │ ← bootstrapAddr
└─────────────────────────┘
```

### Calling Convention

Uses **Windows x64 calling convention**:
- First 4 args: RCX, RDX, R8, R9
- Shadow space: 32 bytes
- Stack alignment: 16-byte boundary
- Caller cleans stack

### Entry Point

The migrated implant starts at the standard PE entry point, which is typically:
- For EXE: `mainCRTStartup` or `WinMainCRTStartup`
- For DLL: `DllMain`

The bootstrap shellcode properly sets up the execution environment to mimic a normal process start.

## Future Enhancements

Potential improvements:
- [ ] Thread hijacking instead of CreateRemoteThread
- [ ] Process hollowing variant (replace target's code)
- [ ] DLL-based migration for more stealth
- [ ] In-memory only (no disk read)
- [ ] Parent process spoofing during migration
- [ ] Multiple migration methods with fallback
- [ ] Syscall direct invocation (bypass hooks)

## References

- PE Format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- Process Injection: https://attack.mitre.org/techniques/T1055/
- Reflective Injection: https://github.com/stephenfewer/ReflectiveDLLInjection
- Base Relocations: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocations
