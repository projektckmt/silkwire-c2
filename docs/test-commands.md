# Test Commands for Console

When you're in a session, try these commands that should work:

## Basic Commands (should work on all systems)
```bash
(hostname) > pwd          # Show current directory
(hostname) > ls           # List files
(hostname) > whoami       # Show current user
(hostname) > ps           # List processes
(hostname) > shell echo "Hello from implant!"
```

## System Information
```bash
(hostname) > sysinfo      # System information
(hostname) > shell uname -a   # Kernel info (Linux/Mac)
(hostname) > shell date   # Current date/time
```

## Network Tests
```bash
(hostname) > ping 8.8.8.8     # Ping Google DNS
(hostname) > shell hostname   # Show hostname
```

## Expected Behavior

✅ **Success**: Server shows "Task result from [ID]: [command output]"
❌ **Failure**: Server shows "Task result from [ID]: Error: exit status 1" 

The error you saw means the command executed but returned a non-zero exit code (failed).

## Full Demo Flow

1. **Terminal 1** (Server):
   ```bash
   cd certs && ../bin/c2-server
   ```

2. **Terminal 2** (Implant):
   ```bash
   ./bin/c2-client localhost:8443
   ```

3. **Terminal 3** (Console):
   ```bash
   ./bin/c2-console localhost:8443
   c2> sessions
   c2> session cd334a25
   (hostname) > pwd
   (hostname) > shell echo "test"
   (hostname) > back
   c2> exit
   ```

Watch Terminal 1 (server) to see the actual command results!