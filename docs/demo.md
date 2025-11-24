# Demo Instructions

This document provides step-by-step instructions to demonstrate the complete Omnic2 C2 framework.

## Setup

1. **Generate certificates:**
   ```bash
   make certs
   ```

2. **Build all components:**
   ```bash
   make build
   ```

## Demo Scenario

### Terminal 1: Start the C2 Server
```bash
cd certs && ../bin/c2-server
```

You should see:
```
C2 Server starting on :8443 with TLS
```

### Terminal 2: Start an Implant Client
```bash
./bin/c2-client localhost:8443
```

You should see:
```
Connecting to C2 server: localhost:8443
Registering with C2 server...
Registration successful. Session token: abcd1234...
Starting beacon with 30s interval (+/- 20% jitter)
Beacon stream established
```

### Terminal 3: Use the Operator Console
```bash
./bin/c2-console localhost:8443
```

You should see:
```
C2 Operator Console
==================
Connecting to server at: localhost:8443
C2 Operator Console
==================
Type 'help' for available commands
c2> 
```

#### Console Commands to Try:

1. **List active sessions:**
   ```
   c2> sessions
   ```
   This should now show the real implant that connected, not just demo data!

2. **Interact with a session:**
   ```
   c2> session <implant_id>
   ```
   Replace `<implant_id>` with the actual ID from the sessions list.

3. **Execute commands:**
   ```
   (hostname) > pwd
   (hostname) > ls
   (hostname) > ps
   ```

4. **Return to main console:**
   ```
   (hostname) > back
   ```

5. **Exit:**
   ```
   c2> exit
   ```

## What's New

The console now:
- ✅ **Connects to real server via gRPC** instead of using demo data
- ✅ **Lists actual implant sessions** from the running server
- ✅ **Sends commands through the server** to real implants
- ✅ **Receives real command results** from implants
- ✅ **Falls back to demo mode** if server is not available

## Expected Behavior

- Server logs will show implant registration and heartbeats
- Console will display real session information (hostname, username, OS, etc.)
- Commands sent through console will execute on the implant
- Results will be displayed in real-time

## Architecture Flow

1. **Client → Server**: Registration and beacon stream
2. **Console → Server**: Session queries and command requests  
3. **Server → Client**: Command forwarding via stream
4. **Client → Server**: Command results via beacon stream
5. **Server → Console**: Results and session updates