# Silkwire C2 Framework

<p align="center">
  <img alt="Silkwire Logo" src="docs/images/silkwire.png" height="30%" width="30%">
</p>

A gRPC-based Command and Control framework for authorized penetration testing and red team operations. Features multi-platform implants, post-exploitation modules, and comprehensive evasion capabilities.

> **⚠️ LEGAL DISCLAIMER**
> **FOR AUTHORIZED SECURITY TESTING ONLY.** This tool is intended solely for authorized penetration testing, red team exercises, and educational purposes. Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical. Users are solely responsible for compliance with all applicable laws.

## Features

**Core Infrastructure**
- Encrypted gRPC communication (TLS/mTLS) with bidirectional streaming
- Multi-platform support: Windows, Linux, macOS (amd64, 386, arm64)
- Dynamic implant generation with custom configurations
- Interactive operator console with session management
- SQLite-based persistence

**Post-Exploitation**
- In-memory .NET assembly execution (AMSI/ETW bypass)
- PE/DLL execution via Donut shellcode conversion
- BOF (Beacon Object File) execution with goffloader
- Multiple shellcode injection techniques
- Process migration and token manipulation
- Credential harvesting (LSASS, browsers, SAM/shadow)
- Persistence mechanisms (registry, scheduled tasks, services, cron, systemd, launchd)

**Surveillance**
- Keylogging with window tracking
- Screenshot, audio, and webcam capture
- Clipboard monitoring

**Networking**
- SOCKS5 proxy and port forwarding
- DNS C2 channel with encryption
- Interactive PTY shells

**Evasion**
- Anti-debug, anti-VM, anti-emulation
- Sleep masking and code obfuscation
- Jittered beacons and kill dates
- Configurable evasion profiles

## Quick Start

### Prerequisites
- Go 1.24.4+
- Protocol Buffers (`protoc` with Go plugins)
- OpenSSL
- SQLite3

```bash
# Clone and setup
git clone https://github.com/projektckmt/silkwire-c2.git
cd silkwire-c2
make dev-setup

# Build all components
make build
```

### Running

**Terminal 1 - Server:**
```bash
make run-server
```

**Terminal 2 - Implant:**
```bash
make run-client
```

**Terminal 3 - Operator Console:**
```bash
make run-console
```

For detailed setup and manual execution options, see the [documentation](docs/).

## Usage

### Basic Commands

```bash
# Session management
sessions                    # List all sessions
session <id>               # Interact with session
kill <id>                  # Terminate session

# Command execution
shell <command>            # Execute command
pty [shell]               # Interactive PTY shell
upload <local> <remote>    # Upload file
download <remote> [local]  # Download file

# Post-exploitation
execute-assembly <path> [args]           # .NET assembly execution
execute-pe <path> [args]                 # PE/DLL via Donut
execute-bof <path> [args]                # BOF execution (Win x64)
execute-shellcode -m <method> <file>     # Shellcode injection
migrate <pid>                            # Process migration

# Credentials
dump-lsass                  # LSASS dump
hashdump                   # Hash extraction
harvest-all-browsers       # Browser credentials

# Surveillance
keylog-start / keylog-stop
screenshot
audio-capture <seconds>
webcam-capture <seconds> <format>

# Networking
socks-start [port]
portfwd-add <bind> <host> <port>

# Persistence
persist-install <method>    # registry, task, service, cron, systemd, launchd
persist-remove <method>
```

For complete command reference and advanced options, see the [operator guide](docs/OPERATOR_GUIDE.md).

## Architecture

### Components

```
┌─────────────┐         gRPC/TLS          ┌─────────────┐
│   Implant   │◄──────────────────────────►│   Server    │
│  (Target)   │    Bidirectional Stream    │  (Handler)  │
└─────────────┘                             └──────┬──────┘
                                                   │
                                             ┌─────▼──────┐
                                             │  Console   │
                                             │ (Operator) │
                                             └────────────┘
```

- **Server** ([server/](server/)): gRPC server, session management, task queuing, implant generation
- **Implant** ([implant/](implant/)): Multi-platform agent with post-exploitation and evasion modules
- **Console** ([console/](console/)): Interactive operator interface
- **Proto** ([proto/](proto/)): gRPC service and message definitions

### Security

- **Communication**: TLS 1.2+, mTLS support, session tokens
- **Evasion**: Anti-debug/VM/emulation, sleep masking, process hiding
- **Obfuscation**: String encryption, name mangling, control flow flattening

## Advanced Capabilities

### Implant Generation
- Cross-platform compilation (Windows, Linux, macOS)
- Custom configurations (beacon interval, jitter, kill date, evasion level)
- Per-implant TLS certificates
- Multiple output formats (EXE, DLL, shellcode, service)
- Optional obfuscation and packing

### Injection & Execution
- **.NET Assemblies**: In-memory execution with AMSI/ETW bypass via donut shellcode or CLR hosting
- **PE/DLL**: Server-side donut conversion with sacrificial process spawning
- **BOF**: In-process execution using goffloader (Windows x64)
- **Shellcode**: Multiple injection methods (CreateRemoteThread, RtlCreateUserThread, QueueUserAPC, reflective DLL)
- **Process Migration**: Migrate implant with connection preservation

### Covert Channels
- **DNS C2**: Tunneling over DNS with TOTP auth and Age encryption
- **SOCKS5**: Full proxy server for traffic pivoting
- **Port Forwarding**: Multiple simultaneous forwards

### Modules
Extensible module system with built-in XMRig cryptocurrency miner. Custom modules can be added via the Module interface.

## Development

### Build Options

```bash
# Cross-platform compilation
GOOS=windows GOARCH=amd64 go build -o implant.exe ./implant
GOOS=linux GOARCH=amd64 go build -o implant-linux ./implant
GOOS=darwin GOARCH=arm64 go build -o implant-macos-arm ./implant

# With obfuscation (requires garble)
make tools
garble -literals -tiny build -o bin/obfuscated-implant ./implant

# Optimize binary size
go build -ldflags="-s -w" -trimpath -o implant ./implant
```

### Extending Functionality

1. **Add Commands**: Edit `proto/c2.proto`, regenerate with `make proto`, implement handler in `implant/commands.go`
2. **Custom Modules**: Implement Module interface in `implant/modules.go`, register, and add console commands
3. **Testing**: `make test` or `go test ./...`

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for detailed development guidelines.

## Operational Guidelines

### Best Practices
- **Authorization**: Obtain explicit written permission before deployment
- **TLS**: Always use TLS/mTLS in production environments
- **OpSec**: Set kill dates, configure jitter, use dedicated infrastructure
- **Cleanup**: Remove persistence, delete binaries, clear artifacts after engagements
- **Testing**: Validate evasion techniques in lab environments first

### Troubleshooting
- **Connection issues**: Check firewall rules, verify certificates, confirm server address
- **Timeouts**: Increase beacon interval, verify implant process is running
- **Build errors**: Run `make clean && make build`, ensure Go 1.24.4+, install protoc plugins

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for detailed solutions.

## License

Provided for **educational and authorized security testing only**. Users must:
- Only use on authorized systems
- Comply with all applicable laws
- Take full responsibility for their actions

The software is provided "AS IS" without warranty. Authors are not responsible for misuse.

## Contributing

Contributions welcome! Please:
- Maintain educational/research focus
- Follow Go best practices
- Include tests and documentation
- Submit PRs with detailed descriptions

Report security vulnerabilities privately to maintainers.

## Acknowledgments

Inspired by Sliver, Metasploit, Cobalt Strike, and Empire. Built with gRPC, Protocol Buffers, go-clr, garble, donut, and XMRig.

---

**Use responsibly and legally.**
