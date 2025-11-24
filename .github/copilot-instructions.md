# Silkwire C2 Framework - AI Agent Instructions

## Project Overview

Silkwire is a gRPC-based Command & Control (C2) framework for cybersecurity research. It features three main components:
- **Server** (`server/`): Handles implant connections, session management, and dynamic implant generation
- **Implant** (`implant/`): Cross-platform agents with evasion, modules (XMRig), and PTY support
- **Console** (`console/`): Interactive operator interface using reeflective/console framework

## Critical Architecture Patterns

### Three-Component Communication Flow
```
Console (operator) → Server (gRPC) → Implant (target)
         ←────────────────────────────
```
- Console connects to server via gRPC (`localhost:8443` default)
- Implants use **bidirectional streaming** (`BeaconStream`) for real-time commands OR polling (`GetTasks/SubmitResult`) as fallback
- All communication uses **TLS with auto-generated self-signed certs** (see `server/tls.go`)

### Implant Generation via Go Text Templates
Implants are **NOT pre-compiled**. Server generates them on-demand from `implant/` source:
1. Server copies all `implant/*.go` files to `generated/` directory
2. Template variables in `main.go` (e.g., `{{.ServerAddr}}`, `{{.Transport}}`) are replaced with config values
3. Compiled with cross-platform `GOOS`/`GOARCH` flags in `server/implant_generator.go`
4. Codename-based filenames like `stormbear_linux_amd64` (see `shared/utils.go:GenerateCodename()`)

**Key files:** `server/implant_generator.go`, `implant/main.go` (template vars), `console/commands.go:executeGeneration()`

### Database Persistence with GORM
SQLite database (`c2_server.db`) persists sessions, commands, results via GORM models:
- `DBSession`, `DBCommand`, `DBCommandResult` in `server/database.go`
- Codenames auto-populated on database init (see `populateCodenames()`)
- Sessions cached in-memory (`C2Server.sessions` map) + synced to DB

## Development Workflows

### Build & Run (Multi-Terminal Required)
```bash
# Terminal 1: Start server
make run-server  # Builds server, generates certs, starts on :8443

# Terminal 2: Run implant (connects to server)
make run-client  # Builds implant, connects to localhost:8443

# Terminal 3: Operator console
make run-console # Interactive interface (can run in demo mode without server)
```

**Critical:** Server MUST be running before implant. Console can run standalone (demo mode) or connect to live server.

### Protobuf Compilation
When modifying `proto/c2.proto`:
```bash
make proto  # Regenerates proto/c2pb/*.pb.go
```
Then rebuild all components: `make build`

### Garble Obfuscation (Advanced)
Use `build_obfuscated.sh` for production implants with string/name/control-flow obfuscation:
```bash
./build_obfuscated.sh 3  # Level 3 = heavy obfuscation
```
See `docs/OBFUSCATION_SUMMARY.md` for techniques (XOR strings, junk code, evasion checks).

## Project-Specific Conventions

### Codename System
- Every session gets a unique codename like "BoldDragon" or "QuietBlade" (adj+noun pattern in `shared/utils.go`)
- Implants use codename filenames: `primewraith_linux_amd64`
- Console displays codenames instead of raw IDs for UX

### Session ID Handling
Console accepts **partial or full** session IDs:
- Full: `cd334a2588bd0281c868894450a431fd`
- Partial: `cd334a25` (matches first 8 chars)
- Implementation in `console/session.go:findSessionByPartialID()`

### Module System
Implants load modules dynamically (see `implant/modules.go`):
- **XMRig module** (`xmrig_module.go`): Downloads binaries, manages mining processes
- Commands: `MODULE_LOAD`, `MODULE_START`, `MODULE_STOP`, `MODULE_STATUS`
- Module state persisted in implant process, not server

### PTY vs Shell Commands
- **Shell commands** (`SHELL` type): One-shot execution, output returned immediately
- **PTY commands** (`PTY_INIT` type): Interactive pseudo-terminal with `PTYStream` RPC
- PTY routing tracked in `C2Server.ptyCommandToImp` map (see `server/handlers.go:PTYStream()`)

## Key Files for Common Tasks

### Adding New Implant Features
1. Add command type to `proto/c2.proto` (e.g., `SCREENSHOT = 6`)
2. Run `make proto` to regenerate Go code
3. Implement handler in `implant/commands.go:executeCommand()`
4. Add console command in `console/commands.go` (follow `handleShellCommand` pattern)

### Modifying Implant Config
Template vars in `implant/main.go` (lines 10-42):
- Add new var with `{{.FieldName}}` syntax
- Update `ImplantConfig` struct in `server/implant_generator.go`
- Pass value in `generateFullSourceFiles()` data map

### Adding Evasion Techniques
- Platform-specific: `implant/evasion_windows.go` or `evasion_unix.go`
- Cross-platform: `implant/advanced_evasion.go`
- Build constraints: `//go:build windows` at file top

## Testing & Debugging

### Quick Test Cycle
```bash
make clean && make build  # Full rebuild
make run-server           # In one terminal
./bin/c2-client localhost:8443  # In another
```

### Debug Mode
Set `DebugMode = true` in `implant/main.go` for verbose logging (NOT for production).

### Check Errors
Server logs: `server.log`  
Client logs: `client.log` (if debug enabled)

## Common Pitfalls

1. **"Unknown command" in console**: Ensure server RPC handler exists (`server/handlers.go`) AND console command registered (`console/commands.go`)
2. **Implant won't compile**: Template syntax errors in `implant/*.go` - check `{{.VarName}}` matches `ImplantConfig` fields
3. **gRPC connection refused**: Server not running or cert mismatch - regenerate with `make certs`
4. **Module load fails**: XMRig binary download requires internet - check `xmrig_module.go:downloadXMRigBinary()`

## External Dependencies

- **protoc**: Required for `make proto` (install via package manager)
- **garble**: Optional obfuscation tool (`make tools` installs to `$GOPATH/bin`)
- **OpenSSL**: For `make certs` TLS generation
- **Go 1.24.4+**: Module uses `go.mod` with workspace-local `replace` directives

## Reference Documentation

- Full feature list: `docs/TIER1_FEATURES.md`
- Obfuscation details: `docs/OBFUSCATION_SUMMARY.md`
- Console autocomplete: `docs/AUTOCOMPLETE_DEMO.md`
- Setup garble: `docs/SETUP_GARBLE.md`
