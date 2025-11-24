# Generate Command Autocomplete Feature

## Overview
The `generate` command now includes intelligent autocomplete functionality that automatically suggests the eth0 IP address with appropriate default ports.

## Features

### 1. **Auto-detect eth0 IP Address**
When typing `generate --mtls ` and pressing TAB, the console will automatically suggest:
- **eth0 IP address** + **:8443** (default mTLS port)

### 2. **Transport-specific Port Defaults**
Different transport types suggest different default ports:
- `--mtls`: Suggests `<eth0_ip>:8443`
- `--http`: Suggests `<eth0_ip>:80`
- `--https`: Suggests `<eth0_ip>:443`

### 3. **OS/Architecture Autocomplete**
- `--os`: Suggests `windows`, `linux`, `darwin`
- `--arch`: Suggests `amd64`, `386`, `arm64`, `arm`
- `--format`: Suggests `exe`, `dll`, `shared`, `service`

### 4. **Flag Autocomplete**
All generate command flags are autocompleted, including:
- Transport flags: `--mtls`, `--http`, `--https`, `--dns`
- Configuration flags: `--os`, `--arch`, `--format`
- Obfuscation flags: `--obfuscation-level`, `--string-obf`, `--name-obf`, etc.
- Evasion flags: `--anti-vm`, `--anti-debug`, `--sandbox-evasion`, etc.

## Usage Examples

### Basic Usage
```bash
# Type this and press TAB after --mtls
silkwire >> generate --mtls <TAB>

# Autocompletes to:
silkwire >> generate --mtls 192.168.120.146:8443
```

### Full Command with Autocomplete
```bash
silkwire >> generate --mtls <TAB> --os <TAB>
# Results in:
silkwire >> generate --mtls 192.168.120.146:8443 --os windows
```

### HTTP/HTTPS Variants
```bash
# HTTP uses port 80
silkwire >> generate --http <TAB>
# Suggests: 192.168.120.146:80

# HTTPS uses port 443
silkwire >> generate --https <TAB>
# Suggests: 192.168.120.146:443
```

## Implementation Details

### Network Interface Detection
The autocomplete feature uses Go's `net` package to:
1. Look up the `eth0` network interface
2. Extract the IPv4 address
3. Combine it with the appropriate default port

### Code Location
- **Helper function**: `getEth0IP()` in `console/main.go`
- **Autocomplete logic**: `ValidArgsFunction` in `generateCmd` definition

### Fallback Behavior
If eth0 is not available or has no IP:
- Autocomplete still works for flags and options
- No IP suggestion is shown (user must type manually)
- No errors are displayed

## Benefits

1. **Faster workflow**: No need to run `ip addr` or remember your local IP
2. **Fewer mistakes**: Correct port defaults prevent common configuration errors
3. **Better UX**: Consistent with modern CLI tools (kubectl, docker, etc.)
4. **Operator-friendly**: Reduces cognitive load during engagements

## Testing

Test autocomplete functionality:
```bash
# Test mTLS autocomplete
./bin/c2-console __complete generate --mtls ''

# Test HTTP autocomplete
./bin/c2-console __complete generate --http ''

# Test OS autocomplete
./bin/c2-console __complete generate --mtls 192.168.120.146:8443 --os ''
```

## Notes

- Requires the `eth0` interface to be present and configured
- Works in both interactive mode and shell completion
- Compatible with the reeflective/console framework
- Does not interfere with manual IP entry
