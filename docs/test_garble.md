# Testing Garble Integration

## Setup
To test the garble integration, you need to install garble first. There are several ways to do this:

### Option 1: Using the Makefile (Recommended)
```bash
make tools
```

### Option 2: Manual installation
```bash
go install mvdan.cc/garble@latest
```

### Option 3: Using go run (temporary)
```bash
# The garble dependency is already included in go.mod
# So you can also use: go run mvdan.cc/garble@latest
```

## Usage Examples

### Basic generation with garble
```bash
# In the console:
generate --mtls 192.168.1.100:8443 --garble
```

### Advanced generation with garble and other options
```bash
# With multiple options:
generate --https example.com:443 --os windows --arch amd64 --garble --evasion

# With garble and debug mode:
generate --mtls localhost:8443 --garble --debug

# Cross-platform with garble:
generate --http 10.0.0.1:80 --os linux --arch arm64 --garble
```

## What Garble Does

Garble (https://github.com/burrowers/garble) provides:
- Obfuscation of Go identifiers (function names, variable names, etc.)
- Control flow obfuscation
- Literal string obfuscation
- Import path obfuscation
- Dead code elimination
- Much stronger obfuscation than standard Go build flags

## Implementation Details

The garble option:
1. Console: `--garble` or `-g` flag sets the Garble field to true
2. Server: Receives the `garble=true` option in the generation request
3. Generator: Uses `garble build` instead of `go build` when Garble is enabled
4. Fallback: Provides clear error message if garble is not installed

## Expected Behavior

When `--garble` is used:
- Console shows: "Code obfuscation enabled (garble)"
- Server uses garble instead of go for compilation
- If garble is not installed, generation fails with helpful error message
- Output binary has obfuscated symbols and improved evasion characteristics