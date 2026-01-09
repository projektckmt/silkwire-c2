# Omnic2 C2 Framework Makefile

# Variables
PROTO_DIR = proto
PROTO_FILES = $(PROTO_DIR)/c2.proto
PROTO_OUT_DIR = $(PROTO_DIR)/c2pb
GO_OUT_DIR = .

# Default target
.PHONY: all
all: proto build

# Generate protobuf files
.PHONY: proto
proto:
	@echo "Generating protobuf files..."
	@mkdir -p $(PROTO_OUT_DIR)
	export PATH=$$PATH:$$(go env GOPATH)/bin && \
	protoc --go_out=$(GO_OUT_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GO_OUT_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)

# Build all components
.PHONY: build
build: build-server build-console

# Build server
.PHONY: build-server
build-server:
	@echo "Building C2 server..."
	go build -o bin/c2-server ./server

# Build client/implant
.PHONY: build-client
build-client:
	@echo "Building C2 client..."
	go build -C implant -o ../bin/c2-client .

# Build console
.PHONY: build-console
build-console:
	@echo "Building operator console..."
	go build -o bin/c2-console ./console

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf $(PROTO_OUT_DIR)/
	@# Clean old certs directory if it exists (legacy)
	@if [ -d certs ]; then rm -rf certs/ && echo "Removed legacy certs/ directory"; fi

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

# Install development tools (including garble)
.PHONY: tools
tools:
	@echo "Installing development tools..."
	@echo "Installing garble for code obfuscation..."
	@export PATH="$$(go env GOPATH)/bin:$$PATH" && go install mvdan.cc/garble@latest
	@echo "Verifying garble installation..."
	@if [ -f "$$(go env GOPATH)/bin/garble" ]; then \
		echo "✓ garble installed successfully at $$(go env GOPATH)/bin/garble"; \
		export PATH="$$(go env GOPATH)/bin:$$PATH" && garble version; \
	else \
		echo "✗ garble installation failed"; \
	fi
	@echo ""
	@echo "To use garble in your shell, add the following to your profile:"
	@echo "export PATH=\"\$$(go env GOPATH)/bin:\$$PATH\""
	@echo ""
	@echo "Or run: export PATH=\"$$(go env GOPATH)/bin:\$$PATH\""

# Initialize CA and certificates (auto-generated on first server run)
# The server now handles certificate generation automatically via CAManager
# Certificates are stored in ca/ directory:
#   ca/ca.crt, ca/ca.key - Certificate Authority
#   ca/certs/*.crt, ca/certs/*.key - Server certificates (persistent)
.PHONY: init-ca
init-ca:
	@echo "CA and certificates are auto-generated on server startup."
	@echo "To manually initialize, run the server once: make run-server"
	@echo ""
	@echo "Certificate storage structure:"
	@echo "  ca/ca.crt          - CA certificate"
	@echo "  ca/ca.key          - CA private key"
	@echo "  ca/certs/          - Server certificates directory"
	@echo "    server.crt/.key  - Main server certificate (port 8443)"
	@echo "    <listener>.crt/.key - Per-listener certificates"

# Clean CA and certificates (WARNING: will invalidate all existing implants)
.PHONY: clean-ca
clean-ca:
	@echo "WARNING: This will delete all CA and server certificates!"
	@echo "All existing implants will fail to connect after this."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "Cleaning CA and certificates..."
	rm -rf ca/

# View CA certificate info
.PHONY: ca-info
ca-info:
	@if [ -f ca/ca.crt ]; then \
		echo "CA Certificate Info:"; \
		openssl x509 -in ca/ca.crt -noout -subject -dates -issuer; \
	else \
		echo "CA not initialized. Run 'make run-server' first."; \
	fi

# List all server certificates
.PHONY: list-certs
list-certs:
	@echo "Server Certificates:"
	@if [ -d ca/certs ]; then \
		for cert in ca/certs/*.crt; do \
			if [ -f "$$cert" ]; then \
				echo ""; \
				echo "=== $$cert ==="; \
				openssl x509 -in "$$cert" -noout -subject -dates 2>/dev/null || echo "  (invalid)"; \
			fi; \
		done; \
	else \
		echo "No certificates found. Run 'make run-server' first."; \
	fi

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test ./...

# Run server
.PHONY: run-server
run-server: build-server
	@echo "Starting C2 server..."
	@echo "Certificates will be auto-generated in ca/ directory"
	./bin/c2-server

# Run client with server address
.PHONY: run-client
run-client: build-client
	@echo "Starting C2 client..."
	./bin/c2-client localhost:8443

# Run console
.PHONY: run-console
run-console: build-console
	@echo "Starting operator console..."
	@echo "Note: This will run in demo mode. To connect to a server use:"
	@echo "  ./bin/c2-console <server:port>"
	./bin/c2-console

# Development setup
.PHONY: dev-setup
dev-setup: deps proto
	@echo "Development environment ready!"
	@echo "Run 'make run-server' to start the server (CA will be auto-generated)"

# Generate cross-platform implants (development builds)
.PHONY: generate-implants
generate-implants:
	@echo "Generating development implants..."
	@mkdir -p generated/
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.defaultServerAddr=localhost:8443" -o generated/implant-linux-amd64 ./implant
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-X main.defaultServerAddr=localhost:8443" -o generated/implant-linux-arm7 ./implant
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.defaultServerAddr=localhost:8443" -o generated/implant-windows-amd64.exe ./implant
	GOOS=windows GOARCH=386 go build -ldflags "-X main.defaultServerAddr=localhost:8443" -o generated/implant-windows-386.exe ./implant
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.defaultServerAddr=localhost:8443" -o generated/implant-darwin-amd64 ./implant
	@echo "Generated implants in generated/ directory"

# Clean generated implants
.PHONY: clean-generated
clean-generated:
	@echo "Cleaning generated implants..."
	rm -rf generated/

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  all              - Generate proto files and build all components"
	@echo "  proto            - Generate protobuf files"
	@echo "  build            - Build all components"
	@echo "  build-server     - Build C2 server"
	@echo "  build-client     - Build C2 client"
	@echo "  build-console    - Build operator console"
	@echo ""
	@echo "Run:"
	@echo "  run-server       - Run C2 server (auto-generates CA/certs)"
	@echo "  run-client       - Run C2 client"
	@echo "  run-console      - Run operator console"
	@echo ""
	@echo "Certificates (persistent CA-based):"
	@echo "  init-ca          - Show CA/cert info (auto-generated on server start)"
	@echo "  ca-info          - View CA certificate details"
	@echo "  list-certs       - List all server certificates"
	@echo "  clean-ca         - Delete CA and all certificates (WARNING: breaks implants)"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean            - Clean build artifacts"
	@echo "  clean-generated  - Clean generated implants"
	@echo ""
	@echo "Development:"
	@echo "  deps             - Install Go dependencies"
	@echo "  tools            - Install development tools (garble, etc.)"
	@echo "  test             - Run tests"
	@echo "  generate-implants- Generate cross-platform development implants"
	@echo "  dev-setup        - Setup development environment"
	@echo ""
	@echo "Certificate Storage (in ca/ directory):"
	@echo "  ca/ca.crt, ca/ca.key     - Certificate Authority (10 year validity)"
	@echo "  ca/certs/server.crt/.key - Main server cert (1 year, auto-renewed)"
	@echo "  ca/certs/<id>.crt/.key   - Listener certificates (persistent)"