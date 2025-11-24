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
build: build-server build-client build-console

# Build server
.PHONY: build-server
build-server:
	@echo "Building C2 server..."
	go build -o bin/c2-server ./server

# Build client/implant
.PHONY: build-client
build-client:
	@echo "Building C2 client..."
	go build -o bin/c2-client ./implant

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

# Generate TLS certificates for development
.PHONY: certs
certs:
	@echo "Generating development TLS certificates..."
	@mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
		-subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test ./...

# Run server
.PHONY: run-server
run-server: build-server certs
	@echo "Starting C2 server..."
	cd certs && ../bin/c2-server

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
dev-setup: deps proto certs
	@echo "Development environment ready!"

# Generate cross-platform implants (development builds)
.PHONY: generate-implants
generate-implants:
	@echo "Generating development implants..."
	@mkdir -p generated/
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.defaultServerAddr=localhost:8443" -o generated/implant-linux-amd64 ./implant
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
	@echo "  all         - Generate proto files and build all components"
	@echo "  proto       - Generate protobuf files"
	@echo "  build       - Build all components"
	@echo "  build-server- Build C2 server"
	@echo "  build-client- Build C2 client"
	@echo "  build-console- Build operator console"
	@echo "  clean       - Clean build artifacts"
	@echo "  clean-generated- Clean generated implants"
	@echo "  deps        - Install Go dependencies"
	@echo "  tools       - Install development tools (garble, etc.)"
	@echo "  certs       - Generate development TLS certificates"
	@echo "  test        - Run tests"
	@echo "  run-server  - Run C2 server"
	@echo "  run-client  - Run C2 client"
	@echo "  run-console - Run operator console"
	@echo "  generate-implants- Generate cross-platform development implants"
	@echo "  dev-setup   - Setup development environment"
	@echo "  help        - Show this help message"