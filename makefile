# Makefile for OPC UA Benthos Plugin

# Variables
APP_NAME := opcua-benthos-plugin
VERSION := $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT := $(shell git rev-parse HEAD)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Build flags
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.BuildTime=$(BUILD_TIME)' \
	-X 'main.Commit=$(COMMIT)' \
	-X 'main.Branch=$(BRANCH)'

# Docker parameters
DOCKER_IMAGE := $(APP_NAME)
DOCKER_TAG := $(VERSION)
DOCKER_REGISTRY := your-registry.com

# Default target
.PHONY: all
all: clean fmt lint test build

# Build the application
.PHONY: build
build:
	@echo "Building $(APP_NAME) version $(VERSION)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME) ./main.go

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building for multiple platforms..."
	mkdir -p dist
	# Linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o dist/$(APP_NAME)-linux-amd64 ./main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o dist/$(APP_NAME)-linux-arm64 ./main.go
	# macOS
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o dist/$(APP_NAME)-darwin-amd64 ./main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o dist/$(APP_NAME)-darwin-arm64 ./main.go
	# Windows
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o dist/$(APP_NAME)-windows-amd64.exe ./main.go

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run integration tests
.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration ./...

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Generate test coverage report
.PHONY: coverage
coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	$(GOLINT) run

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf bin/
	rm -rf dist/
	rm -f coverage.out coverage.html

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Update dependencies
.PHONY: deps-update
deps-update:
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

# Verify dependencies
.PHONY: deps-verify
deps-verify:
	@echo "Verifying dependencies..."
	$(GOMOD) verify

# Install development tools
.PHONY: tools
tools:
	@echo "Installing development tools..."
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) github.com/air-verse/air@latest

# Build Docker image
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

# Push Docker image
.PHONY: docker-push
docker-push:
	@echo "Pushing Docker image..."
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest

# Run the application locally
.PHONY: run
run: build
	@echo "Running $(APP_NAME)..."
	./bin/$(APP_NAME) -c examples/basic.yaml

# Run with development configuration
.PHONY: run-dev
run-dev: build
	@echo "Running $(APP_NAME) in development mode..."
	./bin/$(APP_NAME) -c examples/basic.yaml --log-level DEBUG

# Start development environment
.PHONY: dev-up
dev-up:
	@echo "Starting development environment..."
	docker-compose up -d

# Stop development environment
.PHONY: dev-down
dev-down:
	@echo "Stopping development environment..."
	docker-compose down

# View logs from development environment
.PHONY: dev-logs
dev-logs:
	@echo "Viewing development logs..."
	docker-compose logs -f opcua-connector

# Run load tests
.PHONY: load-test
load-test:
	@echo "Running load tests..."
	docker-compose --profile load-test up -d
	sleep 30
	docker-compose run k6

# Security scan
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	$(GOGET) github.com/securego/gosec/v2/cmd/gosec@latest
	gosec ./...

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	$(GOCMD) doc -all > docs/api.md

# Generate Swagger documentation
.PHONY: swagger
swagger:
	@echo "Generating Swagger documentation..."
	$(HOME)/go/bin/swag init -g cmd/twincore/main.go -o docs/swagger --parseInternal
	@echo "Swagger documentation generated in docs/swagger/"
	@echo "View at: http://localhost:8080/swagger/index.html (when server running)"

# Clean Swagger documentation
.PHONY: swagger-clean
swagger-clean:
	@echo "Cleaning Swagger documentation..."
	rm -rf docs/swagger/

# Create release
.PHONY: release
release: clean fmt lint test build-all docker-build
	@echo "Creating release $(VERSION)..."
	mkdir -p release
	cp dist/* release/
	tar -czf release/$(APP_NAME)-$(VERSION).tar.gz -C dist .
	@echo "Release $(VERSION) created in release/ directory"

# Install the application
.PHONY: install
install: build
	@echo "Installing $(APP_NAME)..."
	cp bin/$(APP_NAME) /usr/local/bin/

# Uninstall the application
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(APP_NAME)..."
	rm -f /usr/local/bin/$(APP_NAME)

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build          - Build the application"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  test           - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  bench          - Run benchmarks"
	@echo "  coverage       - Generate test coverage report"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo "  clean          - Clean build artifacts"
	@echo "  deps           - Download dependencies"
	@echo "  deps-update    - Update dependencies"
	@echo "  tools          - Install development tools"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-push    - Push Docker image"
	@echo "  run            - Run the application locally"
	@echo "  run-dev        - Run in development mode"
	@echo "  dev-up         - Start development environment"
	@echo "  dev-down       - Stop development environment"
	@echo "  dev-logs       - View development logs"
	@echo "  load-test      - Run load tests"
	@echo "  security-scan  - Run security scan"
	@echo "  docs           - Generate documentation"
	@echo "  release        - Create release"
	@echo "  install        - Install the application"
	@echo "  uninstall      - Uninstall the application"
	@echo "  help           - Show this help message"