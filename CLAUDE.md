# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TwinCore Gateway is a Web of Things (WoT) gateway that manages IoT devices through W3C Thing Descriptions. It dynamically generates data processing pipelines using Benthos and exposes HTTP APIs for device interaction.

## Development Commands

### Building
```bash
go build -o twincore ./cmd/twincore
```

### Running
```bash
./twincore --db ./twincore.db --license ./license.jwt --log-level debug
```

Key flags:
- `--license`: Path to license file (required)
- `--db`: Database file path (default: ./twincore.db)
- `--log-level`: debug, info, warn, error
- `--api-port`: API server port (default: 8090)
- `--parquet-log-path`: Parquet log path (default: ./twincore_data)

### Testing
```bash
go test ./...
go test -race ./...  # With race detector
```

### Development Environment
For Nix users:
```bash
nix-shell  # Provides Go, tools, and dependencies
```

## Architecture Overview

### Core Components

1. **Service Interfaces** (`internal/api/interfaces.go`):
   - `ConfigurationManager`: Dynamic Caddy configuration
   - `BenthosStreamManager`: Stream lifecycle management
   - `BindingGenerationService`: Generates HTTP routes from Thing Descriptions
   - `StateManager`: Thing property state with pub/sub
   - `ThingRegistry`: TD storage and retrieval
   - `ThingRegistrationService`: Orchestrates registration workflow

2. **Data Flow**:
   - Thing Registration: TD → Registry → Bindings → Streams → Routes
   - Property Updates: Device → Protocol Adapter → Stream Bridge → Benthos → State Manager → Subscribers
   - Actions: HTTP Request → Handler → Stream Bridge → Benthos → Device

3. **Key Technologies**:
   - Caddy as HTTP server/reverse proxy
   - Benthos v4 for stream processing
   - DuckDB for storage
   - JWT for authentication/licensing
   - WoT Thing Description 1.1 standard

### Package Structure

- `cmd/twincore/`: Main entry point
- `internal/api/`: Core service implementations
- `internal/caddy_app/`: Caddy integration
- `internal/security/`: Auth, licensing, device management
- `pkg/wot/`: WoT data structures and form processing
- `service/`: HTTP, Stream, and WoT service implementations
- `configs/benthos/`: Stream configuration templates

### Important Patterns

1. **Dependency Injection**: Uses `internal/container/` for service wiring
2. **Stream Generation**: Thing Descriptions automatically generate Benthos configs
3. **Protocol Bindings**: HTTP, MQTT, Kafka support through form generators
4. **State Management**: Centralized state with event-driven updates

### Access Points

- Portal UI: http://localhost:8080/portal
- Caddy Admin: http://localhost:2019
- Management API: Configured dynamically via Caddy

### Common Tasks

When modifying Thing Description handling, check:
- `pkg/wot/core.go` for TD structures
- `internal/api/wot_handler.go` for HTTP endpoints
- `pkg/wot/forms/` for protocol binding generation

When working with streams:
- Stream templates in `configs/benthos/streams/`
- Stream management in `internal/api/benthos_stream_manager.go`
- Protocol templates in `pkg/wot/forms/templates/`