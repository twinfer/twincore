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
- `pkg/wot/forms/`: Unified stream generation and binding system
- `service/`: HTTP, Stream, and WoT service implementations
- `configs/benthos/`: Stream configuration templates

### Important Patterns

1. **Dependency Injection**: Uses `internal/container/` for service wiring
2. **Unified Stream Generation**: Modern architecture using centralized template system
3. **Protocol Bindings**: HTTP, MQTT, Kafka support through unified binding generator
4. **State Management**: Centralized state with event-driven updates
5. **License-Aware Security**: Separated security domains with feature gating

### Access Points

- Portal UI: http://localhost:8080/portal
- Caddy Admin: http://localhost:2019
- Management API: Configured dynamically via Caddy

### Common Tasks

When modifying Thing Description handling, check:
- `pkg/wot/core.go` for TD structures
- `internal/api/wot_handler.go` for HTTP endpoints
- `pkg/wot/forms/` for unified binding generation system

When working with streams:
- Stream management in `internal/api/benthos_stream_manager.go`
- Unified stream generation in `pkg/wot/forms/stream_generator_v2.go`
- Stream configuration building in `pkg/wot/forms/stream_config_builder.go`
- Template execution in `pkg/wot/forms/template_executor.go`
- Protocol templates in `pkg/wot/forms/templates/`

When working with security:
- System security in `internal/security/` with separated domains
- License checking via `pkg/types/license_security.go` UnifiedLicenseChecker
- Feature gating throughout the system based on license tiers

## Forms Package Architecture (pkg/wot/forms/)

The forms package has been refactored to use a unified, centralized architecture:

### Core Components

1. **TemplateExecutor** (`template_executor.go`):
   - Centralized YAML template loading using `//go:embed templates/*.yaml`
   - Replaces individual form template embedding
   - Provides unified template execution for all protocols

2. **StreamGeneratorV2** (`stream_generator_v2.go`):
   - Main entry point for generating streams from WoT interactions
   - Uses generic `wot.Form` interface (no concrete form types)
   - Generates property observation, action command, and event notification streams
   - Supports automatic persistence stream generation

3. **StreamConfigBuilder** (`stream_config_builder.go`):
   - Builds complete stream configurations from high-level parameters
   - Integrates with TemplateExecutor, MappingEngine, and OutputConfigFactory
   - Handles input/output endpoint configuration for all protocols

4. **MappingEngine** (`mapping_engine.go`):
   - Generates Bloblang mappings for data transformation
   - Template-based approach for different interaction types
   - Supports property observations, actions, events, and persistence

5. **OutputConfigFactory** (`output_factory.go`):
   - Creates output configurations for various sink types
   - Supports file, S3, Parquet, stream_bridge, stdout, etc.
   - Extensible factory pattern for custom output types

6. **UnifiedBindingGeneratorAdapter** (`binding_generator_unified_adapter.go`):
   - Adapter that wraps BindingGeneratorV2 for interface compatibility
   - Used by the container system for dependency injection

### Recent Cleanup

The following deprecated files were removed during refactoring:
- `enhanced_forms.go` - Contained unreachable code and deprecated functionality
- `http_form.go` - Individual HTTP form implementation (replaced by unified system)
- `mqtt_form.go` - Individual MQTT form implementation (replaced by unified system) 
- `kafka_form.go` - Individual Kafka form implementation (replaced by unified system)
- `protocol_forms.go` - Utility functions no longer needed

### Architecture Benefits

- **Eliminated Code Duplication**: Single template system instead of per-protocol implementations
- **Generic Interface Usage**: Works with `wot.Form` interface, avoiding type assertions
- **Centralized Configuration**: All stream generation goes through unified pipeline
- **Better Separation of Concerns**: Clear separation between template execution, stream generation, and configuration building
- **Extensibility**: Easy to add new protocols and output types through factory patterns

### Integration Flow

```
Container → UnifiedBindingGeneratorAdapter → BindingGeneratorV2 → StreamGeneratorV2 → StreamConfigBuilder → TemplateExecutor + MappingEngine + OutputConfigFactory
```

## WoT Thing Description Compliance

TwinCore's WoT implementation (`pkg/wot/core.go`) follows the W3C WoT Thing Description 1.1 specification:

### Compliance Status

**✅ Fully Compliant Areas:**
- Core TD structure with mandatory fields (@context, title, security, securityDefinitions)
- Complete JSON Schema support for DataSchema (all types, validation keywords)
- Proper affordance structure (Properties, Actions, Events)
- Comprehensive security scheme support (basic, bearer, apikey, oauth2, psk)
- Interaction affordance base types with forms, uriVariables, and metadata
- Version information and link structures
- Comprehensive TD validation using official W3C JSON Schema

**✅ Recently Enhanced:**
- Extended Form interface with WoT TD 1.1 compliance methods:
  - `GetSecurity()` - Form-level security overrides
  - `GetResponse()` - Expected response definitions
  - `GetURIVariables()` - URI template variables
  - `GetSubprotocol()` - Protocol variation indicators
- Fixed SecurityScheme semantic type field naming
- Added validation helpers for compliance checking
- Embedded official WoT TD 1.1 JSON Schema for validation
- Added `ValidateThingDescription()` method to SchemaValidator interface
- Created `TestForm` concrete implementation for testing and validation
- **3-Layer Validation Architecture** for optimal performance and comprehensive checking

**⚠️ Implementation Notes:**
- **Validation Strategy**: Fast basic validation → JSON Schema validation → Semantic validation
- Form interface provides additional methods beyond spec for system integration
- GenerateConfig() method is TwinCore-specific for Benthos stream generation
- Validation helpers available: `ValidateBasicCompliance()`, `ValidateOperationTypes()`
- JSON Schema validation location: `configs/td-json-schema-validation.json`
- Schema embedded in: `internal/api/schema/td-json-schema-validation.json`

**📋 Specification Reference:**
- Based on: [W3C WoT Thing Description 1.1](https://www.w3.org/TR/wot-thing-description11/)
- Context URI: `https://www.w3.org/2022/wot/td/v1.1`
- Supports proper operation type validation per affordance type
- Uses official JSON Schema from W3C WoT Working Group

### Usage for WoT Compliance

```go
// Basic validation
td := &wot.ThingDescription{ /* ... */ }
issues := td.ValidateBasicCompliance()

// Validate affordance operation types
property := &wot.PropertyAffordance{ /* ... */ }
opIssues := property.ValidateOperationTypes()

// Complete TD validation with JSON Schema
validator := api.NewJSONSchemaValidator()
err := validator.ValidateThingDescription(logger, td)

// Using TestForm for concrete form implementation
form := &wot.TestForm{
    HrefValue:        "http://example.com/property",
    ContentTypeValue: "application/json",
    OpValue:          []string{"readproperty"},
}
```