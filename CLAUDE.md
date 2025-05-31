# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## TwinCore Gateway - Essential Developer Information

TwinCore is a configuration-driven W3C WoT servient/TD Processor that unifies HTTP serving (via embedded Caddy) and high-throughput streaming (via Redpanda/Benthos) into a single, dynamically configurable application.

### Build and Development Commands

```bash
# Build the service
go build -o twincore ./cmd/service/main.go

# Run unit tests
go test ./...

# Run integration tests
go test ./tests/integration/...

# Test with coverage
go test -cover ./...

# Enter development shell (requires Nix)
nix-shell

# Run the service
./twincore \
  -license=/etc/twincore/license.jwt \
  -pubkey=/etc/twincore/public.key \
  -db=/var/lib/twincore/config.db \
  -log-level=debug \
  -api-port=8090 \
  -parquet-log-path=./twincore_data
```

### High-Level Architecture

TwinCore bridges HTTP APIs and streaming data pipelines through W3C Web of Things specifications:

```
Thing Description → WoT Service → Binding Engine → {
  HTTP Routes → Caddy Config
  Stream Topics → Benthos Config
} → Dynamic Service Configuration
```

#### Core Components:
1. **WoT Service** (`service/wot_service.go`): Manages Thing Descriptions and registry
2. **HTTP Service** (`service/http-service.go`): Embedded Caddy for REST APIs
3. **Stream Service** (`service/stream-service.go`): Embedded Benthos for streaming
4. **State Manager** (`internal/api/state_manager.go`): DuckDB persistence + Parquet logging
5. **Container** (`internal/container/container.go`): Central dependency injection

#### Key Patterns:
- **Protocol Binding**: WoT TDs generate executable Caddy/Benthos configs
- **Dynamic Configuration**: Services reconfigure on Thing registration
- **State + History**: Current state in DuckDB, history in Parquet files

### Working with Thing Descriptions

Thing Descriptions define device capabilities and generate both HTTP endpoints and stream topics:

```go
// HTTP endpoint pattern: /things/{id}/{type}/{name}
// Stream topic pattern: things.{id}.{type}.{name}

// Example: Temperature sensor
// HTTP: GET /things/sensor1/properties/temperature
// Stream: things.sensor1.properties.temperature
```

### Testing Patterns

- **Unit Tests**: Use mocks for all interfaces (StateManager, StreamBridge, etc.)
- **Integration Tests**: Setup full container with temporary DB
- Always mock external dependencies (Kafka, HTTP clients)

### Important Interfaces

```go
// internal/api/state_manager.go
type StateManager interface {
    GetProperty(ctx context.Context, thingID, name string) (interface{}, error)
    SetProperty(ctx context.Context, thingID, name string, value interface{}) error
}

// internal/api/stream_bridge.go
type StreamBridge interface {
    PublishPropertyUpdate(thingID, propertyName string, value interface{}) error
    PublishActionInvocation(thingID, actionName string, input interface{}) error
}
```

### Current Implementation Status

⚠️ **Known Issues**:
1. **Kafka integration incomplete**: StreamBridge methods are stubs
2. **Security not enforced**: Bearer tokens defined but not validated
3. **Static stream configuration**: Should be dynamic from TDs
4. **Circular update flow**: Property updates loop between HTTP and streams
5. **Custom Parquet code**: Should use Benthos processors (parquet_encode/decode)
6. **No license-based features**: All features available regardless of license

📋 **Planned Architecture (designDoc-v2.md)**:
- Replace custom Parquet writers with Benthos processors
- JWT + OPA driven feature configuration:
  - **JWT defines features**: Each license explicitly lists allowed features
  - **OPA evaluates**: Returns defaults if no JWT, enforces limits if JWT present
  - **Config-driven**: No hardcoded tiers, fully flexible per customer
- Dynamic service registration with OPA-validated features

### Development Workflow

1. **Adding Things**: POST TD to `/api/things`
2. **Property Updates**: PUT to `/things/{id}/properties/{name}`
3. **Action Invocations**: POST to `/things/{id}/actions/{name}`
4. **Event Subscriptions**: SSE on `/things/{id}/events/{name}`

### Configuration Files

- **go.mod**: Go 1.24.3, Caddy v2, Benthos v4, DuckDB
- **shell.nix**: Development environment setup
- **designDoc.md**: Comprehensive architecture documentation

### Key Dependencies

- **caddyserver/caddy/v2**: HTTP server framework
- **benthosdev/benthos/v4**: Stream processing
- **marcboeker/go-duckdb**: State storage
- **open-policy-agent/opa**: Policy evaluation
- **greenpau/go-authcrunch**: Authentication/authorization

### Benthos Stream Patterns (v2 Architecture)

When implementing Benthos-based features:

```yaml
# Property state logging stream
stream_resources:
  - label: property_state_logger
    pipeline:
      processors:
        - license_check: { feature: "parquet_logging" }
        - parquet_encode: { schema: [...] }
    output:
      parquet:
        path: "${PARQUET_LOG_PATH}/properties/props_${!timestamp_unix():yyyy-MM-dd}.parquet"
```

License-aware processor chain:
1. Check license for feature
2. Process data if allowed
3. Use Benthos native outputs

### JWT + OPA Feature System

```json
// Example JWT license
{
  "features": {
    "bindings": ["http", "mqtt", "kafka"],
    "processors": ["json", "parquet_encode"],
    "security": ["jwt", "mtls"],
    "capabilities": {
      "max_things": 1000,
      "max_streams": 100
    }
  }
}
```

OPA evaluates features:
- With JWT: Uses explicit features
- No JWT: Returns minimal defaults (HTTP/MQTT + basic auth)

## Main Package Interfaces Reference

### Benthos v4 (github.com/redpanda-data/benthos/v4/public/service)

Key interfaces for stream processing:

```go
// StreamBuilder - Builds Benthos streams with YAML or programmatic config
type StreamBuilder interface {
    SetYAML(yaml string) error
    AddInputYAML(yaml string) error
    AddProcessorYAML(yaml string) error
    AddOutputYAML(yaml string) error
    Build() (*Stream, error)
}

// Input - Single message input
type Input interface {
    Connect(context.Context) error
    Read(context.Context) (*Message, AckFunc, error)
    Close(context.Context) error
}

// Output - Single message output
type Output interface {
    Connect(context.Context) error
    Write(context.Context, *Message) error
    Close(context.Context) error
}

// Processor - Message transformation
type Processor interface {
    Process(context.Context, *Message) (MessageBatch, error)
    Close(context.Context) error
}
```

**Note**: Benthos v4 migrated from `StreamConfig` to `StreamBuilder` pattern. Always use `service.NewStreamBuilder()` and `builder.SetYAML()`.

### Caddy v2 (github.com/caddyserver/caddy/v2)

Core interfaces for HTTP serving:

```go
// Module - Base interface for all Caddy modules
type Module interface {
    CaddyModule() ModuleInfo
}

// App - Top-level Caddy application
type App interface {
    Start() error
    Stop() error
}

// Handler - HTTP handler with error return
type Handler interface {
    ServeHTTP(http.ResponseWriter, *http.Request) error
}

// MiddlewareHandler - Chainable middleware
type MiddlewareHandler interface {
    ServeHTTP(http.ResponseWriter, *http.Request, Handler) error
}
```

### go-authcrunch (via caddy-security)

Authentication/authorization is handled through configuration structs:

```go
// Primary configuration (from github.com/greenpau/go-authcrunch)
type Config struct {
    Portal         *authn.PortalConfig
    Gatekeeper     *authz.GatekeeperConfig
    IdentityStore  *ids.IdentityStoreConfig
    TokenValidator *validator.TokenValidatorConfig
}

// Used through caddy-security App
type App struct {
    Config *authcrunch.Config
}
```

**Note**: go-authcrunch interfaces are internal. Use configuration-driven approach through caddy-security module.