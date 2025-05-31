# WoT Forms Package

This package provides form implementations for Web of Things (WoT) Thing Descriptions, enabling protocol binding generation for TwinCore's hybrid HTTP/stream architecture.

## Overview

WoT Forms translate Thing Description affordances (properties, actions, events) into executable protocol configurations for both HTTP endpoints and streaming data pipelines.

## Key Components

### Form Implementations
- **HTTPForm**: HTTP protocol bindings with W3C WoT compliance
- **KafkaForm**: Kafka/Redpanda streaming bindings with SASL support
- **MQTTForm**: MQTT pub/sub bindings (planned)

### Binding Generator
- **BindingGenerator**: Centralizes all protocol binding generation
- **AllBindings**: Container for generated HTTP routes, streams, and processors
- **ProcessorChain**: Benthos processor configurations

## ✨ New Architecture Features

### 🔒 App-Level License Validation
- **Before**: License checks embedded as Benthos processors
- **After**: License validation happens at application level before stream generation
- **Benefits**: Cleaner separation of concerns, no license logic in stream configs

### 🗄️ Configurable Persistence Layer
- **Before**: Hard-coded Parquet logging only
- **After**: Pluggable persistence backends with format options
- **Supported Sinks**:
  - **Local File**: JSON, Parquet, CSV formats
  - **AWS S3**: Automatic partitioning by date/time
  - **Kafka**: Persistence to separate Kafka topics
  - **No-op**: Disable persistence entirely

### 🏗️ Persistence Configuration Example

```go
// License-based persistence configuration
persistenceConfig := map[string]interface{}{
    "sink_type": "s3",           // file, s3, kafka, noop
    "format": "parquet",         // json, parquet, csv
    "s3_bucket": "my-data-lake",
    "s3_region": "us-west-2",
}

// Generator automatically selects appropriate output
bindings, err := generator.GenerateAllBindings(td)
```

## Features

### Security Integration
- HTTP: Basic Auth, Bearer Token, API Key, OAuth2
- Kafka: SASL PLAIN, SCRAM-SHA-256/512, OAUTHBEARER
- Environment variable placeholders for credentials

### License-Aware Generation
- ✅ **App-level validation**: License checked before stream creation
- ✅ **Feature-based persistence**: `data_persistence` instead of `parquet_logging`
- ✅ **Graceful degradation**: Skip streams when features unavailable
- ✅ **Configurable sinks**: Different backends based on license tier

### Template System
- Embedded YAML templates for Benthos configurations
- Protocol-specific input/output generation
- Dynamic template selection based on WoT operations

## Architecture

```
Thing Description
       ↓
App-Level License Check ← LicenseChecker.IsFeatureAvailable("data_persistence")
       ↓
   WoT Forms (HTTP, Kafka, MQTT)
       ↓ 
 Binding Generator
       ↓
┌─────────────┬──────────────┬─────────────┐
│HTTP Routes  │   Streams    │ Processors  │
│             │              │             │
│ Caddy       │   Benthos    │ WoT Mapping │
│ Config      │   YAML       │ Data Format │
│             │              │ (No License)│
└─────────────┴──────────────┴─────────────┘
       ↓
┌─────────────────────────────────────────────────┐
│              Configurable Outputs               │
│                                                 │
│  Local File    │    AWS S3     │    Kafka      │
│  ┌─────────────┼─────────────────┼─────────────┐ │
│  │ JSON        │ Auto-partition  │ Persistence │ │
│  │ Parquet     │ Date/time paths │ Topics      │ │
│  │ CSV         │ IAM roles       │ Retention   │ │
│  └─────────────┴─────────────────┴─────────────┘ │
└─────────────────────────────────────────────────┘
```

## Persistence Sink Types

### 1. Local File (`sink_type: "file"`)
```yaml
output:
  file:
    path: "./twincore_data/properties/device1_temperature_2024-01-15.jsonl"
    codec: none
```

### 2. AWS S3 (`sink_type: "s3"`)
```yaml
output:
  aws_s3:
    bucket: "my-data-lake"
    path: "twincore/properties/device1/temperature/2024/01/15/temperature_uuid.parquet"
    region: "${AWS_REGION:us-east-1}"
    credentials:
      id: "${AWS_ACCESS_KEY_ID}"
      secret: "${AWS_SECRET_ACCESS_KEY}"
```

### 3. Kafka Persistence (`sink_type: "kafka"`)
```yaml
output:
  kafka:
    addresses: ["kafka1:9092", "kafka2:9092"]
    topic: "twincore.persistence.device1.temperature"
    key: "${! this.thing_id }-temperature"
```

### 4. No-op (`sink_type: "noop"`)
```yaml
output:
  drop: {}  # Discard all data
```

## Usage Example

```go
// Create binding generator
generator := forms.NewBindingGenerator(
    logger, licenseChecker, streamManager,
    parquetConfig, kafkaConfig, mqttConfig,
)

// App-level license validation
if !licenseChecker.IsFeatureAvailable("data_persistence") {
    logger.Info("Data persistence not available in license")
    return nil
}

// Generate all bindings from Thing Description
bindings, err := generator.GenerateAllBindings(td)
if err != nil {
    return err
}

// Use generated configurations
for routeID, route := range bindings.HTTPRoutes {
    // Configure Caddy routes
}

for streamID, stream := range bindings.Streams {
    // Deploy Benthos streams (no embedded license checks)
}
```

## Configuration

### License-Based Persistence Config
```json
{
  "data_persistence": {
    "sink_type": "s3",
    "format": "parquet", 
    "s3_bucket": "enterprise-data-lake",
    "s3_region": "us-west-2"
  }
}
```

### Generated Clean Benthos YAML
```yaml
input:
  kafka:
    addresses: ["broker1:9092"]
    topics: ["things.device1.properties.temperature"]
    consumer_group: "twincore-property-persistence-device1"

pipeline:
  processors:
    - label: "property_normalization"
      mapping: |
        root.thing_id = "device1"
        root.property_name = "temperature"
        root.value = this.value
        root.timestamp = timestamp_unix_nano()
        root.source = this.source.or("stream")
    
    - label: "parquet_encoding"
      parquet_encode:
        schema:
          - name: "thing_id"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"

output:
  aws_s3:
    bucket: "enterprise-data-lake"
    path: "twincore/properties/device1/temperature/2024/01/15/temperature_uuid.parquet"
```

## Migration from Old Architecture

### Before (Tightly Coupled)
```go
// License validation embedded in stream
processors := []ProcessorConfig{
    {
        Type: types.ProcessorLicenseCheck,  // ❌ Stream-level validation
        Config: map[string]interface{}{
            "feature": "parquet_logging",   // ❌ Hard-coded to Parquet
        },
    },
}

// Hard-coded file output
output := types.StreamEndpointConfig{
    Type: "file",                          // ❌ Fixed to local file
    Config: map[string]interface{}{
        "path": "/fixed/path.parquet",     // ❌ Parquet only
    },
}
```

### After (Decoupled)
```go
// App-level license validation
if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
    return nil // ✅ Skip stream creation entirely
}

// Dynamic persistence configuration
persistenceConfig := bg.licenseChecker.GetFeatureConfig("data_persistence")
outputConfig, err := bg.generatePersistenceOutputConfig(thingID, propName, persistenceConfig)

// Clean processor chain (no license logic)
processors := []ProcessorConfig{
    {
        Type: types.ProcessorBloblangWoTProperty, // ✅ Pure data transformation
        Config: map[string]interface{}{
            "mapping": bg.generatePropertyPersistenceMapping(thingID, propName),
        },
    },
}
```

## Extension Points

### Adding New Persistence Sinks
1. Add new sink type to `generatePersistenceOutputConfig`
2. Implement sink-specific configuration method
3. Update license configuration examples

### Adding New Protocols
1. Implement the `EnhancedForm` interface
2. Add protocol-specific security extraction
3. Create Benthos templates
4. Update `ConvertFormToStreamEndpoint`

## Testing

See `enhanced_forms_test.go` for comprehensive examples of:
- Form configuration generation
- Security scheme handling
- Template rendering
- Binding generation workflows
- Persistence sink configuration