# Package Alignment with Benthos v4 Implementation

## Overview

This document describes the alignment between the `pkg/` directory structures and the new Benthos v4 stream management implementation in `internal/api/`.

## Key Changes

### 1. Benthos API Migration
- Migrated from deprecated `service.StreamConfig` to `service.StreamBuilder`
- All stream configurations now use YAML-based setup via `StreamBuilder.SetYAML()`
- Stream lifecycle properly managed with `Stream.Run()` and `Stream.Stop()`

### 2. Type System Updates

#### pkg/types/config.go
- Added clarification comment that `StreamConfig` is for high-level configuration
- Distinguished from Benthos `StreamBuilder` API

#### pkg/types/benthos_stream.go (NEW)
- Defined stream types aligned with WoT interactions
- Added processor type constants
- Created protocol and direction enums
- Added configuration structures for Kafka, MQTT, and Parquet

### 3. Forms Package Enhancement

#### Existing Forms
- `HTTPForm` - Generates HTTP client/server YAML configurations
- `KafkaForm` - Generates Kafka input/output YAML configurations
- Forms already compatible with `StreamBuilder.SetYAML()` approach

#### New Additions
- `enhanced_forms.go` - Provides utilities for stream configuration
- Helper functions for processor chain generation
- Parquet schema generation for different interaction types
- Stream direction detection based on WoT operations

### 4. Integration Points

#### Stream Creation Flow
1. WoT Thing Description parsed
2. Forms generate protocol-specific YAML configurations
3. Processor chains built based on interaction type
4. Complete YAML assembled and applied via `StreamBuilder.SetYAML()`
5. Stream built and started with proper lifecycle management

#### Security Integration
- Forms extract security from WoT SecuritySchemes
- Environment variables used for sensitive data
- Supports: Basic Auth, Bearer, API Key, OAuth2, SASL

## Remaining Work

### To Be Implemented
1. MQTT form implementation
2. WebSocket form implementation
3. Enhanced processor templates for complex transformations
4. Stream metrics integration

### Configuration Templates
The `configs/benthos/streams/` directory contains example stream configurations:
- `property_logger.yaml` - Parquet logging with license checking
- `event_logger.yaml` - Event stream processing
- `action_logger.yaml` - Action invocation logging

These demonstrate the target YAML structure that forms should generate.

## Usage Example

```go
// Create stream from Thing Description
td := parseThingDescription(tdJSON)
form := td.Properties["temperature"].Forms[0]

// Generate endpoint config
endpointConfig, _ := forms.ConvertFormToStreamEndpoint(form)

// Build processor chain
processors := forms.GenerateProcessorChain("property", map[string]interface{}{
    "enable_parquet": true,
})

// Create stream via manager
streamReq := StreamCreationRequest{
    ThingID:         td.ID,
    InteractionType: "property",
    InteractionName: "temperature",
    Direction:       "inbound",
    Input:           endpointConfig,
    ProcessorChain:  processors,
    Output:          parquetOutputConfig,
}
stream, _ := streamManager.CreateStream(ctx, streamReq)
```

## Testing

Forms package includes comprehensive tests for security extraction and YAML generation. These ensure compatibility with the new stream manager implementation.