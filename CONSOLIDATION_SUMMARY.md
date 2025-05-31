# Consolidation Summary: Removed Duplication in Stream Configuration

## Problem
There was significant duplication in YAML generation for Benthos streams between:
1. `internal/api/benthos_stream_manager.go` - Hardcoded YAML generation
2. `pkg/wot/forms/enhanced_forms.go` - Centralized binding generator
3. Configuration duplication across multiple files

## Solution Implemented

### 1. **Centralized YAML Generation**
- All YAML generation logic is now centralized in `pkg/wot/forms/enhanced_forms.go`
- Added `generateStreamRequestYAML()` method that generates complete Benthos YAML configuration
- This method handles input, processor chain, and output configuration consistently

### 2. **Updated Stream Manager**
- Modified `SimpleBenthosStreamManager.generateBenthosStreamBuilder()` to:
  - First check for YAML in stream metadata (`yaml_config` key)
  - Fall back to deprecated local generation only for backward compatibility
  - Log warnings when using deprecated path
- Marked all local YAML generation methods as DEPRECATED

### 3. **Enhanced Binding Generator Integration**
- Modified `generatePropertyLoggingStream()` to:
  - Generate YAML using centralized method
  - Store YAML in stream metadata before creation
  - Pass YAML through to stream manager
- This pattern should be followed for all stream types

### 4. **Consistent Environment Variables**
- All Kafka broker configurations now use: `${KAFKA_BROKERS:localhost:9092}`
- All MQTT broker configurations now use: `${MQTT_BROKER:tcp://localhost:1883}`
- Updated default configurations in `td_stream_composer.go`

## Benefits

1. **Single Source of Truth**: YAML generation logic is now in one place
2. **Consistency**: All streams use the same configuration patterns
3. **Maintainability**: Changes to YAML format only need to be made in one location
4. **License Integration**: Centralized generation makes it easier to apply license restrictions
5. **Testing**: Easier to test YAML generation in isolation

## Migration Path

For existing code that creates streams directly:
1. Use the centralized binding generator to create streams
2. If direct stream creation is needed, generate YAML first and add to metadata:
   ```go
   request.Metadata["yaml_config"] = yamlConfig
   ```

## Next Steps

1. Implement the remaining stream generation methods in `enhanced_forms.go`
2. Remove deprecated YAML generation methods from `benthos_stream_manager.go` after migration
3. Update all stream creation code to use the centralized approach
4. Add comprehensive tests for YAML generation