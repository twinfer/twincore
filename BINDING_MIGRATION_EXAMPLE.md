# Centralized WoT Binding Generation - Migration Example

This document demonstrates how the new centralized binding generation approach replaces the previous scattered implementation.

## Before: Scattered Binding Logic

Previously, binding generation was scattered across multiple files:

### Old Approach Issues:
```go
// internal/api/benthos_stream_factory.go - Benthos-specific logic
func (f *StreamConfigFactory) NewPropertyLoggerStream(parquetPath string) (*service.StreamBuilder, error) {
    // Hardcoded YAML templates
    // No license checking
    // No WoT schema awareness
}

// internal/models/property_update.go - Separate Parquet models
type PropertyStateParquetRecord struct {
    ThingID      string `parquet:"..."`
    PropertyName string `parquet:"..."`
    // Duplicated schema definitions
}

// internal/api/wot_handler.go - HTTP route generation
func (h *WoTHandler) handlePropertyUpdate(w http.ResponseWriter, r *http.Request) {
    // Manual HTTP endpoint handling
    // No connection to stream generation
}
```

## After: Centralized WoT Binding Generation

### New Approach Benefits:
```go
// pkg/wot/forms/enhanced_forms.go - Single source of truth
type BindingGenerator struct {
    logger         logrus.FieldLogger
    licenseChecker LicenseChecker  // Feature-aware
    // Protocol configs centralized
}

// One method generates ALL bindings
func (bg *BindingGenerator) GenerateAllBindings(td *wot.ThingDescription) (*AllBindings, error) {
    // HTTP routes + Benthos streams + Processor chains
    // License-aware feature gating
    // WoT specification compliance
    // Composition-based processors
}
```

## Migration Example

### Step 1: Replace Stream Factory Usage

**Before:**
```go
// internal/api/some_service.go
factory := NewStreamConfigFactory(logger)
stream, err := factory.NewPropertyLoggerStream("/path/to/parquet")
```

**After:**
```go
// Any service using centralized approach
import "github.com/twinfer/twincore/pkg/wot"

integration := wot.NewBindingIntegration(logger)
result, err := integration.ProcessThingDescription(ctx, thingDescription)

// Get all HTTP endpoints
for _, endpoint := range result.HTTPEndpoints {
    // Deploy to Caddy via Admin API
    deployHTTPEndpoint(endpoint)
}

// Get all stream configurations
for _, streamConfig := range result.StreamConfigs {
    // Deploy to Benthos
    deployBenthosStream(streamConfig)
}
```

### Step 2: Replace Manual HTTP Route Generation

**Before:**
```go
// internal/api/wot_handler.go
func (h *WoTHandler) registerPropertyRoutes(td *wot.ThingDescription) {
    for propName, prop := range td.Properties {
        path := fmt.Sprintf("/things/%s/properties/%s", td.ID, propName)
        // Manual route registration
        h.router.HandleFunc(path, h.handlePropertyUpdate).Methods("PUT")
    }
}
```

**After:**
```go
// The centralized approach automatically generates routes from TD forms
result, err := integration.ProcessThingDescription(ctx, td)

// All HTTP routes are generated with proper WoT compliance
for _, endpoint := range result.HTTPEndpoints {
    log.Printf("Generated route: %s %s", endpoint.Method, endpoint.Path)
    // Routes include security, content-type, headers from TD forms
}
```

### Step 3: Replace Hardcoded Parquet Schemas

**Before:**
```go
// internal/models/property_update.go
type PropertyStateParquetRecord struct {
    ThingID      string `parquet:"name=thing_id,type=BYTE_ARRAY,convertedtype=UTF8"`
    PropertyName string `parquet:"name=property_name,type=BYTE_ARRAY,convertedtype=UTF8"`
    // Hardcoded, not generated from TD schema
}
```

**After:**
```go
// pkg/wot/forms/enhanced_forms.go
func (bg *BindingGenerator) generatePropertyParquetSchema() []map[string]interface{} {
    // Generated dynamically based on WoT DataSchema
    // License-aware (only if parquet_logging feature enabled)
    // Consistent with Benthos parquet_encode processor expectations
}
```

## Usage Example

### Complete Thing Description Processing

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    
    "github.com/sirupsen/logrus"
    "github.com/twinfer/twincore/pkg/wot"
)

func main() {
    logger := logrus.New()
    integration := wot.NewBindingIntegration(logger)
    
    // Sample Thing Description
    td := &wot.ThingDescription{
        ID:    "sensor1",
        Title: "Temperature Sensor",
        Properties: map[string]*wot.PropertyAffordance{
            "temperature": {
                DataSchemaCore: wot.DataSchemaCore{
                    Type:       "number",
                    Unit:       "celsius",
                    Observable: true,
                    ReadOnly:   false,
                },
                InteractionAffordance: wot.InteractionAffordance{
                    Forms: []wot.Form{
                        // HTTP form for property access
                        &forms.HTTPForm{
                            Href: "/things/{thingId}/properties/temperature",
                            Op:   []string{"readproperty", "writeproperty", "observeproperty"},
                        },
                    },
                },
            },
        },
    }
    
    // Generate ALL bindings from the Thing Description
    result, err := integration.ProcessThingDescription(context.Background(), td)
    if err != nil {
        log.Fatalf("Failed to process TD: %v", err)
    }
    
    // Print summary
    log.Printf("Generated bindings for Thing: %s", result.ThingID)
    log.Printf("HTTP Endpoints: %d", len(result.HTTPEndpoints))
    log.Printf("Stream Configs: %d", len(result.StreamConfigs))
    log.Printf("Total Processors: %d", result.Summary.TotalProcessors)
    
    // Display HTTP endpoints
    for _, endpoint := range result.HTTPEndpoints {
        log.Printf("HTTP: %s %s (%s)", endpoint.Method, endpoint.Path, endpoint.Interaction.Purpose)
    }
    
    // Display stream configurations
    for _, stream := range result.StreamConfigs {
        log.Printf("Stream: %s (%s, %d processors)", stream.Name, stream.Interaction.Purpose, stream.ProcessorCount)
        log.Printf("YAML:\n%s", stream.YAML)
    }
}
```

## Key Improvements

1. **Single Source of Truth**: All binding generation centralized in `pkg/wot/forms/`
2. **WoT Specification Compliance**: Generated from actual TD forms and schemas
3. **License-Aware**: Feature gating integrated into processor chains
4. **Composition-Based**: Processor chains built using composition pattern
5. **Type Safety**: Strong typing throughout the generation pipeline
6. **Testability**: Easy to mock LicenseChecker and test different scenarios
7. **Maintainability**: One place to update binding logic for all protocols

## Migration Strategy

1. **Phase 1**: Keep old code working, add new centralized generation alongside
2. **Phase 2**: Update services to use `BindingIntegration` for new Thing Descriptions
3. **Phase 3**: Migrate existing TDs to use centralized approach
4. **Phase 4**: Remove old scattered binding logic files:
   - `internal/api/benthos_stream_factory.go`
   - `internal/models/*ParquetRecord` types  
   - Manual HTTP route registration code

This approach maintains backward compatibility while providing a clear migration path to the superior centralized architecture.