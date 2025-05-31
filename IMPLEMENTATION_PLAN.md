# TwinCore Centralized WoT Binding - Implementation Plan

## Executive Summary

The centralized WoT binding generation has been architected and scaffolded in `pkg/wot/forms/enhanced_forms.go`, but **all core stream generation methods are currently placeholders returning `nil`**. This document provides a prioritized implementation plan to complete the feature.

## Current Status: Framework Complete, Implementation Missing

### ✅ **What's Working**
- Core `BindingGenerator` structure with dependency injection
- HTTP route generation from WoT forms
- Processor chain composition framework
- YAML template generation scaffolding  
- Parquet schema generation for all interaction types
- Clean separation from `internal/api/` redundant code

### ❌ **Critical Missing Implementation**
- **ALL 7 stream generation methods return `nil`** (no actual functionality)
- License interface mismatch with existing OPA system
- No integration with existing `BenthosStreamManager`
- Missing connection to container dependency injection
- Form implementations not leveraged (security, protocols)

## Implementation Priority Plan

### **Phase 1: Core Infrastructure (CRITICAL - Week 1)**

#### **1.1 Fix License Interface Mismatch** 
**Time**: 30 minutes  
**File**: `pkg/wot/forms/enhanced_forms.go`

```go
// Current (broken):
type LicenseChecker interface {
    IsFeatureAvailable(feature string) bool
    GetFeatureConfig(feature string) map[string]interface{}
}

// Fix to match OPA implementation:
type LicenseChecker interface {
    IsFeatureEnabled(category, feature string) (bool, error)
    GetAllowedFeatures() (map[string]interface{}, error)
    CheckLimit(resource string, currentCount int) (bool, error)
}
```

#### **1.2 Create License Adapter**
**Time**: 45 minutes  
**File**: `pkg/wot/forms/license_adapter.go`

```go
// Bridge between BindingGenerator and existing OPA license system
type LicenseCheckerAdapter struct {
    opaChecker *security.LicenseCheckerOPA
}

func (a *LicenseCheckerAdapter) IsFeatureEnabled(category, feature string) (bool, error) {
    return a.opaChecker.IsFeatureEnabled(category, feature)
}
```

#### **1.3 Connect BindingGenerator to Container**  
**Time**: 1 hour  
**File**: `internal/container/container.go`

```go
// Add to Container struct:
type Container struct {
    // ... existing fields ...
    BindingGenerator *forms.BindingGenerator
}

// Add to initialization:
func (c *Container) initWoTComponents(cfg *Config) error {
    licenseAdapter := &forms.LicenseCheckerAdapter{
        opaChecker: c.licenseIntegration.Checker,
    }
    
    c.BindingGenerator = forms.NewBindingGenerator(
        c.Logger,
        licenseAdapter,
        c.BenthosStreamManager,  // Use existing stream manager
        c.StreamConfigDefaults,  // Use existing defaults
    )
    
    return nil
}
```

### **Phase 2: Implement Core Stream Generation (HIGH PRIORITY - Week 1-2)**

#### **2.1 Implement Property Logging Stream**
**Time**: 3 hours  
**File**: `pkg/wot/forms/enhanced_forms.go`

```go
func (bg *BindingGenerator) generatePropertyLoggingStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
    streamID := fmt.Sprintf("%s_property_%s_logging", thingID, propName)
    topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName)
    
    // Create StreamCreationRequest using existing API
    request := StreamCreationRequest{
        ThingID:         thingID,
        InteractionType: "properties", 
        InteractionName: propName,
        Direction:       "input",
        Input: StreamEndpointConfig{
            Type: "kafka",
            Config: map[string]interface{}{
                "addresses": bg.kafkaConfig.Brokers,
                "topics":    []string{topic},
                "consumer_group": fmt.Sprintf("twincore-property-logger-%s", thingID),
            },
        },
        Output: StreamEndpointConfig{
            Type: "file",
            Config: map[string]interface{}{
                "path": fmt.Sprintf("%s/properties/props_%s_%s.parquet", 
                    bg.parquetConfig.BasePath, thingID, "${!timestamp_unix():yyyy-MM-dd}"),
                "codec": "none",
            },
        },
        ProcessorChain: []ProcessorConfig{
            {
                Type: types.ProcessorLicenseCheck,
                Config: map[string]interface{}{
                    "feature": "parquet_logging",
                },
            },
            {
                Type: types.ProcessorBloblangWoTProperty,
                Config: map[string]interface{}{
                    "mapping": bg.generatePropertyLoggingMapping(thingID, propName),
                },
            },
            {
                Type: types.ProcessorParquetEncode,
                Config: map[string]interface{}{
                    "schema": bg.generatePropertyParquetSchema(),
                },
            },
        },
    }
    
    // Use existing stream manager to create stream
    stream, err := bg.streamManager.CreateStream(context.Background(), request)
    if err != nil {
        return fmt.Errorf("failed to create property logging stream: %w", err)
    }
    
    // Convert StreamInfo to StreamConfig and store
    streamConfig := StreamConfig{
        ID:        stream.ID,
        Type:      types.StreamTypePropertyLogger,
        Direction: types.StreamDirectionInternal,
        YAML:      "", // Generate from StreamInfo
    }
    
    bindings.Streams[streamID] = streamConfig
    return nil
}
```

#### **2.2 Implement Remaining Stream Methods**
**Time**: 6 hours (1 hour each)  
**Priority**: Property observation → Action invocation → Event processing → Others

Copy the pattern from property logging but adjust:
- Input/output protocols based on WoT operations
- Processor chains for different interaction types  
- Topic patterns and consumer groups
- File paths and schemas

#### **2.3 Update BindingGenerator Constructor**
**Time**: 30 minutes

```go
func NewBindingGenerator(
    logger logrus.FieldLogger, 
    licenseChecker LicenseChecker,
    streamManager BenthosStreamManager,  // Add existing stream manager
    configDefaults *StreamConfigDefaults, // Add existing defaults
) *BindingGenerator {
    return &BindingGenerator{
        logger:         logger,
        licenseChecker: licenseChecker,
        streamManager:  streamManager,  // Store reference
        configDefaults: configDefaults,
        // ... rest of initialization using existing configs
    }
}
```

### **Phase 3: WoT Integration (MEDIUM PRIORITY - Week 2)**

#### **3.1 Integrate with WoTHandler**  
**Time**: 2 hours  
**File**: `internal/api/wot_handler.go`

```go
func (h *WoTHandler) handleThingRegistration(w http.ResponseWriter, r *http.Request) error {
    // ... existing TD parsing ...
    
    // Generate all bindings using centralized approach
    bindings, err := h.bindingGenerator.GenerateAllBindings(td)
    if err != nil {
        return fmt.Errorf("failed to generate bindings: %w", err)
    }
    
    // Start all streams
    for streamID, stream := range bindings.Streams {
        if err := h.streamManager.StartStream(r.Context(), streamID); err != nil {
            h.logger.WithError(err).WithField("stream_id", streamID).Error("Failed to start stream")
        }
    }
    
    // Register HTTP routes with Caddy Admin API
    for routeID, route := range bindings.HTTPRoutes {
        if err := h.configManager.AddRoute(r.Context(), routeID, route); err != nil {
            h.logger.WithError(err).WithField("route_id", routeID).Error("Failed to register route")
        }
    }
    
    return nil
}
```

#### **3.2 Use Existing Form Implementations**
**Time**: 2 hours  
**File**: `pkg/wot/forms/enhanced_forms.go`

```go
func (bg *BindingGenerator) generateStreamFromForm(form wot.Form, thingID, interactionType, interactionName string) error {
    // Use existing form.GenerateConfig() for proper security/protocol handling
    config, err := form.GenerateConfig(securityDefs)
    if err != nil {
        return err
    }
    
    // Convert form config to StreamEndpointConfig
    endpoint := StreamEndpointConfig{
        Protocol: types.StreamProtocol(form.GetProtocol()),
        Config:   config,
    }
    
    // Use in stream generation...
}
```

### **Phase 4: Testing & Validation (Week 3)**

#### **4.1 Integration Tests**
**Time**: 4 hours

```go
func TestBindingGeneratorIntegration(t *testing.T) {
    // Test with actual container
    container := setupTestContainer(t)
    
    // Create sample Thing Description
    td := &wot.ThingDescription{
        ID: "test-sensor",
        Properties: map[string]*wot.PropertyAffordance{
            "temperature": {
                DataSchemaCore: wot.DataSchemaCore{
                    Type: "number",
                    Observable: true,
                },
            },
        },
    }
    
    // Generate bindings
    bindings, err := container.BindingGenerator.GenerateAllBindings(td)
    require.NoError(t, err)
    
    // Verify streams were created
    assert.Greater(t, len(bindings.Streams), 0)
    
    // Verify streams can be started
    for streamID := range bindings.Streams {
        err := container.BenthosStreamManager.StartStream(context.Background(), streamID)
        assert.NoError(t, err)
    }
}
```

#### **4.2 YAML Validation**
**Time**: 2 hours

Validate generated Benthos YAML configs against Benthos schema.

#### **4.3 License Feature Testing**
**Time**: 2 hours

Test with different license configurations to ensure feature gating works.

### **Phase 5: Documentation & Migration (Week 4)**

#### **5.1 Update Migration Guide**
**Time**: 1 hour

Update `BINDING_MIGRATION_EXAMPLE.md` with actual working examples.

#### **5.2 Container Integration Guide**
**Time**: 1 hour

Document how to properly initialize and use the centralized binding generation.

#### **5.3 Performance Testing**
**Time**: 2 hours

Load test with multiple Thing Descriptions to ensure scalability.

## Risk Mitigation

### **High Risk: Interface Mismatches**
- **Mitigation**: Create adapter patterns to bridge existing interfaces
- **Timeline**: Address in Phase 1 (critical path)

### **Medium Risk: Benthos YAML Validity**
- **Mitigation**: Add YAML validation and integration tests
- **Timeline**: Address in Phase 4

### **Low Risk: Performance Impact**
- **Mitigation**: Benchmark against existing implementation
- **Timeline**: Address in Phase 5

## Success Metrics

1. **Functional**: All 7 stream generation methods implemented and working
2. **Integration**: Successfully connected to existing container and services
3. **Performance**: No degradation compared to existing scattered approach
4. **Test Coverage**: >80% test coverage for new binding generation code
5. **Migration**: At least one Thing Description using new centralized approach

## Estimated Total Time: 25-30 hours over 3-4 weeks

This plan transforms the current scaffold into a fully functional centralized WoT binding generation system that properly integrates with TwinCore's existing architecture.