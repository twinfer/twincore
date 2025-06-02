# HTTP Handler Consolidation Migration Plan

## Overview
Consolidate WoTHandler and BenthosBindingHandler into a single UnifiedWoTHandler to eliminate redundancy and create a coherent API structure.

## Current State Analysis

### WoTHandler (`wot_handler.go`)
- **Purpose**: Handles WoT interaction patterns
- **Routes**: `/things/{id}/{type}/{name}` 
- **Handles**: Properties (GET/PUT), Actions (POST), Events (GET/SSE)
- **Features**: Property caching, SSE, schema validation, event broker
- **Dependencies**: StateManager, StreamBridge, ThingRegistry, EventBroker
- **Size**: ~740 lines

### BenthosBindingHandler (`benthos_binding_handler.go`)
- **Purpose**: Stream management and development APIs
- **Routes**: `/wot/binding/*`
- **Handles**: Stream CRUD, Processor collections, TD-to-stream generation
- **Dependencies**: ThingRegistry, BenthosStreamManager
- **Size**: ~600 lines

### WoTMapper (`wot_mapper.go`)
- **Purpose**: Generates HTTP route configurations from Thing Descriptions
- **Output**: Routes that should be handled by WoTHandler
- **Pattern**: `/things/{id}/{type}/{name}` (matches WoTHandler)

## Consolidation Strategy

### New Unified API Structure
```
/api/things/{id}                      - Thing CRUD operations
/api/things/{id}/properties/{name}    - Property read/write/observe  
/api/things/{id}/actions/{name}       - Action invocation
/api/things/{id}/events/{name}        - Event subscription (SSE)
/api/streams                          - Stream management
/api/streams/{id}                     - Stream CRUD
/api/streams/{id}/start               - Stream control
/api/streams/{id}/stop                - Stream control  
/api/streams/{id}/status              - Stream status
/api/processors                       - Processor collections
/api/bindings/generate                - Generate bindings from TD
```

### Benefits
1. **Single API endpoint prefix** (`/api/`)
2. **Logical grouping** of WoT vs Stream operations
3. **Eliminates routing conflicts** between handlers
4. **Consistent request/response patterns**
5. **Shared utilities** (logging, validation, error handling)
6. **Reduced maintenance complexity**

## Migration Steps

### Phase 1: Create Unified Handler Foundation ✅
- [x] Create `unified_wot_handler.go` with basic structure
- [x] Define unified routing patterns
- [x] Set up dependency injection and provisioning

### Phase 2: Migrate WoT Functionality
- [ ] Copy property handling methods from WoTHandler
- [ ] Copy action handling methods from WoTHandler  
- [ ] Copy event handling methods from WoTHandler
- [ ] Copy helper methods (caching, SSE, validation)
- [ ] Migrate EventBroker integration

### Phase 3: Migrate Stream Management
- [ ] Copy stream CRUD methods from BenthosBindingHandler
- [ ] Copy processor collection methods
- [ ] Copy TD generation method
- [ ] Migrate stream validation logic

### Phase 4: Update Configuration  
- [ ] Update WoTMapper to generate `/api/things/*` routes
- [ ] Update Caddy route configuration in container
- [ ] Remove old handler registrations
- [ ] Add unified handler registration

### Phase 5: Update Tests
- [ ] Update handler tests to use new endpoints
- [ ] Create integration tests for unified API
- [ ] Test backwards compatibility if needed

### Phase 6: Cleanup
- [ ] Remove `wot_handler.go`
- [ ] Remove `benthos_binding_handler.go`  
- [ ] Update documentation
- [ ] Update API examples

## Implementation Details

### Route Mapping Changes

#### Before:
```
WoTHandler:           /things/{id}/{type}/{name}
BenthosBindingHandler: /wot/binding/streams
                      /wot/binding/processors
                      /wot/binding/generate
```

#### After:
```
UnifiedWoTHandler:    /api/things/{id}
                     /api/things/{id}/{type}/{name}
                     /api/streams/*
                     /api/processors/*
                     /api/bindings/*
```

### Caddy Configuration Changes

#### Current:
```json
{
  "match": [{"path": ["/things/*"]}],
  "handle": [{"handler": "core_wot_handler"}]
},
{
  "match": [{"path": ["/wot/binding/*"]}], 
  "handle": [{"handler": "wot_binding_handler"}]
}
```

#### New:
```json
{
  "match": [{"path": ["/api/*"]}],
  "handle": [{"handler": "unified_wot_handler"}]
}
```

### Dependency Changes

#### container.go updates:
```go
// Remove separate handler initializations
// h.WoTHandler = api.NewWoTHandler(...)
// h.BenthosBindingHandler = api.NewBenthosBindingHandler(...)

// Add unified handler
h.UnifiedWoTHandler = api.NewUnifiedWoTHandler(
    h.StateManager,
    h.StreamBridge, 
    h.ThingRegistry,
    h.BenthosStreamManager,
    h.EventBroker,
    h.Logger,
)
```

## Testing Strategy

### Unit Tests
- Test each route group independently
- Mock dependencies for isolated testing
- Verify request/response formats

### Integration Tests  
- End-to-end Thing registration workflow
- Stream creation and management
- SSE connections for events/properties
- Error handling and edge cases

### Backwards Compatibility
- Maintain existing endpoint behavior
- Consider adding redirect handlers for old endpoints
- Document API changes in migration guide

## Risk Mitigation

### Rollback Plan
1. Keep old handlers during initial deployment
2. Use feature flags to switch between handlers
3. Monitor error rates and performance
4. Quick rollback capability if issues arise

### Validation Checklist
- [ ] All existing WoT functionality preserved
- [ ] All stream management features working
- [ ] SSE connections stable
- [ ] Property caching functioning
- [ ] Schema validation working
- [ ] Event broker integration intact
- [ ] Stream lifecycle management preserved
- [ ] Error handling consistent

## Timeline

- **Week 1**: Complete Phase 2 (WoT functionality migration)
- **Week 2**: Complete Phase 3 (Stream management migration)  
- **Week 3**: Complete Phase 4 (Configuration updates)
- **Week 4**: Complete Phase 5-6 (Testing and cleanup)

## Success Criteria

1. ✅ Single HTTP handler manages all API requests
2. ✅ Consistent `/api/*` endpoint structure
3. ✅ All existing functionality preserved  
4. ✅ Reduced code duplication
5. ✅ Improved maintainability
6. ✅ Clean separation between WoT and Stream operations
7. ✅ Comprehensive test coverage

## Next Steps

1. Implement Phase 2: Migrate WoT functionality to UnifiedWoTHandler
2. Update WoTMapper route generation patterns
3. Test property, action, and event handling
4. Migrate stream management functionality
5. Update container configuration and registration