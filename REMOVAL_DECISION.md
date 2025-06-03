# File Removal Decision: context_parser.go vs binding_forms.go

## Summary

✅ **REMOVED: `context_parser.go`** - Completely replaced by json-gold implementation  
✅ **KEPT: `binding_forms.go`** - Enhanced to work with json-gold parser

## Decision Rationale

### `context_parser.go` - **REMOVED** ❌

**Why removed:**
1. ✅ **Completely superseded** by `jsonld_parser.go` with json-gold
2. ✅ **Naive implementation** - only handles simple context mappings
3. ✅ **Limited JSON-LD support** - no expansion, no complex contexts
4. ✅ **Unfixable TODOs** - fundamental architecture limitations

**What json-gold provides instead:**
- Full W3C JSON-LD 1.1 compliance
- Document expansion and compaction
- Complex context resolution
- Vocabulary term extraction
- Standards-compliant processing

### `binding_forms.go` - **KEPT** ✅

**Why kept:**
1. ✅ **W3C Binding Templates** - implements official HTTP/MQTT/Kafka forms
2. ✅ **Protocol-specific logic** - concrete form implementations with vocabulary
3. ✅ **Template integration** - works with our Benthos YAML templates
4. ✅ **Enhanced by json-gold** - now gets proper vocabulary from expanded documents

**Integration with json-gold:**
```go
// json-gold expands the document
expandedDoc := jsonldParser.ParseWoTThingDescription(tdJSON)

// binding_forms parses protocol-specific vocabulary
formParser := &FormParser{}
httpForm, err := formParser.parseHTTPForm(compactedFormData)

// Combined result: W3C-compliant forms with proper vocabulary
```

## Architecture After Changes

### New Flow:
```
Thing Description JSON
       ↓
json-gold processing (jsonld_parser.go)
       ↓
Expanded document with full URIs
       ↓
Compact back to prefixed form
       ↓
Parse with binding forms (binding_forms.go)
       ↓
Protocol-specific forms with W3C vocabulary
```

### Key Benefits:
1. **Standards Compliance** - Full W3C JSON-LD + Binding Templates support
2. **Vocabulary Access** - Can access `htv:methodName`, `mqv:qos`, etc.
3. **Protocol Detection** - Based on vocabulary presence, not URL schemes
4. **Template Integration** - Benthos templates get proper vocabulary data

## Files Status

### Removed Files:
- ❌ `pkg/wot/context_parser.go` - Replaced by json-gold

### Active Files:
- ✅ `pkg/wot/jsonld_parser.go` - Full JSON-LD processing
- ✅ `pkg/wot/enhanced_thing_description.go` - JSON-LD + binding forms integration
- ✅ `pkg/wot/binding_forms.go` - W3C-compliant form implementations
- ✅ `pkg/wot/jsonld_parser_test.go` - Comprehensive tests

### Enhanced Functionality:
```go
// Before: Limited context parsing
parser := NewContextParser()
parser.ParseContext(context) // Only basic mappings

// After: Full JSON-LD + W3C forms
etd := NewEnhancedThingDescription()
json.Unmarshal(tdJSON, etd)
formsWithVocab, err := etd.ParseFormsWithVocabulary()
// Returns: HTTPForm, MQTTForm, KafkaForm with full vocabulary
```

## Impact on Existing Code

### Breaking Changes:
- `ContextParser` types removed
- `ThingDescriptionWithContext` replaced by `EnhancedThingDescription`

### Migration Path:
```go
// Old approach (removed)
td := NewThingDescriptionWithContext()
contextParser := td.GetContextParser()

// New approach  
etd := NewEnhancedThingDescription()
namespaces := etd.GetNamespaces()
formsWithVocab, _ := etd.ParseFormsWithVocabulary()
```

### Backward Compatibility:
- Existing `Form` interface unchanged
- `TestForm` still works for testing
- Template system unchanged

## Conclusion

The removal of `context_parser.go` and retention of `binding_forms.go` provides:

1. ✅ **Better Standards Compliance** - Full W3C JSON-LD + Binding Templates
2. ✅ **Enhanced Functionality** - Access to all protocol vocabulary
3. ✅ **Cleaner Architecture** - json-gold handles JSON-LD, binding forms handle protocols
4. ✅ **Future Extensibility** - Easy to add new protocols with proper vocabulary

This decision **completely solves the original TODO** about form vocabulary parsing while maintaining our template-based architecture.