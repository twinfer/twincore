package wot

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ContextParser handles W3C WoT Thing Description @context parsing
type ContextParser struct {
	namespaces map[string]string
}

// NewContextParser creates a new context parser
func NewContextParser() *ContextParser {
	return &ContextParser{
		namespaces: make(map[string]string),
	}
}

// ParseContext extracts namespace mappings from a Thing Description @context
func (p *ContextParser) ParseContext(context interface{}) error {
	p.namespaces = make(map[string]string) // Reset
	
	switch ctx := context.(type) {
	case string:
		// Single context string
		return p.parseSingleContext(ctx)
		
	case []interface{}:
		// Array of contexts
		return p.parseContextArray(ctx)
		
	case map[string]interface{}:
		// Context object with mappings
		return p.parseContextObject(ctx)
		
	default:
		return fmt.Errorf("invalid @context type: %T", context)
	}
}

func (p *ContextParser) parseSingleContext(ctx string) error {
	// Handle well-known WoT contexts
	switch ctx {
	case "https://www.w3.org/2022/wot/td/v1.1", "https://www.w3.org/2019/wot/td/v1":
		// Standard WoT TD context - no additional namespaces
		return nil
	default:
		return fmt.Errorf("unknown context: %s", ctx)
	}
}

func (p *ContextParser) parseContextArray(contexts []interface{}) error {
	for _, ctx := range contexts {
		switch c := ctx.(type) {
		case string:
			err := p.parseSingleContext(c)
			if err != nil {
				return err
			}
			
		case map[string]interface{}:
			err := p.parseContextObject(c)
			if err != nil {
				return err
			}
			
		default:
			return fmt.Errorf("invalid context array item type: %T", ctx)
		}
	}
	return nil
}

func (p *ContextParser) parseContextObject(obj map[string]interface{}) error {
	for key, value := range obj {
		switch v := value.(type) {
		case string:
			// Simple namespace mapping: "prefix": "namespace_url"
			p.namespaces[key] = v
			
		case map[string]interface{}:
			// Complex mapping with @id, @type, etc. - for now just extract @id
			if id, ok := v["@id"].(string); ok {
				p.namespaces[key] = id
			}
		}
	}
	return nil
}

// GetNamespace returns the full namespace URI for a prefix
func (p *ContextParser) GetNamespace(prefix string) (string, bool) {
	ns, ok := p.namespaces[prefix]
	return ns, ok
}

// GetKnownPrefixes returns all known namespace prefixes
func (p *ContextParser) GetKnownPrefixes() []string {
	prefixes := make([]string, 0, len(p.namespaces))
	for prefix := range p.namespaces {
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// ExpandProperty expands a prefixed property name to its full URI
func (p *ContextParser) ExpandProperty(property string) string {
	if !strings.Contains(property, ":") {
		return property // No prefix
	}
	
	parts := strings.SplitN(property, ":", 2)
	if len(parts) != 2 {
		return property
	}
	
	prefix, localName := parts[0], parts[1]
	if namespace, ok := p.namespaces[prefix]; ok {
		return namespace + localName
	}
	
	return property // Return as-is if prefix not found
}

// ValidateStandardBindings checks if standard W3C binding namespaces are present
func (p *ContextParser) ValidateStandardBindings() []string {
	var missing []string
	
	standardBindings := map[string]string{
		"htv": "http://www.w3.org/2011/http#",     // HTTP vocabulary
		"mqv": "http://www.w3.org/2018/wot/mqtt#", // MQTT vocabulary (proposed)
	}
	
	for prefix, expectedNS := range standardBindings {
		if actualNS, exists := p.namespaces[prefix]; exists {
			if actualNS != expectedNS {
				missing = append(missing, fmt.Sprintf("%s maps to %s, expected %s", prefix, actualNS, expectedNS))
			}
		} else {
			missing = append(missing, fmt.Sprintf("missing namespace for %s", prefix))
		}
	}
	
	return missing
}

// Enhanced Thing Description with context parsing
type ThingDescriptionWithContext struct {
	ThingDescription
	contextParser *ContextParser
}

// NewThingDescriptionWithContext creates a TD with context parsing capability
func NewThingDescriptionWithContext() *ThingDescriptionWithContext {
	return &ThingDescriptionWithContext{
		contextParser: NewContextParser(),
	}
}

// UnmarshalJSON implements custom JSON unmarshaling with context parsing
func (td *ThingDescriptionWithContext) UnmarshalJSON(data []byte) error {
	// First unmarshal into base ThingDescription
	err := json.Unmarshal(data, &td.ThingDescription)
	if err != nil {
		return err
	}
	
	// Parse the @context for namespace information
	if td.Context != nil {
		err = td.contextParser.ParseContext(td.Context)
		if err != nil {
			return fmt.Errorf("failed to parse @context: %w", err)
		}
	}
	
	return nil
}

// TODO: Proper form parsing with W3C vocabulary requires restructuring JSON unmarshaling
// The current Form interface cannot capture protocol-specific vocabulary (htv:*, mqv:*, etc.)
// This would require custom JSON unmarshaling that creates concrete form types based on vocabulary presence

// GetContextParser returns the context parser for external use
func (td *ThingDescriptionWithContext) GetContextParser() *ContextParser {
	return td.contextParser
}

// ValidateBindingCompliance checks if the TD follows W3C binding templates
func (td *ThingDescriptionWithContext) ValidateBindingCompliance() []string {
	var issues []string
	
	// Check context namespaces
	missing := td.contextParser.ValidateStandardBindings()
	issues = append(issues, missing...)
	
	// Check if forms use appropriate vocabulary
	issues = append(issues, td.validateFormVocabulary()...)
	
	return issues
}

func (td *ThingDescriptionWithContext) validateFormVocabulary() []string {
	var issues []string
	
	// TODO: Form vocabulary validation requires access to raw JSON form data
	// Current Form interface abstracts away protocol-specific vocabulary
	// Would need to validate presence of required vocabulary terms like:
	// - htv:methodName for HTTP forms
	// - mqv:qos for MQTT forms  
	// - kfv:topic for Kafka forms
	
	return issues
}