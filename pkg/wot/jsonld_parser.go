package wot

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"
)

// JSONLDParser handles W3C WoT Thing Description JSON-LD processing using json-gold
type JSONLDParser struct {
	processor *ld.JsonLdProcessor
	options   *ld.JsonLdOptions
}

// NewJSONLDParser creates a new JSON-LD parser
func NewJSONLDParser() *JSONLDParser {
	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	
	return &JSONLDParser{
		processor: processor,
		options:   options,
	}
}

// WoTContextResult contains parsed WoT context information
type WoTContextResult struct {
	Namespaces    map[string]string      // Prefix -> Namespace URI
	ExpandedDoc   map[string]interface{} // Fully expanded JSON-LD document
	CompactedDoc  map[string]interface{} // Original compacted document
	VocabularyTerms map[string]string    // All vocabulary terms found
}

// ParseWoTThingDescription processes a WoT Thing Description with full JSON-LD support
func (p *JSONLDParser) ParseWoTThingDescription(tdJSON []byte) (*WoTContextResult, error) {
	// Parse JSON to generic map
	var tdDoc map[string]interface{}
	if err := json.Unmarshal(tdJSON, &tdDoc); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	// Expand the document to resolve all contexts and prefixes
	// json-gold Expand returns []interface{} directly
	expandedArray, err := p.processor.Expand(tdDoc, p.options)
	if err != nil {
		return nil, fmt.Errorf("failed to expand JSON-LD document: %w", err)
	}
	
	// Convert to map[string]interface{} for easier processing
	var expandedDoc map[string]interface{}
	if len(expandedArray) > 0 {
		if firstDoc, ok := expandedArray[0].(map[string]interface{}); ok {
			expandedDoc = firstDoc
		} else {
			expandedDoc = make(map[string]interface{})
		}
	} else {
		expandedDoc = make(map[string]interface{})
	}
	
	// Extract namespaces from context
	namespaces, err := p.extractNamespaces(tdDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to extract namespaces: %w", err)
	}
	
	// Extract vocabulary terms
	vocabTerms := p.extractVocabularyTerms(expandedDoc)
	
	result := &WoTContextResult{
		Namespaces:      namespaces,
		ExpandedDoc:     expandedDoc,
		CompactedDoc:    tdDoc,
		VocabularyTerms: vocabTerms,
	}
	
	return result, nil
}

// extractNamespaces extracts namespace mappings from the @context
func (p *JSONLDParser) extractNamespaces(doc map[string]interface{}) (map[string]string, error) {
	namespaces := make(map[string]string)
	
	context, exists := doc["@context"]
	if !exists {
		return namespaces, nil
	}
	
	// Process the context to extract mappings
	p.processContextValue(context, namespaces)
	
	// Add standard WoT namespaces if not present
	p.addStandardWoTNamespaces(namespaces)
	
	return namespaces, nil
}

// processContextValue recursively processes context values to extract namespaces
func (p *JSONLDParser) processContextValue(context interface{}, namespaces map[string]string) {
	switch ctx := context.(type) {
	case string:
		// Single context URL - add known WoT namespaces
		if strings.Contains(ctx, "wot/td") {
			p.addStandardWoTNamespaces(namespaces)
		}
		
	case []interface{}:
		// Array of contexts
		for _, item := range ctx {
			p.processContextValue(item, namespaces)
		}
		
	case map[string]interface{}:
		// Context object with mappings
		for key, value := range ctx {
			if strings.HasPrefix(key, "@") {
				continue // Skip JSON-LD keywords
			}
			
			switch v := value.(type) {
			case string:
				// Simple namespace mapping: "prefix": "namespace_url"
				namespaces[key] = v
				
			case map[string]interface{}:
				// Complex mapping with @id, @type, etc.
				if id, ok := v["@id"].(string); ok {
					namespaces[key] = id
				}
			}
		}
	}
}

// addStandardWoTNamespaces adds standard W3C WoT namespaces if not already present
func (p *JSONLDParser) addStandardWoTNamespaces(namespaces map[string]string) {
	standardNamespaces := map[string]string{
		"td":   "https://www.w3.org/2019/wot/td#",
		"htv":  "http://www.w3.org/2011/http#",
		"mqv":  "http://www.w3.org/2018/wot/mqtt#",
		"wotsec": "https://www.w3.org/2019/wot/security#",
		"hctl": "https://www.w3.org/2019/wot/hypermedia#",
	}
	
	for prefix, namespace := range standardNamespaces {
		if _, exists := namespaces[prefix]; !exists {
			namespaces[prefix] = namespace
		}
	}
}

// extractVocabularyTerms extracts all vocabulary terms used in the expanded document
func (p *JSONLDParser) extractVocabularyTerms(expanded map[string]interface{}) map[string]string {
	terms := make(map[string]string)
	
	// Recursively extract all property names that are URIs
	p.extractTermsRecursive(expanded, terms)
	
	return terms
}

// extractTermsRecursive recursively extracts vocabulary terms from the expanded document
func (p *JSONLDParser) extractTermsRecursive(obj interface{}, terms map[string]string) {
	switch v := obj.(type) {
	case map[string]interface{}:
		for key, value := range v {
			// If key is a full URI, it's a vocabulary term
			if strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://") {
				terms[key] = p.extractLocalName(key)
			}
			
			// Recursively process the value
			p.extractTermsRecursive(value, terms)
		}
		
	case []interface{}:
		for _, item := range v {
			p.extractTermsRecursive(item, terms)
		}
	}
}

// extractLocalName extracts the local name from a full URI
func (p *JSONLDParser) extractLocalName(uri string) string {
	// Find the last # or / character
	lastHash := strings.LastIndex(uri, "#")
	lastSlash := strings.LastIndex(uri, "/")
	
	separator := lastHash
	if lastSlash > lastHash {
		separator = lastSlash
	}
	
	if separator >= 0 && separator < len(uri)-1 {
		return uri[separator+1:]
	}
	
	return uri
}

// GetProtocolVocabulary extracts protocol-specific vocabulary from forms
func (r *WoTContextResult) GetProtocolVocabulary(protocol string) map[string]interface{} {
	vocabulary := make(map[string]interface{})
	
	// Define protocol prefixes
	protocolPrefixes := map[string][]string{
		"http":  {"htv", "http://www.w3.org/2011/http#"},
		"mqtt":  {"mqv", "http://www.w3.org/2018/wot/mqtt#"},
		"kafka": {"kfv", "http://example.org/kafka#"}, // Custom extension
	}
	
	prefixes, exists := protocolPrefixes[protocol]
	if !exists {
		return vocabulary
	}
	
	// Extract terms that belong to this protocol
	for term, localName := range r.VocabularyTerms {
		for _, prefix := range prefixes {
			if r.Namespaces[prefix] != "" && strings.HasPrefix(term, r.Namespaces[prefix]) {
				vocabulary[prefix+":"+localName] = term
			}
		}
	}
	
	return vocabulary
}

// CompactDocument compacts an expanded JSON-LD document using the original context
func (p *JSONLDParser) CompactDocument(expanded map[string]interface{}, context interface{}) (map[string]interface{}, error) {
	return p.processor.Compact(expanded, context, p.options)
}

// ValidateWoTCompliance checks if the document follows W3C WoT binding templates
func (r *WoTContextResult) ValidateWoTCompliance() []string {
	var issues []string
	
	// Check for required WoT context
	hasWoTContext := false
	for prefix, namespace := range r.Namespaces {
		if strings.Contains(namespace, "wot/td") {
			hasWoTContext = true
			break
		}
		_ = prefix // Avoid unused variable warning
	}
	
	if !hasWoTContext {
		issues = append(issues, "missing W3C WoT Thing Description context")
	}
	
	// Check for standard binding namespaces
	requiredBindings := map[string]string{
		"htv": "http://www.w3.org/2011/http#",
		"mqv": "http://www.w3.org/2018/wot/mqtt#",
	}
	
	for prefix, expectedNS := range requiredBindings {
		if actualNS, exists := r.Namespaces[prefix]; exists {
			if actualNS != expectedNS {
				issues = append(issues, fmt.Sprintf("namespace '%s' maps to '%s', expected '%s'", prefix, actualNS, expectedNS))
			}
		} else {
			issues = append(issues, fmt.Sprintf("missing standard binding namespace '%s'", prefix))
		}
	}
	
	return issues
}

// ExtractFormVocabulary extracts protocol-specific vocabulary from a form object
func (r *WoTContextResult) ExtractFormVocabulary(formData map[string]interface{}) map[string]interface{} {
	vocabulary := make(map[string]interface{})
	
	for key, value := range formData {
		// Check if key is a prefixed term
		if strings.Contains(key, ":") {
			parts := strings.SplitN(key, ":", 2)
			if len(parts) == 2 {
				prefix := parts[0]
				if _, exists := r.Namespaces[prefix]; exists {
					vocabulary[key] = value
				}
			}
		}
	}
	
	return vocabulary
}