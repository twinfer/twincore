package wot

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EnhancedThingDescription wraps ThingDescription with JSON-LD processing capabilities
type EnhancedThingDescription struct {
	ThingDescription
	jsonldResult *WoTContextResult
	parser       *JSONLDParser
}

// NewEnhancedThingDescription creates a new enhanced Thing Description
func NewEnhancedThingDescription() *EnhancedThingDescription {
	return &EnhancedThingDescription{
		parser: NewJSONLDParser(),
	}
}

// UnmarshalJSON implements custom JSON unmarshaling with full JSON-LD processing
func (etd *EnhancedThingDescription) UnmarshalJSON(data []byte) error {
	// First, process with JSON-LD parser
	result, err := etd.parser.ParseWoTThingDescription(data)
	if err != nil {
		return fmt.Errorf("JSON-LD processing failed: %w", err)
	}
	etd.jsonldResult = result
	
	// Then unmarshal into base ThingDescription
	err = json.Unmarshal(data, &etd.ThingDescription)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Thing Description: %w", err)
	}
	
	return nil
}

// GetNamespaces returns all extracted namespaces
func (etd *EnhancedThingDescription) GetNamespaces() map[string]string {
	if etd.jsonldResult == nil {
		return make(map[string]string)
	}
	return etd.jsonldResult.Namespaces
}

// GetExpandedDocument returns the fully expanded JSON-LD document
func (etd *EnhancedThingDescription) GetExpandedDocument() map[string]interface{} {
	if etd.jsonldResult == nil {
		return make(map[string]interface{})
	}
	return etd.jsonldResult.ExpandedDoc
}

// GetVocabularyTerms returns all vocabulary terms found in the document
func (etd *EnhancedThingDescription) GetVocabularyTerms() map[string]string {
	if etd.jsonldResult == nil {
		return make(map[string]string)
	}
	return etd.jsonldResult.VocabularyTerms
}

// ValidateJSONLDCompliance checks JSON-LD and WoT compliance
func (etd *EnhancedThingDescription) ValidateJSONLDCompliance() []string {
	if etd.jsonldResult == nil {
		return []string{"JSON-LD processing not performed"}
	}
	return etd.jsonldResult.ValidateWoTCompliance()
}

// ParseFormsWithVocabulary extracts protocol-specific vocabulary from all forms using json-gold + binding forms
func (etd *EnhancedThingDescription) ParseFormsWithVocabulary() (map[string][]FormWithVocabulary, error) {
	if etd.jsonldResult == nil {
		return nil, fmt.Errorf("JSON-LD processing not performed")
	}
	
	// Use the FormParser from binding_forms.go for W3C-compliant parsing
	formParser := &FormParser{}
	result := make(map[string][]FormWithVocabulary)
	
	// Parse forms from the expanded JSON-LD document for proper vocabulary access
	expandedDoc := etd.jsonldResult.ExpandedDoc
	
	// Process property forms
	if props, ok := expandedDoc["https://www.w3.org/2019/wot/td#hasPropertyAffordance"]; ok {
		result["properties"] = etd.parseExpandedForms(props, formParser)
	}
	
	// Process action forms  
	if actions, ok := expandedDoc["https://www.w3.org/2019/wot/td#hasActionAffordance"]; ok {
		result["actions"] = etd.parseExpandedForms(actions, formParser)
	}
	
	// Process event forms
	if events, ok := expandedDoc["https://www.w3.org/2019/wot/td#hasEventAffordance"]; ok {
		result["events"] = etd.parseExpandedForms(events, formParser)
	}
	
	return result, nil
}

// parseExpandedForms extracts forms from expanded JSON-LD and parses them with binding forms
func (etd *EnhancedThingDescription) parseExpandedForms(affordances interface{}, formParser *FormParser) []FormWithVocabulary {
	var formsWithVocab []FormWithVocabulary
	
	// Handle the case where affordances is an array
	if affordanceArray, ok := affordances.([]interface{}); ok {
		for _, affordance := range affordanceArray {
			if affordanceMap, ok := affordance.(map[string]interface{}); ok {
				if forms, ok := affordanceMap["https://www.w3.org/2019/wot/td#hasForm"]; ok {
					if formArray, ok := forms.([]interface{}); ok {
						for _, formData := range formArray {
							if formMap, ok := formData.(map[string]interface{}); ok {
								// Convert expanded form back to compact form for parsing
								compactForm := etd.compactForm(formMap)
								
								// Parse with FormParser from binding_forms.go
								if parsedForm, err := formParser.ParseForm(compactForm); err == nil {
									vocab := etd.jsonldResult.ExtractFormVocabulary(compactForm)
									protocol := etd.detectProtocolFromVocab(vocab)
									
									formsWithVocab = append(formsWithVocab, FormWithVocabulary{
										Form:       parsedForm,
										Vocabulary: vocab,
										Protocol:   protocol,
									})
								}
							}
						}
					}
				}
			}
		}
	}
	
	return formsWithVocab
}

// compactForm converts an expanded form back to compact form for parsing
func (etd *EnhancedThingDescription) compactForm(expandedForm map[string]interface{}) map[string]interface{} {
	compactForm := make(map[string]interface{})
	
	// Map common expanded URIs back to compact terms
	uriMappings := map[string]string{
		"https://www.w3.org/2019/wot/hypermedia#hasTarget":    "href",
		"https://www.w3.org/2019/wot/hypermedia#forContentType": "contentType",
		"http://www.w3.org/2011/http#methodName":              "htv:methodName",
		"http://www.w3.org/2018/wot/mqtt#qos":                 "mqv:qos",
		"http://www.w3.org/2018/wot/mqtt#topic":               "mqv:topic",
	}
	
	for expandedURI, value := range expandedForm {
		if compactTerm, exists := uriMappings[expandedURI]; exists {
			compactForm[compactTerm] = value
		} else {
			// Keep as-is if no mapping found
			compactForm[expandedURI] = value
		}
	}
	
	return compactForm
}

// detectProtocolFromVocab detects protocol from vocabulary terms
func (etd *EnhancedThingDescription) detectProtocolFromVocab(vocab map[string]interface{}) string {
	for key := range vocab {
		switch {
		case strings.HasPrefix(key, "htv:"):
			return "http"
		case strings.HasPrefix(key, "mqv:"):
			return "mqtt"
		case strings.HasPrefix(key, "kfv:"):
			return "kafka"
		}
	}
	return "unknown"
}

// FormWithVocabulary represents a form with its extracted vocabulary
type FormWithVocabulary struct {
	Form       Form                   // Original form interface
	Vocabulary map[string]interface{} // Extracted protocol vocabulary
	Protocol   string                 // Detected protocol
}


// GetProtocolVocabulary returns vocabulary for a specific protocol
func (etd *EnhancedThingDescription) GetProtocolVocabulary(protocol string) map[string]interface{} {
	if etd.jsonldResult == nil {
		return make(map[string]interface{})
	}
	return etd.jsonldResult.GetProtocolVocabulary(protocol)
}

// ExpandProperty expands a prefixed property using the parsed context
func (etd *EnhancedThingDescription) ExpandProperty(property string) string {
	if etd.jsonldResult == nil {
		return property
	}
	
	// Use the JSON-LD namespaces to expand
	parts := strings.SplitN(property, ":", 2)
	if len(parts) == 2 {
		prefix, localName := parts[0], parts[1]
		if namespace, exists := etd.jsonldResult.Namespaces[prefix]; exists {
			return namespace + localName
		}
	}
	
	return property
}