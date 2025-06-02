package forms

import (
	"fmt"
)

// SchemaRegistry manages schema definitions for different interaction types
type SchemaRegistry struct {
	baseFields   []SchemaField
	typeSpecific map[string][]SchemaField
}

// SchemaField represents a field in a schema
type SchemaField struct {
	Name     string
	Type     string
	Nullable bool
}

// NewSchemaRegistry creates a new schema registry
func NewSchemaRegistry() *SchemaRegistry {
	registry := &SchemaRegistry{
		typeSpecific: make(map[string][]SchemaField),
	}
	registry.initializeSchemas()
	return registry
}

// initializeSchemas sets up default schemas
func (r *SchemaRegistry) initializeSchemas() {
	// Base fields common to all interactions
	r.baseFields = []SchemaField{
		{Name: "thing_id", Type: "STRING", Nullable: false},
		{Name: "timestamp", Type: "INT64", Nullable: false},
		{Name: "source", Type: "STRING", Nullable: false},
	}

	// Property-specific fields
	r.typeSpecific["property"] = []SchemaField{
		{Name: "property_name", Type: "STRING", Nullable: false},
		{Name: "property_value", Type: "STRING", Nullable: true},
	}

	// Action-specific fields
	r.typeSpecific["action"] = []SchemaField{
		{Name: "action_name", Type: "STRING", Nullable: false},
		{Name: "command_id", Type: "STRING", Nullable: false},
		{Name: "action_params", Type: "STRING", Nullable: true},
		{Name: "result", Type: "STRING", Nullable: true},
		{Name: "status", Type: "STRING", Nullable: true},
		{Name: "correlation_id", Type: "STRING", Nullable: true},
	}

	// Event-specific fields
	r.typeSpecific["event"] = []SchemaField{
		{Name: "event_name", Type: "STRING", Nullable: false},
		{Name: "event_data", Type: "STRING", Nullable: true},
		{Name: "event_id", Type: "STRING", Nullable: false},
	}
}

// GetSchema returns the complete schema for an interaction type
func (r *SchemaRegistry) GetSchema(interactionType string) []map[string]interface{} {
	// Combine base fields with type-specific fields
	var fields []SchemaField
	fields = append(fields, r.baseFields...)

	if specific, ok := r.typeSpecific[interactionType]; ok {
		fields = append(fields, specific...)
	}

	// Convert to Parquet schema format
	return r.convertToParquetSchema(fields)
}

// GetParquetSchema returns a Parquet-formatted schema
func (r *SchemaRegistry) GetParquetSchema(interactionType string) []map[string]interface{} {
	return r.GetSchema(interactionType)
}

// convertToParquetSchema converts schema fields to Parquet format
func (r *SchemaRegistry) convertToParquetSchema(fields []SchemaField) []map[string]interface{} {
	schema := make([]map[string]interface{}, len(fields))

	for i, field := range fields {
		schema[i] = map[string]interface{}{
			"name": field.Name,
			"type": field.Type,
		}

		if field.Nullable {
			schema[i]["repetition_type"] = "OPTIONAL"
		} else {
			schema[i]["repetition_type"] = "REQUIRED"
		}
	}

	return schema
}

// RegisterCustomSchema allows adding custom schemas
func (r *SchemaRegistry) RegisterCustomSchema(interactionType string, fields []SchemaField) {
	r.typeSpecific[interactionType] = fields
}

// AddFieldToSchema adds a field to an existing schema
func (r *SchemaRegistry) AddFieldToSchema(interactionType string, field SchemaField) error {
	if _, exists := r.typeSpecific[interactionType]; !exists {
		return fmt.Errorf("schema for interaction type %s does not exist", interactionType)
	}

	r.typeSpecific[interactionType] = append(r.typeSpecific[interactionType], field)
	return nil
}

// GetAvailableSchemas returns a list of available schema types
func (r *SchemaRegistry) GetAvailableSchemas() []string {
	schemas := make([]string, 0, len(r.typeSpecific))
	for name := range r.typeSpecific {
		schemas = append(schemas, name)
	}
	return schemas
}

// MergeSchemas combines multiple schemas
func (r *SchemaRegistry) MergeSchemas(schemas ...[]SchemaField) []SchemaField {
	// Use a map to avoid duplicates
	fieldMap := make(map[string]SchemaField)

	// Add all fields, later ones override earlier ones
	for _, schema := range schemas {
		for _, field := range schema {
			fieldMap[field.Name] = field
		}
	}

	// Convert back to slice
	result := make([]SchemaField, 0, len(fieldMap))
	for _, field := range fieldMap {
		result = append(result, field)
	}

	return result
}