// internal/config/thing_registry.go
package config

import (
	"database/sql"
	_ "embed" // Added for //go:embed
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/kazarena/json-gold/ld"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// ThingRegistry manages Thing Descriptions
type ThingRegistry struct {
	db        *sql.DB
	logger    *logrus.Logger
	jsonld    *ld.JsonLdProcessor
	validator *api.JSONSchemaValidator
	cache     sync.Map // id -> *wot.ThingDescription
	mapper    *WoTMapper
}

func NewThingRegistry(db *sql.DB, logger *logrus.Logger) *ThingRegistry {
	r := &ThingRegistry{
		db:     db,
		logger: logger,
		jsonld: ld.NewJsonLdProcessor(),
		mapper: NewWoTMapper(logger),
	}

	// Use the centralized schema validator
	r.validator = api.NewJSONSchemaValidator()
	return r
}

// RegisterThing registers a new Thing Description via API
func (r *ThingRegistry) RegisterThing(tdJSONLD string) (*wot.ThingDescription, error) {
	r.logger.Debug("Registering new Thing Description")

	// Parse JSON-LD
	var doc any
	if err := json.Unmarshal([]byte(tdJSONLD), &doc); err != nil {
		r.logger.Errorf("Failed to parse TD JSON-LD: %v", err)
		return nil, fmt.Errorf("invalid JSON-LD: %w", err)
	}

	// Validate TD against JSON schema before further processing
	if err := r.validateTD(doc); err != nil {
		r.logger.Errorf("TD validation against JSON schema failed: %v", err)
		return nil, fmt.Errorf("TD schema validation failed: %w", err)
	}

	// Expand JSON-LD
	options := ld.NewJsonLdOptions("")
	expanded, err := r.jsonld.Expand(doc, options)
	if err != nil {
		r.logger.Errorf("Failed to expand JSON-LD: %v", err)
		return nil, fmt.Errorf("JSON-LD expansion failed: %w", err)
	}

	// Convert to Thing Description
	td, err := r.parseTD(expanded)
	if err != nil {
		r.logger.Errorf("Failed to parse TD: %v", err)
		return nil, err
	}

	// Validate TD (original basic Go struct validation can be re-added here if needed after parsing)
	// For now, the primary validation is the JSON schema validation done on `doc`.
	// If basic checks on `td` (the *wot.ThingDescription struct) are still needed, they could go here:
	// if td.ID == "" { ... }

	// Check if already exists
	existing, _ := r.GetThing(td.ID)
	if existing != nil {
		return nil, fmt.Errorf("thing with ID %s already exists", td.ID)
	}

	// Save to database
	tdParsedJSON, _ := json.Marshal(td)
	_, err = r.db.Exec(`
        INSERT INTO things (id, title, description, td_jsonld, td_parsed)
        VALUES (?, ?, ?, ?, ?)
    `, td.ID, td.Title, td.Description, tdJSONLD, string(tdParsedJSON))

	if err != nil {
		r.logger.Errorf("Failed to save TD to database: %v", err)
		return nil, fmt.Errorf("failed to save TD: %w", err)
	}

	// Cache it
	r.cache.Store(td.ID, td)

	r.logger.Infof("Registered Thing: %s (%s)", td.ID, td.Title)
	return td, nil
}

// UpdateThing updates an existing Thing Description
func (r *ThingRegistry) UpdateThing(thingID string, tdJSONLD string) (*wot.ThingDescription, error) {
	r.logger.Debugf("Updating Thing: %s", thingID)

	// Check if exists
	_, err := r.GetThing(thingID)
	if err != nil {
		return nil, fmt.Errorf("thing not found: %w", err)
	}

	// Parse and validate new TD
	var doc any
	if err := json.Unmarshal([]byte(tdJSONLD), &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON-LD: %w", err)
	}

	// Validate TD against JSON schema before further processing
	if err := r.validateTD(doc); err != nil {
		r.logger.Errorf("TD validation against JSON schema failed for update: %v", err)
		return nil, fmt.Errorf("TD schema validation failed for update: %w", err)
	}

	expanded, err := r.jsonld.Expand(doc, r.getJSONLDOptions())
	if err != nil {
		return nil, fmt.Errorf("JSON-LD expansion failed: %w", err)
	}

	td, err := r.parseTD(expanded)
	if err != nil {
		return nil, err
	}

	// Original basic Go struct validation can be re-added here if needed after parsing
	// For now, the primary validation is the JSON schema validation done on `doc`.

	// Ensure ID matches
	if td.ID != thingID {
		return nil, fmt.Errorf("TD ID mismatch: expected %s, got %s", thingID, td.ID)
	}

	// Update in database
	tdParsedJSON, _ := json.Marshal(td)
	_, err = r.db.Exec(`
        UPDATE things 
        SET title = ?, description = ?, td_jsonld = ?, td_parsed = ?, updated_at = ?
        WHERE id = ?
    `, td.Title, td.Description, tdJSONLD, string(tdParsedJSON), time.Now(), thingID)

	if err != nil {
		return nil, fmt.Errorf("failed to update TD: %w", err)
	}

	// Update cache
	r.cache.Store(td.ID, td)

	r.logger.Infof("Updated Thing: %s", thingID)
	return td, nil
}

// DeleteThing removes a Thing Description
func (r *ThingRegistry) DeleteThing(thingID string) error {
	r.logger.Debugf("Deleting Thing: %s", thingID)

	_, err := r.db.Exec("DELETE FROM things WHERE id = ?", thingID)
	if err != nil {
		return fmt.Errorf("failed to delete TD: %w", err)
	}

	r.cache.Delete(thingID)

	r.logger.Infof("Deleted Thing: %s", thingID)
	return nil
}

// GetThing retrieves a Thing Description
func (r *ThingRegistry) GetThing(thingID string) (*wot.ThingDescription, error) {
	// Check cache first
	if cached, ok := r.cache.Load(thingID); ok {
		return cached.(*wot.ThingDescription), nil
	}

	// Load from database
	var tdParsedJSON string
	err := r.db.QueryRow(`
        SELECT td_parsed FROM things WHERE id = ?
    `, thingID).Scan(&tdParsedJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("thing not found")
	}
	if err != nil {
		return nil, err
	}

	var td wot.ThingDescription
	if err := json.Unmarshal([]byte(tdParsedJSON), &td); err != nil {
		return nil, err
	}

	// Cache it
	r.cache.Store(thingID, &td)

	return &td, nil
}

// GetProperty retrieves a specific property affordance
func (r *ThingRegistry) GetProperty(thingID, propertyName string) (wot.PropertyAffordance, error) {
	td, err := r.GetThing(thingID)
	if err != nil {
		return wot.PropertyAffordance{}, err
	}

	// Assuming td.Properties is map[string]*wot.PropertyAffordance or similar if the error occurs
	// If td.Properties is map[string]wot.PropertyAffordance, the error for 'prop' type wouldn't occur.
	// Given the error, we assume it stores pointers.
	propPtr, exists := td.Properties[propertyName]
	if !exists {
		return wot.PropertyAffordance{}, fmt.Errorf("property '%s' not found in Thing '%s'", propertyName, thingID)
	}
	if propPtr == nil {
		return wot.PropertyAffordance{}, fmt.Errorf("property '%s' in Thing '%s' has a nil definition", propertyName, thingID)
	}

	return *propPtr, nil // Dereference pointer to return value
}

// GetAction retrieves a specific action affordance
func (r *ThingRegistry) GetAction(thingID, actionName string) (wot.ActionAffordance, error) {
	td, err := r.GetThing(thingID)
	if err != nil {
		return wot.ActionAffordance{}, err
	}

	actionPtr, exists := td.Actions[actionName]
	if !exists {
		return wot.ActionAffordance{}, fmt.Errorf("action '%s' not found in Thing '%s'", actionName, thingID)
	}
	if actionPtr == nil {
		return wot.ActionAffordance{}, fmt.Errorf("action '%s' in Thing '%s' has a nil definition", actionName, thingID)
	}

	return *actionPtr, nil // Dereference pointer
}

// GetEvent retrieves a specific event affordance
func (r *ThingRegistry) GetEvent(thingID, eventName string) (wot.EventAffordance, error) {
	td, err := r.GetThing(thingID)
	if err != nil {
		return wot.EventAffordance{}, err
	}

	eventPtr, exists := td.Events[eventName]
	if !exists {
		return wot.EventAffordance{}, fmt.Errorf("event '%s' not found in Thing '%s'", eventName, thingID)
	}
	if eventPtr == nil {
		return wot.EventAffordance{}, fmt.Errorf("event '%s' in Thing '%s' has a nil definition", eventName, thingID)
	}

	return *eventPtr, nil // Dereference pointer
}

// ListThings returns all registered Thing Descriptions
func (r *ThingRegistry) ListThings() ([]*wot.ThingDescription, error) {
	rows, err := r.db.Query(`
        SELECT td_parsed FROM things ORDER BY updated_at DESC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var things []*wot.ThingDescription
	for rows.Next() {
		var tdJSON string
		if err := rows.Scan(&tdJSON); err != nil {
			r.logger.Errorf("Failed to scan TD: %v", err)
			continue
		}

		var td wot.ThingDescription
		if err := json.Unmarshal([]byte(tdJSON), &td); err != nil {
			r.logger.Errorf("Failed to unmarshal TD: %v", err)
			continue
		}

		things = append(things, &td)
	}

	return things, nil
}

// GenerateConfigs generates Caddy and Benthos configs from TD
func (r *ThingRegistry) GenerateConfigs(td *wot.ThingDescription) (*types.UnifiedConfig, error) {
	return r.mapper.ProcessTD(td)
}

// Helper methods

func (r *ThingRegistry) parseTD(expanded any) (*wot.ThingDescription, error) {
	// Convert expanded JSON-LD to Thing Description
	// This is a simplified version - real implementation would handle
	// all the complexity of JSON-LD to TD conversion

	data, err := json.Marshal(expanded)
	if err != nil {
		return nil, err
	}

	var td wot.ThingDescription
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, err
	}

	return &td, nil
}

func (r *ThingRegistry) validateTD(jsonData any) error {
	// Convert jsonData to TD struct for validation using centralized validator
	tdJSON, err := json.Marshal(jsonData)
	if err != nil {
		return fmt.Errorf("failed to marshal TD for validation: %w", err)
	}

	var td wot.ThingDescription
	if err := json.Unmarshal(tdJSON, &td); err != nil {
		return fmt.Errorf("failed to unmarshal TD for validation: %w", err)
	}

	// Use the centralized validator with 3-layer validation
	logger := r.logger.WithField("component", "ThingRegistry")
	return r.validator.ValidateThingDescription(logger, &td)
}

func (r *ThingRegistry) getJSONLDOptions() *ld.JsonLdOptions {
	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	return options
}
