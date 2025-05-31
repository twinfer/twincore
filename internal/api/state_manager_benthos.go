package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/models"
)

// BenthosStateManager is a refactored StateManager that uses Benthos for Parquet logging
type BenthosStateManager struct {
	db             *sql.DB
	logger         logrus.FieldLogger
	parquetClient  *SimpleBenthosParquetClient
	parquetEnabled bool
}

// NewBenthosStateManager creates a new state manager with Benthos Parquet logging
func NewBenthosStateManager(db *sql.DB, benthosConfigDir, parquetLogPath string, logger logrus.FieldLogger) (*BenthosStateManager, error) {
	sm := &BenthosStateManager{
		db:     db,
		logger: logger,
	}

	// Initialize simple Benthos Parquet client
	if benthosConfigDir != "" || parquetLogPath != "" {
		client, err := NewSimpleBenthosParquetClient(benthosConfigDir, parquetLogPath, logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize Benthos Parquet client, continuing without Parquet logging")
		} else {
			sm.parquetClient = client
			sm.parquetEnabled = true
			logger.Info("Benthos-based Parquet logging enabled")
		}
	}

	return sm, nil
}

// GetProperty retrieves a property value from the database
func (sm *BenthosStateManager) GetProperty(thingID, name string) (interface{}, error) {
	query := `SELECT value FROM property_state WHERE thing_id = ? AND property_name = ?`

	var valueJSON string
	err := sm.db.QueryRow(query, thingID, name).Scan(&valueJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("property %s not found for thing %s", name, thingID)
		}
		return nil, fmt.Errorf("failed to get property: %w", err)
	}

	var value interface{}
	if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
		return nil, fmt.Errorf("failed to unmarshal property value: %w", err)
	}

	return value, nil
}

// SetProperty updates a property value in the database and logs to Parquet
func (sm *BenthosStateManager) SetProperty(thingID, name string, value interface{}) error {
	// Use default HTTP source for backward compatibility
	ctx := models.WithUpdateContext(context.Background(), models.NewUpdateContext(models.UpdateSourceHTTP))
	return sm.SetPropertyWithContext(ctx, thingID, name, value)
}

// SetPropertyWithContext updates a property value with source context
func (sm *BenthosStateManager) SetPropertyWithContext(ctx context.Context, thingID, name string, value interface{}) error {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal property value: %w", err)
	}

	// Update database
	query := `
		INSERT INTO property_state (thing_id, property_name, value, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(thing_id, property_name) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at
	`

	now := time.Now()
	_, err = sm.db.Exec(query, thingID, name, string(valueJSON), now)
	if err != nil {
		return fmt.Errorf("failed to update property: %w", err)
	}

	// Log to Parquet via Benthos with source context
	if sm.parquetEnabled && sm.parquetClient != nil {
		// Extract source from context
		source := "unknown"
		if updateCtx, ok := models.GetUpdateContext(ctx); ok {
			source = string(updateCtx.Source)
		}

		if err := sm.parquetClient.LogPropertyUpdate(thingID, name, value, source); err != nil {
			// Log error but don't fail the operation
			sm.logger.WithError(err).Error("Failed to log property update to Parquet")
		}
	}

	return nil
}

// GetAllProperties retrieves all properties for a thing
func (sm *BenthosStateManager) GetAllProperties(ctx context.Context, thingID string) (map[string]interface{}, error) {
	query := `SELECT property_name, value FROM property_state WHERE thing_id = ?`

	rows, err := sm.db.QueryContext(ctx, query, thingID)
	if err != nil {
		return nil, fmt.Errorf("failed to query properties: %w", err)
	}
	defer rows.Close()

	properties := make(map[string]interface{})
	for rows.Next() {
		var name, valueJSON string
		if err := rows.Scan(&name, &valueJSON); err != nil {
			return nil, fmt.Errorf("failed to scan property row: %w", err)
		}

		var value interface{}
		if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
			sm.logger.WithError(err).Warnf("Failed to unmarshal property %s", name)
			continue
		}

		properties[name] = value
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating properties: %w", err)
	}

	return properties, nil
}

// DeleteProperty removes a property from the database
func (sm *BenthosStateManager) DeleteProperty(ctx context.Context, thingID, name string) error {
	query := `DELETE FROM property_state WHERE thing_id = ? AND property_name = ?`

	result, err := sm.db.ExecContext(ctx, query, thingID, name)
	if err != nil {
		return fmt.Errorf("failed to delete property: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("property %s not found for thing %s", name, thingID)
	}

	return nil
}

// DeleteAllProperties removes all properties for a thing
func (sm *BenthosStateManager) DeleteAllProperties(ctx context.Context, thingID string) error {
	query := `DELETE FROM property_state WHERE thing_id = ?`

	_, err := sm.db.ExecContext(ctx, query, thingID)
	if err != nil {
		return fmt.Errorf("failed to delete properties: %w", err)
	}

	return nil
}

// Close shuts down the state manager
func (sm *BenthosStateManager) Close() error {
	if sm.parquetClient != nil {
		return sm.parquetClient.Close()
	}
	return nil
}

// SubscribeProperty implements StateManager interface
func (sm *BenthosStateManager) SubscribeProperty(thingID, propertyName string) (<-chan models.PropertyUpdate, error) {
	// For now, return nil channel - this would need to be implemented with proper subscription
	// This is beyond the scope of Benthos Parquet replacement
	return nil, fmt.Errorf("subscription not implemented in Benthos state manager")
}

// UnsubscribeProperty implements StateManager interface
func (sm *BenthosStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan models.PropertyUpdate) {
	// No-op for now
}

// Ensure BenthosStateManager implements StateManager interface
var _ StateManager = (*BenthosStateManager)(nil)
