package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/models"
)

// BenthosStateManager is a refactored StateManager that uses Benthos for Parquet logging
// Parquet logging is now handled by centralized binding generation
type BenthosStateManager struct {
	db             *sql.DB
	logger         logrus.FieldLogger
	parquetEnabled bool
	subscribers    sync.Map     // map[string][]chan PropertyUpdate
	mu             sync.RWMutex // Protects subscribers map
}

// NewBenthosStateManager creates a new state manager with Benthos Parquet logging
func NewBenthosStateManager(db *sql.DB, benthosConfigDir, parquetLogPath string, logger logrus.FieldLogger) (*BenthosStateManager, error) {
	logger.Debug("Creating Benthos state manager") // Entry log for constructor
	sm := &BenthosStateManager{
		db:     db,
		logger: logger,
	}

	// Parquet logging now handled by centralized binding generation
	if benthosConfigDir != "" || parquetLogPath != "" {
		sm.parquetEnabled = true
		logger.Info("Parquet logging will be handled by centralized binding generation (via BenthosStateManager config)")
	} else {
		logger.Info("Parquet logging (via BenthosStateManager config) is disabled as paths are empty")
	}

	return sm, nil
}

// GetProperty retrieves a property value from the database
func (sm *BenthosStateManager) GetProperty(thingID, name string) (interface{}, error) {
	// Using sm.logger as base, assuming request_id is not directly available or needed for this specific implementation's logging detail level
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetProperty", "thing_id": thingID, "property_name": name})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	query := `SELECT value FROM property_state WHERE thing_id = ? AND property_name = ?`
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "QueryRow"}).Debug("Calling dependency")
	var valueJSON string
	err := sm.db.QueryRow(query, thingID, name).Scan(&valueJSON)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "QueryRow"}).Error("Dependency call failed")
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("property %s not found for thing %s", name, thingID)
		}
		return nil, fmt.Errorf("failed to get property: %w", err)
	}

	var value interface{}
	if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
		logger.WithError(err).Error("Failed to unmarshal property value from DB")
		return nil, fmt.Errorf("failed to unmarshal property value: %w", err)
	}
	logger.WithField("retrieved_value", value).Debug("Retrieved property successfully")
	return value, nil
}

// SetProperty updates a property value in the database and logs to Parquet
func (sm *BenthosStateManager) SetProperty(logger logrus.FieldLogger, thingID, name string, value interface{}) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "SetProperty", "thing_id": thingID, "property_name": name, "value": value})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	// Use default HTTP source for backward compatibility
	ctx := models.WithUpdateContext(context.Background(), models.NewUpdateContext(models.UpdateSourceHTTP))
	return sm.SetPropertyWithContext(logger, ctx, thingID, name, value) // Pass the provided logger
}

// SetPropertyWithContext updates a property value with source context
func (sm *BenthosStateManager) SetPropertyWithContext(logger logrus.FieldLogger, ctx context.Context, thingID, name string, value interface{}) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "SetPropertyWithContext", "thing_id": thingID, "property_name": name}) // Removed value from initial log for brevity
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	valueJSON, err := json.Marshal(value)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal property value")
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
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Debug("Calling dependency to set property")
	_, err = sm.db.ExecContext(ctx, query, thingID, name, string(valueJSON), now)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Error("Dependency call failed")
		return fmt.Errorf("failed to update property: %w", err)
	}
	logger.Info("Property updated in DB")

	// Log to Parquet via Benthos with source context
	if sm.parquetEnabled {
		source := "unknown"
		if updateCtx, ok := models.GetUpdateContext(ctx); ok {
			source = string(updateCtx.Source)
		}
		logger.WithFields(logrus.Fields{ // Use the passed-in logger which might have request_id
			"thing_id": thingID, // Explicitly log identifiers for this specific message
			"property": name,
			"source":   source,
		}).Debug("Parquet logging for property update handled by centralized binding generation (BenthosStateManager)")
	}

	// Notify subscribers
	// Pass the entryLogger (which includes request_id if available from the handler) to notifySubscribers
	sm.notifySubscribers(entryLogger, thingID, name, value)

	return nil
}

// GetAllProperties retrieves all properties for a thing
func (sm *BenthosStateManager) GetAllProperties(ctx context.Context, thingID string) (map[string]interface{}, error) {
	// Using sm.logger as base
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetAllProperties", "thing_id": thingID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	query := `SELECT property_name, value FROM property_state WHERE thing_id = ?`
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "QueryContext"}).Debug("Calling dependency")
	rows, err := sm.db.QueryContext(ctx, query, thingID)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "QueryContext"}).Error("Dependency call failed")
		return nil, fmt.Errorf("failed to query properties: %w", err)
	}
	defer rows.Close()

	properties := make(map[string]interface{})
	for rows.Next() {
		var name, valueJSON string
		if err := rows.Scan(&name, &valueJSON); err != nil {
			logger.WithError(err).Error("Failed to scan property row from DB")
			return nil, fmt.Errorf("failed to scan property row: %w", err)
		}

		var value interface{}
		if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
			logger.WithError(err).WithField("property_name", name).Warn("Failed to unmarshal property value from DB")
			continue
		}
		properties[name] = value
	}

	if err := rows.Err(); err != nil {
		logger.WithError(err).Error("Error iterating over property rows from DB")
		return nil, fmt.Errorf("error iterating properties: %w", err)
	}
	logger.WithField("property_count", len(properties)).Debug("Retrieved all properties successfully")
	return properties, nil
}

// DeleteProperty removes a property from the database
func (sm *BenthosStateManager) DeleteProperty(ctx context.Context, thingID, name string) error {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "DeleteProperty", "thing_id": thingID, "property_name": name})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	query := `DELETE FROM property_state WHERE thing_id = ? AND property_name = ?`
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Debug("Calling dependency to delete property")
	result, err := sm.db.ExecContext(ctx, query, thingID, name)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Error("Dependency call failed")
		return fmt.Errorf("failed to delete property: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logger.WithError(err).Error("Failed to get rows affected after delete")
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		logger.Warn("Property not found for deletion")
		return fmt.Errorf("property %s not found for thing %s", name, thingID)
	}
	logger.Info("Property deleted successfully")
	return nil
}

// DeleteAllProperties removes all properties for a thing
func (sm *BenthosStateManager) DeleteAllProperties(ctx context.Context, thingID string) error {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "DeleteAllProperties", "thing_id": thingID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	query := `DELETE FROM property_state WHERE thing_id = ?`
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Debug("Calling dependency to delete all properties")
	_, err := sm.db.ExecContext(ctx, query, thingID)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Error("Dependency call failed")
		return fmt.Errorf("failed to delete properties: %w", err)
	}
	logger.Info("All properties deleted for thing")
	return nil
}

// Close shuts down the state manager
func (sm *BenthosStateManager) Close() error {
	// Parquet client cleanup now handled by centralized binding generation
	return nil
}

func (sm *BenthosStateManager) notifySubscribers(logger logrus.FieldLogger, thingID, propertyName string, value interface{}) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)
	// Use the logger passed from SetPropertyWithContext, which may include request_id
	notifyLogger := logger.WithFields(logrus.Fields{"internal_method": "notifySubscribers", "key": key})
	notifyLogger.Debug("Notifying subscribers")

	if subs, ok := sm.subscribers.Load(key); ok {
		channels := subs.([]chan models.PropertyUpdate)
		notifyLogger.WithField("subscriber_count", len(channels)).Debug("Found subscribers to notify")

		// Determine source from context if possible, otherwise default or leave as is
		// For now, using a generic source as the original SetProperty context is not directly available here.
		// This could be enhanced by passing source information through if critical.
		source := "state_manager" // Default source
		// Attempt to get source from context if available (this function doesn't have direct access to original ctx)
		// This part is tricky as notifySubscribers doesn't have the original context.
		// The PropertyUpdate model expects a source. We'll use a generic one.
		// If SetPropertyWithContext's context's source is needed, it should be passed explicitly.

		update := models.PropertyUpdate{
			ThingID:      thingID,
			PropertyName: propertyName,
			Value:        value,
			Timestamp:    time.Now(),
			Source:       source, // Ensure this matches the type if it's an enum/defined type
		}

		for i, ch := range channels {
			select {
			case ch <- update:
				notifyLogger.WithField("subscriber_index", i).Debug("Notified subscriber")
			default:
				notifyLogger.WithField("subscriber_index", i).Warn("Subscriber channel full, skipping notification")
			}
		}
	} else {
		notifyLogger.Debug("No subscribers for property")
	}
}

// SubscribeProperty implements StateManager interface
func (sm *BenthosStateManager) SubscribeProperty(thingID, propertyName string) (<-chan models.PropertyUpdate, error) {
	// Use sm.logger as this is not typically part of a request needing specific request_id logging from handler.
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "SubscribeProperty", "thing_id": thingID, "property_name": propertyName})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	ch := make(chan models.PropertyUpdate, 10) // Buffer size 10
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if subs, ok := sm.subscribers.Load(key); ok {
		channels, ok := subs.([]chan models.PropertyUpdate)
		if !ok {
			// This case should ideally not happen if types are consistent.
			// If it does, it implies a different type was stored, which is a programming error.
			logger.Error("Subscribers list is not of expected type, reinitializing.")
			// Reinitialize the subscriber list for this key.
			sm.subscribers.Store(key, []chan models.PropertyUpdate{ch})
		} else {
			channels = append(channels, ch)
			sm.subscribers.Store(key, channels)
			logger.WithField("total_subscribers", len(channels)).Debug("Added subscriber to existing list")
		}
	} else {
		sm.subscribers.Store(key, []chan models.PropertyUpdate{ch})
		logger.Debug("Created new subscriber list")
	}

	return ch, nil
}

// UnsubscribeProperty implements StateManager interface
func (sm *BenthosStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan models.PropertyUpdate) {
	// Use sm.logger for similar reasons as SubscribeProperty.
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "UnsubscribeProperty", "thing_id": thingID, "property_name": propertyName})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	subs, ok := sm.subscribers.Load(key)
	if !ok {
		logger.Warn("No subscriber list found for key during unsubscribe")
		return
	}

	channels, ok := subs.([]chan models.PropertyUpdate)
	if !ok {
		// Log error, as this indicates a type mismatch issue.
		logger.Error("Subscribers list is not of expected type during unsubscribe.")
		// It's safer to delete the key if the type is wrong to prevent further issues.
		sm.subscribers.Delete(key)
		return
	}

	for i, c := range channels {
		if c == ch {
			channels = append(channels[:i], channels[i+1:]...)
			if len(channels) == 0 {
				sm.subscribers.Delete(key)
				logger.Debug("Removed last subscriber, deleting list")
			} else {
				sm.subscribers.Store(key, channels)
				logger.WithField("remaining_subscribers", len(channels)).Debug("Removed subscriber")
			}
			close(c) // Close the channel to signal the subscriber
			return
		}
	}
	logger.Warn("Channel not found in subscriber list for key")
}

// Ensure BenthosStateManager implements StateManager interface
var _ StateManager = (*BenthosStateManager)(nil)
