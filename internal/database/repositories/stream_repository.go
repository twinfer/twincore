package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/pkg/types"
)

// StreamRepository provides data access operations for stream state management
type StreamRepository struct {
	manager DatabaseManager
	logger  *logrus.Logger
}

// NewStreamRepository creates a new Stream repository
func NewStreamRepository(manager DatabaseManager, logger *logrus.Logger) *StreamRepository {
	return &StreamRepository{
		manager: manager,
		logger:  logger,
	}
}

// PropertyState operations

// UpsertPropertyState creates or updates a property state
func (sr *StreamRepository) UpsertPropertyState(ctx context.Context, thingID, propertyName, value string) error {
	_, err := sr.manager.Execute(ctx, "UpsertPropertyState", thingID, propertyName, value)
	if err != nil {
		sr.logger.WithError(err).WithFields(logrus.Fields{
			"thing_id":      thingID,
			"property_name": propertyName,
		}).Error("Failed to upsert property state")
		return fmt.Errorf("failed to upsert property state: %w", err)
	}

	sr.logger.WithFields(logrus.Fields{
		"thing_id":      thingID,
		"property_name": propertyName,
	}).Debug("Property state upserted successfully")
	return nil
}

// GetPropertyValue retrieves a property value
func (sr *StreamRepository) GetPropertyValue(ctx context.Context, thingID, propertyName string) (string, error) {
	row := sr.manager.QueryRow(ctx, "GetPropertyValue", thingID, propertyName)
	
	var value string
	err := row.Scan(&value)
	if err != nil {
		sr.logger.WithError(err).WithFields(logrus.Fields{
			"thing_id":      thingID,
			"property_name": propertyName,
		}).Error("Failed to get property value")
		return "", fmt.Errorf("failed to get property value: %w", err)
	}

	return value, nil
}

// GetPropertyState retrieves a complete property state record
func (sr *StreamRepository) GetPropertyState(ctx context.Context, thingID, propertyName string) (*database.PropertyStateEntity, error) {
	row := sr.manager.QueryRow(ctx, "GetPropertyState", thingID, propertyName)
	
	var entity database.PropertyStateEntity
	err := row.Scan(&entity.ThingID, &entity.PropertyName, &entity.Value, &entity.UpdatedAt)
	if err != nil {
		sr.logger.WithError(err).WithFields(logrus.Fields{
			"thing_id":      thingID,
			"property_name": propertyName,
		}).Error("Failed to get property state")
		return nil, fmt.Errorf("failed to get property state: %w", err)
	}

	return &entity, nil
}

// GetThingProperties retrieves all properties for a thing
func (sr *StreamRepository) GetThingProperties(ctx context.Context, thingID string) ([]*database.PropertyStateEntity, error) {
	rows, err := sr.manager.Query(ctx, "GetThingProperties", thingID)
	if err != nil {
		sr.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to get thing properties")
		return nil, fmt.Errorf("failed to get thing properties: %w", err)
	}
	defer rows.Close()

	var properties []*database.PropertyStateEntity
	for rows.Next() {
		var entity database.PropertyStateEntity
		entity.ThingID = thingID // We know the thing ID
		
		err := rows.Scan(&entity.PropertyName, &entity.Value, &entity.UpdatedAt)
		if err != nil {
			sr.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to scan property")
			return nil, fmt.Errorf("failed to scan property: %w", err)
		}
		properties = append(properties, &entity)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating properties: %w", err)
	}

	sr.logger.WithFields(logrus.Fields{
		"thing_id": thingID,
		"count":    len(properties),
	}).Debug("Retrieved thing properties")

	return properties, nil
}

// GetAllPropertyStates retrieves all property states
func (sr *StreamRepository) GetAllPropertyStates(ctx context.Context) ([]*database.PropertyStateEntity, error) {
	rows, err := sr.manager.Query(ctx, "GetAllPropertyStates")
	if err != nil {
		sr.logger.WithError(err).Error("Failed to get all property states")
		return nil, fmt.Errorf("failed to get all property states: %w", err)
	}
	defer rows.Close()

	var properties []*database.PropertyStateEntity
	for rows.Next() {
		var entity database.PropertyStateEntity
		err := rows.Scan(&entity.ThingID, &entity.PropertyName, &entity.Value, &entity.UpdatedAt)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan property state")
			return nil, fmt.Errorf("failed to scan property state: %w", err)
		}
		properties = append(properties, &entity)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating property states: %w", err)
	}

	sr.logger.WithField("count", len(properties)).Debug("Retrieved all property states")
	return properties, nil
}

// DeletePropertyState removes a specific property state
func (sr *StreamRepository) DeletePropertyState(ctx context.Context, thingID, propertyName string) error {
	result, err := sr.manager.Execute(ctx, "DeletePropertyState", thingID, propertyName)
	if err != nil {
		sr.logger.WithError(err).WithFields(logrus.Fields{
			"thing_id":      thingID,
			"property_name": propertyName,
		}).Error("Failed to delete property state")
		return fmt.Errorf("failed to delete property state: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("property state not found: %s/%s", thingID, propertyName)
	}

	sr.logger.WithFields(logrus.Fields{
		"thing_id":      thingID,
		"property_name": propertyName,
	}).Debug("Property state deleted successfully")

	return nil
}

// DeleteThingProperties removes all properties for a thing
func (sr *StreamRepository) DeleteThingProperties(ctx context.Context, thingID string) error {
	_, err := sr.manager.Execute(ctx, "DeleteThingProperties", thingID)
	if err != nil {
		sr.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to delete thing properties")
		return fmt.Errorf("failed to delete thing properties: %w", err)
	}

	sr.logger.WithField("thing_id", thingID).Debug("Thing properties deleted successfully")
	return nil
}

// Action state operations

// CreateActionState creates a new action state record
func (sr *StreamRepository) CreateActionState(ctx context.Context, action *database.ActionStateEntity) error {
	completedAt := (*time.Time)(nil)
	if action.CompletedAt != nil {
		completedAt = action.CompletedAt
	}

	_, err := sr.manager.Execute(ctx, "InsertActionState",
		action.ActionID, action.ThingID, action.ActionName,
		action.Input, action.Output, action.Status,
		completedAt, action.Error)

	if err != nil {
		sr.logger.WithError(err).WithField("action_id", action.ActionID).Error("Failed to create action state")
		return fmt.Errorf("failed to create action state: %w", err)
	}

	sr.logger.WithField("action_id", action.ActionID).Debug("Action state created successfully")
	return nil
}

// GetActionState retrieves an action state by ID
func (sr *StreamRepository) GetActionState(ctx context.Context, actionID string) (*database.ActionStateEntity, error) {
	row := sr.manager.QueryRow(ctx, "GetActionState", actionID)
	
	var entity database.ActionStateEntity
	err := row.Scan(&entity.ActionID, &entity.ThingID, &entity.ActionName,
		&entity.Input, &entity.Output, &entity.Status,
		&entity.StartedAt, &entity.CompletedAt, &entity.Error)

	if err != nil {
		sr.logger.WithError(err).WithField("action_id", actionID).Error("Failed to get action state")
		return nil, fmt.Errorf("failed to get action state: %w", err)
	}

	return &entity, nil
}

// UpdateActionState updates an action state
func (sr *StreamRepository) UpdateActionState(ctx context.Context, actionID, output, status, errorMsg string) error {
	var errorPtr *string
	if errorMsg != "" {
		errorPtr = &errorMsg
	}

	_, err := sr.manager.Execute(ctx, "UpdateActionState", output, status, time.Now(), errorPtr, actionID)
	if err != nil {
		sr.logger.WithError(err).WithField("action_id", actionID).Error("Failed to update action state")
		return fmt.Errorf("failed to update action state: %w", err)
	}

	sr.logger.WithField("action_id", actionID).Debug("Action state updated successfully")
	return nil
}

// ListActionsByThing retrieves all actions for a thing
func (sr *StreamRepository) ListActionsByThing(ctx context.Context, thingID string) ([]*database.ActionStateEntity, error) {
	rows, err := sr.manager.Query(ctx, "ListActionsByThing", thingID)
	if err != nil {
		sr.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to list actions by thing")
		return nil, fmt.Errorf("failed to list actions by thing: %w", err)
	}
	defer rows.Close()

	var actions []*database.ActionStateEntity
	for rows.Next() {
		var entity database.ActionStateEntity
		err := rows.Scan(&entity.ActionID, &entity.ThingID, &entity.ActionName,
			&entity.Input, &entity.Output, &entity.Status,
			&entity.StartedAt, &entity.CompletedAt, &entity.Error)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan action state")
			return nil, fmt.Errorf("failed to scan action state: %w", err)
		}
		actions = append(actions, &entity)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating actions: %w", err)
	}

	return actions, nil
}

// ListActionsByStatus retrieves actions by status
func (sr *StreamRepository) ListActionsByStatus(ctx context.Context, status string) ([]*database.ActionStateEntity, error) {
	rows, err := sr.manager.Query(ctx, "ListActionsByStatus", status)
	if err != nil {
		sr.logger.WithError(err).WithField("status", status).Error("Failed to list actions by status")
		return nil, fmt.Errorf("failed to list actions by status: %w", err)
	}
	defer rows.Close()

	var actions []*database.ActionStateEntity
	for rows.Next() {
		var entity database.ActionStateEntity
		err := rows.Scan(&entity.ActionID, &entity.ThingID, &entity.ActionName,
			&entity.Input, &entity.Output, &entity.Status,
			&entity.StartedAt, &entity.CompletedAt, &entity.Error)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan action state")
			return nil, fmt.Errorf("failed to scan action state: %w", err)
		}
		actions = append(actions, &entity)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating actions: %w", err)
	}

	return actions, nil
}

// DeleteActionState removes an action state
func (sr *StreamRepository) DeleteActionState(ctx context.Context, actionID string) error {
	result, err := sr.manager.Execute(ctx, "DeleteActionState", actionID)
	if err != nil {
		sr.logger.WithError(err).WithField("action_id", actionID).Error("Failed to delete action state")
		return fmt.Errorf("failed to delete action state: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("action state not found: %s", actionID)
	}

	sr.logger.WithField("action_id", actionID).Debug("Action state deleted successfully")
	return nil
}

// DeleteCompletedActions removes completed actions before a given time
func (sr *StreamRepository) DeleteCompletedActions(ctx context.Context, before time.Time) error {
	_, err := sr.manager.Execute(ctx, "DeleteCompletedActions", before)
	if err != nil {
		sr.logger.WithError(err).WithField("before", before).Error("Failed to delete completed actions")
		return fmt.Errorf("failed to delete completed actions: %w", err)
	}

	sr.logger.WithField("before", before).Debug("Completed actions deleted successfully")
	return nil
}

// Cleanup operations

// CleanupOldPropertyStates removes old property states
func (sr *StreamRepository) CleanupOldPropertyStates(ctx context.Context, before time.Time) error {
	_, err := sr.manager.Execute(ctx, "CleanupOldPropertyStates", before)
	if err != nil {
		sr.logger.WithError(err).WithField("before", before).Error("Failed to cleanup old property states")
		return fmt.Errorf("failed to cleanup old property states: %w", err)
	}

	sr.logger.WithField("before", before).Debug("Old property states cleaned up successfully")
	return nil
}

// CleanupDeletedStreams removes deleted streams before a given time
func (sr *StreamRepository) CleanupDeletedStreams(ctx context.Context, before time.Time) error {
	_, err := sr.manager.Execute(ctx, "CleanupDeletedStreams", before)
	if err != nil {
		sr.logger.WithError(err).WithField("before", before).Error("Failed to cleanup deleted streams")
		return fmt.Errorf("failed to cleanup deleted streams: %w", err)
	}

	sr.logger.WithField("before", before).Debug("Deleted streams cleaned up successfully")
	return nil
}

// IsHealthy checks if the repository is healthy (implements RepositoryBase interface)
func (sr *StreamRepository) IsHealthy(ctx context.Context) bool {
	// Simple health check - try to get all property states
	_, err := sr.GetAllPropertyStates(ctx)
	return err == nil
}

// Stream configuration operations (placeholders for interface compliance)
// Note: These methods are required by the interface but not fully implemented
// as the current system doesn't store stream configurations in the database

// CreateStreamConfig creates a new stream configuration (placeholder)
func (sr *StreamRepository) CreateStreamConfig(ctx context.Context, config *types.StreamInfo) error {
	sr.logger.Debug("CreateStreamConfig called - not fully implemented")
	return fmt.Errorf("CreateStreamConfig not implemented - streams managed by Benthos directly")
}

// GetStreamConfig retrieves a stream configuration (placeholder)
func (sr *StreamRepository) GetStreamConfig(ctx context.Context, streamID string) (*types.StreamInfo, error) {
	sr.logger.Debug("GetStreamConfig called - not fully implemented")
	return nil, fmt.Errorf("GetStreamConfig not implemented - streams managed by Benthos directly")
}

// UpdateStreamConfig updates a stream configuration (placeholder)
func (sr *StreamRepository) UpdateStreamConfig(ctx context.Context, config *types.StreamInfo) error {
	sr.logger.Debug("UpdateStreamConfig called - not fully implemented")
	return fmt.Errorf("UpdateStreamConfig not implemented - streams managed by Benthos directly")
}

// UpdateStreamStatus updates stream status (placeholder)
func (sr *StreamRepository) UpdateStreamStatus(ctx context.Context, streamID, status string) error {
	sr.logger.Debug("UpdateStreamStatus called - not fully implemented")
	return fmt.Errorf("UpdateStreamStatus not implemented - streams managed by Benthos directly")
}

// DeleteStreamConfig deletes a stream configuration (placeholder)
func (sr *StreamRepository) DeleteStreamConfig(ctx context.Context, streamID string) error {
	sr.logger.Debug("DeleteStreamConfig called - not fully implemented")
	return fmt.Errorf("DeleteStreamConfig not implemented - streams managed by Benthos directly")
}

// HardDeleteStreamConfig permanently deletes a stream configuration (placeholder)
func (sr *StreamRepository) HardDeleteStreamConfig(ctx context.Context, streamID string) error {
	sr.logger.Debug("HardDeleteStreamConfig called - not fully implemented")
	return fmt.Errorf("HardDeleteStreamConfig not implemented - streams managed by Benthos directly")
}

// ListActiveStreams lists all active streams (placeholder)
func (sr *StreamRepository) ListActiveStreams(ctx context.Context) ([]*types.StreamInfo, error) {
	sr.logger.Debug("ListActiveStreams called - not fully implemented")
	return []*types.StreamInfo{}, nil // Return empty list for now
}

// ListStreamsByThing lists streams for a specific thing (placeholder)
func (sr *StreamRepository) ListStreamsByThing(ctx context.Context, thingID string) ([]*types.StreamInfo, error) {
	sr.logger.Debug("ListStreamsByThing called - not fully implemented")
	return []*types.StreamInfo{}, nil // Return empty list for now
}

// ListStreamsByStatus lists streams by status (placeholder)
func (sr *StreamRepository) ListStreamsByStatus(ctx context.Context, status string) ([]*types.StreamInfo, error) {
	sr.logger.Debug("ListStreamsByStatus called - not fully implemented")
	return []*types.StreamInfo{}, nil // Return empty list for now
}

// CountActiveStreams returns the count of active streams (placeholder)
func (sr *StreamRepository) CountActiveStreams(ctx context.Context) (int, error) {
	sr.logger.Debug("CountActiveStreams called - not fully implemented")
	return 0, nil // Return 0 for now
}

// StreamExists checks if a stream exists (placeholder)
func (sr *StreamRepository) StreamExists(ctx context.Context, streamID string) (bool, error) {
	sr.logger.Debug("StreamExists called - not fully implemented")
	return false, nil // Return false for now
}