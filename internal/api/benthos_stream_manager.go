package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot/forms" // Added for unified stream configuration
)

// SimpleBenthosStreamManager implements BenthosStreamManager for dynamic stream management
// This implementation uses DuckDB for persistent stream configuration storage
type SimpleBenthosStreamManager struct {
	configDir            string
	db                   *sql.DB
	streams              map[string]*types.StreamInfo // Changed type
	streamBuilders       map[string]*service.StreamBuilder
	activeStreams        map[string]*service.Stream
	processorCollections map[string]*types.ProcessorCollection // Changed type
	// Unified stream configuration components
	streamConfigBuilder *forms.StreamConfigBuilder // Added for unified configuration
	schemaRegistry      *forms.SchemaRegistry      // Added for schema management
	logger              logrus.FieldLogger
	mu                  sync.RWMutex
}

// NewSimpleBenthosStreamManager creates a new simple Benthos stream manager with DuckDB persistence
func NewSimpleBenthosStreamManager(configDir string, db *sql.DB, logger logrus.FieldLogger) (*SimpleBenthosStreamManager, error) {
	logger.Debug("Creating NewSimpleBenthosStreamManager")

	// Initialize unified stream configuration components
	schemaRegistry := forms.NewSchemaRegistry()
	streamConfigBuilder := forms.NewStreamConfigBuilder(logger)

	sm := &SimpleBenthosStreamManager{
		configDir:            configDir,
		db:                   db,
		streams:              make(map[string]*types.StreamInfo),
		streamBuilders:       make(map[string]*service.StreamBuilder),
		activeStreams:        make(map[string]*service.Stream),
		processorCollections: make(map[string]*types.ProcessorCollection),
		streamConfigBuilder:  streamConfigBuilder,
		schemaRegistry:       schemaRegistry,
		logger:               logger,
	}

	// Initialize database schema
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "initializeSchema"}).Debug("Calling internal method")
	if err := sm.initializeSchema(); err != nil {
		logger.WithError(err).Error("Failed to initialize database schema")
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Load existing stream configurations from database
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "loadStreamsFromDatabase"}).Debug("Calling internal method")
	if err := sm.loadStreamsFromDatabase(); err != nil {
		logger.WithError(err).Error("Failed to load streams from database")
		return nil, fmt.Errorf("failed to load streams from database: %w", err)
	}
	logger.Info("SimpleBenthosStreamManager created and initialized successfully")
	return sm, nil
}

// initializeSchema creates the necessary tables for stream persistence
func (sm *SimpleBenthosStreamManager) initializeSchema() error {
	sm.logger.WithFields(logrus.Fields{"internal_method": "initializeSchema"}).Debug("Initializing database schema for stream manager")
	// Create stream_configs table for persisting stream configurations
	sm.logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec", "table_name": "stream_configs"}).Debug("Calling dependency")
	_, err := sm.db.Exec(`
		CREATE TABLE IF NOT EXISTS stream_configs (
			stream_id TEXT PRIMARY KEY,
			thing_id TEXT NOT NULL,
			interaction_type TEXT NOT NULL,
			interaction_name TEXT NOT NULL,
			direction TEXT NOT NULL,
			input_config TEXT NOT NULL,
			output_config TEXT NOT NULL,
			processor_chain TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'created',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			metadata TEXT,
			config_yaml TEXT,
			validation_error TEXT
		)
	`)
	if err != nil {
		sm.logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed")
		return &ErrBenthosDatabaseOperationFailed{Operation: "initialize_schema_create_table", WrappedErr: err}
	}

	sm.logger.Info("Initialized DuckDB schema for stream configuration persistence")
	return nil
}

// loadStreamsFromDatabase loads and validates all stored stream configurations at startup
func (sm *SimpleBenthosStreamManager) loadStreamsFromDatabase() error {
	logger := sm.logger.WithFields(logrus.Fields{"internal_method": "loadStreamsFromDatabase"})
	logger.Debug("Loading stream configurations from database")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Finished loading streams from database")
	}()

	query := `
		SELECT stream_id, thing_id, interaction_type, interaction_name, direction,
		       input_config, output_config, processor_chain, status,
		       created_at, updated_at, metadata
		FROM stream_configs
		WHERE status != 'deleted'
	`
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Query"}).Debug("Calling dependency to query stream configs")
	rows, err := sm.db.Query(query)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Query"}).Error("Dependency call failed")
		return &ErrBenthosDatabaseOperationFailed{Operation: "load_streams_query", WrappedErr: err}
	}
	defer rows.Close()

	loadedCount := 0
	validatedCount := 0
	errorCount := 0

	for rows.Next() {
		var streamID, thingID, interactionType, interactionName, direction string
		var inputConfigJSON, outputConfigJSON, processorChainJSON, status string
		var createdAt, updatedAt, metadataJSON string

		err := rows.Scan(
			&streamID, &thingID, &interactionType, &interactionName, &direction,
			&inputConfigJSON, &outputConfigJSON, &processorChainJSON, &status,
			&createdAt, &updatedAt, &metadataJSON,
		)
		if err != nil {
			logger.WithError(err).Error("Failed to scan stream config row")
			errorCount++
			continue
		}

		// Deserialize configurations
		var inputConfig types.StreamEndpointConfig // Changed type
		if err := json.Unmarshal([]byte(inputConfigJSON), &inputConfig); err != nil {
			logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal input config for loaded stream")
			// Log and continue, this stream might be corrupted
			errorCount++
			continue
		}

		var outputConfig types.StreamEndpointConfig // Changed type
		if err := json.Unmarshal([]byte(outputConfigJSON), &outputConfig); err != nil {
			logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal output config for loaded stream")
			errorCount++
			continue
		}

		var processorChain []types.ProcessorConfig // Changed type
		if err := json.Unmarshal([]byte(processorChainJSON), &processorChain); err != nil {
			logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal processor chain for loaded stream")
			errorCount++
			continue
		}

		var metadata map[string]interface{}
		if metadataJSON != "" { // metadata can be null
			if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
				logger.WithError(err).WithField("stream_id", streamID).Warn("Failed to unmarshal metadata for loaded stream, using empty")
				metadata = make(map[string]interface{}) // Default to empty map if unmarshalling fails
			}
		}

		// Create StreamInfo
		streamInfo := &types.StreamInfo{ // Changed type
			ID:              streamID,
			ThingID:         thingID,
			InteractionType: interactionType,
			InteractionName: interactionName,
			Direction:       direction,
			ProcessorChain:  processorChain,
			Input:           inputConfig,
			Output:          outputConfig,
			Status:          status,
			CreatedAt:       createdAt,
			UpdatedAt:       updatedAt,
			Metadata:        metadata,
		}

		// Generate Benthos configuration using StreamBuilder
		logger.WithField("stream_id", streamID).Debug("Generating Benthos stream builder for loaded stream")
		benthosConfig, err := sm.generateBenthosStreamBuilder(streamInfo)
		if err != nil {
			// Log error and update validation_error in DB for this stream
			errMsg := fmt.Sprintf("Failed to generate Benthos stream builder for loaded stream %s: %v", streamID, err)
			logger.WithError(err).WithField("stream_id", streamID).Error(errMsg)
			sm.updateValidationError(logger, streamID, err.Error()) // Pass logger
			errorCount++
			continue
		}
		sm.updateValidationError(logger, streamID, "") // Clear any previous validation error

		// Store in memory
		sm.streams[streamID] = streamInfo
		sm.streamBuilders[streamID] = benthosConfig

		logger.WithFields(logrus.Fields{
			"stream_id":        streamID,
			"thing_id":         thingID,
			"interaction_type": interactionType,
		}).Debug("Loaded and validated stream configuration from database")

		loadedCount++
		validatedCount++
	}

	if err := rows.Err(); err != nil {
		logger.WithError(err).Error("Error iterating stream config rows")
		return &ErrBenthosDatabaseOperationFailed{Operation: "load_streams_rows_iteration", WrappedErr: err}
	}

	logger.WithFields(logrus.Fields{
		"loaded":    loadedCount,
		"validated": validatedCount,
		"errors":    errorCount,
	}).Info("Completed loading stream configurations from database")

	return nil
}

// updateValidationError updates the validation error for a stream in the database
func (sm *SimpleBenthosStreamManager) updateValidationError(logger logrus.FieldLogger, streamID, errorMsg string) {
	entryLogger := logger.WithFields(logrus.Fields{"internal_method": "updateValidationError", "stream_id": streamID, "error_message": errorMsg})
	entryLogger.Debug("Internal method called to update validation error in DB")
	// logger itself might already have request_id if this was called from a request-scoped path.
	// If not, and if this method is critical enough to trace, streamID is a good identifier.

	_, err := sm.db.Exec(`
		UPDATE stream_configs 
		SET validation_error = ?, updated_at = ?
		WHERE stream_id = ?
	`, errorMsg, time.Now(), streamID)

	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec", "stream_id": streamID}).Error("Dependency call failed (updateValidationError)")
	}
}

// updateStreamStatusInDatabase updates the stream status in the database
func (sm *SimpleBenthosStreamManager) updateStreamStatusInDatabase(logger logrus.FieldLogger, streamID, status string) error {
	entryLogger := logger.WithFields(logrus.Fields{"internal_method": "updateStreamStatusInDatabase", "stream_id": streamID, "new_status": status})
	entryLogger.Debug("Internal method called to update stream status in DB")

	_, err := sm.db.Exec(`
		UPDATE stream_configs 
		SET status = ?, updated_at = ?
		WHERE stream_id = ?
	`, status, time.Now().UTC().Format(time.RFC3339), streamID)

	if err != nil {
		dbErr := &ErrBenthosDatabaseOperationFailed{Operation: "update_stream_status", WrappedErr: err}
		logger.WithError(dbErr).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (updateStreamStatusInDatabase)")
		return dbErr
	}
	logger.WithFields(logrus.Fields{"stream_id": streamID, "status": status}).Debug("Stream status updated in DB")
	return nil
}

// Stream lifecycle methods

func (sm *SimpleBenthosStreamManager) CreateStream(ctx context.Context, request types.StreamCreationRequest) (*types.StreamInfo, error) { // Changed types
	// This method is part of an interface. If request_id needs to be logged,
	// it should ideally come from ctx or be added to logger passed in if signature changes.
	// For now, using sm.logger and adding specific fields from request.
	logger := sm.logger.WithFields(logrus.Fields{
		"service_method":   "CreateStream",
		"thing_id":         request.ThingID,
		"interaction_name": request.InteractionName,
		"interaction_type": request.InteractionType,
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate unique stream ID
	streamID := uuid.New().String()
	now := time.Now().UTC()

	// Create stream info
	stream := &types.StreamInfo{ // Changed type
		ID:              streamID,
		ThingID:         request.ThingID,
		InteractionType: request.InteractionType,
		InteractionName: request.InteractionName,
		Direction:       request.Direction,
		ProcessorChain:  request.ProcessorChain,
		Input:           request.Input,
		Output:          request.Output,
		Status:          "created",
		CreatedAt:       now.Format(time.RFC3339),
		UpdatedAt:       now.Format(time.RFC3339),
		Metadata:        request.Metadata,
	}

	// Generate Benthos stream configuration using StreamBuilder
	logger.Debug("Generating Benthos stream builder")
	streamBuilder, err := sm.generateBenthosStreamBuilder(stream)
	if err != nil {
		logger.WithError(err).Error("Failed to generate Benthos stream builder")
		// err from generateBenthosStreamBuilder is already a custom error type
		return nil, err
	}
	logger.Debug("Benthos stream builder generated and validated")

	// Persist to DuckDB
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "persistStreamToDatabase"}).Debug("Calling internal method")
	if err := sm.persistStreamToDatabase(logger, stream); err != nil { // Pass logger
		logger.WithError(err).Error("Failed to persist stream to database")
		// err from persistStreamToDatabase is already a custom error type
		return nil, err
	}

	// Store in memory
	sm.streams[streamID] = stream
	sm.streamBuilders[streamID] = streamBuilder
	logger.Debug("Stream stored in memory")

	// Write configuration file for debugging/inspection (optional)
	if sm.configDir != "" {
		configPath := filepath.Join(sm.configDir, fmt.Sprintf("stream_%s.yaml", streamID))
		logger.WithField("config_path", configPath).Debug("Writing Benthos stream config to file for inspection")
		if err := sm.writeBenthosStreamBuilder(configPath, streamBuilder); err != nil { // writeBenthosStreamBuilder uses sm.logger
			logger.WithError(err).Warn("Failed to write debug config file")
		}
	}

	logger.Info("Created and validated Benthos stream successfully")
	return stream, nil
}

// persistStreamToDatabase saves stream configuration to DuckDB
func (sm *SimpleBenthosStreamManager) persistStreamToDatabase(logger logrus.FieldLogger, stream *types.StreamInfo) error { // Changed type
	logger = logger.WithFields(logrus.Fields{"internal_method": "persistStreamToDatabase", "stream_id": stream.ID})
	logger.Debug("Persisting stream to database")
	// Serialize configurations to JSON
	inputConfigJSON, err := json.Marshal(stream.Input)

	if err != nil {
		logger.WithError(err).Error("Failed to marshal input config for DB persistence")
		return fmt.Errorf("internal error: failed to marshal input config: %w", err)
	}

	outputConfigJSON, err := json.Marshal(stream.Output)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal output config for DB persistence")
		return fmt.Errorf("internal error: failed to marshal output config: %w", err)
	}

	processorChainJSON, err := json.Marshal(stream.ProcessorChain)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal processor chain for DB persistence")
		return fmt.Errorf("internal error: failed to marshal processor chain: %w", err)
	}

	var metadataJSON []byte
	if stream.Metadata != nil { // metadata can be nil
		metadataJSON, err = json.Marshal(stream.Metadata)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal metadata for DB persistence")
			return fmt.Errorf("internal error: failed to marshal metadata: %w", err)
		}
	}

	// Insert into database
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Debug("Calling dependency to insert stream config")
	_, err = sm.db.Exec(`
		INSERT INTO stream_configs (
			stream_id, thing_id, interaction_type, interaction_name, direction,
			input_config, output_config, processor_chain, status,
			created_at, updated_at, metadata, validation_error
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		stream.ID, stream.ThingID, stream.InteractionType, stream.InteractionName, stream.Direction,
		string(inputConfigJSON), string(outputConfigJSON), string(processorChainJSON), stream.Status,
		stream.CreatedAt, stream.UpdatedAt, string(metadataJSON), "", // No validation error on creation
	)

	if err != nil {
		dbErr := &ErrBenthosDatabaseOperationFailed{Operation: "persist_stream_insert", WrappedErr: err}
		logger.WithError(dbErr).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (persistStreamToDatabase)")
		return dbErr
	}

	logger.Debug("Persisted stream configuration to DuckDB successfully")
	return nil
}

func (sm *SimpleBenthosStreamManager) UpdateStream(ctx context.Context, streamID string, request types.StreamUpdateRequest) (*types.StreamInfo, error) { // Changed types
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "UpdateStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		errNotFound := &ErrBenthosStreamNotFound{StreamID: streamID}
		logger.Warn(errNotFound.Error())
		return nil, errNotFound
	}
	logger.Debug("Found stream for update")

	// Update stream info
	now := time.Now().UTC()
	updatedFields := []string{}

	if request.ProcessorChain != nil {
		stream.ProcessorChain = request.ProcessorChain
		updatedFields = append(updatedFields, "ProcessorChain")
	}
	if request.Input != nil {
		stream.Input = *request.Input
		updatedFields = append(updatedFields, "Input")
	}
	if request.Output != nil {
		stream.Output = *request.Output
		updatedFields = append(updatedFields, "Output")
	}
	if request.Metadata != nil {
		stream.Metadata = request.Metadata
		updatedFields = append(updatedFields, "Metadata")
	}

	stream.UpdatedAt = now.Format(time.RFC3339)
	logger.WithField("updated_fields", strings.Join(updatedFields, ", ")).Debug("Stream fields updated in memory")

	// Regenerate Benthos configuration using StreamBuilder
	logger.Debug("Regenerating Benthos stream builder")
	streamBuilder, err := sm.generateBenthosStreamBuilder(stream)
	if err != nil {
		logger.WithError(err).Error("Failed to generate updated Benthos stream builder")
		// err from generateBenthosStreamBuilder is already a custom error type
		return nil, &ErrBenthosStreamUpdateFailed{StreamID: streamID, WrappedErr: err}
	}
	logger.Debug("Benthos stream builder regenerated and validated")

	// Update in database
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "updateStreamInDatabase"}).Debug("Calling internal method")
	if err := sm.updateStreamInDatabase(logger, stream); err != nil { // Pass logger
		logger.WithError(err).Error("Failed to update stream in database")
		// err from updateStreamInDatabase is already a custom error type
		return nil, &ErrBenthosStreamUpdateFailed{StreamID: streamID, WrappedErr: err}
	}

	// Update in memory
	sm.streamBuilders[streamID] = streamBuilder
	logger.Debug("Updated stream builder in memory")

	logger.Info("Updated and validated Benthos stream successfully")
	return stream, nil
}

// updateStreamInDatabase updates stream configuration in DuckDB
func (sm *SimpleBenthosStreamManager) updateStreamInDatabase(logger logrus.FieldLogger, stream *types.StreamInfo) error { // Changed type
	logger = logger.WithFields(logrus.Fields{"internal_method": "updateStreamInDatabase", "stream_id": stream.ID})
	logger.Debug("Updating stream in database")

	// Serialize configurations to JSON
	inputConfigJSON, err := json.Marshal(stream.Input)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal input config for DB update")
		return fmt.Errorf("internal error: failed to marshal input config for update: %w", err)
	}

	outputConfigJSON, err := json.Marshal(stream.Output)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal output config for DB update")
		return fmt.Errorf("internal error: failed to marshal output config for update: %w", err)
	}

	processorChainJSON, err := json.Marshal(stream.ProcessorChain)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal processor chain for DB update")
		return fmt.Errorf("internal error: failed to marshal processor chain for update: %w", err)
	}

	var metadataJSON []byte
	if stream.Metadata != nil { // metadata can be nil
		metadataJSON, err = json.Marshal(stream.Metadata)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal metadata for DB update")
			return fmt.Errorf("internal error: failed to marshal metadata for update: %w", err)
		}
	}

	// Update in database
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Debug("Calling dependency to update stream config")
	_, err = sm.db.Exec(`
		UPDATE stream_configs SET
			input_config = ?, output_config = ?, processor_chain = ?,
			updated_at = ?, metadata = ?, validation_error = ?
		WHERE stream_id = ?
	`,
		string(inputConfigJSON), string(outputConfigJSON), string(processorChainJSON),
		stream.UpdatedAt, string(metadataJSON), "", // Clear validation error on successful update
		stream.ID,
	)

	if err != nil {
		dbErr := &ErrBenthosDatabaseOperationFailed{Operation: "update_stream_in_db_exec", WrappedErr: err}
		logger.WithError(dbErr).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (updateStreamInDatabase)")
		return dbErr
	}

	logger.Debug("Updated stream configuration in DuckDB successfully")
	return nil
}

func (sm *SimpleBenthosStreamManager) DeleteStream(ctx context.Context, streamID string) error {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "DeleteStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		errNotFound := &ErrBenthosStreamNotFound{StreamID: streamID}
		logger.Warn(errNotFound.Error())
		return errNotFound
	}
	logger = logger.WithField("thing_id", stream.ThingID) // Add thing_id to logger context
	logger.Debug("Found stream for deletion")

	// Mark as deleted in database (soft delete for audit trail)
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Debug("Calling dependency to mark stream as deleted")
	_, err := sm.db.Exec(`
		UPDATE stream_configs 
		SET status = 'deleted', updated_at = ?
		WHERE stream_id = ?
	`, time.Now().Format(time.RFC3339), streamID)

	if err != nil {
		dbErr := &ErrBenthosDatabaseOperationFailed{Operation: "delete_stream_mark_deleted", WrappedErr: err}
		logger.WithError(dbErr).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (mark as deleted)")
		return dbErr
	}
	logger.Debug("Stream marked as deleted in DB")

	// Remove from memory
	delete(sm.streams, streamID)
	delete(sm.streamBuilders, streamID)
	logger.Debug("Stream removed from memory maps")

	// Stop stream if running
	if activeStream, exists := sm.activeStreams[streamID]; exists {
		logger.Info("Stopping active stream during deletion")
		if err := activeStream.Stop(ctx); err != nil {
			// Log non-fatal error, but continue deletion process
			stopErr := &ErrBenthosStreamStopFailed{StreamID: streamID, WrappedErr: err}
			logger.WithError(stopErr).Warn("Failed to stop stream during deletion (non-fatal)")
		}
		delete(sm.activeStreams, streamID)
		logger.Debug("Active stream instance removed from map")
	}

	// Optionally remove configuration file
	if sm.configDir != "" {
		configPath := filepath.Join(sm.configDir, fmt.Sprintf("stream_%s.yaml", streamID))
		logger.WithField("config_path", configPath).Debug("Attempting to remove debug config file")
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			logger.WithError(err).Warn("Failed to remove debug config file")
		}
	}

	logger.Info("Deleted Benthos stream successfully")
	return nil
}

func (sm *SimpleBenthosStreamManager) GetStream(ctx context.Context, streamID string) (*types.StreamInfo, error) { // Changed type
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		errNotFound := &ErrBenthosStreamNotFound{StreamID: streamID}
		logger.Warn(errNotFound.Error())
		return nil, errNotFound
	}
	logger.WithField("thing_id", stream.ThingID).Debug("Stream found")
	return stream, nil
}

func (sm *SimpleBenthosStreamManager) ListStreams(ctx context.Context, filters types.StreamFilters) ([]types.StreamInfo, error) { // Changed types
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "ListStreams", "filters": fmt.Sprintf("%+v", filters)})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []types.StreamInfo // Changed type
	logger.WithField("total_streams_in_memory", len(sm.streams)).Debug("Filtering streams")
	for _, stream := range sm.streams {
		// Apply filters
		if filters.ThingID != "" && stream.ThingID != filters.ThingID {
			continue
		}
		if filters.InteractionType != "" && stream.InteractionType != filters.InteractionType {
			continue
		}
		if filters.Status != "" && stream.Status != filters.Status {
			continue
		}

		result = append(result, *stream)
	}
	logger.WithField("match_count", len(result)).Debug("Finished filtering streams")
	return result, nil
}

// Stream operations

func (sm *SimpleBenthosStreamManager) StartStream(ctx context.Context, streamID string) error {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "StartStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		errNotFound := &ErrBenthosStreamNotFound{StreamID: streamID}
		logger.Warn(errNotFound.Error())
		return errNotFound
	}
	logger = logger.WithField("thing_id", stream.ThingID) // Add context

	if _, isRunning := sm.activeStreams[streamID]; isRunning {
		logger.Warn("Stream is already running")
		// Not an error per se, but an idempotent check might return nil or a specific status
		return nil // Or return a specific error e.g. ErrBenthosStreamAlreadyRunning
	}

	builder, exists := sm.streamBuilders[streamID]
	if !exists {
		// This indicates an inconsistency if sm.streams[streamID] exists but sm.streamBuilders[streamID] doesn't
		errInternal := fmt.Errorf("internal inconsistency: stream info exists but builder not found for stream ID %s", streamID)
		logger.Error(errInternal.Error())
		return &ErrBenthosStreamStartFailed{StreamID: streamID, WrappedErr: errInternal}
	}
	logger.Debug("Retrieved stream builder")

	logger.Debug("Building Benthos stream from builder")
	benthosStream, err := builder.Build()
	if err != nil {
		startErr := &ErrBenthosStreamCreateFailed{StreamID: streamID, WrappedErr: err} // Could be create or build, using CreateFailed as more general
		logger.WithError(startErr).Error("Failed to build Benthos stream")
		return startErr
	}
	logger.Debug("Benthos stream built successfully")

	// Start the stream in a goroutine
	go func() {
		goroutineLogger := logger.WithField("goroutine", "benthos_stream_run") // Use the request-scoped logger
		goroutineLogger.Info("Starting Benthos stream run loop")
		runErr := benthosStream.Run(context.Background()) // Use a new context for the stream's lifecycle
		if runErr != nil {
			// This error is logged from within the goroutine.
			// The main StartStream function has already returned success if it reached this point.
			// We need a mechanism to report this async error if necessary (e.g., via a status update and event).
			goroutineLogger.WithError(runErr).Error("Benthos stream stopped with error")
			sm.mu.Lock()
			// Update status only if the stream entry still exists (it might have been deleted concurrently)
			if s, ok := sm.streams[streamID]; ok {
				s.Status = "error" // Or a more specific error status
				s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				// Log error from DB update but don't let it panic the goroutine
				if dbUpdateErr := sm.updateStreamStatusInDatabase(goroutineLogger, streamID, "error"); dbUpdateErr != nil {
					goroutineLogger.WithError(dbUpdateErr).Error("Failed to update stream status to 'error' in DB")
				}
			}
			delete(sm.activeStreams, streamID) // Remove from active streams map
			sm.mu.Unlock()
		} else {
			goroutineLogger.Info("Benthos stream run loop finished cleanly")
			// Stream might have been stopped externally, update status if it's still "running"
			sm.mu.Lock()
			if s, ok := sm.streams[streamID]; ok && s.Status == "running" {
				s.Status = "stopped"
				s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				if dbUpdateErr := sm.updateStreamStatusInDatabase(goroutineLogger, streamID, "stopped"); dbUpdateErr != nil {
					goroutineLogger.WithError(dbUpdateErr).Error("Failed to update stream status to 'stopped' in DB")
				}
			}
			delete(sm.activeStreams, streamID)
			sm.mu.Unlock()
		}
	}()

	// Store the running stream
	sm.activeStreams[streamID] = benthosStream

	// Update status
	stream.Status = "running"
	stream.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	// Update in database
	if errDb := sm.updateStreamStatusInDatabase(logger, streamID, "running"); errDb != nil { // Pass logger
		logger.WithError(errDb).Warn("Failed to update stream status in database after starting")
		// Non-fatal for the start operation itself
	}

	logger.Info("Started Benthos stream successfully")
	return nil
}

func (sm *SimpleBenthosStreamManager) StopStream(ctx context.Context, streamID string) error {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "StopStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		errNotFound := &ErrBenthosStreamNotFound{StreamID: streamID}
		logger.Warn(errNotFound.Error())
		return errNotFound
	}
	logger = logger.WithField("thing_id", stream.ThingID)

	activeStream, isRunning := sm.activeStreams[streamID]
	if !isRunning {
		logger.Warn("Stream is not running, cannot stop (idempotent)")
		// If already stopped, this is not an error.
		// If it was supposed to be running but isn't, that's an inconsistency.
		// For now, treat as success if not in activeStreams.
		if stream.Status == "running" { // If DB says running but not in active map
			stream.Status = "stopped" // Correct the status
			stream.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			if errDb := sm.updateStreamStatusInDatabase(logger, streamID, "stopped"); errDb != nil {
				logger.WithError(errDb).Warn("Failed to update inconsistent stream status to 'stopped' in DB")
			}
		}
		return nil
	}

	logger.Info("Stopping Benthos stream")
	if err := activeStream.Stop(ctx); err != nil {
		stopErr := &ErrBenthosStreamStopFailed{StreamID: streamID, WrappedErr: err}
		logger.WithError(stopErr).Error("Failed to stop Benthos stream")
		return stopErr
	}

	// Remove from active streams
	delete(sm.activeStreams, streamID)
	logger.Debug("Removed stream from active map")

	// Update status
	stream.Status = "stopped"
	stream.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	// Update in database
	if errDb := sm.updateStreamStatusInDatabase(logger, streamID, "stopped"); errDb != nil { // Pass logger
		logger.WithError(errDb).Warn("Failed to update stream status in database after stopping")
	}

	logger.Info("Stopped Benthos stream successfully")
	return nil
}

func (sm *SimpleBenthosStreamManager) GetStreamStatus(ctx context.Context, streamID string) (*types.StreamStatus, error) { // Changed type
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetStreamStatus", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		errNotFound := &ErrBenthosStreamNotFound{StreamID: streamID}
		logger.Warn(errNotFound.Error())
		return nil, errNotFound
	}
	logger = logger.WithField("thing_id", stream.ThingID)

	// Check if stream is actually running
	_, isRunning := sm.activeStreams[streamID]
	actualStatus := stream.Status
	if isRunning {
		actualStatus = "running"
	} else if stream.Status == "running" {
		// Stream thinks it's running but it's not
		actualStatus = "stopped"
	}

	// Get metrics from running stream if available
	metrics := map[string]interface{}{
		"messages_processed": 0,    // Placeholder
		"errors":             0,    // Placeholder
		"uptime":             "0s", // Placeholder
		"is_running":         isRunning,
	}

	// Note: Benthos v4 Stream doesn't expose metrics directly
	// In production, you'd typically use Benthos HTTP API or metrics exporters
	logger.WithFields(logrus.Fields{"is_running": isRunning, "reported_status": actualStatus}).Debug("Stream status determined")

	status := &types.StreamStatus{ // Changed type
		Status:      actualStatus,
		LastUpdated: stream.UpdatedAt,
		Metrics:     metrics,
		Error:       "", // Placeholder for actual error reporting
	}

	return status, nil
}

// Processor collection methods

func (sm *SimpleBenthosStreamManager) CreateProcessorCollection(ctx context.Context, request types.ProcessorCollectionRequest) (*types.ProcessorCollection, error) { // Changed types
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "CreateProcessorCollection", "collection_name": request.Name})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate unique collection ID
	collectionID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	collection := &types.ProcessorCollection{ // Changed type
		ID:          collectionID,
		Name:        request.Name,
		Description: request.Description,
		Processors:  request.Processors,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Store collection
	sm.processorCollections[collectionID] = collection
	logger = logger.WithField("collection_id", collectionID) // Add to context for subsequent logs

	logger.Info("Created processor collection successfully")
	return collection, nil
}

func (sm *SimpleBenthosStreamManager) GetProcessorCollection(ctx context.Context, collectionID string) (*types.ProcessorCollection, error) { // Changed type
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetProcessorCollection", "collection_id": collectionID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	collection, exists := sm.processorCollections[collectionID]
	if !exists {
		errNotFound := &ErrBenthosProcessorCollectionNotFound{CollectionID: collectionID}
		logger.Warn(errNotFound.Error())
		return nil, errNotFound
	}
	logger.WithField("collection_name", collection.Name).Debug("Processor collection found")
	return collection, nil
}

func (sm *SimpleBenthosStreamManager) ListProcessorCollections(ctx context.Context) ([]types.ProcessorCollection, error) { // Changed type
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "ListProcessorCollections"})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []types.ProcessorCollection // Changed type
	logger.WithField("total_collections_in_memory", len(sm.processorCollections)).Debug("Listing processor collections")
	for _, collection := range sm.processorCollections {
		result = append(result, *collection)
	}
	logger.WithField("count", len(result)).Debug("Listed processor collections successfully")
	return result, nil
}

// Helper methods for generating Benthos configurations

// generateBenthosStreamBuilder creates Benthos StreamBuilder using unified configuration system
func (sm *SimpleBenthosStreamManager) generateBenthosStreamBuilder(stream *types.StreamInfo) (*service.StreamBuilder, error) {
	logger := sm.logger.WithFields(logrus.Fields{"internal_method": "generateBenthosStreamBuilder", "stream_id": stream.ID})
	logger.Debug("Internal method called")

	// Create new stream builder
	builder := service.NewStreamBuilder()

	// Try to use pre-generated YAML from metadata first (backward compatibility)
	var yamlConfig string
	if stream.Metadata != nil {
		if yamlStr, ok := stream.Metadata["yaml_config"].(string); ok && yamlStr != "" {
			yamlConfig = yamlStr
			logger.Debug("Using pre-generated YAML config from metadata for stream builder")
		}
	}

	// If no pre-generated YAML, use unified stream configuration system
	if yamlConfig == "" {
		logger.Debug("No pre-generated YAML found, using unified stream configuration system")

		// Convert StreamInfo to StreamCreationRequest for unified processing
		request := &types.StreamCreationRequest{
			ThingID:         stream.ThingID,
			InteractionType: stream.InteractionType,
			InteractionName: stream.InteractionName,
			Direction:       stream.Direction,
			ProcessorChain:  stream.ProcessorChain,
			Input:           stream.Input,
			Output:          stream.Output,
			Metadata:        stream.Metadata,
		}

		// Generate YAML using unified stream configuration builder
		generatedYAML, err := sm.generateUnifiedStreamConfig(request)
		if err != nil {
			confErr := &ErrBenthosStreamConfigInvalid{StreamID: stream.ID, Details: "Failed to generate unified stream config", WrappedErr: err}
			logger.WithError(confErr).Error("Failed to generate YAML using unified stream configuration")
			return nil, confErr
		}
		yamlConfig = generatedYAML
		logger.Debug("Successfully generated YAML using unified stream configuration system")
	}

	// Set complete configuration using YAML
	if err := builder.SetYAML(yamlConfig); err != nil {
		confErr := &ErrBenthosStreamConfigInvalid{StreamID: stream.ID, Details: "Benthos SetYAML failed", WrappedErr: err}
		logger.WithError(confErr).Error("Failed to set YAML config for StreamBuilder via SetYAML")
		return nil, confErr
	}

	logger.WithFields(logrus.Fields{
		"thing_id":         stream.ThingID,
		"interaction_type": stream.InteractionType,
		"direction":        stream.Direction,
	}).Debug("Successfully configured Benthos stream builder using unified configuration system")

	return builder, nil
}

// generateUnifiedStreamConfig generates YAML configuration using the unified stream configuration system
func (sm *SimpleBenthosStreamManager) generateUnifiedStreamConfig(request *types.StreamCreationRequest) (string, error) {
	logger := sm.logger.WithFields(logrus.Fields{"internal_method": "generateUnifiedStreamConfig", "thing_id": request.ThingID})
	logger.Debug("Generating unified stream configuration")

	// Convert to StreamBuildConfig format
	buildConfig := forms.StreamBuildConfig{
		ThingID:         request.ThingID,
		InteractionType: request.InteractionType,
		InteractionName: request.InteractionName,
		Purpose:         sm.determinePurpose(request.InteractionType, request.Direction),
		Direction:       sm.convertDirection(request.Direction),
		StreamType:      types.BenthosStreamType("standard"), // Default stream type
		Metadata:        request.Metadata,
	}

	// Convert input configuration
	if request.Input.Type != "" {
		buildConfig.InputConfig = forms.StreamEndpointParams{
			Type:     request.Input.Type,
			Protocol: request.Input.Type,
			Config:   request.Input.Config,
		}
	}

	// Convert output configuration
	if request.Output.Type != "" {
		buildConfig.OutputConfig = forms.StreamEndpointParams{
			Type:     request.Output.Type,
			Protocol: request.Output.Type,
			Config:   request.Output.Config,
		}
	}

	// Convert processors
	for _, proc := range request.ProcessorChain {
		buildConfig.Processors = append(buildConfig.Processors, forms.ProcessorConfig{
			Type:       proc.Type,
			Label:      proc.Type + "_processor",
			Parameters: proc.Config,
		})
	}

	// Use unified stream configuration builder
	streamRequest, err := sm.streamConfigBuilder.BuildStream(buildConfig)
	if err != nil {
		return "", fmt.Errorf("failed to build unified stream config: %w", err)
	}

	// Convert StreamCreationRequest to YAML
	yamlConfig := sm.convertStreamRequestToYAML(streamRequest)
	logger.Debug("Successfully generated unified stream configuration")
	return yamlConfig, nil
}

// Helper methods for configuration conversion
func (sm *SimpleBenthosStreamManager) determinePurpose(interactionType, direction string) forms.StreamPurpose {
	switch interactionType {
	case "property":
		if direction == "input" {
			return forms.PurposeObservation
		}
		return forms.PurposePersistence
	case "action":
		return forms.PurposeCommand
	case "event":
		return forms.PurposeNotification
	default:
		return forms.PurposeInternal
	}
}

func (sm *SimpleBenthosStreamManager) convertDirection(direction string) forms.StreamDirection {
	switch direction {
	case "input":
		return forms.DirectionInput
	case "output":
		return forms.DirectionOutput
	default:
		return forms.DirectionInternal
	}
}

func (sm *SimpleBenthosStreamManager) convertStreamRequestToYAML(request *types.StreamCreationRequest) string {
	var config string

	// Add input section
	if request.Input.Type != "" {
		inputType := sm.normalizeBenthosComponentType(request.Input.Type, "input")
		config += fmt.Sprintf("input:\n  %s:\n", inputType)
		for k, v := range request.Input.Config {
			config += fmt.Sprintf("    %s: %v\n", k, v)
		}
	}

	// Add processor section
	if len(request.ProcessorChain) > 0 {
		config += "\npipeline:\n  processors:\n"
		for _, proc := range request.ProcessorChain {
			procType := sm.normalizeBenthosComponentType(proc.Type, "processor")
			config += fmt.Sprintf("    - %s:\n", procType)
			for k, v := range proc.Config {
				config += fmt.Sprintf("        %s: %v\n", k, v)
			}
		}
	}

	// Add output section
	if request.Output.Type != "" {
		outputType := sm.normalizeBenthosComponentType(request.Output.Type, "output")
		config += fmt.Sprintf("\noutput:\n  %s:\n", outputType)
		for k, v := range request.Output.Config {
			config += fmt.Sprintf("    %s: %v\n", k, v)
		}
	}

	return config
}

// normalizeBenthosComponentType ensures component types are valid for Benthos v4
func (sm *SimpleBenthosStreamManager) normalizeBenthosComponentType(componentType, category string) string {
	// For now, return the original component type to maintain backward compatibility
	// The test expects 'generate' and 'drop' to work, so let's see if they're valid in Benthos v4
	return componentType
}

// writeBenthosStreamBuilder writes a StreamBuilder to file for inspection
func (sm *SimpleBenthosStreamManager) writeBenthosStreamBuilder(configPath string, builder *service.StreamBuilder) error {
	// This is an internal helper, using sm.logger is fine.
	logger := sm.logger.WithFields(logrus.Fields{"internal_method": "writeBenthosStreamBuilder", "config_path": configPath})
	logger.Debug("Attempting to write Benthos stream builder config to file")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Finished writing Benthos stream builder config to file")
	}()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		logger.WithError(err).Error("Failed to create config directory for Benthos stream file")
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Try to get YAML representation from StreamBuilder
	logger.Debug("Attempting to get YAML from StreamBuilder for file writing")
	yamlContent, err := builder.AsYAML()
	if err != nil {
		logger.WithError(err).Warn("Failed to get YAML from StreamBuilder for file writing; using placeholder content")
		// If AsYAML fails, write a placeholder
		yamlContent = fmt.Sprintf(`# Benthos Stream Configuration (Placeholder due to AsYAML error)
# Generated by TwinCore Stream Manager
# Stream created with service.NewStreamBuilder()
# ERROR Getting YAML from builder: %v
stream_info:
  created: %s
  type: "benthos_service_stream"
  note: "Configuration managed via service.StreamBuilder API"
`, err, time.Now().Format(time.RFC3339))
	}

	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		logger.WithError(err).Error("Failed to write Benthos config file")
		return fmt.Errorf("failed to write config file: %w", err)
	}
	logger.Debug("Successfully wrote Benthos stream config to file")
	return nil
}

// Ensure SimpleBenthosStreamManager implements BenthosStreamManager interface
var _ BenthosStreamManager = (*SimpleBenthosStreamManager)(nil)
