package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
)

// SimpleBenthosStreamManager implements BenthosStreamManager for dynamic stream management
// This implementation uses DuckDB for persistent stream configuration storage
type SimpleBenthosStreamManager struct {
	configDir            string
	db                   *sql.DB
	streams              map[string]*StreamInfo
	streamBuilders       map[string]*service.StreamBuilder
	activeStreams        map[string]*service.Stream
	processorCollections map[string]*ProcessorCollection
	// templateFactory removed - using direct YAML generation now
	logger logrus.FieldLogger
	mu     sync.RWMutex
}

// NewSimpleBenthosStreamManager creates a new simple Benthos stream manager with DuckDB persistence
func NewSimpleBenthosStreamManager(configDir string, db *sql.DB, logger logrus.FieldLogger) (*SimpleBenthosStreamManager, error) {
	logger.Debug("Creating NewSimpleBenthosStreamManager")
	// Template factory removed - using centralized binding generation

	sm := &SimpleBenthosStreamManager{
		configDir:            configDir,
		db:                   db,
		streams:              make(map[string]*StreamInfo),
		streamBuilders:       make(map[string]*service.StreamBuilder),
		activeStreams:        make(map[string]*service.Stream),
		processorCollections: make(map[string]*ProcessorCollection),
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
		return fmt.Errorf("failed to create stream_configs table: %w", err)
	}

	sm.logger.Info("Initialized DuckDB schema for stream configuration persistence")
	return nil
}

// loadStreamsFromDatabase loads and validates all stored stream configurations at startup
func (sm *SimpleBenthosStreamManager) loadStreamsFromDatabase() error {
	logger := sm.logger.WithFields(logrus.Fields{"internal_method": "loadStreamsFromDatabase"})
	logger.Debug("Loading stream configurations from database")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Finished loading streams from database") }()

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
		return fmt.Errorf("failed to query stream configs: %w", err)
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
		var inputConfig StreamEndpointConfig
		if err := json.Unmarshal([]byte(inputConfigJSON), &inputConfig); err != nil {
			logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal input config")
			errorCount++
			continue
		}

		var outputConfig StreamEndpointConfig
		if err := json.Unmarshal([]byte(outputConfigJSON), &outputConfig); err != nil {
			logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal output config")
			errorCount++
			continue
		}

		var processorChain []ProcessorConfig
		if err := json.Unmarshal([]byte(processorChainJSON), &processorChain); err != nil {
			logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal processor chain")
			errorCount++
			continue
		}

		var metadata map[string]interface{}
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
				logger.WithError(err).WithField("stream_id", streamID).Warn("Failed to unmarshal metadata, using empty")
				metadata = make(map[string]interface{})
			}
		}

		// Create StreamInfo
		streamInfo := &StreamInfo{
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
		benthosConfig, err := sm.generateBenthosStreamBuilder(streamInfo) // generateBenthosStreamBuilder uses sm.logger
		if err != nil {
			logger.WithError(err).WithField("stream_id", streamID).Error("Failed to generate Benthos config during startup")
			sm.updateValidationError(logger, streamID, err.Error()) // Pass logger
			errorCount++
			continue
		}

		// Note: StreamBuilder doesn't have a Lint() method - validation happens during SetYAML()
		// If we reach here, the configuration is already validated

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
		return fmt.Errorf("error iterating stream config rows: %w", err)
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
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (updateStreamStatusInDatabase)")
		return fmt.Errorf("failed to update stream status in database: %w", err)
	}
	logger.WithFields(logrus.Fields{"stream_id": streamID, "status": status}).Debug("Stream status updated in DB")
	return nil
}

// Stream lifecycle methods

func (sm *SimpleBenthosStreamManager) CreateStream(ctx context.Context, request StreamCreationRequest) (*StreamInfo, error) {
	// This method is part of an interface. If request_id needs to be logged,
	// it should ideally come from ctx or be added to logger passed in if signature changes.
	// For now, using sm.logger and adding specific fields from request.
	logger := sm.logger.WithFields(logrus.Fields{
		"service_method":   "CreateStream",
		"stream_id_req":    request.ID, // This might be empty if not set by caller
		"thing_id":         request.ThingID,
		"interaction_name": request.InteractionName,
		"interaction_type": request.InteractionType,
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate unique stream ID
	streamID := uuid.New().String()
	now := time.Now().UTC()

	// Create stream info
	stream := &StreamInfo{
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
	streamBuilder, err := sm.generateBenthosStreamBuilder(stream) // Uses sm.logger internally
	if err != nil {
		logger.WithError(err).Error("Failed to generate Benthos stream builder")
		return nil, fmt.Errorf("failed to generate Benthos stream builder: %w", err)
	}

	// StreamBuilder validates configuration during SetYAML() call
	logger.Debug("Benthos stream builder generated and validated")

	// Persist to DuckDB
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "persistStreamToDatabase"}).Debug("Calling internal method")
	if err := sm.persistStreamToDatabase(logger, stream); err != nil { // Pass logger
		logger.WithError(err).Error("Failed to persist stream to database")
		return nil, fmt.Errorf("failed to persist stream to database: %w", err)
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
func (sm *SimpleBenthosStreamManager) persistStreamToDatabase(logger logrus.FieldLogger, stream *StreamInfo) error {
	logger = logger.WithFields(logrus.Fields{"internal_method": "persistStreamToDatabase", "stream_id": stream.ID})
	logger.Debug("Persisting stream to database")
	// Serialize configurations to JSON
	inputConfigJSON, err := json.Marshal(stream.Input)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal input config")
		return fmt.Errorf("failed to marshal input config: %w", err)
	}

	outputConfigJSON, err := json.Marshal(stream.Output)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal output config")
		return fmt.Errorf("failed to marshal output config: %w", err)
	}

	processorChainJSON, err := json.Marshal(stream.ProcessorChain)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal processor chain")
		return fmt.Errorf("failed to marshal processor chain: %w", err)
	}

	var metadataJSON []byte
	if stream.Metadata != nil {
		metadataJSON, err = json.Marshal(stream.Metadata)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal metadata")
			return fmt.Errorf("failed to marshal metadata: %w", err)
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
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (persistStreamToDatabase)")
		return fmt.Errorf("failed to insert stream config into database: %w", err)
	}

	logger.Debug("Persisted stream configuration to DuckDB successfully")
	return nil
}

func (sm *SimpleBenthosStreamManager) UpdateStream(ctx context.Context, streamID string, request StreamUpdateRequest) (*StreamInfo, error) {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "UpdateStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		logger.Warn("Stream not found for update")
		return nil, fmt.Errorf("stream not found: %s", streamID)
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
	streamBuilder, err := sm.generateBenthosStreamBuilder(stream) // Uses sm.logger
	if err != nil {
		logger.WithError(err).Error("Failed to generate updated Benthos stream builder")
		return nil, fmt.Errorf("failed to generate updated Benthos stream builder: %w", err)
	}
	logger.Debug("Benthos stream builder regenerated and validated")

	// Update in database
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "updateStreamInDatabase"}).Debug("Calling internal method")
	if err := sm.updateStreamInDatabase(logger, stream); err != nil { // Pass logger
		logger.WithError(err).Error("Failed to update stream in database")
		return nil, fmt.Errorf("failed to update stream in database: %w", err)
	}

	// Update in memory
	sm.streamBuilders[streamID] = streamBuilder
	logger.Debug("Updated stream builder in memory")

	logger.Info("Updated and validated Benthos stream successfully")
	return stream, nil
}

// updateStreamInDatabase updates stream configuration in DuckDB
func (sm *SimpleBenthosStreamManager) updateStreamInDatabase(logger logrus.FieldLogger, stream *StreamInfo) error {
	logger = logger.WithFields(logrus.Fields{"internal_method": "updateStreamInDatabase", "stream_id": stream.ID})
	logger.Debug("Updating stream in database")

	// Serialize configurations to JSON
	inputConfigJSON, err := json.Marshal(stream.Input)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal input config for DB update")
		return fmt.Errorf("failed to marshal input config: %w", err)
	}

	outputConfigJSON, err := json.Marshal(stream.Output)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal output config for DB update")
		return fmt.Errorf("failed to marshal output config: %w", err)
	}

	processorChainJSON, err := json.Marshal(stream.ProcessorChain)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal processor chain for DB update")
		return fmt.Errorf("failed to marshal processor chain: %w", err)
	}

	var metadataJSON []byte
	if stream.Metadata != nil {
		metadataJSON, err = json.Marshal(stream.Metadata)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal metadata for DB update")
			return fmt.Errorf("failed to marshal metadata: %w", err)
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
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (updateStreamInDatabase)")
		return fmt.Errorf("failed to update stream config in database: %w", err)
	}

	logger.Debug("Updated stream configuration in DuckDB successfully")
	return nil
}

func (sm *SimpleBenthosStreamManager) DeleteStream(ctx context.Context, streamID string) error {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "DeleteStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		logger.Warn("Stream not found for deletion")
		return fmt.Errorf("stream not found: %s", streamID)
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
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed (mark as deleted)")
		return fmt.Errorf("failed to mark stream as deleted in database: %w", err)
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
			logger.WithError(err).Warn("Failed to stop stream during deletion (non-fatal)")
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

func (sm *SimpleBenthosStreamManager) GetStream(ctx context.Context, streamID string) (*StreamInfo, error) {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetStream", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		logger.Warn("Stream not found")
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}
	logger.WithField("thing_id", stream.ThingID).Debug("Stream found")
	return stream, nil
}

func (sm *SimpleBenthosStreamManager) ListStreams(ctx context.Context, filters StreamFilters) ([]StreamInfo, error) {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "ListStreams", "filters": fmt.Sprintf("%+v", filters)})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []StreamInfo
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
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		logger.Warn("Stream not found to start")
		return fmt.Errorf("stream not found: %s", streamID)
	}
	logger = logger.WithField("thing_id", stream.ThingID) // Add context

	// Check if stream is already running
	if _, isRunning := sm.activeStreams[streamID]; isRunning {
		logger.Warn("Stream is already running")
		return fmt.Errorf("stream %s is already running", streamID)
	}

	// Get the stream builder
	builder, exists := sm.streamBuilders[streamID]
	if !exists {
		logger.Error("Stream builder not found for stream")
		return fmt.Errorf("stream builder not found for stream: %s", streamID)
	}
	logger.Debug("Retrieved stream builder")

	// Build the stream
	logger.Debug("Building Benthos stream from builder")
	benthosStream, err := builder.Build()
	if err != nil {
		logger.WithError(err).Error("Failed to build Benthos stream")
		return fmt.Errorf("failed to build Benthos stream: %w", err)
	}
	logger.Debug("Benthos stream built successfully")

	// Start the stream in a goroutine
	go func() {
		goroutineLogger := logger.WithField("goroutine", "benthos_stream_run")
		goroutineLogger.Info("Starting Benthos stream run loop")
		if err := benthosStream.Run(context.Background()); err != nil {
			goroutineLogger.WithError(err).Error("Benthos stream stopped with error")
			// Update status to stopped
			sm.mu.Lock()
			if s, ok := sm.streams[streamID]; ok {
				s.Status = "stopped"
				s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				sm.updateStreamStatusInDatabase(goroutineLogger, streamID, "stopped") // Pass logger
			}
			delete(sm.activeStreams, streamID)
			sm.mu.Unlock()
		} else {
			goroutineLogger.Info("Benthos stream run loop finished cleanly")
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
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		logger.Warn("Stream not found to stop")
		return fmt.Errorf("stream not found: %s", streamID)
	}
	logger = logger.WithField("thing_id", stream.ThingID)

	// Check if stream is running
	activeStream, isRunning := sm.activeStreams[streamID]
	if !isRunning {
		logger.Warn("Stream is not running, cannot stop")
		return fmt.Errorf("stream %s is not running", streamID)
	}

	// Stop the stream
	logger.Info("Stopping Benthos stream")
	if err := activeStream.Stop(ctx); err != nil {
		logger.WithError(err).Error("Failed to stop Benthos stream")
		return fmt.Errorf("failed to stop Benthos stream: %w", err)
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

func (sm *SimpleBenthosStreamManager) GetStreamStatus(ctx context.Context, streamID string) (*StreamStatus, error) {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetStreamStatus", "stream_id": streamID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		logger.Warn("Stream not found for status check")
		return nil, fmt.Errorf("stream not found: %s", streamID)
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
		"messages_processed": 0, // Placeholder
		"errors":             0, // Placeholder
		"uptime":             "0s", // Placeholder
		"is_running":         isRunning,
	}

	// Note: Benthos v4 Stream doesn't expose metrics directly
	// In production, you'd typically use Benthos HTTP API or metrics exporters
	logger.WithFields(logrus.Fields{"is_running": isRunning, "reported_status": actualStatus}).Debug("Stream status determined")

	status := &StreamStatus{
		Status:       actualStatus,
		LastActivity: stream.UpdatedAt,
		Metrics:      metrics,
		Errors:       []string{}, // Placeholder for actual error reporting
	}

	return status, nil
}

// Processor collection methods

func (sm *SimpleBenthosStreamManager) CreateProcessorCollection(ctx context.Context, request ProcessorCollectionRequest) (*ProcessorCollection, error) {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "CreateProcessorCollection", "collection_name": request.Name})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate unique collection ID
	collectionID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	collection := &ProcessorCollection{
		ID:          collectionID,
		Name:        request.Name,
		Description: request.Description,
		Processors:  request.Processors,
		CreatedAt:   now,
		UpdatedAt:   now,
		Metadata:    request.Metadata,
	}

	// Store collection
	sm.processorCollections[collectionID] = collection
	logger = logger.WithField("collection_id", collectionID) // Add to context for subsequent logs

	logger.Info("Created processor collection successfully")
	return collection, nil
}

func (sm *SimpleBenthosStreamManager) GetProcessorCollection(ctx context.Context, collectionID string) (*ProcessorCollection, error) {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "GetProcessorCollection", "collection_id": collectionID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	collection, exists := sm.processorCollections[collectionID]
	if !exists {
		logger.Warn("Processor collection not found")
		return nil, fmt.Errorf("processor collection not found: %s", collectionID)
	}
	logger.WithField("collection_name", collection.Name).Debug("Processor collection found")
	return collection, nil
}

func (sm *SimpleBenthosStreamManager) ListProcessorCollections(ctx context.Context) ([]ProcessorCollection, error) {
	logger := sm.logger.WithFields(logrus.Fields{"service_method": "ListProcessorCollections"})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []ProcessorCollection
	logger.WithField("total_collections_in_memory", len(sm.processorCollections)).Debug("Listing processor collections")
	for _, collection := range sm.processorCollections {
		result = append(result, *collection)
	}
	logger.WithField("count", len(result)).Debug("Listed processor collections successfully")
	return result, nil
}

// Helper methods for generating Benthos configurations

// generateBenthosStreamBuilder creates Benthos StreamBuilder using service API
func (sm *SimpleBenthosStreamManager) generateBenthosStreamBuilder(stream *StreamInfo) (*service.StreamBuilder, error) {
	// Using sm.logger as this is an internal helper. Contextual info like stream.ID is logged.
	logger := sm.logger.WithFields(logrus.Fields{"internal_method": "generateBenthosStreamBuilder", "stream_id": stream.ID})
	logger.Debug("Internal method called")

	// Create new stream builder
	builder := service.NewStreamBuilder()

	// Check if YAML configuration is provided in metadata
	var yamlConfig string
	if stream.Metadata != nil {
		if yamlStr, ok := stream.Metadata["yaml_config"].(string); ok && yamlStr != "" {
			yamlConfig = yamlStr
			logger.Debug("Using YAML config from metadata for stream builder")
		} else {
			logger.Warn("yaml_config field missing or empty in stream metadata for stream_builder")
		}
	} else {
		logger.Warn("Stream metadata is nil, cannot retrieve yaml_config for stream_builder")
	}

	if yamlConfig == "" { // Check if yamlConfig is still empty
	    logger.Error("No YAML configuration provided to StreamBuilder after checking metadata")
	    return nil, fmt.Errorf("no YAML configuration available for stream %s to build StreamBuilder", stream.ID)
	}

	// Set complete configuration using YAML
	if err := builder.SetYAML(yamlConfig); err != nil {
		logger.WithError(err).Error("Failed to set YAML config for StreamBuilder via SetYAML")
		return nil, fmt.Errorf("failed to set YAML config for StreamBuilder: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"thing_id":         stream.ThingID,
		"interaction_type": stream.InteractionType,
		"direction":        stream.Direction,
	}).Debug("Successfully configured Benthos stream builder using service API with YAML from metadata")

	return builder, nil
}

// writeBenthosStreamBuilder writes a StreamBuilder to file for inspection
func (sm *SimpleBenthosStreamManager) writeBenthosStreamBuilder(configPath string, builder *service.StreamBuilder) error {
	// This is an internal helper, using sm.logger is fine.
	logger := sm.logger.WithFields(logrus.Fields{"internal_method": "writeBenthosStreamBuilder", "config_path": configPath})
	logger.Debug("Attempting to write Benthos stream builder config to file")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Finished writing Benthos stream builder config to file") }()


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
