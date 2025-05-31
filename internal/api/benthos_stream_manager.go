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
	if err := sm.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Load existing stream configurations from database
	if err := sm.loadStreamsFromDatabase(); err != nil {
		return nil, fmt.Errorf("failed to load streams from database: %w", err)
	}

	return sm, nil
}

// initializeSchema creates the necessary tables for stream persistence
func (sm *SimpleBenthosStreamManager) initializeSchema() error {
	// Create stream_configs table for persisting stream configurations
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
		return fmt.Errorf("failed to create stream_configs table: %w", err)
	}

	sm.logger.Info("Initialized DuckDB schema for stream configuration persistence")
	return nil
}

// loadStreamsFromDatabase loads and validates all stored stream configurations at startup
func (sm *SimpleBenthosStreamManager) loadStreamsFromDatabase() error {
	query := `
		SELECT stream_id, thing_id, interaction_type, interaction_name, direction,
		       input_config, output_config, processor_chain, status,
		       created_at, updated_at, metadata
		FROM stream_configs
		WHERE status != 'deleted'
	`

	rows, err := sm.db.Query(query)
	if err != nil {
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
			sm.logger.WithError(err).Error("Failed to scan stream config row")
			errorCount++
			continue
		}

		// Deserialize configurations
		var inputConfig StreamEndpointConfig
		if err := json.Unmarshal([]byte(inputConfigJSON), &inputConfig); err != nil {
			sm.logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal input config")
			errorCount++
			continue
		}

		var outputConfig StreamEndpointConfig
		if err := json.Unmarshal([]byte(outputConfigJSON), &outputConfig); err != nil {
			sm.logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal output config")
			errorCount++
			continue
		}

		var processorChain []ProcessorConfig
		if err := json.Unmarshal([]byte(processorChainJSON), &processorChain); err != nil {
			sm.logger.WithError(err).WithField("stream_id", streamID).Error("Failed to unmarshal processor chain")
			errorCount++
			continue
		}

		var metadata map[string]interface{}
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
				sm.logger.WithError(err).WithField("stream_id", streamID).Warn("Failed to unmarshal metadata, using empty")
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
		benthosConfig, err := sm.generateBenthosStreamBuilder(streamInfo)
		if err != nil {
			sm.logger.WithError(err).WithField("stream_id", streamID).Error("Failed to generate Benthos config during startup")
			sm.updateValidationError(streamID, err.Error())
			errorCount++
			continue
		}

		// Note: StreamBuilder doesn't have a Lint() method - validation happens during SetYAML()
		// If we reach here, the configuration is already validated

		// Store in memory
		sm.streams[streamID] = streamInfo
		sm.streamBuilders[streamID] = benthosConfig

		sm.logger.WithFields(logrus.Fields{
			"stream_id":        streamID,
			"thing_id":         thingID,
			"interaction_type": interactionType,
		}).Debug("Loaded and validated stream configuration from database")

		loadedCount++
		validatedCount++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating stream config rows: %w", err)
	}

	sm.logger.WithFields(logrus.Fields{
		"loaded":    loadedCount,
		"validated": validatedCount,
		"errors":    errorCount,
	}).Info("Completed loading stream configurations from database")

	return nil
}

// updateValidationError updates the validation error for a stream in the database
func (sm *SimpleBenthosStreamManager) updateValidationError(streamID, errorMsg string) {
	_, err := sm.db.Exec(`
		UPDATE stream_configs 
		SET validation_error = ?, updated_at = ?
		WHERE stream_id = ?
	`, errorMsg, time.Now(), streamID)

	if err != nil {
		sm.logger.WithError(err).WithField("stream_id", streamID).Error("Failed to update validation error")
	}
}

// updateStreamStatusInDatabase updates the stream status in the database
func (sm *SimpleBenthosStreamManager) updateStreamStatusInDatabase(streamID, status string) error {
	_, err := sm.db.Exec(`
		UPDATE stream_configs 
		SET status = ?, updated_at = ?
		WHERE stream_id = ?
	`, status, time.Now().UTC().Format(time.RFC3339), streamID)

	if err != nil {
		return fmt.Errorf("failed to update stream status in database: %w", err)
	}

	return nil
}

// Stream lifecycle methods

func (sm *SimpleBenthosStreamManager) CreateStream(ctx context.Context, request StreamCreationRequest) (*StreamInfo, error) {
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
	streamBuilder, err := sm.generateBenthosStreamBuilder(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Benthos stream builder: %w", err)
	}

	// StreamBuilder validates configuration during SetYAML() call
	// No additional validation needed here

	// Persist to DuckDB
	if err := sm.persistStreamToDatabase(stream); err != nil {
		return nil, fmt.Errorf("failed to persist stream to database: %w", err)
	}

	// Store in memory
	sm.streams[streamID] = stream
	sm.streamBuilders[streamID] = streamBuilder

	// Write configuration file for debugging/inspection (optional)
	if sm.configDir != "" {
		configPath := filepath.Join(sm.configDir, fmt.Sprintf("stream_%s.yaml", streamID))
		if err := sm.writeBenthosStreamBuilder(configPath, streamBuilder); err != nil {
			sm.logger.WithError(err).Warn("Failed to write debug config file")
		}
	}

	sm.logger.WithFields(logrus.Fields{
		"stream_id":        streamID,
		"thing_id":         request.ThingID,
		"interaction_type": request.InteractionType,
		"interaction_name": request.InteractionName,
	}).Info("Created and validated Benthos stream")

	return stream, nil
}

// persistStreamToDatabase saves stream configuration to DuckDB
func (sm *SimpleBenthosStreamManager) persistStreamToDatabase(stream *StreamInfo) error {
	// Serialize configurations to JSON
	inputConfigJSON, err := json.Marshal(stream.Input)
	if err != nil {
		return fmt.Errorf("failed to marshal input config: %w", err)
	}

	outputConfigJSON, err := json.Marshal(stream.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output config: %w", err)
	}

	processorChainJSON, err := json.Marshal(stream.ProcessorChain)
	if err != nil {
		return fmt.Errorf("failed to marshal processor chain: %w", err)
	}

	var metadataJSON []byte
	if stream.Metadata != nil {
		metadataJSON, err = json.Marshal(stream.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	// Insert into database
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
		return fmt.Errorf("failed to insert stream config into database: %w", err)
	}

	sm.logger.WithField("stream_id", stream.ID).Debug("Persisted stream configuration to DuckDB")
	return nil
}

func (sm *SimpleBenthosStreamManager) UpdateStream(ctx context.Context, streamID string, request StreamUpdateRequest) (*StreamInfo, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	// Update stream info
	now := time.Now().UTC()

	if request.ProcessorChain != nil {
		stream.ProcessorChain = request.ProcessorChain
	}
	if request.Input != nil {
		stream.Input = *request.Input
	}
	if request.Output != nil {
		stream.Output = *request.Output
	}
	if request.Metadata != nil {
		stream.Metadata = request.Metadata
	}

	stream.UpdatedAt = now.Format(time.RFC3339)

	// Regenerate Benthos configuration using StreamBuilder
	streamBuilder, err := sm.generateBenthosStreamBuilder(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to generate updated Benthos stream builder: %w", err)
	}

	// StreamBuilder validates configuration during SetYAML() call
	// No additional validation needed here

	// Update in database
	if err := sm.updateStreamInDatabase(stream); err != nil {
		return nil, fmt.Errorf("failed to update stream in database: %w", err)
	}

	// Update in memory
	sm.streamBuilders[streamID] = streamBuilder

	sm.logger.WithField("stream_id", streamID).Info("Updated and validated Benthos stream")

	return stream, nil
}

// updateStreamInDatabase updates stream configuration in DuckDB
func (sm *SimpleBenthosStreamManager) updateStreamInDatabase(stream *StreamInfo) error {
	// Serialize configurations to JSON
	inputConfigJSON, err := json.Marshal(stream.Input)
	if err != nil {
		return fmt.Errorf("failed to marshal input config: %w", err)
	}

	outputConfigJSON, err := json.Marshal(stream.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output config: %w", err)
	}

	processorChainJSON, err := json.Marshal(stream.ProcessorChain)
	if err != nil {
		return fmt.Errorf("failed to marshal processor chain: %w", err)
	}

	var metadataJSON []byte
	if stream.Metadata != nil {
		metadataJSON, err = json.Marshal(stream.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	// Update in database
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
		return fmt.Errorf("failed to update stream config in database: %w", err)
	}

	sm.logger.WithField("stream_id", stream.ID).Debug("Updated stream configuration in DuckDB")
	return nil
}

func (sm *SimpleBenthosStreamManager) DeleteStream(ctx context.Context, streamID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	// Mark as deleted in database (soft delete for audit trail)
	_, err := sm.db.Exec(`
		UPDATE stream_configs 
		SET status = 'deleted', updated_at = ?
		WHERE stream_id = ?
	`, time.Now().Format(time.RFC3339), streamID)

	if err != nil {
		return fmt.Errorf("failed to mark stream as deleted in database: %w", err)
	}

	// Remove from memory
	delete(sm.streams, streamID)
	delete(sm.streamBuilders, streamID)
	// Stop stream if running
	if activeStream, exists := sm.activeStreams[streamID]; exists {
		if err := activeStream.Stop(ctx); err != nil {
			sm.logger.WithError(err).Warn("Failed to stop stream during deletion")
		}
		delete(sm.activeStreams, streamID)
	}

	// Optionally remove configuration file
	if sm.configDir != "" {
		configPath := filepath.Join(sm.configDir, fmt.Sprintf("stream_%s.yaml", streamID))
		if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
			sm.logger.WithError(err).Warn("Failed to remove debug config file")
		}
	}

	sm.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  stream.ThingID,
	}).Info("Deleted Benthos stream")

	return nil
}

func (sm *SimpleBenthosStreamManager) GetStream(ctx context.Context, streamID string) (*StreamInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	return stream, nil
}

func (sm *SimpleBenthosStreamManager) ListStreams(ctx context.Context, filters StreamFilters) ([]StreamInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []StreamInfo
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

	return result, nil
}

// Stream operations

func (sm *SimpleBenthosStreamManager) StartStream(ctx context.Context, streamID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	// Check if stream is already running
	if _, isRunning := sm.activeStreams[streamID]; isRunning {
		return fmt.Errorf("stream %s is already running", streamID)
	}

	// Get the stream builder
	builder, exists := sm.streamBuilders[streamID]
	if !exists {
		return fmt.Errorf("stream builder not found for stream: %s", streamID)
	}

	// Build the stream
	benthosStream, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build Benthos stream: %w", err)
	}

	// Start the stream in a goroutine
	go func() {
		if err := benthosStream.Run(context.Background()); err != nil {
			sm.logger.WithError(err).WithField("stream_id", streamID).Error("Benthos stream stopped with error")
			// Update status to stopped
			sm.mu.Lock()
			if s, ok := sm.streams[streamID]; ok {
				s.Status = "stopped"
				s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
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
	if err := sm.updateStreamStatusInDatabase(streamID, "running"); err != nil {
		sm.logger.WithError(err).Warn("Failed to update stream status in database")
	}

	sm.logger.WithField("stream_id", streamID).Info("Started Benthos stream")

	return nil
}

func (sm *SimpleBenthosStreamManager) StopStream(ctx context.Context, streamID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	// Check if stream is running
	activeStream, isRunning := sm.activeStreams[streamID]
	if !isRunning {
		return fmt.Errorf("stream %s is not running", streamID)
	}

	// Stop the stream
	if err := activeStream.Stop(ctx); err != nil {
		return fmt.Errorf("failed to stop Benthos stream: %w", err)
	}

	// Remove from active streams
	delete(sm.activeStreams, streamID)

	// Update status
	stream.Status = "stopped"
	stream.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	// Update in database
	if err := sm.updateStreamStatusInDatabase(streamID, "stopped"); err != nil {
		sm.logger.WithError(err).Warn("Failed to update stream status in database")
	}

	sm.logger.WithField("stream_id", streamID).Info("Stopped Benthos stream")

	return nil
}

func (sm *SimpleBenthosStreamManager) GetStreamStatus(ctx context.Context, streamID string) (*StreamStatus, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

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
		"messages_processed": 0,
		"errors":             0,
		"uptime":             "0s",
		"is_running":         isRunning,
	}

	// Note: Benthos v4 Stream doesn't expose metrics directly
	// In production, you'd typically use Benthos HTTP API or metrics exporters

	status := &StreamStatus{
		Status:       actualStatus,
		LastActivity: stream.UpdatedAt,
		Metrics:      metrics,
		Errors:       []string{},
	}

	return status, nil
}

// Processor collection methods

func (sm *SimpleBenthosStreamManager) CreateProcessorCollection(ctx context.Context, request ProcessorCollectionRequest) (*ProcessorCollection, error) {
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

	sm.logger.WithFields(logrus.Fields{
		"collection_id": collectionID,
		"name":          request.Name,
	}).Info("Created processor collection")

	return collection, nil
}

func (sm *SimpleBenthosStreamManager) GetProcessorCollection(ctx context.Context, collectionID string) (*ProcessorCollection, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	collection, exists := sm.processorCollections[collectionID]
	if !exists {
		return nil, fmt.Errorf("processor collection not found: %s", collectionID)
	}

	return collection, nil
}

func (sm *SimpleBenthosStreamManager) ListProcessorCollections(ctx context.Context) ([]ProcessorCollection, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []ProcessorCollection
	for _, collection := range sm.processorCollections {
		result = append(result, *collection)
	}

	return result, nil
}

// Helper methods for generating Benthos configurations

// generateBenthosStreamBuilder creates Benthos StreamBuilder using service API
func (sm *SimpleBenthosStreamManager) generateBenthosStreamBuilder(stream *StreamInfo) (*service.StreamBuilder, error) {
	// Create new stream builder
	builder := service.NewStreamBuilder()

	// Check if YAML configuration is provided in metadata
	var yamlConfig string
	if stream.Metadata != nil {
		if yamlStr, ok := stream.Metadata["yaml_config"].(string); ok && yamlStr != "" {
			yamlConfig = yamlStr
			sm.logger.WithField("stream_id", stream.ID).Debug("Using YAML config from metadata")
		}
	}

	// Set complete configuration using YAML
	if err := builder.SetYAML(yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to set YAML config: %w", err)
	}

	sm.logger.WithFields(logrus.Fields{
		"stream_id":        stream.ID,
		"thing_id":         stream.ThingID,
		"interaction_type": stream.InteractionType,
		"direction":        stream.Direction,
		"yaml_source":      "metadata",
	}).Debug("Created Benthos stream builder using service API")

	return builder, nil
}

// writeBenthosStreamBuilder writes a StreamBuilder to file for inspection
func (sm *SimpleBenthosStreamManager) writeBenthosStreamBuilder(configPath string, builder *service.StreamBuilder) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Try to get YAML representation from StreamBuilder
	yamlContent, err := builder.AsYAML()
	if err != nil {
		// If AsYAML fails, write a placeholder
		yamlContent = fmt.Sprintf(`# Benthos Stream Configuration
# Generated by TwinCore Stream Manager
# Stream created with service.NewStreamBuilder()

# This file is for inspection only
# Actual stream runs in memory via Benthos service API

stream_info:
  created: %s
  type: "benthos_service_stream"
  note: "Configuration managed via service.StreamBuilder API"
`, time.Now().Format(time.RFC3339))
	}

	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Ensure SimpleBenthosStreamManager implements BenthosStreamManager interface
var _ BenthosStreamManager = (*SimpleBenthosStreamManager)(nil)
