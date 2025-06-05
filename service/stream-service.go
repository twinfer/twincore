// Package service provides thin orchestration layers for TwinCore services
package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/pkg/types"
)

// StreamService is a thin orchestration layer that delegates to BenthosStreamManager
type StreamService struct {
	streamManager api.BenthosStreamManager
	logger        *logrus.Logger
	mu            sync.RWMutex
	running       bool
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewStreamService creates a new stream service that delegates to BenthosStreamManager
func NewStreamService(streamManager api.BenthosStreamManager, logger *logrus.Logger) types.Service {
	return &StreamService{
		streamManager: streamManager,
		logger:        logger,
	}
}

// Name returns the service name
func (s *StreamService) Name() string {
	return "stream"
}

// RequiredLicense returns required license features
func (s *StreamService) RequiredLicense() []string {
	return []string{"core", "streaming"}
}

// Dependencies returns service dependencies
func (s *StreamService) Dependencies() []string {
	return []string{}
}

// Start initializes and starts the stream service
func (s *StreamService) Start(ctx context.Context, config types.ServiceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("stream service already running")
	}

	s.logger.Info("StreamService starting...")

	// Initialize context for managing stream lifecycles
	s.ctx, s.cancel = context.WithCancel(ctx)

	// Extract stream configuration if provided
	streamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		s.logger.Info("No 'stream' configuration found. Service will run without initial streams.")
		s.running = true
		return nil
	}

	s.logger.WithFields(logrus.Fields{
		"topics":   len(streamConfig.Topics),
		"commands": len(streamConfig.Commands),
	}).Info("Processing stream configuration")

	// Delegate stream creation to BenthosStreamManager
	// Convert legacy stream config to modern StreamCreationRequest format
	for _, topic := range streamConfig.Topics {
		if err := s.createStreamFromTopic(topic); err != nil {
			s.logger.WithError(err).Errorf("Failed to create stream for topic %s", topic.Name)
			// Continue with other streams instead of failing completely
		}
	}

	for _, command := range streamConfig.Commands {
		if err := s.createStreamFromCommand(command); err != nil {
			s.logger.WithError(err).Errorf("Failed to create stream for command %s", command.Name)
			// Continue with other streams instead of failing completely
		}
	}

	s.running = true
	s.logger.Info("StreamService started successfully")
	return nil
}

// Stop gracefully stops the stream service
func (s *StreamService) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("StreamService stopping...")

	// Cancel context to signal all streams to stop
	if s.cancel != nil {
		s.cancel()
	}

	// List and stop all active streams
	streams, err := s.streamManager.ListStreams(ctx, types.StreamFilters{})
	if err != nil {
		s.logger.WithError(err).Warn("Failed to list streams during shutdown")
	} else {
		for _, stream := range streams {
			if err := s.streamManager.StopStream(ctx, stream.ID); err != nil {
				s.logger.WithError(err).Warnf("Failed to stop stream %s", stream.ID)
			}
		}
	}

	s.running = false
	s.ctx = nil
	s.cancel = nil
	s.logger.Info("StreamService stopped")
	return nil
}

// UpdateConfig updates the service configuration
func (s *StreamService) UpdateConfig(config types.ServiceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("service not running, cannot update config")
	}

	s.logger.Info("StreamService: Updating configuration")

	// For now, we'll implement a simple strategy:
	// Stop all existing streams and recreate based on new config
	// In the future, this could be optimized to only update changed streams

	// Get current streams
	currentStreams, err := s.streamManager.ListStreams(context.Background(), types.StreamFilters{})
	if err != nil {
		return fmt.Errorf("failed to list current streams: %w", err)
	}

	// Stop all current streams
	for _, stream := range currentStreams {
		if err := s.streamManager.StopStream(context.Background(), stream.ID); err != nil {
			s.logger.WithError(err).Warnf("Failed to stop stream %s during config update", stream.ID)
		}
	}

	// Process new configuration
	streamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		s.logger.Info("New configuration has no 'stream' section")
		return nil
	}

	// Create new streams based on updated config
	for _, topic := range streamConfig.Topics {
		if err := s.createStreamFromTopic(topic); err != nil {
			s.logger.WithError(err).Errorf("Failed to create stream for topic %s", topic.Name)
		}
	}

	for _, command := range streamConfig.Commands {
		if err := s.createStreamFromCommand(command); err != nil {
			s.logger.WithError(err).Errorf("Failed to create stream for command %s", command.Name)
		}
	}

	s.logger.Info("StreamService configuration updated successfully")
	return nil
}

// HealthCheck verifies the service is healthy
func (s *StreamService) HealthCheck() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return fmt.Errorf("service not running")
	}

	// Check if stream manager is available
	if s.streamManager == nil {
		return fmt.Errorf("stream manager not available")
	}

	// Could add more health checks here, such as:
	// - Checking if critical streams are running
	// - Verifying connection to message brokers
	// - etc.

	return nil
}

// createStreamFromTopic converts legacy topic config to StreamCreationRequest
// This delegates to BenthosStreamManager, which uses the unified forms system
func (s *StreamService) createStreamFromTopic(topic types.StreamTopic) error {
	s.logger.WithField("topic", topic.Name).Debug("Converting legacy topic to modern stream request")

	// Convert legacy configuration to modern StreamCreationRequest
	// The BenthosStreamManager will handle this via the unified forms system
	request := types.StreamCreationRequest{
		ThingID:         topic.Name,
		InteractionType: "properties", // Assuming topics are for properties
		InteractionName: topic.Name,
		Direction:       "input",
		Input: types.StreamEndpointConfig{
			Type:   string(topic.Type),
			Config: topic.Config,
		},
		Output: types.StreamEndpointConfig{
			Type: "stream_bridge",
			Config: map[string]any{
				"topic": topic.Name + "_processed",
			},
		},
		Metadata: map[string]any{
			"source":         "legacy_topic_config",
			"original_id":    topic.Name,
			"migration_note": "Converted from legacy StreamTopic format",
			"forms_system":   "unified_v2", // Indicates modern forms system should be used
		},
	}

	// Delegate to BenthosStreamManager, which uses pkg/wot/forms/ unified system
	streamInfo, err := s.streamManager.CreateStream(s.ctx, request)
	if err != nil {
		return fmt.Errorf("failed to create stream via BenthosStreamManager: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"topic":     topic.Name,
		"stream_id": streamInfo.ID,
		"status":    streamInfo.Status,
	}).Info("Successfully created stream from legacy topic config")

	return nil
}

// createStreamFromCommand converts legacy command config to StreamCreationRequest
// This delegates to BenthosStreamManager, which uses the unified forms system
func (s *StreamService) createStreamFromCommand(command types.CommandStream) error {
	s.logger.WithField("command", command.Name).Debug("Converting legacy command to modern stream request")

	// Convert legacy configuration to modern StreamCreationRequest
	// The BenthosStreamManager will handle this via the unified forms system
	request := types.StreamCreationRequest{
		ThingID:         command.Name,
		InteractionType: "actions", // Commands are actions
		InteractionName: command.Name,
		Direction:       "output",
		Input: types.StreamEndpointConfig{
			Type: "stream_bridge",
			Config: map[string]any{
				"topic": command.Name + "_input",
			},
		},
		Output: types.StreamEndpointConfig{
			Type:   string(command.Type),
			Config: command.Config,
		},
		Metadata: map[string]any{
			"source":         "legacy_command_config",
			"original_id":    command.Name,
			"migration_note": "Converted from legacy CommandStream format",
			"forms_system":   "unified_v2", // Indicates modern forms system should be used
		},
	}

	// Delegate to BenthosStreamManager, which uses pkg/wot/forms/ unified system
	streamInfo, err := s.streamManager.CreateStream(s.ctx, request)
	if err != nil {
		return fmt.Errorf("failed to create stream via BenthosStreamManager: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"command":   command.Name,
		"stream_id": streamInfo.ID,
		"status":    streamInfo.Status,
	}).Info("Successfully created stream from legacy command config")

	return nil
}

// Interface guard
var _ types.Service = (*StreamService)(nil)
