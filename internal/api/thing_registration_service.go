package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/wot"
)

// ThingRegistrationService is defined in interfaces.go

// ThingRegistrationResult contains the complete result of Thing registration
type ThingRegistrationResult struct {
	ThingDescription  *wot.ThingDescription    `json:"thing_description"`
	StreamComposition *StreamCompositionResult `json:"stream_composition"`
	ConfigGeneration  *ConfigGenerationResult  `json:"config_generation,omitempty"`
	Summary           ThingRegistrationSummary `json:"summary"`
}

// ConfigGenerationResult contains information about generated service configurations
type ConfigGenerationResult struct {
	HTTPRoutes        int  `json:"http_routes"`
	StreamTopics      int  `json:"stream_topics"`
	CaddyConfigured   bool `json:"caddy_configured"`
	BenthosConfigured bool `json:"benthos_configured"`
}

// ThingRegistrationSummary provides high-level statistics
type ThingRegistrationSummary struct {
	ThingID          string `json:"thing_id"`
	Success          bool   `json:"success"`
	StreamsCreated   int    `json:"streams_created"`
	StreamsFailed    int    `json:"streams_failed"`
	ConfigsGenerated bool   `json:"configs_generated"`
	Error            string `json:"error,omitempty"`
}

// ThingWithStreams combines Thing Description with stream information
type ThingWithStreams struct {
	ThingDescription *wot.ThingDescription    `json:"thing_description"`
	Streams          []StreamInfo             `json:"streams"`
	StreamStatus     *StreamCompositionStatus `json:"stream_status"`
}

// DefaultThingRegistrationService implements ThingRegistrationService
type DefaultThingRegistrationService struct {
	thingRegistry  ThingRegistryExt           // Interface from interfaces.go
	streamComposer TDStreamCompositionService // Interface from interfaces.go
	configManager  ConfigurationManager       // Added ConfigurationManager
	logger         logrus.FieldLogger
}

// ThingRegistryExt is defined in interfaces.go

// NewDefaultThingRegistrationService creates a new Thing registration service
func NewDefaultThingRegistrationService(
	thingRegistry ThingRegistryExt,
	streamComposer TDStreamCompositionService,
	configManager ConfigurationManager, // Added configManager parameter
	logger logrus.FieldLogger,
) *DefaultThingRegistrationService {
	return &DefaultThingRegistrationService{
		thingRegistry:  thingRegistry,
		streamComposer: streamComposer,
		configManager:  configManager, // Assign configManager
		logger:         logger,
	}
}

// RegisterThing registers a Thing Description and creates associated streams
func (s *DefaultThingRegistrationService) RegisterThing(logger logrus.FieldLogger, ctx context.Context, tdJSONLD string) (*ThingRegistrationResult, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "RegisterThing"})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	result := &ThingRegistrationResult{
		Summary: ThingRegistrationSummary{
			Success: false,
		},
	}

	// Parse TD to extract ID for early validation
	var tdMap map[string]interface{}
	if err := json.Unmarshal([]byte(tdJSONLD), &tdMap); err != nil {
		return nil, fmt.Errorf("invalid JSON-LD: %w", err)
	}

	thingID, ok := tdMap["id"].(string)
	if !ok {
		return nil, fmt.Errorf("Thing Description missing required 'id' field")
	}

	result.Summary.ThingID = thingID
	logger = logger.WithField("thing_id", thingID) // Add thingID to logger context
	logger.Info("Registering Thing Description")

	// Register Thing Description first
	logger.WithFields(logrus.Fields{"dependency_name": "ThingRegistryExt", "operation": "RegisterThing"}).Debug("Calling dependency")
	td, err := s.thingRegistry.RegisterThing(tdJSONLD) // Assuming ThingRegistryExt methods don't need logger yet, or will be updated separately
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "ThingRegistryExt", "operation": "RegisterThing"}).Error("Dependency call failed")
		result.Summary.Error = err.Error()
		return result, fmt.Errorf("failed to register Thing Description: %w", err)
	}

	result.ThingDescription = td
	logger.Info("Thing Description registered successfully")

	// Create streams from Thing Description
	logger.WithFields(logrus.Fields{"dependency_name": "TDStreamCompositionService", "operation": "ProcessThingDescription"}).Debug("Calling dependency")
	// Pass the logger to streamComposer methods
	streamResult, err := s.streamComposer.ProcessThingDescription(logger, ctx, td)
	if err != nil {
		logger.WithError(err).Error("Failed to create streams for Thing Description (dependency call failed)")
		// Don't fail the entire registration for stream composition errors
		// The TD is still valid and registered
		result.Summary.Error = fmt.Sprintf("Thing registered but stream composition failed: %v", err)
	} else {
		result.StreamComposition = streamResult
		result.Summary.StreamsCreated = streamResult.Summary.StreamsCreated
		result.Summary.StreamsFailed = streamResult.Summary.StreamsFailed

		s.logger.WithFields(logrus.Fields{
			"thing_id":        td.ID,
			"streams_created": streamResult.Summary.StreamsCreated,
			"streams_failed":  streamResult.Summary.StreamsFailed,
		}).Info("Stream composition completed")
	}

	result.Summary.Success = true

	s.logger.WithFields(logrus.Fields{
		"thing_id":        td.ID,
		"streams_created": result.Summary.StreamsCreated,
		"streams_failed":  result.Summary.StreamsFailed,
	}).Info("Thing registration with stream composition completed")

	return result, nil
}

// UpdateThing updates a Thing Description and its associated streams
func (s *DefaultThingRegistrationService) UpdateThing(logger logrus.FieldLogger, ctx context.Context, thingID string, tdJSONLD string) (*ThingRegistrationResult, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "UpdateThing", "thing_id": thingID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger = logger.WithField("thing_id", thingID) // Add thingID to logger for subsequent logs
	logger.Info("Starting Thing update with stream composition")

	result := &ThingRegistrationResult{
		Summary: ThingRegistrationSummary{
			ThingID: thingID,
			Success: false,
		},
	}

	// Parse TD for stream composition
	var tdMap map[string]interface{}
	if err := json.Unmarshal([]byte(tdJSONLD), &tdMap); err != nil {
		logger.WithError(err).Error("Invalid JSON-LD for Thing update")
		return nil, fmt.Errorf("invalid JSON-LD: %w", err)
	}

	// Update Thing Description
	logger.WithFields(logrus.Fields{"dependency_name": "ThingRegistryExt", "operation": "UpdateThing"}).Debug("Calling dependency")
	td, err := s.thingRegistry.UpdateThing(thingID, tdJSONLD) // Assuming ThingRegistryExt methods don't need logger yet
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "ThingRegistryExt", "operation": "UpdateThing"}).Error("Dependency call failed")
		result.Summary.Error = err.Error()
		return result, fmt.Errorf("failed to update Thing Description: %w", err)
	}

	result.ThingDescription = td
	logger.Info("Thing Description updated successfully")

	// Update streams for Thing Description
	logger.WithFields(logrus.Fields{"dependency_name": "TDStreamCompositionService", "operation": "UpdateStreamsForThing"}).Debug("Calling dependency")
	// Pass the logger to streamComposer methods
	streamResult, err := s.streamComposer.UpdateStreamsForThing(logger, ctx, td)
	if err != nil {
		logger.WithError(err).Error("Failed to update streams for Thing Description (dependency call failed)")
		result.Summary.Error = fmt.Sprintf("Thing updated but stream update failed: %v", err)
	} else {
		result.StreamComposition = streamResult
		result.Summary.StreamsCreated = streamResult.Summary.StreamsCreated
		result.Summary.StreamsFailed = streamResult.Summary.StreamsFailed

		s.logger.WithFields(logrus.Fields{
			"thing_id":        td.ID,
			"streams_created": streamResult.Summary.StreamsCreated,
			"streams_failed":  streamResult.Summary.StreamsFailed,
			"streams_removed": streamResult.Summary.StreamsRemoved,
		}).Info("Stream update completed")
	}

	result.Summary.Success = true

	s.logger.WithFields(logrus.Fields{
		"thing_id":        td.ID,
		"streams_created": result.Summary.StreamsCreated,
		"streams_failed":  result.Summary.StreamsFailed,
	}).Info("Thing update with stream composition completed")

	return result, nil
}

// UnregisterThing removes a Thing Description and all associated streams
func (s *DefaultThingRegistrationService) UnregisterThing(logger logrus.FieldLogger, ctx context.Context, thingID string) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "UnregisterThing", "thing_id": thingID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger = logger.WithField("thing_id", thingID)
	logger.Info("Starting Thing unregistration with stream and route cleanup")

	var errors []string

	// Step 1: Remove streams
	logger.WithFields(logrus.Fields{"dependency_name": "TDStreamCompositionService", "operation": "RemoveStreamsForThing"}).Info("Attempting to remove streams")
	if err := s.streamComposer.RemoveStreamsForThing(logger, ctx, thingID); err != nil {
		errMsg := fmt.Sprintf("failed to remove streams for Thing %s: %v", thingID, err)
		logger.WithError(err).Error(errMsg)
		errors = append(errors, errMsg)
		// Continue with other cleanup steps
	} else {
		logger.Info("Successfully removed streams")
	}

	// Step 2: Remove Caddy routes
	logger.WithFields(logrus.Fields{"dependency_name": "ConfigurationManager", "operation": "RemoveThingRoutes"}).Info("Attempting to remove Caddy routes")
	if err := s.configManager.RemoveThingRoutes(logger, thingID); err != nil {
		errMsg := fmt.Sprintf("failed to remove Caddy routes for Thing %s: %v", thingID, err)
		logger.WithError(err).Error(errMsg)
		errors = append(errors, errMsg)
		// Continue with other cleanup steps
	} else {
		logger.Info("Successfully removed Caddy routes (or placeholder executed)")
	}

	// Step 3: Remove Thing Description from registry
	logger.WithFields(logrus.Fields{"dependency_name": "ThingRegistryExt", "operation": "DeleteThing"}).Info("Attempting to delete Thing Description from registry")
	if err := s.thingRegistry.DeleteThing(thingID); err != nil {
		errMsg := fmt.Sprintf("failed to delete Thing Description %s: %v", thingID, err)
		logger.WithError(err).Error(errMsg)
		errors = append(errors, errMsg)
	} else {
		logger.Info("Successfully deleted Thing Description from registry")
	}

	if len(errors) > 0 {
		compositeError := fmt.Errorf("unregisterThing for %s encountered errors: %s", thingID, strings.Join(errors, "; "))
		logger.WithField("errors_count", len(errors)).Error("Thing unregistration completed with errors.")
		return compositeError
	}

	logger.Info("Thing unregistration completed successfully")
	return nil
}

// GetThingWithStreams gets a Thing Description along with its stream information
func (s *DefaultThingRegistrationService) GetThingWithStreams(logger logrus.FieldLogger, ctx context.Context, thingID string) (*ThingWithStreams, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "GetThingWithStreams", "thing_id": thingID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger = logger.WithField("thing_id", thingID)

	// Get Thing Description
	logger.WithFields(logrus.Fields{"dependency_name": "ThingRegistry", "operation": "GetThing"}).Debug("Calling dependency")
	td, err := s.thingRegistry.GetThing(thingID) // Assuming ThingRegistry methods don't need logger yet
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "ThingRegistry", "operation": "GetThing"}).Error("Dependency call failed")
		return nil, fmt.Errorf("failed to get Thing Description: %w", err)
	}

	// Get stream composition status - create a basic status for now
	// TODO: Implement GetStreamCompositionStatus in the stream composition service
	status := &StreamCompositionStatus{
		ThingID:         thingID,
		TotalStreams:    0,
		StreamsByType:   make(map[string]int),
		StreamsByStatus: make(map[string]int),
	}

	// Get streams - this assumes the stream manager supports listing by Thing ID
	// We'll create a helper interface for this
	streams := []StreamInfo{} // Placeholder - would need actual stream listing implementation

	return &ThingWithStreams{
		ThingDescription: td,
		Streams:          streams,
		StreamStatus:     status,
	}, nil
}

// Ensure DefaultThingRegistrationService implements ThingRegistrationService interface
// ThingRegistrationService is defined in interfaces.go
var _ ThingRegistrationService = (*DefaultThingRegistrationService)(nil)
