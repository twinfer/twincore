package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/wot"
)

// ThingRegistrationService orchestrates the complete Thing registration process including stream composition
type ThingRegistrationService interface {
	// RegisterThing registers a Thing Description and creates associated streams
	RegisterThing(ctx context.Context, tdJSONLD string) (*ThingRegistrationResult, error)

	// UpdateThing updates a Thing Description and its associated streams
	UpdateThing(ctx context.Context, thingID string, tdJSONLD string) (*ThingRegistrationResult, error)

	// UnregisterThing removes a Thing Description and all associated streams
	UnregisterThing(ctx context.Context, thingID string) error

	// GetThingWithStreams gets a Thing Description along with its stream information
	GetThingWithStreams(ctx context.Context, thingID string) (*ThingWithStreams, error)
}

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
	thingRegistry  ThingRegistryExt // Extended interface
	streamComposer TDStreamCompositionService
	logger         logrus.FieldLogger
}

// ThingRegistryExt extends ThingRegistry with registration methods
type ThingRegistryExt interface {
	ThingRegistry
	RegisterThing(tdJSONLD string) (*wot.ThingDescription, error)
	UpdateThing(thingID string, tdJSONLD string) (*wot.ThingDescription, error)
	DeleteThing(thingID string) error
	ListThings() ([]*wot.ThingDescription, error)
}

// NewDefaultThingRegistrationService creates a new Thing registration service
func NewDefaultThingRegistrationService(
	thingRegistry ThingRegistryExt,
	streamComposer TDStreamCompositionService,
	logger logrus.FieldLogger,
) *DefaultThingRegistrationService {
	return &DefaultThingRegistrationService{
		thingRegistry:  thingRegistry,
		streamComposer: streamComposer,
		logger:         logger,
	}
}

// RegisterThing registers a Thing Description and creates associated streams
func (s *DefaultThingRegistrationService) RegisterThing(ctx context.Context, tdJSONLD string) (*ThingRegistrationResult, error) {
	s.logger.Info("Starting Thing registration with stream composition")

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
	s.logger.WithField("thing_id", thingID).Info("Registering Thing Description")

	// Register Thing Description first
	td, err := s.thingRegistry.RegisterThing(tdJSONLD)
	if err != nil {
		result.Summary.Error = err.Error()
		return result, fmt.Errorf("failed to register Thing Description: %w", err)
	}

	result.ThingDescription = td
	s.logger.WithField("thing_id", td.ID).Info("Thing Description registered successfully")

	// Create streams from Thing Description
	streamResult, err := s.streamComposer.ProcessThingDescription(ctx, td)
	if err != nil {
		s.logger.WithError(err).WithField("thing_id", td.ID).Error("Failed to create streams for Thing Description")
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
func (s *DefaultThingRegistrationService) UpdateThing(ctx context.Context, thingID string, tdJSONLD string) (*ThingRegistrationResult, error) {
	s.logger.WithField("thing_id", thingID).Info("Starting Thing update with stream composition")

	result := &ThingRegistrationResult{
		Summary: ThingRegistrationSummary{
			ThingID: thingID,
			Success: false,
		},
	}

	// Parse TD for stream composition
	var tdMap map[string]interface{}
	if err := json.Unmarshal([]byte(tdJSONLD), &tdMap); err != nil {
		return nil, fmt.Errorf("invalid JSON-LD: %w", err)
	}

	// Update Thing Description
	td, err := s.thingRegistry.UpdateThing(thingID, tdJSONLD)
	if err != nil {
		result.Summary.Error = err.Error()
		return result, fmt.Errorf("failed to update Thing Description: %w", err)
	}

	result.ThingDescription = td
	s.logger.WithField("thing_id", td.ID).Info("Thing Description updated successfully")

	// Update streams for Thing Description
	streamResult, err := s.streamComposer.UpdateStreamsForThing(ctx, td)
	if err != nil {
		s.logger.WithError(err).WithField("thing_id", td.ID).Error("Failed to update streams for Thing Description")
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
func (s *DefaultThingRegistrationService) UnregisterThing(ctx context.Context, thingID string) error {
	s.logger.WithField("thing_id", thingID).Info("Starting Thing unregistration with stream cleanup")

	// Remove streams first
	if err := s.streamComposer.RemoveStreamsForThing(ctx, thingID); err != nil {
		s.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to remove streams for Thing")
		// Continue with TD removal even if stream cleanup fails
	}

	// Remove Thing Description
	if err := s.thingRegistry.DeleteThing(thingID); err != nil {
		return fmt.Errorf("failed to delete Thing Description: %w", err)
	}

	s.logger.WithField("thing_id", thingID).Info("Thing unregistration completed")
	return nil
}

// GetThingWithStreams gets a Thing Description along with its stream information
func (s *DefaultThingRegistrationService) GetThingWithStreams(ctx context.Context, thingID string) (*ThingWithStreams, error) {
	// Get Thing Description
	td, err := s.thingRegistry.GetThing(thingID)
	if err != nil {
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
var _ ThingRegistrationService = (*DefaultThingRegistrationService)(nil)
