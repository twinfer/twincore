package api

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
)

// TDStreamCompositionService orchestrates the complete flow from Thing Description to active streams
type TDStreamCompositionService interface {
	// ProcessThingDescription analyzes a TD and creates all necessary streams
	ProcessThingDescription(ctx context.Context, thingID string, td map[string]interface{}, config StreamCompositionConfig) (*StreamCompositionResult, error)

	// ProcessThingDescriptionWithExistingAnalysis creates streams from pre-analyzed TD
	ProcessThingDescriptionWithExistingAnalysis(ctx context.Context, analysis *TDAnalysis, config StreamCompositionConfig) (*StreamCompositionResult, error)

	// UpdateStreamsForThing updates streams when a Thing Description changes
	UpdateStreamsForThing(ctx context.Context, thingID string, td map[string]interface{}, config StreamCompositionConfig) (*StreamCompositionResult, error)

	// RemoveStreamsForThing removes all streams associated with a Thing
	RemoveStreamsForThing(ctx context.Context, thingID string) error
}

// StreamCompositionResult contains the result of TD stream composition
type StreamCompositionResult struct {
	ThingID        string                   `json:"thing_id"`
	Analysis       *TDAnalysis              `json:"analysis"`
	CreatedStreams []StreamInfo             `json:"created_streams"`
	FailedStreams  []StreamCreationFailure  `json:"failed_streams,omitempty"`
	UpdatedStreams []StreamInfo             `json:"updated_streams,omitempty"`
	RemovedStreams []string                 `json:"removed_streams,omitempty"`
	Summary        StreamCompositionSummary `json:"summary"`
}

// StreamCreationFailure represents a failed stream creation attempt
type StreamCreationFailure struct {
	Request StreamCreationRequest `json:"request"`
	Error   string                `json:"error"`
}

// StreamCompositionSummary provides high-level statistics
type StreamCompositionSummary struct {
	TotalInteractions int `json:"total_interactions"`
	StreamsCreated    int `json:"streams_created"`
	StreamsFailed     int `json:"streams_failed"`
	StreamsUpdated    int `json:"streams_updated,omitempty"`
	StreamsRemoved    int `json:"streams_removed,omitempty"`
}

// DefaultTDStreamCompositionService implements TDStreamCompositionService
type DefaultTDStreamCompositionService struct {
	composer      TDStreamComposer
	streamManager BenthosStreamManager
	logger        logrus.FieldLogger
}

// NewDefaultTDStreamCompositionService creates a new TD stream composition service
func NewDefaultTDStreamCompositionService(
	composer TDStreamComposer,
	streamManager BenthosStreamManager,
	logger logrus.FieldLogger,
) *DefaultTDStreamCompositionService {
	return &DefaultTDStreamCompositionService{
		composer:      composer,
		streamManager: streamManager,
		logger:        logger,
	}
}

// ProcessThingDescription analyzes a TD and creates all necessary streams
func (s *DefaultTDStreamCompositionService) ProcessThingDescription(ctx context.Context, thingID string, td map[string]interface{}, config StreamCompositionConfig) (*StreamCompositionResult, error) {
	s.logger.WithField("thing_id", thingID).Info("Processing Thing Description for stream composition")

	// Analyze the Thing Description
	analysis, err := s.composer.AnalyzeTD(ctx, td)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze Thing Description: %w", err)
	}

	// Ensure analysis has the correct thing ID
	if analysis.ThingID != thingID {
		s.logger.WithFields(logrus.Fields{
			"expected_id": thingID,
			"actual_id":   analysis.ThingID,
		}).Warn("Thing ID mismatch between parameter and TD analysis")
		analysis.ThingID = thingID // Use the provided ID
	}

	return s.ProcessThingDescriptionWithExistingAnalysis(ctx, analysis, config)
}

// ProcessThingDescriptionWithExistingAnalysis creates streams from pre-analyzed TD
func (s *DefaultTDStreamCompositionService) ProcessThingDescriptionWithExistingAnalysis(ctx context.Context, analysis *TDAnalysis, config StreamCompositionConfig) (*StreamCompositionResult, error) {
	result := &StreamCompositionResult{
		ThingID:        analysis.ThingID,
		Analysis:       analysis,
		CreatedStreams: []StreamInfo{},
		FailedStreams:  []StreamCreationFailure{},
	}

	// Calculate total interactions
	totalInteractions := len(analysis.Properties) + len(analysis.Actions) + len(analysis.Events)
	result.Summary.TotalInteractions = totalInteractions

	s.logger.WithFields(logrus.Fields{
		"thing_id":   analysis.ThingID,
		"properties": len(analysis.Properties),
		"actions":    len(analysis.Actions),
		"events":     len(analysis.Events),
		"total":      totalInteractions,
	}).Info("Composing streams from TD analysis")

	// Generate stream creation requests
	streamRequests, err := s.composer.ComposeStreams(ctx, analysis, config)
	if err != nil {
		return nil, fmt.Errorf("failed to compose streams: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"thing_id": analysis.ThingID,
		"requests": len(streamRequests),
	}).Info("Generated stream creation requests")

	// Create streams
	for _, request := range streamRequests {
		s.logger.WithFields(logrus.Fields{
			"thing_id":         request.ThingID,
			"interaction_type": request.InteractionType,
			"interaction_name": request.InteractionName,
			"direction":        request.Direction,
		}).Debug("Creating stream from request")

		streamInfo, err := s.streamManager.CreateStream(ctx, request)
		if err != nil {
			s.logger.WithError(err).WithFields(logrus.Fields{
				"thing_id":         request.ThingID,
				"interaction_type": request.InteractionType,
				"interaction_name": request.InteractionName,
			}).Error("Failed to create stream")

			failure := StreamCreationFailure{
				Request: request,
				Error:   err.Error(),
			}
			result.FailedStreams = append(result.FailedStreams, failure)
			result.Summary.StreamsFailed++
			continue
		}

		result.CreatedStreams = append(result.CreatedStreams, *streamInfo)
		result.Summary.StreamsCreated++

		s.logger.WithFields(logrus.Fields{
			"stream_id":        streamInfo.ID,
			"thing_id":         streamInfo.ThingID,
			"interaction_type": streamInfo.InteractionType,
			"interaction_name": streamInfo.InteractionName,
		}).Info("Successfully created stream")
	}

	s.logger.WithFields(logrus.Fields{
		"thing_id":        analysis.ThingID,
		"streams_created": result.Summary.StreamsCreated,
		"streams_failed":  result.Summary.StreamsFailed,
		"total_requests":  len(streamRequests),
	}).Info("Completed stream composition for Thing Description")

	return result, nil
}

// UpdateStreamsForThing updates streams when a Thing Description changes
func (s *DefaultTDStreamCompositionService) UpdateStreamsForThing(ctx context.Context, thingID string, td map[string]interface{}, config StreamCompositionConfig) (*StreamCompositionResult, error) {
	s.logger.WithField("thing_id", thingID).Info("Updating streams for Thing Description")

	// Get existing streams for this thing
	existingStreams, err := s.streamManager.ListStreams(ctx, StreamFilters{ThingID: thingID})
	if err != nil {
		return nil, fmt.Errorf("failed to list existing streams: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"thing_id":         thingID,
		"existing_streams": len(existingStreams),
	}).Info("Found existing streams for thing")

	// Remove existing streams
	var removedStreamIDs []string
	for _, stream := range existingStreams {
		if err := s.streamManager.DeleteStream(ctx, stream.ID); err != nil {
			s.logger.WithError(err).WithField("stream_id", stream.ID).Error("Failed to delete existing stream")
		} else {
			removedStreamIDs = append(removedStreamIDs, stream.ID)
		}
	}

	// Create new streams
	result, err := s.ProcessThingDescription(ctx, thingID, td, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create new streams: %w", err)
	}

	// Update result to include removed streams
	result.RemovedStreams = removedStreamIDs
	result.Summary.StreamsRemoved = len(removedStreamIDs)

	s.logger.WithFields(logrus.Fields{
		"thing_id":        thingID,
		"streams_removed": len(removedStreamIDs),
		"streams_created": result.Summary.StreamsCreated,
		"streams_failed":  result.Summary.StreamsFailed,
	}).Info("Completed stream update for Thing Description")

	return result, nil
}

// RemoveStreamsForThing removes all streams associated with a Thing
func (s *DefaultTDStreamCompositionService) RemoveStreamsForThing(ctx context.Context, thingID string) error {
	s.logger.WithField("thing_id", thingID).Info("Removing all streams for Thing")

	// Get existing streams for this thing
	existingStreams, err := s.streamManager.ListStreams(ctx, StreamFilters{ThingID: thingID})
	if err != nil {
		return fmt.Errorf("failed to list existing streams: %w", err)
	}

	var removeErrors []error
	removedCount := 0

	for _, stream := range existingStreams {
		if err := s.streamManager.DeleteStream(ctx, stream.ID); err != nil {
			s.logger.WithError(err).WithFields(logrus.Fields{
				"stream_id": stream.ID,
				"thing_id":  thingID,
			}).Error("Failed to delete stream")
			removeErrors = append(removeErrors, err)
		} else {
			removedCount++
			s.logger.WithFields(logrus.Fields{
				"stream_id": stream.ID,
				"thing_id":  thingID,
			}).Debug("Deleted stream")
		}
	}

	s.logger.WithFields(logrus.Fields{
		"thing_id":        thingID,
		"streams_removed": removedCount,
		"errors":          len(removeErrors),
		"total_streams":   len(existingStreams),
	}).Info("Completed stream removal for Thing")

	if len(removeErrors) > 0 {
		return fmt.Errorf("failed to remove %d of %d streams", len(removeErrors), len(existingStreams))
	}

	return nil
}

// Utility methods for enhanced stream composition

// GetStreamCompositionStatus returns the current status of streams for a Thing
func (s *DefaultTDStreamCompositionService) GetStreamCompositionStatus(ctx context.Context, thingID string) (*StreamCompositionStatus, error) {
	streams, err := s.streamManager.ListStreams(ctx, StreamFilters{ThingID: thingID})
	if err != nil {
		return nil, fmt.Errorf("failed to list streams: %w", err)
	}

	status := &StreamCompositionStatus{
		ThingID:         thingID,
		TotalStreams:    len(streams),
		StreamsByType:   make(map[string]int),
		StreamsByStatus: make(map[string]int),
	}

	for _, stream := range streams {
		status.StreamsByType[stream.InteractionType]++
		status.StreamsByStatus[stream.Status]++
	}

	return status, nil
}

// StreamCompositionStatus provides status information about streams for a Thing
type StreamCompositionStatus struct {
	ThingID         string         `json:"thing_id"`
	TotalStreams    int            `json:"total_streams"`
	StreamsByType   map[string]int `json:"streams_by_type"`
	StreamsByStatus map[string]int `json:"streams_by_status"`
}

// ValidateStreamCompositionConfig validates a stream composition configuration
func ValidateStreamCompositionConfig(config StreamCompositionConfig) error {
	if config.TopicPrefix == "" {
		return fmt.Errorf("topic prefix is required")
	}

	if config.DefaultConsumerGroup == "" {
		return fmt.Errorf("default consumer group is required")
	}

	if len(config.KafkaBrokers) == 0 {
		return fmt.Errorf("at least one Kafka broker is required")
	}

	if !config.CreatePropertyStreams && !config.CreateActionStreams && !config.CreateEventStreams {
		return fmt.Errorf("at least one stream type must be enabled")
	}

	// Validate processor chains
	for interactionType, chain := range config.DefaultProcessorChains {
		if len(chain) == 0 {
			return fmt.Errorf("processor chain for %s cannot be empty", interactionType)
		}

		for i, processor := range chain {
			if processor.Type == "" {
				return fmt.Errorf("processor %d in %s chain has empty type", i, interactionType)
			}
		}
	}

	return nil
}

// Ensure DefaultTDStreamCompositionService implements TDStreamCompositionService interface
var _ TDStreamCompositionService = (*DefaultTDStreamCompositionService)(nil)
