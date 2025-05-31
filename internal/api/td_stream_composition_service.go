package api

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/twinfer/twincore/pkg/wot/forms"
)

// TDStreamCompositionService orchestrates the complete flow from Thing Description to active streams
// This is a thin orchestration layer that uses the centralized binding generator
type TDStreamCompositionService interface {
	// ProcessThingDescription analyzes a TD and creates all necessary streams
	ProcessThingDescription(ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error)

	// UpdateStreamsForThing updates streams when a Thing Description changes
	UpdateStreamsForThing(ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error)

	// RemoveStreamsForThing removes all streams associated with a Thing
	RemoveStreamsForThing(ctx context.Context, thingID string) error

	// GetStreamCompositionStatus returns the current status of streams for a Thing
	GetStreamCompositionStatus(ctx context.Context, thingID string) (*StreamCompositionStatus, error)
}

// StreamCompositionResult contains the result of TD stream composition
type StreamCompositionResult struct {
	ThingID        string                   `json:"thing_id"`
	Bindings       *forms.AllBindings       `json:"bindings"`
	CreatedStreams []StreamInfo             `json:"created_streams"`
	FailedStreams  []StreamCreationFailure  `json:"failed_streams,omitempty"`
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
	StreamsRemoved    int `json:"streams_removed,omitempty"`
	HTTPRoutes        int `json:"http_routes"`
	ProcessorChains   int `json:"processor_chains"`
}

// DefaultTDStreamCompositionService implements TDStreamCompositionService
// Uses centralized binding generator instead of duplicating logic
type DefaultTDStreamCompositionService struct {
	bindingGenerator *forms.BindingGenerator
	streamManager    BenthosStreamManager
	logger           logrus.FieldLogger
}

// NewDefaultTDStreamCompositionService creates a new TD stream composition service
func NewDefaultTDStreamCompositionService(
	bindingGenerator *forms.BindingGenerator,
	streamManager BenthosStreamManager,
	logger logrus.FieldLogger,
) *DefaultTDStreamCompositionService {
	return &DefaultTDStreamCompositionService{
		bindingGenerator: bindingGenerator,
		streamManager:    streamManager,
		logger:           logger,
	}
}

// ProcessThingDescription analyzes a TD and creates all necessary streams
func (s *DefaultTDStreamCompositionService) ProcessThingDescription(ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error) {
	s.logger.WithField("thing_id", td.ID).Info("Processing Thing Description for stream composition")

	result := &StreamCompositionResult{
		ThingID:        td.ID,
		CreatedStreams: []StreamInfo{},
		FailedStreams:  []StreamCreationFailure{},
	}

	// Use centralized binding generator to create all bindings
	bindings, err := s.bindingGenerator.GenerateAllBindings(td)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bindings: %w", err)
	}

	result.Bindings = bindings

	// Count total interactions
	totalInteractions := len(td.Properties) + len(td.Actions) + len(td.Events)
	result.Summary.TotalInteractions = totalInteractions
	result.Summary.HTTPRoutes = len(bindings.HTTPRoutes)
	result.Summary.ProcessorChains = len(bindings.Processors)

	s.logger.WithFields(logrus.Fields{
		"thing_id":         td.ID,
		"total_streams":    len(bindings.Streams),
		"http_routes":      len(bindings.HTTPRoutes),
		"processor_chains": len(bindings.Processors),
	}).Info("Generated bindings from Thing Description")

	// The streams are already created by the binding generator
	// Just collect the results
	for streamID := range bindings.Streams {
		// Get stream info from stream manager
		streamInfo, err := s.streamManager.GetStream(ctx, streamID)
		if err != nil {
			s.logger.WithError(err).WithField("stream_id", streamID).Warn("Failed to get stream info")
			continue
		}
		if streamInfo != nil {
			result.CreatedStreams = append(result.CreatedStreams, *streamInfo)
			result.Summary.StreamsCreated++
		}
	}

	s.logger.WithFields(logrus.Fields{
		"thing_id":        td.ID,
		"streams_created": result.Summary.StreamsCreated,
		"streams_failed":  result.Summary.StreamsFailed,
	}).Info("Completed stream composition for Thing Description")

	return result, nil
}

// UpdateStreamsForThing updates streams when a Thing Description changes
func (s *DefaultTDStreamCompositionService) UpdateStreamsForThing(ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error) {
	s.logger.WithField("thing_id", td.ID).Info("Updating streams for Thing Description")

	// Get existing streams for this thing
	existingStreams, err := s.streamManager.ListStreams(ctx, StreamFilters{ThingID: td.ID})
	if err != nil {
		return nil, fmt.Errorf("failed to list existing streams: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"thing_id":         td.ID,
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
	result, err := s.ProcessThingDescription(ctx, td)
	if err != nil {
		return nil, fmt.Errorf("failed to create new streams: %w", err)
	}

	// Update result to include removed streams
	result.RemovedStreams = removedStreamIDs
	result.Summary.StreamsRemoved = len(removedStreamIDs)

	s.logger.WithFields(logrus.Fields{
		"thing_id":        td.ID,
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

// Ensure DefaultTDStreamCompositionService implements TDStreamCompositionService interface
var _ TDStreamCompositionService = (*DefaultTDStreamCompositionService)(nil)
