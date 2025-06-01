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
	ProcessThingDescription(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error)

	// UpdateStreamsForThing updates streams when a Thing Description changes
	UpdateStreamsForThing(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error)

	// RemoveStreamsForThing removes all streams associated with a Thing
	RemoveStreamsForThing(logger logrus.FieldLogger, ctx context.Context, thingID string) error

	// GetStreamCompositionStatus returns the current status of streams for a Thing
	GetStreamCompositionStatus(logger logrus.FieldLogger, ctx context.Context, thingID string) (*StreamCompositionStatus, error)
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
func (s *DefaultTDStreamCompositionService) ProcessThingDescription(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "ProcessThingDescription", "thing_id": td.ID})
	entryLogger.Debug("Service method called")
	startTime := time.Now() // Assuming time is imported
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger = logger.WithField("thing_id", td.ID) // Use this for subsequent logs
	logger.Info("Processing Thing Description for stream composition")

	result := &StreamCompositionResult{
		ThingID:        td.ID,
		CreatedStreams: []StreamInfo{},
		FailedStreams:  []StreamCreationFailure{},
	}

	// Use centralized binding generator to create all bindings
	// Pass the logger to bindingGenerator methods if they are updated to accept it.
	// For now, assuming GenerateAllBindings uses its own internal logger or one set at instantiation.
	// If GenerateAllBindings is modified to accept a logger, this call needs to change.
	logger.WithFields(logrus.Fields{"dependency_name": "BindingGenerator", "operation": "GenerateAllBindings"}).Debug("Calling dependency")
	bindings, err := s.bindingGenerator.GenerateAllBindings(td)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "BindingGenerator", "operation": "GenerateAllBindings"}).Error("Dependency call failed")
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
		logger.WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "GetStream", "stream_id": streamID}).Debug("Calling dependency")
		streamInfo, err := s.streamManager.GetStream(ctx, streamID)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "GetStream", "stream_id": streamID}).Warn("Dependency call failed (continuing)")
			continue
		}
		if streamInfo != nil {
			result.CreatedStreams = append(result.CreatedStreams, *streamInfo)
			result.Summary.StreamsCreated++
		}
	}

	logger.WithFields(logrus.Fields{
		"streams_created": result.Summary.StreamsCreated,
		"streams_failed":  result.Summary.StreamsFailed,
	}).Info("Completed stream composition for Thing Description")

	return result, nil
}

// UpdateStreamsForThing updates streams when a Thing Description changes
func (s *DefaultTDStreamCompositionService) UpdateStreamsForThing(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "UpdateStreamsForThing", "thing_id": td.ID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger = logger.WithField("thing_id", td.ID)
	logger.Info("Updating streams for Thing Description")

	// Get existing streams for this thing
	logger.WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "ListStreams"}).Debug("Calling dependency")
	existingStreams, err := s.streamManager.ListStreams(ctx, StreamFilters{ThingID: td.ID})
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "ListStreams"}).Error("Dependency call failed")
		return nil, fmt.Errorf("failed to list existing streams: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"existing_streams": len(existingStreams),
	}).Info("Found existing streams for thing")

	// Remove existing streams
	var removedStreamIDs []string
	for _, stream := range existingStreams {
		logger.WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "DeleteStream", "stream_id": stream.ID}).Debug("Calling dependency")
		if err := s.streamManager.DeleteStream(ctx, stream.ID); err != nil {
			logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "DeleteStream", "stream_id": stream.ID}).Error("Dependency call failed")
		} else {
			removedStreamIDs = append(removedStreamIDs, stream.ID)
		}
	}

	// Create new streams
	// Pass the logger down.
	result, err := s.ProcessThingDescription(logger, ctx, td)
	if err != nil {
		// ProcessThingDescription already logs its errors.
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
func (s *DefaultTDStreamCompositionService) RemoveStreamsForThing(logger logrus.FieldLogger, ctx context.Context, thingID string) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "RemoveStreamsForThing", "thing_id": thingID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger = logger.WithField("thing_id", thingID)
	logger.Info("Removing all streams for Thing")

	// Get existing streams for this thing
	logger.WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "ListStreams"}).Debug("Calling dependency")
	existingStreams, err := s.streamManager.ListStreams(ctx, StreamFilters{ThingID: thingID})
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "ListStreams"}).Error("Dependency call failed")
		return fmt.Errorf("failed to list existing streams: %w", err)
	}

	var removeErrors []error
	removedCount := 0

	for _, stream := range existingStreams {
		logger.WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "DeleteStream", "stream_id": stream.ID}).Debug("Calling dependency")
		if err := s.streamManager.DeleteStream(ctx, stream.ID); err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"dependency_name": "BenthosStreamManager",
				"operation": "DeleteStream",
				"stream_id": stream.ID,
			}).Error("Dependency call failed")
			removeErrors = append(removeErrors, err)
		} else {
			removedCount++
			logger.WithFields(logrus.Fields{
				"stream_id": stream.ID,
			}).Debug("Deleted stream")
		}
	}

	logger.WithFields(logrus.Fields{
		"streams_removed": removedCount,
		"errors":          len(removeErrors),
		"total_streams":   len(existingStreams),
	}).Info("Completed stream removal for Thing")

	if len(removeErrors) > 0 {
		// Consolidate errors or return the first one, for simplicity returning a generic message
		return fmt.Errorf("failed to remove %d of %d streams, first error: %w", len(removeErrors), len(existingStreams), removeErrors[0])
	}

	return nil
}

// GetStreamCompositionStatus returns the current status of streams for a Thing
func (s *DefaultTDStreamCompositionService) GetStreamCompositionStatus(logger logrus.FieldLogger, ctx context.Context, thingID string) (*StreamCompositionStatus, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "GetStreamCompositionStatus", "thing_id": thingID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger = logger.WithField("thing_id", thingID)
	logger.WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "ListStreams"}).Debug("Calling dependency")
	streams, err := s.streamManager.ListStreams(ctx, StreamFilters{ThingID: thingID})
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "BenthosStreamManager", "operation": "ListStreams"}).Error("Dependency call failed")
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
