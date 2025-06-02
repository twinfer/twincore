package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types" // Added
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/twinfer/twincore/pkg/wot/forms"
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

// ThingWithStreams contains a Thing Description along with its associated streams
type ThingWithStreams struct {
	ThingDescription *wot.ThingDescription      `json:"thing_description"`
	Streams          []types.StreamInfo         `json:"streams"`
	StreamStatus     *StreamCompositionStatus   `json:"stream_status"`
}

// DefaultThingRegistrationService implements ThingRegistrationService
type DefaultThingRegistrationService struct {
	thingRegistry        ThingRegistryExt           // Interface from interfaces.go
	streamComposer       TDStreamCompositionService // Interface from interfaces.go
	configManager        ConfigurationManager       // Added ConfigurationManager
	bindingGenerator     *forms.BindingGenerator    // Added
	benthosStreamManager BenthosStreamManager       // Added
	logger               logrus.FieldLogger
}

// ThingRegistryExt is defined in interfaces.go

// NewDefaultThingRegistrationService creates a new Thing registration service
func NewDefaultThingRegistrationService(
	thingRegistry ThingRegistryExt,
	streamComposer TDStreamCompositionService,
	configManager ConfigurationManager, // Added configManager parameter
	bindingGenerator *forms.BindingGenerator, // Added
	benthosStreamManager BenthosStreamManager, // Added
	logger logrus.FieldLogger,
) *DefaultThingRegistrationService {
	return &DefaultThingRegistrationService{
		thingRegistry:        thingRegistry,
		streamComposer:       streamComposer,
		configManager:        configManager,        // Assign configManager
		bindingGenerator:     bindingGenerator,     // Added
		benthosStreamManager: benthosStreamManager, // Added
		logger:               logger,
	}
}

// RegisterThing registers a Thing Description and creates associated streams
func (s *DefaultThingRegistrationService) RegisterThing(logger logrus.FieldLogger, ctx context.Context, tdJSONLD string) (*ThingRegistrationResult, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "RegisterThing"})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

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

	// Add new BindingGenerator logic starting here:
	logger.Info("Attempting to generate and apply bindings via BindingGenerator")
	allBindings, bindingErr := s.bindingGenerator.GenerateAllBindings(logger, td) // Renamed err to bindingErr
	if bindingErr != nil {
		logger.WithError(bindingErr).Error("Failed to generate bindings using BindingGenerator")
		// Append to existing error or log; don't overwrite if streamComposer already set an error.
		if result.Summary.Error == "" {
			result.Summary.Error = fmt.Sprintf("Binding generation failed: %v", bindingErr)
		} else {
			result.Summary.Error = fmt.Sprintf("%s; Binding generation failed: %v", result.Summary.Error, bindingErr)
		}
	} else {
		logger.WithFields(logrus.Fields{
			"http_routes_generated": len(allBindings.HTTPRoutes),
			"streams_generated":     len(allBindings.Streams),
		}).Info("Successfully generated bindings from BindingGenerator")

		if result.ConfigGeneration == nil {
			result.ConfigGeneration = &ConfigGenerationResult{}
		}

		// Start generated streams
		// GenerateAllBindings already calls CreateStream. Now we need to start them.
		streamsSuccessfullyStarted := 0
		for _, streamConfig := range allBindings.Streams { // streamIDFromBinding to avoid conflict if streamID is in outer scope
			if err := s.benthosStreamManager.StartStream(ctx, streamConfig.ID); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"stream_id": streamConfig.ID,
					"type":      streamConfig.Type,
				}).Error("Failed to start generated stream from BindingGenerator")
				// Note: StreamsFailed is already handled by streamComposer, avoid double counting for now
				// unless BindingGenerator's streams are entirely separate.
				// result.Summary.StreamsFailed++
			} else {
				logger.WithFields(logrus.Fields{
					"stream_id": streamConfig.ID,
					"type":      streamConfig.Type,
				}).Info("Successfully started generated stream from BindingGenerator")
				streamsSuccessfullyStarted++
			}
		}
		// It's safer to add to existing counts if they are from different sources.
		// However, the plan implies BindingGenerator might be the primary source now.
		// For now, let's assume streamComposer's summary is primary and these are logged.
		// If BindingGenerator replaces streamComposer for these counts, then uncomment next line:
		// result.Summary.StreamsCreated += streamsSuccessfullyStarted // Or assign if replacing

		logger.Infof("%d streams started via BindingGenerator.", streamsSuccessfullyStarted)

		// Register HTTP routes
		routesSuccessfullyAdded := 0
		for generatedRouteKey, formRoute := range allBindings.HTTPRoutes { // Use generatedRouteKey as it's the map key
			routeID := fmt.Sprintf("%s_br_%s", td.ID, generatedRouteKey) // Generate unique route ID
			// Adapt forms.HTTPRoute to the new types.HTTPRoute structure
			apiRoute := types.HTTPRoute{
				Path:    formRoute.Path,
				Methods: []string{formRoute.Method}, // New HTTPRoute uses []string
				Handler: "wot_handler",             // Mapped from old TargetService
				// RequiresAuth needs to be determined, e.g., based on td.Security.
				// Assuming true if security definitions exist, similar to wot_mapper.
				RequiresAuth: len(td.Security) > 0,
				Config: map[string]interface{}{
					"id":          routeID, // Store original ID in Config
					"contentType": formRoute.ContentType,
					// Add other necessary fields from formRoute or td to Config if needed
					// "headers": formRoute.Headers, // Example
				},
			}

			if err := s.configManager.AddRoute(ctx, routeID, apiRoute); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"route_id": routeID,
					"path":     apiRoute.Path,
				}).Error("Failed to register HTTP route from BindingGenerator")
			} else {
				logger.WithFields(logrus.Fields{
					"route_id": routeID,
					"path":     apiRoute.Path,
				}).Info("Successfully registered HTTP route from BindingGenerator")
				routesSuccessfullyAdded++
			}
		result.ConfigGeneration.HTTPRoutes += routesSuccessfullyAdded // Add to existing count
		if routesSuccessfullyAdded > 0 {
			result.ConfigGeneration.CaddyConfigured = true // If any route added, consider Caddy configured by this step
		}

		if streamsSuccessfullyStarted > 0 && !result.ConfigGeneration.BenthosConfigured {
			// If streamComposer didn't set it, and BG started streams, set it.
			result.ConfigGeneration.BenthosConfigured = true
		}
		logger.Infof("%d HTTP routes registered via BindingGenerator.", routesSuccessfullyAdded)
	}

	// Ensure result.Summary.Success reflects the overall status.
	// If bindingErr occurred, or significant failures in starting streams/routes,
	// success might need to be reconsidered or error messages aggregated.
	// For now, existing success logic is: result.Summary.Success = true (set after streamComposer)
	// This might need adjustment based on how critical bindingGenerator failures are.
	// if bindingErr != nil || (len(allBindings.Streams) > 0 && streamsSuccessfullyStarted == 0) {
	//    result.Summary.Success = false // Example of stricter success criteria
	// }

	result.Summary.Success = result.Summary.Error == "" && bindingErr == nil // Adjusted success criteria

	s.logger.WithFields(logrus.Fields{
		"thing_id":        td.ID,
		"streams_created": result.Summary.StreamsCreated, // This might need to sum results from streamComposer and bindingGenerator
		"streams_failed":  result.Summary.StreamsFailed,  // Same as above
		"routes_added":    result.ConfigGeneration.HTTPRoutes,
		"success":         result.Summary.Success,
	}).Info("Thing registration with stream composition and binding generation completed")

	return result, nil
}

// UpdateThing updates a Thing Description and its associated streams
func (s *DefaultThingRegistrationService) UpdateThing(logger logrus.FieldLogger, ctx context.Context, thingID string, tdJSONLD string) (*ThingRegistrationResult, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "UpdateThing", "thing_id": thingID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

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

	// Add new BindingGenerator logic for HTTP routes starting here:
	logger.Info("Attempting to generate bindings via BindingGenerator for HTTP route updates")
	allBindings, bindingErr := s.bindingGenerator.GenerateAllBindings(logger, td)
	if bindingErr != nil {
		logger.WithError(bindingErr).Error("Failed to generate bindings using BindingGenerator for HTTP route updates")
		if result.Summary.Error == "" {
			result.Summary.Error = fmt.Sprintf("Binding generation for routes failed: %v", bindingErr)
		} else {
			result.Summary.Error = fmt.Sprintf("%s; Binding generation for routes failed: %v", result.Summary.Error, bindingErr)
		}
	} else {
		logger.WithFields(logrus.Fields{
			"http_routes_generated": len(allBindings.HTTPRoutes),
		}).Info("Successfully generated bindings from BindingGenerator, focusing on HTTP routes")

		if result.ConfigGeneration == nil {
			result.ConfigGeneration = &ConfigGenerationResult{}
		}

		// HTTP Route Reconciliation: Remove old routes for the thing, then add new ones.
		logger.Info("Removing existing HTTP routes for the thing before adding updated ones.")
		if err := s.configManager.RemoveThingRoutes(logger, thingID); err != nil {
			logger.WithError(err).Error("Failed to remove existing HTTP routes for thing.")
			// Potentially update summary error, but proceed with adding new routes if possible
			if result.Summary.Error == "" {
				result.Summary.Error = fmt.Sprintf("Failed to remove old routes: %v", err)
			} else {
				result.Summary.Error = fmt.Sprintf("%s; Failed to remove old routes: %v", result.Summary.Error, err)
			}
		}

		routesSuccessfullyAdded := 0
		for generatedRouteKey, formRoute := range allBindings.HTTPRoutes {
			routeID := fmt.Sprintf("%s_br_%s", td.ID, generatedRouteKey) // Generate unique route ID
			// Adapt forms.HTTPRoute to the new types.HTTPRoute structure
			apiRoute := types.HTTPRoute{
				Path:    formRoute.Path,
				Methods: []string{formRoute.Method}, // New HTTPRoute uses []string
				Handler: "wot_handler",             // Mapped from old TargetService
				// RequiresAuth needs to be determined, e.g., based on td.Security
				RequiresAuth: len(td.Security) > 0,
				Config: map[string]interface{}{
					"id":          routeID, // Store original ID in Config
					"contentType": formRoute.ContentType,
					// Add other necessary fields from formRoute or td to Config if needed
				},
			}

			if err := s.configManager.AddRoute(ctx, routeID, apiRoute); err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"route_id": routeID,
					"path":     apiRoute.Path,
				}).Error("Failed to register HTTP route from BindingGenerator during update")
			} else {
				logger.WithFields(logrus.Fields{
					"route_id": routeID,
					"path":     apiRoute.Path,
				}).Info("Successfully registered HTTP route from BindingGenerator during update")
				routesSuccessfullyAdded++
			}
		}
		result.ConfigGeneration.HTTPRoutes = routesSuccessfullyAdded // Set, as old ones were removed
		result.ConfigGeneration.CaddyConfigured = routesSuccessfullyAdded > 0

		logger.Infof("%d HTTP routes registered via BindingGenerator for update.", routesSuccessfullyAdded)
	}

	// Update overall success status
	// streamResult error is already factored into result.Summary.Error by previous block
	if bindingErr != nil { // If binding generation for routes failed
		result.Summary.Success = false
	} else if result.Summary.Error != "" { // If streamComposer or route removal had errors
		result.Summary.Success = false
	} else {
		result.Summary.Success = true // Only true if no errors from streamComposer, bindingGen, or route removal/add
	}

	// Update the final log message
	finalFields := logrus.Fields{
		"thing_id":          td.ID,
		"streams_created":   result.Summary.StreamsCreated, // From streamComposer
		"streams_failed":    result.Summary.StreamsFailed,  // From streamComposer
		"streams_removed":   0,                             // Potentially from streamComposer, if it logs it
		"routes_configured": result.ConfigGeneration.HTTPRoutes,
		"success":           result.Summary.Success,
	}
	if streamResult != nil { // streamResult might be nil if streamComposer.UpdateStreamsForThing itself failed critically
		finalFields["streams_removed"] = streamResult.Summary.StreamsRemoved
	}
	s.logger.WithFields(finalFields).Info("Thing update process (stream composition and binding generation for routes) completed")

	return result, nil
}

// UnregisterThing removes a Thing Description and all associated streams
func (s *DefaultThingRegistrationService) UnregisterThing(logger logrus.FieldLogger, ctx context.Context, thingID string) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "UnregisterThing", "thing_id": thingID})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

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
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

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
	streams := []types.StreamInfo{} // Placeholder - would need actual stream listing implementation

	return &ThingWithStreams{
		ThingDescription: td,
		Streams:          streams,
		StreamStatus:     status,
	}, nil
}

// Ensure DefaultThingRegistrationService implements ThingRegistrationService interface
// ThingRegistrationService is defined in interfaces.go
var _ ThingRegistrationService = (*DefaultThingRegistrationService)(nil)
