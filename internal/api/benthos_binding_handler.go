package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

const RequestIDHeader = "X-Request-ID" // Define if not already globally available

// BenthosBindingHandler provides the Benthos streaming API at /wot/binding
// This handler enables dynamic stream creation and management from Thing Descriptions
type BenthosBindingHandler struct {
	thingRegistry ThingRegistry
	streamManager BenthosStreamManager
	logger        *logrus.Logger
}

// Type aliases from pkg/types for backward compatibility
type (
	StreamCreationRequest = types.StreamCreationRequest
	ProcessorConfig       = types.ProcessorConfig
	StreamEndpointConfig  = types.StreamEndpointConfig
	StreamInfo            = types.StreamInfo
	StreamFilters         = types.StreamFilters
)

// Additional types not in pkg/types
type StreamUpdateRequest struct {
	ProcessorChain []ProcessorConfig      `json:"processor_chain,omitempty"`
	Input          *StreamEndpointConfig  `json:"input,omitempty"`
	Output         *StreamEndpointConfig  `json:"output,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type StreamStatus struct {
	Status       string                 `json:"status"`
	LastActivity string                 `json:"last_activity,omitempty"`
	Metrics      map[string]interface{} `json:"metrics,omitempty"`
	Errors       []string               `json:"errors,omitempty"`
}

// Processor collection types
type ProcessorCollectionRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Processors  []ProcessorConfig      `json:"processors"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ProcessorCollection struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Processors  []ProcessorConfig      `json:"processors"`
	CreatedAt   string                 `json:"created_at"`
	UpdatedAt   string                 `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewBenthosBindingHandler creates a new Benthos binding handler
func NewBenthosBindingHandler(
	tr ThingRegistry,
	sm BenthosStreamManager,
	logger *logrus.Logger,
) *BenthosBindingHandler {
	return &BenthosBindingHandler{
		thingRegistry: tr,
		streamManager: sm,
		logger:        logger,
	}
}

// CaddyModule returns the Caddy module information
func (BenthosBindingHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "wot_binding_handler",
		New: func() caddy.Module { return new(BenthosBindingHandler) },
	}
}

// Provision sets up the handler with dependencies from TwinCore app
func (h *BenthosBindingHandler) Provision(ctx caddy.Context) error {
	// Get dependencies from TwinCore app
	appModule, err := ctx.App("twincore")
	if err != nil {
		return fmt.Errorf("wotBindingHandler: 'twincore' Caddy app module not found: %w", err)
	}

	coreProvider, ok := appModule.(CoreProvider)
	if !ok {
		return fmt.Errorf("wotBindingHandler: 'twincore' Caddy app module does not implement CoreProvider")
	}

	h.logger = coreProvider.GetLogger()
	h.thingRegistry = coreProvider.GetThingRegistry()
	h.streamManager = coreProvider.GetBenthosStreamManager()

	if h.logger == nil {
		h.logger = logrus.New()
		h.logger.SetLevel(logrus.WarnLevel)
		h.logger.Warn("BenthosBindingHandler: Logger was nil, using fallback")
	}

	if h.thingRegistry == nil {
		h.logger.Error("BenthosBindingHandler: ThingRegistry is nil")
		return fmt.Errorf("BenthosBindingHandler: missing ThingRegistry dependency")
	}

	if h.streamManager == nil {
		h.logger.Error("BenthosBindingHandler: BenthosStreamManager is nil")
		return fmt.Errorf("BenthosBindingHandler: missing BenthosStreamManager dependency")
	}

	h.logger.Info("BenthosBindingHandler provisioned")
	return nil
}

// ServeHTTP handles Benthos binding requests
func (h *BenthosBindingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	requestID := r.Header.Get(RequestIDHeader)
	if requestID == "" {
		requestID = uuid.NewString()
	}
	logger := h.logger.WithField("request_id", requestID)

	logger.WithFields(logrus.Fields{"handler_name": "BenthosBindingHandler.ServeHTTP", "method": r.Method, "path": r.URL.Path}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "BenthosBindingHandler.ServeHTTP"}).Debug("Handler finished")

	// Extract path from request URL
	path := strings.TrimPrefix(r.URL.Path, "/wot/binding")

	// Route based on path
	switch {
	case path == "/streams" && r.Method == http.MethodPost:
		return h.handleCreateStream(logger, w, r)
	case path == "/streams" && r.Method == http.MethodGet:
		return h.handleListStreams(logger, w, r)
	case strings.HasPrefix(path, "/streams/") && r.Method == http.MethodGet:
		streamID := strings.TrimPrefix(path, "/streams/")
		return h.handleGetStream(logger, w, r, streamID)
	case strings.HasPrefix(path, "/streams/") && r.Method == http.MethodPut:
		streamID := strings.TrimPrefix(path, "/streams/")
		return h.handleUpdateStream(logger, w, r, streamID)
	case strings.HasPrefix(path, "/streams/") && r.Method == http.MethodDelete:
		streamID := strings.TrimPrefix(path, "/streams/")
		return h.handleDeleteStream(logger, w, r, streamID)
	case strings.HasSuffix(path, "/start") && r.Method == http.MethodPost:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/streams/"), "/start")
		return h.handleStartStream(logger, w, r, streamID)
	case strings.HasSuffix(path, "/stop") && r.Method == http.MethodPost:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/streams/"), "/stop")
		return h.handleStopStream(logger, w, r, streamID)
	case strings.HasSuffix(path, "/status") && r.Method == http.MethodGet:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/streams/"), "/status")
		return h.handleGetStreamStatus(logger, w, r, streamID)
	case path == "/processors" && r.Method == http.MethodPost:
		return h.handleCreateProcessorCollection(logger, w, r)
	case path == "/processors" && r.Method == http.MethodGet:
		return h.handleListProcessorCollections(logger, w, r)
	case strings.HasPrefix(path, "/processors/") && r.Method == http.MethodGet:
		collectionID := strings.TrimPrefix(path, "/processors/")
		return h.handleGetProcessorCollection(logger, w, r, collectionID)
	case path == "/generate" && r.Method == http.MethodPost:
		return h.handleGenerateFromTD(logger, w, r)
	default:
		logger.WithField("path", path).Warn("Endpoint not found")
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("endpoint not found"))
	}
}

// Stream management handlers

func (h *BenthosBindingHandler) handleCreateStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleCreateStream"}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleCreateStream"}).Debug("Handler finished")

	var request StreamCreationRequest
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON for create stream request")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	logger = logger.WithFields(logrus.Fields{"thing_id": request.ThingID, "interaction_type": request.InteractionType, "interaction_name": request.InteractionName})

	// Validate Thing exists
	logger.WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetThing", "thing_id": request.ThingID}).Debug("Calling service")
	if _, err := h.thingRegistry.GetThing(request.ThingID); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetThing"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("thing not found: %s", request.ThingID))
	}

	// Validate interaction exists
	if err := h.validateInteraction(request.ThingID, request.InteractionType, request.InteractionName); err != nil {
		logger.WithError(err).Warn("Interaction validation failed")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "CreateStream"}).Debug("Calling service")
	stream, err := h.streamManager.CreateStream(r.Context(), request)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "CreateStream"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(stream)
}

func (h *BenthosBindingHandler) handleListStreams(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleListStreams"}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleListStreams"}).Debug("Handler finished")

	// Parse query filters
	filters := StreamFilters{
		ThingID:         r.URL.Query().Get("thing_id"),
		InteractionType: r.URL.Query().Get("interaction_type"),
		Status:          r.URL.Query().Get("status"),
	}

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "ListStreams", "filters": filters}).Debug("Calling service")
	streams, err := h.streamManager.ListStreams(r.Context(), filters)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "ListStreams"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"streams": streams,
		"count":   len(streams),
	})
}

func (h *BenthosBindingHandler) handleGetStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleGetStream", "stream_id": streamID}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleGetStream"}).Debug("Handler finished")

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "GetStream", "stream_id": streamID}).Debug("Calling service")
	stream, err := h.streamManager.GetStream(r.Context(), streamID)
	if err != nil {
		var streamNotFoundErr *ErrBenthosStreamNotFound
		if errors.As(err, &streamNotFoundErr) {
			logger.WithError(err).WithFields(logrus.Fields{"stream_id": streamID}).Warn("Stream not found")
			return caddyhttp.Error(http.StatusNotFound, streamNotFoundErr)
		}
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "GetStream"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err) // Generic error for other cases
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(stream)
}

func (h *BenthosBindingHandler) handleUpdateStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleUpdateStream", "stream_id": streamID}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleUpdateStream"}).Debug("Handler finished")

	var request StreamUpdateRequest
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON for update stream request")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "UpdateStream", "stream_id": streamID}).Debug("Calling service")
	stream, err := h.streamManager.UpdateStream(r.Context(), streamID, request)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "UpdateStream"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(stream)
}

func (h *BenthosBindingHandler) handleDeleteStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleDeleteStream", "stream_id": streamID}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleDeleteStream"}).Debug("Handler finished")

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "DeleteStream", "stream_id": streamID}).Debug("Calling service")
	if err := h.streamManager.DeleteStream(r.Context(), streamID); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "DeleteStream"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *BenthosBindingHandler) handleStartStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleStartStream", "stream_id": streamID}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleStartStream"}).Debug("Handler finished")

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "StartStream", "stream_id": streamID}).Debug("Calling service")
	if err := h.streamManager.StartStream(r.Context(), streamID); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "StartStream"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *BenthosBindingHandler) handleStopStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleStopStream", "stream_id": streamID}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleStopStream"}).Debug("Handler finished")

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "StopStream", "stream_id": streamID}).Debug("Calling service")
	if err := h.streamManager.StopStream(r.Context(), streamID); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "StopStream"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *BenthosBindingHandler) handleGetStreamStatus(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleGetStreamStatus", "stream_id": streamID}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleGetStreamStatus"}).Debug("Handler finished")

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "GetStreamStatus", "stream_id": streamID}).Debug("Calling service")
	status, err := h.streamManager.GetStreamStatus(r.Context(), streamID)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "GetStreamStatus"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(status)
}

// Processor collection handlers

func (h *BenthosBindingHandler) handleCreateProcessorCollection(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleCreateProcessorCollection"}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleCreateProcessorCollection"}).Debug("Handler finished")

	var request ProcessorCollectionRequest
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON for create processor collection request")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "CreateProcessorCollection", "collection_name": request.Name}).Debug("Calling service")
	collection, err := h.streamManager.CreateProcessorCollection(r.Context(), request)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "CreateProcessorCollection"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(collection)
}

func (h *BenthosBindingHandler) handleListProcessorCollections(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleListProcessorCollections"}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleListProcessorCollections"}).Debug("Handler finished")

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "ListProcessorCollections"}).Debug("Calling service")
	collections, err := h.streamManager.ListProcessorCollections(r.Context())
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "ListProcessorCollections"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"collections": collections,
		"count":       len(collections),
	})
}

func (h *BenthosBindingHandler) handleGetProcessorCollection(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, collectionID string) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleGetProcessorCollection", "collection_id": collectionID}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleGetProcessorCollection"}).Debug("Handler finished")

	if h.streamManager == nil {
		logger.Error("Stream manager not available")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	logger.WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "GetProcessorCollection", "collection_id": collectionID}).Debug("Calling service")
	collection, err := h.streamManager.GetProcessorCollection(r.Context(), collectionID)
	if err != nil {
		var notFoundErr *ErrBenthosProcessorCollectionNotFound
		if errors.As(err, &notFoundErr) {
			logger.WithError(err).WithFields(logrus.Fields{"collection_id": collectionID}).Warn("Processor collection not found")
			return caddyhttp.Error(http.StatusNotFound, notFoundErr)
		}
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "BenthosStreamManager", "method_name": "GetProcessorCollection"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusInternalServerError, err) // Generic error
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(collection)
}

// Special handler for generating streams from Thing Description

func (h *BenthosBindingHandler) handleGenerateFromTD(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.WithFields(logrus.Fields{"handler_name": "handleGenerateFromTD"}).Debug("Handler called")
	defer logger.WithFields(logrus.Fields{"handler_name": "handleGenerateFromTD"}).Debug("Handler finished")

	var request struct {
		ThingID string `json:"thing_id"`
	}
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON for generate from TD request")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	logger = logger.WithField("thing_id", request.ThingID)

	// Get Thing Description
	logger.WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetThing"}).Debug("Calling service")
	td, err := h.thingRegistry.GetThing(request.ThingID)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetThing"}).Error("Service call returned error")
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("thing not found: %s", request.ThingID))
	}

	// Generate stream configurations from TD
	logger.Debug("Generating streams from TD")
	streamConfigs := h.generateStreamsFromTD(td) // This internal method might need more logging if complex

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"thing_id": request.ThingID,
		"streams":  streamConfigs,
		"count":    len(streamConfigs),
	})
}

// Helper methods

func (h *BenthosBindingHandler) decodeJSON(r *http.Request, target interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	return nil
}

func (h *BenthosBindingHandler) validateInteraction(thingID, interactionType, interactionName string) error {
	switch interactionType {
	case "properties":
		_, err := h.thingRegistry.GetProperty(thingID, interactionName)
		return err
	case "actions":
		_, err := h.thingRegistry.GetAction(thingID, interactionName)
		return err
	case "events":
		_, err := h.thingRegistry.GetEvent(thingID, interactionName)
		return err
	default:
		return fmt.Errorf("invalid interaction type: %s", interactionType)
	}
}

func (h *BenthosBindingHandler) generateStreamsFromTD(td *wot.ThingDescription) []StreamCreationRequest {
	var streams []StreamCreationRequest

	// Generate property streams
	for name, property := range td.Properties {
		if property.IsObservable() {
			// Property output stream (device -> platform)
			streams = append(streams, StreamCreationRequest{
				ThingID:         td.ID,
				InteractionType: "properties",
				InteractionName: name,
				Direction:       "input",
				ProcessorChain: []ProcessorConfig{
					{Type: "license_check", Config: map[string]interface{}{"feature": "property_ingestion"}},
					{Type: "json_validation", Config: map[string]interface{}{"schema": property.DataSchemaCore}},
					{Type: "parquet_encode", Config: map[string]interface{}{"schema": "property_schema"}},
				},
				Input: StreamEndpointConfig{
					Type: "kafka",
					Config: map[string]interface{}{
						"topic": fmt.Sprintf("things.%s.properties.%s", td.ID, name),
					},
				},
				Output: StreamEndpointConfig{
					Type: "parquet",
					Config: map[string]interface{}{
						"path": "${PARQUET_LOG_PATH}/properties/props_${!timestamp_unix():yyyy-MM-dd}.parquet",
					},
				},
			})
		}

		if !property.IsReadOnly() {
			// Property input stream (platform -> device)
			streams = append(streams, StreamCreationRequest{
				ThingID:         td.ID,
				InteractionType: "properties",
				InteractionName: name,
				Direction:       "output",
				ProcessorChain: []ProcessorConfig{
					{Type: "license_check", Config: map[string]interface{}{"feature": "property_commands"}},
					{Type: "json_validation", Config: map[string]interface{}{"schema": property.DataSchemaCore}},
				},
				Input: StreamEndpointConfig{
					Type: "http",
					Config: map[string]interface{}{
						"path": fmt.Sprintf("/things/%s/properties/%s", td.ID, name),
					},
				},
				Output: StreamEndpointConfig{
					Type: "kafka",
					Config: map[string]interface{}{
						"topic": fmt.Sprintf("things.%s.properties.%s.commands", td.ID, name),
					},
				},
			})
		}
	}

	// Generate action streams
	for name, action := range td.Actions {
		streams = append(streams, StreamCreationRequest{
			ThingID:         td.ID,
			InteractionType: "actions",
			InteractionName: name,
			Direction:       "bidirectional",
			ProcessorChain: []ProcessorConfig{
				{Type: "license_check", Config: map[string]interface{}{"feature": "action_invocation"}},
				{Type: "json_validation", Config: map[string]interface{}{"schema": action.GetInput()}},
				{Type: "action_tracker", Config: map[string]interface{}{"timeout": "30s"}},
			},
			Input: StreamEndpointConfig{
				Type: "http",
				Config: map[string]interface{}{
					"path": fmt.Sprintf("/things/%s/actions/%s", td.ID, name),
				},
			},
			Output: StreamEndpointConfig{
				Type: "kafka",
				Config: map[string]interface{}{
					"topic": fmt.Sprintf("things.%s.actions.%s", td.ID, name),
				},
			},
		})
	}

	// Generate event streams
	for name := range td.Events {
		streams = append(streams, StreamCreationRequest{
			ThingID:         td.ID,
			InteractionType: "events",
			InteractionName: name,
			Direction:       "input",
			ProcessorChain: []ProcessorConfig{
				{Type: "license_check", Config: map[string]interface{}{"feature": "event_processing"}},
				{Type: "event_enrichment", Config: map[string]interface{}{}},
				{Type: "parquet_encode", Config: map[string]interface{}{"schema": "event_schema"}},
			},
			Input: StreamEndpointConfig{
				Type: "kafka",
				Config: map[string]interface{}{
					"topic": fmt.Sprintf("things.%s.events.%s", td.ID, name),
				},
			},
			Output: StreamEndpointConfig{
				Type: "parquet",
				Config: map[string]interface{}{
					"path": "${PARQUET_LOG_PATH}/events/events_${!timestamp_unix():yyyy-MM-dd}.parquet",
				},
			},
		})
	}

	return streams
}

func init() {
	caddy.RegisterModule(BenthosBindingHandler{})
}
