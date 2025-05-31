package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

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

// BenthosStreamManager manages Benthos stream lifecycle
// This extends the basic interface from pkg/types with additional methods
type BenthosStreamManager interface {
	types.BenthosStreamManager

	// Additional methods for stream management
	UpdateStream(ctx context.Context, streamID string, request StreamUpdateRequest) (*StreamInfo, error)

	// Processor collection
	CreateProcessorCollection(ctx context.Context, request ProcessorCollectionRequest) (*ProcessorCollection, error)
	GetProcessorCollection(ctx context.Context, collectionID string) (*ProcessorCollection, error)
	ListProcessorCollections(ctx context.Context) ([]ProcessorCollection, error)

	// Stream operations
	StartStream(ctx context.Context, streamID string) error
	StopStream(ctx context.Context, streamID string) error
	GetStreamStatus(ctx context.Context, streamID string) (*StreamStatus, error)
}

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
	// Extract path from request URL
	path := strings.TrimPrefix(r.URL.Path, "/wot/binding")

	// Route based on path
	switch {
	case path == "/streams" && r.Method == http.MethodPost:
		return h.handleCreateStream(w, r)
	case path == "/streams" && r.Method == http.MethodGet:
		return h.handleListStreams(w, r)
	case strings.HasPrefix(path, "/streams/") && r.Method == http.MethodGet:
		streamID := strings.TrimPrefix(path, "/streams/")
		return h.handleGetStream(w, r, streamID)
	case strings.HasPrefix(path, "/streams/") && r.Method == http.MethodPut:
		streamID := strings.TrimPrefix(path, "/streams/")
		return h.handleUpdateStream(w, r, streamID)
	case strings.HasPrefix(path, "/streams/") && r.Method == http.MethodDelete:
		streamID := strings.TrimPrefix(path, "/streams/")
		return h.handleDeleteStream(w, r, streamID)
	case strings.HasSuffix(path, "/start") && r.Method == http.MethodPost:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/streams/"), "/start")
		return h.handleStartStream(w, r, streamID)
	case strings.HasSuffix(path, "/stop") && r.Method == http.MethodPost:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/streams/"), "/stop")
		return h.handleStopStream(w, r, streamID)
	case strings.HasSuffix(path, "/status") && r.Method == http.MethodGet:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/streams/"), "/status")
		return h.handleGetStreamStatus(w, r, streamID)
	case path == "/processors" && r.Method == http.MethodPost:
		return h.handleCreateProcessorCollection(w, r)
	case path == "/processors" && r.Method == http.MethodGet:
		return h.handleListProcessorCollections(w, r)
	case strings.HasPrefix(path, "/processors/") && r.Method == http.MethodGet:
		collectionID := strings.TrimPrefix(path, "/processors/")
		return h.handleGetProcessorCollection(w, r, collectionID)
	case path == "/generate" && r.Method == http.MethodPost:
		return h.handleGenerateFromTD(w, r)
	default:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("endpoint not found"))
	}
}

// Stream management handlers

func (h *BenthosBindingHandler) handleCreateStream(w http.ResponseWriter, r *http.Request) error {
	var request StreamCreationRequest
	if err := h.decodeJSON(r, &request); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Validate Thing exists
	if _, err := h.thingRegistry.GetThing(request.ThingID); err != nil {
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("thing not found: %s", request.ThingID))
	}

	// Validate interaction exists
	if err := h.validateInteraction(request.ThingID, request.InteractionType, request.InteractionName); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	stream, err := h.streamManager.CreateStream(r.Context(), request)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(stream)
}

func (h *BenthosBindingHandler) handleListStreams(w http.ResponseWriter, r *http.Request) error {
	// Parse query filters
	filters := StreamFilters{
		ThingID:         r.URL.Query().Get("thing_id"),
		InteractionType: r.URL.Query().Get("interaction_type"),
		Status:          r.URL.Query().Get("status"),
	}

	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	streams, err := h.streamManager.ListStreams(r.Context(), filters)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"streams": streams,
		"count":   len(streams),
	})
}

func (h *BenthosBindingHandler) handleGetStream(w http.ResponseWriter, r *http.Request, streamID string) error {
	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	stream, err := h.streamManager.GetStream(r.Context(), streamID)
	if err != nil {
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(stream)
}

func (h *BenthosBindingHandler) handleUpdateStream(w http.ResponseWriter, r *http.Request, streamID string) error {
	var request StreamUpdateRequest
	if err := h.decodeJSON(r, &request); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	stream, err := h.streamManager.UpdateStream(r.Context(), streamID, request)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(stream)
}

func (h *BenthosBindingHandler) handleDeleteStream(w http.ResponseWriter, r *http.Request, streamID string) error {
	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	if err := h.streamManager.DeleteStream(r.Context(), streamID); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *BenthosBindingHandler) handleStartStream(w http.ResponseWriter, r *http.Request, streamID string) error {
	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	if err := h.streamManager.StartStream(r.Context(), streamID); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *BenthosBindingHandler) handleStopStream(w http.ResponseWriter, r *http.Request, streamID string) error {
	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	if err := h.streamManager.StopStream(r.Context(), streamID); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *BenthosBindingHandler) handleGetStreamStatus(w http.ResponseWriter, r *http.Request, streamID string) error {
	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	status, err := h.streamManager.GetStreamStatus(r.Context(), streamID)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(status)
}

// Processor collection handlers

func (h *BenthosBindingHandler) handleCreateProcessorCollection(w http.ResponseWriter, r *http.Request) error {
	var request ProcessorCollectionRequest
	if err := h.decodeJSON(r, &request); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	collection, err := h.streamManager.CreateProcessorCollection(r.Context(), request)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(collection)
}

func (h *BenthosBindingHandler) handleListProcessorCollections(w http.ResponseWriter, r *http.Request) error {
	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	collections, err := h.streamManager.ListProcessorCollections(r.Context())
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"collections": collections,
		"count":       len(collections),
	})
}

func (h *BenthosBindingHandler) handleGetProcessorCollection(w http.ResponseWriter, r *http.Request, collectionID string) error {
	if h.streamManager == nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("stream manager not available"))
	}

	collection, err := h.streamManager.GetProcessorCollection(r.Context(), collectionID)
	if err != nil {
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(collection)
}

// Special handler for generating streams from Thing Description

func (h *BenthosBindingHandler) handleGenerateFromTD(w http.ResponseWriter, r *http.Request) error {
	var request struct {
		ThingID string `json:"thing_id"`
	}
	if err := h.decodeJSON(r, &request); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Get Thing Description
	td, err := h.thingRegistry.GetThing(request.ThingID)
	if err != nil {
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("thing not found: %s", request.ThingID))
	}

	// Generate stream configurations from TD
	streamConfigs := h.generateStreamsFromTD(td)

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
