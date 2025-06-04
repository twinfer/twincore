// internal/api/unified_wot_handler.go
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/internal/models"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// UnifiedWoTHandler consolidates WoT interactions and stream management
// Routes:
//   - /api/things/{id}                      - Thing CRUD operations
//   - /api/things/{id}/properties/{name}    - Property read/write/observe
//   - /api/things/{id}/actions/{name}       - Action invocation
//   - /api/things/{id}/events/{name}        - Event subscription (SSE)
//   - /api/streams                          - Stream management
//   - /api/streams/{id}                     - Stream CRUD
//   - /api/streams/{id}/start               - Stream control
//   - /api/streams/{id}/stop                - Stream control
//   - /api/streams/{id}/status              - Stream status
//   - /api/processors                       - Processor collections
//   - /api/bindings/generate                - Generate bindings from TD
type UnifiedWoTHandler struct {
	// WoT components
	stateManager  StateManager
	streamBridge  StreamBridge
	thingRegistry ThingRegistry
	validator     SchemaValidator
	eventBroker   *EventBroker

	// Stream management components
	streamManager BenthosStreamManager

	// Caching and utilities
	propertyCache *PropertyCache
	logger        *logrus.Logger
	metrics       MetricsCollector
}

// MetricsCollector defines the interface for collecting metrics
type MetricsCollector struct {
	propertyReads  uint64
	propertyWrites uint64
	actionInvokes  uint64
	eventEmissions uint64
	errors         uint64
}

// EventBroker manages SSE connections for events
type EventBroker struct {
	subscribers sync.Map     // map[string][]chan models.Event -> stores []chan models.Event for a given key
	mu          sync.RWMutex // mu protects modifications to the slices stored in subscribers
}

// NewEventBroker creates a new EventBroker
func NewEventBroker() *EventBroker {
	return &EventBroker{} // sync.Map is ready to use from zero value
}

// Subscribe creates a new channel for the given thing and event, adds it to subscribers, and returns it
func (eb *EventBroker) Subscribe(thingID, eventName string) <-chan models.Event {
	key := thingID + "/" + eventName
	ch := make(chan models.Event, 10) // Buffered channel, using models.Event

	eb.mu.Lock()
	defer eb.mu.Unlock()

	var chans []chan models.Event
	if actual, ok := eb.subscribers.Load(key); ok {
		chans = actual.([]chan models.Event)
	}

	// Create a new slice for storing to avoid modifying a potentially shared slice
	newChans := make([]chan models.Event, len(chans)+1)
	copy(newChans, chans)
	newChans[len(chans)] = ch

	eb.subscribers.Store(key, newChans)
	return ch
}

// Unsubscribe removes the given channel from the subscribers list for the specific thing and event
func (eb *EventBroker) Unsubscribe(thingID, eventName string, ch <-chan models.Event) {
	key := thingID + "/" + eventName

	eb.mu.Lock()
	var channelToRemoveAndClose chan models.Event
	if actual, ok := eb.subscribers.Load(key); ok {
		chans := actual.([]chan models.Event)
		newChans := []chan models.Event{}
		found := false
		for _, c := range chans {
			if c == ch {
				found = true
				channelToRemoveAndClose = c
			} else {
				newChans = append(newChans, c)
			}
		}

		if found {
			if len(newChans) == 0 {
				eb.subscribers.Delete(key)
			} else {
				eb.subscribers.Store(key, newChans)
			}
		}
	}
	eb.mu.Unlock()

	// If a channel was identified and removed from the map, close it
	if channelToRemoveAndClose != nil {
		go close(channelToRemoveAndClose)
	}
}

// Publish sends an event to all subscribers of that event
func (eb *EventBroker) Publish(event models.Event) {
	key := event.ThingID + "/" + event.EventName

	var chansCopy []chan models.Event

	eb.mu.RLock()
	if actual, ok := eb.subscribers.Load(key); ok {
		chans := actual.([]chan models.Event)
		// Make a copy of the slice to iterate over
		chansCopy = make([]chan models.Event, len(chans))
		copy(chansCopy, chans)
	}
	eb.mu.RUnlock()

	for _, c := range chansCopy {
		select {
		case c <- event:
		default:
			// Optional: Log or handle slow subscriber
		}
	}
}

// Constants for routing and content types
const (
	// API path prefixes
	apiPrefix        = "/api"
	thingsPrefix     = "/things"
	streamsPrefix    = "/streams"
	processorsPrefix = "/processors"
	bindingsPrefix   = "/bindings"

	// Interaction types
	propertiesType = "properties"
	actionsType    = "actions"
	eventsType     = "events"

	// Headers
	requestIDHeader      = "X-Request-ID"
	headerAccept         = "Accept"
	headerContentType    = "Content-Type"
	headerCacheControl   = "Cache-Control"
	headerConnection     = "Connection"
	headerPrefer         = "Prefer"
	headerLocation       = "Location"
	headerXActionTimeout = "X-Action-Timeout"

	// Content types
	contentTypeJSON        = "application/json"
	contentTypeTextPlain   = "text/plain"
	contentTypeEventStream = "text/event-stream"

	// SSE constants
	sseEventPrefix   = "event: "
	sseDataPrefix    = "data: "
	sseNewline       = "\n"
	sseDoubleNewline = "\n\n"

	// Cache control
	cacheControlNoCache = "no-cache"
	connectionKeepAlive = "keep-alive"
	preferRespondAsync  = "respond-async"
)

// NewUnifiedWoTHandler creates a new unified handler
func NewUnifiedWoTHandler(
	sm StateManager,
	sb StreamBridge,
	tr ThingRegistry,
	streamMgr BenthosStreamManager,
	eb *EventBroker,
	logger *logrus.Logger,
) *UnifiedWoTHandler {
	return &UnifiedWoTHandler{
		stateManager:  sm,
		streamBridge:  sb,
		thingRegistry: tr,
		streamManager: streamMgr,
		eventBroker:   eb,
		logger:        logger,
		validator:     NewJSONSchemaValidator(),
		propertyCache: &PropertyCache{ttl: 5 * time.Second},
	}
}

// CaddyModule returns the Caddy module information
func (UnifiedWoTHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "unified_wot_handler",
		New: func() caddy.Module { return new(UnifiedWoTHandler) },
	}
}

// Provision sets up the handler with dependencies from TwinCore app
func (h *UnifiedWoTHandler) Provision(ctx caddy.Context) error {
	// Initialize components
	h.validator = NewJSONSchemaValidator()
	h.propertyCache = &PropertyCache{ttl: 5 * time.Second}

	// Get dependencies from TwinCore app
	appModule, err := ctx.App("twincore")
	if err != nil {
		return fmt.Errorf("unified_wot_handler: 'twincore' Caddy app module not found: %w", err)
	}

	coreProvider, ok := appModule.(CoreProvider)
	if !ok {
		return fmt.Errorf("unified_wot_handler: 'twincore' Caddy app module does not implement CoreProvider")
	}

	// Assign dependencies
	h.logger = coreProvider.GetLogger()
	h.stateManager = coreProvider.GetStateManager()
	h.streamBridge = coreProvider.GetStreamBridge()
	h.thingRegistry = coreProvider.GetThingRegistry()
	h.eventBroker = coreProvider.GetEventBroker()
	h.streamManager = coreProvider.GetBenthosStreamManager()

	// Validate dependencies
	if h.logger == nil {
		h.logger = logrus.New()
		h.logger.SetLevel(logrus.WarnLevel)
		h.logger.Warn("UnifiedWoTHandler: Logger was nil, using fallback")
	}

	requiredDeps := map[string]any{
		"StateManager":  h.stateManager,
		"StreamBridge":  h.streamBridge,
		"ThingRegistry": h.thingRegistry,
		"EventBroker":   h.eventBroker,
		"StreamManager": h.streamManager,
	}

	for name, dep := range requiredDeps {
		if dep == nil {
			h.logger.Errorf("UnifiedWoTHandler: %s is nil", name)
			return fmt.Errorf("UnifiedWoTHandler: missing %s dependency", name)
		}
	}

	h.logger.Info("UnifiedWoTHandler provisioned successfully")
	return nil
}

// ServeHTTP handles all WoT and stream management requests
func (h *UnifiedWoTHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	requestID := r.Header.Get(requestIDHeader)
	if requestID == "" {
		requestID = uuid.NewString()
	}
	logger := h.logger.WithField("request_id", requestID)

	logger.WithFields(logrus.Fields{
		"handler": "UnifiedWoTHandler",
		"method":  r.Method,
		"path":    r.URL.Path,
	}).Debug("Request received")

	// Route based on path structure
	path := strings.TrimPrefix(r.URL.Path, apiPrefix)

	switch {
	// Thing management routes
	case strings.HasPrefix(path, thingsPrefix):
		return h.handleThingRoutes(logger, w, r, path)

	// Stream management routes
	case strings.HasPrefix(path, streamsPrefix):
		return h.handleStreamRoutes(logger, w, r, path)

	// Processor management routes
	case strings.HasPrefix(path, processorsPrefix):
		return h.handleProcessorRoutes(logger, w, r, path)

	// Binding generation routes
	case strings.HasPrefix(path, bindingsPrefix):
		return h.handleBindingRoutes(logger, w, r, path)

	default:
		logger.WithField("path", path).Warn("Unknown API endpoint")
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown endpoint: %s", path))
	}
}

// handleThingRoutes handles /api/things/* routes
func (h *UnifiedWoTHandler) handleThingRoutes(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, path string) error {
	logger.Debug("Routing thing request")

	// Remove /things prefix
	path = strings.TrimPrefix(path, thingsPrefix)

	// Extract path parameters using Caddy's mechanism
	vars, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]string)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("path variables not available"))
	}

	thingID := vars["id"]
	interactionType := vars["type"]
	name := vars["name"]

	// Route based on interaction type
	switch interactionType {
	case propertiesType:
		return h.handleProperty(logger, w, r, thingID, name)
	case actionsType:
		return h.handleAction(logger, w, r, thingID, name)
	case eventsType:
		return h.handleEvent(logger, w, r, thingID, name)
	case "": // Direct thing access /api/things/{id}
		return h.handleThingDirect(logger, w, r, thingID)
	default:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown interaction type: %s", interactionType))
	}
}

// handleStreamRoutes handles /api/streams/* routes
func (h *UnifiedWoTHandler) handleStreamRoutes(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, path string) error {
	logger.Debug("Routing stream request")

	// Remove /streams prefix
	path = strings.TrimPrefix(path, streamsPrefix)

	switch {
	case path == "" && r.Method == http.MethodPost:
		return h.handleCreateStream(logger, w, r)
	case path == "" && r.Method == http.MethodGet:
		return h.handleListStreams(logger, w, r)
	case strings.HasPrefix(path, "/") && r.Method == http.MethodGet:
		streamID := strings.TrimPrefix(path, "/")
		if strings.Contains(streamID, "/") {
			// Handle sub-operations like /streams/{id}/status
			parts := strings.Split(streamID, "/")
			if len(parts) == 2 {
				streamID, operation := parts[0], parts[1]
				switch operation {
				case "status":
					return h.handleGetStreamStatus(logger, w, r, streamID)
				default:
					return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown stream operation: %s", operation))
				}
			}
		}
		return h.handleGetStream(logger, w, r, streamID)
	case strings.HasPrefix(path, "/") && r.Method == http.MethodPut:
		streamID := strings.TrimPrefix(path, "/")
		return h.handleUpdateStream(logger, w, r, streamID)
	case strings.HasPrefix(path, "/") && r.Method == http.MethodDelete:
		streamID := strings.TrimPrefix(path, "/")
		return h.handleDeleteStream(logger, w, r, streamID)
	case strings.HasSuffix(path, "/start") && r.Method == http.MethodPost:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/start")
		return h.handleStartStream(logger, w, r, streamID)
	case strings.HasSuffix(path, "/stop") && r.Method == http.MethodPost:
		streamID := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/stop")
		return h.handleStopStream(logger, w, r, streamID)
	default:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown stream endpoint"))
	}
}

// handleProcessorRoutes handles /api/processors/* routes
func (h *UnifiedWoTHandler) handleProcessorRoutes(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, path string) error {
	logger.Debug("Routing processor request")

	path = strings.TrimPrefix(path, processorsPrefix)

	switch {
	case path == "" && r.Method == http.MethodPost:
		return h.handleCreateProcessorCollection(logger, w, r)
	case path == "" && r.Method == http.MethodGet:
		return h.handleListProcessorCollections(logger, w, r)
	case strings.HasPrefix(path, "/") && r.Method == http.MethodGet:
		collectionID := strings.TrimPrefix(path, "/")
		return h.handleGetProcessorCollection(logger, w, r, collectionID)
	default:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown processor endpoint"))
	}
}

// handleBindingRoutes handles /api/bindings/* routes
func (h *UnifiedWoTHandler) handleBindingRoutes(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, path string) error {
	logger.Debug("Routing binding request")

	path = strings.TrimPrefix(path, bindingsPrefix)

	switch {
	case path == "/generate" && r.Method == http.MethodPost:
		return h.handleGenerateFromTD(logger, w, r)
	default:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown binding endpoint"))
	}
}

// handleThingDirect handles direct thing access /api/things/{id}
func (h *UnifiedWoTHandler) handleThingDirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID string) error {
	logger.WithField("thing_id", thingID).Debug("Handling direct thing access")

	switch r.Method {
	case http.MethodGet:
		// Get Thing Description
		td, err := h.thingRegistry.GetThing(thingID)
		if err != nil {
			return caddyhttp.Error(http.StatusNotFound, err)
		}

		w.Header().Set(headerContentType, contentTypeJSON)
		return json.NewEncoder(w).Encode(td)

	default:
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

// ============================================================================
// WoT Interaction Handlers (migrated from WoTHandler)
// ============================================================================

// handleProperty handles property read/write operations
func (h *UnifiedWoTHandler) handleProperty(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string) error {
	logger.WithFields(logrus.Fields{
		"handler":       "handleProperty",
		"thing_id":      thingID,
		"property_name": propertyName,
		"method":        r.Method,
	}).Debug("Property request received")

	// Get property definition
	property, err := h.thingRegistry.GetProperty(thingID, propertyName)
	if err != nil {
		logger.WithError(err).Error("Failed to get property definition")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	switch r.Method {
	case http.MethodGet:
		return h.handlePropertyRead(logger, w, r, thingID, propertyName, property)
	case http.MethodPut:
		return h.handlePropertyWrite(logger, w, r, thingID, propertyName, property)
	default:
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

// handlePropertyRead handles GET requests for properties
func (h *UnifiedWoTHandler) handlePropertyRead(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string, property wot.PropertyAffordance) error {
	logger.Debug("Handling property read")

	// Check if observable and client wants SSE
	if property.IsObservable() && r.Header.Get(headerAccept) == contentTypeEventStream {
		return h.handlePropertyObserve(logger, w, r, thingID, propertyName)
	}

	// Get property value
	value, err := h.getPropertyValue(thingID, propertyName)
	if err != nil {
		logger.WithError(err).Error("Failed to get property value")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Content negotiation
	contentType := h.negotiateContentType(r, property)
	w.Header().Set(headerContentType, contentType)

	// Serialize based on content type
	switch contentType {
	case contentTypeJSON:
		return json.NewEncoder(w).Encode(map[string]any{
			"value":     value,
			"timestamp": time.Now().UTC(),
		})
	case contentTypeTextPlain:
		_, err = fmt.Fprintf(w, "%v", value)
		return err
	default:
		return caddyhttp.Error(http.StatusNotAcceptable, fmt.Errorf("unsupported content type"))
	}
}

// handlePropertyWrite handles PUT requests for properties
func (h *UnifiedWoTHandler) handlePropertyWrite(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string, property wot.PropertyAffordance) error {
	logger.Debug("Handling property write")

	// Check if property is writable
	if property.IsReadOnly() {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("property is read-only"))
	}

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Warn("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Deserialize value
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		logger.WithError(err).Warn("Failed to unmarshal JSON")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Extract value if wrapped
	if wrapped, ok := value.(map[string]any); ok {
		if v, exists := wrapped["value"]; exists {
			value = v
		}
	}

	// Validate against schema
	propertySchema := wot.DataSchema{
		DataSchemaCore: property.DataSchemaCore,
		Title:          property.InteractionAffordance.Title,
		Titles:         property.InteractionAffordance.Titles,
		Description:    property.InteractionAffordance.Description,
		Descriptions:   property.InteractionAffordance.Descriptions,
		Comment:        property.InteractionAffordance.Comment,
	}

	if err := h.validator.ValidateProperty(logger, propertyName, propertySchema, value); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("validation failed: %w", err))
	}

	// Create update context
	updateCtx := models.WithUpdateContext(r.Context(), models.NewUpdateContext(models.UpdateSourceHTTP))

	// Update property value
	if err := h.stateManager.SetPropertyWithContext(logger, updateCtx, thingID, propertyName, value); err != nil {
		logger.WithError(err).Error("Failed to set property value")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Publish update to stream
	if err := h.streamBridge.PublishPropertyUpdateWithContext(logger, updateCtx, thingID, propertyName, value); err != nil {
		logger.WithError(err).Warn("Failed to publish property update")
	}

	// Clear cache
	h.propertyCache.cache.Delete(fmt.Sprintf("%s/%s", thingID, propertyName))

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handlePropertyObserve handles SSE subscriptions for observable properties
func (h *UnifiedWoTHandler) handlePropertyObserve(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string) error {
	logger.Debug("Handling property observation via SSE")

	// Set SSE headers
	w.Header().Set(headerContentType, contentTypeEventStream)
	w.Header().Set(headerCacheControl, cacheControlNoCache)
	w.Header().Set(headerConnection, connectionKeepAlive)

	// Subscribe to property updates
	updates, err := h.stateManager.SubscribeProperty(thingID, propertyName)
	if err != nil {
		logger.WithError(err).Error("Failed to subscribe to property")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	defer h.stateManager.UnsubscribeProperty(thingID, propertyName, updates)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
	}

	// Send initial value
	if value, err := h.getPropertyValue(thingID, propertyName); err == nil {
		fmt.Fprintf(w, "%s%s%s", sseDataPrefix, h.encodeSSEData(map[string]any{
			"value":     value,
			"timestamp": time.Now().UTC(),
		}), sseDoubleNewline)
		flusher.Flush()
	}

	// Stream updates
	for {
		select {
		case update := <-updates:
			fmt.Fprintf(w, "%s%s%s", sseDataPrefix, h.encodeSSEData(map[string]any{
				"value":     update.Value,
				"timestamp": update.Timestamp,
			}), sseDoubleNewline)
			flusher.Flush()
		case <-r.Context().Done():
			logger.Debug("SSE connection closed")
			return nil
		}
	}
}

// handleAction handles action invocations
func (h *UnifiedWoTHandler) handleAction(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, actionName string) error {
	logger.WithFields(logrus.Fields{
		"handler":     "handleAction",
		"thing_id":    thingID,
		"action_name": actionName,
	}).Debug("Action request received")

	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Get action definition
	action, err := h.thingRegistry.GetAction(thingID, actionName)
	if err != nil {
		logger.WithError(err).Error("Failed to get action definition")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	var input any
	inputSchema := action.GetInput()

	// Parse request body if present
	if r.ContentLength > 0 {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.WithError(err).Warn("Failed to read request body")
			return caddyhttp.Error(http.StatusBadRequest, err)
		}
		defer r.Body.Close()

		if len(body) > 0 {
			if err := json.Unmarshal(body, &input); err != nil {
				logger.WithError(err).Warn("Failed to unmarshal JSON")
				return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid JSON input: %w", err))
			}
		}
	}

	// Validate input
	if err := h.validator.ValidateActionInput(logger, inputSchema, input); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("validation failed: %w", err))
	}

	// Publish action invocation
	actionID, err := h.streamBridge.PublishActionInvocation(logger, thingID, actionName, input)
	if err != nil {
		logger.WithError(err).Error("Failed to publish action invocation")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	logger = logger.WithField("action_id", actionID)

	// Check if client wants async response
	if r.Header.Get(headerPrefer) == preferRespondAsync {
		w.Header().Set(headerLocation, fmt.Sprintf("/api/things/%s/actions/%s/status/%s", thingID, actionName, actionID))
		w.WriteHeader(http.StatusAccepted)
		return json.NewEncoder(w).Encode(map[string]any{
			"actionId": actionID,
			"status":   "pending",
		})
	}

	// Wait for result with timeout
	timeout := 30 * time.Second
	if t := r.Header.Get(headerXActionTimeout); t != "" {
		if parsed, err := time.ParseDuration(t); err == nil {
			timeout = parsed
		}
	}

	result, err := h.streamBridge.GetActionResult(logger, actionID, timeout)
	if err != nil {
		logger.WithError(err).Error("Failed to get action result")
		return caddyhttp.Error(http.StatusGatewayTimeout, err)
	}

	// Return result
	if action.Output != nil {
		w.Header().Set(headerContentType, contentTypeJSON)
		return json.NewEncoder(w).Encode(result)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleEvent handles event subscriptions
func (h *UnifiedWoTHandler) handleEvent(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, eventName string) error {
	logger.WithFields(logrus.Fields{
		"handler":    "handleEvent",
		"thing_id":   thingID,
		"event_name": eventName,
	}).Debug("Event subscription request received")

	if r.Method != http.MethodGet {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Get event definition
	_, err := h.thingRegistry.GetEvent(thingID, eventName)
	if err != nil {
		logger.WithError(err).Error("Failed to get event definition")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	// Set SSE headers
	w.Header().Set(headerContentType, contentTypeEventStream)
	w.Header().Set(headerCacheControl, cacheControlNoCache)
	w.Header().Set(headerConnection, connectionKeepAlive)

	// Subscribe to events
	eventChan := h.eventBroker.Subscribe(thingID, eventName)
	defer h.eventBroker.Unsubscribe(thingID, eventName, eventChan)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
	}

	logger.Debug("SSE connection established for event stream")

	// Stream events
	for {
		select {
		case evt := <-eventChan:
			fmt.Fprintf(w, "%s%s%s", sseEventPrefix, eventName, sseNewline)
			fmt.Fprintf(w, "%s%s%s", sseDataPrefix, h.encodeSSEData(evt), sseDoubleNewline)
			flusher.Flush()
		case <-r.Context().Done():
			logger.Debug("SSE connection closed")
			return nil
		}
	}
}

// ============================================================================
// Stream Management Handlers (migrated from BenthosBindingHandler)
// ============================================================================

// handleCreateStream handles stream creation
func (h *UnifiedWoTHandler) handleCreateStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.Debug("Handling stream creation")

	var request types.StreamCreationRequest
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON")
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

	stream, err := h.streamManager.CreateStream(r.Context(), request)
	if err != nil {
		logger.WithError(err).Error("Failed to create stream")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(stream)
}

// handleListStreams handles stream listing
func (h *UnifiedWoTHandler) handleListStreams(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.Debug("Handling stream listing")

	filters := types.StreamFilters{
		ThingID:         r.URL.Query().Get("thing_id"),
		InteractionType: r.URL.Query().Get("interaction_type"),
		Status:          r.URL.Query().Get("status"),
	}

	streams, err := h.streamManager.ListStreams(r.Context(), filters)
	if err != nil {
		logger.WithError(err).Error("Failed to list streams")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(map[string]any{
		"streams": streams,
		"count":   len(streams),
	})
}

// handleGetStream handles getting a specific stream
func (h *UnifiedWoTHandler) handleGetStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithField("stream_id", streamID).Debug("Handling get stream")

	stream, err := h.streamManager.GetStream(r.Context(), streamID)
	if err != nil {
		logger.WithError(err).Error("Failed to get stream")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(stream)
}

// handleUpdateStream handles stream updates
func (h *UnifiedWoTHandler) handleUpdateStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithField("stream_id", streamID).Debug("Handling stream update")

	var request types.StreamUpdateRequest
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	stream, err := h.streamManager.UpdateStream(r.Context(), streamID, request)
	if err != nil {
		logger.WithError(err).Error("Failed to update stream")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(stream)
}

// handleDeleteStream handles stream deletion
func (h *UnifiedWoTHandler) handleDeleteStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithField("stream_id", streamID).Debug("Handling stream deletion")

	if err := h.streamManager.DeleteStream(r.Context(), streamID); err != nil {
		logger.WithError(err).Error("Failed to delete stream")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleStartStream handles starting a stream
func (h *UnifiedWoTHandler) handleStartStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithField("stream_id", streamID).Debug("Handling stream start")

	if err := h.streamManager.StartStream(r.Context(), streamID); err != nil {
		logger.WithError(err).Error("Failed to start stream")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleStopStream handles stopping a stream
func (h *UnifiedWoTHandler) handleStopStream(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithField("stream_id", streamID).Debug("Handling stream stop")

	if err := h.streamManager.StopStream(r.Context(), streamID); err != nil {
		logger.WithError(err).Error("Failed to stop stream")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleGetStreamStatus handles getting stream status
func (h *UnifiedWoTHandler) handleGetStreamStatus(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string) error {
	logger.WithField("stream_id", streamID).Debug("Handling get stream status")

	status, err := h.streamManager.GetStreamStatus(r.Context(), streamID)
	if err != nil {
		logger.WithError(err).Error("Failed to get stream status")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(status)
}

// handleCreateProcessorCollection handles processor collection creation
func (h *UnifiedWoTHandler) handleCreateProcessorCollection(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.Debug("Handling processor collection creation")

	var request types.ProcessorCollectionRequest
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	collection, err := h.streamManager.CreateProcessorCollection(r.Context(), request)
	if err != nil {
		logger.WithError(err).Error("Failed to create processor collection")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(collection)
}

// handleListProcessorCollections handles listing processor collections
func (h *UnifiedWoTHandler) handleListProcessorCollections(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.Debug("Handling processor collection listing")

	collections, err := h.streamManager.ListProcessorCollections(r.Context())
	if err != nil {
		logger.WithError(err).Error("Failed to list processor collections")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(map[string]any{
		"collections": collections,
		"count":       len(collections),
	})
}

// handleGetProcessorCollection handles getting a specific processor collection
func (h *UnifiedWoTHandler) handleGetProcessorCollection(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, collectionID string) error {
	logger.WithField("collection_id", collectionID).Debug("Handling get processor collection")

	collection, err := h.streamManager.GetProcessorCollection(r.Context(), collectionID)
	if err != nil {
		logger.WithError(err).Error("Failed to get processor collection")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(collection)
}

// handleGenerateFromTD handles generating streams from Thing Description
func (h *UnifiedWoTHandler) handleGenerateFromTD(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.Debug("Handling TD-to-stream generation")

	var request struct {
		ThingID string `json:"thing_id"`
	}
	if err := h.decodeJSON(r, &request); err != nil {
		logger.WithError(err).Warn("Failed to decode JSON")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Get Thing Description
	td, err := h.thingRegistry.GetThing(request.ThingID)
	if err != nil {
		logger.WithError(err).Error("Failed to get Thing Description")
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("thing not found: %s", request.ThingID))
	}

	// Generate stream configurations
	streamConfigs := h.generateStreamsFromTD(td)

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(map[string]any{
		"thing_id": request.ThingID,
		"streams":  streamConfigs,
		"count":    len(streamConfigs),
	})
}

// ============================================================================
// Helper Methods and Utilities
// ============================================================================

// PropertyCache provides fast property access
type PropertyCache struct {
	cache sync.Map
	ttl   time.Duration
}

type PropertyValue struct {
	Value     any
	UpdatedAt time.Time
}

// getPropertyValue retrieves property value with caching
func (h *UnifiedWoTHandler) getPropertyValue(thingID, propertyName string) (any, error) {
	cacheKey := fmt.Sprintf("%s/%s", thingID, propertyName)

	// Check cache
	if cached, ok := h.propertyCache.cache.Load(cacheKey); ok {
		pv := cached.(PropertyValue)
		if time.Since(pv.UpdatedAt) < h.propertyCache.ttl {
			return pv.Value, nil
		}
	}

	// Get from state manager
	value, err := h.stateManager.GetProperty(thingID, propertyName)
	if err != nil {
		return nil, err
	}

	// Update cache
	h.propertyCache.cache.Store(cacheKey, PropertyValue{
		Value:     value,
		UpdatedAt: time.Now(),
	})

	return value, nil
}

// negotiateContentType determines the best content type for the response
func (h *UnifiedWoTHandler) negotiateContentType(r *http.Request, property wot.PropertyAffordance) string {
	accept := r.Header.Get(headerAccept)
	if accept == "" || accept == "*/*" {
		accept = contentTypeJSON
	}

	var httpForms []wot.Form
	for _, form := range property.GetForms() {
		protocol := form.GetProtocol()
		if protocol == "http" || protocol == "https" {
			httpForms = append(httpForms, form)
		}
	}

	// Prefer forms that match the Accept header
	for _, form := range httpForms {
		if strings.Contains(accept, form.GetContentType()) {
			return form.GetContentType()
		}
	}

	// JSON fallback
	if strings.Contains(accept, contentTypeJSON) {
		for _, form := range httpForms {
			if form.GetContentType() == contentTypeJSON {
				return contentTypeJSON
			}
		}
	}

	// Use first HTTP form or JSON fallback
	if len(httpForms) > 0 {
		return httpForms[0].GetContentType()
	}

	return contentTypeJSON
}

// encodeSSEData encodes data for Server-Sent Events
func (h *UnifiedWoTHandler) encodeSSEData(data any) string {
	encoded, _ := json.Marshal(data)
	return string(encoded)
}

// decodeJSON helper for JSON decoding
func (h *UnifiedWoTHandler) decodeJSON(r *http.Request, target any) error {
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

// validateInteraction validates that an interaction exists on a thing
func (h *UnifiedWoTHandler) validateInteraction(thingID, interactionType, interactionName string) error {
	switch interactionType {
	case propertiesType:
		_, err := h.thingRegistry.GetProperty(thingID, interactionName)
		return err
	case actionsType:
		_, err := h.thingRegistry.GetAction(thingID, interactionName)
		return err
	case eventsType:
		_, err := h.thingRegistry.GetEvent(thingID, interactionName)
		return err
	default:
		return fmt.Errorf("invalid interaction type: %s", interactionType)
	}
}

// generateStreamsFromTD generates stream configurations from Thing Description
func (h *UnifiedWoTHandler) generateStreamsFromTD(td *wot.ThingDescription) []types.StreamCreationRequest {
	var streams []types.StreamCreationRequest

	// Generate property streams
	for name, property := range td.Properties {
		if property.IsObservable() {
			// Property output stream (device -> platform)
			streams = append(streams, types.StreamCreationRequest{
				ThingID:         td.ID,
				InteractionType: propertiesType,
				InteractionName: name,
				Direction:       "input",
				ProcessorChain: []types.ProcessorConfig{
					{Type: "license_check", Config: map[string]any{"feature": "property_ingestion"}},
					{Type: "json_validation", Config: map[string]any{"schema": property.DataSchemaCore}},
					{Type: "parquet_encode", Config: map[string]any{"schema": "property_schema"}},
				},
				Input: types.StreamEndpointConfig{
					Type: "kafka",
					Config: map[string]any{
						"topic": fmt.Sprintf("things.%s.properties.%s", td.ID, name),
					},
				},
				Output: types.StreamEndpointConfig{
					Type: "parquet",
					Config: map[string]any{
						"path": "${PARQUET_LOG_PATH}/properties/props_${!timestamp_unix():yyyy-MM-dd}.parquet",
					},
				},
			})
		}

		if !property.IsReadOnly() {
			// Property input stream (platform -> device)
			streams = append(streams, types.StreamCreationRequest{
				ThingID:         td.ID,
				InteractionType: propertiesType,
				InteractionName: name,
				Direction:       "output",
				ProcessorChain: []types.ProcessorConfig{
					{Type: "license_check", Config: map[string]any{"feature": "property_commands"}},
					{Type: "json_validation", Config: map[string]any{"schema": property.DataSchemaCore}},
				},
				Input: types.StreamEndpointConfig{
					Type: "http",
					Config: map[string]any{
						"path": fmt.Sprintf("/api/things/%s/properties/%s", td.ID, name),
					},
				},
				Output: types.StreamEndpointConfig{
					Type: "kafka",
					Config: map[string]any{
						"topic": fmt.Sprintf("things.%s.properties.%s.commands", td.ID, name),
					},
				},
			})
		}
	}

	// Generate action streams
	for name, action := range td.Actions {
		streams = append(streams, types.StreamCreationRequest{
			ThingID:         td.ID,
			InteractionType: actionsType,
			InteractionName: name,
			Direction:       "bidirectional",
			ProcessorChain: []types.ProcessorConfig{
				{Type: "license_check", Config: map[string]any{"feature": "action_invocation"}},
				{Type: "json_validation", Config: map[string]any{"schema": action.GetInput()}},
				{Type: "action_tracker", Config: map[string]any{"timeout": "30s"}},
			},
			Input: types.StreamEndpointConfig{
				Type: "http",
				Config: map[string]any{
					"path": fmt.Sprintf("/api/things/%s/actions/%s", td.ID, name),
				},
			},
			Output: types.StreamEndpointConfig{
				Type: "kafka",
				Config: map[string]any{
					"topic": fmt.Sprintf("things.%s.actions.%s", td.ID, name),
				},
			},
		})
	}

	// Generate event streams
	for name := range td.Events {
		streams = append(streams, types.StreamCreationRequest{
			ThingID:         td.ID,
			InteractionType: eventsType,
			InteractionName: name,
			Direction:       "input",
			ProcessorChain: []types.ProcessorConfig{
				{Type: "license_check", Config: map[string]any{"feature": "event_processing"}},
				{Type: "event_enrichment", Config: map[string]any{}},
				{Type: "parquet_encode", Config: map[string]any{"schema": "event_schema"}},
			},
			Input: types.StreamEndpointConfig{
				Type: "kafka",
				Config: map[string]any{
					"topic": fmt.Sprintf("things.%s.events.%s", td.ID, name),
				},
			},
			Output: types.StreamEndpointConfig{
				Type: "parquet",
				Config: map[string]any{
					"path": "${PARQUET_LOG_PATH}/events/events_${!timestamp_unix():yyyy-MM-dd}.parquet",
				},
			},
		})
	}

	return streams
}

func init() {
	caddy.RegisterModule(UnifiedWoTHandler{})
}
