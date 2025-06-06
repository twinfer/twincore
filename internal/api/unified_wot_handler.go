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

	// User management components
	userHandler         *UserManagementHandler
	authHandler         *AuthHandler
	authProviderHandler *AuthProviderHandler

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
	healthPrefix     = "/health"
	metricsPrefix    = "/metrics"
	usersPrefix      = "/users"
	authPrefix       = "/auth"

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

	// Initialize user management and auth handlers
	securityManager := coreProvider.GetSystemSecurityManager()
	configManager := coreProvider.GetConfigurationManager()
	h.userHandler = NewUserManagementHandler(securityManager, h.logger)
	h.authHandler = NewAuthHandler(h.logger)
	h.authProviderHandler = NewAuthProviderHandler(securityManager, configManager, h.logger)

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

	// Administrative endpoints
	case strings.HasPrefix(path, healthPrefix):
		return h.handleHealth(logger, w, r)
	case strings.HasPrefix(path, metricsPrefix):
		return h.handleMetrics(logger, w, r)

	// User management routes
	case strings.HasPrefix(path, usersPrefix):
		return h.userHandler.handleUserRoutes(logger, w, r, path)
	case strings.HasPrefix(path, authPrefix):
		return h.authHandler.handleAuthRoutes(logger, w, r, path)

	// Auth provider management routes (admin only)
	case strings.HasPrefix(path, "/admin/auth/providers"):
		return h.authProviderHandler.handleAuthProviderRoutes(logger, w, r, strings.TrimPrefix(path, "/admin/auth"))

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

	// Handle /api/things root path (CRUD collection operations)
	if path == "" {
		return h.handleThingCollection(logger, w, r)
	}

	// Extract path parameters using Caddy's mechanism for /api/things/{id}/* paths
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

// @Summary Get Thing Description
// @Description Retrieve a specific Thing Description by ID
// @Tags Things
// @Produce json
// @Param id path string true "Thing ID"
// @Success 200 {object} wot.ThingDescription
// @Failure 404 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /things/{id} [get]
func (h *UnifiedWoTHandler) handleThingDirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID string) error {
	logger.WithField("thing_id", thingID).Debug("Handling direct thing access")

	switch r.Method {
	case http.MethodGet:
		return h.getThingByID(logger, w, r, thingID)
	case http.MethodPut:
		return h.updateThing(logger, w, r, thingID)
	case http.MethodDelete:
		return h.deleteThing(logger, w, r, thingID)
	default:
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

// handleThingCollection handles /api/things collection operations
func (h *UnifiedWoTHandler) handleThingCollection(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	logger.Debug("Handling thing collection operations")

	switch r.Method {
	case http.MethodGet:
		return h.listThings(logger, w, r)
	case http.MethodPost:
		return h.registerThing(logger, w, r)
	default:
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

// getThingByID retrieves a Thing Description by ID
func (h *UnifiedWoTHandler) getThingByID(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID string) error {
	td, err := h.thingRegistry.GetThing(thingID)
	if err != nil {
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(td)
}

// @Summary List all Thing Descriptions
// @Description Retrieve all registered Thing Descriptions
// @Tags Things
// @Produce json
// @Success 200 {array} wot.ThingDescription
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /things [get]
func (h *UnifiedWoTHandler) listThings(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	// Check if registry supports listing
	registryExt, ok := h.thingRegistry.(ThingRegistryExt)
	if !ok {
		return caddyhttp.Error(http.StatusNotImplemented, fmt.Errorf("thing listing not supported"))
	}

	things, err := registryExt.ListThings()
	if err != nil {
		logger.WithError(err).Error("Failed to list things")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(things)
}

// @Summary Register new Thing Description
// @Description Register a new Thing Description and create associated streams
// @Tags Things
// @Accept json
// @Produce json
// @Param td body wot.ThingDescription true "Thing Description"
// @Success 201 {object} wot.ThingDescription
// @Failure 400 {object} types.ErrorResponse
// @Failure 409 {object} types.ErrorResponse
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /things [post]
func (h *UnifiedWoTHandler) registerThing(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	// Check if registry supports registration
	registryExt, ok := h.thingRegistry.(ThingRegistryExt)
	if !ok {
		return caddyhttp.Error(http.StatusNotImplemented, fmt.Errorf("thing registration not supported"))
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	defer r.Body.Close()

	// Register thing using raw JSON-LD
	td, err := registryExt.RegisterThing(string(body))
	if err != nil {
		logger.WithError(err).Error("Failed to register thing")
		// Return appropriate error code based on error type
		if strings.Contains(err.Error(), "already exists") {
			return caddyhttp.Error(http.StatusConflict, err)
		}
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(td)
}

// @Summary Update Thing Description
// @Description Update an existing Thing Description
// @Tags Things
// @Accept json
// @Produce json
// @Param id path string true "Thing ID"
// @Param td body wot.ThingDescription true "Updated Thing Description"
// @Success 200 {object} wot.ThingDescription
// @Failure 400 {object} types.ErrorResponse
// @Failure 404 {object} types.ErrorResponse
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /things/{id} [put]
func (h *UnifiedWoTHandler) updateThing(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID string) error {
	// Check if registry supports updates
	registryExt, ok := h.thingRegistry.(ThingRegistryExt)
	if !ok {
		return caddyhttp.Error(http.StatusNotImplemented, fmt.Errorf("thing updates not supported"))
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	defer r.Body.Close()

	// Update thing using raw JSON-LD
	td, err := registryExt.UpdateThing(thingID, string(body))
	if err != nil {
		logger.WithError(err).WithField("thing_id", thingID).Error("Failed to update thing")
		if strings.Contains(err.Error(), "not found") {
			return caddyhttp.Error(http.StatusNotFound, err)
		}
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(td)
}

// @Summary Delete Thing Description
// @Description Delete a Thing Description and its associated streams
// @Tags Things
// @Param id path string true "Thing ID"
// @Success 204 "No Content"
// @Failure 404 {object} types.ErrorResponse
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /things/{id} [delete]
func (h *UnifiedWoTHandler) deleteThing(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID string) error {
	// Check if registry supports deletion
	registryExt, ok := h.thingRegistry.(ThingRegistryExt)
	if !ok {
		return caddyhttp.Error(http.StatusNotImplemented, fmt.Errorf("thing deletion not supported"))
	}

	err := registryExt.DeleteThing(thingID)
	if err != nil {
		logger.WithError(err).WithField("thing_id", thingID).Error("Failed to delete thing")
		if strings.Contains(err.Error(), "not found") {
			return caddyhttp.Error(http.StatusNotFound, err)
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ============================================================================
// Administrative Endpoints
// ============================================================================

// @Summary System health check
// @Description Get system health status and basic information
// @Tags Admin
// @Produce json
// @Success 200 {object} types.HealthResponse
// @Router /health [get]
func (h *UnifiedWoTHandler) handleHealth(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// For now, always return healthy. In the future, this could check:
	// - Database connectivity
	// - Stream manager status
	// - License validity
	// - Memory usage, etc.

	health := types.NewHealthResponse("healthy", "1.0.0", time.Since(time.Now().Add(-24*time.Hour))) // placeholder uptime

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(health)
}

// @Summary System metrics
// @Description Get system performance metrics and statistics
// @Tags Admin
// @Produce json
// @Success 200 {object} types.MetricsResponse
// @Security BearerAuth
// @Router /metrics [get]
func (h *UnifiedWoTHandler) handleMetrics(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Create metrics response from current handler metrics
	metrics := types.NewMetricsResponse(
		h.metrics.propertyReads,
		h.metrics.propertyWrites,
		h.metrics.actionInvokes,
		h.metrics.eventEmissions,
		h.metrics.errors,
	)

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(metrics)
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

// ReadProperty godoc
//
//	@Summary		Read property value
//	@Description	Reads the current value of a WoT property. Supports real-time observation via Server-Sent Events when Accept header is 'text/event-stream' and property is observable.
//	@Tags			Properties
//	@Accept			json
//	@Produce		json,text/plain,text/event-stream
//	@Param			id		path		string	true	"Thing ID"
//	@Param			name	path		string	true	"Property name"
//	@Param			Accept	header		string	false	"Content type preference - use 'text/event-stream' for real-time observation"
//	@Success		200		{object}	map[string]interface{}	"Property value and timestamp"
//	@Success		200		{string}	string					"Property value as plain text"
//	@Failure		404		{object}	map[string]string		"Property or thing not found"
//	@Failure		406		{object}	map[string]string		"Content type not acceptable"
//	@Failure		500		{object}	map[string]string		"Internal server error"
//	@Security		BearerAuth
//	@Router			/things/{id}/properties/{name} [get]
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

// WriteProperty godoc
//
//	@Summary		Write property value
//	@Description	Updates the value of a WoT property. Property must be writable (not read-only). Value is validated against the property's data schema.
//	@Tags			Properties
//	@Accept			json
//	@Produce		json
//	@Param			id		path	string				true	"Thing ID"
//	@Param			name	path	string				true	"Property name"
//	@Param			value	body	map[string]interface{}	true	"Property value to set - can be raw value or wrapped in {'value': ...}"
//	@Success		204		"Property updated successfully"
//	@Failure		400		{object}	map[string]string	"Invalid request body or validation failed"
//	@Failure		403		{object}	map[string]string	"Property is read-only"
//	@Failure		404		{object}	map[string]string	"Property or thing not found"
//	@Failure		500		{object}	map[string]string	"Internal server error"
//	@Security		BearerAuth
//	@Router			/things/{id}/properties/{name} [put]
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

// InvokeAction godoc
//
//	@Summary		Invoke action
//	@Description	Executes a WoT action on a device. Supports both synchronous and asynchronous execution. Use 'Prefer: respond-async' header for async execution and 'X-Action-Timeout' header to specify custom timeout.
//	@Tags			Actions
//	@Accept			json
//	@Produce		json
//	@Param			id					path	string				true	"Thing ID"
//	@Param			name				path	string				true	"Action name"
//	@Param			input				body	map[string]interface{}	false	"Action input parameters (optional, depends on action definition)"
//	@Param			Prefer				header	string				false	"Use 'respond-async' for asynchronous execution"
//	@Param			X-Action-Timeout	header	string				false	"Custom timeout duration (e.g., '30s', '1m')"
//	@Success		200					{object}	map[string]interface{}	"Action result (synchronous execution)"
//	@Success		202					{object}	map[string]interface{}	"Action accepted for async execution"
//	@Success		204					"Action completed without output"
//	@Failure		400					{object}	map[string]string		"Invalid input or validation failed"
//	@Failure		404					{object}	map[string]string		"Action or thing not found"
//	@Failure		405					{object}	map[string]string		"Method not allowed"
//	@Failure		500					{object}	map[string]string		"Internal server error"
//	@Failure		504					{object}	map[string]string		"Action execution timeout"
//	@Security		BearerAuth
//	@Router			/things/{id}/actions/{name} [post]
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

// SubscribeToEvent godoc
//
//	@Summary		Subscribe to events
//	@Description	Establishes a Server-Sent Events (SSE) stream to receive real-time WoT events from a device. The connection remains open and events are streamed as they occur.
//	@Tags			Events
//	@Accept			json
//	@Produce		text/event-stream
//	@Param			id		path	string	true	"Thing ID"
//	@Param			name	path	string	true	"Event name"
//	@Success		200		{string}	string				"SSE stream established - events will be streamed"
//	@Failure		404		{object}	map[string]string	"Event or thing not found"
//	@Failure		405		{object}	map[string]string	"Method not allowed"
//	@Failure		500		{object}	map[string]string	"Internal server error or streaming not supported"
//	@Security		BearerAuth
//	@Router			/things/{id}/events/{name} [get]
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

// CreateStream godoc
//
//	@Summary		Create stream
//	@Description	Creates a new Benthos data processing stream for a WoT interaction. Streams handle data flow between devices and the platform with configurable processing pipelines.
//	@Tags			Streams
//	@Accept			json
//	@Produce		json
//	@Param			request	body		types.StreamCreationRequest	true	"Stream configuration"
//	@Success		201		{object}	types.StreamInfo			"Stream created successfully"
//	@Failure		400		{object}	map[string]string			"Invalid request body or validation failed"
//	@Failure		404		{object}	map[string]string			"Referenced thing not found"
//	@Failure		500		{object}	map[string]string			"Internal server error"
//	@Security		BearerAuth
//	@Router			/streams [post]
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

// ListStreams godoc
//
//	@Summary		List streams
//	@Description	Retrieves a list of all Benthos streams with optional filtering by thing ID, interaction type, or status
//	@Tags			Streams
//	@Accept			json
//	@Produce		json
//	@Param			thing_id			query		string	false	"Filter by Thing ID"
//	@Param			interaction_type	query		string	false	"Filter by interaction type (properties, actions, events)"
//	@Param			status				query		string	false	"Filter by stream status"
//	@Success		200					{object}	map[string]interface{}	"List of streams with count"
//	@Failure		500					{object}	map[string]string		"Internal server error"
//	@Security		BearerAuth
//	@Router			/streams [get]
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

// CreateProcessorCollection godoc
//
//	@Summary		Create processor collection
//	@Description	Creates a reusable collection of data processors that can be applied to multiple streams. Collections help organize and standardize processing logic across the platform.
//	@Tags			Processors
//	@Accept			json
//	@Produce		json
//	@Param			request	body		types.ProcessorCollectionRequest	true	"Processor collection configuration"
//	@Success		201		{object}	types.ProcessorCollection			"Processor collection created successfully"
//	@Failure		400		{object}	map[string]string					"Invalid request body"
//	@Failure		500		{object}	map[string]string					"Internal server error"
//	@Security		BearerAuth
//	@Router			/processors [post]
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

// ListProcessorCollections godoc
//
//	@Summary		List processor collections
//	@Description	Retrieves all available processor collections with their configurations. These collections can be referenced when creating streams to apply standardized processing logic.
//	@Tags			Processors
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"List of processor collections with count"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Security		BearerAuth
//	@Router			/processors [get]
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

// GetProcessorCollection godoc
//
//	@Summary		Get processor collection
//	@Description	Retrieves detailed information about a specific processor collection including its configuration and all associated processors.
//	@Tags			Processors
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"Processor collection ID"
//	@Success		200	{object}	types.ProcessorCollection	"Processor collection details"
//	@Failure		404	{object}	map[string]string			"Processor collection not found"
//	@Failure		500	{object}	map[string]string			"Internal server error"
//	@Security		BearerAuth
//	@Router			/processors/{id} [get]
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

// GenerateBindingsFromTD godoc
//
//	@Summary		Generate bindings from Thing Description
//	@Description	Automatically generates stream configurations and protocol bindings from a W3C WoT Thing Description. Creates streams for all properties, actions, and events defined in the TD.
//	@Tags			Bindings
//	@Accept			json
//	@Produce		json
//	@Param			request	body		map[string]string		true	"Thing ID to generate bindings for"
//	@Success		200		{object}	map[string]interface{}	"Generated stream configurations with count"
//	@Failure		400		{object}	map[string]string		"Invalid request body"
//	@Failure		404		{object}	map[string]string		"Thing not found"
//	@Failure		500		{object}	map[string]string		"Internal server error"
//	@Security		BearerAuth
//	@Router			/bindings/generate [post]
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
