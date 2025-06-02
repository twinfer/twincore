// // internal/api/wot_handler.go
package api

// import (
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"net/http"
// 	"strings"
// 	"sync"
// 	"time"

// 	"github.com/caddyserver/caddy/v2"
// 	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
// 	"github.com/google/uuid"
// 	"github.com/sirupsen/logrus"

// 	// Import the caddy_app package
// 	"github.com/twinfer/twincore/internal/models" // Added for models.Event
// 	"github.com/twinfer/twincore/pkg/wot"
// )

// // Constants for interaction types, HTTP headers, content types, and SSE elements
// const (
// 	interactionTypeProperties = "properties"
// 	interactionTypeActions    = "actions"
// 	interactionTypeEvents     = "events"

// 	headerAccept         = "Accept"
// 	headerContentType    = "Content-Type"
// 	headerCacheControl   = "Cache-Control"
// 	headerConnection     = "Connection"
// 	headerPrefer         = "Prefer"
// 	headerLocation       = "Location"
// 	headerXActionTimeout = "X-Action-Timeout"

// 	contentTypeJSON        = "application/json"
// 	contentTypeTextPlain   = "text/plain"
// 	contentTypeEventStream = "text/event-stream"

// 	sseEventPrefix   = "event: "
// 	sseDataPrefix    = "data: "
// 	sseNewline       = "\n"
// 	sseDoubleNewline = "\n\n"

// 	cacheControlNoCache = "no-cache"
// 	connectionKeepAlive = "keep-alive"
// 	preferRespondAsync  = "respond-async"
// )

// // WoTHandler manages all WoT interactions
// type WoTHandler struct {
// 	// Core components
// 	stateManager  StateManager
// 	streamBridge  StreamBridge
// 	thingRegistry ThingRegistry
// 	validator     SchemaValidator

// 	// Caching
// 	propertyCache *PropertyCache

// 	// Event management
// 	eventBroker *EventBroker
// 	logger      *logrus.Logger

// 	// Metrics (Placeholder)
// 	metrics MetricsCollector
// }

// // StateManager, StreamBridge, ThingRegistry, SchemaValidator interfaces are now defined in interfaces.go

// // PropertyCache provides fast property access
// type PropertyCache struct {
// 	cache sync.Map // map[string]PropertyValue
// 	ttl   time.Duration
// }

// type PropertyValue struct {
// 	Value     interface{}
// 	UpdatedAt time.Time
// }

// // EventBroker manages SSE connections for events
// type EventBroker struct {
// 	subscribers sync.Map     // map[string][]chan models.Event -> stores []chan models.Event for a given key
// 	mu          sync.RWMutex // mu protects modifications to the slices stored in subscribers
// }

// // NewEventBroker creates a new EventBroker.
// // Note: WoTHandler.Provision already initializes its eventBroker field.
// // This constructor is provided if EventBroker needs to be created independently.
// func NewEventBroker() *EventBroker {
// 	return &EventBroker{} // sync.Map is ready to use from zero value
// }

// // Subscribe creates a new channel for the given thing and event, adds it to subscribers, and returns it.
// func (eb *EventBroker) Subscribe(thingID, eventName string) <-chan models.Event {
// 	key := thingID + "/" + eventName
// 	ch := make(chan models.Event, 10) // Buffered channel, using models.Event

// 	eb.mu.Lock()
// 	defer eb.mu.Unlock()

// 	var chans []chan models.Event
// 	if actual, ok := eb.subscribers.Load(key); ok {
// 		chans = actual.([]chan models.Event)
// 	}

// 	// Create a new slice for storing to avoid modifying a potentially shared slice
// 	newChans := make([]chan models.Event, len(chans)+1)
// 	copy(newChans, chans)
// 	newChans[len(chans)] = ch

// 	eb.subscribers.Store(key, newChans)
// 	return ch
// }

// // Unsubscribe removes the given channel from the subscribers list for the specific thing and event.
// // It also closes the channel.
// func (eb *EventBroker) Unsubscribe(thingID, eventName string, ch <-chan models.Event) {
// 	key := thingID + "/" + eventName

// 	eb.mu.Lock()
// 	var channelToRemoveAndClose chan models.Event // To store the actual chan models.Event from the map
// 	if actual, ok := eb.subscribers.Load(key); ok {
// 		chans := actual.([]chan models.Event)
// 		newChans := []chan models.Event{}
// 		found := false
// 		for _, c := range chans {
// 			if c == ch {
// 				found = true
// 				channelToRemoveAndClose = c // This is the chan models.Event from the map
// 			} else {
// 				newChans = append(newChans, c)
// 			}
// 		}

// 		if found {
// 			if len(newChans) == 0 {
// 				eb.subscribers.Delete(key)
// 			} else {
// 				eb.subscribers.Store(key, newChans)
// 			}
// 			// Note: channelToRemoveAndClose is now set if found was true.
// 		}
// 	}
// 	eb.mu.Unlock()

// 	// If a channel was identified and removed from the map, close it.
// 	if channelToRemoveAndClose != nil {
// 		go close(channelToRemoveAndClose) // Close the actual `chan models.Event`
// 	}
// }

// // Publish sends an event to all subscribers of that event.
// // It uses a non-blocking send.
// func (eb *EventBroker) Publish(event models.Event) {
// 	key := event.ThingID + "/" + event.EventName

// 	var chansCopy []chan models.Event

// 	eb.mu.RLock()
// 	if actual, ok := eb.subscribers.Load(key); ok {
// 		chans := actual.([]chan models.Event)
// 		// Make a copy of the slice to iterate over,
// 		// so we don't hold the lock while sending to channels.
// 		chansCopy = make([]chan models.Event, len(chans))
// 		copy(chansCopy, chans)
// 	}
// 	eb.mu.RUnlock()

// 	for _, c := range chansCopy {
// 		select {
// 		case c <- event:
// 		default:
// 			// Optional: Log or handle slow subscriber.
// 			// fmt.Printf("EventBroker: Slow subscriber or closed channel for key %s\n", key)
// 		}
// 	}
// }

// // NewWoTHandler creates a new WoTHandler with its dependencies.
// // This constructor is used when the WoTHandler is managed by the application container,
// // as opposed to being solely provisioned by Caddy.
// func NewWoTHandler(
// 	sm StateManager,
// 	sb StreamBridge,
// 	tr ThingRegistry,
// 	eb *EventBroker,
// 	logger *logrus.Logger,
// ) *WoTHandler {
// 	return &WoTHandler{
// 		stateManager:  sm,
// 		streamBridge:  sb,
// 		thingRegistry: tr,
// 		eventBroker:   eb,
// 		logger:        logger,
// 		validator:     NewJSONSchemaValidator(),             // Initialize the validator
// 		propertyCache: &PropertyCache{ttl: 5 * time.Second}, // Initialize property cache
// 		// metrics field is a struct, not a pointer, so it's zero-value initialized.
// 		// If MetricsCollector needs specific construction, do it here.
// 	}
// }

// // CaddyModule returns the Caddy module information
// func (WoTHandler) CaddyModule() caddy.ModuleInfo {
// 	return caddy.ModuleInfo{
// 		ID:  "core_wot_handler", // Changed ID
// 		New: func() caddy.Module { return new(WoTHandler) },
// 	}
// }

// // Provision sets up the handler
// func (h *WoTHandler) Provision(ctx caddy.Context) error {
// 	// Initialize components
// 	h.validator = NewJSONSchemaValidator()                 // Ensure validator is initialized
// 	h.propertyCache = &PropertyCache{ttl: 5 * time.Second} // Default TTL

// 	// Attempt to get the main "twincore" Caddy app module
// 	appModule, err := ctx.App("twincore")
// 	if err != nil {
// 		// If the app module itself isn't found, it's a fundamental setup error.
// 		// A basic logger can be used for this specific error.
// 		localLogger := logrus.New()
// 		localLogger.SetLevel(logrus.ErrorLevel)
// 		localLogger.Errorf("WoTHandler: 'twincore' Caddy app module not found: %v. This is a critical configuration error.", err)
// 		return fmt.Errorf("WoTHandler: 'twincore' Caddy app module not found: %w", err)
// 	}

// 	coreProvider, ok := appModule.(CoreProvider) // Type assert to the interface defined in `api` package
// 	if !ok {
// 		localLogger := logrus.New()
// 		localLogger.SetLevel(logrus.ErrorLevel)
// 		localLogger.Errorf("WoTHandler: 'twincore' Caddy app module does not implement api.CoreProvider. Type is %T", appModule)
// 		return fmt.Errorf("WoTHandler: 'twincore' Caddy app module does not implement api.CoreProvider")
// 	}

// 	// Now, assign dependencies from the twinCoreApp
// 	h.logger = coreProvider.GetLogger()
// 	h.stateManager = coreProvider.GetStateManager()
// 	h.streamBridge = coreProvider.GetStreamBridge()
// 	h.thingRegistry = coreProvider.GetThingRegistry()
// 	h.eventBroker = coreProvider.GetEventBroker()

// 	// Validate that all dependencies were successfully assigned
// 	if h.logger == nil {
// 		// This case should ideally not happen if TwinCoreApp.Provision ensures Logger is set
// 		h.logger = logrus.New()
// 		h.logger.SetLevel(logrus.WarnLevel) // Default to Warn if main logger isn't available
// 		h.logger.Warn("WoTHandler: Logger was nil after retrieving from CoreProvider, using fallback.")
// 	}
// 	if h.stateManager == nil {
// 		h.logger.Error("WoTHandler: StateManager is nil after retrieving from TwinCoreApp.")
// 		return fmt.Errorf("WoTHandler: missing StateManager dependency from TwinCoreApp")
// 	}
// 	if h.streamBridge == nil {
// 		h.logger.Error("WoTHandler: StreamBridge is nil after retrieving from TwinCoreApp.")
// 		return fmt.Errorf("WoTHandler: missing StreamBridge dependency from TwinCoreApp")
// 	}
// 	if h.thingRegistry == nil {
// 		h.logger.Error("WoTHandler: ThingRegistry is nil after retrieving from TwinCoreApp.")
// 		return fmt.Errorf("WoTHandler: missing ThingRegistry dependency from TwinCoreApp")
// 	}
// 	if h.eventBroker == nil {
// 		h.logger.Error("WoTHandler: EventBroker is nil after retrieving from TwinCoreApp.")
// 		return fmt.Errorf("WoTHandler: missing EventBroker dependency from TwinCoreApp")
// 	}
// 	h.logger.Info("CoreWoTHandler provisioned with dependencies from Caddy app context.")
// 	return nil
// }

// // ServeHTTP handles WoT requests
// func (h *WoTHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
// 	requestID := r.Header.Get(RequestIDHeader)
// 	if requestID == "" {
// 		requestID = uuid.NewString()
// 	}
// 	handlerLogger := h.logger.WithField("request_id", requestID)

// 	handlerLogger.WithFields(logrus.Fields{"handler_name": "WoTHandler.ServeHTTP", "method": r.Method, "path": r.URL.Path}).Debug("Handler called")
// 	defer handlerLogger.WithFields(logrus.Fields{"handler_name": "WoTHandler.ServeHTTP"}).Debug("Handler finished")

// 	// Extract path parameters using Caddy's mechanism
// 	vars, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]string)
// 	if !ok {
// 		handlerLogger.Error("Path variables not available in request context")
// 		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("path variables not available"))
// 	}
// 	thingID := vars["id"]           // Key "id" as per WoTMapper pattern /things/{id}/...
// 	interactionType := vars["type"] // Key "type" as per WoTMapper pattern /things/{id}/{type}/...
// 	name := vars["name"]            // Key "name" as per WoTMapper pattern /things/{id}/{type}/{name}

// 	// Pass the request-specific logger down
// 	// Route based on interaction type
// 	switch interactionType {
// 	case interactionTypeProperties:
// 		return h.handleProperty(handlerLogger, w, r, thingID, name)
// 	case interactionTypeActions:
// 		return h.handleAction(handlerLogger, w, r, thingID, name)
// 	case interactionTypeEvents:
// 		return h.handleEvent(handlerLogger, w, r, thingID, name)
// 	default:
// 		handlerLogger.WithField("interaction_type", interactionType).Warn("Unknown interaction type requested")
// 		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown interaction type: %s", interactionType))
// 	}
// }

// // handleProperty handles property read/write operations
// func (h *WoTHandler) handleProperty(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string) error {
// 	logger.WithFields(logrus.Fields{"handler_name": "handleProperty", "thing_id": thingID, "property_name": propertyName, "method": r.Method}).Debug("Handler called")
// 	defer logger.WithFields(logrus.Fields{"handler_name": "handleProperty"}).Debug("Handler finished")

// 	// Get property definition
// 	logger.WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetProperty", "thing_id": thingID, "property_name": propertyName}).Debug("Calling service")
// 	property, err := h.thingRegistry.GetProperty(thingID, propertyName)
// 	if err != nil {
// 		logger.WithError(err).WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetProperty", "thing_id": thingID, "property_name": propertyName}).Error("Service call returned error")
// 		return caddyhttp.Error(http.StatusNotFound, err)
// 	}

// 	switch r.Method {
// 	case http.MethodGet:
// 		return h.handlePropertyRead(logger, w, r, thingID, propertyName, property)
// 	case http.MethodPut:
// 		return h.handlePropertyWrite(logger, w, r, thingID, propertyName, property)
// 	default:
// 		logger.WithField("method", r.Method).Warn("Method not allowed for property interaction")
// 		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
// 	}
// }

// // handlePropertyRead handles GET requests for properties
// func (h *WoTHandler) handlePropertyRead(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string, property wot.PropertyAffordance) error {
// 	logger.WithFields(logrus.Fields{"handler_name": "handlePropertyRead", "thing_id": thingID, "property_name": propertyName}).Debug("Handler called")
// 	defer logger.WithFields(logrus.Fields{"handler_name": "handlePropertyRead"}).Debug("Handler finished")

// 	// Check if observable and client wants SSE
// 	if property.IsObservable() && r.Header.Get(headerAccept) == contentTypeEventStream {
// 		return h.handlePropertyObserve(logger, w, r, thingID, propertyName)
// 	}

// 	// Get property value from cache or state manager
// 	logger.WithFields(logrus.Fields{"method_name": "getPropertyValue", "thing_id": thingID, "property_name": propertyName}).Debug("Calling internal method")
// 	value, err := h.getPropertyValue(thingID, propertyName) // Assuming getPropertyValue doesn't need request-scoped logger for now
// 	if err != nil {
// 		logger.WithError(err).WithFields(logrus.Fields{"method_name": "getPropertyValue", "thing_id": thingID, "property_name": propertyName}).Error("Internal method call returned error")
// 		return caddyhttp.Error(http.StatusInternalServerError, err)
// 	}

// 	// Content negotiation
// 	contentType := h.negotiateContentType(r, property)
// 	w.Header().Set(headerContentType, contentType)

// 	// Serialize based on content type
// 	switch contentType {
// 	case contentTypeJSON:
// 		return json.NewEncoder(w).Encode(map[string]interface{}{
// 			"value":     value,
// 			"timestamp": time.Now().UTC(),
// 		})
// 	case contentTypeTextPlain:
// 		_, err = fmt.Fprintf(w, "%v", value)
// 		return err
// 	default:
// 		return caddyhttp.Error(http.StatusNotAcceptable, fmt.Errorf("unsupported content type"))
// 	}
// }

// // handlePropertyWrite handles PUT requests for properties
// func (h *WoTHandler) handlePropertyWrite(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string, property wot.PropertyAffordance) error {
// 	logger.WithFields(logrus.Fields{"handler_name": "handlePropertyWrite", "thing_id": thingID, "property_name": propertyName}).Debug("Handler called")
// 	defer logger.WithFields(logrus.Fields{"handler_name": "handlePropertyWrite"}).Debug("Handler finished")

// 	// Check if property is writable
// 	if property.IsReadOnly() {
// 		logger.Warn("Attempt to write to read-only property")
// 		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("property is read-only"))
// 	}

// 	// Parse request body
// 	body, err := io.ReadAll(r.Body)
// 	if err != nil {
// 		logger.WithError(err).Warn("Failed to read request body for property write")
// 		return caddyhttp.Error(http.StatusBadRequest, err)
// 	}

// 	// Deserialize value
// 	var value interface{}
// 	if err := json.Unmarshal(body, &value); err != nil {
// 		logger.WithError(err).Warn("Failed to unmarshal JSON for property write")
// 		return caddyhttp.Error(http.StatusBadRequest, err)
// 	}

// 	// Extract value if wrapped
// 	if wrapped, ok := value.(map[string]interface{}); ok {
// 		if v, exists := wrapped["value"]; exists {
// 			value = v
// 		}
// 	}

// 	// Validate against schema
// 	// Construct a wot.DataSchema from the PropertyAffordance
// 	propertySchemaForValidation := wot.DataSchema{
// 		DataSchemaCore: property.DataSchemaCore,
// 		Title:          property.InteractionAffordance.Title,
// 		Titles:         property.InteractionAffordance.Titles,
// 		Description:    property.InteractionAffordance.Description,
// 		Descriptions:   property.InteractionAffordance.Descriptions,
// 		Comment:        property.InteractionAffordance.Comment,
// 	}
// 	logger.WithField("property_name_for_validation", propertyName).Debug("Validating property against schema")
// 	if err := h.validator.ValidateProperty(logger, propertyName, propertySchemaForValidation, value); err != nil {
// 		// Logger inside ValidateProperty already logs details of validation_errors at Warn level
// 		// Here we log that the validation step failed at a higher level if needed, or just return.
// 		// The logger passed to ValidateProperty will contain request_id.
// 		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("validation failed for property %s: %w", propertyName, err))
// 	}

// 	// Create update context to track source
// 	updateCtx := models.WithUpdateContext(r.Context(), models.NewUpdateContext(models.UpdateSourceHTTP))

// 	// Update property value with context
// 	logger.WithFields(logrus.Fields{"service_name": "StateManager", "method_name": "SetPropertyWithContext", "thing_id": thingID, "property_name": propertyName}).Debug("Calling service")
// 	if err := h.stateManager.SetPropertyWithContext(logger, updateCtx, thingID, propertyName, value); err != nil { // Pass logger
// 		logger.WithError(err).WithFields(logrus.Fields{"service_name": "StateManager", "method_name": "SetPropertyWithContext", "thing_id": thingID, "property_name": propertyName}).Error("Service call returned error")
// 		return caddyhttp.Error(http.StatusInternalServerError, err)
// 	}

// 	// Publish update to stream (only if source is HTTP to prevent circular updates)
// 	logger.WithFields(logrus.Fields{"service_name": "StreamBridge", "method_name": "PublishPropertyUpdateWithContext", "thing_id": thingID, "property_name": propertyName}).Debug("Calling service")
// 	if err := h.streamBridge.PublishPropertyUpdateWithContext(logger, updateCtx, thingID, propertyName, value); err != nil {
// 		// Log but don't fail the request
// 		h.logError(logger, "failed to publish property update", err) // Pass logger
// 	}

// 	// Clear cache
// 	h.propertyCache.cache.Delete(fmt.Sprintf("%s/%s", thingID, propertyName))

// 	w.WriteHeader(http.StatusNoContent)
// 	return nil
// }

// // handlePropertyObserve handles SSE subscriptions for observable properties
// func (h *WoTHandler) handlePropertyObserve(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, propertyName string) error {
// 	logger.WithFields(logrus.Fields{"handler_name": "handlePropertyObserve", "thing_id": thingID, "property_name": propertyName}).Debug("Handler called")
// 	// Deferring finish log here might be tricky due to long-lived SSE connection.
// 	// Consider logging when connection closes if possible, or just entry.

// 	// Set SSE headers
// 	w.Header().Set(headerContentType, contentTypeEventStream)
// 	w.Header().Set(headerCacheControl, cacheControlNoCache)
// 	w.Header().Set(headerConnection, connectionKeepAlive)

// 	// Subscribe to property updates
// 	logger.WithFields(logrus.Fields{"service_name": "StateManager", "method_name": "SubscribeProperty", "thing_id": thingID, "property_name": propertyName}).Debug("Calling service")
// 	updates, err := h.stateManager.SubscribeProperty(thingID, propertyName)
// 	if err != nil {
// 		logger.WithError(err).WithFields(logrus.Fields{"service_name": "StateManager", "method_name": "SubscribeProperty", "thing_id": thingID, "property_name": propertyName}).Error("Service call returned error")
// 		return caddyhttp.Error(http.StatusInternalServerError, err)
// 	}
// 	defer h.stateManager.UnsubscribeProperty(thingID, propertyName, updates)

// 	// Create SSE encoder
// 	flusher, ok := w.(http.Flusher)
// 	if !ok {
// 		logger.Error("Streaming not supported by ResponseWriter")
// 		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
// 	}

// 	// Send initial value
// 	logger.WithFields(logrus.Fields{"method_name": "getPropertyValue", "thing_id": thingID, "property_name": propertyName}).Debug("Calling internal method for initial SSE value")
// 	if value, err := h.getPropertyValue(thingID, propertyName); err == nil { // Assuming getPropertyValue doesn't need request-scoped logger
// 		logger.Debug("Sending initial property value for SSE")
// 		fmt.Fprintf(w, "%s%s%s", sseDataPrefix, h.encodeSSEData(map[string]interface{}{
// 			"value":     value,
// 			"timestamp": time.Now().UTC(),
// 		}), sseDoubleNewline)
// 		flusher.Flush()
// 	} else {
// 		logger.WithError(err).WithFields(logrus.Fields{"method_name": "getPropertyValue", "thing_id": thingID, "property_name": propertyName}).Warn("Failed to get initial property value for SSE")
// 	}

// 	// Stream updates
// 	for {
// 		select {
// 		case update := <-updates:
// 			fmt.Fprintf(w, "%s%s%s", sseDataPrefix, h.encodeSSEData(map[string]interface{}{
// 				"value":     update.Value,
// 				"timestamp": update.Timestamp,
// 			}), sseDoubleNewline)
// 			flusher.Flush()
// 		case <-r.Context().Done():
// 			logger.Debug("SSE connection closed by client")
// 			return nil
// 		}
// 	}
// }

// // handleAction handles action invocations
// func (h *WoTHandler) handleAction(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, actionName string) error {
// 	logger.WithFields(logrus.Fields{"handler_name": "handleAction", "thing_id": thingID, "action_name": actionName, "method": r.Method}).Debug("Handler called")
// 	defer logger.WithFields(logrus.Fields{"handler_name": "handleAction"}).Debug("Handler finished")

// 	if r.Method != http.MethodPost {
// 		logger.WithField("method", r.Method).Warn("Method not allowed for action invocation")
// 		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
// 	}

// 	// Get action definition
// 	logger.WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetAction", "thing_id": thingID, "action_name": actionName}).Debug("Calling service")
// 	action, err := h.thingRegistry.GetAction(thingID, actionName)
// 	if err != nil {
// 		logger.WithError(err).WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetAction", "thing_id": thingID, "action_name": actionName}).Error("Service call returned error")
// 		return caddyhttp.Error(http.StatusNotFound, err)
// 	}

// 	var input interface{}
// 	inputSchema := action.GetInput() // Assume this returns wot.DataSchema (value type)

// 	// Attempt to read and parse the body if the request method implies a body (e.g., POST)
// 	// and ContentLength is positive.
// 	// If the action expects no input (schema is empty/zero), but a body is provided,
// 	// the permissive validation on an empty schema will likely pass.
// 	// If the action expects input, it will be validated against the schema.
// 	if r.ContentLength > 0 {
// 		body, err := io.ReadAll(r.Body)
// 		if err != nil {
// 			logger.WithError(err).Warn("Failed to read request body for action invocation")
// 			return caddyhttp.Error(http.StatusBadRequest, err)
// 		}
// 		defer r.Body.Close()

// 		if len(body) > 0 { // Only unmarshal if body is not empty
// 			if err := json.Unmarshal(body, &input); err != nil {
// 				logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "action_name": actionName}).Warn("Failed to unmarshal JSON for action input")
// 				return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid JSON input: %w", err))
// 			}
// 		}
// 	} // If ContentLength is 0 or body was empty, `input` remains `nil`.

// 	// Validate input. `inputSchema` is wot.DataSchema. If it's a zero struct, validator is permissive.
// 	logger.WithField("action_name_for_validation", actionName).Debug("Validating action input against schema")
// 	if err := h.validator.ValidateActionInput(logger, inputSchema, input); err != nil {
// 		// Logger inside ValidateActionInput already logs details
// 		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("validation failed for action %s input: %w", actionName, err))
// 	}

// 	// Publish action invocation
// 	logger.WithFields(logrus.Fields{"service_name": "StreamBridge", "method_name": "PublishActionInvocation", "thing_id": thingID, "action_name": actionName}).Debug("Calling service")
// 	actionID, err := h.streamBridge.PublishActionInvocation(logger, thingID, actionName, input)
// 	if err != nil {
// 		logger.WithError(err).WithFields(logrus.Fields{"service_name": "StreamBridge", "method_name": "PublishActionInvocation", "thing_id": thingID, "action_name": actionName}).Error("Service call returned error")
// 		return caddyhttp.Error(http.StatusInternalServerError, err)
// 	}
// 	logger = logger.WithField("action_id", actionID) // Add actionID to subsequent logs for this request

// 	// Check if client wants async response
// 	if r.Header.Get(headerPrefer) == preferRespondAsync {

// 		w.Header().Set("Location", fmt.Sprintf("/things/%s/actions/%s/status/%s", thingID, actionName, actionID))
// 		w.WriteHeader(http.StatusAccepted)
// 		return json.NewEncoder(w).Encode(map[string]interface{}{
// 			"actionId": actionID,
// 			"status":   "pending",
// 		})
// 	}

// 	// Wait for result (with timeout)
// 	timeout := 30 * time.Second // Default timeout
// 	if t := r.Header.Get(headerXActionTimeout); t != "" {
// 		if parsed, err := time.ParseDuration(t); err == nil { // Corrected: check err before using parsed
// 			timeout = parsed
// 			logger.WithField("timeout", timeout.String()).Debug("Using client-provided action timeout")
// 		} else {
// 			logger.WithError(err).WithField("header_value", t).Warn("Failed to parse X-Action-Timeout header")
// 		}
// 	}

// 	logger.WithFields(logrus.Fields{"service_name": "StreamBridge", "method_name": "GetActionResult", "action_id": actionID, "timeout": timeout.String()}).Debug("Calling service to get action result")
// 	result, err := h.streamBridge.GetActionResult(logger, actionID, timeout)
// 	if err != nil {
// 		logger.WithError(err).WithFields(logrus.Fields{"service_name": "StreamBridge", "method_name": "GetActionResult", "action_id": actionID}).Error("Service call for action result returned error")
// 		return caddyhttp.Error(http.StatusGatewayTimeout, err)
// 	}

// 	// Return result
// 	if action.Output != nil { // Check the pointer field directly
// 		w.Header().Set(headerContentType, contentTypeJSON)

// 		return json.NewEncoder(w).Encode(result)
// 	}

// 	w.WriteHeader(http.StatusNoContent)
// 	return nil
// }

// // handleEvent handles event subscriptions
// func (h *WoTHandler) handleEvent(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, thingID, eventName string) error {
// 	logger.WithFields(logrus.Fields{"handler_name": "handleEvent", "thing_id": thingID, "event_name": eventName, "method": r.Method}).Debug("Handler called")
// 	// Deferring finish log here might be tricky due to long-lived SSE connection.

// 	if r.Method != http.MethodGet {
// 		logger.WithField("method", r.Method).Warn("Method not allowed for event subscription")
// 		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
// 	}

// 	// Get event definition
// 	logger.WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetEvent", "thing_id": thingID, "event_name": eventName}).Debug("Calling service")
// 	_, err := h.thingRegistry.GetEvent(thingID, eventName)
// 	if err != nil {
// 		logger.WithError(err).WithFields(logrus.Fields{"service_name": "ThingRegistry", "method_name": "GetEvent", "thing_id": thingID, "event_name": eventName}).Error("Service call returned error")
// 		return caddyhttp.Error(http.StatusNotFound, err)
// 	}

// 	// Set SSE headers
// 	w.Header().Set(headerContentType, contentTypeEventStream)
// 	w.Header().Set(headerCacheControl, cacheControlNoCache)
// 	w.Header().Set(headerConnection, connectionKeepAlive)

// 	// Subscribe to events
// 	logger.WithFields(logrus.Fields{"service_name": "EventBroker", "method_name": "Subscribe", "thing_id": thingID, "event_name": eventName}).Debug("Calling service")
// 	eventChan := h.eventBroker.Subscribe(thingID, eventName)
// 	defer func() {
// 		logger.Debug("Unsubscribing from event stream")
// 		h.eventBroker.Unsubscribe(thingID, eventName, eventChan)
// 	}()

// 	flusher, ok := w.(http.Flusher)
// 	if !ok {
// 		logger.Error("Streaming not supported by ResponseWriter for event stream")
// 		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
// 	}
// 	logger.Debug("SSE connection established for event stream")

// 	// Stream events
// 	for {
// 		select {
// 		case evt := <-eventChan:
// 			fmt.Fprintf(w, "%s%s%s", sseEventPrefix, eventName, sseNewline)
// 			fmt.Fprintf(w, "%s%s%s", sseDataPrefix, h.encodeSSEData(evt), sseDoubleNewline)

// 			flusher.Flush()
// 		case <-r.Context().Done():
// 			logger.Debug("SSE connection closed by client for event stream")
// 			return nil
// 		}
// 	}
// }

// // Helper methods

// func (h *WoTHandler) getPropertyValue(thingID, propertyName string) (interface{}, error) {
// 	// Ensure dependencies are initialized before use
// 	if h.stateManager == nil {
// 		// This check is for safety; in a real scenario, dependencies must be injected.
// 		return nil, fmt.Errorf("stateManager not initialized in WoTHandler")
// 	}
// 	cacheKey := fmt.Sprintf("%s/%s", thingID, propertyName)

// 	// Check cache
// 	if cached, ok := h.propertyCache.cache.Load(cacheKey); ok {
// 		pv := cached.(PropertyValue)
// 		if time.Since(pv.UpdatedAt) < h.propertyCache.ttl {
// 			return pv.Value, nil
// 		}
// 	}

// 	// Get from state manager
// 	value, err := h.stateManager.GetProperty(thingID, propertyName)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Update cache
// 	h.propertyCache.cache.Store(cacheKey, PropertyValue{
// 		Value:     value,
// 		UpdatedAt: time.Now(),
// 	})

// 	return value, nil
// }

// func (h *WoTHandler) negotiateContentType(r *http.Request, property wot.PropertyAffordance) string {
// 	accept := r.Header.Get(headerAccept) // Use constant
// 	if accept == "" || accept == "*/*" { // if accept is empty or wildcard, default to JSON
// 		accept = contentTypeJSON // Use constant
// 	}

// 	var httpForms []wot.Form
// 	for _, form := range property.GetForms() {
// 		// Filter for HTTP/HTTPS forms
// 		protocol := form.GetProtocol()
// 		if protocol == "http" || protocol == "https" {
// 			httpForms = append(httpForms, form)
// 		}
// 	}

// 	// Prefer forms that match the Accept header
// 	for _, form := range httpForms {
// 		if strings.Contains(accept, form.GetContentType()) { // Ensure form.GetContentType() is not empty
// 			return form.GetContentType()
// 		}
// 	}

// 	// If no direct match, and if JSON is acceptable by client, and we have a JSON form, use it.
// 	if strings.Contains(accept, contentTypeJSON) {
// 		for _, form := range httpForms {
// 			if form.GetContentType() == contentTypeJSON {
// 				return contentTypeJSON
// 			}
// 		}
// 	}

// 	// If still no match, but there are HTTP forms, return the content type of the first one as a fallback.
// 	if len(httpForms) > 0 {
// 		return httpForms[0].GetContentType()
// 	}

// 	// Absolute fallback
// 	return contentTypeJSON // Use constant
// }

// func (h *WoTHandler) encodeSSEData(data interface{}) string {
// 	encoded, _ := json.Marshal(data)
// 	return string(encoded)
// }

// // logError is a local helper, now takes logger to ensure request_id context is kept if possible
// func (h *WoTHandler) logError(logger *logrus.Entry, msg string, err error) {
// 	// If a specific request logger is passed, use it. Otherwise, fall back to handler's general logger.
// 	if logger != nil {
// 		logger.WithError(err).Error(msg)
// 	} else if h.logger != nil {
// 		h.logger.WithError(err).Error(msg)
// 	} else {
// 		// Fallback if no logger is available at all (should be rare after provisioning)
// 		fmt.Printf("WoT Handler Error (logger not initialized): %s: %v\n", msg, err)
// 	}
// }

// func init() {
// 	caddy.RegisterModule(WoTHandler{})
// }
