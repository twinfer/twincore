// internal/api/wot_handler.go
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

	"github.com/twinfer/twincore/pkg/wot"
)

// WoTHandler manages all WoT interactions
type WoTHandler struct {
	// Core components
	stateManager  StateManager
	streamBridge  StreamBridge
	thingRegistry ThingRegistry
	validator     SchemaValidator

	// Caching
	propertyCache *PropertyCache

	// Event management
	eventBroker *EventBroker

	// Metrics
	metrics MetricsCollector
}

// StateManager handles property state and synchronization
type StateManager interface {
	GetProperty(thingID, propertyName string) (interface{}, error)
	SetProperty(thingID, propertyName string, value interface{}) error
	SubscribeProperty(thingID, propertyName string) (<-chan PropertyUpdate, error)
	UnsubscribeProperty(thingID, propertyName string, ch <-chan PropertyUpdate)
}

// StreamBridge connects HTTP handlers to Benthos streams
type StreamBridge interface {
	PublishPropertyUpdate(thingID, propertyName string, value interface{}) error
	PublishActionInvocation(thingID, actionName string, input interface{}) (string, error)
	PublishEvent(thingID, eventName string, data interface{}) error
	GetActionResult(actionID string, timeout time.Duration) (interface{}, error)
}

// ThingRegistry provides access to Thing Descriptions
type ThingRegistry interface {
	GetThing(thingID string) (*wot.ThingDescription, error)
	GetProperty(thingID, propertyName string) (wot.PropertyAffordance, error)
	GetAction(thingID, actionName string) (wot.ActionAffordance, error)
	GetEvent(thingID, eventName string) (wot.EventAffordance, error)
}

// SchemaValidator validates inputs against WoT schemas
type SchemaValidator interface {
	ValidateProperty(schema interface{}, value interface{}) error
	ValidateActionInput(schema interface{}, input interface{}) error
	ValidateEventData(schema interface{}, data interface{}) error
}

// PropertyCache provides fast property access
type PropertyCache struct {
	cache sync.Map // map[string]PropertyValue
	ttl   time.Duration
}

type PropertyValue struct {
	Value     interface{}
	UpdatedAt time.Time
}

// EventBroker manages SSE connections for events
type EventBroker struct {
	subscribers sync.Map // map[string][]chan Event
	mu          sync.RWMutex
}

type Event struct {
	ThingID   string      `json:"thingId"`
	EventName string      `json:"eventName"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// CaddyModule returns the Caddy module information
func (WoTHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "core_wot_handler", // Changed ID
		New: func() caddy.Module { return new(WoTHandler) },
	}
}

// Provision sets up the handler
func (h *WoTHandler) Provision(ctx caddy.Context) error {
	// Initialize components
	h.propertyCache = &PropertyCache{ttl: 5 * time.Second}
	h.eventBroker = &EventBroker{}

	// Get dependencies from context
	// h.logger = ctx.Logger(h) // Get a Caddy logger
	// h.logger.Info("CoreWoTHandler provisioned. StateManager, StreamBridge, etc. must be injected post-provisioning.")
	fmt.Println("CoreWoTHandler provisioned by Caddy. StateManager, StreamBridge, etc. must be injected post-provisioning by the main application.")
	// h.stateManager = ctx.App("wot.state").(StateManager) // These will be injected by main app
	// h.streamBridge = ctx.App("wot.stream").(StreamBridge) // These will be injected by main app
	// h.thingRegistry = ctx.App("wot.registry").(ThingRegistry) // These will be injected by main app

	return nil
}

// ServeHTTP handles WoT requests
func (h *WoTHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract path parameters using Caddy's mechanism
	vars, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]string)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("path variables not available"))
	}
	thingID := vars["id"]           // Key "id" as per WoTMapper pattern /things/{id}/...
	interactionType := vars["type"] // Key "type" as per WoTMapper pattern /things/{id}/{type}/...
	name := vars["name"]            // Key "name" as per WoTMapper pattern /things/{id}/{type}/{name}

	// Route based on interaction type
	switch interactionType {
	case "properties":
		return h.handleProperty(w, r, thingID, name)
	case "actions":
		return h.handleAction(w, r, thingID, name)
	case "events":
		return h.handleEvent(w, r, thingID, name)
	default:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown interaction type: %s", interactionType))
	}
}

// handleProperty handles property read/write operations
func (h *WoTHandler) handleProperty(w http.ResponseWriter, r *http.Request, thingID, propertyName string) error {
	// Get property definition
	property, err := h.thingRegistry.GetProperty(thingID, propertyName)
	if err != nil {
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	switch r.Method {
	case http.MethodGet:
		return h.handlePropertyRead(w, r, thingID, propertyName, property)
	case http.MethodPut:
		return h.handlePropertyWrite(w, r, thingID, propertyName, property)
	default:
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

// handlePropertyRead handles GET requests for properties
func (h *WoTHandler) handlePropertyRead(w http.ResponseWriter, r *http.Request, thingID, propertyName string, property wot.PropertyAffordance) error {
	// Check if observable and client wants SSE
	if property.IsObservable() && r.Header.Get("Accept") == "text/event-stream" {
		return h.handlePropertyObserve(w, r, thingID, propertyName)
	}

	// Get property value from cache or state manager
	value, err := h.getPropertyValue(thingID, propertyName)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Content negotiation
	contentType := h.negotiateContentType(r, property)
	w.Header().Set("Content-Type", contentType)

	// Serialize based on content type
	switch contentType {
	case "application/json":
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"value":     value,
			"timestamp": time.Now().UTC(),
		})
	case "text/plain":
		_, err = fmt.Fprintf(w, "%v", value)
		return err
	default:
		return caddyhttp.Error(http.StatusNotAcceptable, fmt.Errorf("unsupported content type"))
	}
}

// handlePropertyWrite handles PUT requests for properties
func (h *WoTHandler) handlePropertyWrite(w http.ResponseWriter, r *http.Request, thingID, propertyName string, property wot.PropertyAffordance) error {
	// Check if property is writable
	if property.IsReadOnly() {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("property is read-only"))
	}

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Deserialize value
	var value interface{}
	if err := json.Unmarshal(body, &value); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Extract value if wrapped
	if wrapped, ok := value.(map[string]interface{}); ok {
		if v, exists := wrapped["value"]; exists {
			value = v
		}
	}

	// Validate against schema
	if err := h.validator.ValidateProperty(property, value); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("validation failed: %w", err))
	}

	// Update property value
	if err := h.stateManager.SetProperty(thingID, propertyName, value); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Publish update to stream
	if err := h.streamBridge.PublishPropertyUpdate(thingID, propertyName, value); err != nil {
		// Log but don't fail the request
		h.logError("failed to publish property update", err)
	}

	// Clear cache
	h.propertyCache.cache.Delete(fmt.Sprintf("%s/%s", thingID, propertyName))

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handlePropertyObserve handles SSE subscriptions for observable properties
func (h *WoTHandler) handlePropertyObserve(w http.ResponseWriter, r *http.Request, thingID, propertyName string) error {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Subscribe to property updates
	updates, err := h.stateManager.SubscribeProperty(thingID, propertyName)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	defer h.stateManager.UnsubscribeProperty(thingID, propertyName, updates)

	// Create SSE encoder
	flusher, ok := w.(http.Flusher)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
	}

	// Send initial value
	if value, err := h.getPropertyValue(thingID, propertyName); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", h.encodeSSEData(map[string]interface{}{
			"value":     value,
			"timestamp": time.Now().UTC(),
		}))
		flusher.Flush()
	}

	// Stream updates
	for {
		select {
		case update := <-updates:
			fmt.Fprintf(w, "data: %s\n\n", h.encodeSSEData(map[string]interface{}{
				"value":     update.Value,
				"timestamp": update.Timestamp,
			}))
			flusher.Flush()
		case <-r.Context().Done():
			return nil
		}
	}
}

// handleAction handles action invocations
func (h *WoTHandler) handleAction(w http.ResponseWriter, r *http.Request, thingID, actionName string) error {
	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Get action definition
	action, err := h.thingRegistry.GetAction(thingID, actionName)
	if err != nil {
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	// Parse input
	var input interface{}
	if action.GetInput() != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return caddyhttp.Error(http.StatusBadRequest, err)
		}

		if err := json.Unmarshal(body, &input); err != nil {
			return caddyhttp.Error(http.StatusBadRequest, err)
		}

		// Validate input
		if err := h.validator.ValidateActionInput(action.GetInput(), input); err != nil {
			return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("validation failed: %w", err))
		}
	}

	// Publish action invocation
	actionID, err := h.streamBridge.PublishActionInvocation(thingID, actionName, input)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Check if client wants async response
	if r.Header.Get("Prefer") == "respond-async" {
		w.Header().Set("Location", fmt.Sprintf("/things/%s/actions/%s/status/%s", thingID, actionName, actionID))
		w.WriteHeader(http.StatusAccepted)
		return json.NewEncoder(w).Encode(map[string]interface{}{
			"actionId": actionID,
			"status":   "pending",
		})
	}

	// Wait for result (with timeout)
	timeout := 30 * time.Second
	if t := r.Header.Get("X-Action-Timeout"); t != "" {
		if parsed, err := time.ParseDuration(t); err == nil {
			timeout = parsed
		}
	}

	result, err := h.streamBridge.GetActionResult(actionID, timeout)
	if err != nil {
		return caddyhttp.Error(http.StatusGatewayTimeout, err)
	}

	// Return result
	if action.GetOutput() != nil {
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(result)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleEvent handles event subscriptions
func (h *WoTHandler) handleEvent(w http.ResponseWriter, r *http.Request, thingID, eventName string) error {
	if r.Method != http.MethodGet {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Get event definition
	event, err := h.thingRegistry.GetEvent(thingID, eventName)
	if err != nil {
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Subscribe to events
	eventChan := h.eventBroker.Subscribe(thingID, eventName)
	defer h.eventBroker.Unsubscribe(thingID, eventName, eventChan)

	flusher, ok := w.(http.Flusher)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("streaming not supported"))
	}

	// Stream events
	for {
		select {
		case evt := <-eventChan:
			fmt.Fprintf(w, "event: %s\n", eventName)
			fmt.Fprintf(w, "data: %s\n\n", h.encodeSSEData(evt))
			flusher.Flush()
		case <-r.Context().Done():
			return nil
		}
	}
}

// Helper methods

func (h *WoTHandler) getPropertyValue(thingID, propertyName string) (interface{}, error) {
	// Ensure dependencies are initialized before use
	if h.stateManager == nil {
		// This check is for safety; in a real scenario, dependencies must be injected.
		return nil, fmt.Errorf("stateManager not initialized in WoTHandler")
	}
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

func (h *WoTHandler) negotiateContentType(r *http.Request, property wot.PropertyAffordance) string {
	accept := r.Header.Get("Accept")
	if accept == "" {
		accept = "application/json"
	}

	// Check forms for supported content types
	for _, form := range property.GetForms() {
		if strings.Contains(accept, form.GetContentType()) {
			return form.GetContentType()
		}
	}

	return "application/json"
}

func (h *WoTHandler) encodeSSEData(data interface{}) string {
	encoded, _ := json.Marshal(data)
	return string(encoded)
}

func (h *WoTHandler) logError(msg string, err error) {
	// Log error for monitoring
	// Consider using a logger if available, e.g., h.logger.Error(...)
	fmt.Printf("WoT Handler Error: %s: %v\n", msg, err)
}

func init() {
	caddy.RegisterModule(WoTHandler{})
}
