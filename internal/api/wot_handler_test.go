package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/twinfer/twincore/pkg/wot"
)

// --- Mock Dependencies ---

// MockStateManager is a mock for api.StateManager
type MockStateManager struct {
	mock.Mock
}

func (m *MockStateManager) GetProperty(thingID, propertyName string) (interface{}, error) {
	args := m.Called(thingID, propertyName)
	return args.Get(0), args.Error(1)
}
func (m *MockStateManager) SetProperty(thingID, propertyName string, value interface{}) error {
	args := m.Called(thingID, propertyName, value)
	return args.Error(0)
}
func (m *MockStateManager) SubscribeProperty(thingID, propertyName string) (<-chan PropertyUpdate, error) {
	args := m.Called(thingID, propertyName)
	if args.Get(0) == nil { // Handle nil channel case for error returns
		return nil, args.Error(1)
	}
	return args.Get(0).(<-chan PropertyUpdate), args.Error(1)
}
func (m *MockStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan PropertyUpdate) {
	m.Called(thingID, propertyName, ch)
}

// MockStreamBridge is a mock for api.StreamBridge
type MockStreamBridge struct {
	mock.Mock
}

func (m *MockStreamBridge) PublishPropertyUpdate(thingID, propertyName string, value interface{}) error {
	args := m.Called(thingID, propertyName, value)
	return args.Error(0)
}
func (m *MockStreamBridge) PublishActionInvocation(thingID, actionName string, input interface{}) (string, error) {
	args := m.Called(thingID, actionName, input)
	return args.String(0), args.Error(1)
}
func (m *MockStreamBridge) PublishEvent(thingID, eventName string, data interface{}) error {
	args := m.Called(thingID, eventName, data)
	return args.Error(0)
}
func (m *MockStreamBridge) GetActionResult(actionID string, timeout time.Duration) (interface{}, error) {
	args := m.Called(actionID, timeout)
	return args.Get(0), args.Error(1)
}

// MockThingRegistry is a mock for api.ThingRegistry
type MockThingRegistry struct {
	mock.Mock
}

func (m *MockThingRegistry) GetThing(thingID string) (*wot.ThingDescription, error) {
	args := m.Called(thingID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*wot.ThingDescription), args.Error(1)
}
func (m *MockThingRegistry) GetProperty(thingID, propertyName string) (wot.PropertyAffordance, error) {
	args := m.Called(thingID, propertyName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(wot.PropertyAffordance), args.Error(1)
}
func (m *MockThingRegistry) GetAction(thingID, actionName string) (wot.ActionAffordance, error) {
	args := m.Called(thingID, actionName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(wot.ActionAffordance), args.Error(1)
}
func (m *MockThingRegistry) GetEvent(thingID, eventName string) (wot.EventAffordance, error) {
	args := m.Called(thingID, eventName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(wot.EventAffordance), args.Error(1)
}

// MockSchemaValidator is a mock for api.SchemaValidator
type MockSchemaValidator struct {
	mock.Mock
}

func (m *MockSchemaValidator) ValidateProperty(schema interface{}, value interface{}) error {
	args := m.Called(schema, value)
	return args.Error(0)
}
func (m *MockSchemaValidator) ValidateActionInput(schema interface{}, input interface{}) error {
	args := m.Called(schema, input)
	return args.Error(0)
}
func (m *MockSchemaValidator) ValidateEventData(schema interface{}, data interface{}) error {
	args := m.Called(schema, data)
	return args.Error(0)
}

// --- Mock/Placeholder WoT Structs/Interfaces ---
// These are minimal versions. The actual wot package might have more complex types.

// MockWotForm implements wot.Form
type MockWotForm struct {
	mock.Mock
	HrefVal        string
	ContentTypeVal string
	OpVal          []string
}

func (m *MockWotForm) GetHref() string        { return m.HrefVal }
func (m *MockWotForm) GetContentType() string { return m.ContentTypeVal }
func (m *MockWotForm) GetOp() []string        { return m.OpVal }

// Add other methods if wot.Form interface requires them, e.g., GetProtocol, GenerateConfig
func (m *MockWotForm) GetProtocol() string { return "http" } // Default mock
func (m *MockWotForm) GenerateConfig(_ map[string]wot.SecurityScheme) (map[string]interface{}, error) {
	return nil, nil
}

// MockWotPropertyAffordance implements wot.PropertyAffordance
type MockWotPropertyAffordance struct {
	mock.Mock
	PForms []wot.Form
	PIsRO  bool
	PIsWO  bool
	PIsObs bool
}

func (m *MockWotPropertyAffordance) GetForms() []wot.Form { return m.PForms }
func (m *MockWotPropertyAffordance) IsReadOnly() bool     { return m.PIsRO }
func (m *MockWotPropertyAffordance) IsWriteOnly() bool    { return m.PIsWO }
func (m *MockWotPropertyAffordance) IsObservable() bool   { return m.PIsObs }

// MockWotDataSchema implements wot.DataSchema (assuming it's an interface)
type MockWotDataSchema struct {
	mock.Mock
}

// MockWotActionAffordance implements wot.ActionAffordance
type MockWotActionAffordance struct {
	mock.Mock
	AForms  []wot.Form
	AInput  wot.DataSchema
	AOutput wot.DataSchema
}

func (m *MockWotActionAffordance) GetForms() []wot.Form      { return m.AForms }
func (m *MockWotActionAffordance) GetInput() wot.DataSchema  { return m.AInput }
func (m *MockWotActionAffordance) GetOutput() wot.DataSchema { return m.AOutput }

// MockWotEventAffordance implements wot.EventAffordance
type MockWotEventAffordance struct {
	mock.Mock
	EForms []wot.Form
	EData  wot.DataSchema
}

func (m *MockWotEventAffordance) GetForms() []wot.Form    { return m.EForms }
func (m *MockWotEventAffordance) GetData() wot.DataSchema { return m.EData }

// MockWotThingDescription for wot.ThingDescription
type MockWotThingDescription struct {
	// Minimal fields needed if any, WoTHandler mostly uses affordances from ThingRegistry
}

// --- Test Setup ---
func setupHandlerWithMocks(t *testing.T) (*WoTHandler, *MockStateManager, *MockStreamBridge, *MockThingRegistry, *MockSchemaValidator) {
	mockStateManager := new(MockStateManager)
	mockStreamBridge := new(MockStreamBridge)
	mockThingRegistry := new(MockThingRegistry)
	mockSchemaValidator := new(MockSchemaValidator)

	handler := &WoTHandler{
		stateManager:  mockStateManager,
		streamBridge:  mockStreamBridge,
		thingRegistry: mockThingRegistry,
		validator:     mockSchemaValidator,
		propertyCache: &PropertyCache{ttl: 5 * time.Second}, // As in Provision
		eventBroker:   NewEventBroker(),                     // As in Provision. NewEventBroker() is defined in wot-handler-core.go.
		// metrics field is not initialized here, assuming it's not critical for handler logic tests
	}
	return handler, mockStateManager, mockStreamBridge, mockThingRegistry, mockSchemaValidator
}

// --- Test Functions ---

func TestWoTHandler_ServeHTTP_RoutingToProperties(t *testing.T) {
	handler, mockStateManager, _, mockThingRegistry, _ := setupHandlerWithMocks(t)

	mockProperty := &MockWotPropertyAffordance{PIsRO: false, PIsObs: false}
	mockProperty.PForms = []wot.Form{&MockWotForm{ContentTypeVal: "application/json"}} // Ensure at least one form

	mockThingRegistry.On("GetProperty", "test-thing", "status").Return(mockProperty, nil)
	mockStateManager.On("GetProperty", "test-thing", "status").Return(map[string]interface{}{"value": "on"}, nil)

	req := httptest.NewRequest(http.MethodGet, "/test-thing/properties/status", nil)
	reqCtx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]string{
		"id":   "test-thing",
		"type": "properties",
		"name": "status",
	})
	req = req.WithContext(reqCtx)
	rr := httptest.NewRecorder()

	err := handler.ServeHTTP(rr, req, nil) // next handler can be nil

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
	mockThingRegistry.AssertCalled(t, "GetProperty", "test-thing", "status")
	mockStateManager.AssertCalled(t, "GetProperty", "test-thing", "status")
	// TODO: Add more assertions for response body, content type.
	// Expected: {"value":"on","timestamp":"..."}
	// assert.Contains(t, rr.Body.String(), `"value":"on"`)
}

func TestWoTHandler_handlePropertyRead_Success(t *testing.T) {
	handler, mockStateManager, _, _, _ := setupHandlerWithMocks(t)

	mockProperty := &MockWotPropertyAffordance{PIsRO: false, PIsObs: false}
	mockProperty.PForms = []wot.Form{&MockWotForm{ContentTypeVal: "application/json"}}

	mockStateManager.On("GetProperty", "thing1", "prop1").Return(map[string]interface{}{"value": "testValue"}, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil) // Path doesn't matter here
	rr := httptest.NewRecorder()

	err := handler.handlePropertyRead(rr, req, "thing1", "prop1", mockProperty)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	// TODO: Assert JSON response body, e.g., `{"value":"testValue", "timestamp":"..."}`
	// assert.Contains(t, rr.Body.String(), `"value":"testValue"`)
}

func TestWoTHandler_handlePropertyWrite_Success(t *testing.T) {
	handler, mockStateManager, mockStreamBridge, mockThingRegistry, mockSchemaValidator := setupHandlerWithMocks(t)

	mockProperty := &MockWotPropertyAffordance{PIsRO: false, PIsWO: false} // Writable
	mockProperty.PForms = []wot.Form{&MockWotForm{ContentTypeVal: "application/json"}}

	mockThingRegistry.On("GetProperty", "thing1", "prop1").Return(mockProperty, nil) // Not directly used by handlePropertyWrite, but good practice
	mockSchemaValidator.On("ValidateProperty", mockProperty, "newValue").Return(nil)
	mockStateManager.On("SetProperty", "thing1", "prop1", "newValue").Return(nil)
	mockStreamBridge.On("PublishPropertyUpdate", "thing1", "prop1", "newValue").Return(nil)

	body := strings.NewReader(`{"value": "newValue"}`)
	req := httptest.NewRequest(http.MethodPut, "/", body) // Path doesn't matter
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	err := handler.handlePropertyWrite(rr, req, "thing1", "prop1", mockProperty)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, rr.Code)
	mockSchemaValidator.AssertCalled(t, "ValidateProperty", mockProperty, "newValue")
	mockStateManager.AssertCalled(t, "SetProperty", "thing1", "prop1", "newValue")
	mockStreamBridge.AssertCalled(t, "PublishPropertyUpdate", "thing1", "prop1", "newValue")
}

func TestWoTHandler_handleAction_SyncSuccess(t *testing.T) {
	handler, _, mockStreamBridge, mockThingRegistry, mockSchemaValidator := setupHandlerWithMocks(t)

	mockAction := &MockWotActionAffordance{
		AForms:  []wot.Form{&MockWotForm{ContentTypeVal: "application/json"}},
		AInput:  &MockWotDataSchema{}, // Assuming input schema exists for validation
		AOutput: &MockWotDataSchema{}, // Assuming output schema exists for response
	}
	actionInput := map[string]interface{}{"param": "value"}
	actionOutput := map[string]interface{}{"result": "done"}

	mockThingRegistry.On("GetAction", "thing1", "action1").Return(mockAction, nil)
	mockSchemaValidator.On("ValidateActionInput", mockAction.AInput, actionInput).Return(nil)
	mockStreamBridge.On("PublishActionInvocation", "thing1", "action1", actionInput).Return("actionID123", nil)
	mockStreamBridge.On("GetActionResult", "actionID123", 30*time.Second).Return(actionOutput, nil)

	body := strings.NewReader(`{"param":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// Path variables for ServeHTTP context (though handleAction is called directly)
	reqCtx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]string{
		"id":   "thing1",
		"type": "actions",
		"name": "action1",
	})
	req = req.WithContext(reqCtx)

	err := handler.handleAction(rr, req, "thing1", "action1")

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	// TODO: Assert JSON response matches actionOutput
	// responseBody, _ := io.ReadAll(rr.Body)
	// assert.JSONEq(t, `{"result":"done"}`, string(responseBody))

	mockThingRegistry.AssertCalled(t, "GetAction", "thing1", "action1")
	mockSchemaValidator.AssertCalled(t, "ValidateActionInput", mockAction.AInput, actionInput)
	mockStreamBridge.AssertCalled(t, "PublishActionInvocation", "thing1", "action1", actionInput)
	mockStreamBridge.AssertCalled(t, "GetActionResult", "actionID123", 30*time.Second)
}

func TestWoTHandler_handleEvent_Subscription(t *testing.T) {
	handler, _, _, mockThingRegistry, _ := setupHandlerWithMocks(t)

	mockEvent := &MockWotEventAffordance{
		EForms: []wot.Form{&MockWotForm{ContentTypeVal: "text/event-stream"}},
		EData:  &MockWotDataSchema{},
	}
	mockThingRegistry.On("GetEvent", "thing1", "event1").Return(mockEvent, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/event-stream")
	rr := httptest.NewRecorder()

	// Path variables for ServeHTTP context
	reqCtx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]string{
		"id":   "thing1",
		"type": "events",
		"name": "event1",
	})
	req = req.WithContext(reqCtx)

	// Since handleEvent runs a loop, run it in a goroutine for the test
	// and use a context with timeout to control its execution.
	ctx, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond) // Short timeout for test
	defer cancel()
	req = req.WithContext(ctx)

	go func() {
		// This will block until context is canceled or an error occurs.
		// We don't expect an error here for basic setup.
		_ = handler.handleEvent(rr, req, "thing1", "event1")
	}()

	// Allow some time for the handler to set up headers and potentially write initial data
	time.Sleep(20 * time.Millisecond)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/event-stream", rr.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "keep-alive", rr.Header().Get("Connection"))

	// Test actual event emission:
	// 1. Publish an event to handler.eventBroker
	testEventData := map[string]interface{}{"value": "sample_event"}
	handler.eventBroker.Publish(Event{
		ThingID:   "thing1",
		EventName: "event1",
		Data:      testEventData,
		Timestamp: time.Now(),
	})

	// 2. Read from rr.Body to see if the event was written.
	// This part is more complex due to potential buffering and SSE format.
	// For a simple check, one might wait a bit and then read.
	time.Sleep(50 * time.Millisecond) // Wait for event to be processed

	// TODO: Implement robust SSE parsing to check for the specific event.
	// For now, we've checked headers and initiated the stream.
	// bodyBytes, _ := io.ReadAll(rr.Body)
	// bodyString := string(bodyBytes)
	// assert.Contains(t, bodyString, "event: event1")
	// assert.Contains(t, bodyString, `data: {"thingId":"thing1","eventName":"event1","data":{"value":"sample_event"}`)

	mockThingRegistry.AssertCalled(t, "GetEvent", "thing1", "event1")
}
