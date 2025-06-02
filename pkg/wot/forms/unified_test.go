package forms

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// MockLicenseCheckerV2 for testing
type MockLicenseCheckerV2 struct {
	mock.Mock
}

func (m *MockLicenseCheckerV2) IsFeatureEnabled(category, feature string) (bool, error) {
	args := m.Called(category, feature)
	return args.Bool(0), args.Error(1)
}

func (m *MockLicenseCheckerV2) CheckLimit(resource string, currentCount int) (bool, error) {
	args := m.Called(resource, currentCount)
	return args.Bool(0), args.Error(1)
}

func (m *MockLicenseCheckerV2) GetAllowedFeatures() (map[string]interface{}, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockLicenseCheckerV2) IsFeatureAvailable(feature string) bool {
	args := m.Called(feature)
	return args.Bool(0)
}

func (m *MockLicenseCheckerV2) GetFeatureConfig(feature string) map[string]interface{} {
	args := m.Called(feature)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(map[string]interface{})
}

// MockStreamManagerV2 for testing
type MockStreamManagerV2 struct {
	mock.Mock
}

// MockForm implements wot.Form for testing
type MockForm struct {
	href        string
	contentType string
	op          []string
	protocol    string
}

func (f *MockForm) GetOp() []string        { return f.op }
func (f *MockForm) GetHref() string        { return f.href }
func (f *MockForm) GetContentType() string { return f.contentType }
func (f *MockForm) GetProtocol() string    { return f.protocol }
func (f *MockForm) GenerateConfig(securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
	return map[string]interface{}{
		"href":        f.href,
		"contentType": f.contentType,
		"method":      f.op[0],
	}, nil
}

func (m *MockStreamManagerV2) CreateStream(ctx context.Context, request types.StreamCreationRequest) (*types.StreamInfo, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.StreamInfo), args.Error(1)
}

func TestUnifiedStreamGenerator_PropertyObservation(t *testing.T) {
	// Setup
	logger := logrus.New()
	licenseChecker := new(MockLicenseCheckerV2)
	streamManager := new(MockStreamManagerV2)
	
	generator := NewStreamGeneratorV2(logger, licenseChecker, streamManager)
	
	// Mock license check
	licenseChecker.On("IsFeatureAvailable", "streams").Return(true)
	
	// Create test data
	ctx := context.Background()
	thingID := "test-thing"
	propertyName := "temperature"
	
	property := &wot.PropertyAffordance{
		InteractionAffordance: wot.InteractionAffordance{
			Title:       "Temperature",
			Description: "Current temperature",
			Forms: []wot.Form{
				&MockForm{
					href:        "/things/test-thing/properties/temperature",
					contentType: "application/json",
					op:          []string{"readproperty", "observeproperty"},
				},
			},
		},
		DataSchemaCore: wot.DataSchemaCore{
			Type:       "number",
			Unit:       "celsius",
			ReadOnly:   false,
			Observable: true,
		},
	}
	
	// Expected stream info
	expectedStreamInfo := &types.StreamInfo{
		ID:              "test-thing_property_temperature_observation",
		ThingID:         thingID,
		InteractionType: "property",
		InteractionName: propertyName,
		Direction:       "input",
		Status:          "created",
	}
	
	// Mock stream creation
	streamManager.On("CreateStream", ctx, mock.AnythingOfType("types.StreamCreationRequest")).Return(expectedStreamInfo, nil)
	
	// Execute
	result, err := generator.GeneratePropertyObservationStream(ctx, thingID, property, propertyName, property.Forms[0])
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, expectedStreamInfo.ID, result.ID)
	assert.Equal(t, thingID, result.ThingID)
	assert.Equal(t, "property", result.InteractionType)
	assert.Equal(t, propertyName, result.InteractionName)
	
	// Verify mocks
	licenseChecker.AssertExpectations(t)
	streamManager.AssertExpectations(t)
	
	// Verify the stream creation request
	streamManager.AssertCalled(t, "CreateStream", ctx, mock.MatchedBy(func(req types.StreamCreationRequest) bool {
		return req.ThingID == thingID &&
			req.InteractionType == "property" &&
			req.InteractionName == propertyName &&
			req.Direction == "input"
	}))
}

func TestUnifiedBindingGenerator_CompleteFlow(t *testing.T) {
	// Setup
	logger := logrus.New()
	licenseChecker := new(MockLicenseCheckerV2)
	streamManager := new(MockStreamManagerV2)
	
	generator := NewBindingGeneratorV2(logger, licenseChecker, streamManager)
	
	// Mock license check
	licenseChecker.On("IsFeatureAvailable", "streams").Return(true)
	
	// Create test Thing Description
	td := &wot.ThingDescription{
		ID:    "test-thing",
		Title: "Test Thing",
		Properties: map[string]*wot.PropertyAffordance{
			"temperature": {
				InteractionAffordance: wot.InteractionAffordance{
					Title: "Temperature",
					Forms: []wot.Form{
						&MockForm{
							href:        "/things/test-thing/properties/temperature",
							contentType: "application/json",
							op:          []string{"readproperty", "observeproperty"},
							protocol:    "http",
						},
					},
				},
				DataSchemaCore: wot.DataSchemaCore{
					Type:       "number",
					Unit:       "celsius",
					Observable: true,
				},
			},
		},
		Actions: map[string]*wot.ActionAffordance{
			"toggle": {
				InteractionAffordance: wot.InteractionAffordance{
					Title: "Toggle",
					Forms: []wot.Form{
						&MockForm{
							href:        "/things/test-thing/actions/toggle",
							contentType: "application/json",
							op:          []string{"invokeaction"},
						},
					},
				},
				Input: &wot.DataSchema{
					DataSchemaCore: wot.DataSchemaCore{
						Type: "boolean",
					},
				},
			},
		},
	}
	
	// Mock stream creations
	streamManager.On("CreateStream", mock.Anything, mock.AnythingOfType("types.StreamCreationRequest")).
		Return(&types.StreamInfo{
			ID:              "mock-stream-id",
			ThingID:         td.ID,
			Status:          "created",
			InteractionType: "property",
			Direction:       "input",
			Input: types.StreamEndpointConfig{
				Type:   "http_server",
				Config: map[string]interface{}{},
			},
			Output: types.StreamEndpointConfig{
				Type:   "stream_bridge",
				Config: map[string]interface{}{},
			},
			ProcessorChain: []types.ProcessorConfig{},
			Metadata:       map[string]interface{}{},
		}, nil)
	
	// Execute
	ctx := context.Background()
	bindings, err := generator.GenerateAllBindings(ctx, td)
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, bindings)
	assert.Equal(t, td.ID, bindings.ThingID)
	assert.Greater(t, len(bindings.HTTPRoutes), 0)
	assert.Greater(t, len(bindings.Streams), 0)
	
	// Verify HTTP routes were generated
	assert.Contains(t, bindings.HTTPRoutes, "properties_temperature")
	assert.Contains(t, bindings.HTTPRoutes, "actions_toggle")
	
	// Verify route details
	tempRoute := bindings.HTTPRoutes["properties_temperature"]
	assert.Equal(t, "/things/test-thing/properties/temperature", tempRoute.Path)
	assert.Equal(t, "application/json", tempRoute.ContentType)
}