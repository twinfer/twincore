package api

import (
	"context"
	"errors"
	"io"
	"testing"

	// Required for ThingRegistrationResult and other time-related fields in actual code
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// MockThingRegistryExt is a mock for api.ThingRegistryExt interface.
type MockThingRegistryExt struct {
	mock.Mock
}

func (m *MockThingRegistryExt) GetThing(thingID string) (*wot.ThingDescription, error) {
	args := m.Called(thingID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*wot.ThingDescription), args.Error(1)
}

func (m *MockThingRegistryExt) GetProperty(thingID, propertyName string) (wot.PropertyAffordance, error) {
	args := m.Called(thingID, propertyName)
	// Assuming PropertyAffordance is a struct, handle nil for error case
	if args.Get(0) == nil && args.Error(1) != nil { // Typical error return
		return wot.PropertyAffordance{}, args.Error(1)
	}
	return args.Get(0).(wot.PropertyAffordance), args.Error(1)
}

func (m *MockThingRegistryExt) GetAction(thingID, actionName string) (wot.ActionAffordance, error) {
	args := m.Called(thingID, actionName)
	if args.Get(0) == nil && args.Error(1) != nil {
		return wot.ActionAffordance{}, args.Error(1)
	}
	return args.Get(0).(wot.ActionAffordance), args.Error(1)
}

func (m *MockThingRegistryExt) GetEvent(thingID, eventName string) (wot.EventAffordance, error) {
	args := m.Called(thingID, eventName)
	if args.Get(0) == nil && args.Error(1) != nil {
		return wot.EventAffordance{}, args.Error(1)
	}
	return args.Get(0).(wot.EventAffordance), args.Error(1)
}

func (m *MockThingRegistryExt) RegisterThing(tdJSONLD string) (*wot.ThingDescription, error) {
	args := m.Called(tdJSONLD)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*wot.ThingDescription), args.Error(1)
}

func (m *MockThingRegistryExt) UpdateThing(thingID string, tdJSONLD string) (*wot.ThingDescription, error) {
	args := m.Called(thingID, tdJSONLD)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*wot.ThingDescription), args.Error(1)
}

func (m *MockThingRegistryExt) DeleteThing(thingID string) error {
	args := m.Called(thingID)
	return args.Error(0)
}

func (m *MockThingRegistryExt) ListThings() ([]*wot.ThingDescription, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*wot.ThingDescription), args.Error(1)
}

// MockTDStreamCompositionService is a mock for api.TDStreamCompositionService interface.
type MockTDStreamCompositionService struct {
	mock.Mock
}

func (m *MockTDStreamCompositionService) ProcessThingDescription(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error) {
	args := m.Called(logger, ctx, td)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StreamCompositionResult), args.Error(1)
}

func (m *MockTDStreamCompositionService) UpdateStreamsForThing(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error) {
	args := m.Called(logger, ctx, td)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StreamCompositionResult), args.Error(1)
}

func (m *MockTDStreamCompositionService) RemoveStreamsForThing(logger logrus.FieldLogger, ctx context.Context, thingID string) error {
	args := m.Called(logger, ctx, thingID)
	return args.Error(0)
}

func (m *MockTDStreamCompositionService) GetStreamCompositionStatus(logger logrus.FieldLogger, ctx context.Context, thingID string) (*StreamCompositionStatus, error) {
	args := m.Called(logger, ctx, thingID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StreamCompositionStatus), args.Error(1)
}

// MockConfigurationManager is a mock for api.ConfigurationManager interface.
type MockConfigurationManager struct {
	mock.Mock
}

func (m *MockConfigurationManager) IsSetupComplete() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockConfigurationManager) CompleteSetup(logger logrus.FieldLogger) error {
	args := m.Called(logger)
	return args.Error(0)
}

func (m *MockConfigurationManager) GetAuthProviders(license License) []AuthProviderInfo {
	args := m.Called(license)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]AuthProviderInfo)
}

func (m *MockConfigurationManager) ConfigureAuth(logger logrus.FieldLogger, req AuthConfigRequest) error {
	args := m.Called(logger, req)
	return args.Error(0)
}

func (m *MockConfigurationManager) GetConfiguration(logger logrus.FieldLogger) (map[string]any, error) {
	args := m.Called(logger)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *MockConfigurationManager) UpdateConfiguration(logger logrus.FieldLogger, section string, config map[string]any) error {
	args := m.Called(logger, section, config)
	return args.Error(0)
}

func (m *MockConfigurationManager) RemoveThingRoutes(logger logrus.FieldLogger, thingID string) error {
	args := m.Called(logger, thingID)
	return args.Error(0)
}

func (m *MockConfigurationManager) AddRoute(ctx context.Context, routeID string, route types.HTTPRoute) error {
	args := m.Called(ctx, routeID, route)
	return args.Error(0)
}

// ThingRegistrationServiceTestSuite is the test suite for ThingRegistrationService.
type ThingRegistrationServiceTestSuite struct {
	suite.Suite
	service            ThingRegistrationService // System Under Test (the interface)
	mockRegistry       *MockThingRegistryExt
	mockStreamComposer *MockTDStreamCompositionService
	mockConfigManager  *MockConfigurationManager
	logger             *logrus.Logger
}

// SetupTest sets up resources before each test.
func (suite *ThingRegistrationServiceTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.logger.SetOutput(io.Discard) // Disable log output during tests

	suite.mockRegistry = new(MockThingRegistryExt)
	suite.mockStreamComposer = new(MockTDStreamCompositionService)
	suite.mockConfigManager = new(MockConfigurationManager)

	// Provide nil or suitable mocks for BindingGenerator and BenthosStreamManager as needed for tests
	// var mockBindingGenerator *forms.BindingGenerator = nil
	var mockBenthosStreamManager BenthosStreamManager = nil
	var mockBindingGenerator BindingGenerationService = nil

	// Constructor order: thingRegistry, streamComposer, configManager, bindingGenerator, benthosStreamManager, logger
	suite.service = NewDefaultThingRegistrationService(
		suite.mockRegistry,
		suite.mockStreamComposer,
		suite.mockConfigManager,
		mockBindingGenerator,
		mockBenthosStreamManager,
		suite.logger,
	)
}

// TestThingRegistrationServiceTestSuite runs the test suite.
func TestThingRegistrationServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ThingRegistrationServiceTestSuite))
}

// --- Example Test Methods ---

func (suite *ThingRegistrationServiceTestSuite) TestRegisterThing_Success() {
	// --- Arrange ---
	ctx := context.Background()
	tdJSONLD := `{"@context": "https://www.w3.org/2022/wot/td/v1.1", "id": "urn:dev:test-thing-1", "title": "Test Thing 1"}`
	expectedThingID := "urn:dev:test-thing-1"
	loggerWithCtx := suite.logger.WithContext(ctx)

	mockTd := &wot.ThingDescription{
		ID:      expectedThingID,
		Title:   "Test Thing 1",
		Context: []string{"https://www.w3.org/2022/wot/td/v1.1"},
		// Populate other fields if necessary for ProcessThingDescription
	}

	suite.mockRegistry.On("RegisterThing", tdJSONLD).Return(mockTd, nil)

	mockStreamResult := &StreamCompositionResult{
		ThingID: expectedThingID,
		Summary: StreamCompositionSummary{StreamsCreated: 1, StreamsFailed: 0},
		// Populate other fields if needed for assertions
	}
	suite.mockStreamComposer.On("ProcessThingDescription", loggerWithCtx, ctx, mockTd).Return(mockStreamResult, nil)

	// --- Act ---
	result, err := suite.service.RegisterThing(loggerWithCtx, ctx, tdJSONLD)

	// --- Assert ---
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)
	assert.True(suite.T(), result.Summary.Success)
	assert.Equal(suite.T(), expectedThingID, result.Summary.ThingID) // Summary.ThingID is set from parsed tdJSONLD
	assert.Equal(suite.T(), mockTd, result.ThingDescription)
	assert.Equal(suite.T(), mockStreamResult, result.StreamComposition)
	assert.Empty(suite.T(), result.Summary.Error, "Expected no summary error on full success")

	suite.mockRegistry.AssertCalled(suite.T(), "RegisterThing", tdJSONLD)
	suite.mockStreamComposer.AssertCalled(suite.T(), "ProcessThingDescription", loggerWithCtx, ctx, mockTd)
}

func (suite *ThingRegistrationServiceTestSuite) TestUnregisterThing_Success() {
	// --- Arrange ---
	ctx := context.Background()
	thingID := "urn:dev:test-thing-1"
	loggerWithCtx := suite.logger.WithContext(ctx)

	suite.mockStreamComposer.On("RemoveStreamsForThing", loggerWithCtx, ctx, thingID).Return(nil)
	suite.mockConfigManager.On("RemoveThingRoutes", loggerWithCtx, thingID).Return(nil)
	suite.mockRegistry.On("DeleteThing", thingID).Return(nil) // DeleteThing from ThingRegistryExt doesn't take logger or ctx

	// --- Act ---
	err := suite.service.UnregisterThing(loggerWithCtx, ctx, thingID)

	// --- Assert ---
	assert.NoError(suite.T(), err)
	suite.mockStreamComposer.AssertCalled(suite.T(), "RemoveStreamsForThing", loggerWithCtx, ctx, thingID)
	suite.mockConfigManager.AssertNumberOfCalls(suite.T(), "RemoveThingRoutes", 1)
	suite.mockRegistry.AssertNumberOfCalls(suite.T(), "DeleteThing", 1)
}

func (suite *ThingRegistrationServiceTestSuite) TestUnregisterThing_StreamRemovalFails() {
	// --- Arrange ---
	ctx := context.Background()
	thingID := "urn:dev:test-thing-1"
	loggerWithCtx := suite.logger.WithContext(ctx)
	streamErr := errors.New("failed to remove streams")

	suite.mockStreamComposer.On("RemoveStreamsForThing", loggerWithCtx, ctx, thingID).Return(streamErr)
	suite.mockConfigManager.On("RemoveThingRoutes", loggerWithCtx, thingID).Return(nil) // This should still be called
	suite.mockRegistry.On("DeleteThing", thingID).Return(nil)                           // And this

	// --- Act ---
	err := suite.service.UnregisterThing(loggerWithCtx, ctx, thingID)

	// --- Assert ---
	assert.Error(suite.T(), err)
	// Check if it's an ErrComposite or contains the streamErr message
	// The current implementation in DefaultThingRegistrationService joins error strings.
	assert.Contains(suite.T(), err.Error(), streamErr.Error())
	// Check if it's an ErrComposite if we decide to use that type explicitly in the service
	// var compositeErr *ErrComposite
	// if errors.As(err, &compositeErr) {
	// assert.Contains(suite.T(), compositeErr.Error(), streamErr.Error())
	// }

	suite.mockStreamComposer.AssertNumberOfCalls(suite.T(), "RemoveStreamsForThing", 1)
	suite.mockConfigManager.AssertNumberOfCalls(suite.T(), "RemoveThingRoutes", 1)
	suite.mockRegistry.AssertNumberOfCalls(suite.T(), "DeleteThing", 1)
}

// Add more test methods here based on the test plan...
// e.g., TestRegisterThing_RegistryFails, TestRegisterThing_StreamCompositionFails,
// TestUnregisterThing_RouteRemovalFails, TestUnregisterThing_TDDeleteFails,
// TestUnregisterThing_MultipleFailures, TestUpdateThing_Success, TestUpdateThing_Failures,
// TestGetThingWithStreams_Success, TestGetThingWithStreams_NotFound, TestGetThingWithStreams_StreamInfoError
