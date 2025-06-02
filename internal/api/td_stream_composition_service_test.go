package api

import (
	"context"
	"errors"
	"io"
	"testing"
	"time" // Required for some types like forms.AllBindings

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/twinfer/twincore/pkg/wot/forms"
)

// MockBindingGenerationService is a mock for api.BindingGenerationService interface.
type MockBindingGenerationService struct {
	mock.Mock
}

func (m *MockBindingGenerationService) GenerateAllBindings(td *wot.ThingDescription) (*forms.AllBindings, error) {
	args := m.Called(td)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*forms.AllBindings), args.Error(1)
}

// MockBenthosStreamManager is a mock for api.BenthosStreamManager interface.
// Re-defined here for this test file. Ideally, this would be in a shared test utility.
type MockBenthosStreamManager struct {
	mock.Mock
}

func (m *MockBenthosStreamManager) CreateStream(ctx context.Context, request StreamCreationRequest) (*StreamInfo, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StreamInfo), args.Error(1)
}

func (m *MockBenthosStreamManager) UpdateStream(ctx context.Context, streamID string, request StreamUpdateRequest) (*StreamInfo, error) {
	args := m.Called(ctx, streamID, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StreamInfo), args.Error(1)
}

func (m *MockBenthosStreamManager) DeleteStream(ctx context.Context, streamID string) error {
	args := m.Called(ctx, streamID)
	return args.Error(0)
}

func (m *MockBenthosStreamManager) GetStream(ctx context.Context, streamID string) (*StreamInfo, error) {
	args := m.Called(ctx, streamID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StreamInfo), args.Error(1)
}

func (m *MockBenthosStreamManager) ListStreams(ctx context.Context, filters StreamFilters) ([]StreamInfo, error) {
	args := m.Called(ctx, filters)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]StreamInfo), args.Error(1)
}

func (m *MockBenthosStreamManager) StartStream(ctx context.Context, streamID string) error {
	args := m.Called(ctx, streamID)
	return args.Error(0)
}

func (m *MockBenthosStreamManager) StopStream(ctx context.Context, streamID string) error {
	args := m.Called(ctx, streamID)
	return args.Error(0)
}

func (m *MockBenthosStreamManager) GetStreamStatus(ctx context.Context, streamID string) (*StreamStatus, error) {
	args := m.Called(ctx, streamID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StreamStatus), args.Error(1)
}

func (m *MockBenthosStreamManager) CreateProcessorCollection(ctx context.Context, request ProcessorCollectionRequest) (*ProcessorCollection, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ProcessorCollection), args.Error(1)
}

func (m *MockBenthosStreamManager) GetProcessorCollection(ctx context.Context, collectionID string) (*ProcessorCollection, error) {
	args := m.Called(ctx, collectionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ProcessorCollection), args.Error(1)
}

func (m *MockBenthosStreamManager) ListProcessorCollections(ctx context.Context) ([]ProcessorCollection, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]ProcessorCollection), args.Error(1)
}

// TDStreamCompositionServiceTestSuite is the test suite for TDStreamCompositionService.
type TDStreamCompositionServiceTestSuite struct {
	suite.Suite
	service         TDStreamCompositionService // System Under Test (the interface)
	mockBindingGen  *MockBindingGenerationService
	mockStreamMgr   *MockBenthosStreamManager
	logger          *logrus.Logger
}

// SetupTest sets up resources before each test.
func (suite *TDStreamCompositionServiceTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.logger.SetOutput(io.Discard) // Disable log output during tests

	suite.mockBindingGen = new(MockBindingGenerationService)
	suite.mockStreamMgr = new(MockBenthosStreamManager)

	// Constructor order: bindingGenerator, streamManager, logger
	// (as per current DefaultTDStreamCompositionService constructor)
	suite.service = NewDefaultTDStreamCompositionService(
		suite.mockBindingGen,
		suite.mockStreamMgr,
		suite.logger,
	)
}

// TestTDStreamCompositionServiceTestSuite runs the test suite.
func TestTDStreamCompositionServiceTestSuite(t *testing.T) {
	suite.Run(t, new(TDStreamCompositionServiceTestSuite))
}

// --- Example Test Methods ---

func (suite *TDStreamCompositionServiceTestSuite) TestProcessThingDescription_Success() {
	// --- Arrange ---
	ctx := context.Background()
	loggerWithCtx := suite.logger.WithContext(ctx) // Example of passing logger with context
	testTD := &wot.ThingDescription{ID: "urn:test:td1", Title: "Test TD"}

	mockBindings := &forms.AllBindings{
		ThingID: testTD.ID,
		Streams: map[string]forms.StreamConfig{
			"stream1-id": {ID: "stream1-id", Type: "property_output" /* ... other fields */},
		},
		// ... other binding fields
	}
	// GenerateAllBindings does not take logger or context according to its interface
	suite.mockBindingGen.On("GenerateAllBindings", testTD).Return(mockBindings, nil)

	// Assume BindingGenerator itself calls streamManager.CreateStream implicitly.
	// ProcessThingDescription then calls GetStream to confirm/fetch details.
	mockStreamInfo := &StreamInfo{ID: "stream1-id", Status: "created" /* ... */}
	suite.mockStreamMgr.On("GetStream", ctx, "stream1-id").Return(mockStreamInfo, nil) // GetStream takes ctx

	// --- Act ---
	result, err := suite.service.ProcessThingDescription(loggerWithCtx, ctx, testTD)

	// --- Assert ---
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)
	if result != nil && result.CreatedStreams != nil { // Guard against nil panic
		assert.Len(suite.T(), result.CreatedStreams, 1)
		if len(result.CreatedStreams) > 0 {
			assert.Equal(suite.T(), "stream1-id", result.CreatedStreams[0].ID) // Corrected to streamInfo.ID
		}
		assert.Empty(suite.T(), result.FailedStreams)
	}


	suite.mockBindingGen.AssertCalledOnce(suite.T(), "GenerateAllBindings", testTD)
	suite.mockStreamMgr.AssertCalledOnce(suite.T(), "GetStream", ctx, "stream1-id")
}

func (suite *TDStreamCompositionServiceTestSuite) TestRemoveStreamsForThing_Success() {
	// --- Arrange ---
	ctx := context.Background()
	loggerWithCtx := suite.logger.WithContext(ctx)
	thingID := "urn:test:td1"

	streamsToReturn := []StreamInfo{
		{ID: "stream1", ThingID: thingID},
		{ID: "stream2", ThingID: thingID},
	}
	suite.mockStreamMgr.On("ListStreams", ctx, StreamFilters{ThingID: thingID}).Return(streamsToReturn, nil)
	suite.mockStreamMgr.On("DeleteStream", ctx, "stream1").Return(nil)
	suite.mockStreamMgr.On("DeleteStream", ctx, "stream2").Return(nil)

	// --- Act ---
	err := suite.service.RemoveStreamsForThing(loggerWithCtx, ctx, thingID)

	// --- Assert ---
	assert.NoError(suite.T(), err)
	suite.mockStreamMgr.AssertCalledOnce(suite.T(), "ListStreams", ctx, StreamFilters{ThingID: thingID})
	suite.mockStreamMgr.AssertCalledOnce(suite.T(), "DeleteStream", ctx, "stream1")
	suite.mockStreamMgr.AssertCalledOnce(suite.T(), "DeleteStream", ctx, "stream2")
}

func (suite *TDStreamCompositionServiceTestSuite) TestRemoveStreamsForThing_DeleteFailsPartially() {
	// --- Arrange ---
	ctx := context.Background()
	loggerWithCtx := suite.logger.WithContext(ctx)
	thingID := "urn:test:td1"
	deleteErr1 := errors.New("failed to delete stream1")
	// deleteErr2 is not used, one error is enough to make the whole operation fail with composite error

	streamsToReturn := []StreamInfo{
		{ID: "stream1", ThingID: thingID},
		{ID: "stream2", ThingID: thingID},
	}
	suite.mockStreamMgr.On("ListStreams", ctx, StreamFilters{ThingID: thingID}).Return(streamsToReturn, nil)
	suite.mockStreamMgr.On("DeleteStream", ctx, "stream1").Return(deleteErr1)
	suite.mockStreamMgr.On("DeleteStream", ctx, "stream2").Return(nil) // This one succeeds

	// --- Act ---
	err := suite.service.RemoveStreamsForThing(loggerWithCtx, ctx, thingID)

	// --- Assert ---
	assert.Error(suite.T(), err)
	// The current implementation of DefaultTDStreamCompositionService.RemoveStreamsForThing
	// returns the first error encountered after trying all deletions.
	assert.Contains(suite.T(), err.Error(), deleteErr1.Error())
	// If it were to use ErrComposite:
	// var compositeErr *ErrComposite
	// assert.True(suite.T(), errors.As(err, &compositeErr), "Expected ErrComposite")
	// if compositeErr != nil {
	//    assert.Len(suite.T(), compositeErr.Errors, 1)
	//    assert.Contains(suite.T(), compositeErr.Errors[0].Error(), deleteErr1.Error())
	// }


	suite.mockStreamMgr.AssertCalledOnce(suite.T(), "ListStreams", ctx, StreamFilters{ThingID: thingID})
	suite.mockStreamMgr.AssertCalledOnce(suite.T(), "DeleteStream", ctx, "stream1")
	suite.mockStreamMgr.AssertCalledOnce(suite.T(), "DeleteStream", ctx, "stream2")
}

// Add more test methods here based on the test plan...
// e.g., TestProcessThingDescription_BindingGenFails, TestProcessThingDescription_GetStreamFails,
// TestUpdateStreamsForThing_Success, TestUpdateStreamsForThing_ListFails, TestUpdateStreamsForThing_ProcessFails,
// TestGetStreamCompositionStatus_Success, TestGetStreamCompositionStatus_ListFails
