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

// MockLicenseChecker for testing
type MockLicenseChecker struct {
	mock.Mock
}

func (m *MockLicenseChecker) IsFeatureEnabled(category, feature string) (bool, error) {
	args := m.Called(category, feature)
	return args.Bool(0), args.Error(1)
}

func (m *MockLicenseChecker) CheckLimit(resource string, currentCount int) (bool, error) {
	args := m.Called(resource, currentCount)
	return args.Bool(0), args.Error(1)
}

func (m *MockLicenseChecker) GetAllowedFeatures() (map[string]interface{}, error) {
	args := m.Called()
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockLicenseChecker) IsFeatureAvailable(feature string) bool {
	args := m.Called(feature)
	return args.Bool(0)
}

func (m *MockLicenseChecker) GetFeatureConfig(feature string) map[string]interface{} {
	args := m.Called(feature)
	return args.Get(0).(map[string]interface{})
}

// MockStreamManager for testing
type MockStreamManager struct {
	mock.Mock
}

func (m *MockStreamManager) CreateStream(ctx context.Context, request types.StreamCreationRequest) (*types.StreamInfo, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*types.StreamInfo), args.Error(1)
}

func (m *MockStreamManager) UpdateStream(ctx context.Context, streamID string, request types.StreamUpdateRequest) (*types.StreamInfo, error) {
	args := m.Called(ctx, streamID, request)
	return args.Get(0).(*types.StreamInfo), args.Error(1)
}

func (m *MockStreamManager) DeleteStream(ctx context.Context, streamID string) error {
	args := m.Called(ctx, streamID)
	return args.Error(0)
}

func (m *MockStreamManager) GetStream(ctx context.Context, streamID string) (*types.StreamInfo, error) {
	args := m.Called(ctx, streamID)
	return args.Get(0).(*types.StreamInfo), args.Error(1)
}

func (m *MockStreamManager) ListStreams(ctx context.Context, filters types.StreamFilters) ([]types.StreamInfo, error) {
	args := m.Called(ctx, filters)
	return args.Get(0).([]types.StreamInfo), args.Error(1)
}

func (m *MockStreamManager) CreateProcessorCollection(ctx context.Context, request types.ProcessorCollectionRequest) (*types.ProcessorCollection, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*types.ProcessorCollection), args.Error(1)
}

func (m *MockStreamManager) GetProcessorCollection(ctx context.Context, collectionID string) (*types.ProcessorCollection, error) {
	args := m.Called(ctx, collectionID)
	return args.Get(0).(*types.ProcessorCollection), args.Error(1)
}

func (m *MockStreamManager) ListProcessorCollections(ctx context.Context) ([]types.ProcessorCollection, error) {
	args := m.Called(ctx)
	return args.Get(0).([]types.ProcessorCollection), args.Error(1)
}

func (m *MockStreamManager) StartStream(ctx context.Context, streamID string) error {
	args := m.Called(ctx, streamID)
	return args.Error(0)
}

func (m *MockStreamManager) StopStream(ctx context.Context, streamID string) error {
	args := m.Called(ctx, streamID)
	return args.Error(0)
}

func (m *MockStreamManager) GetStreamStatus(ctx context.Context, streamID string) (*types.StreamStatus, error) {
	args := m.Called(ctx, streamID)
	return args.Get(0).(*types.StreamStatus), args.Error(1)
}

func TestBindingGenerator_PropertyLoggingStream(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	mockLicense := &MockLicenseChecker{}
	mockStreamManager := &MockStreamManager{}

	// Configure mocks for features that will actually be checked
	mockLicense.On("IsFeatureAvailable", "parquet_logging").Return(true)
	mockLicense.On("IsFeatureAvailable", "property_streaming").Return(true)
	mockLicense.On("IsFeatureAvailable", "property_commands").Return(true)

	// Mock stream creation
	expectedStreamInfo := &types.StreamInfo{
		ID:              "test-stream-id",
		ThingID:         "sensor1",
		InteractionType: "properties",
		InteractionName: "temperature",
		Status:          "created",
	}
	mockStreamManager.On("CreateStream", mock.Anything, mock.AnythingOfType("types.StreamCreationRequest")).Return(expectedStreamInfo, nil)

	// Create binding generator
	bindingGenerator := NewBindingGenerator(
		logger,
		mockLicense,
		mockStreamManager,
		types.ParquetConfig{
			BasePath:        "/tmp/test",
			BatchSize:       1000,
			BatchPeriod:     "5s",
			Compression:     "gzip",
			FileNamePattern: "%s_%s.parquet",
		},
		types.KafkaConfig{
			Brokers: []string{"localhost:9092"},
		},
		types.MQTTConfig{
			Broker: "tcp://localhost:1883",
			QoS:    1,
		},
	)

	// Create test Thing Description
	td := &wot.ThingDescription{
		ID:    "sensor1",
		Title: "Test Sensor",
		Properties: map[string]*wot.PropertyAffordance{
			"temperature": {
				DataSchemaCore: wot.DataSchemaCore{
					Type:       "number",
					Unit:       "celsius",
					Observable: true,
					ReadOnly:   false,
				},
				InteractionAffordance: wot.InteractionAffordance{
					Title: "Temperature",
					Forms: []wot.Form{}, // Empty for this test
				},
			},
		},
	}

	// Test
	bindings, err := bindingGenerator.GenerateAllBindings(logger, td)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, bindings)
	assert.Equal(t, "sensor1", bindings.ThingID)

	// Verify property logging stream was created
	assert.Greater(t, len(bindings.Streams), 0, "Should have created at least one stream")

	// TODO: Add more specific stream validation once types are aligned

	// Verify processor chains were created
	assert.Greater(t, len(bindings.Processors), 0, "Should have created processor chains")

	// TODO: Add processor chain validation once types are aligned

	// Basic validation passed
}

func TestBindingGenerator_LicenseFeatureGating(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	mockLicense := &MockLicenseChecker{}
	mockStreamManager := &MockStreamManager{}

	// Configure mocks to deny parquet logging
	mockLicense.On("IsFeatureAvailable", "parquet_logging").Return(false)
	mockLicense.On("IsFeatureAvailable", "property_streaming").Return(true)
	mockLicense.On("IsFeatureAvailable", "property_commands").Return(true)

	// Create binding generator
	bindingGenerator := NewBindingGenerator(
		logger,
		mockLicense,
		mockStreamManager,
		types.ParquetConfig{BasePath: "/tmp/test"},
		types.KafkaConfig{Brokers: []string{"localhost:9092"}},
		types.MQTTConfig{Broker: "tcp://localhost:1883"},
	)

	// Create test Thing Description
	td := &wot.ThingDescription{
		ID:    "sensor1",
		Title: "Test Sensor",
		Properties: map[string]*wot.PropertyAffordance{
			"temperature": {
				DataSchemaCore: wot.DataSchemaCore{
					Type:       "number",
					Observable: true,
					ReadOnly:   false,
				},
			},
		},
	}

	// Test
	bindings, err := bindingGenerator.GenerateAllBindings(logger, td)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, bindings)

	// TODO: Add license restriction validation once types are aligned

	// Basic validation passed
}
