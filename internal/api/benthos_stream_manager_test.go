package api

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/twinfer/twincore/pkg/types"
)

// MockableBenthosStream is an interface abstracting Benthos's service.Stream
type MockableBenthosStream interface {
	Run(ctx context.Context) error
	Stop(ctx context.Context) error
	// Add other methods used by SimpleBenthosStreamManager from service.Stream if any
}

// MockBenthosStream is a mock for MockableBenthosStream
type MockBenthosStream struct {
	mock.Mock
}

func (m *MockBenthosStream) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockBenthosStream) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockableBenthosStreamBuilder is an interface abstracting Benthos's service.StreamBuilder
type MockableBenthosStreamBuilder interface {
	SetYAML(yamlConfig string) error
	Build() (MockableBenthosStream, error) // Returns our mockable stream interface
	AsYAML() (string, error)               // Added as it's used in SimpleBenthosStreamManager
	// Add other methods used by SimpleBenthosStreamManager from service.StreamBuilder
}

// MockBenthosStreamBuilder is a mock for MockableBenthosStreamBuilder
type MockBenthosStreamBuilder struct {
	mock.Mock
}

func (m *MockBenthosStreamBuilder) SetYAML(yamlConfig string) error {
	args := m.Called(yamlConfig)
	return args.Error(0)
}

func (m *MockBenthosStreamBuilder) Build() (MockableBenthosStream, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(MockableBenthosStream), args.Error(1)
}

func (m *MockBenthosStreamBuilder) AsYAML() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

// BenthosStreamManagerTestSuite is the test suite for SimpleBenthosStreamManager.
type BenthosStreamManagerTestSuite struct {
	suite.Suite
	manager       *SimpleBenthosStreamManager // System Under Test
	db            *sql.DB
	mockSql       sqlmock.Sqlmock // For sql.DB mocking
	logger        *logrus.Logger
	testConfigDir string // For testing config file writing

	// mockStream and mockBuilder can be initialized per test if needed
	// mockStream   *MockBenthosStream
	// mockBuilder  *MockBenthosStreamBuilder
}

// SetupTest sets up resources before each test.
func (suite *BenthosStreamManagerTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.logger.SetOutput(io.Discard) // Disable log output during tests

	var err error
	suite.db, suite.mockSql, err = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual)) // Use equal query matching
	assert.NoError(suite.T(), err, "Failed to create sqlmock")

	// Prepare for the NewSimpleBenthosStreamManager call:
	// It calls initializeSchema and loadStreamsFromDatabase.

	// Mock for initializeSchema
	suite.mockSql.ExpectExec("CREATE TABLE IF NOT EXISTS stream_configs ( stream_id TEXT PRIMARY KEY, thing_id TEXT NOT NULL, interaction_type TEXT NOT NULL, interaction_name TEXT NOT NULL, direction TEXT NOT NULL, input_config TEXT NOT NULL, output_config TEXT NOT NULL, processor_chain TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'created', created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, metadata TEXT, config_yaml TEXT, validation_error TEXT )").
		WillReturnResult(sqlmock.NewResult(0, 0))

	// Mock for loadStreamsFromDatabase (assuming no streams initially)
	rows := sqlmock.NewRows([]string{"stream_id", "thing_id", "interaction_type", "interaction_name", "direction", "input_config", "output_config", "processor_chain", "status", "created_at", "updated_at", "metadata"})
	suite.mockSql.ExpectQuery("SELECT stream_id, thing_id, interaction_type, interaction_name, direction, input_config, output_config, processor_chain, status, created_at, updated_at, metadata FROM stream_configs WHERE status != 'deleted'").
		WillReturnRows(rows)

	tempDir, err := os.MkdirTemp("", "benthos_configs_test")
	assert.NoError(suite.T(), err, "Failed to create temp config dir")
	suite.testConfigDir = tempDir

	// CRITICAL: SimpleBenthosStreamManager's NewSimpleBenthosStreamManager
	// needs to be adaptable for testing. It currently calls service.NewStreamBuilder() directly
	// within generateBenthosStreamBuilder.
	// For testing, we need to inject mocks. This might mean NewSimpleBenthosStreamManager
	// takes a factory function for StreamBuilders, or the manager has a method to set a builder factory.
	// The following instantiation will work for tests not involving actual Benthos stream construction
	// or if those parts are refactored for mock injection.
	suite.manager, err = NewSimpleBenthosStreamManager(suite.testConfigDir, suite.db, suite.logger)
	assert.NoError(suite.T(), err, "NewSimpleBenthosStreamManager failed during setup")
}

// TearDownTest cleans up resources after each test.
func (suite *BenthosStreamManagerTestSuite) TearDownTest() {
	assert.NoError(suite.T(), suite.mockSql.ExpectationsWereMet(), "SQL mock expectations not met")
	suite.db.Close()
	_ = os.RemoveAll(suite.testConfigDir) // Clean up temp dir
}

// TestBenthosStreamManagerTestSuite runs the test suite.
func TestBenthosStreamManagerTestSuite(t *testing.T) {
	suite.Run(t, new(BenthosStreamManagerTestSuite))
}

// --- Example Test Method ---

func (suite *BenthosStreamManagerTestSuite) TestCreateStream_Success() {
	// --- Arrange ---
	ctx := context.Background()
	testThingID := "thing-abc"
	testYAMLConfig := `
input:
  generate:
    mapping: 'root = {"message": "test", "timestamp": timestamp_unix()}'
    interval: "1s"
    count: 1
output:
  drop: {}
`
	// This request is for the manager's CreateStream, not directly Benthos config.
	// The manager expects `yaml_config` in Metadata to then create a Benthos stream.
	request := types.StreamCreationRequest{
		ThingID:         testThingID,
		InteractionName: "testProperty",
		InteractionType: "properties",
		Direction:       "input",
		Input:           types.StreamEndpointConfig{Type: "generate", Config: map[string]interface{}{"mapping": "root = {\"message\": \"test\", \"timestamp\": timestamp_unix()}", "interval": "1s", "count": 1}},
		Output:          types.StreamEndpointConfig{Type: "drop", Config: map[string]interface{}{}},
		ProcessorChain:  []types.ProcessorConfig{},
		Metadata:        map[string]interface{}{"yaml_config": testYAMLConfig},
	}

	// Mock DB persistStreamToDatabase
	// The actual stream_id is generated internally, so we use sqlmock.AnyArg() for it.
	// Also for created_at and updated_at.
	suite.mockSql.ExpectExec("INSERT INTO stream_configs ( stream_id, thing_id, interaction_type, interaction_name, direction, input_config, output_config, processor_chain, status, created_at, updated_at, metadata, validation_error ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").
		WithArgs(sqlmock.AnyArg(), request.ThingID, request.InteractionType, request.InteractionName, request.Direction,
			`{"type":"generate","config":{"count":1,"interval":"1s","mapping":"root = {\"message\": \"test\", \"timestamp\": timestamp_unix()}"}}`, // Marshalled Input
			`{"type":"drop","config":{}}`, // Marshalled Output
			`[]`,                          // Marshalled ProcessorChain
			"created",                     // Default status
			sqlmock.AnyArg(),              // created_at
			sqlmock.AnyArg(),              // updated_at
			`{"yaml_config":"\ninput:\n  generate:\n    mapping: 'root = {\"message\": \"test\", \"timestamp\": timestamp_unix()}'\n    interval: \"1s\"\n    count: 1\noutput:\n  drop: {}\n"}`, // Marshalled Metadata
			"", // No validation error
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// --- Act ---
	// NOTE: This test relies on the assumption that SimpleBenthosStreamManager's
	// internal call to `generateBenthosStreamBuilder` and its use of `service.NewStreamBuilder()`
	// does not itself fail with this minimal YAML. For more robust tests of `generateBenthosStreamBuilder`,
	// that method would need to be refactored to accept a builder factory or be tested more directly
	// if it becomes more complex.
	streamInfo, err := suite.manager.CreateStream(ctx, request)

	// --- Assert ---
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), streamInfo)
	assert.NotEmpty(suite.T(), streamInfo.ID, "Stream ID should be generated")
	assert.Equal(suite.T(), testThingID, streamInfo.ThingID)
	assert.Equal(suite.T(), request.InteractionName, streamInfo.InteractionName)
	assert.Equal(suite.T(), "created", streamInfo.Status)

	// Ensure all SQL expectations were met
	// This is also checked in TearDownTest, but good to check here for this specific test's DB interactions.
	assert.NoError(suite.T(), suite.mockSql.ExpectationsWereMet(), "SQL expectations in TestCreateStream_Success not met")

	// Further check if the stream is in the manager's internal map
	_, exists := suite.manager.streams[streamInfo.ID]
	assert.True(suite.T(), exists, "Stream should be added to internal map")
}

// Placeholder for a test showing how to mock Benthos components if SUT is refactored
func (suite *BenthosStreamManagerTestSuite) TestStartStream_WithMockedBenthosComponents() {
	suite.T().Skip(`Skipping TestStartStream_WithMockedBenthosComponents:
This test requires SimpleBenthosStreamManager to be refactored
to allow injection of mock Benthos StreamBuilder and Stream components.`)

	// --- Arrange ---
	// ctx := context.Background()
	// streamID := "existing-stream-id"
	// suite.manager.streams[streamID] = &StreamInfo{ID: streamID, Status: "stopped", Metadata: map[string]interface{}{"yaml_config": "input:\n  none: {}\noutput:\n  drop: {}\n"}}

	// mockBuilder := new(MockBenthosStreamBuilder)
	// mockStream := new(MockBenthosStream)

	// Assumes SimpleBenthosStreamManager is refactored to use a builder factory or setter
	// suite.manager.SetBenthosStreamBuilderFactory(func(yaml string) (MockableBenthosStreamBuilder, error) {
	// 	mockBuilder.On("SetYAML", yaml).Return(nil)
	// 	mockBuilder.On("Build").Return(mockStream, nil)
	// 	mockBuilder.On("AsYAML").Return(yaml, nil) // If writeBenthosStreamBuilder is called
	// 	return mockBuilder, nil
	// })
	// suite.manager.streamBuilders[streamID] = mockBuilder // Or handled via factory

	// mockStream.On("Run", mock.AnythingOfType("*context.emptyCtx")).Return(nil)

	// suite.mockSql.ExpectExec("UPDATE stream_configs SET status = \\?, updated_at = \\? WHERE stream_id = \\?").
	// 	WithArgs("running", sqlmock.AnyArg(), streamID).
	// 	WillReturnResult(sqlmock.NewResult(0, 1))

	// --- Act ---
	// err := suite.manager.StartStream(ctx, streamID)

	// --- Assert ---
	// assert.NoError(suite.T(), err)
	// mockBuilder.AssertExpectations(suite.T())
	// mockStream.AssertExpectations(suite.T())
	// assert.Equal(suite.T(), "running", suite.manager.streams[streamID].Status)
}

// Add more test methods here based on the test plan...
// Example: TestGetStream_NotFound
func (suite *BenthosStreamManagerTestSuite) TestGetStream_NotFound() {
	ctx := context.Background()
	streamInfo, err := suite.manager.GetStream(ctx, "non-existent-stream-id")

	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), streamInfo)
	var expectedErr *ErrBenthosStreamNotFound
	assert.True(suite.T(), errors.As(err, &expectedErr), "Error should be ErrBenthosStreamNotFound")
	if expectedErr != nil {
		assert.Equal(suite.T(), "non-existent-stream-id", expectedErr.StreamID)
	}
}
