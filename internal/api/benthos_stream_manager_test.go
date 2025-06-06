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
	"github.com/twinfer/twincore/internal/database"
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

// MockDatabaseManager is a simplified mock for database.DatabaseManager
type MockDatabaseManager struct {
	mock.Mock
	isHealthy bool
}

func (m *MockDatabaseManager) Execute(ctx context.Context, queryName string, args ...any) (sql.Result, error) {
	mockArgs := m.Called(ctx, queryName, args)
	if mockArgs.Get(0) == nil {
		return sqlmock.NewResult(1, 1), mockArgs.Error(1)
	}
	return mockArgs.Get(0).(sql.Result), mockArgs.Error(1)
}

func (m *MockDatabaseManager) Query(ctx context.Context, queryName string, args ...any) (*sql.Rows, error) {
	// For Query operations, return nil rows and no error to simulate empty result set
	return nil, nil
}

func (m *MockDatabaseManager) QueryRow(ctx context.Context, queryName string, args ...any) *sql.Row {
	// Not used in stream manager tests
	return nil
}

func (m *MockDatabaseManager) Transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	// Not used in stream manager tests
	return nil
}

func (m *MockDatabaseManager) GetQuery(name string) (string, error) {
	return "SELECT 1", nil
}

func (m *MockDatabaseManager) ListQueries() []string {
	return []string{"LoadAllActiveStreams", "UpdateValidationError", "InsertStreamConfig"}
}

func (m *MockDatabaseManager) IsHealthy() bool {
	return m.isHealthy
}

func (m *MockDatabaseManager) GetQueryStats() map[string]*database.QueryStats {
	return make(map[string]*database.QueryStats)
}

func (m *MockDatabaseManager) Close() error {
	return nil
}

func (m *MockDatabaseManager) GetConnection() *sql.DB {
	return nil
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
	manager         *SimpleBenthosStreamManager // System Under Test
	db              *sql.DB
	mockSql         sqlmock.Sqlmock           // For sql.DB mocking
	mockDbManager   *MockDatabaseManager      // Mock DatabaseManager
	logger          *logrus.Logger
	testConfigDir   string // For testing config file writing

	// mockStream and mockBuilder can be initialized per test if needed
	// mockStream   *MockBenthosStream
	// mockBuilder  *MockBenthosStreamBuilder
}

// SetupTest sets up resources before each test.
func (suite *BenthosStreamManagerTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.logger.SetOutput(io.Discard) // Disable log output during tests

	// Setup mock DatabaseManager with simplified approach
	suite.mockDbManager = &MockDatabaseManager{isHealthy: true}

	tempDir, err := os.MkdirTemp("", "benthos_configs_test")
	assert.NoError(suite.T(), err, "Failed to create temp config dir")
	suite.testConfigDir = tempDir

	// Create SimpleBenthosStreamManager with mock DatabaseManager
	// The loadStreamsFromDatabase will get nil rows and handle gracefully
	suite.manager, err = NewSimpleBenthosStreamManager(suite.testConfigDir, suite.mockDbManager, suite.logger)
	assert.NoError(suite.T(), err, "NewSimpleBenthosStreamManager failed during setup")
}

// TearDownTest cleans up resources after each test.
func (suite *BenthosStreamManagerTestSuite) TearDownTest() {
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
		Input:           types.StreamEndpointConfig{Type: "generate", Config: map[string]any{"mapping": "root = {\"message\": \"test\", \"timestamp\": timestamp_unix()}", "interval": "1s", "count": 1}},
		Output:          types.StreamEndpointConfig{Type: "drop", Config: map[string]any{}},
		ProcessorChain:  []types.ProcessorConfig{},
		Metadata:        map[string]any{"yaml_config": testYAMLConfig},
	}

	// Mock database operations for stream creation
	suite.mockDbManager.On("Execute", mock.Anything, "InsertStreamConfig", mock.Anything).Return(sqlmock.NewResult(1, 1), nil)

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

	// Verify mock was called
	suite.mockDbManager.AssertCalled(suite.T(), "Execute", mock.Anything, "InsertStreamConfig", mock.Anything)

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
