package forms

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

func TestHTTPBindingCompliance(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("HTTP form with htv:methodName and htv:headers", func(t *testing.T) {
		// Create an HTTP form with W3C HTTP vocabulary
		httpForm := &wot.HTTPForm{
			Op:          []string{"readproperty"},
			Href:        "https://api.example.com/thing/temperature",
			ContentType: "application/json",
			MethodName:  "GET", // htv:methodName
			Headers: []wot.HTTPHeader{
				{
					FieldName:  "X-API-Key",
					FieldValue: "test-key-123",
				},
				{
					FieldName:  "Accept",
					FieldValue: "application/json",
				},
			},
			StatusCodeNumber: intPtr(200), // htv:statusCodeNumber
		}

		// Create a mock stream generator
		mockLicense := &mockLicenseChecker{available: true}
		mockManager := &mockStreamManager{}
		
		generator := &StreamGeneratorV2{
			logger:         logger,
			licenseChecker: mockLicense,
			streamManager:  mockManager,
			configBuilder:  NewStreamConfigBuilder(logger),
		}

		// Extract form configuration
		formConfig := generator.extractFormConfig(httpForm, []string{"basic_sc"})

		// Verify HTTP-specific fields are extracted correctly
		assert.Equal(t, "GET", formConfig.Method, "htv:methodName should be extracted")
		assert.NotNil(t, formConfig.Headers, "Headers should be extracted")
		assert.Len(t, formConfig.Headers, 2, "Should have 2 headers")
		assert.Equal(t, "test-key-123", formConfig.Headers["X-API-Key"])
		assert.Equal(t, "application/json", formConfig.Headers["Accept"])
		assert.NotNil(t, formConfig.StatusCode, "Status code should be extracted")
		assert.Equal(t, 200, *formConfig.StatusCode)
	})

	t.Run("HTTP form method inference from operation", func(t *testing.T) {
		// Create forms without htv:methodName to test inference
		testCases := []struct {
			op             string
			expectedMethod string
		}{
			{"readproperty", "GET"},
			{"writeproperty", "PUT"},
			{"invokeaction", "POST"},
			{"queryaction", "GET"},
			{"cancelaction", "DELETE"},
			{"subscribeevent", "GET"},
			{"unsubscribeevent", "GET"},
		}

		mockLicense := &mockLicenseChecker{available: true}
		mockManager := &mockStreamManager{}
		
		generator := &StreamGeneratorV2{
			logger:         logger,
			licenseChecker: mockLicense,
			streamManager:  mockManager,
			configBuilder:  NewStreamConfigBuilder(logger),
		}

		for _, tc := range testCases {
			t.Run(tc.op, func(t *testing.T) {
				form := &wot.HTTPForm{
					Op:          []string{tc.op},
					Href:        "https://api.example.com/resource",
					ContentType: "application/json",
					// No MethodName set - should infer from operation
				}

				formConfig := generator.extractFormConfig(form, nil)
				assert.Equal(t, tc.expectedMethod, formConfig.Method, 
					"Method should be inferred from operation %s", tc.op)
			})
		}
	})

	t.Run("StreamConfigBuilder passes headers to HTTP output", func(t *testing.T) {
		builder := NewStreamConfigBuilder(logger)
		
		params := StreamEndpointParams{
			Type: "http",
			FormConfig: FormConfiguration{
				Href:        "https://api.example.com/resource",
				Method:      "POST",
				ContentType: "application/json",
				Headers: map[string]string{
					"Authorization": "Bearer token123",
					"X-Custom-Header": "custom-value",
				},
			},
		}

		config := builder.buildHTTPOutputConfig(params)
		
		require.Equal(t, "http_client", config.Type)
		configMap := config.Config
		
		// Verify headers are passed through
		headers, ok := configMap["headers"].(map[string]string)
		require.True(t, ok)
		assert.Equal(t, "application/json", headers["Content-Type"])
		assert.Equal(t, "Bearer token123", headers["Authorization"])
		assert.Equal(t, "custom-value", headers["X-Custom-Header"])
		
		// Verify other fields
		assert.Equal(t, "https://api.example.com/resource", configMap["url"])
		assert.Equal(t, "POST", configMap["verb"])
	})

	t.Run("FormParser correctly parses HTTP forms with W3C vocabulary", func(t *testing.T) {
		parser := &wot.FormParser{}
		
		// Test parsing form data with HTTP vocabulary
		formData := map[string]any{
			"op":               []string{"readproperty"},
			"href":             "https://api.example.com/thing/status",
			"contentType":      "application/json",
			"htv:methodName":   "GET",
			"htv:headers": []map[string]string{
				{
					"htv:fieldName":  "Authorization",
					"htv:fieldValue": "Bearer abc123",
				},
				{
					"htv:fieldName":  "X-Request-ID",
					"htv:fieldValue": "req-456",
				},
			},
			"htv:statusCodeNumber": 200,
		}
		
		form, err := parser.ParseForm(formData)
		require.NoError(t, err)
		require.NotNil(t, form)
		
		// Verify it parsed as HTTPForm
		httpForm, ok := form.(*wot.HTTPForm)
		require.True(t, ok, "Should parse as HTTPForm")
		
		// Verify all fields were parsed correctly
		assert.Equal(t, []string{"readproperty"}, httpForm.Op)
		assert.Equal(t, "https://api.example.com/thing/status", httpForm.Href)
		assert.Equal(t, "application/json", httpForm.ContentType)
		assert.Equal(t, "GET", httpForm.MethodName)
		assert.Len(t, httpForm.Headers, 2)
		assert.Equal(t, "Authorization", httpForm.Headers[0].FieldName)
		assert.Equal(t, "Bearer abc123", httpForm.Headers[0].FieldValue)
		assert.Equal(t, "X-Request-ID", httpForm.Headers[1].FieldName)
		assert.Equal(t, "req-456", httpForm.Headers[1].FieldValue)
		assert.NotNil(t, httpForm.StatusCodeNumber)
		assert.Equal(t, 200, *httpForm.StatusCodeNumber)
	})
}

// Helper function to create int pointer
func intPtr(i int) *int {
	return &i
}

// Mock implementations for testing
type mockLicenseChecker struct {
	available bool
}

func (m *mockLicenseChecker) IsFeatureEnabled(category, feature string) (bool, error) {
	return m.available, nil
}

func (m *mockLicenseChecker) CheckLimit(resource string, currentCount int) (bool, error) {
	return true, nil
}

func (m *mockLicenseChecker) GetAllowedFeatures() (map[string]any, error) {
	return map[string]any{"streams": true}, nil
}

func (m *mockLicenseChecker) IsFeatureAvailable(feature string) bool {
	return m.available
}

func (m *mockLicenseChecker) GetFeatureConfig(feature string) map[string]any {
	return map[string]any{}
}

type mockStreamManager struct{}

func (m *mockStreamManager) CreateStream(ctx context.Context, request types.StreamCreationRequest) (*types.StreamInfo, error) {
	return &types.StreamInfo{
		ID:     "test-stream",
		Status: "active",
	}, nil
}