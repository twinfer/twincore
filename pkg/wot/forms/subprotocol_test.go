package forms

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/pkg/wot"
)

func TestSubprotocolImplementation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("HTTP form with subprotocol extraction", func(t *testing.T) {
		httpForm := &wot.HTTPForm{
			Op:          []string{"subscribeevent"},
			Href:        "https://api.example.com/events",
			ContentType: "text/event-stream",
			Subprotocol: "sse",
		}

		mockLicense := &mockLicenseChecker{available: true}
		mockManager := &mockStreamManager{}
		
		generator := &StreamGeneratorV2{
			logger:         logger,
			licenseChecker: mockLicense,
			streamManager:  mockManager,
			configBuilder:  NewStreamConfigBuilder(logger),
		}

		formConfig := generator.extractFormConfig(httpForm, nil)

		assert.Equal(t, "sse", formConfig.Subprotocol, "Subprotocol should be extracted")
		assert.Equal(t, "sse", formConfig.Metadata["subprotocol"], "Subprotocol should be stored in metadata")
	})

	t.Run("HTTP subprotocol configuration - SSE", func(t *testing.T) {
		builder := NewStreamConfigBuilder(logger)
		
		params := StreamEndpointParams{
			Type: "http",
			FormConfig: FormConfiguration{
				Href:        "https://api.example.com/events",
				Method:      "GET",
				ContentType: "text/event-stream",
				Subprotocol: "sse",
			},
		}

		config := builder.buildHTTPOutputConfig(params)
		
		require.Equal(t, "http_server", config.Type, "SSE should use http_server")
		configMap := config.Config
		
		// Verify SSE-specific configuration
		assert.Equal(t, "text/event-stream", configMap["headers"].(map[string]string)["Accept"])
		assert.Equal(t, "no-cache", configMap["headers"].(map[string]string)["Cache-Control"])
		
		syncResponse := configMap["sync_response"].(map[string]any)
		assert.Equal(t, 200, syncResponse["status"])
		assert.Equal(t, "text/event-stream", syncResponse["headers"].(map[string]string)["Content-Type"])
	})

	t.Run("HTTP subprotocol configuration - Long Poll", func(t *testing.T) {
		builder := NewStreamConfigBuilder(logger)
		
		params := StreamEndpointParams{
			Type: "http",
			FormConfig: FormConfiguration{
				Href:        "https://api.example.com/poll",
				Method:      "GET",
				ContentType: "application/json",
				Subprotocol: "longpoll",
			},
		}

		config := builder.buildHTTPOutputConfig(params)
		
		require.Equal(t, "http_client", config.Type, "Long poll should use http_client")
		configMap := config.Config
		
		// Verify long polling configuration
		assert.Equal(t, "300s", configMap["timeout"], "Should have extended timeout")
		assert.Equal(t, []int{1, 5, 10}, configMap["retry_after"], "Should have retry intervals")
		assert.Equal(t, "application/json", configMap["headers"].(map[string]string)["Accept"])
	})

	t.Run("WebSocket form creation and validation", func(t *testing.T) {
		wsForm := &wot.WebSocketForm{
			Op:               []string{"subscribeevent"},
			Href:             "wss://api.example.com/ws",
			ContentType:      "application/json",
			Subprotocol:      "mqtt",
			KeepAlive:        intPtr(30),
			PingInterval:     intPtr(10),
			MaxMessageSize:   intPtr(1024),
			NATSSubject:      "device.events",
			NATSQueue:        "workers",
		}

		// Test form interface methods
		assert.Equal(t, []string{"subscribeevent"}, wsForm.GetOp())
		assert.Equal(t, "wss://api.example.com/ws", wsForm.GetHref())
		assert.Equal(t, "application/json", wsForm.GetContentType())
		assert.Equal(t, "mqtt", wsForm.GetSubprotocol())
		assert.Equal(t, "ws", wsForm.GetProtocol())

		// Test config generation
		config, err := wsForm.GenerateConfig(nil)
		require.NoError(t, err)
		
		assert.Equal(t, "wss://api.example.com/ws", config["url"])
		assert.Equal(t, "mqtt", config["subprotocol"])
		assert.Equal(t, 30, config["keep_alive"])
		assert.Equal(t, 10, config["ping_interval"])
		assert.Equal(t, 1024, config["max_message_size"])
		assert.Equal(t, "device.events", config["nats_subject"])
		assert.Equal(t, "workers", config["nats_queue"])
	})

	t.Run("WebSocket form extraction", func(t *testing.T) {
		wsForm := &wot.WebSocketForm{
			Op:             []string{"subscribeevent"},
			Href:           "wss://api.example.com/ws",
			Subprotocol:    "wamp", // Use IANA-registered protocol instead
			KeepAlive:      intPtr(60),
			NATSSubject:    "device.rpc",
		}

		mockLicense := &mockLicenseChecker{available: true}
		mockManager := &mockStreamManager{}
		
		generator := &StreamGeneratorV2{
			logger:         logger,
			licenseChecker: mockLicense,
			streamManager:  mockManager,
			configBuilder:  NewStreamConfigBuilder(logger),
		}

		formConfig := generator.extractFormConfig(wsForm, nil)

		assert.Equal(t, "wamp", formConfig.Subprotocol)
		assert.Equal(t, "wamp", formConfig.Metadata["subprotocol"])
		assert.Equal(t, 60, formConfig.Metadata["ws:keepAlive"])
		assert.Equal(t, "device.rpc", formConfig.Metadata["nats:subject"])
	})

	t.Run("FormParser WebSocket detection", func(t *testing.T) {
		parser := &wot.FormParser{}
		
		// Test WebSocket form parsing with vocabulary
		formData := map[string]any{
			"op":             []string{"subscribeevent"},
			"href":           "wss://api.example.com/ws",
			"contentType":    "application/json",
			"subprotocol":    "mqtt",
			"wsv:keepAlive":  30,
			"wsv:pingInterval": 10,
			"nats:subject":   "device.events",
		}
		
		form, err := parser.ParseForm(formData)
		require.NoError(t, err)
		require.NotNil(t, form)
		
		wsForm, ok := form.(*wot.WebSocketForm)
		require.True(t, ok, "Should parse as WebSocketForm")
		
		assert.Equal(t, []string{"subscribeevent"}, wsForm.Op)
		assert.Equal(t, "wss://api.example.com/ws", wsForm.Href)
		assert.Equal(t, "mqtt", wsForm.Subprotocol)
		assert.NotNil(t, wsForm.KeepAlive)
		assert.Equal(t, 30, *wsForm.KeepAlive)
		assert.Equal(t, "device.events", wsForm.NATSSubject)
	})

	t.Run("WebSocket with Kafka subprotocol for WoT binding alignment", func(t *testing.T) {
		wsForm := &wot.WebSocketForm{
			Op:          []string{"subscribeevent"},
			Href:        "wss://api.example.com/kafka",
			ContentType: "application/json",
			Subprotocol: "kafka", // TwinCore custom for WoT binding alignment
		}

		mockLicense := &mockLicenseChecker{available: true}
		mockManager := &mockStreamManager{}
		
		generator := &StreamGeneratorV2{
			logger:         logger,
			licenseChecker: mockLicense,
			streamManager:  mockManager,
			configBuilder:  NewStreamConfigBuilder(logger),
		}

		formConfig := generator.extractFormConfig(wsForm, nil)

		assert.Equal(t, "kafka", formConfig.Subprotocol)
		assert.Equal(t, "kafka", formConfig.Metadata["subprotocol"])
		
		// Validate Kafka subprotocol is accepted
		err := wsForm.ValidateSubprotocol()
		assert.NoError(t, err, "Kafka subprotocol should be valid for WoT binding alignment")
	})

	t.Run("FormParser WebSocket URL detection", func(t *testing.T) {
		parser := &wot.FormParser{}
		
		// Test WebSocket form parsing by URL
		formData := map[string]any{
			"op":          []string{"subscribeevent"},
			"href":        "ws://api.example.com/ws",
			"contentType": "application/json",
		}
		
		form, err := parser.ParseForm(formData)
		require.NoError(t, err)
		require.NotNil(t, form)
		
		wsForm, ok := form.(*wot.WebSocketForm)
		require.True(t, ok, "Should parse as WebSocketForm by URL")
		assert.Equal(t, "ws://api.example.com/ws", wsForm.Href)
	})

	t.Run("Subprotocol validator - valid combinations", func(t *testing.T) {
		validator := &wot.SubprotocolValidator{}
		
		testCases := []struct {
			protocol    string
			subprotocol string
			operations  []string
			shouldPass  bool
		}{
			// HTTP subprotocols
			{"http", "sse", []string{"subscribeevent"}, true},
			{"http", "sse", []string{"observeproperty"}, true},
			{"http", "longpoll", []string{"readproperty"}, true},
			{"http", "websub", []string{"subscribeevent"}, true},
			
			// WebSocket subprotocols (IANA-registered)
			{"ws", "mqtt", []string{"subscribeevent"}, true},
			{"ws", "wamp", []string{"invokeaction"}, true},
			{"ws", "amqp", []string{"subscribeevent"}, true},
			{"ws", "coap", []string{"readproperty"}, true},
			{"ws", "opcua+uacp", []string{"writeproperty"}, true},
			{"ws", "opcua+uajson", []string{"observeproperty"}, true},
			// TwinCore custom subprotocols
			{"ws", "kafka", []string{"subscribeevent"}, true},
			{"ws", "nats", []string{"invokeaction"}, true},
			
			// Invalid combinations
			{"http", "sse", []string{"writeproperty"}, false},
			{"http", "websub", []string{"readproperty"}, false},
			{"mqtt", "sse", []string{"subscribeevent"}, false}, // MQTT doesn't support subprotocols
			{"http", "invalid", []string{"readproperty"}, false},
		}

		for _, tc := range testCases {
			t.Run(tc.protocol+"_"+tc.subprotocol, func(t *testing.T) {
				err := validator.ValidateSubprotocol(tc.protocol, tc.subprotocol, tc.operations)
				if tc.shouldPass {
					assert.NoError(t, err, "Should be valid: %s/%s with %v", tc.protocol, tc.subprotocol, tc.operations)
				} else {
					assert.Error(t, err, "Should be invalid: %s/%s with %v", tc.protocol, tc.subprotocol, tc.operations)
				}
			})
		}
	})

	t.Run("WebSocket subprotocol validation", func(t *testing.T) {
		wsForm := &wot.WebSocketForm{
			Op:          []string{"subscribeevent"},
			Subprotocol: "mqtt",
		}

		err := wsForm.ValidateSubprotocol()
		assert.NoError(t, err, "MQTT over WebSocket should be valid")

		wsForm.Subprotocol = "unknown-protocol"
		err = wsForm.ValidateSubprotocol()
		assert.Error(t, err, "Unknown subprotocol should be invalid")
		
		// Test IANA-registered subprotocols
		validSubprotocols := []string{"wamp", "amqp", "coap", "opcua+uacp", "opcua+uajson"}
		for _, subproto := range validSubprotocols {
			wsForm.Subprotocol = subproto
			err = wsForm.ValidateSubprotocol()
			assert.NoError(t, err, "IANA subprotocol %s should be valid", subproto)
		}
		
		// Test TwinCore custom subprotocols
		customSubprotocols := []string{"kafka", "nats"}
		for _, subproto := range customSubprotocols {
			wsForm.Subprotocol = subproto
			err = wsForm.ValidateSubprotocol()
			assert.NoError(t, err, "TwinCore custom subprotocol %s should be valid", subproto)
		}
	})
}