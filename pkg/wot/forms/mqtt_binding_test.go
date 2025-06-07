package forms

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/pkg/wot"
)

func TestMQTTBindingCompliance(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("MQTT form with mqv vocabulary fields", func(t *testing.T) {
		// Create an MQTT form with W3C MQTT vocabulary
		mqttForm := &wot.MQTTForm{
			Op:            []string{"subscribeevent"},
			Href:          "mqtt://broker.example.com:1883",
			ContentType:   "application/json",
			ControlPacket: "subscribe", // mqv:controlPacket
			QoS:           "1",         // mqv:qos
			Retain:        boolPtr(true), // mqv:retain
			Topic:         "sensors/temperature", // mqv:topic
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
		formConfig := generator.extractFormConfig(mqttForm, []string{"basic_sc"})

		// Verify MQTT-specific fields are extracted correctly
		assert.Equal(t, "sensors/temperature", formConfig.Topic, "mqv:topic should be extracted")
		assert.Equal(t, 1, formConfig.QoS, "mqv:qos should be converted to int")
		assert.NotNil(t, formConfig.Retain, "mqv:retain should be extracted")
		assert.True(t, *formConfig.Retain, "mqv:retain value should be preserved")
		assert.NotNil(t, formConfig.Metadata, "Metadata should be initialized")
		assert.Equal(t, "subscribe", formConfig.Metadata["mqv:controlPacket"], "mqv:controlPacket should be stored")
	})

	t.Run("MQTT form with topic filter fallback", func(t *testing.T) {
		mqttForm := &wot.MQTTForm{
			Op:          []string{"subscribeevent"},
			Href:        "mqtt://broker.example.com:1883",
			ContentType: "application/json",
			Filter:      "sensors/+/temperature", // mqv:filter instead of topic
			QoS:         "2",
		}

		mockLicense := &mockLicenseChecker{available: true}
		mockManager := &mockStreamManager{}
		
		generator := &StreamGeneratorV2{
			logger:         logger,
			licenseChecker: mockLicense,
			streamManager:  mockManager,
			configBuilder:  NewStreamConfigBuilder(logger),
		}

		formConfig := generator.extractFormConfig(mqttForm, nil)

		// Should use filter as topic when topic is not specified
		assert.Equal(t, "sensors/+/temperature", formConfig.Topic, "Should fallback to mqv:filter when mqv:topic is empty")
		assert.Equal(t, 2, formConfig.QoS, "QoS should be converted correctly")
	})

	t.Run("MQTT control packet validation - valid combinations", func(t *testing.T) {
		testCases := []struct {
			controlPacket string
			operation     string
			shouldPass    bool
		}{
			{"publish", "writeproperty", true},
			{"publish", "invokeaction", true},
			{"subscribe", "readproperty", true},
			{"subscribe", "observeproperty", true},
			{"subscribe", "subscribeevent", true},
			{"unsubscribe", "unobserveproperty", true},
			{"unsubscribe", "unsubscribeevent", true},
			// Invalid combinations
			{"publish", "readproperty", false},
			{"subscribe", "writeproperty", false},
			{"unsubscribe", "invokeaction", false},
			{"invalid", "readproperty", false},
		}

		for _, tc := range testCases {
			t.Run(tc.controlPacket+"_"+tc.operation, func(t *testing.T) {
				form := &wot.MQTTForm{
					Op:            []string{tc.operation},
					Href:          "mqtt://broker.example.com:1883",
					ControlPacket: tc.controlPacket,
				}

				err := form.ValidateControlPacket()
				if tc.shouldPass {
					assert.NoError(t, err, "Control packet '%s' should be valid for operation '%s'", tc.controlPacket, tc.operation)
				} else {
					assert.Error(t, err, "Control packet '%s' should be invalid for operation '%s'", tc.controlPacket, tc.operation)
				}
			})
		}
	})

	t.Run("MQTT output configuration includes retain flag", func(t *testing.T) {
		builder := NewStreamConfigBuilder(logger)
		
		params := StreamEndpointParams{
			Type: "mqtt",
			FormConfig: FormConfiguration{
				Href:   "mqtt://broker.example.com:1883",
				Topic:  "sensors/data",
				QoS:    1,
				Retain: boolPtr(true),
			},
		}

		config := builder.buildMQTTOutputConfig(params)
		
		require.Equal(t, "mqtt", config.Type)
		configMap := config.Config
		
		// Verify retain flag is passed through
		assert.Equal(t, true, configMap["retained"], "Retain flag should be passed as 'retained'")
		assert.Equal(t, "sensors/data", configMap["topic"])
		assert.Equal(t, 1, configMap["qos"])
		assert.Equal(t, []string{"mqtt://broker.example.com:1883"}, configMap["urls"])
	})

	t.Run("MQTT output configuration without retain flag", func(t *testing.T) {
		builder := NewStreamConfigBuilder(logger)
		
		params := StreamEndpointParams{
			Type: "mqtt",
			FormConfig: FormConfiguration{
				Href:  "mqtt://broker.example.com:1883",
				Topic: "sensors/data",
				QoS:   0,
				// No retain flag specified
			},
		}

		config := builder.buildMQTTOutputConfig(params)
		
		require.Equal(t, "mqtt", config.Type)
		configMap := config.Config
		
		// Verify retain flag is not present when not specified
		_, hasRetain := configMap["retained"]
		assert.False(t, hasRetain, "Retain flag should not be present when not specified")
	})

	t.Run("FormParser correctly parses MQTT forms with W3C vocabulary", func(t *testing.T) {
		parser := &wot.FormParser{}
		
		// Test parsing form data with MQTT vocabulary
		formData := map[string]any{
			"op":                 []string{"subscribeevent"},
			"href":               "mqtt://broker.example.com:1883/sensors/temperature",
			"contentType":        "application/json",
			"mqv:controlPacket":  "subscribe",
			"mqv:qos":            "1",
			"mqv:retain":         true,
			"mqv:topic":          "sensors/temperature",
		}
		
		form, err := parser.ParseForm(formData)
		require.NoError(t, err)
		require.NotNil(t, form)
		
		// Verify it parsed as MQTTForm
		mqttForm, ok := form.(*wot.MQTTForm)
		require.True(t, ok, "Should parse as MQTTForm")
		
		// Verify all fields were parsed correctly
		assert.Equal(t, []string{"subscribeevent"}, mqttForm.Op)
		assert.Equal(t, "mqtt://broker.example.com:1883/sensors/temperature", mqttForm.Href)
		assert.Equal(t, "application/json", mqttForm.ContentType)
		assert.Equal(t, "subscribe", mqttForm.ControlPacket)
		assert.Equal(t, "1", mqttForm.QoS)
		assert.NotNil(t, mqttForm.Retain)
		assert.True(t, *mqttForm.Retain)
		assert.Equal(t, "sensors/temperature", mqttForm.Topic)
	})

	t.Run("QoS string to int conversion", func(t *testing.T) {
		testCases := []struct {
			qosString string
			expected  int
		}{
			{"0", 0},
			{"1", 1},
			{"2", 2},
			{"", 0},     // Default
			{"invalid", 0}, // Default
		}

		for _, tc := range testCases {
			t.Run("QoS_"+tc.qosString, func(t *testing.T) {
				form := &wot.MQTTForm{
					Op:   []string{"subscribeevent"},
					Href: "mqtt://broker.example.com:1883",
					QoS:  tc.qosString,
				}

				mockLicense := &mockLicenseChecker{available: true}
				mockManager := &mockStreamManager{}
				
				generator := &StreamGeneratorV2{
					logger:         logger,
					licenseChecker: mockLicense,
					streamManager:  mockManager,
					configBuilder:  NewStreamConfigBuilder(logger),
				}

				formConfig := generator.extractFormConfig(form, nil)
				assert.Equal(t, tc.expected, formConfig.QoS, "QoS string '%s' should convert to %d", tc.qosString, tc.expected)
			})
		}
	})
}

// Helper function to create bool pointer
func boolPtr(b bool) *bool {
	return &b
}