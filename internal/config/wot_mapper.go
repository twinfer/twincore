// internal/config/wot_mapper.go
package config

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types" // This will resolve to the new types after old config.go is removed/changed
	"github.com/twinfer/twincore/pkg/wot"
)

type WoTMapper struct {
	httpPattern   string
	streamPattern string
	logger        *logrus.Logger
}

func NewWoTMapper(logger *logrus.Logger) *WoTMapper {
	return &WoTMapper{
		httpPattern:   "/things/{id}/{type}/{name}",
		streamPattern: "things.{id}.{type}.{name}",
		logger:        logger,
	}
}

func (m *WoTMapper) ProcessTD(td *wot.ThingDescription) (*types.UnifiedConfig, error) {
	m.logger.Debugf("Processing TD: %s", td.ID)

	config := &types.UnifiedConfig{
		Version: "1.0",
		HTTP: types.HTTPConfig{ // Will use new HTTPConfig from config_v2.go
			Routes:   []types.HTTPRoute{},
			Security: types.SimpleSecurityConfig{Enabled: false}, // Default, may be overridden
		},
		Stream: types.StreamConfig{Topics: []types.StreamTopic{}, Commands: []types.CommandStream{}},
	}

	// Process properties
	for name, property := range td.Properties {
		if property == nil {
			m.logger.Warnf("Skipping property '%s' in TD '%s' due to nil definition.", name, td.ID)
			continue
		}
		m.logger.Debugf("Processing property: %s", name)

		// Extract forms for configuration
		// Assuming GetForms() can be called on *wot.PropertyAffordance
		forms := property.GetForms()

		// HTTP route
		route := types.HTTPRoute{
			Path:         m.expandPattern(m.httpPattern, td.ID, "properties", name),
			Methods:      m.getPropertyMethods(*property), // Dereference pointer
			Handler:      "wot_property_handler",
			RequiresAuth: len(td.Security) > 0,
			Config: map[string]interface{}{ // Changed Metadata to Config
				"thingId":      td.ID,
				"propertyName": name,
				"forms":        forms,
			},
		}
		config.HTTP.Routes = append(config.HTTP.Routes, route)

		// Stream topic
		topic := types.StreamTopic{
			Name: m.expandPattern(m.streamPattern, td.ID, "properties", name),
			Type: "property_update",
			Config: map[string]interface{}{
				"thingId":             td.ID,
				"propertyName":        name,
				"forms":               forms,
				"securityDefinitions": td.SecurityDefinitions,
			},
		}
		config.Stream.Topics = append(config.Stream.Topics, topic)

		m.logger.Debugf("Created routes for property %s", name)
	}

	// Process actions
	for name, action := range td.Actions {
		if action == nil {
			m.logger.Warnf("Skipping action '%s' in TD '%s' due to nil definition.", name, td.ID)
			continue
		}
		m.logger.Debugf("Processing action: %s", name)

		forms := action.GetForms()

		// HTTP route
		route := types.HTTPRoute{
			Path:         m.expandPattern(m.httpPattern, td.ID, "actions", name),
			Methods:      []string{"POST"},
			Handler:      "wot_action_handler",
			RequiresAuth: len(td.Security) > 0,
			Config: map[string]interface{}{ // Changed Metadata to Config
				"thingId":    td.ID,
				"actionName": name,
				"input":      action.GetInput(),
				"output":     action.GetOutput(),
				"forms":      forms,
			},
		}
		config.HTTP.Routes = append(config.HTTP.Routes, route)

		// Command stream
		command := types.CommandStream{
			Name: m.expandPattern(m.streamPattern, td.ID, "actions", name),
			Type: "action_invocation",
			Config: map[string]interface{}{
				"thingId":             td.ID,
				"actionName":          name,
				"forms":               forms,
				"securityDefinitions": td.SecurityDefinitions,
			},
		}
		config.Stream.Commands = append(config.Stream.Commands, command)

		m.logger.Debugf("Created routes for action %s", name)
	}

	// Process events
	for name, event := range td.Events {
		if event == nil {
			m.logger.Warnf("Skipping event '%s' in TD '%s' due to nil definition.", name, td.ID)
			continue
		}
		m.logger.Debugf("Processing event: %s", name)

		forms := event.GetForms()

		// HTTP route (SSE)
		route := types.HTTPRoute{
			Path:         m.expandPattern(m.httpPattern, td.ID, "events", name),
			Methods:      []string{"GET"},
			Handler:      "wot_event_handler",
			RequiresAuth: len(td.Security) > 0,
			Config: map[string]interface{}{ // Changed Metadata to Config
				"thingId":   td.ID,
				"eventName": name,
				"data":      event.GetData(),
				"forms":     forms,
			},
		}
		config.HTTP.Routes = append(config.HTTP.Routes, route)

		// Event stream
		topic := types.StreamTopic{
			Name: m.expandPattern(m.streamPattern, td.ID, "events", name),
			Type: "event_emission",
			Config: map[string]interface{}{
				"thingId":             td.ID,
				"eventName":           name,
				"forms":               forms,
				"securityDefinitions": td.SecurityDefinitions,
			},
		}
		config.Stream.Topics = append(config.Stream.Topics, topic)

		m.logger.Debugf("Created routes for event %s", name)
	}

	// Add security configurations
	if len(td.Security) > 0 {
		config.HTTP.Security = m.mapSecuritySchemes(td.SecurityDefinitions)
		m.logger.Debugf("Mapped %d security schemes", len(td.SecurityDefinitions))
	}

	m.logger.Infof("Generated config for TD %s: %d HTTP routes, %d stream topics, %d commands",
		td.ID, len(config.HTTP.Routes), len(config.Stream.Topics), len(config.Stream.Commands))

	return config, nil
}

func (m *WoTMapper) getPropertyMethods(property wot.PropertyAffordance) []string {
	methods := []string{}

	if !property.IsWriteOnly() {
		methods = append(methods, "GET")
	}
	if !property.IsReadOnly() {
		methods = append(methods, "PUT")
	}

	return methods
}

func (m *WoTMapper) expandPattern(pattern, thingID, interactionType, name string) string {
	result := strings.ReplaceAll(pattern, "{id}", thingID)
	result = strings.ReplaceAll(result, "{type}", interactionType)
	result = strings.ReplaceAll(result, "{name}", name)
	return result
}

// mapSecuritySchemes translates WoT security definitions into a SimpleSecurityConfig.
// This is a simplification, as SimpleSecurityConfig holds a single configuration
// rather than a map of named schemes. It enables auth if any scheme is present.
func (m *WoTMapper) mapSecuritySchemes(schemes map[string]wot.SecurityScheme) types.SimpleSecurityConfig {
	if len(schemes) == 0 {
		m.logger.Debug("No security schemes defined in TD, HTTP security will be disabled.")
		return types.SimpleSecurityConfig{Enabled: false}
	}

	m.logger.Debugf("Processing %d security schemes for SimpleSecurityConfig.", len(schemes))
	// For now, presence of any scheme enables the generic security flag.
	// Detailed mapping to BasicAuth, BearerAuth, JWTAuth would require more context
	// (e.g., where to get user lists, tokens, JWT keys) or assumptions.
	// Example: if a "basic" scheme is found, one might initialize BasicAuth, but users are not in TD.
	// Example: if a "bearer" scheme is "jwt", JWTAuth could be initialized, but public key is not in TD.
	
	// Simplified: if any security scheme is defined, mark security as enabled.
	// The actual methods (Basic, JWT) would need to be configured externally
	// or through a more detailed mapping if possible.
	secConfig := types.SimpleSecurityConfig{
		Enabled: true,
	}

	// Potential future enhancement:
	// Iterate through schemes and try to populate specific fields if possible.
	// For example, if a 'basic' scheme exists, maybe set:
	// secConfig.BasicAuth = &types.BasicAuthConfig{} // Users would be empty
	// This indicates basic auth is expected.
	// Similar for BearerAuth or JWTAuth if a 'bearer' scheme implies JWT.
	// For now, just enabling is the most robust direct mapping.
	for name, scheme := range schemes {
		m.logger.Debugf("Found security scheme: %s (type: %s)", name, scheme.Scheme)
		// If specific mappings are needed, they would go here.
		// e.g., if scheme.Scheme == "basic", set secConfig.BasicAuth = ...
	}
	
	m.logger.Info("HTTP security enabled due to presence of security schemes in TD.")
	return secConfig
}
