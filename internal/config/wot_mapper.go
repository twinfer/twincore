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
		httpPattern:   "/api/things/{id}/{type}/{name}",
		streamPattern: "things.{id}.{type}.{name}",
		logger:        logger,
	}
}

func (m *WoTMapper) ProcessTD(td *wot.ThingDescription) (*types.UnifiedConfig, error) {
	m.logger.Debugf("Processing TD: %s", td.ID)

	config := &types.UnifiedConfig{
		Version: "1.0",
		HTTP: types.HTTPConfig{
			Routes: []types.HTTPRoute{},
			// Security is now handled separately via SystemSecurityManager
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
		// Note: RequiresAuth is now determined by SystemSecurityManager, not Thing security
		route := types.HTTPRoute{
			Path:    m.expandPattern(m.httpPattern, td.ID, "properties", name),
			Methods: m.getPropertyMethods(*property), // Dereference pointer
			Handler: "unified_wot_handler",
			// RequiresAuth removed - now handled by SystemSecurityManager middleware
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
		// Note: RequiresAuth is now determined by SystemSecurityManager, not Thing security
		route := types.HTTPRoute{
			Path:    m.expandPattern(m.httpPattern, td.ID, "actions", name),
			Methods: []string{"POST"},
			Handler: "unified_wot_handler",
			// RequiresAuth removed - now handled by SystemSecurityManager middleware
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
		// Note: RequiresAuth is now determined by SystemSecurityManager, not Thing security
		route := types.HTTPRoute{
			Path:    m.expandPattern(m.httpPattern, td.ID, "events", name),
			Methods: []string{"GET"},
			Handler: "unified_wot_handler",
			// RequiresAuth removed - now handled by SystemSecurityManager middleware
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

	// Security configurations are now handled separately by WoTSecurityManager
	// WoT security schemes are processed by the WoTSecurityManager, not mixed with HTTP authentication

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

// NOTE: mapSecuritySchemes method removed as part of security separation.
// WoT security schemes are now handled by WoTSecurityManager, not mixed with HTTP authentication.
// This separation ensures Thing-level security for device communication is separate from
// system-level HTTP authentication for API access.
