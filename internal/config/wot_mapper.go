// internal/config/wot_mapper.go
package config

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
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
		HTTP:    types.HTTPConfig{Routes: []types.HTTPRoute{}},
		Stream:  types.StreamConfig{Topics: []types.StreamTopic{}, Commands: []types.CommandStream{}},
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
			Metadata: map[string]interface{}{
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
			Metadata: map[string]interface{}{
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
			Metadata: map[string]interface{}{
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

func (m *WoTMapper) mapSecuritySchemes(schemes map[string]wot.SecurityScheme) map[string]interface{} {
	result := make(map[string]interface{})

	for name, scheme := range schemes {
		switch scheme.Scheme {
		case "bearer":
			result[name] = map[string]interface{}{
				"type":   "jwt",
				"source": "header",
				"name":   "Authorization",
			}
			m.logger.Debugf("Mapped bearer scheme: %s", name)

		case "basic":
			result[name] = map[string]interface{}{
				"type": "basic",
			}
			m.logger.Debugf("Mapped basic scheme: %s", name)

		case "apikey":
			result[name] = map[string]interface{}{
				"type":   "apikey",
				"source": scheme.In,
				"name":   scheme.Name,
			}
			m.logger.Debugf("Mapped apikey scheme: %s", name)

		default:
			m.logger.Warnf("Unknown security scheme: %s", scheme.Scheme)
		}
	}

	return result
}
