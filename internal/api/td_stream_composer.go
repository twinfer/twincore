package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// TDStreamComposer analyzes Thing Descriptions and generates stream configurations
type TDStreamComposer interface {
	// AnalyzeTD extracts stream-relevant information from a Thing Description
	AnalyzeTD(ctx context.Context, td map[string]interface{}) (*TDAnalysis, error)

	// ComposeStreams generates StreamCreationRequests for all interactions in a TD
	ComposeStreams(ctx context.Context, analysis *TDAnalysis, config StreamCompositionConfig) ([]StreamCreationRequest, error)

	// ComposeStreamForInteraction generates a single stream for a specific interaction
	ComposeStreamForInteraction(ctx context.Context, thingID string, interactionType string, interactionName string, affordance map[string]interface{}, config StreamCompositionConfig) (*StreamCreationRequest, error)
}

// TDAnalysis contains extracted information from Thing Description analysis
type TDAnalysis struct {
	ThingID     string                        `json:"thing_id"`
	Title       string                        `json:"title,omitempty"`
	Description string                        `json:"description,omitempty"`
	BaseURI     string                        `json:"base_uri,omitempty"`
	Properties  map[string]PropertyAffordance `json:"properties,omitempty"`
	Actions     map[string]ActionAffordance   `json:"actions,omitempty"`
	Events      map[string]EventAffordance    `json:"events,omitempty"`
	Security    []SecurityScheme              `json:"security,omitempty"`
	Forms       []Form                        `json:"forms,omitempty"`
}

// PropertyAffordance represents a WoT property with its forms and metadata
type PropertyAffordance struct {
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	Type        string                 `json:"type,omitempty"`
	ReadOnly    bool                   `json:"readOnly,omitempty"`
	WriteOnly   bool                   `json:"writeOnly,omitempty"`
	Observable  bool                   `json:"observable,omitempty"`
	Forms       []Form                 `json:"forms,omitempty"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
}

// ActionAffordance represents a WoT action with its forms and metadata
type ActionAffordance struct {
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	Input       map[string]interface{} `json:"input,omitempty"`
	Output      map[string]interface{} `json:"output,omitempty"`
	Safe        bool                   `json:"safe,omitempty"`
	Idempotent  bool                   `json:"idempotent,omitempty"`
	Forms       []Form                 `json:"forms,omitempty"`
}

// EventAffordance represents a WoT event with its forms and metadata
type EventAffordance struct {
	Name         string                 `json:"name"`
	Title        string                 `json:"title,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Data         map[string]interface{} `json:"data,omitempty"`
	DataResponse map[string]interface{} `json:"dataResponse,omitempty"`
	Forms        []Form                 `json:"forms,omitempty"`
}

// Form represents a WoT form with protocol bindings
type Form struct {
	Href                string                 `json:"href"`
	ContentType         string                 `json:"contentType,omitempty"`
	Op                  []string               `json:"op,omitempty"`
	Subprotocol         string                 `json:"subprotocol,omitempty"`
	Security            []string               `json:"security,omitempty"`
	AdditionalResponses map[string]interface{} `json:"additionalResponses,omitempty"`
}

// SecurityScheme represents a WoT security scheme
type SecurityScheme struct {
	Scheme     string                 `json:"scheme"`
	Name       string                 `json:"name,omitempty"`
	In         string                 `json:"in,omitempty"`
	Additional map[string]interface{} `json:"additional,omitempty"`
}

// StreamCompositionConfig controls how streams are generated from TD analysis
type StreamCompositionConfig struct {
	// Stream generation preferences
	CreatePropertyStreams bool `json:"create_property_streams"`
	CreateActionStreams   bool `json:"create_action_streams"`
	CreateEventStreams    bool `json:"create_event_streams"`

	// Default templates and configurations
	DefaultInputTemplate   string                       `json:"default_input_template"`
	DefaultOutputTemplate  string                       `json:"default_output_template"`
	DefaultProcessorChains map[string][]ProcessorConfig `json:"default_processor_chains"`

	// Stream routing and topics
	KafkaBrokers         []string `json:"kafka_brokers,omitempty"`
	DefaultConsumerGroup string   `json:"default_consumer_group,omitempty"`
	TopicPrefix          string   `json:"topic_prefix,omitempty"`

	// Protocol binding preferences
	PreferredProtocols  []string `json:"preferred_protocols,omitempty"`
	EnableBidirectional bool     `json:"enable_bidirectional"`

	// License and feature control
	RequiredFeatures map[string]string `json:"required_features,omitempty"`

	// Output and logging
	ParquetLogPath string `json:"parquet_log_path,omitempty"`
	EnableMetrics  bool   `json:"enable_metrics"`
}

// DefaultStreamCompositionConfig returns sensible defaults for stream composition
func DefaultStreamCompositionConfig() StreamCompositionConfig {
	return StreamCompositionConfig{
		CreatePropertyStreams: true,
		CreateActionStreams:   true,
		CreateEventStreams:    true,
		DefaultInputTemplate:  "input-kafka",
		DefaultOutputTemplate: "output-parquet",
		DefaultProcessorChains: map[string][]ProcessorConfig{
			"properties": {
				{Type: "bloblang_wot_property", Config: map[string]interface{}{}},
				{Type: "parquet_encode", Config: map[string]interface{}{"schema": "wot_property"}},
			},
			"actions": {
				{Type: "bloblang_wot_action", Config: map[string]interface{}{}},
				{Type: "parquet_encode", Config: map[string]interface{}{"schema": "wot_action"}},
			},
			"events": {
				{Type: "bloblang_wot_event", Config: map[string]interface{}{}},
				{Type: "parquet_encode", Config: map[string]interface{}{"schema": "wot_event"}},
			},
		},
		KafkaBrokers:         []string{"localhost:9092"},
		DefaultConsumerGroup: "twincore-default",
		TopicPrefix:          "things",
		PreferredProtocols:   []string{"kafka", "mqtt", "http"},
		EnableBidirectional:  true,
		RequiredFeatures: map[string]string{
			"properties": "property_processing",
			"actions":    "action_processing",
			"events":     "event_processing",
		},
		ParquetLogPath: "./logs",
		EnableMetrics:  true,
	}
}

// SimpleTDStreamComposer implements TDStreamComposer for basic TD analysis and stream generation
type SimpleTDStreamComposer struct {
	logger logrus.FieldLogger
}

// NewSimpleTDStreamComposer creates a new TD stream composer
func NewSimpleTDStreamComposer(logger logrus.FieldLogger) *SimpleTDStreamComposer {
	return &SimpleTDStreamComposer{
		logger: logger,
	}
}

// AnalyzeTD extracts stream-relevant information from a Thing Description
func (c *SimpleTDStreamComposer) AnalyzeTD(ctx context.Context, td map[string]interface{}) (*TDAnalysis, error) {
	analysis := &TDAnalysis{
		Properties: make(map[string]PropertyAffordance),
		Actions:    make(map[string]ActionAffordance),
		Events:     make(map[string]EventAffordance),
		Security:   []SecurityScheme{},
		Forms:      []Form{},
	}

	// Extract basic TD metadata
	if id, ok := td["id"].(string); ok {
		analysis.ThingID = id
	} else {
		return nil, fmt.Errorf("Thing Description missing required 'id' field")
	}

	if title, ok := td["title"].(string); ok {
		analysis.Title = title
	}

	if desc, ok := td["description"].(string); ok {
		analysis.Description = desc
	}

	if base, ok := td["base"].(string); ok {
		analysis.BaseURI = base
	}

	// Extract properties
	if props, ok := td["properties"].(map[string]interface{}); ok {
		for propName, propData := range props {
			if propMap, ok := propData.(map[string]interface{}); ok {
				affordance, err := c.extractPropertyAffordance(propName, propMap)
				if err != nil {
					c.logger.WithError(err).WithField("property", propName).Warn("Failed to extract property affordance")
					continue
				}
				analysis.Properties[propName] = *affordance
			}
		}
	}

	// Extract actions
	if actions, ok := td["actions"].(map[string]interface{}); ok {
		for actionName, actionData := range actions {
			if actionMap, ok := actionData.(map[string]interface{}); ok {
				affordance, err := c.extractActionAffordance(actionName, actionMap)
				if err != nil {
					c.logger.WithError(err).WithField("action", actionName).Warn("Failed to extract action affordance")
					continue
				}
				analysis.Actions[actionName] = *affordance
			}
		}
	}

	// Extract events
	if events, ok := td["events"].(map[string]interface{}); ok {
		for eventName, eventData := range events {
			if eventMap, ok := eventData.(map[string]interface{}); ok {
				affordance, err := c.extractEventAffordance(eventName, eventMap)
				if err != nil {
					c.logger.WithError(err).WithField("event", eventName).Warn("Failed to extract event affordance")
					continue
				}
				analysis.Events[eventName] = *affordance
			}
		}
	}

	// Extract top-level forms
	if forms, ok := td["forms"].([]interface{}); ok {
		for _, formData := range forms {
			if formMap, ok := formData.(map[string]interface{}); ok {
				form := c.extractForm(formMap)
				analysis.Forms = append(analysis.Forms, form)
			}
		}
	}

	// Extract security schemes
	if security, ok := td["security"].([]interface{}); ok {
		for _, secData := range security {
			if secMap, ok := secData.(map[string]interface{}); ok {
				scheme := c.extractSecurityScheme(secMap)
				analysis.Security = append(analysis.Security, scheme)
			}
		}
	}

	c.logger.WithFields(logrus.Fields{
		"thing_id":   analysis.ThingID,
		"properties": len(analysis.Properties),
		"actions":    len(analysis.Actions),
		"events":     len(analysis.Events),
	}).Info("Analyzed Thing Description")

	return analysis, nil
}

// extractPropertyAffordance extracts a property affordance from TD property data
func (c *SimpleTDStreamComposer) extractPropertyAffordance(name string, propData map[string]interface{}) (*PropertyAffordance, error) {
	affordance := &PropertyAffordance{
		Name:   name,
		Forms:  []Form{},
		Schema: make(map[string]interface{}),
	}

	// Extract basic metadata
	if title, ok := propData["title"].(string); ok {
		affordance.Title = title
	}
	if desc, ok := propData["description"].(string); ok {
		affordance.Description = desc
	}
	if propType, ok := propData["type"].(string); ok {
		affordance.Type = propType
	}
	if readOnly, ok := propData["readOnly"].(bool); ok {
		affordance.ReadOnly = readOnly
	}
	if writeOnly, ok := propData["writeOnly"].(bool); ok {
		affordance.WriteOnly = writeOnly
	}
	if observable, ok := propData["observable"].(bool); ok {
		affordance.Observable = observable
	}

	// Extract forms
	if forms, ok := propData["forms"].([]interface{}); ok {
		for _, formData := range forms {
			if formMap, ok := formData.(map[string]interface{}); ok {
				form := c.extractForm(formMap)
				affordance.Forms = append(affordance.Forms, form)
			}
		}
	}

	// Extract schema (copy all non-WoT specific fields)
	for key, value := range propData {
		if !isWoTSpecificField(key) {
			affordance.Schema[key] = value
		}
	}

	return affordance, nil
}

// extractActionAffordance extracts an action affordance from TD action data
func (c *SimpleTDStreamComposer) extractActionAffordance(name string, actionData map[string]interface{}) (*ActionAffordance, error) {
	affordance := &ActionAffordance{
		Name:  name,
		Forms: []Form{},
	}

	// Extract basic metadata
	if title, ok := actionData["title"].(string); ok {
		affordance.Title = title
	}
	if desc, ok := actionData["description"].(string); ok {
		affordance.Description = desc
	}
	if safe, ok := actionData["safe"].(bool); ok {
		affordance.Safe = safe
	}
	if idempotent, ok := actionData["idempotent"].(bool); ok {
		affordance.Idempotent = idempotent
	}

	// Extract input/output schemas
	if input, ok := actionData["input"].(map[string]interface{}); ok {
		affordance.Input = input
	}
	if output, ok := actionData["output"].(map[string]interface{}); ok {
		affordance.Output = output
	}

	// Extract forms
	if forms, ok := actionData["forms"].([]interface{}); ok {
		for _, formData := range forms {
			if formMap, ok := formData.(map[string]interface{}); ok {
				form := c.extractForm(formMap)
				affordance.Forms = append(affordance.Forms, form)
			}
		}
	}

	return affordance, nil
}

// extractEventAffordance extracts an event affordance from TD event data
func (c *SimpleTDStreamComposer) extractEventAffordance(name string, eventData map[string]interface{}) (*EventAffordance, error) {
	affordance := &EventAffordance{
		Name:  name,
		Forms: []Form{},
	}

	// Extract basic metadata
	if title, ok := eventData["title"].(string); ok {
		affordance.Title = title
	}
	if desc, ok := eventData["description"].(string); ok {
		affordance.Description = desc
	}

	// Extract data schemas
	if data, ok := eventData["data"].(map[string]interface{}); ok {
		affordance.Data = data
	}
	if dataResponse, ok := eventData["dataResponse"].(map[string]interface{}); ok {
		affordance.DataResponse = dataResponse
	}

	// Extract forms
	if forms, ok := eventData["forms"].([]interface{}); ok {
		for _, formData := range forms {
			if formMap, ok := formData.(map[string]interface{}); ok {
				form := c.extractForm(formMap)
				affordance.Forms = append(affordance.Forms, form)
			}
		}
	}

	return affordance, nil
}

// extractForm extracts form information from TD form data
func (c *SimpleTDStreamComposer) extractForm(formData map[string]interface{}) Form {
	form := Form{}

	if href, ok := formData["href"].(string); ok {
		form.Href = href
	}
	if contentType, ok := formData["contentType"].(string); ok {
		form.ContentType = contentType
	}
	if subprotocol, ok := formData["subprotocol"].(string); ok {
		form.Subprotocol = subprotocol
	}

	// Extract operations
	if ops, ok := formData["op"].([]interface{}); ok {
		for _, op := range ops {
			if opStr, ok := op.(string); ok {
				form.Op = append(form.Op, opStr)
			}
		}
	}

	// Extract security
	if security, ok := formData["security"].([]interface{}); ok {
		for _, sec := range security {
			if secStr, ok := sec.(string); ok {
				form.Security = append(form.Security, secStr)
			}
		}
	}

	return form
}

// extractSecurityScheme extracts security scheme information
func (c *SimpleTDStreamComposer) extractSecurityScheme(secData map[string]interface{}) SecurityScheme {
	scheme := SecurityScheme{
		Additional: make(map[string]interface{}),
	}

	if schemeType, ok := secData["scheme"].(string); ok {
		scheme.Scheme = schemeType
	}
	if name, ok := secData["name"].(string); ok {
		scheme.Name = name
	}
	if in, ok := secData["in"].(string); ok {
		scheme.In = in
	}

	// Copy additional fields
	for key, value := range secData {
		if key != "scheme" && key != "name" && key != "in" {
			scheme.Additional[key] = value
		}
	}

	return scheme
}

// isWoTSpecificField checks if a field is WoT-specific metadata
func isWoTSpecificField(field string) bool {
	wotFields := []string{
		"title", "description", "forms", "readOnly", "writeOnly", "observable",
		"safe", "idempotent", "input", "output", "data", "dataResponse",
		"@context", "@type", "security",
	}

	for _, wotField := range wotFields {
		if field == wotField {
			return true
		}
	}

	return strings.HasPrefix(field, "@")
}

// ComposeStreams generates StreamCreationRequests for all interactions in a TD
func (c *SimpleTDStreamComposer) ComposeStreams(ctx context.Context, analysis *TDAnalysis, config StreamCompositionConfig) ([]StreamCreationRequest, error) {
	var requests []StreamCreationRequest

	// Generate streams for properties
	if config.CreatePropertyStreams {
		for propName, propAffordance := range analysis.Properties {
			request, err := c.generatePropertyStream(analysis.ThingID, propName, propAffordance, config)
			if err != nil {
				c.logger.WithError(err).WithFields(logrus.Fields{
					"thing_id": analysis.ThingID,
					"property": propName,
				}).Warn("Failed to generate property stream")
				continue
			}
			if request != nil {
				requests = append(requests, *request)
			}
		}
	}

	// Generate streams for actions
	if config.CreateActionStreams {
		for actionName, actionAffordance := range analysis.Actions {
			request, err := c.generateActionStream(analysis.ThingID, actionName, actionAffordance, config)
			if err != nil {
				c.logger.WithError(err).WithFields(logrus.Fields{
					"thing_id": analysis.ThingID,
					"action":   actionName,
				}).Warn("Failed to generate action stream")
				continue
			}
			if request != nil {
				requests = append(requests, *request)
			}
		}
	}

	// Generate streams for events
	if config.CreateEventStreams {
		for eventName, eventAffordance := range analysis.Events {
			request, err := c.generateEventStream(analysis.ThingID, eventName, eventAffordance, config)
			if err != nil {
				c.logger.WithError(err).WithFields(logrus.Fields{
					"thing_id": analysis.ThingID,
					"event":    eventName,
				}).Warn("Failed to generate event stream")
				continue
			}
			if request != nil {
				requests = append(requests, *request)
			}
		}
	}

	c.logger.WithFields(logrus.Fields{
		"thing_id": analysis.ThingID,
		"streams":  len(requests),
	}).Info("Generated stream creation requests from TD analysis")

	return requests, nil
}

// ComposeStreamForInteraction generates a single stream for a specific interaction
func (c *SimpleTDStreamComposer) ComposeStreamForInteraction(ctx context.Context, thingID string, interactionType string, interactionName string, affordance map[string]interface{}, config StreamCompositionConfig) (*StreamCreationRequest, error) {
	switch interactionType {
	case "properties":
		propAffordance, err := c.mapToPropertyAffordance(interactionName, affordance)
		if err != nil {
			return nil, fmt.Errorf("failed to map to property affordance: %w", err)
		}
		return c.generatePropertyStream(thingID, interactionName, *propAffordance, config)

	case "actions":
		actionAffordance, err := c.mapToActionAffordance(interactionName, affordance)
		if err != nil {
			return nil, fmt.Errorf("failed to map to action affordance: %w", err)
		}
		return c.generateActionStream(thingID, interactionName, *actionAffordance, config)

	case "events":
		eventAffordance, err := c.mapToEventAffordance(interactionName, affordance)
		if err != nil {
			return nil, fmt.Errorf("failed to map to event affordance: %w", err)
		}
		return c.generateEventStream(thingID, interactionName, *eventAffordance, config)

	default:
		return nil, fmt.Errorf("unsupported interaction type: %s", interactionType)
	}
}

// generatePropertyStream creates a stream configuration for a WoT property
func (c *SimpleTDStreamComposer) generatePropertyStream(thingID string, propName string, affordance PropertyAffordance, config StreamCompositionConfig) (*StreamCreationRequest, error) {
	// Determine stream direction based on property characteristics
	directions := []string{}

	if !affordance.WriteOnly {
		// Property is readable - create inbound stream (device -> twincore)
		directions = append(directions, "inbound")
	}

	if !affordance.ReadOnly && config.EnableBidirectional {
		// Property is writable - create outbound stream (twincore -> device)
		directions = append(directions, "outbound")
	}

	// Generate streams for each direction
	var requests []StreamCreationRequest
	for _, direction := range directions {
		input := c.generateInputConfig(thingID, "properties", propName, direction, affordance.Forms, config)
		output := c.generateOutputConfig(thingID, "properties", propName, direction, config)
		processors := c.getProcessorChain("properties", config)

		request := StreamCreationRequest{
			ThingID:         thingID,
			InteractionType: "properties",
			InteractionName: propName,
			Direction:       direction,
			Input:           input,
			Output:          output,
			ProcessorChain:  processors,
			Metadata: map[string]interface{}{
				"affordance_type": "property",
				"readable":        !affordance.WriteOnly,
				"writable":        !affordance.ReadOnly,
				"observable":      affordance.Observable,
				"data_type":       affordance.Type,
				"schema":          affordance.Schema,
			},
		}

		requests = append(requests, request)
	}

	// Return the first request (prefer inbound for properties)
	if len(requests) > 0 {
		return &requests[0], nil
	}

	return nil, nil
}

// generateActionStream creates a stream configuration for a WoT action
func (c *SimpleTDStreamComposer) generateActionStream(thingID string, actionName string, affordance ActionAffordance, config StreamCompositionConfig) (*StreamCreationRequest, error) {
	// Actions typically flow inbound (requests to device) and outbound (responses from device)
	direction := "inbound" // Default to inbound for action invocations

	input := c.generateInputConfig(thingID, "actions", actionName, direction, affordance.Forms, config)
	output := c.generateOutputConfig(thingID, "actions", actionName, direction, config)
	processors := c.getProcessorChain("actions", config)

	request := StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "actions",
		InteractionName: actionName,
		Direction:       direction,
		Input:           input,
		Output:          output,
		ProcessorChain:  processors,
		Metadata: map[string]interface{}{
			"affordance_type": "action",
			"safe":            affordance.Safe,
			"idempotent":      affordance.Idempotent,
			"input_schema":    affordance.Input,
			"output_schema":   affordance.Output,
		},
	}

	return &request, nil
}

// generateEventStream creates a stream configuration for a WoT event
func (c *SimpleTDStreamComposer) generateEventStream(thingID string, eventName string, affordance EventAffordance, config StreamCompositionConfig) (*StreamCreationRequest, error) {
	// Events typically flow outbound (from device to subscribers)
	direction := "outbound"

	input := c.generateInputConfig(thingID, "events", eventName, direction, affordance.Forms, config)
	output := c.generateOutputConfig(thingID, "events", eventName, direction, config)
	processors := c.getProcessorChain("events", config)

	request := StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "events",
		InteractionName: eventName,
		Direction:       direction,
		Input:           input,
		Output:          output,
		ProcessorChain:  processors,
		Metadata: map[string]interface{}{
			"affordance_type": "event",
			"data_schema":     affordance.Data,
			"response_schema": affordance.DataResponse,
		},
	}

	return &request, nil
}

// generateInputConfig creates input configuration based on interaction and available forms
func (c *SimpleTDStreamComposer) generateInputConfig(thingID, interactionType, interactionName, direction string, forms []Form, config StreamCompositionConfig) StreamEndpointConfig {
	// Analyze forms to determine best input protocol
	protocol := c.selectInputProtocol(forms, config.PreferredProtocols)

	topic := fmt.Sprintf("%s.%s.%s.%s", config.TopicPrefix, thingID, interactionType, interactionName)

	switch protocol {
	case "kafka":
		return StreamEndpointConfig{
			Type: "kafka",
			Config: map[string]interface{}{
				"topic":          topic,
				"consumer_group": fmt.Sprintf("%s-%s-%s", config.DefaultConsumerGroup, interactionType, thingID),
			},
		}
	case "mqtt":
		return StreamEndpointConfig{
			Type: "mqtt",
			Config: map[string]interface{}{
				"topic": strings.ReplaceAll(topic, ".", "/"),
				"qos":   1,
			},
		}
	case "http":
		return StreamEndpointConfig{
			Type: "http_server",
			Config: map[string]interface{}{
				"path": fmt.Sprintf("/things/%s/%s/%s", thingID, interactionType, interactionName),
			},
		}
	default:
		// Default to Kafka
		return StreamEndpointConfig{
			Type: "kafka",
			Config: map[string]interface{}{
				"topic":          topic,
				"consumer_group": fmt.Sprintf("%s-%s-%s", config.DefaultConsumerGroup, interactionType, thingID),
			},
		}
	}
}

// generateOutputConfig creates output configuration based on interaction and direction
func (c *SimpleTDStreamComposer) generateOutputConfig(thingID, interactionType, interactionName, direction string, config StreamCompositionConfig) StreamEndpointConfig {
	if config.ParquetLogPath != "" {
		// Output to Parquet for logging
		return StreamEndpointConfig{
			Type: "parquet",
			Config: map[string]interface{}{
				"path": fmt.Sprintf("%s/%s/%s_%s.parquet", config.ParquetLogPath, interactionType, interactionType, "${!timestamp_unix():yyyy-MM-dd}"),
			},
		}
	}

	// Default to Kafka output
	topic := fmt.Sprintf("%s.%s.%s.%s.%s", config.TopicPrefix, thingID, interactionType, interactionName, direction)
	return StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"topic": topic,
		},
	}
}

// selectInputProtocol selects the best input protocol from available forms
func (c *SimpleTDStreamComposer) selectInputProtocol(forms []Form, preferredProtocols []string) string {
	// Extract protocols from forms
	availableProtocols := make(map[string]bool)
	for _, form := range forms {
		if strings.HasPrefix(form.Href, "kafka://") {
			availableProtocols["kafka"] = true
		} else if strings.HasPrefix(form.Href, "mqtt://") || strings.HasPrefix(form.Href, "mqtts://") {
			availableProtocols["mqtt"] = true
		} else if strings.HasPrefix(form.Href, "http://") || strings.HasPrefix(form.Href, "https://") {
			availableProtocols["http"] = true
		}
	}

	// Select based on preference order
	for _, preferred := range preferredProtocols {
		if availableProtocols[preferred] {
			return preferred
		}
	}

	// Default to first available or kafka
	for protocol := range availableProtocols {
		return protocol
	}

	return "kafka"
}

// getProcessorChain returns the default processor chain for an interaction type
func (c *SimpleTDStreamComposer) getProcessorChain(interactionType string, config StreamCompositionConfig) []ProcessorConfig {
	if chain, exists := config.DefaultProcessorChains[interactionType]; exists {
		return chain
	}

	// Fallback to basic chain
	return []ProcessorConfig{
		{Type: fmt.Sprintf("bloblang_wot_%s", strings.TrimSuffix(interactionType, "s")), Config: map[string]interface{}{}},
	}
}

// Helper methods for mapping affordances from generic interfaces

// mapToPropertyAffordance converts generic map to PropertyAffordance
func (c *SimpleTDStreamComposer) mapToPropertyAffordance(name string, data map[string]interface{}) (*PropertyAffordance, error) {
	return c.extractPropertyAffordance(name, data)
}

// mapToActionAffordance converts generic map to ActionAffordance
func (c *SimpleTDStreamComposer) mapToActionAffordance(name string, data map[string]interface{}) (*ActionAffordance, error) {
	return c.extractActionAffordance(name, data)
}

// mapToEventAffordance converts generic map to EventAffordance
func (c *SimpleTDStreamComposer) mapToEventAffordance(name string, data map[string]interface{}) (*EventAffordance, error) {
	return c.extractEventAffordance(name, data)
}

// Ensure SimpleTDStreamComposer implements TDStreamComposer interface
var _ TDStreamComposer = (*SimpleTDStreamComposer)(nil)
