package forms

import (
	"bytes"
	"fmt"
	"text/template"
)

// MappingEngine generates Bloblang mappings for stream processors
type MappingEngine struct {
	templates map[string]*template.Template
}

// NewMappingEngine creates a new mapping engine
func NewMappingEngine() *MappingEngine {
	engine := &MappingEngine{
		templates: make(map[string]*template.Template),
	}
	engine.initializeTemplates()
	return engine
}

// MappingConfig contains parameters for generating a mapping
type MappingConfig struct {
	Type            string // "property", "action", "event"
	Purpose         string // "observation", "command", "persistence", etc.
	ThingID         string
	InteractionName string
	Parameters      map[string]interface{}
}

// initializeTemplates sets up the mapping templates
func (e *MappingEngine) initializeTemplates() {
	// Base template with common fields
	baseTemplate := `root.thing_id = "{{.ThingID}}"
root.timestamp = timestamp_unix_nano()
root.source = "wot_gateway"`

	// Property observation mapping
	e.registerTemplate("property_observation", baseTemplate+`
root.property_name = "{{.InteractionName}}"
root.property_value = this.{{.ValuePath | default "value"}}`+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// Property persistence mapping
	e.registerTemplate("property_persistence", baseTemplate+`
root.property_name = "{{.InteractionName}}"
root.property_value = this.{{.ValuePath | default "property_value"}}`+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// Action command mapping
	e.registerTemplate("action_command", baseTemplate+`
root.action_name = "{{.InteractionName}}"
root.command_id = uuid_v4()
root.action_params = this.{{.ParamsPath | default "params"}}
root.correlation_id = meta("correlation_id")`+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// Action result mapping
	e.registerTemplate("action_result", baseTemplate+`
root.action_name = "{{.InteractionName}}"
root.command_id = this.{{.CommandIdPath | default "command_id"}}
root.result = this.{{.ResultPath | default "result"}}
root.status = this.{{.StatusPath | default "status"}}
root.correlation_id = this.{{.CorrelationIdPath | default "correlation_id"}}`+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// Action persistence mapping
	e.registerTemplate("action_persistence", baseTemplate+`
root.action_name = "{{.InteractionName}}"
root.command_id = this.{{.CommandIdPath | default "command_id"}}
root.action_params = this.{{.ParamsPath | default "action_params"}}
root.result = this.{{.ResultPath | default "result"}}
root.status = this.{{.StatusPath | default "status"}}`+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// Event notification mapping
	e.registerTemplate("event_notification", baseTemplate+`
root.event_name = "{{.InteractionName}}"
root.event_data = this.{{.DataPath | default "data"}}
root.event_id = uuid_v4()`+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// Event persistence mapping
	e.registerTemplate("event_persistence", baseTemplate+`
root.event_name = "{{.InteractionName}}"
root.event_data = this.{{.DataPath | default "event_data"}}
root.event_id = this.{{.EventIdPath | default "event_id"}}`+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// Device-to-WoT mapping (for incoming device data)
	e.registerTemplate("device_to_wot", `root = this
root.thing_id = "{{.ThingID}}"
root.timestamp = timestamp_unix_nano()
root.{{.InteractionType}}_name = "{{.InteractionName}}"`+
		"{{if .ValueTransform}}\nroot.value = {{.ValueTransform}}{{end}}"+
		"{{if .AdditionalFields}}{{range $k, $v := .AdditionalFields}}\nroot.{{$k}} = {{$v}}{{end}}{{end}}")

	// WoT-to-device mapping (for outgoing device commands)
	e.registerTemplate("wot_to_device", `root = this.{{.PayloadPath | default "action_params"}}`+
		"{{if .Transform}}\n{{.Transform}}{{end}}")

	// Generic transformation mapping
	e.registerTemplate("transform", "{{.Expression}}")
}

// registerTemplate adds a template to the engine
func (e *MappingEngine) registerTemplate(name string, tmpl string) {
	funcMap := template.FuncMap{
		"default": func(defaultVal, val interface{}) interface{} {
			if val == nil || val == "" {
				return defaultVal
			}
			return val
		},
	}

	t := template.New(name).Funcs(funcMap)
	parsed, err := t.Parse(tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to parse template %s: %v", name, err))
	}
	e.templates[name] = parsed
}

// GenerateMapping creates a Bloblang mapping based on configuration
func (e *MappingEngine) GenerateMapping(config MappingConfig) (string, error) {
	// Determine template key
	templateKey := e.getTemplateKey(config)

	// Get template
	tmpl, exists := e.templates[templateKey]
	if !exists {
		// Fallback to generic transform if custom expression provided
		if expr, ok := config.Parameters["expression"].(string); ok {
			return e.generateCustomMapping(expr)
		}
		return "", fmt.Errorf("no template found for %s_%s", config.Type, config.Purpose)
	}

	// Prepare template data
	data := e.prepareTemplateData(config)

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// getTemplateKey determines which template to use
func (e *MappingEngine) getTemplateKey(config MappingConfig) string {
	// Special cases
	if config.Purpose == "device_bridge" {
		if config.Parameters["direction"] == "to_device" {
			return "wot_to_device"
		}
		return "device_to_wot"
	}

	// Standard pattern: type_purpose
	return fmt.Sprintf("%s_%s", config.Type, config.Purpose)
}

// prepareTemplateData prepares data for template execution
func (e *MappingEngine) prepareTemplateData(config MappingConfig) map[string]interface{} {
	data := map[string]interface{}{
		"ThingID":         config.ThingID,
		"InteractionName": config.InteractionName,
		"InteractionType": config.Type,
	}

	// Copy all parameters
	for k, v := range config.Parameters {
		data[k] = v
	}

	// Extract common patterns
	if additionalFields, ok := config.Parameters["additional_fields"].(map[string]interface{}); ok {
		data["AdditionalFields"] = additionalFields
	}

	return data
}

// generateCustomMapping creates a mapping from a custom expression
func (e *MappingEngine) generateCustomMapping(expression string) (string, error) {
	tmpl, exists := e.templates["transform"]
	if !exists {
		return expression, nil // Return as-is
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]interface{}{"Expression": expression}); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GetAvailableMappings returns a list of available mapping types
func (e *MappingEngine) GetAvailableMappings() []string {
	mappings := make([]string, 0, len(e.templates))
	for name := range e.templates {
		mappings = append(mappings, name)
	}
	return mappings
}

// AddCustomTemplate allows adding custom mapping templates
func (e *MappingEngine) AddCustomTemplate(name string, template string) error {
	e.registerTemplate(name, template)
	return nil
}
