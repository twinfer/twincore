package forms

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
)

//go:embed templates/*.yaml
var templateFiles embed.FS

// TemplateExecutor handles template execution for stream configurations
type TemplateExecutor struct {
	templates map[string]*template.Template
}

// NewTemplateExecutor creates a new template executor
func NewTemplateExecutor() *TemplateExecutor {
	executor := &TemplateExecutor{
		templates: make(map[string]*template.Template),
	}
	executor.loadTemplates()
	return executor
}

// loadTemplates loads all embedded templates
func (e *TemplateExecutor) loadTemplates() {
	// Load protocol templates
	protocolTemplates := map[string]string{
		"http_client": "templates/http_client.yaml",
		"http_server": "templates/http_server.yaml",
		"kafka_input": "templates/kafka_input.yaml",
		"kafka_output": "templates/kafka_output.yaml",
		"mqtt_input":  "templates/mqtt_input.yaml",
		"mqtt_output": "templates/mqtt_output.yaml",
	}

	for name, path := range protocolTemplates {
		data, err := templateFiles.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("failed to read template %s: %v", path, err))
		}

		funcMap := template.FuncMap{
			"default": func(defaultVal, val interface{}) interface{} {
				if val == nil || val == "" {
					return defaultVal
				}
				return val
			},
		}
		
		tmpl, err := template.New(name).Funcs(funcMap).Parse(string(data))
		if err != nil {
			panic(fmt.Sprintf("failed to parse template %s: %v", name, err))
		}

		e.templates[name] = tmpl
	}
}

// Execute runs a template with the given data
func (e *TemplateExecutor) Execute(templateName string, data interface{}) (string, error) {
	tmpl, exists := e.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

// ExecuteWithFuncs runs a template with custom functions
func (e *TemplateExecutor) ExecuteWithFuncs(templateName string, data interface{}, funcs template.FuncMap) (string, error) {
	tmpl, exists := e.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	// Clone template and add functions
	tmplWithFuncs := tmpl.Funcs(funcs)

	var buf bytes.Buffer
	if err := tmplWithFuncs.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

// RegisterTemplate adds a custom template
func (e *TemplateExecutor) RegisterTemplate(name string, templateContent string) error {
	tmpl, err := template.New(name).Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	e.templates[name] = tmpl
	return nil
}

// HasTemplate checks if a template exists
func (e *TemplateExecutor) HasTemplate(name string) bool {
	_, exists := e.templates[name]
	return exists
}

// GetTemplateNames returns all registered template names
func (e *TemplateExecutor) GetTemplateNames() []string {
	names := make([]string, 0, len(e.templates))
	for name := range e.templates {
		names = append(names, name)
	}
	return names
}