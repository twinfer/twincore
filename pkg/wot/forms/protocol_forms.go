package forms

import (
	"bytes"
	"text/template" // For executeTemplate

	"github.com/twinfer/twincore/pkg/types" // For GetStreamDirection
)

// executeTemplate parses and executes a template with the given data.
func executeTemplate(templateName, tmplStr string, data map[string]interface{}) (string, error) {
	tmpl, err := template.New(templateName).Parse(tmplStr)
	if err != nil {
		// If detailed error wrapping with fmt.Errorf is desired here, fmt would be needed.
		// For now, returning raw error from template package.
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GetStreamDirection determines stream direction based on WoT operations
// This function is used by the GetStreamDirection methods of the forms
// and needs to be accessible.
func GetStreamDirection(ops []string) types.StreamDirection {
	for _, op := range ops {
		switch op {
		case "readproperty", "observeproperty", "subscribeevent":
			return types.StreamDirectionInbound
		case "writeproperty", "invokeaction":
			return types.StreamDirectionOutbound
		}
	}
	return types.StreamDirectionInternal
}
