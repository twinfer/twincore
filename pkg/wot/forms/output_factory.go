package forms

import (
	"fmt"
	"strings"

	"github.com/twinfer/twincore/pkg/types"
)

// OutputConfigFactory creates output configurations for different types
type OutputConfigFactory struct {
	handlers map[string]OutputHandler
}

// OutputHandler generates configuration for a specific output type
type OutputHandler func(params StreamEndpointParams) (types.StreamEndpointConfig, error)

// NewOutputConfigFactory creates a new output configuration factory
func NewOutputConfigFactory() *OutputConfigFactory {
	factory := &OutputConfigFactory{
		handlers: make(map[string]OutputHandler),
	}
	factory.registerDefaultHandlers()
	return factory
}

// registerDefaultHandlers registers built-in output handlers
func (f *OutputConfigFactory) registerDefaultHandlers() {
	// File output handler
	f.handlers["file"] = func(params StreamEndpointParams) (types.StreamEndpointConfig, error) {
		config := map[string]interface{}{
			"path": params.Config["path"],
		}

		// Add codec if specified
		if codec, ok := params.Config["codec"]; ok {
			config["codec"] = codec
		}

		return types.StreamEndpointConfig{
			Type:   "file",
			Config: config,
		}, nil
	}

	// S3 output handler
	f.handlers["s3"] = func(params StreamEndpointParams) (types.StreamEndpointConfig, error) {
		bucket, ok := params.Config["bucket"].(string)
		if !ok {
			return types.StreamEndpointConfig{}, fmt.Errorf("s3 output requires 'bucket' parameter")
		}

		path, ok := params.Config["path"].(string)
		if !ok {
			return types.StreamEndpointConfig{}, fmt.Errorf("s3 output requires 'path' parameter")
		}

		config := map[string]interface{}{
			"bucket": bucket,
			"path":   path,
			"region": params.Config["region"],
		}

		// Add optional parameters
		if endpoint, ok := params.Config["endpoint"]; ok {
			config["endpoint"] = endpoint
		}

		return types.StreamEndpointConfig{
			Type:   "aws_s3",
			Config: config,
		}, nil
	}

	// Parquet output handler
	f.handlers["parquet"] = func(params StreamEndpointParams) (types.StreamEndpointConfig, error) {
		path, ok := params.Config["path"].(string)
		if !ok {
			return types.StreamEndpointConfig{}, fmt.Errorf("parquet output requires 'path' parameter")
		}

		schema, ok := params.Config["schema"].([]map[string]interface{})
		if !ok {
			return types.StreamEndpointConfig{}, fmt.Errorf("parquet output requires 'schema' parameter")
		}

		// Wrap in file output
		return types.StreamEndpointConfig{
			Type: "file",
			Config: map[string]interface{}{
				"path": path,
				"codec": map[string]interface{}{
					"parquet": map[string]interface{}{
						"schema":            schema,
						"compression":       params.Config["compression"],
						"compression_level": params.Config["compression_level"],
					},
				},
			},
		}, nil
	}

	// Stream bridge output handler (internal)
	f.handlers["stream_bridge"] = func(params StreamEndpointParams) (types.StreamEndpointConfig, error) {
		stream, ok := params.Config["stream"].(string)
		if !ok {
			return types.StreamEndpointConfig{}, fmt.Errorf("stream_bridge output requires 'stream' parameter")
		}

		return types.StreamEndpointConfig{
			Type: "resource",
			Config: map[string]interface{}{
				"stream_bridge": stream,
			},
		}, nil
	}

	// Stdout output handler (for debugging)
	f.handlers["stdout"] = func(params StreamEndpointParams) (types.StreamEndpointConfig, error) {
		config := map[string]interface{}{}

		if codec, ok := params.Config["codec"]; ok {
			config["codec"] = codec
		}

		return types.StreamEndpointConfig{
			Type:   "stdout",
			Config: config,
		}, nil
	}

	// Drop output handler (discard data)
	f.handlers["drop"] = func(params StreamEndpointParams) (types.StreamEndpointConfig, error) {
		return types.StreamEndpointConfig{
			Type:   "drop",
			Config: map[string]interface{}{},
		}, nil
	}

	// Switch output handler (conditional routing)
	f.handlers["switch"] = func(params StreamEndpointParams) (types.StreamEndpointConfig, error) {
		cases, ok := params.Config["cases"].([]interface{})
		if !ok {
			return types.StreamEndpointConfig{}, fmt.Errorf("switch output requires 'cases' parameter")
		}

		return types.StreamEndpointConfig{
			Type: "switch",
			Config: map[string]interface{}{
				"cases": cases,
			},
		}, nil
	}
}

// Generate creates an output configuration for the specified type
func (f *OutputConfigFactory) Generate(outputType string, params StreamEndpointParams) (types.StreamEndpointConfig, error) {
	// Normalize output type
	outputType = strings.ToLower(outputType)

	handler, exists := f.handlers[outputType]
	if !exists {
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported output type: %s", outputType)
	}

	return handler(params)
}

// RegisterHandler adds a custom output handler
func (f *OutputConfigFactory) RegisterHandler(outputType string, handler OutputHandler) {
	f.handlers[strings.ToLower(outputType)] = handler
}

// GetSupportedTypes returns a list of supported output types
func (f *OutputConfigFactory) GetSupportedTypes() []string {
	types := make([]string, 0, len(f.handlers))
	for t := range f.handlers {
		types = append(types, t)
	}
	return types
}

// GeneratePersistenceOutput creates output configuration for data persistence
func (f *OutputConfigFactory) GeneratePersistenceOutput(format string, basePath string, thingID string, interactionType string, interactionName string, schema interface{}) (types.StreamEndpointConfig, error) {
	// Build path
	pathPattern := fmt.Sprintf("%s/%s/%s/%s/${!timestamp(\"2006/01/02\")}/data_${!timestamp(\"20060102_150405\")}.%s",
		basePath, thingID, interactionType, interactionName, format)

	params := StreamEndpointParams{
		Type: format,
		Config: map[string]interface{}{
			"path": pathPattern,
		},
	}

	// Add format-specific configuration
	switch format {
	case "parquet":
		params.Config["schema"] = schema
		params.Config["compression"] = "snappy"
		params.Config["compression_level"] = 0
	case "json":
		params.Config["codec"] = map[string]interface{}{
			"json_lines": map[string]interface{}{},
		}
	case "csv":
		params.Config["codec"] = map[string]interface{}{
			"csv": map[string]interface{}{},
		}
	}

	return f.Generate(format, params)
}