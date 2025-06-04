package types

import "time"

// AllBindings contains all generated bindings for a Thing Description
type AllBindings struct {
	ThingID     string                         `json:"thing_id"`
	HTTPRoutes  map[string]BindingHTTPRoute    `json:"http_routes"`
	Streams     map[string]BenthosStreamConfig `json:"streams"`
	Processors  map[string]ProcessorChain      `json:"processors"`
	GeneratedAt time.Time                      `json:"generated_at"`
}

// BindingHTTPRoute represents an HTTP endpoint configuration for WoT bindings
type BindingHTTPRoute struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers,omitempty"`
	Security    []string          `json:"security,omitempty"`
}

// BenthosStreamConfig represents a complete Benthos stream configuration
type BenthosStreamConfig struct {
	ID             string            `json:"id"`
	Type           BenthosStreamType `json:"type"`
	Direction      StreamDirection   `json:"direction"`
	Input          StreamEndpoint    `json:"input"`
	Output         StreamEndpoint    `json:"output"`
	ProcessorChain ProcessorChain    `json:"processor_chain"`
	YAML           string            `json:"yaml"`
}

// StreamEndpoint represents input/output configuration for streams
type StreamEndpoint struct {
	Protocol StreamProtocol `json:"protocol"`
	Config   map[string]any `json:"config"`
}

// ProcessorChain represents a sequence of Benthos processors
type ProcessorChain struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Processors []ProcessorConfigItem `json:"processors"`
	Metadata   map[string]any        `json:"metadata,omitempty"`
}

// ProcessorConfigItem represents a single Benthos processor configuration
type ProcessorConfigItem struct {
	Type        BenthosProcessorType `json:"type"`
	Label       string               `json:"label"`
	Config      map[string]any       `json:"config"`
	Description string               `json:"description,omitempty"`
}
