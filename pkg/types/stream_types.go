package types

// StreamCreationRequest represents a request to create a Benthos stream
type StreamCreationRequest struct {
	ThingID         string               `json:"thing_id"`
	InteractionType string               `json:"interaction_type"` // "properties", "actions", "events"
	InteractionName string               `json:"interaction_name"`
	Direction       string               `json:"direction"` // "input", "output", "bidirectional"
	ProcessorChain  []ProcessorConfig    `json:"processor_chain"`
	Input           StreamEndpointConfig `json:"input"`
	Output          StreamEndpointConfig `json:"output"`
	Metadata        map[string]any       `json:"metadata,omitempty"`
}

// ProcessorConfig defines a processor in the chain
type ProcessorConfig struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

// StreamEndpointConfig defines an input or output endpoint
type StreamEndpointConfig struct {
	Type   string         `json:"type"` // "kafka", "http", "mqtt", etc.
	Config map[string]any `json:"config"`
}

// StreamInfo represents a created stream
type StreamInfo struct {
	ID              string               `json:"id"`
	ThingID         string               `json:"thing_id"`
	InteractionType string               `json:"interaction_type"`
	InteractionName string               `json:"interaction_name"`
	Direction       string               `json:"direction"`
	ProcessorChain  []ProcessorConfig    `json:"processor_chain"`
	Input           StreamEndpointConfig `json:"input"`
	Output          StreamEndpointConfig `json:"output"`
	Status          string               `json:"status"`
	CreatedAt       string               `json:"created_at"`
	UpdatedAt       string               `json:"updated_at"`
	Metadata        map[string]any       `json:"metadata,omitempty"`
}

// StreamFilters for querying streams
type StreamFilters struct {
	ThingID         string `json:"thing_id,omitempty"`
	InteractionType string `json:"interaction_type,omitempty"`
	Status          string `json:"status,omitempty"`
}

// StreamUpdateRequest represents a request to update a stream
type StreamUpdateRequest struct {
	ProcessorChain []ProcessorConfig     `json:"processor_chain,omitempty"`
	Input          *StreamEndpointConfig `json:"input,omitempty"`
	Output         *StreamEndpointConfig `json:"output,omitempty"`
	Metadata       map[string]any        `json:"metadata,omitempty"`
}

// ProcessorCollection represents a collection of processors
type ProcessorCollection struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Processors  []ProcessorConfig `json:"processors"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

// ProcessorCollectionRequest represents a request to create a processor collection
type ProcessorCollectionRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Processors  []ProcessorConfig `json:"processors"`
}

// StreamStatus represents the runtime status of a stream
type StreamStatus struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"` // "running", "stopped", "error"
	Error       string         `json:"error,omitempty"`
	Metrics     map[string]any `json:"metrics,omitempty"`
	LastUpdated string         `json:"last_updated"`
}
