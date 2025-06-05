package types

// StreamCreationRequest represents a request to create a Benthos stream
// @Description Request body for creating a new data processing stream
type StreamCreationRequest struct {
	ThingID         string               `json:"thing_id" example:"device-001" description:"ID of the WoT Thing"`
	InteractionType string               `json:"interaction_type" example:"properties" description:"Type of interaction: properties, actions, or events"`
	InteractionName string               `json:"interaction_name" example:"temperature" description:"Name of the specific property, action, or event"`
	Direction       string               `json:"direction" example:"input" description:"Data flow direction: input, output, or bidirectional"`
	ProcessorChain  []ProcessorConfig    `json:"processor_chain" description:"Chain of data processors to apply"`
	Input           StreamEndpointConfig `json:"input" description:"Input endpoint configuration"`
	Output          StreamEndpointConfig `json:"output" description:"Output endpoint configuration"`
	Metadata        map[string]any       `json:"metadata,omitempty" description:"Additional metadata for the stream"`
}

// ProcessorConfig defines a processor in the chain
// @Description Configuration for a data processor in the processing pipeline
type ProcessorConfig struct {
	Type   string         `json:"type" example:"json_validation" description:"Type of processor"`
	Config map[string]any `json:"config" description:"Processor-specific configuration"`
}

// StreamEndpointConfig defines an input or output endpoint
// @Description Configuration for stream input or output endpoint
type StreamEndpointConfig struct {
	Type   string         `json:"type" example:"kafka" description:"Endpoint type: kafka, http, mqtt, etc."`
	Config map[string]any `json:"config" description:"Endpoint-specific configuration"`
}

// StreamInfo represents a created stream
// @Description Information about a created data processing stream
type StreamInfo struct {
	ID              string               `json:"id" example:"stream-123" description:"Unique stream identifier"`
	ThingID         string               `json:"thing_id" example:"device-001" description:"ID of the associated WoT Thing"`
	InteractionType string               `json:"interaction_type" example:"properties" description:"Type of interaction"`
	InteractionName string               `json:"interaction_name" example:"temperature" description:"Name of the interaction"`
	Direction       string               `json:"direction" example:"input" description:"Data flow direction"`
	ProcessorChain  []ProcessorConfig    `json:"processor_chain" description:"Configured processor chain"`
	Input           StreamEndpointConfig `json:"input" description:"Input endpoint configuration"`
	Output          StreamEndpointConfig `json:"output" description:"Output endpoint configuration"`
	Status          string               `json:"status" example:"running" description:"Current stream status"`
	CreatedAt       string               `json:"created_at" example:"2023-12-01T10:30:00Z" description:"Creation timestamp"`
	UpdatedAt       string               `json:"updated_at" example:"2023-12-01T10:30:00Z" description:"Last update timestamp"`
	Metadata        map[string]any       `json:"metadata,omitempty" description:"Additional stream metadata"`
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
// @Description Reusable collection of data processors that can be applied to streams
type ProcessorCollection struct {
	ID          string            `json:"id" example:"collection-123" description:"Unique collection identifier"`
	Name        string            `json:"name" example:"IoT Data Pipeline" description:"Human-readable collection name"`
	Description string            `json:"description" example:"Standard processing for IoT sensor data" description:"Collection description"`
	Processors  []ProcessorConfig `json:"processors" description:"Array of processors in execution order"`
	CreatedAt   string            `json:"created_at" example:"2023-12-01T10:30:00Z" description:"Creation timestamp"`
	UpdatedAt   string            `json:"updated_at" example:"2023-12-01T10:30:00Z" description:"Last update timestamp"`
}

// ProcessorCollectionRequest represents a request to create a processor collection
// @Description Request body for creating a new processor collection
type ProcessorCollectionRequest struct {
	Name        string            `json:"name" example:"IoT Data Pipeline" description:"Human-readable collection name"`
	Description string            `json:"description,omitempty" example:"Standard processing for IoT sensor data" description:"Optional collection description"`
	Processors  []ProcessorConfig `json:"processors" description:"Array of processors to include in the collection"`
}

// StreamStatus represents the runtime status of a stream
type StreamStatus struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"` // "running", "stopped", "error"
	Error       string         `json:"error,omitempty"`
	Metrics     map[string]any `json:"metrics,omitempty"`
	LastUpdated string         `json:"last_updated"`
}
