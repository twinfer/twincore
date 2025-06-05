package wot

import "slices"

import "fmt"

// DataSchemaCore contains the structural and constraint fields of a DataSchema,
// excluding common metadata like title and description to avoid conflicts when embedded.
// These metadata fields are added back in the main DataSchema struct.
type DataSchemaCore struct {
	// Type and format
	Type    string `json:"type,omitempty"`   // e.g., "object", "array", "string", "number", "integer", "boolean", "null"
	Format  string `json:"format,omitempty"` // e.g., "date-time", "uri", "email"
	Unit    string `json:"unit,omitempty"`
	Enum    []any  `json:"enum,omitempty"`
	Const   any    `json:"const,omitempty"`
	Default any    `json:"default,omitempty"`

	// String-specific
	Pattern          string `json:"pattern,omitempty"`
	MinLength        *uint  `json:"minLength,omitempty"`
	MaxLength        *uint  `json:"maxLength,omitempty"`
	ContentMediaType string `json:"contentMediaType,omitempty"`
	ContentEncoding  string `json:"contentEncoding,omitempty"`

	// Number/Integer-specific
	Minimum          *float64 `json:"minimum,omitempty"`
	ExclusiveMinimum *float64 `json:"exclusiveMinimum,omitempty"`
	Maximum          *float64 `json:"maximum,omitempty"`
	ExclusiveMaximum *float64 `json:"exclusiveMaximum,omitempty"`
	MultipleOf       *float64 `json:"multipleOf,omitempty"`

	// Object-specific
	Properties           map[string]*DataSchema `json:"properties,omitempty"` // Pointer to allow recursive defs
	Required             []string               `json:"required,omitempty"`
	AdditionalProperties any                    `json:"additionalProperties,omitempty"` // bool or *DataSchema
	PropertyNames        *DataSchema            `json:"propertyNames,omitempty"`

	// Array-specific
	Items       any   `json:"items,omitempty"` // *DataSchema or []*DataSchema (tuple validation)
	MinItems    *uint `json:"minItems,omitempty"`
	MaxItems    *uint `json:"maxItems,omitempty"`
	UniqueItems bool  `json:"uniqueItems,omitempty"`

	// Logical keywords
	OneOf []DataSchema `json:"oneOf,omitempty"`
	AnyOf []DataSchema `json:"anyOf,omitempty"`
	AllOf []DataSchema `json:"allOf,omitempty"`
	Not   *DataSchema  `json:"not,omitempty"`

	// WoT specific (often found within PropertyAffordance, but part of DataSchema concept)
	ReadOnly   bool `json:"readOnly,omitempty"`   // Default false
	WriteOnly  bool `json:"writeOnly,omitempty"`  // Default false
	Observable bool `json:"observable,omitempty"` // Default false, relevant for PropertyAffordance
}

// DataSchema defines the structure for data types used in Thing Descriptions.
// It is based on a subset of JSON Schema.
type DataSchema struct {
	// Embed core structural and constraint fields
	DataSchemaCore

	// Common annotations specific to this DataSchema definition
	Title        string            `json:"title,omitempty"`
	Titles       map[string]string `json:"titles,omitempty"`
	Description  string            `json:"description,omitempty"`
	Descriptions map[string]string `json:"descriptions,omitempty"`
	Comment      string            `json:"$comment,omitempty"`
	SemanticType []string          `json:"@type,omitempty"` // Added for W3C WoT TD 1.1
}

// Form is an interface that concrete protocol binding forms will implement.
type Form interface {
	// GetOp returns the operation(s) this form is for.
	GetOp() []string
	// GetHref returns the target URI of the form.
	GetHref() string
	// GetContentType returns the content type of the form.
	GetContentType() string
	// GetSecurity returns form-level security overrides (optional).
	GetSecurity() []string
	// GetResponse returns expected response definition (optional).
	GetResponse() *ExpectedResponse
	// GetURIVariables returns URI template variables (optional).
	GetURIVariables() map[string]*DataSchema
	// GetSubprotocol returns protocol variation indicator (optional).
	GetSubprotocol() string
	// GenerateConfig produces a protocol-specific configuration map,
	// often including Benthos YAML, based on the form's fields and security definitions.
	GenerateConfig(securityDefs map[string]SecurityScheme) (map[string]any, error)
	// GetProtocol returns a string identifying the protocol (e.g., "http", "kafka").
	// This was added as it's commonly needed by form implementations.
	GetProtocol() string
}

// ExpectedResponse defines the structure for expected responses within a Form.
type ExpectedResponse struct {
	ContentType string `json:"contentType,omitempty"`
}

// SecurityScheme defines a security mechanism.
type SecurityScheme struct {
	SemanticType any               `json:"@type,omitempty"` // e.g. "BasicSecurityScheme", "OAuth2SecurityScheme"
	Description  string            `json:"description,omitempty"`
	Descriptions map[string]string `json:"descriptions,omitempty"`
	Proxy        string            `json:"proxy,omitempty"` // URI
	Scheme       string            `json:"scheme"`          // e.g. "basic", "bearer", "apikey", "oauth2" - this is the primary discriminator

	// Scheme-specific properties are stored in this map.
	// Keys should follow W3C TD spec, e.g., "in", "name" for apikey;
	// "authorization", "token", "flow", "scopes" for oauth2.
	// This provides flexibility for various schemes.
	// However, for fields consistently accessed like 'in' and 'name' by WoTMapper,
	// they are also included as top-level for convenience and to match current WoTMapper assumptions.
	// This might be harmonized later: either always use Properties map or ensure top-level fields cover all needs.
	Properties map[string]any `json:"-"`

	In   string `json:"in,omitempty"`   // For apikey (location of security information), also used by some other schemes
	Name string `json:"name,omitempty"` // For apikey (name of header/query param)

	// Fields for specific security schemes as per TD 1.1
	QOP              string   `json:"qop,omitempty"`           // For Digest
	AuthorizationURI string   `json:"authorization,omitempty"` // For Bearer, OAuth2
	Alg              string   `json:"alg,omitempty"`           // For Bearer
	Format           string   `json:"format,omitempty"`        // For Bearer
	TokenURI         string   `json:"token,omitempty"`         // For OAuth2
	RefreshURI       string   `json:"refresh,omitempty"`       // For OAuth2
	Scopes           []string `json:"scopes,omitempty"`        // For OAuth2
	Flow             string   `json:"flow,omitempty"`          // For OAuth2
	Identity         string   `json:"identity,omitempty"`      // For PSK
}

// InteractionAffordance is a base type for Properties, Actions, and Events.
type InteractionAffordance struct {
	Title        string                 `json:"title,omitempty"`
	Titles       map[string]string      `json:"titles,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Descriptions map[string]string      `json:"descriptions,omitempty"`
	Forms        []Form                 `json:"forms"` // Must contain at least one form
	URIVariables map[string]*DataSchema `json:"uriVariables,omitempty"`
	Comment      string                 `json:"$comment,omitempty"`
}

// PropertyAffordance defines a property of a Thing.
type PropertyAffordance struct {
	InteractionAffordance
	DataSchemaCore // Embed DataSchemaCore fields (type, readOnly, writeOnly, observable, etc.)
}

// GetForms returns the forms associated with the property affordance.
func (pa *PropertyAffordance) GetForms() []Form { return pa.Forms }

// IsReadOnly returns the readOnly status from the embedded DataSchema.
func (pa *PropertyAffordance) IsReadOnly() bool { return pa.DataSchemaCore.ReadOnly }

// IsWriteOnly returns the writeOnly status from the embedded DataSchema.
func (pa *PropertyAffordance) IsWriteOnly() bool { return pa.DataSchemaCore.WriteOnly }

// IsObservable returns the observable status from the embedded DataSchema.
func (pa *PropertyAffordance) IsObservable() bool { return pa.DataSchemaCore.Observable }

// GetName is a placeholder; property names are keys in the map.
// However, if an affordance needs to know its own name, it would be set externally.
// For now, this is not strictly required by WoTMapper's direct usage pattern.
// func (pa *PropertyAffordance) GetName() string { return "" }

// ActionAffordance defines an action that can be performed on a Thing.
type ActionAffordance struct {
	InteractionAffordance
	Input       *DataSchema `json:"input,omitempty"`
	Output      *DataSchema `json:"output,omitempty"`
	Safe        bool        `json:"safe,omitempty"`        // Default false
	Idempotent  bool        `json:"idempotent,omitempty"`  // Default false
	Synchronous bool        `json:"synchronous,omitempty"` // Added for W3C WoT TD 1.1
}

// GetForms returns the forms associated with the action affordance.
func (aa *ActionAffordance) GetForms() []Form { return aa.Forms }

// GetInput returns the input schema for the action.
func (aa *ActionAffordance) GetInput() DataSchema {
	if aa.Input == nil {
		return DataSchema{}
	}
	return *aa.Input
}

// GetOutput returns the output schema for the action.
func (aa *ActionAffordance) GetOutput() DataSchema {
	if aa.Output == nil {
		return DataSchema{}
	}
	return *aa.Output
}

// EventAffordance defines an event that can be emitted by a Thing.
type EventAffordance struct {
	InteractionAffordance
	Subscription *DataSchema `json:"subscription,omitempty"`
	Data         *DataSchema `json:"data,omitempty"`
	Cancellation *DataSchema `json:"cancellation,omitempty"`
	DataResponse *DataSchema `json:"dataResponse,omitempty"` // Added for W3C WoT TD 1.1
}

// GetForms returns the forms associated with the event affordance.
func (ea *EventAffordance) GetForms() []Form { return ea.Forms }

// GetData returns the data schema for the event.
func (ea *EventAffordance) GetData() DataSchema {
	if ea.Data == nil {
		return DataSchema{}
	}
	return *ea.Data
}

// Link provides a link to a related resource.
type Link struct {
	Href     string `json:"href"`
	Type     string `json:"type,omitempty"` // Media type
	Rel      string `json:"rel,omitempty"`
	Anchor   string `json:"anchor,omitempty"`
	Sizes    string `json:"sizes,omitempty"`    // Added for W3C WoT TD 1.1
	Hreflang any    `json:"hreflang,omitempty"` // Added for W3C WoT TD 1.1
}

// VersionInfo provides detailed versioning for a Thing Description.
type VersionInfo struct {
	Instance string `json:"instance"`
	Model    string `json:"model,omitempty"`
}

// AdditionalExpectedResponse defines requirements for responses beyond the primary one in a Form.
// This is relevant for TD 1.1.
type AdditionalExpectedResponse struct {
	ContentType string `json:"contentType"` // Making this non-omitempty as per spec's default handling described.
	Schema      string `json:"schema,omitempty"`
	Success     bool   `json:"success,omitempty"`
}

// ThingDescription is the top-level structure for a W3C WoT Thing Description.
// @Description Complete W3C WoT Thing Description 1.1 specification compliant structure
type ThingDescription struct {
	Context             any                            `json:"@context" swaggertype:"string" example:"https://www.w3.org/2022/wot/td/v1.1" description:"JSON-LD context, must include WoT TD 1.1 context"`
	ID                  string                         `json:"id,omitempty" example:"urn:device:001" description:"Unique identifier for the Thing"`
	Title               string                         `json:"title" example:"My IoT Device" description:"Human-readable name (mandatory)"`
	Titles              map[string]string              `json:"titles,omitempty" description:"Multi-language titles"`
	Description         string                         `json:"description,omitempty" example:"A sample IoT device for demonstration" description:"Human-readable description"`
	Descriptions        map[string]string              `json:"descriptions,omitempty" description:"Multi-language descriptions"`
	Version             *VersionInfo                   `json:"version,omitempty" description:"Version information"`
	Created             string                         `json:"created,omitempty" example:"2023-12-01T10:30:00Z" description:"Creation timestamp (ISO8601)"`
	Modified            string                         `json:"modified,omitempty" example:"2023-12-01T10:30:00Z" description:"Last modification timestamp (ISO8601)"`
	Support             string                         `json:"support,omitempty" example:"mailto:support@example.com" description:"Contact information URI"`
	Base                string                         `json:"base,omitempty" example:"https://device.example.com/" description:"Base URI for relative references"`
	Properties          map[string]*PropertyAffordance `json:"properties,omitempty" description:"Available properties"`
	Actions             map[string]*ActionAffordance   `json:"actions,omitempty" description:"Available actions"`
	Events              map[string]*EventAffordance    `json:"events,omitempty" description:"Available events"`
	Links               []*Link                        `json:"links,omitempty" description:"Web links"`
	Forms               []Form                         `json:"forms,omitempty" description:"Global protocol bindings"`
	Security            []string                       `json:"security" example:"[\"basic_sc\"]" description:"Security schemes (mandatory)"`
	SecurityDefinitions map[string]SecurityScheme      `json:"securityDefinitions" description:"Security scheme definitions (mandatory)"`
	SchemaDefinitions   map[string]*DataSchema         `json:"schemaDefinitions,omitempty" description:"Reusable data schemas"`
	Profile             []string                       `json:"profile,omitempty" description:"Profile URIs"`
	URIs                []string                       `json:"uris,omitempty" description:"External URIs for this TD"`
	Comment             string                         `json:"$comment,omitempty" description:"Implementation comments"`
}

// Validation helpers and compliance methods

// ValidateBasicCompliance checks if the Thing Description meets basic W3C WoT TD 1.1 requirements
func (td *ThingDescription) ValidateBasicCompliance() []string {
	var issues []string

	// Check mandatory fields
	if td.Title == "" {
		issues = append(issues, "missing mandatory 'title' field")
	}

	if len(td.Security) == 0 {
		issues = append(issues, "missing mandatory 'security' field")
	}

	if len(td.SecurityDefinitions) == 0 && len(td.Security) > 0 {
		// Check if security is not just "nosec"
		hasNonNosec := false
		for _, sec := range td.Security {
			if sec != "nosec" {
				hasNonNosec = true
				break
			}
		}
		if hasNonNosec {
			issues = append(issues, "missing 'securityDefinitions' when security schemes other than 'nosec' are used")
		}
	}

	// Validate context
	if td.Context == nil {
		issues = append(issues, "missing mandatory '@context' field")
	}

	// Check that at least one interaction affordance has forms
	totalInteractions := len(td.Properties) + len(td.Actions) + len(td.Events)
	if totalInteractions == 0 && len(td.Forms) == 0 {
		issues = append(issues, "Thing Description should have at least one interaction affordance or global form")
	}

	return issues
}

// ValidateOperationTypes checks if operation types in forms match their affordance context
func (pa *PropertyAffordance) ValidateOperationTypes() []string {
	var issues []string
	validOps := []string{"readproperty", "writeproperty", "observeproperty", "unobserveproperty"}

	for _, form := range pa.Forms {
		ops := form.GetOp()
		for _, op := range ops {
			valid := slices.Contains(validOps, op)
			if !valid {
				issues = append(issues, fmt.Sprintf("invalid operation '%s' for PropertyAffordance", op))
			}
		}
	}
	return issues
}

// ValidateOperationTypes checks if operation types in forms match their affordance context
func (aa *ActionAffordance) ValidateOperationTypes() []string {
	var issues []string
	validOps := []string{"invokeaction", "queryaction", "cancelaction"}

	for _, form := range aa.Forms {
		ops := form.GetOp()
		for _, op := range ops {
			valid := slices.Contains(validOps, op)
			if !valid {
				issues = append(issues, fmt.Sprintf("invalid operation '%s' for ActionAffordance", op))
			}
		}
	}
	return issues
}

// ValidateOperationTypes checks if operation types in forms match their affordance context
func (ea *EventAffordance) ValidateOperationTypes() []string {
	var issues []string
	validOps := []string{"subscribeevent", "unsubscribeevent"}

	for _, form := range ea.Forms {
		ops := form.GetOp()
		for _, op := range ops {
			valid := slices.Contains(validOps, op)
			if !valid {
				issues = append(issues, fmt.Sprintf("invalid operation '%s' for EventAffordance", op))
			}
		}
	}
	return issues
}
