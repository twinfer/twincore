package types

import (
	"context"
	"time"
)

// WoTSecurityConfig manages Thing-to-Device authentication and authorization
// This is completely separate from system-level security
type WoTSecurityConfig struct {
	ThingPolicies      map[string]ThingSecurityPolicy `json:"thing_policies"`
	CredentialStores   map[string]CredentialStore     `json:"credential_stores"`
	SecurityTemplates  map[string]SecurityTemplate    `json:"security_templates"`
	GlobalPolicies     *GlobalWoTSecurityPolicy       `json:"global_policies,omitempty"`
}

// ThingSecurityPolicy defines security policy for a specific Thing
type ThingSecurityPolicy struct {
	ThingID           string                      `json:"thing_id"`
	RequiredSchemes   []string                    `json:"required_schemes"`   // WoT security schemes this Thing must support
	CredentialMapping map[string]CredentialRef    `json:"credential_mapping"` // Map scheme to credential store
	AccessControl     *ThingAccessControl         `json:"access_control,omitempty"`
	ProtocolSecurity  map[string]ProtocolSecurity `json:"protocol_security"` // Per-protocol security config
	Encryption        *EncryptionPolicy           `json:"encryption,omitempty"`
}

// CredentialStore defines where and how Thing credentials are stored
type CredentialStore struct {
	Type     string                 `json:"type"`     // "env", "vault", "db", "file", "kubernetes"
	Config   map[string]interface{} `json:"config"`   // Store-specific configuration
	Encrypted bool                  `json:"encrypted"` // Whether credentials are encrypted at rest
	TTL      time.Duration          `json:"ttl,omitempty"` // Credential time-to-live
	Rotation *CredentialRotation    `json:"rotation,omitempty"` // Automatic rotation policy
}

// SecurityTemplate provides reusable security configurations
type SecurityTemplate struct {
	Name        string                      `json:"name"`
	Description string                      `json:"description,omitempty"`
	Schemes     []WoTSecurityScheme         `json:"schemes"`     // WoT security schemes
	Credentials map[string]CredentialRef    `json:"credentials"` // Default credential mappings
	Policies    *ThingAccessControl         `json:"policies,omitempty"`
	Tags        []string                    `json:"tags,omitempty"` // For categorization
}

// WoTSecurityScheme represents a WoT security scheme configuration
type WoTSecurityScheme struct {
	Name        string                 `json:"name"`
	Scheme      string                 `json:"scheme"`      // "basic", "bearer", "apikey", "oauth2", "psk", "cert"
	Description string                 `json:"description,omitempty"`
	In          string                 `json:"in,omitempty"`          // For apikey: "header", "query", "cookie"
	Name_       string                 `json:"name_,omitempty"`       // For apikey: header/query parameter name
	Format      string                 `json:"format,omitempty"`      // Token format requirements
	Scopes      []string               `json:"scopes,omitempty"`      // OAuth2 scopes
	Flow        string                 `json:"flow,omitempty"`        // OAuth2 flow type
	TokenURL    string                 `json:"token_url,omitempty"`   // OAuth2 token endpoint
	AuthURL     string                 `json:"auth_url,omitempty"`    // OAuth2 authorization endpoint
	Config      map[string]interface{} `json:"config,omitempty"`      // Additional scheme-specific config
}

// ThingAccessControl defines access control for Thing operations
type ThingAccessControl struct {
	AllowedOperations []string              `json:"allowed_operations"` // ["readProperty", "writeProperty", "invokeAction", "subscribeEvent"]
	PropertyAccess    map[string]AccessRule `json:"property_access,omitempty"` // Per-property access rules
	ActionAccess      map[string]AccessRule `json:"action_access,omitempty"`   // Per-action access rules
	EventAccess       map[string]AccessRule `json:"event_access,omitempty"`    // Per-event access rules
	IPWhitelist       []string              `json:"ip_whitelist,omitempty"`
	TimeRestrictions  []TimeRestriction     `json:"time_restrictions,omitempty"`
	RateLimit         *WoTRateLimit         `json:"rate_limit,omitempty"`
}

// AccessRule defines access permissions for a specific affordance
type AccessRule struct {
	Allow      bool                   `json:"allow"`
	Conditions []AccessCondition      `json:"conditions,omitempty"`
	Transform  *DataTransformation    `json:"transform,omitempty"` // Data transformation rules
	Audit      bool                   `json:"audit,omitempty"`     // Whether to audit access
}

// AccessCondition defines conditional access rules
type AccessCondition struct {
	Type      string      `json:"type"`      // "ip", "time", "device_id", "protocol", "value_range"
	Operator  string      `json:"operator"`  // "equals", "contains", "in_range", "matches"
	Value     interface{} `json:"value"`
	Negate    bool        `json:"negate,omitempty"` // Negate the condition
}

// TimeRestriction defines time-based access restrictions
type TimeRestriction struct {
	Days      []string `json:"days"`       // ["monday", "tuesday", ...] or ["weekday", "weekend"]
	StartTime string   `json:"start_time"` // "09:00"
	EndTime   string   `json:"end_time"`   // "17:00"
	Timezone  string   `json:"timezone"`   // "UTC", "America/New_York"
}

// WoTRateLimit defines rate limiting for Thing operations
type WoTRateLimit struct {
	RequestsPerMinute int                    `json:"requests_per_minute"`
	BurstSize         int                    `json:"burst_size"`
	PerProperty       map[string]int         `json:"per_property,omitempty"` // Property-specific limits
	PerAction         map[string]int         `json:"per_action,omitempty"`   // Action-specific limits
	PerProtocol       map[string]int         `json:"per_protocol,omitempty"` // Protocol-specific limits
}

// ProtocolSecurity defines protocol-specific security configuration
type ProtocolSecurity struct {
	TLS          *TLSConfig             `json:"tls,omitempty"`
	Certificates *CertificateConfig     `json:"certificates,omitempty"`
	Headers      map[string]string      `json:"headers,omitempty"`      // HTTP headers
	Properties   map[string]interface{} `json:"properties,omitempty"`   // Protocol-specific properties
}

// EncryptionPolicy defines encryption requirements
type EncryptionPolicy struct {
	Required       bool     `json:"required"`        // Whether encryption is mandatory
	Algorithms     []string `json:"algorithms"`      // Allowed encryption algorithms
	KeySize        int      `json:"key_size,omitempty"` // Minimum key size
	ForceUpgrade   bool     `json:"force_upgrade"`   // Force upgrade to encrypted protocols
}

// CertificateConfig defines client certificate configuration
type CertificateConfig struct {
	ClientCert string `json:"client_cert,omitempty"` // Path to client certificate
	ClientKey  string `json:"client_key,omitempty"`  // Path to client private key
	CACert     string `json:"ca_cert,omitempty"`     // Path to CA certificate
	CertStore  string `json:"cert_store,omitempty"`  // Reference to certificate store
}

// CredentialRef references credentials in a credential store
type CredentialRef struct {
	Store string                 `json:"store"`           // Credential store name
	Key   string                 `json:"key"`             // Key/identifier in the store
	Type  string                 `json:"type"`            // "username_password", "token", "certificate", "key"
	Config map[string]interface{} `json:"config,omitempty"` // Additional configuration
}

// CredentialRotation defines automatic credential rotation policy
type CredentialRotation struct {
	Enabled    bool          `json:"enabled"`
	Interval   time.Duration `json:"interval"`    // How often to rotate
	NotifyDays int           `json:"notify_days"` // Days before expiry to notify
	AutoApply  bool          `json:"auto_apply"`  // Automatically apply new credentials
}

// DeviceCredentials represents credentials for authenticating to a device
type DeviceCredentials struct {
	Type         string                 `json:"type"`         // "basic", "bearer", "apikey", "oauth2", "certificate"
	Username     string                 `json:"username,omitempty"`
	Password     string                 `json:"password,omitempty"`
	Token        string                 `json:"token,omitempty"`
	APIKey       string                 `json:"api_key,omitempty"`
	Certificate  *CertificateConfig     `json:"certificate,omitempty"`
	OAuth2       *OAuth2Credentials     `json:"oauth2,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// OAuth2Credentials represents OAuth2 credentials
type OAuth2Credentials struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"` // "Bearer", etc.
	Scopes       []string  `json:"scopes,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// DataTransformation defines data transformation rules for security
type DataTransformation struct {
	Encrypt   bool                   `json:"encrypt,omitempty"`   // Encrypt data
	Hash      bool                   `json:"hash,omitempty"`      // Hash sensitive data
	Mask      *MaskingRule           `json:"mask,omitempty"`      // Mask sensitive fields
	Filter    []string               `json:"filter,omitempty"`    // Filter out specific fields
	Validate  *ValidationRule        `json:"validate,omitempty"`  // Validate data format
	Custom    map[string]interface{} `json:"custom,omitempty"`    // Custom transformation rules
}

// MaskingRule defines data masking rules
type MaskingRule struct {
	Fields    []string `json:"fields"`     // Fields to mask
	Pattern   string   `json:"pattern"`    // Masking pattern (e.g., "***")
	Preserve  int      `json:"preserve"`   // Number of characters to preserve
	Algorithm string   `json:"algorithm"`  // Masking algorithm
}

// ValidationRule defines data validation rules
type ValidationRule struct {
	Schema     string                 `json:"schema,omitempty"`     // JSON schema for validation
	Regex      string                 `json:"regex,omitempty"`      // Regex pattern
	Range      *ValueRange            `json:"range,omitempty"`      // Value range validation
	Custom     map[string]interface{} `json:"custom,omitempty"`     // Custom validation rules
}

// ValueRange defines acceptable value ranges
type ValueRange struct {
	Min interface{} `json:"min,omitempty"`
	Max interface{} `json:"max,omitempty"`
	Enum []interface{} `json:"enum,omitempty"` // Allowed values
}

// GlobalWoTSecurityPolicy defines global security policies for all Things
type GlobalWoTSecurityPolicy struct {
	DefaultTemplate       string            `json:"default_template,omitempty"`
	RequireAuthentication bool              `json:"require_authentication"`
	RequireEncryption     bool              `json:"require_encryption"`
	AllowedProtocols      []string          `json:"allowed_protocols,omitempty"` // ["http", "mqtt", "kafka"]
	BlockedIPs            []string          `json:"blocked_ips,omitempty"`
	DefaultRateLimit      *WoTRateLimit     `json:"default_rate_limit,omitempty"`
	AuditAllAccess        bool              `json:"audit_all_access"`
	ComplianceMode        string            `json:"compliance_mode,omitempty"` // "strict", "moderate", "permissive"
}

// WoTSecurityEvent represents a WoT security event for auditing
type WoTSecurityEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ThingID     string    `json:"thing_id"`
	Operation   string    `json:"operation"`   // "readProperty", "writeProperty", etc.
	Resource    string    `json:"resource"`    // Property/action/event name
	Protocol    string    `json:"protocol"`    // "http", "mqtt", etc.
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	Credentials string    `json:"credentials,omitempty"` // Credential type used
	Details     map[string]interface{} `json:"details,omitempty"`
}

// WoTSecurityManager defines the interface for WoT security management
type WoTSecurityManager interface {
	// Thing Security Management
	GetThingCredentials(ctx context.Context, thingID string, protocolType string) (*DeviceCredentials, error)
	SetThingCredentials(ctx context.Context, thingID string, protocolType string, credentials *DeviceCredentials) error
	ValidateThingAccess(ctx context.Context, thingID string, operation string, context *WoTAccessContext) error
	GetThingSecurityPolicy(ctx context.Context, thingID string) (*ThingSecurityPolicy, error)
	SetThingSecurityPolicy(ctx context.Context, thingID string, policy *ThingSecurityPolicy) error
	
	// Security Scheme Processing
	ProcessSecuritySchemes(ctx context.Context, thingID string, schemes []WoTSecurityScheme) (*ThingSecurityPolicy, error)
	GenerateProtocolAuth(ctx context.Context, schemes []WoTSecurityScheme, protocol string) (*ProtocolAuthConfig, error)
	ValidateSecurityScheme(ctx context.Context, scheme WoTSecurityScheme) error
	
	// Credential Store Management
	RegisterCredentialStore(ctx context.Context, name string, store CredentialStore) error
	GetCredentialStore(ctx context.Context, name string) (*CredentialStore, error)
	ListCredentialStores(ctx context.Context) (map[string]CredentialStore, error)
	GetCredentials(ctx context.Context, storeRef CredentialRef) (*DeviceCredentials, error)
	SetCredentials(ctx context.Context, storeRef CredentialRef, credentials *DeviceCredentials) error
	RotateCredentials(ctx context.Context, storeRef CredentialRef) error
	
	// Security Template Management
	CreateSecurityTemplate(ctx context.Context, template SecurityTemplate) error
	GetSecurityTemplate(ctx context.Context, name string) (*SecurityTemplate, error)
	ListSecurityTemplates(ctx context.Context) ([]SecurityTemplate, error)
	ApplySecurityTemplate(ctx context.Context, thingID string, templateName string) error
	
	// Access Control
	EvaluateAccess(ctx context.Context, accessCtx *WoTAccessContext) error
	LogSecurityEvent(ctx context.Context, event WoTSecurityEvent) error
	GetSecurityEvents(ctx context.Context, filters map[string]interface{}) ([]WoTSecurityEvent, error)
	
	// Configuration Management
	UpdateConfig(ctx context.Context, config WoTSecurityConfig) error
	GetConfig(ctx context.Context) (*WoTSecurityConfig, error)
	ValidateConfig(ctx context.Context, config WoTSecurityConfig) error
	
	// Health and Monitoring
	HealthCheck(ctx context.Context) error
	GetSecurityMetrics(ctx context.Context) (map[string]interface{}, error)
}

// WoTAccessContext provides context for WoT access control decisions
type WoTAccessContext struct {
	ThingID     string    `json:"thing_id"`
	Operation   string    `json:"operation"`   // "readProperty", "writeProperty", "invokeAction", "subscribeEvent"
	Resource    string    `json:"resource"`    // Property/action/event name
	Protocol    string    `json:"protocol"`    // "http", "mqtt", "kafka", etc.
	SourceIP    string    `json:"source_ip,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Credentials *DeviceCredentials `json:"credentials,omitempty"`
	Data        interface{} `json:"data,omitempty"`        // Data being accessed/written
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// ProtocolAuthConfig represents protocol-specific authentication configuration
type ProtocolAuthConfig struct {
	Protocol string                 `json:"protocol"` // "http", "mqtt", "kafka"
	Type     string                 `json:"type"`     // "basic", "bearer", "certificate", etc.
	Config   map[string]interface{} `json:"config"`   // Protocol-specific auth configuration
	Headers  map[string]string      `json:"headers,omitempty"`  // For HTTP
	Properties map[string]interface{} `json:"properties,omitempty"` // For MQTT/Kafka
}