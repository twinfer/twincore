package types

import (
	"context"
	"time"
)

// LicenseSecurityFeatures defines all security features controlled by license
// Clearly separated between system and WoT security domains
type LicenseSecurityFeatures struct {
	SystemSecurity SystemSecurityFeatures  `json:"system_security"`
	WoTSecurity    WoTSecurityFeatures     `json:"wot_security"`
	General        GeneralSecurityFeatures `json:"general"`
	Tier           string                  `json:"tier"` // "basic", "professional", "enterprise"
	ExpiresAt      time.Time               `json:"expires_at"`
	DeviceLimit    int                     `json:"device_limit,omitempty"`
}

// SystemSecurityFeatures defines license-controlled system security features
type SystemSecurityFeatures struct {
	// Authentication Methods
	LocalAuth bool `json:"local_auth"` // Local user management
	LDAPAuth  bool `json:"ldap_auth"`  // LDAP authentication
	SAMLAuth  bool `json:"saml_auth"`  // SAML authentication
	OIDCAuth  bool `json:"oidc_auth"`  // OpenID Connect authentication

	// Advanced Authentication
	MFA     bool `json:"mfa"`      // Multi-factor authentication
	SSO     bool `json:"sso"`      // Single sign-on
	JWTAuth bool `json:"jwt_auth"` // JWT token authentication
	APIKeys bool `json:"api_keys"` // API key authentication

	// Session Management
	SessionMgmt        bool `json:"session_mgmt"`        // Advanced session management
	SessionTimeout     bool `json:"session_timeout"`     // Configurable session timeouts
	ConcurrentSessions bool `json:"concurrent_sessions"` // Multiple concurrent sessions

	// Authorization
	RBAC           bool `json:"rbac"`             // Role-based access control
	PolicyEngine   bool `json:"policy_engine"`    // Advanced policy engine
	FineGrainedACL bool `json:"fine_grained_acl"` // Fine-grained access control lists

	// Security Features
	AuditLogging         bool `json:"audit_logging"`          // Security audit logging
	BruteForceProtection bool `json:"brute_force_protection"` // Account lockout
	PasswordPolicy       bool `json:"password_policy"`        // Enforced password policies
	CSRFProtection       bool `json:"csrf_protection"`        // CSRF token validation

	// API Security
	RateLimit      bool `json:"rate_limit"`      // API rate limiting
	IPWhitelist    bool `json:"ip_whitelist"`    // IP-based access control
	RequestSigning bool `json:"request_signing"` // Request signature validation

	// Compliance
	ComplianceMode bool `json:"compliance_mode"` // Compliance reporting and enforcement
	DataRetention  bool `json:"data_retention"`  // Data retention policies
}

// WoTSecurityFeatures defines license-controlled WoT security features
type WoTSecurityFeatures struct {
	// WoT Security Schemes
	BasicAuth       bool `json:"basic_auth"`       // HTTP Basic authentication for Things
	BearerAuth      bool `json:"bearer_auth"`      // Bearer token authentication
	APIKeyAuth      bool `json:"api_key_auth"`     // API key authentication
	OAuth2Auth      bool `json:"oauth2_auth"`      // OAuth2 authentication
	CertificateAuth bool `json:"certificate_auth"` // Certificate-based authentication
	PSKAuth         bool `json:"psk_auth"`         // Pre-shared key authentication
	CustomAuth      bool `json:"custom_auth"`      // Custom authentication schemes

	// Credential Management
	CredentialStores     bool `json:"credential_stores"`     // Multiple credential stores
	VaultIntegration     bool `json:"vault_integration"`     // HashiCorp Vault integration
	K8sSecrets           bool `json:"k8s_secrets"`           // Kubernetes secrets integration
	CredentialRotation   bool `json:"credential_rotation"`   // Automatic credential rotation
	CredentialEncryption bool `json:"credential_encryption"` // Encrypted credential storage

	// Access Control
	ThingAccessControl bool `json:"thing_access_control"` // Per-Thing access control
	PropertyACL        bool `json:"property_acl"`         // Property-level access control
	ActionACL          bool `json:"action_acl"`           // Action-level access control
	EventACL           bool `json:"event_acl"`            // Event-level access control
	TimeBasedAccess    bool `json:"time_based_access"`    // Time-based access restrictions
	IPBasedAccess      bool `json:"ip_based_access"`      // IP-based access control

	// Security Policies
	SecurityTemplates bool `json:"security_templates"` // Reusable security templates
	GlobalPolicies    bool `json:"global_policies"`    // Global WoT security policies
	PolicyInheritance bool `json:"policy_inheritance"` // Policy inheritance from templates
	ConditionalAccess bool `json:"conditional_access"` // Conditional access rules

	// Data Security
	DataEncryption     bool `json:"data_encryption"`     // Data encryption in transit/at rest
	DataMasking        bool `json:"data_masking"`        // Sensitive data masking
	DataTransformation bool `json:"data_transformation"` // Security data transformations
	DataValidation     bool `json:"data_validation"`     // Input/output data validation

	// Protocol Security
	TLSRequired           bool `json:"tls_required"`           // Mandatory TLS for protocols
	ProtocolEncryption    bool `json:"protocol_encryption"`    // Protocol-level encryption
	CertificateManagement bool `json:"certificate_management"` // Certificate lifecycle management

	// Monitoring & Auditing
	SecurityAudit       bool `json:"security_audit"`       // WoT security event auditing
	AccessLogging       bool `json:"access_logging"`       // Detailed access logging
	SecurityMetrics     bool `json:"security_metrics"`     // Security metrics and reporting
	ComplianceReporting bool `json:"compliance_reporting"` // Compliance reporting for WoT

	// Rate Limiting & DoS Protection
	WoTRateLimit   bool `json:"wot_rate_limit"`   // WoT-specific rate limiting
	PerThingLimits bool `json:"per_thing_limits"` // Per-Thing rate limits
	ProtocolLimits bool `json:"protocol_limits"`  // Per-protocol rate limits
	DoSProtection  bool `json:"dos_protection"`   // Denial of Service protection
}

// GeneralSecurityFeatures defines general security features that apply to both domains
type GeneralSecurityFeatures struct {
	// Transport Security
	TLSRequired  bool     `json:"tls_required"`  // Force TLS for all connections
	TLSVersions  []string `json:"tls_versions"`  // Allowed TLS versions
	CipherSuites []string `json:"cipher_suites"` // Allowed cipher suites
	HSTS         bool     `json:"hsts"`          // HTTP Strict Transport Security

	// HTTP Security
	SecurityHeaders bool `json:"security_headers"` // HTTP security headers (CSP, etc.)
	CORSControl     bool `json:"cors_control"`     // CORS policy control
	ContentSecurity bool `json:"content_security"` // Content Security Policy

	// Network Security
	IPFiltering        bool `json:"ip_filtering"`        // IP allowlist/blocklist
	GeolocationControl bool `json:"geolocation_control"` // Geographic access control
	VPNDetection       bool `json:"vpn_detection"`       // VPN/proxy detection

	// General Rate Limiting
	GlobalRateLimit bool `json:"global_rate_limit"` // Global rate limiting
	BurstControl    bool `json:"burst_control"`     // Burst request control

	// Monitoring & Alerting
	SecurityMonitoring bool `json:"security_monitoring"` // Real-time security monitoring
	AlertingSystem     bool `json:"alerting_system"`     // Security alerting
	IncidentResponse   bool `json:"incident_response"`   // Automated incident response

	// Compliance & Standards
	SOC2Compliance bool `json:"soc2_compliance"` // SOC 2 compliance features
	GDPR           bool `json:"gdpr"`            // GDPR compliance features
	HIPAA          bool `json:"hipaa"`           // HIPAA compliance features
	ISOCompliance  bool `json:"iso_compliance"`  // ISO 27001 compliance features

	// Advanced Features
	ZeroTrustModel     bool `json:"zero_trust_model"`    // Zero trust security model
	MicroSegmentation  bool `json:"micro_segmentation"`  // Network micro-segmentation
	BehaviorAnalysis   bool `json:"behavior_analysis"`   // Behavioral security analysis
	ThreatIntelligence bool `json:"threat_intelligence"` // Threat intelligence integration
}

// LicenseTier defines predefined license tiers with feature sets
type LicenseTier struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Features    LicenseSecurityFeatures `json:"features"`
	Limits      LicenseLimits           `json:"limits"`
	Price       *LicensePrice           `json:"price,omitempty"`
}

// LicenseLimits defines quantitative limits for license tiers
type LicenseLimits struct {
	MaxDevices           int `json:"max_devices"`            // Maximum number of connected devices
	MaxThings            int `json:"max_things"`             // Maximum number of registered Things
	MaxUsers             int `json:"max_users"`              // Maximum number of system users
	MaxAPIRequests       int `json:"max_api_requests"`       // Maximum API requests per month
	MaxDataStorage       int `json:"max_data_storage"`       // Maximum data storage in GB
	MaxPolicies          int `json:"max_policies"`           // Maximum security policies
	MaxCredentialStores  int `json:"max_credential_stores"`  // Maximum credential stores
	MaxSecurityTemplates int `json:"max_security_templates"` // Maximum security templates
}

// LicensePrice defines pricing information
type LicensePrice struct {
	Currency string  `json:"currency"`
	Amount   float64 `json:"amount"`
	Period   string  `json:"period"` // "monthly", "yearly"
}

// UnifiedLicenseChecker defines the unified interface for license validation
type UnifiedLicenseChecker interface {
	// License Validation
	ValidateLicense(ctx context.Context, licenseData string) (*LicenseSecurityFeatures, error)
	GetLicenseFeatures(ctx context.Context) (*LicenseSecurityFeatures, error)
	IsLicenseValid(ctx context.Context) bool
	GetLicenseExpiry(ctx context.Context) (time.Time, error)

	// Feature Checking - System Security
	IsSystemFeatureEnabled(ctx context.Context, feature string) bool
	GetSystemSecurityFeatures(ctx context.Context) (*SystemSecurityFeatures, error)
	ValidateSystemOperation(ctx context.Context, operation string) error

	// Feature Checking - WoT Security
	IsWoTFeatureEnabled(ctx context.Context, feature string) bool
	GetWoTSecurityFeatures(ctx context.Context) (*WoTSecurityFeatures, error)
	ValidateWoTOperation(ctx context.Context, operation string) error
	ValidateSecurityScheme(ctx context.Context, scheme string) error

	// Feature Checking - General
	IsGeneralFeatureEnabled(ctx context.Context, feature string) bool
	GetGeneralSecurityFeatures(ctx context.Context) (*GeneralSecurityFeatures, error)

	// Limits Checking
	GetLicenseLimits(ctx context.Context) (*LicenseLimits, error)
	CheckLimit(ctx context.Context, limitType string, currentUsage int) error
	GetUsageStats(ctx context.Context) (map[string]int, error)

	// License Management
	ReloadLicense(ctx context.Context) error
	GetLicenseInfo(ctx context.Context) (*LicenseInfo, error)
	ValidateLicenseForUpgrade(ctx context.Context, newLicenseData string) error

	// Tier Management
	GetAvailableTiers(ctx context.Context) ([]LicenseTier, error)
	GetCurrentTier(ctx context.Context) (*LicenseTier, error)
	CompareTiers(ctx context.Context, currentTier, targetTier string) (*TierComparison, error)
}

// LicenseInfo provides detailed license information
type LicenseInfo struct {
	ID           string                  `json:"id"`
	Issuer       string                  `json:"issuer"`
	Subject      string                  `json:"subject"`
	IssuedAt     time.Time               `json:"issued_at"`
	ExpiresAt    time.Time               `json:"expires_at"`
	Tier         string                  `json:"tier"`
	Features     LicenseSecurityFeatures `json:"features"`
	Limits       LicenseLimits           `json:"limits"`
	DeviceID     string                  `json:"device_id,omitempty"`
	Organization string                  `json:"organization,omitempty"`
	Metadata     map[string]any          `json:"metadata,omitempty"`
}

// TierComparison compares features between license tiers
type TierComparison struct {
	CurrentTier     string                 `json:"current_tier"`
	TargetTier      string                 `json:"target_tier"`
	AddedFeatures   []string               `json:"added_features"`
	RemovedFeatures []string               `json:"removed_features"`
	LimitChanges    map[string]LimitChange `json:"limit_changes"`
	Recommendation  string                 `json:"recommendation,omitempty"`
}

// LimitChange describes a change in license limits
type LimitChange struct {
	Current int    `json:"current"`
	Target  int    `json:"target"`
	Change  string `json:"change"` // "increase", "decrease", "unlimited"
}

// Predefined license tiers
var (
	BasicTier = LicenseTier{
		Name:        "basic",
		Description: "Basic security features for small deployments",
		Features: LicenseSecurityFeatures{
			SystemSecurity: SystemSecurityFeatures{
				LocalAuth:    true,
				SessionMgmt:  true,
				AuditLogging: true,
				RateLimit:    true,
			},
			WoTSecurity: WoTSecurityFeatures{
				BasicAuth:     true,
				BearerAuth:    true,
				SecurityAudit: true,
				WoTRateLimit:  true,
			},
			General: GeneralSecurityFeatures{
				TLSRequired:     true,
				SecurityHeaders: true,
				GlobalRateLimit: true,
			},
			Tier: "basic",
		},
		Limits: LicenseLimits{
			MaxDevices:           10,
			MaxThings:            50,
			MaxUsers:             5,
			MaxAPIRequests:       10000,
			MaxDataStorage:       1,
			MaxPolicies:          10,
			MaxCredentialStores:  2,
			MaxSecurityTemplates: 5,
		},
	}

	ProfessionalTier = LicenseTier{
		Name:        "professional",
		Description: "Professional security features for medium deployments",
		Features: LicenseSecurityFeatures{
			SystemSecurity: SystemSecurityFeatures{
				LocalAuth:            true,
				LDAPAuth:             true,
				MFA:                  true,
				JWTAuth:              true,
				SessionMgmt:          true,
				RBAC:                 true,
				AuditLogging:         true,
				BruteForceProtection: true,
				PasswordPolicy:       true,
				RateLimit:            true,
				IPWhitelist:          true,
			},
			WoTSecurity: WoTSecurityFeatures{
				BasicAuth:          true,
				BearerAuth:         true,
				APIKeyAuth:         true,
				OAuth2Auth:         true,
				CredentialStores:   true,
				ThingAccessControl: true,
				PropertyACL:        true,
				SecurityTemplates:  true,
				DataEncryption:     true,
				TLSRequired:        true,
				SecurityAudit:      true,
				WoTRateLimit:       true,
				PerThingLimits:     true,
			},
			General: GeneralSecurityFeatures{
				TLSRequired:        true,
				SecurityHeaders:    true,
				CORSControl:        true,
				IPFiltering:        true,
				GlobalRateLimit:    true,
				SecurityMonitoring: true,
			},
			Tier: "professional",
		},
		Limits: LicenseLimits{
			MaxDevices:           100,
			MaxThings:            500,
			MaxUsers:             25,
			MaxAPIRequests:       100000,
			MaxDataStorage:       10,
			MaxPolicies:          50,
			MaxCredentialStores:  10,
			MaxSecurityTemplates: 25,
		},
	}

	EnterpriseTier = LicenseTier{
		Name:        "enterprise",
		Description: "Enterprise security features for large deployments",
		Features: LicenseSecurityFeatures{
			SystemSecurity: SystemSecurityFeatures{
				LocalAuth:            true,
				LDAPAuth:             true,
				SAMLAuth:             true,
				OIDCAuth:             true,
				MFA:                  true,
				SSO:                  true,
				JWTAuth:              true,
				APIKeys:              true,
				SessionMgmt:          true,
				SessionTimeout:       true,
				ConcurrentSessions:   true,
				RBAC:                 true,
				PolicyEngine:         true,
				FineGrainedACL:       true,
				AuditLogging:         true,
				BruteForceProtection: true,
				PasswordPolicy:       true,
				CSRFProtection:       true,
				RateLimit:            true,
				IPWhitelist:          true,
				RequestSigning:       true,
				ComplianceMode:       true,
				DataRetention:        true,
			},
			WoTSecurity: WoTSecurityFeatures{
				BasicAuth:             true,
				BearerAuth:            true,
				APIKeyAuth:            true,
				OAuth2Auth:            true,
				CertificateAuth:       true,
				PSKAuth:               true,
				CustomAuth:            true,
				CredentialStores:      true,
				VaultIntegration:      true,
				K8sSecrets:            true,
				CredentialRotation:    true,
				CredentialEncryption:  true,
				ThingAccessControl:    true,
				PropertyACL:           true,
				ActionACL:             true,
				EventACL:              true,
				TimeBasedAccess:       true,
				IPBasedAccess:         true,
				SecurityTemplates:     true,
				GlobalPolicies:        true,
				PolicyInheritance:     true,
				ConditionalAccess:     true,
				DataEncryption:        true,
				DataMasking:           true,
				DataTransformation:    true,
				DataValidation:        true,
				TLSRequired:           true,
				ProtocolEncryption:    true,
				CertificateManagement: true,
				SecurityAudit:         true,
				AccessLogging:         true,
				SecurityMetrics:       true,
				ComplianceReporting:   true,
				WoTRateLimit:          true,
				PerThingLimits:        true,
				ProtocolLimits:        true,
				DoSProtection:         true,
			},
			General: GeneralSecurityFeatures{
				TLSRequired:        true,
				SecurityHeaders:    true,
				CORSControl:        true,
				ContentSecurity:    true,
				IPFiltering:        true,
				GeolocationControl: true,
				VPNDetection:       true,
				GlobalRateLimit:    true,
				BurstControl:       true,
				SecurityMonitoring: true,
				AlertingSystem:     true,
				IncidentResponse:   true,
				SOC2Compliance:     true,
				GDPR:               true,
				HIPAA:              true,
				ISOCompliance:      true,
				ZeroTrustModel:     true,
				MicroSegmentation:  true,
				BehaviorAnalysis:   true,
				ThreatIntelligence: true,
			},
			Tier: "enterprise",
		},
		Limits: LicenseLimits{
			MaxDevices:           -1, // Unlimited
			MaxThings:            -1, // Unlimited
			MaxUsers:             -1, // Unlimited
			MaxAPIRequests:       -1, // Unlimited
			MaxDataStorage:       -1, // Unlimited
			MaxPolicies:          -1, // Unlimited
			MaxCredentialStores:  -1, // Unlimited
			MaxSecurityTemplates: -1, // Unlimited
		},
	}
)

// GetPredefinedTiers returns all predefined license tiers
func GetPredefinedTiers() []LicenseTier {
	return []LicenseTier{BasicTier, ProfessionalTier, EnterpriseTier}
}
