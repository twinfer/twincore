package config

import (
	"context"
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/twinfer/twincore/pkg/types"
)

//go:embed default-config.json
var defaultConfigJSON []byte

// DefaultConfiguration represents the complete default configuration structure
type DefaultConfiguration struct {
	HTTP           HTTPConfiguration           `json:"http"`
	Stream         StreamConfiguration         `json:"stream"`
	WoT            WoTConfiguration            `json:"wot"`
	SystemSecurity SystemSecurityConfiguration `json:"system_security"`
	WoTSecurity    WoTSecurityConfiguration    `json:"wot_security"`
	CaddySecurity  CaddySecurityConfiguration  `json:"caddy_security"`
	Licensing      LicensingConfiguration      `json:"licensing"`
}

// HTTPConfiguration represents HTTP service configuration
type HTTPConfiguration struct {
	Listen []string      `json:"listen"`
	Routes []RouteConfig `json:"routes"`
}

// RouteConfig represents a single route configuration
type RouteConfig struct {
	Path         string         `json:"path"`
	Handler      string         `json:"handler"`
	RequiresAuth bool           `json:"requires_auth"`
	Config       map[string]any `json:"config"`
}

// StreamConfiguration represents stream processing configuration
type StreamConfiguration struct {
	Topics     []TopicConfig    `json:"topics"`
	Processing ProcessingConfig `json:"processing"`
}

// TopicConfig represents a stream topic configuration
type TopicConfig struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

// ProcessingConfig represents stream processing settings
type ProcessingConfig struct {
	BatchSize  int    `json:"batch_size"`
	Timeout    string `json:"timeout"`
	MaxRetries int    `json:"max_retries"`
}

// WoTConfiguration represents Web of Things configuration
type WoTConfiguration struct {
	Discovery        DiscoveryConfig        `json:"discovery"`
	SchemaValidation SchemaValidationConfig `json:"schema_validation"`
	BindingTemplates BindingTemplatesConfig `json:"binding_templates"`
}

// DiscoveryConfig represents WoT discovery configuration
type DiscoveryConfig struct {
	Enabled   bool            `json:"enabled"`
	Port      int             `json:"port"`
	Multicast MulticastConfig `json:"multicast"`
}

// MulticastConfig represents multicast discovery configuration
type MulticastConfig struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// SchemaValidationConfig represents schema validation configuration
type SchemaValidationConfig struct {
	Enabled      bool `json:"enabled"`
	StrictMode   bool `json:"strict_mode"`
	CacheSchemas bool `json:"cache_schemas"`
}

// BindingTemplatesConfig represents binding templates configuration
type BindingTemplatesConfig struct {
	HTTP  HTTPBindingConfig  `json:"http"`
	MQTT  MQTTBindingConfig  `json:"mqtt"`
	Kafka KafkaBindingConfig `json:"kafka"`
}

// HTTPBindingConfig represents HTTP binding configuration
type HTTPBindingConfig struct {
	DefaultPort int    `json:"default_port"`
	Timeout     string `json:"timeout"`
	RateLimit   string `json:"rate_limit"`
}

// MQTTBindingConfig represents MQTT binding configuration
type MQTTBindingConfig struct {
	Broker string `json:"broker"`
	QoS    int    `json:"qos"`
	Retain bool   `json:"retain"`
}

// KafkaBindingConfig represents Kafka binding configuration
type KafkaBindingConfig struct {
	Brokers           []string `json:"brokers"`
	PartitionStrategy string   `json:"partition_strategy"`
}

// SystemSecurityConfiguration represents system security configuration
type SystemSecurityConfiguration struct {
	Enabled       bool                 `json:"enabled"`
	AdminAuth     AdminAuthConfig      `json:"admin_auth"`
	APIAuth       APIAuthConfig        `json:"api_auth"`
	SessionConfig SessionConfigDetails `json:"session_config"`
}

// AdminAuthConfig represents admin authentication configuration
type AdminAuthConfig struct {
	Method    string          `json:"method"`
	Providers []string        `json:"providers"`
	MFA       bool            `json:"mfa"`
	Local     LocalAuthConfig `json:"local"`
}

// LocalAuthConfig represents local authentication configuration
type LocalAuthConfig struct {
	Users          []LocalUserConfig    `json:"users"`
	PasswordPolicy PasswordPolicyConfig `json:"password_policy"`
	AccountLockout AccountLockoutConfig `json:"account_lockout"`
}

// LocalUserConfig represents a local user configuration
type LocalUserConfig struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Email        string   `json:"email"`
	FullName     string   `json:"full_name"`
	Roles        []string `json:"roles"`
	Disabled     bool     `json:"disabled"`
}

// PasswordPolicyConfig represents password policy configuration
type PasswordPolicyConfig struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAgeDays       int  `json:"max_age_days"`
	PreventReuse     int  `json:"prevent_reuse"`
}

// AccountLockoutConfig represents account lockout configuration
type AccountLockoutConfig struct {
	Enabled         bool `json:"enabled"`
	MaxAttempts     int  `json:"max_attempts"`
	LockoutDuration int  `json:"lockout_duration"`
	ResetDuration   int  `json:"reset_duration"`
}

// APIAuthConfig represents API authentication configuration
type APIAuthConfig struct {
	Methods   []string         `json:"methods"`
	JWTConfig JWTConfigDetails `json:"jwt_config"`
	Policies  []PolicyConfig   `json:"policies"`
	RateLimit RateLimitConfig  `json:"rate_limit"`
}

// JWTConfigDetails represents JWT configuration details
type JWTConfigDetails struct {
	Algorithm    string `json:"algorithm"`
	Issuer       string `json:"issuer"`
	Audience     string `json:"audience"`
	Expiry       string `json:"expiry"`
	RefreshToken bool   `json:"refresh_token"`
}

// PolicyConfig represents a policy configuration
type PolicyConfig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Principal   string   `json:"principal"`
	Resources   []string `json:"resources"`
	Actions     []string `json:"actions"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool `json:"enabled"`
	RequestsPerMinute int  `json:"requests_per_minute"`
	Burst             int  `json:"burst"`
}

// SessionConfigDetails represents session configuration details
type SessionConfigDetails struct {
	Timeout        int    `json:"timeout"`
	MaxSessions    int    `json:"max_sessions"`
	SecureCookies  bool   `json:"secure_cookies"`
	SameSite       string `json:"same_site"`
	CSRFProtection bool   `json:"csrf_protection"`
}

// WoTSecurityConfiguration represents WoT security configuration
type WoTSecurityConfiguration struct {
	Enabled               bool                     `json:"enabled"`
	DefaultSecurityScheme string                   `json:"default_security_scheme"`
	CredentialStores      []CredentialStoreConfig  `json:"credential_stores"`
	SecurityTemplates     []SecurityTemplateConfig `json:"security_templates"`
	DevicePolicies        DevicePoliciesConfig     `json:"device_policies"`
}

// CredentialStoreConfig represents a credential store configuration
type CredentialStoreConfig struct {
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Encrypted bool           `json:"encrypted"`
	Config    map[string]any `json:"config"`
}

// SecurityTemplateConfig represents a security template configuration
type SecurityTemplateConfig struct {
	Name   string         `json:"name"`
	Scheme string         `json:"scheme"`
	Config map[string]any `json:"config"`
}

// DevicePoliciesConfig represents device policies configuration
type DevicePoliciesConfig struct {
	DefaultAccess         string `json:"default_access"`
	RequireAuthentication bool   `json:"require_authentication"`
	AuditAllAccess        bool   `json:"audit_all_access"`
}

// CaddySecurityConfiguration represents caddy-security configuration
type CaddySecurityConfiguration struct {
	Portal        PortalConfig        `json:"portal"`
	Authorization AuthorizationConfig `json:"authorization"`
	UserRegistry  UserRegistryConfig  `json:"user_registry"`
}

// PortalConfig represents portal configuration
type PortalConfig struct {
	UserInterface UserInterfaceConfig `json:"user_interface"`
	Cookie        CookieConfig        `json:"cookie"`
	Token         TokenConfig         `json:"token"`
	Crypto        CryptoConfig        `json:"crypto"`
	Transform     TransformConfig     `json:"transform"`
}

// UserInterfaceConfig represents user interface configuration
type UserInterfaceConfig struct {
	Title   string `json:"title"`
	LogoURL string `json:"logo_url"`
}

// CookieConfig represents cookie configuration
type CookieConfig struct {
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Lifetime int    `json:"lifetime"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httponly"`
	SameSite string `json:"samesite"`
}

// TokenConfig represents token configuration
type TokenConfig struct {
	JWT JWTTokenConfig `json:"jwt"`
}

// JWTTokenConfig represents JWT token configuration
type JWTTokenConfig struct {
	TokenName     string   `json:"token_name"`
	TokenSecret   string   `json:"token_secret"`
	TokenIssuer   string   `json:"token_issuer"`
	TokenAudience []string `json:"token_audience"`
	TokenLifetime int      `json:"token_lifetime"`
	TokenOrigins  []string `json:"token_origins"`
}

// CryptoConfig represents crypto configuration
type CryptoConfig struct {
	Key     KeyConfig     `json:"key"`
	Default DefaultConfig `json:"default"`
}

// KeyConfig represents key configuration
type KeyConfig struct {
	SignVerify string `json:"sign_verify"`
}

// DefaultConfig represents default crypto configuration
type DefaultConfig struct {
	TokenName     string `json:"token_name"`
	TokenLifetime int    `json:"token_lifetime"`
}

// TransformConfig represents transform configuration
type TransformConfig struct {
	Match MatchConfig `json:"match"`
	UI    UIConfig    `json:"ui"`
}

// MatchConfig represents match configuration
type MatchConfig struct {
	Action string `json:"action"`
	Realm  string `json:"realm"`
}

// UIConfig represents UI configuration
type UIConfig struct {
	Links []LinkConfig `json:"links"`
}

// LinkConfig represents a link configuration
type LinkConfig struct {
	Title string `json:"title"`
	Link  string `json:"link"`
	Icon  string `json:"icon"`
}

// AuthorizationConfig represents authorization configuration
type AuthorizationConfig struct {
	DefaultAction string    `json:"default_action"`
	ACL           ACLConfig `json:"acl"`
}

// ACLConfig represents ACL configuration
type ACLConfig struct {
	Rules []ACLRuleConfig `json:"rules"`
}

// ACLRuleConfig represents an ACL rule configuration
type ACLRuleConfig struct {
	Comment    string   `json:"comment"`
	Conditions []string `json:"conditions"`
	Action     string   `json:"action"`
}

// UserRegistryConfig represents user registry configuration
type UserRegistryConfig struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

// LicensingConfiguration represents licensing configuration
type LicensingConfiguration struct {
	Tiers       map[string]LicenseTierConfig `json:"tiers"`
	Enforcement EnforcementConfig            `json:"enforcement"`
}

// LicenseTierConfig represents a license tier configuration
type LicenseTierConfig struct {
	MaxThings  int      `json:"max_things"`
	MaxStreams int      `json:"max_streams"`
	Features   []string `json:"features"`
}

// EnforcementConfig represents enforcement configuration
type EnforcementConfig struct {
	StrictLimits          bool    `json:"strict_limits"`
	GracePeriodDays       int     `json:"grace_period_days"`
	NotificationThreshold float64 `json:"notification_threshold"`
}

// DefaultConfigProvider provides default configurations for TwinCore
type DefaultConfigProvider struct {
	// License checker for separated security domains
	licenseChecker types.UnifiedLicenseChecker
	// Legacy license features (deprecated)
	licenseFeatures map[string]bool
	// Parsed default configuration
	defaultConfig *DefaultConfiguration
}

// NewDefaultConfigProvider creates a new default config provider
func NewDefaultConfigProvider() *DefaultConfigProvider {
	config := &DefaultConfigProvider{
		licenseFeatures: make(map[string]bool),
	}
	config.loadDefaultConfiguration()
	return config
}

// NewDefaultConfigProviderWithLicense creates a new default config provider with license checker
func NewDefaultConfigProviderWithLicense(licenseChecker types.UnifiedLicenseChecker) *DefaultConfigProvider {
	config := &DefaultConfigProvider{
		licenseChecker:  licenseChecker,
		licenseFeatures: make(map[string]bool),
	}
	config.loadDefaultConfiguration()
	return config
}

// loadDefaultConfiguration loads and parses the embedded default configuration
func (d *DefaultConfigProvider) loadDefaultConfiguration() {
	var config DefaultConfiguration
	if err := json.Unmarshal(defaultConfigJSON, &config); err != nil {
		// If parsing fails, use minimal fallback configuration
		config = DefaultConfiguration{
			HTTP: HTTPConfiguration{
				Listen: []string{":8080"},
				Routes: []RouteConfig{},
			},
			SystemSecurity: SystemSecurityConfiguration{
				Enabled: false,
			},
		}
	}
	d.defaultConfig = &config
}

// SetLicenseFeatures updates the available license features (deprecated)
func (d *DefaultConfigProvider) SetLicenseFeatures(features map[string]bool) {
	d.licenseFeatures = features
}

// SetLicenseChecker updates the license checker for separated security domains
func (d *DefaultConfigProvider) SetLicenseChecker(licenseChecker types.UnifiedLicenseChecker) {
	d.licenseChecker = licenseChecker
}

// GetDefaultHTTPConfig returns the default HTTP service configuration
func (d *DefaultConfigProvider) GetDefaultHTTPConfig() types.HTTPConfig {
	if d.defaultConfig == nil {
		// Fallback to minimal configuration if no embedded config is available
		return types.HTTPConfig{
			Listen: []string{":8080"},
			Routes: []types.HTTPRoute{},
		}
	}

	// Convert embedded configuration to types.HTTPConfig
	httpConfig := types.HTTPConfig{
		Listen: d.defaultConfig.HTTP.Listen,
		Routes: make([]types.HTTPRoute, len(d.defaultConfig.HTTP.Routes)),
	}

	// Convert RouteConfig to HTTPRoute
	for i, route := range d.defaultConfig.HTTP.Routes {
		httpConfig.Routes[i] = types.HTTPRoute{
			Path:         route.Path,
			Handler:      route.Handler,
			RequiresAuth: route.RequiresAuth,
			Config:       route.Config,
		}
	}

	return httpConfig
}

// GetDefaultStreamConfig returns the default stream service configuration
func (d *DefaultConfigProvider) GetDefaultStreamConfig() types.StreamConfig {
	if d.defaultConfig == nil {
		// Fallback to minimal configuration if no embedded config is available
		return types.StreamConfig{
			Topics:   []types.StreamTopic{},
			Commands: []types.CommandStream{},
		}
	}

	// Convert embedded configuration to types.StreamConfig
	streamConfig := types.StreamConfig{
		Topics:   make([]types.StreamTopic, len(d.defaultConfig.Stream.Topics)),
		Commands: []types.CommandStream{}, // Commands not in JSON config yet
	}

	// Convert TopicConfig to StreamTopic
	for i, topic := range d.defaultConfig.Stream.Topics {
		streamConfig.Topics[i] = types.StreamTopic{
			Name:   topic.Name,
			Type:   topic.Type,
			Config: topic.Config,
		}
	}

	// Add default command streams (not in JSON config yet)
	streamConfig.Commands = []types.CommandStream{
		{
			Name: "device_commands",
			Type: "mqtt",
			Config: map[string]any{
				"broker": "tcp://localhost:1883",
				"qos":    1,
			},
		},
	}

	// Add advanced features based on license
	if d.isFeatureEnabled("enterprise_streaming") {
		streamConfig.Topics = append(streamConfig.Topics, types.StreamTopic{
			Name: "analytics_stream",
			Type: "kafka",
			Config: map[string]any{
				"brokers": []string{"localhost:9092"},
				"topic":   "twincore.analytics",
			},
		})
	}

	return streamConfig
}

// GetDefaultCaddyConfig returns a minimal default Caddy configuration
func (d *DefaultConfigProvider) GetDefaultCaddyConfig() *caddy.Config {
	// Create default HTTP app configuration
	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{
			"srv0": {
				Listen: []string{":8080"},
				Routes: caddyhttp.RouteList{
					// Default route showing TwinCore is running
					{
						MatcherSetsRaw: []caddy.ModuleMap{
							{
								"path": json.RawMessage(`["/"]`),
							},
						},
						HandlersRaw: []json.RawMessage{
							json.RawMessage(`{
								"handler": "static_response",
								"body": "{\"message\": \"TwinCore Gateway is running. Please access /portal for the web interface or /setup for initial configuration.\"}",
								"status_code": 200,
								"headers": {
									"Content-Type": ["application/json"]
								}
							}`),
						},
					},
					// Portal static files
					{
						MatcherSetsRaw: []caddy.ModuleMap{
							{
								"path": json.RawMessage(`["/portal/*"]`),
							},
						},
						HandlersRaw: []json.RawMessage{
							json.RawMessage(`{
								"handler": "file_server",
								"root": "./portal/dist",
								"strip_prefix": "/portal"
							}`),
						},
					},
					// Setup endpoint
					{
						MatcherSetsRaw: []caddy.ModuleMap{
							{
								"path": json.RawMessage(`["/setup/*"]`),
							},
						},
						HandlersRaw: []json.RawMessage{
							json.RawMessage(`{
								"handler": "reverse_proxy",
								"upstreams": [{"dial": "localhost:8090"}]
							}`),
						},
					},
				},
			},
		},
	}

	// Marshal the HTTP app
	httpAppJSON, _ := json.Marshal(httpApp)

	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true, // Disable Admin API for security and simpler deployment
		},
		AppsRaw: caddy.ModuleMap{
			"http": json.RawMessage(httpAppJSON),
		},
	}

	return cfg
}

// GetDefaultSystemSecurityConfig returns default system security configuration based on license
func (d *DefaultConfigProvider) GetDefaultSystemSecurityConfig() types.SystemSecurityConfig {
	if d.defaultConfig == nil {
		// Fallback to minimal configuration if no embedded config is available
		return types.SystemSecurityConfig{
			Enabled: false,
		}
	}

	// Convert embedded configuration to types.SystemSecurityConfig
	secConfig := types.SystemSecurityConfig{
		Enabled: d.defaultConfig.SystemSecurity.Enabled,
	}

	// Convert AdminAuthConfig
	if d.defaultConfig.SystemSecurity.AdminAuth.Method != "" {
		adminAuth := &types.AdminAuthConfig{
			Method:    d.defaultConfig.SystemSecurity.AdminAuth.Method,
			Providers: d.defaultConfig.SystemSecurity.AdminAuth.Providers,
			MFA:       d.defaultConfig.SystemSecurity.AdminAuth.MFA,
		}

		// Convert LocalAuthConfig
		if len(d.defaultConfig.SystemSecurity.AdminAuth.Local.Users) > 0 {
			localUsers := make([]types.LocalUser, len(d.defaultConfig.SystemSecurity.AdminAuth.Local.Users))
			for i, user := range d.defaultConfig.SystemSecurity.AdminAuth.Local.Users {
				localUsers[i] = types.LocalUser{
					Username:     user.Username,
					PasswordHash: user.PasswordHash,
					Email:        user.Email,
					FullName:     user.FullName,
					Roles:        user.Roles,
					Disabled:     user.Disabled,
				}
			}

			adminAuth.Local = &types.LocalAuthConfig{
				Users: localUsers,
				PasswordPolicy: &types.PasswordPolicy{
					MinLength:        d.defaultConfig.SystemSecurity.AdminAuth.Local.PasswordPolicy.MinLength,
					RequireUppercase: d.defaultConfig.SystemSecurity.AdminAuth.Local.PasswordPolicy.RequireUppercase,
					RequireLowercase: d.defaultConfig.SystemSecurity.AdminAuth.Local.PasswordPolicy.RequireLowercase,
					RequireNumbers:   d.defaultConfig.SystemSecurity.AdminAuth.Local.PasswordPolicy.RequireNumbers,
					RequireSymbols:   d.defaultConfig.SystemSecurity.AdminAuth.Local.PasswordPolicy.RequireSymbols,
					MaxAge:           time.Duration(d.defaultConfig.SystemSecurity.AdminAuth.Local.PasswordPolicy.MaxAgeDays) * 24 * time.Hour,
					PreventReuse:     d.defaultConfig.SystemSecurity.AdminAuth.Local.PasswordPolicy.PreventReuse,
				},
				AccountLockout: &types.AccountLockoutPolicy{
					Enabled:         d.defaultConfig.SystemSecurity.AdminAuth.Local.AccountLockout.Enabled,
					MaxAttempts:     d.defaultConfig.SystemSecurity.AdminAuth.Local.AccountLockout.MaxAttempts,
					LockoutDuration: time.Duration(d.defaultConfig.SystemSecurity.AdminAuth.Local.AccountLockout.LockoutDuration) * time.Second,
					ResetAfter:      time.Duration(d.defaultConfig.SystemSecurity.AdminAuth.Local.AccountLockout.ResetDuration) * time.Second,
				},
			}
		}

		secConfig.AdminAuth = adminAuth
	}

	// Convert APIAuthConfig
	if len(d.defaultConfig.SystemSecurity.APIAuth.Methods) > 0 {
		apiAuth := &types.APIAuthConfig{
			Methods: d.defaultConfig.SystemSecurity.APIAuth.Methods,
		}

		// Convert JWTConfig
		if d.defaultConfig.SystemSecurity.APIAuth.JWTConfig.Algorithm != "" {
			expiry, _ := time.ParseDuration(d.defaultConfig.SystemSecurity.APIAuth.JWTConfig.Expiry)
			apiAuth.JWTConfig = &types.JWTConfig{
				Algorithm:    d.defaultConfig.SystemSecurity.APIAuth.JWTConfig.Algorithm,
				Issuer:       d.defaultConfig.SystemSecurity.APIAuth.JWTConfig.Issuer,
				Audience:     d.defaultConfig.SystemSecurity.APIAuth.JWTConfig.Audience,
				Expiry:       expiry,
				RefreshToken: d.defaultConfig.SystemSecurity.APIAuth.JWTConfig.RefreshToken,
			}
		}

		// Convert Policies
		if len(d.defaultConfig.SystemSecurity.APIAuth.Policies) > 0 {
			policies := make([]types.APIPolicy, len(d.defaultConfig.SystemSecurity.APIAuth.Policies))
			for i, policy := range d.defaultConfig.SystemSecurity.APIAuth.Policies {
				policies[i] = types.APIPolicy{
					ID:          policy.ID,
					Name:        policy.Name,
					Description: policy.Description,
					Principal:   policy.Principal,
					Resources:   policy.Resources,
					Actions:     policy.Actions,
				}
			}
			apiAuth.Policies = policies
		}

		// Convert RateLimitConfig
		if d.defaultConfig.SystemSecurity.APIAuth.RateLimit.Enabled {
			apiAuth.RateLimit = &types.RateLimitConfig{
				RequestsPerMinute: d.defaultConfig.SystemSecurity.APIAuth.RateLimit.RequestsPerMinute,
				BurstSize:         d.defaultConfig.SystemSecurity.APIAuth.RateLimit.Burst,
			}
		}

		secConfig.APIAuth = apiAuth
	}

	// Convert SessionConfig
	if d.defaultConfig.SystemSecurity.SessionConfig.Timeout > 0 {
		secConfig.SessionConfig = &types.SessionConfig{
			Timeout:        time.Duration(d.defaultConfig.SystemSecurity.SessionConfig.Timeout) * time.Second,
			MaxSessions:    d.defaultConfig.SystemSecurity.SessionConfig.MaxSessions,
			SecureCookies:  d.defaultConfig.SystemSecurity.SessionConfig.SecureCookies,
			SameSite:       d.defaultConfig.SystemSecurity.SessionConfig.SameSite,
			CSRFProtection: d.defaultConfig.SystemSecurity.SessionConfig.CSRFProtection,
		}
	}

	// Enable additional features based on separated license domains
	if d.isSystemFeatureEnabled("ldap_auth") {
		if secConfig.AdminAuth != nil {
			secConfig.AdminAuth.Providers = append(secConfig.AdminAuth.Providers, "ldap")
		}
	}
	if d.isSystemFeatureEnabled("mfa") {
		if secConfig.AdminAuth != nil {
			secConfig.AdminAuth.MFA = true
		}
	}
	if d.isSystemFeatureEnabled("rbac") {
		// RBAC is enabled by default if licensed
		if secConfig.APIAuth != nil {
			secConfig.APIAuth.Policies = append(secConfig.APIAuth.Policies, types.APIPolicy{
				ID:          "rbac_operator",
				Name:        "Operator Policy",
				Description: "Operator level access",
				Principal:   "role:operator",
				Resources:   []string{"/api/things/*", "/api/streams/*"},
				Actions:     []string{"read", "write"},
			})
		}
	}

	return secConfig
}

// GetDefaultParquetConfig returns default Parquet logging configuration
func (d *DefaultConfigProvider) GetDefaultParquetConfig() types.ParquetConfig {
	// Use Caddy's AppDataDir for default data storage
	dataDir := caddy.AppDataDir()
	return types.ParquetConfig{
		BasePath:        filepath.Join(dataDir, "twincore_data"),
		BatchSize:       1000,
		BatchPeriod:     "5s",
		Compression:     "snappy",
		FileNamePattern: "%s_%s_%s.parquet", // stream_name, date, uuid
	}
}

// GetDefaultMQTTConfig returns default MQTT configuration
func (d *DefaultConfigProvider) GetDefaultMQTTConfig() types.MQTTConfig {
	return types.MQTTConfig{
		Broker:   "tcp://localhost:1883",
		Topic:    "twincore/+/+", // twincore/{thingId}/{interaction}
		ClientID: "twincore-gateway",
		QoS:      1,
	}
}

// GetDefaultKafkaConfig returns default Kafka configuration
func (d *DefaultConfigProvider) GetDefaultKafkaConfig() types.KafkaConfig {
	return types.KafkaConfig{
		Brokers:       []string{"localhost:9092"},
		Topic:         "twincore-events",
		ConsumerGroup: "twincore-gateway",
	}
}

// Helper methods for license feature checking

// isFeatureEnabled checks if a general feature is enabled (legacy support)
func (d *DefaultConfigProvider) isFeatureEnabled(feature string) bool {
	// First try unified license checker for general features
	if d.licenseChecker != nil {
		return d.licenseChecker.IsGeneralFeatureEnabled(context.Background(), feature)
	}
	// Fall back to legacy feature map
	return d.licenseFeatures[feature]
}

// isSystemFeatureEnabled checks if a system security feature is enabled
func (d *DefaultConfigProvider) isSystemFeatureEnabled(feature string) bool {
	if d.licenseChecker != nil {
		return d.licenseChecker.IsSystemFeatureEnabled(context.Background(), feature)
	}
	// Fall back to legacy feature map
	return d.licenseFeatures[feature]
}

// isWoTFeatureEnabled checks if a WoT security feature is enabled
func (d *DefaultConfigProvider) isWoTFeatureEnabled(feature string) bool {
	if d.licenseChecker != nil {
		return d.licenseChecker.IsWoTFeatureEnabled(context.Background(), feature)
	}
	// Fall back to legacy feature map
	return d.licenseFeatures[feature]
}

// GetDefaultWoTSecurityConfig returns default WoT security configuration based on license
func (d *DefaultConfigProvider) GetDefaultWoTSecurityConfig() types.WoTSecurityConfig {
	if d.defaultConfig == nil {
		// Fallback to minimal configuration if no embedded config is available
		return types.WoTSecurityConfig{
			ThingPolicies:     make(map[string]types.ThingSecurityPolicy),
			CredentialStores:  make(map[string]types.CredentialStore),
			SecurityTemplates: make(map[string]types.SecurityTemplate),
		}
	}

	// Convert embedded configuration to types.WoTSecurityConfig
	wotConfig := types.WoTSecurityConfig{
		ThingPolicies:     make(map[string]types.ThingSecurityPolicy),
		CredentialStores:  make(map[string]types.CredentialStore),
		SecurityTemplates: make(map[string]types.SecurityTemplate),
	}

	// Convert credential stores from embedded config
	for _, store := range d.defaultConfig.WoTSecurity.CredentialStores {
		wotConfig.CredentialStores[store.Name] = types.CredentialStore{
			Type:      store.Type,
			Encrypted: store.Encrypted,
			Config:    store.Config,
		}
	}

	// Convert security templates from embedded config
	for _, template := range d.defaultConfig.WoTSecurity.SecurityTemplates {
		wotConfig.SecurityTemplates[template.Name] = types.SecurityTemplate{
			Name:        template.Name,
			Description: "Security template for " + template.Scheme,
			Schemes: []types.WoTSecurityScheme{
				{
					Scheme:      template.Scheme,
					Description: "Authentication scheme: " + template.Scheme,
				},
			},
			Credentials: map[string]types.CredentialRef{
				template.Scheme: {
					Store: "env", // Default to env store
					Key:   "DEVICE_" + strings.ToUpper(template.Scheme),
					Type:  template.Scheme,
				},
			},
		}
	}

	// Set default security scheme if specified
	if d.defaultConfig.WoTSecurity.DefaultSecurityScheme != "" {
		// Create GlobalPolicies if not exists
		if wotConfig.GlobalPolicies == nil {
			wotConfig.GlobalPolicies = &types.GlobalWoTSecurityPolicy{}
		}
	}

	// Convert device policies from embedded config
	if d.defaultConfig.WoTSecurity.DevicePolicies.RequireAuthentication {
		if wotConfig.GlobalPolicies == nil {
			wotConfig.GlobalPolicies = &types.GlobalWoTSecurityPolicy{}
		}
		wotConfig.GlobalPolicies.RequireAuthentication = d.defaultConfig.WoTSecurity.DevicePolicies.RequireAuthentication
		wotConfig.GlobalPolicies.AllowedProtocols = []string{"http", "https", "mqtt", "mqtts", "kafka"}
		wotConfig.GlobalPolicies.BlockedIPs = []string{}
	}

	// Add advanced features based on license
	if d.isWoTFeatureEnabled("credential_stores") {
		// Additional credential stores based on license
		if d.isWoTFeatureEnabled("vault_integration") {
			wotConfig.CredentialStores["vault"] = types.CredentialStore{
				Type:      "vault",
				Encrypted: true,
				Config: map[string]any{
					"address": "${VAULT_ADDR:http://localhost:8200}",
					"path":    "secret/twincore",
				},
			}
		}
	}

	// Add global policies if licensed
	if d.isWoTFeatureEnabled("global_policies") {
		if wotConfig.GlobalPolicies == nil {
			wotConfig.GlobalPolicies = &types.GlobalWoTSecurityPolicy{
				RequireAuthentication: true,
				AllowedProtocols:      []string{"http", "https", "mqtt", "mqtts", "kafka"},
				BlockedIPs:            []string{},
			}
		}

		// Add rate limiting if licensed
		if d.isWoTFeatureEnabled("wot_rate_limit") {
			wotConfig.GlobalPolicies.DefaultRateLimit = &types.WoTRateLimit{
				RequestsPerMinute: 100,
				BurstSize:         10,
			}
		}
	}

	return wotConfig
}
