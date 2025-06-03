package config

import (
	"encoding/json"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/twinfer/twincore/pkg/types"
)

// DefaultConfigProvider provides default configurations for TwinCore
type DefaultConfigProvider struct {
	// License features to determine which defaults to apply
	licenseFeatures map[string]bool
}

// NewDefaultConfigProvider creates a new default config provider
func NewDefaultConfigProvider() *DefaultConfigProvider {
	return &DefaultConfigProvider{
		licenseFeatures: make(map[string]bool),
	}
}

// SetLicenseFeatures updates the available license features
func (d *DefaultConfigProvider) SetLicenseFeatures(features map[string]bool) {
	d.licenseFeatures = features
}

// GetDefaultHTTPConfig returns the default HTTP service configuration
func (d *DefaultConfigProvider) GetDefaultHTTPConfig() types.HTTPConfig {
	// Base configuration
	httpConfig := types.HTTPConfig{
		Listen: []string{":8080"},
		Routes: []types.HTTPRoute{
			// Portal route (always available)
			{
				Path:    "/portal/*",
				Handler: "file_server",
				Config: map[string]interface{}{
					"root":         "./portal/dist",
					"strip_prefix": "/portal",
				},
			},
			// Setup route (available during initial setup)
			{
				Path:    "/setup/*",
				Handler: "reverse_proxy",
				Config: map[string]interface{}{
					"upstream": "localhost:8090",
				},
			},
			// API routes - authentication now handled by SystemSecurityManager middleware
			{
				Path:         "/api/*",
				Handler:      "reverse_proxy",
				// RequiresAuth removed - now handled by SystemSecurityManager
				Config: map[string]interface{}{
					"upstream": "localhost:8090",
				},
			},
			// WoT routes - authentication now handled by SystemSecurityManager middleware
			{
				Path:         "/things/*",
				Handler:      "unified_wot_handler",
				// RequiresAuth removed - now handled by SystemSecurityManager
			},
		},
		// Security is now handled separately via SystemSecurityManager
	}

	return httpConfig
}

// GetDefaultStreamConfig returns the default stream service configuration
func (d *DefaultConfigProvider) GetDefaultStreamConfig() types.StreamConfig {
	streamConfig := types.StreamConfig{
		Topics: []types.StreamTopic{
			// Default property update topic
			{
				Name: "property_updates",
				Type: "kafka",
				Config: map[string]interface{}{
					"brokers": []string{"localhost:9092"},
					"topic":   "twincore.property.updates",
				},
			},
			// Default action invocation topic
			{
				Name: "action_invocations",
				Type: "kafka",
				Config: map[string]interface{}{
					"brokers": []string{"localhost:9092"},
					"topic":   "twincore.action.invocations",
				},
			},
		},
		Commands: []types.CommandStream{
			// Default command stream for device control
			{
				Name: "device_commands",
				Type: "mqtt",
				Config: map[string]interface{}{
					"broker": "tcp://localhost:1883",
					"qos":    1,
				},
			},
		},
	}

	// Add advanced features based on license
	if d.licenseFeatures["enterprise_streaming"] {
		streamConfig.Topics = append(streamConfig.Topics, types.StreamTopic{
			Name: "analytics_stream",
			Type: "kafka",
			Config: map[string]interface{}{
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
	// Basic security configuration - disabled by default for security
	secConfig := types.SystemSecurityConfig{
		Enabled: false, // Must be explicitly enabled during setup
		AdminAuth: &types.AdminAuthConfig{
			Method:    "local",
			Providers: []string{"local"},
			MFA:       false,
			Local: &types.LocalAuthConfig{
				Users: []types.LocalUser{
					// Default admin user (password should be changed on first login)
					{
						Username:     "admin", 
						PasswordHash: "$2a$10$defaulthash", // This should be replaced during setup
						Email:        "admin@twincore.local",
						FullName:     "System Administrator",
						Roles:        []string{"admin"},
						Disabled:     false,
					},
				},
				PasswordPolicy: &types.PasswordPolicy{
					MinLength:        8,
					RequireUppercase: true,
					RequireLowercase: true,
					RequireNumbers:   true,
					RequireSymbols:   false,
				},
			},
		},
		APIAuth: &types.APIAuthConfig{
			Methods: []string{"jwt"},
			JWTConfig: &types.JWTConfig{
				Algorithm: "RS256",
				Issuer:    "twincore-gateway",
				Audience:  "twincore-api",
				// PublicKey will be set during initialization
			},
			Policies: []types.APIPolicy{
				{
					ID:          "default_admin",
					Name:        "Default Admin Policy",
					Description: "Full access for admin role",
					Principal:   "role:admin",
					Resources:   []string{"/api/*"},
					Actions:     []string{"read", "write", "delete", "admin"},
				},
				{
					ID:          "default_user",
					Name:        "Default User Policy", 
					Description: "Limited access for regular users",
					Principal:   "role:user",
					Resources:   []string{"/api/things/*", "/api/status"},
					Actions:     []string{"read"},
				},
			},
		},
		SessionConfig: &types.SessionConfig{
			Timeout:        3600000000000, // 1 hour in nanoseconds
			MaxSessions:    5,
			SecureCookies:  true,
			SameSite:       "strict",
			CSRFProtection: true,
		},
	}

	// Enable additional features based on license
	if d.licenseFeatures["ldap_auth"] {
		secConfig.AdminAuth.Providers = append(secConfig.AdminAuth.Providers, "ldap")
	}
	if d.licenseFeatures["mfa"] {
		secConfig.AdminAuth.MFA = true
	}
	if d.licenseFeatures["rbac"] {
		// RBAC is enabled by default if licensed
		secConfig.APIAuth.Policies = append(secConfig.APIAuth.Policies, types.APIPolicy{
			ID:          "rbac_operator",
			Name:        "Operator Policy",
			Description: "Operator level access",
			Principal:   "role:operator", 
			Resources:   []string{"/api/things/*", "/api/streams/*"},
			Actions:     []string{"read", "write"},
		})
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
