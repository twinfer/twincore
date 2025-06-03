package forms

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// ProtocolSecurityManager handles protocol-specific security configuration
type ProtocolSecurityManager struct {
	logger         *logrus.Logger
	licenseChecker types.UnifiedLicenseChecker
}

// NewProtocolSecurityManager creates a new protocol security manager
func NewProtocolSecurityManager(logger *logrus.Logger, licenseChecker types.UnifiedLicenseChecker) *ProtocolSecurityManager {
	return &ProtocolSecurityManager{
		logger:         logger,
		licenseChecker: licenseChecker,
	}
}

// GenerateHTTPAuth generates HTTP authentication configuration
func (psm *ProtocolSecurityManager) GenerateHTTPAuth(ctx context.Context, schemes []wot.SecurityScheme, credentials *types.DeviceCredentials) (*HTTPAuthConfig, error) {
	psm.logger.WithFields(logrus.Fields{
		"scheme_count": len(schemes),
		"cred_type":    credentials.Type,
	}).Debug("Generating HTTP authentication configuration")

	if len(schemes) == 0 {
		return &HTTPAuthConfig{
			Headers: make(map[string]string),
		}, nil
	}

	// Find the first compatible scheme
	for _, scheme := range schemes {
		if psm.isHTTPCompatible(scheme.Scheme) {
			return psm.generateHTTPAuthForScheme(ctx, scheme, credentials)
		}
	}

	return nil, fmt.Errorf("no HTTP-compatible security scheme found")
}

// GenerateMQTTAuth generates MQTT authentication configuration
func (psm *ProtocolSecurityManager) GenerateMQTTAuth(ctx context.Context, schemes []wot.SecurityScheme, credentials *types.DeviceCredentials) (*MQTTAuthConfig, error) {
	psm.logger.WithFields(logrus.Fields{
		"scheme_count": len(schemes),
		"cred_type":    credentials.Type,
	}).Debug("Generating MQTT authentication configuration")

	if len(schemes) == 0 {
		return &MQTTAuthConfig{}, nil
	}

	// Find the first compatible scheme
	for _, scheme := range schemes {
		if psm.isMQTTCompatible(scheme.Scheme) {
			return psm.generateMQTTAuthForScheme(ctx, scheme, credentials)
		}
	}

	return nil, fmt.Errorf("no MQTT-compatible security scheme found")
}

// GenerateKafkaAuth generates Kafka authentication configuration
func (psm *ProtocolSecurityManager) GenerateKafkaAuth(ctx context.Context, schemes []wot.SecurityScheme, credentials *types.DeviceCredentials) (*KafkaAuthConfig, error) {
	psm.logger.WithFields(logrus.Fields{
		"scheme_count": len(schemes),
		"cred_type":    credentials.Type,
	}).Debug("Generating Kafka authentication configuration")

	if len(schemes) == 0 {
		return &KafkaAuthConfig{}, nil
	}

	// Find the first compatible scheme
	for _, scheme := range schemes {
		if psm.isKafkaCompatible(scheme.Scheme) {
			return psm.generateKafkaAuthForScheme(ctx, scheme, credentials)
		}
	}

	return nil, fmt.Errorf("no Kafka-compatible security scheme found")
}

// ConfigureTLS configures TLS settings for a protocol
func (psm *ProtocolSecurityManager) ConfigureTLS(ctx context.Context, protocol string, config *TLSConfig) error {
	// Check if TLS is required by license
	if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "tls_required") {
		config.Enabled = true
	}

	// Set secure defaults based on license features
	if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "protocol_encryption") {
		if config.MinVersion == "" {
			config.MinVersion = "1.2" // Default to TLS 1.2 minimum
		}
		
		// Set secure cipher suites if none specified
		if len(config.CipherSuites) == 0 {
			config.CipherSuites = []string{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			}
		}
	}

	psm.logger.WithFields(logrus.Fields{
		"protocol":    protocol,
		"tls_enabled": config.Enabled,
		"min_version": config.MinVersion,
	}).Debug("Configured TLS for protocol")

	return nil
}

// ValidateProtocolSecurity validates protocol-specific security configuration
func (psm *ProtocolSecurityManager) ValidateProtocolSecurity(ctx context.Context, protocol string, config map[string]interface{}) error {
	switch strings.ToLower(protocol) {
	case "http", "https":
		return psm.validateHTTPSecurity(ctx, config)
	case "mqtt", "mqtts":
		return psm.validateMQTTSecurity(ctx, config)
	case "kafka":
		return psm.validateKafkaSecurity(ctx, config)
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// HTTP Authentication Configuration Types

// HTTPAuthConfig represents HTTP authentication configuration
type HTTPAuthConfig struct {
	Headers     map[string]string      `json:"headers"`
	BasicAuth   *HTTPBasicAuth         `json:"basic_auth,omitempty"`
	BearerToken *string                `json:"bearer_token,omitempty"`
	OAuth2      *HTTPOAuth2Config      `json:"oauth2,omitempty"`
	APIKey      *HTTPAPIKeyConfig      `json:"api_key,omitempty"`
	Custom      map[string]interface{} `json:"custom,omitempty"`
}

// HTTPBasicAuth represents HTTP Basic authentication
type HTTPBasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HTTPOAuth2Config represents OAuth2 configuration for HTTP
type HTTPOAuth2Config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	TokenURL     string   `json:"token_url"`
	Scopes       []string `json:"scopes,omitempty"`
	GrantType    string   `json:"grant_type"` // "client_credentials", "authorization_code", etc.
}

// HTTPAPIKeyConfig represents API key configuration for HTTP
type HTTPAPIKeyConfig struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	In        string `json:"in"`        // "header", "query", "cookie"
	Name      string `json:"name"`      // Header name or query parameter name
}

// MQTT Authentication Configuration Types

// MQTTAuthConfig represents MQTT authentication configuration
type MQTTAuthConfig struct {
	Username    string              `json:"username,omitempty"`
	Password    string              `json:"password,omitempty"`
	ClientCert  *types.TLSConfig    `json:"client_cert,omitempty"`
	TLS         *TLSConfig          `json:"tls,omitempty"`
	PSK         *MQTTPSKConfig      `json:"psk,omitempty"`
	Custom      map[string]interface{} `json:"custom,omitempty"`
}

// MQTTPSKConfig represents MQTT Pre-Shared Key configuration
type MQTTPSKConfig struct {
	Identity string `json:"identity"`
	Key      string `json:"key"`
}

// Kafka Authentication Configuration Types

// KafkaAuthConfig represents Kafka authentication configuration
type KafkaAuthConfig struct {
	SASL        *KafkaSASLConfig       `json:"sasl,omitempty"`
	TLS         *TLSConfig             `json:"tls,omitempty"`
	OAuth2      *KafkaOAuth2Config     `json:"oauth2,omitempty"`
	Custom      map[string]interface{} `json:"custom,omitempty"`
}

// KafkaSASLConfig represents Kafka SASL configuration
type KafkaSASLConfig struct {
	Mechanism string `json:"mechanism"` // "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// KafkaOAuth2Config represents Kafka OAuth2 configuration
type KafkaOAuth2Config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	TokenURL     string   `json:"token_url"`
	Scopes       []string `json:"scopes,omitempty"`
}

// TLS Configuration Type

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled            bool     `json:"enabled"`
	CertFile           string   `json:"cert_file,omitempty"`
	KeyFile            string   `json:"key_file,omitempty"`
	CAFile             string   `json:"ca_file,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty"`
	MinVersion         string   `json:"min_version,omitempty"` // "1.0", "1.1", "1.2", "1.3"
	MaxVersion         string   `json:"max_version,omitempty"`
	CipherSuites       []string `json:"cipher_suites,omitempty"`
	ServerName         string   `json:"server_name,omitempty"` // For SNI
}

// Helper methods for protocol compatibility

func (psm *ProtocolSecurityManager) isHTTPCompatible(scheme string) bool {
	compatible := []string{"basic", "bearer", "apikey", "oauth2", "digest"}
	for _, compat := range compatible {
		if compat == scheme {
			return true
		}
	}
	return false
}

func (psm *ProtocolSecurityManager) isMQTTCompatible(scheme string) bool {
	compatible := []string{"basic", "cert", "psk"}
	for _, compat := range compatible {
		if compat == scheme {
			return true
		}
	}
	return false
}

func (psm *ProtocolSecurityManager) isKafkaCompatible(scheme string) bool {
	compatible := []string{"basic", "oauth2", "cert", "sasl"}
	for _, compat := range compatible {
		if compat == scheme {
			return true
		}
	}
	return false
}

// HTTP Authentication Generation

func (psm *ProtocolSecurityManager) generateHTTPAuthForScheme(ctx context.Context, scheme wot.SecurityScheme, credentials *types.DeviceCredentials) (*HTTPAuthConfig, error) {
	config := &HTTPAuthConfig{
		Headers: make(map[string]string),
	}

	switch scheme.Scheme {
	case "basic":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return nil, fmt.Errorf("basic authentication not licensed")
		}
		
		config.BasicAuth = &HTTPBasicAuth{
			Username: credentials.Username,
			Password: credentials.Password,
		}
		
		// Generate Authorization header value for Benthos
		config.Headers["Authorization"] = fmt.Sprintf("Basic ${base64:%s:%s}", 
			credentials.Username, credentials.Password)

	case "bearer":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "bearer_auth") {
			return nil, fmt.Errorf("bearer authentication not licensed")
		}
		
		token := credentials.Token
		config.BearerToken = &token
		config.Headers["Authorization"] = fmt.Sprintf("Bearer %s", token)

	case "apikey":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "api_key_auth") {
			return nil, fmt.Errorf("API key authentication not licensed")
		}
		
		apiKeyConfig := &HTTPAPIKeyConfig{
			Key:   credentials.APIKey,
			Value: credentials.APIKey,
			In:    scheme.In,
			Name:  scheme.Name,
		}
		config.APIKey = apiKeyConfig

		if scheme.In == "header" {
			config.Headers[scheme.Name] = credentials.APIKey
		}
		// Query parameters are handled differently in Benthos

	case "oauth2":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			return nil, fmt.Errorf("OAuth2 authentication not licensed")
		}
		
		if credentials.OAuth2 != nil {
			config.OAuth2 = &HTTPOAuth2Config{
				ClientID:     credentials.OAuth2.ClientID,
				ClientSecret: credentials.OAuth2.ClientSecret,
				TokenURL:     getStringFromProperties(scheme.Properties, "token"),
				Scopes:       credentials.OAuth2.Scopes,
				GrantType:    "client_credentials", // Default
			}
			
			// Use the access token if available
			if credentials.OAuth2.AccessToken != "" {
				config.Headers["Authorization"] = fmt.Sprintf("Bearer %s", credentials.OAuth2.AccessToken)
			}
		}

	default:
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "custom_auth") {
			return nil, fmt.Errorf("custom authentication schemes not licensed")
		}
		
		config.Custom = map[string]interface{}{
			"scheme": scheme.Scheme,
			"config": credentials.Metadata,
		}
	}

	return config, nil
}

// MQTT Authentication Generation

func (psm *ProtocolSecurityManager) generateMQTTAuthForScheme(ctx context.Context, scheme wot.SecurityScheme, credentials *types.DeviceCredentials) (*MQTTAuthConfig, error) {
	config := &MQTTAuthConfig{}

	switch scheme.Scheme {
	case "basic":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return nil, fmt.Errorf("basic authentication not licensed")
		}
		
		config.Username = credentials.Username
		config.Password = credentials.Password

	case "cert":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			return nil, fmt.Errorf("certificate authentication not licensed")
		}
		
		if credentials.Certificate != nil {
			config.ClientCert = &types.TLSConfig{
				Enabled:  true,
				CertFile: credentials.Certificate.ClientCert,
				KeyFile:  credentials.Certificate.ClientKey,
				CAFile:   credentials.Certificate.CACert,
			}
		}

	case "psk":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "psk_auth") {
			return nil, fmt.Errorf("PSK authentication not licensed")
		}
		
		// PSK configuration from credentials metadata
		if identity, ok := credentials.Metadata["psk_identity"].(string); ok {
			if key, ok := credentials.Metadata["psk_key"].(string); ok {
				config.PSK = &MQTTPSKConfig{
					Identity: identity,
					Key:      key,
				}
			}
		}

	default:
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "custom_auth") {
			return nil, fmt.Errorf("custom authentication schemes not licensed")
		}
		
		config.Custom = map[string]interface{}{
			"scheme": scheme.Scheme,
			"config": credentials.Metadata,
		}
	}

	return config, nil
}

// Kafka Authentication Generation

func (psm *ProtocolSecurityManager) generateKafkaAuthForScheme(ctx context.Context, scheme wot.SecurityScheme, credentials *types.DeviceCredentials) (*KafkaAuthConfig, error) {
	config := &KafkaAuthConfig{}

	switch scheme.Scheme {
	case "basic", "sasl":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return nil, fmt.Errorf("SASL authentication not licensed")
		}
		
		mechanism := "PLAIN" // Default
		if mech, ok := credentials.Metadata["sasl_mechanism"].(string); ok {
			mechanism = mech
		}
		
		config.SASL = &KafkaSASLConfig{
			Mechanism: mechanism,
			Username:  credentials.Username,
			Password:  credentials.Password,
		}

	case "oauth2":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			return nil, fmt.Errorf("OAuth2 authentication not licensed")
		}
		
		if credentials.OAuth2 != nil {
			config.OAuth2 = &KafkaOAuth2Config{
				ClientID:     credentials.OAuth2.ClientID,
				ClientSecret: credentials.OAuth2.ClientSecret,
				TokenURL:     getStringFromProperties(scheme.Properties, "token"),
				Scopes:       credentials.OAuth2.Scopes,
			}
		}

	case "cert":
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			return nil, fmt.Errorf("certificate authentication not licensed")
		}
		
		if credentials.Certificate != nil {
			config.TLS = &TLSConfig{
				Enabled:  true,
				CertFile: credentials.Certificate.ClientCert,
				KeyFile:  credentials.Certificate.ClientKey,
				CAFile:   credentials.Certificate.CACert,
			}
		}

	default:
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "custom_auth") {
			return nil, fmt.Errorf("custom authentication schemes not licensed")
		}
		
		config.Custom = map[string]interface{}{
			"scheme": scheme.Scheme,
			"config": credentials.Metadata,
		}
	}

	return config, nil
}

// Security Validation Methods

func (psm *ProtocolSecurityManager) validateHTTPSecurity(ctx context.Context, config map[string]interface{}) error {
	// Validate required security features are licensed
	if authType, ok := config["auth_type"].(string); ok {
		switch authType {
		case "basic":
			if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
				return fmt.Errorf("basic authentication not licensed")
			}
		case "bearer":
			if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "bearer_auth") {
				return fmt.Errorf("bearer authentication not licensed")
			}
		case "oauth2":
			if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
				return fmt.Errorf("OAuth2 authentication not licensed")
			}
		}
	}

	// Validate TLS configuration if present
	if tlsConfig, ok := config["tls"].(map[string]interface{}); ok {
		if enabled, ok := tlsConfig["enabled"].(bool); ok && enabled {
			if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "protocol_encryption") {
				return fmt.Errorf("TLS encryption not licensed")
			}
		}
	}

	return nil
}

func (psm *ProtocolSecurityManager) validateMQTTSecurity(ctx context.Context, config map[string]interface{}) error {
	// Check for username/password authentication
	if _, hasUsername := config["username"]; hasUsername {
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return fmt.Errorf("MQTT username/password authentication not licensed")
		}
	}

	// Check for certificate authentication
	if _, hasCert := config["client_cert"]; hasCert {
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			return fmt.Errorf("MQTT certificate authentication not licensed")
		}
	}

	// Check for PSK authentication
	if _, hasPSK := config["psk"]; hasPSK {
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "psk_auth") {
			return fmt.Errorf("MQTT PSK authentication not licensed")
		}
	}

	return nil
}

func (psm *ProtocolSecurityManager) validateKafkaSecurity(ctx context.Context, config map[string]interface{}) error {
	// Check for SASL authentication
	if saslConfig, ok := config["sasl"].(map[string]interface{}); ok {
		if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return fmt.Errorf("Kafka SASL authentication not licensed")
		}
		
		// Validate SASL mechanism
		if mechanism, ok := saslConfig["mechanism"].(string); ok {
			switch mechanism {
			case "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512":
				// These are basic mechanisms
			case "OAUTHBEARER":
				if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
					return fmt.Errorf("Kafka OAuth2 authentication not licensed")
				}
			}
		}
	}

	// Check for TLS/SSL
	if tlsConfig, ok := config["tls"].(map[string]interface{}); ok {
		if enabled, ok := tlsConfig["enabled"].(bool); ok && enabled {
			if !psm.licenseChecker.IsWoTFeatureEnabled(ctx, "protocol_encryption") {
				return fmt.Errorf("Kafka TLS encryption not licensed")
			}
		}
	}

	return nil
}

// Utility Methods

// GetSupportedSchemes returns supported security schemes for a protocol
func (psm *ProtocolSecurityManager) GetSupportedSchemes(ctx context.Context, protocol string) ([]string, error) {
	schemes := make([]string, 0)

	switch strings.ToLower(protocol) {
	case "http", "https":
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			schemes = append(schemes, "basic")
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "bearer_auth") {
			schemes = append(schemes, "bearer")
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "api_key_auth") {
			schemes = append(schemes, "apikey")
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			schemes = append(schemes, "oauth2")
		}

	case "mqtt", "mqtts":
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			schemes = append(schemes, "basic")
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			schemes = append(schemes, "cert")
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "psk_auth") {
			schemes = append(schemes, "psk")
		}

	case "kafka":
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			schemes = append(schemes, "sasl")
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			schemes = append(schemes, "oauth2")
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			schemes = append(schemes, "cert")
		}

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// Add custom schemes if licensed
	if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "custom_auth") {
		schemes = append(schemes, "custom")
	}

	return schemes, nil
}

// GetRecommendedScheme returns the recommended security scheme for a protocol
func (psm *ProtocolSecurityManager) GetRecommendedScheme(ctx context.Context, protocol string) (string, error) {
	switch strings.ToLower(protocol) {
	case "http":
		// For HTTP, prefer OAuth2 > Bearer > Basic
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			return "oauth2", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "bearer_auth") {
			return "bearer", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return "basic", nil
		}

	case "https":
		// For HTTPS, prefer certificate > OAuth2 > Bearer > Basic
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			return "cert", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			return "oauth2", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "bearer_auth") {
			return "bearer", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return "basic", nil
		}

	case "mqtt":
		// For MQTT, prefer basic auth
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return "basic", nil
		}

	case "mqtts":
		// For MQTTS, prefer certificate > PSK > basic
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			return "cert", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "psk_auth") {
			return "psk", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return "basic", nil
		}

	case "kafka":
		// For Kafka, prefer OAuth2 > SASL
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			return "oauth2", nil
		}
		if psm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return "sasl", nil
		}

	default:
		return "", fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return "", fmt.Errorf("no licensed security schemes available for protocol %s", protocol)
}

// Helper function to safely extract string values from Properties map
func getStringFromProperties(properties map[string]interface{}, key string) string {
	if properties == nil {
		return ""
	}
	if value, ok := properties[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}