package types

import (
	"context"
	"time"
)

// SystemSecurityConfig defines system-level security configuration
// This controls access to TwinCore's management APIs and web interface
type SystemSecurityConfig struct {
	Enabled       bool                     `json:"enabled"`
	AdminAuth     *AdminAuthConfig         `json:"admin_auth,omitempty"`
	APIAuth       *APIAuthConfig           `json:"api_auth,omitempty"`
	SessionConfig *SessionConfig           `json:"session_config,omitempty"`
}

// AdminAuthConfig configures authentication for administrative access
type AdminAuthConfig struct {
	Method    string   `json:"method"`    // "local", "ldap", "saml", "oidc"
	Providers []string `json:"providers"` // Multiple auth providers
	MFA       bool     `json:"mfa"`       // Multi-factor authentication
	Local     *LocalAuthConfig `json:"local,omitempty"`
	LDAP      *LDAPAuthConfig  `json:"ldap,omitempty"`
	SAML      *SAMLAuthConfig  `json:"saml,omitempty"`
	OIDC      *OIDCAuthConfig  `json:"oidc,omitempty"`
}

// APIAuthConfig configures authentication for API access
type APIAuthConfig struct {
	Methods    []string      `json:"methods"`    // ["bearer", "jwt", "apikey"]
	JWTConfig  *JWTConfig    `json:"jwt_config,omitempty"`
	Policies   []APIPolicy   `json:"policies"`   // RBAC policies
	RateLimit  *RateLimitConfig `json:"rate_limit,omitempty"`
}

// SessionConfig configures user session management
type SessionConfig struct {
	Timeout        time.Duration `json:"timeout"`         // Session timeout
	MaxSessions    int          `json:"max_sessions"`    // Max concurrent sessions per user
	SecureCookies  bool         `json:"secure_cookies"`  // HTTPS-only cookies
	SameSite       string       `json:"same_site"`       // Cookie SameSite policy
	CSRFProtection bool         `json:"csrf_protection"` // CSRF token validation
}

// LocalAuthConfig configures local user authentication
type LocalAuthConfig struct {
	Users           []LocalUser `json:"users"`
	PasswordPolicy  *PasswordPolicy `json:"password_policy,omitempty"`
	AccountLockout  *AccountLockoutPolicy `json:"account_lockout,omitempty"`
}

// LDAPAuthConfig configures LDAP authentication
type LDAPAuthConfig struct {
	Server       string            `json:"server"`
	Port         int              `json:"port"`
	BaseDN       string           `json:"base_dn"`
	BindDN       string           `json:"bind_dn"`
	BindPassword string           `json:"bind_password,omitempty"`
	UserFilter   string           `json:"user_filter"`
	GroupFilter  string           `json:"group_filter,omitempty"`
	TLS          *TLSConfig       `json:"tls,omitempty"`
	Attributes   *LDAPAttributes  `json:"attributes,omitempty"`
}

// SAMLAuthConfig configures SAML authentication
type SAMLAuthConfig struct {
	EntityID     string     `json:"entity_id"`
	SSOURL       string     `json:"sso_url"`
	Certificate  string     `json:"certificate"`
	PrivateKey   string     `json:"private_key,omitempty"`
	Attributes   *SAMLAttributes `json:"attributes,omitempty"`
}

// OIDCAuthConfig configures OpenID Connect authentication
type OIDCAuthConfig struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes"`
	RedirectURL  string   `json:"redirect_url"`
}

// JWTConfig configures JWT token validation
type JWTConfig struct {
	PublicKey    string        `json:"public_key"`
	Algorithm    string        `json:"algorithm"`    // "RS256", "HS256", etc.
	Issuer       string        `json:"issuer"`
	Audience     string        `json:"audience"`
	Expiry       time.Duration `json:"expiry"`
	RefreshToken bool          `json:"refresh_token"`
}

// APIPolicy defines RBAC policy for API access
type APIPolicy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Principal   string   `json:"principal"` // user, group, role
	Resources   []string `json:"resources"` // API endpoints or resource patterns
	Actions     []string `json:"actions"`   // read, write, delete, admin
	Conditions  []PolicyCondition `json:"conditions,omitempty"`
}

// PolicyCondition defines conditional access rules
type PolicyCondition struct {
	Type      string      `json:"type"`      // "ip", "time", "mfa", "device"
	Operator  string      `json:"operator"`  // "equals", "contains", "in_range"
	Value     interface{} `json:"value"`
}

// RateLimitConfig configures API rate limiting
type RateLimitConfig struct {
	RequestsPerMinute int    `json:"requests_per_minute"`
	BurstSize         int    `json:"burst_size"`
	ByIP              bool   `json:"by_ip"`
	ByUser            bool   `json:"by_user"`
	WhitelistIPs      []string `json:"whitelist_ips,omitempty"`
}

// LocalUser defines a local system user
type LocalUser struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"` // Hashed password
	Email        string    `json:"email,omitempty"`
	FullName     string    `json:"full_name,omitempty"`
	Roles        []string  `json:"roles"`
	Disabled     bool      `json:"disabled"`
	LastLogin    time.Time `json:"last_login,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAge           time.Duration `json:"max_age,omitempty"`
	PreventReuse     int  `json:"prevent_reuse,omitempty"` // Number of previous passwords to check
}

// AccountLockoutPolicy defines account lockout rules
type AccountLockoutPolicy struct {
	Enabled           bool          `json:"enabled"`
	MaxAttempts       int           `json:"max_attempts"`
	LockoutDuration   time.Duration `json:"lockout_duration"`
	ResetAfter        time.Duration `json:"reset_after"` // Reset attempt counter after this time
}

// LDAPAttributes maps LDAP attributes to user fields
type LDAPAttributes struct {
	Username string `json:"username"` // LDAP attribute for username
	Email    string `json:"email"`    // LDAP attribute for email
	FullName string `json:"full_name"` // LDAP attribute for full name
	Groups   string `json:"groups"`   // LDAP attribute for group membership
}

// SAMLAttributes maps SAML attributes to user fields
type SAMLAttributes struct {
	Username string `json:"username"` // SAML attribute for username
	Email    string `json:"email"`    // SAML attribute for email
	FullName string `json:"full_name"` // SAML attribute for full name
	Groups   string `json:"groups"`   // SAML attribute for group membership
}

// TLSConfig defines TLS configuration
type TLSConfig struct {
	Enabled            bool     `json:"enabled"`
	CertFile           string   `json:"cert_file,omitempty"`
	KeyFile            string   `json:"key_file,omitempty"`
	CAFile             string   `json:"ca_file,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty"`
	MinVersion         string   `json:"min_version,omitempty"` // "1.2", "1.3"
	CipherSuites       []string `json:"cipher_suites,omitempty"`
}

// UserCredentials represents user authentication credentials
type UserCredentials struct {
	Username string                 `json:"username"`
	Password string                 `json:"password,omitempty"`
	Token    string                 `json:"token,omitempty"`
	MFACode  string                 `json:"mfa_code,omitempty"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// User represents an authenticated user
type User struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email,omitempty"`
	FullName string    `json:"full_name,omitempty"`
	Roles    []string  `json:"roles"`
	Groups   []string  `json:"groups,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// UserSession represents an active user session
type UserSession struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	Token       string    `json:"token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
}

// AccessContext provides context for authorization decisions
type AccessContext struct {
	User      *User     `json:"user"`
	Session   *UserSession `json:"session,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// SystemSecurityManager defines the interface for system-level security management
type SystemSecurityManager interface {
	// User Management
	AuthenticateUser(ctx context.Context, credentials UserCredentials) (*UserSession, error)
	AuthorizeAPIAccess(ctx context.Context, user *User, resource string, action string) error
	GetUser(ctx context.Context, userID string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	CreateUser(ctx context.Context, user *User, password string) error
	UpdateUser(ctx context.Context, userID string, updates map[string]interface{}) error
	DeleteUser(ctx context.Context, userID string) error
	ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error
	
	// Session Management
	CreateSession(ctx context.Context, user *User) (*UserSession, error)
	ValidateSession(ctx context.Context, sessionToken string) (*UserSession, error)
	RefreshSession(ctx context.Context, refreshToken string) (*UserSession, error)
	RevokeSession(ctx context.Context, sessionToken string) error
	ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error)
	RevokeAllUserSessions(ctx context.Context, userID string) error
	
	// Policy Management
	AddPolicy(ctx context.Context, policy APIPolicy) error
	RemovePolicy(ctx context.Context, policyID string) error
	UpdatePolicy(ctx context.Context, policyID string, policy APIPolicy) error
	GetPolicy(ctx context.Context, policyID string) (*APIPolicy, error)
	ListPolicies(ctx context.Context) ([]APIPolicy, error)
	EvaluatePolicy(ctx context.Context, accessCtx *AccessContext) error
	
	// Configuration Management
	UpdateConfig(ctx context.Context, config SystemSecurityConfig) error
	GetConfig(ctx context.Context) (*SystemSecurityConfig, error)
	ValidateConfig(ctx context.Context, config SystemSecurityConfig) error
	
	// Health and Monitoring
	HealthCheck(ctx context.Context) error
	GetSecurityMetrics(ctx context.Context) (map[string]interface{}, error)
	GetAuditLog(ctx context.Context, filters map[string]interface{}) ([]AuditEvent, error)
}

// AuditEvent represents a security audit event
type AuditEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`      // "auth", "session", "policy", "config"
	Action    string    `json:"action"`    // "login", "logout", "create", "update", "delete"
	UserID    string    `json:"user_id,omitempty"`
	Username  string    `json:"username,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}