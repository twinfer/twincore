# TwinCore Security Separation Plan

## Current Problem

TwinCore currently mixes two fundamentally different security domains:
1. **System Security** - User authentication to TwinCore APIs
2. **WoT Security** - Thing authentication to physical devices

This mixing causes configuration confusion, inappropriate access controls, and architectural complexity.

## Proposed Security Architecture

### 1. System Security Domain

**Purpose**: Controls access to TwinCore's management APIs and web interface.

#### Components to Create:

```go
// pkg/types/system_security.go
type SystemSecurityConfig struct {
    Enabled       bool                     `json:"enabled"`
    AdminAuth     *AdminAuthConfig         `json:"admin_auth,omitempty"`
    APIAuth       *APIAuthConfig           `json:"api_auth,omitempty"`
    SessionConfig *SessionConfig           `json:"session_config,omitempty"`
}

type AdminAuthConfig struct {
    Method    string   `json:"method"`    // "local", "ldap", "saml", "oidc"
    Providers []string `json:"providers"` // Multiple auth providers
    MFA       bool     `json:"mfa"`       // Multi-factor authentication
}

type APIAuthConfig struct {
    Methods    []string `json:"methods"`    // ["bearer", "jwt", "apikey"]
    JWTConfig  *JWTConfig `json:"jwt_config,omitempty"`
    Policies   []APIPolicy `json:"policies"` // RBAC policies
}

type APIPolicy struct {
    Principal string   `json:"principal"` // user, group, role
    Resources []string `json:"resources"` // API endpoints
    Actions   []string `json:"actions"`   // read, write, delete
}
```

#### System Security Manager:

```go
// internal/security/system_security_manager.go
type SystemSecurityManager interface {
    // User Management
    AuthenticateUser(ctx context.Context, credentials UserCredentials) (*UserSession, error)
    AuthorizeAPIAccess(ctx context.Context, user *User, resource string, action string) error
    
    // Session Management
    CreateSession(user *User) (*UserSession, error)
    ValidateSession(sessionToken string) (*UserSession, error)
    RevokeSession(sessionToken string) error
    
    // Policy Management
    AddPolicy(policy APIPolicy) error
    RemovePolicy(policyID string) error
    ListPolicies() ([]APIPolicy, error)
}
```

### 2. WoT Security Domain

**Purpose**: Manages Thing-to-Device authentication and authorization.

#### Components to Create:

```go
// pkg/types/wot_security.go
type WoTSecurityConfig struct {
    ThingPolicies      map[string]ThingSecurityPolicy `json:"thing_policies"`
    CredentialStores   map[string]CredentialStore     `json:"credential_stores"`
    SecurityTemplates  map[string]SecurityTemplate    `json:"security_templates"`
}

type ThingSecurityPolicy struct {
    ThingID           string                      `json:"thing_id"`
    RequiredSchemes   []string                    `json:"required_schemes"`
    CredentialMapping map[string]CredentialRef    `json:"credential_mapping"`
    AccessControl     *ThingAccessControl         `json:"access_control,omitempty"`
}

type CredentialStore struct {
    Type     string                 `json:"type"`     // "env", "vault", "db", "file"
    Config   map[string]interface{} `json:"config"`
    Encrypted bool                  `json:"encrypted"`
}

type ThingAccessControl struct {
    AllowedOperations []string `json:"allowed_operations"` // ["readProperty", "writeProperty", "invokeAction"]
    IPWhitelist       []string `json:"ip_whitelist,omitempty"`
    TimeRestrictions  []string `json:"time_restrictions,omitempty"`
}
```

#### WoT Security Manager:

```go
// internal/security/wot_security_manager.go
type WoTSecurityManager interface {
    // Thing Security Management
    GetThingCredentials(thingID string, protocolType string) (*DeviceCredentials, error)
    SetThingCredentials(thingID string, credentials *DeviceCredentials) error
    ValidateThingAccess(thingID string, operation string, context *AccessContext) error
    
    // Security Scheme Processing
    ProcessSecuritySchemes(td *wot.ThingDescription) (*WoTSecurityConfig, error)
    GenerateProtocolAuth(schemes []wot.SecurityScheme, protocol string) (*ProtocolAuthConfig, error)
    
    // Credential Store Management
    RegisterCredentialStore(name string, store CredentialStore) error
    GetCredentials(storeRef CredentialRef) (*DeviceCredentials, error)
}
```

### 3. License Security Domain

**Purpose**: Controls which security features are available in each domain.

#### Separated License Features:

```go
// pkg/types/license_security.go
type LicenseSecurityFeatures struct {
    SystemSecurity SystemSecurityFeatures `json:"system_security"`
    WoTSecurity    WoTSecurityFeatures    `json:"wot_security"`
    General        GeneralSecurityFeatures `json:"general"`
}

type SystemSecurityFeatures struct {
    AuthMethods     []string `json:"auth_methods"`     // ["local", "ldap", "saml", "oidc"]
    SessionMgmt     bool     `json:"session_mgmt"`     // Session management
    RBAC           bool     `json:"rbac"`             // Role-based access control
    MFA            bool     `json:"mfa"`              // Multi-factor authentication
    AuditLogging   bool     `json:"audit_logging"`    // Security audit logs
}

type WoTSecurityFeatures struct {
    SecuritySchemes []string `json:"security_schemes"` // ["basic", "bearer", "oauth2", "psk"]
    CredentialStores []string `json:"credential_stores"` // ["vault", "env", "db"]
    AccessControl   bool     `json:"access_control"`    // Thing-level access control
    Encryption      bool     `json:"encryption"`        // Protocol encryption
}

type GeneralSecurityFeatures struct {
    TLSRequired     bool `json:"tls_required"`     // Force TLS for all connections
    SecurityHeaders bool `json:"security_headers"` // HTTP security headers
    RateLimit       bool `json:"rate_limit"`       // Rate limiting
}
```

### 4. Protocol Security Domain

**Purpose**: Handles transport-level security for each protocol binding.

#### Components to Create:

```go
// pkg/wot/forms/protocol_security.go
type ProtocolSecurityManager interface {
    // Protocol-specific auth generation
    GenerateHTTPAuth(schemes []wot.SecurityScheme, credentials *DeviceCredentials) (*HTTPAuthConfig, error)
    GenerateMQTTAuth(schemes []wot.SecurityScheme, credentials *DeviceCredentials) (*MQTTAuthConfig, error)
    GenerateKafkaAuth(schemes []wot.SecurityScheme, credentials *DeviceCredentials) (*KafkaAuthConfig, error)
    
    // Transport security
    ConfigureTLS(protocol string, config *TLSConfig) error
    ValidateProtocolSecurity(protocol string, config map[string]interface{}) error
}

type HTTPAuthConfig struct {
    Headers     map[string]string `json:"headers"`
    BasicAuth   *HTTPBasicAuth    `json:"basic_auth,omitempty"`
    BearerToken *string           `json:"bearer_token,omitempty"`
    OAuth2      *HTTPOAuth2Config `json:"oauth2,omitempty"`
}

type MQTTAuthConfig struct {
    Username    string            `json:"username,omitempty"`
    Password    string            `json:"password,omitempty"`
    ClientCert  *TLSCertConfig    `json:"client_cert,omitempty"`
    TLS         *TLSConfig        `json:"tls,omitempty"`
}
```

## Implementation Phases

### Phase 1: Create Separated Interfaces (Week 1)

1. **Create new security domain packages**:
   - `pkg/types/system_security.go`
   - `pkg/types/wot_security.go` 
   - `pkg/types/license_security.go`

2. **Create security managers**:
   - `internal/security/system_security_manager.go`
   - `internal/security/wot_security_manager.go`
   - `pkg/wot/forms/protocol_security_manager.go`

3. **Update license interface**:
   - `pkg/license/unified_license_checker.go` - Single interface for all license features

### Phase 2: Migrate System Security (Week 2)

1. **Replace `SimpleSecurityConfig`** with `SystemSecurityConfig`
2. **Update HTTP authentication middleware** to use `SystemSecurityManager`
3. **Migrate configuration management** to separate system vs WoT concerns
4. **Update default configurations** to separate domains

### Phase 3: Migrate WoT Security (Week 3)

1. **Update WoT form generation** to use `WoTSecurityManager`
2. **Create credential store implementations** (env, vault, db)
3. **Update protocol forms** to use `ProtocolSecurityManager`
4. **Remove WoT→System security mapping** from `wot_mapper.go`

### Phase 4: License Integration (Week 4)

1. **Update license validation** to use separated features
2. **Update default config provider** to respect separated license features
3. **Add license feature gates** to security managers
4. **Create license feature testing**

### Phase 5: Testing & Documentation (Week 5)

1. **Create comprehensive security tests** for each domain
2. **Update developer documentation** with security architecture
3. **Create security configuration examples**
4. **Performance testing** of separated architecture

## Migration Strategy

### Backward Compatibility

- Keep existing `SimpleSecurityConfig` as deprecated wrapper
- Provide migration utilities for existing configurations
- Add feature flags to enable new security architecture gradually

### Configuration Migration

```go
// internal/config/security_migrator.go
type SecurityMigrator struct{}

func (m *SecurityMigrator) MigrateSystemSecurity(old types.SimpleSecurityConfig) (*SystemSecurityConfig, error) {
    // Convert old system security config to new format
}

func (m *SecurityMigrator) ExtractWoTSecurity(td *wot.ThingDescription) (*WoTSecurityConfig, error) {
    // Extract WoT security from Thing Description
    // No longer mix with system security
}
```

### Environment Variable Separation

**Current (Mixed)**:
```bash
TWINEDGE_BASIC_USER=admin          # Used for both system and WoT
TWINEDGE_BEARER_TOKEN=xyz123       # Used for both system and WoT
```

**Proposed (Separated)**:
```bash
# System Security
TWINCORE_ADMIN_USER=admin
TWINCORE_ADMIN_PASSWORD=secret
TWINCORE_JWT_SECRET=jwt_secret

# WoT Device Credentials
DEVICE_BASIC_USER=device_user
DEVICE_BASIC_PASSWORD=device_pass
DEVICE_BEARER_TOKEN=device_token_xyz
```

## Benefits of Separation

1. **Clear Security Boundaries**: System admins vs. device credentials are clearly separated
2. **Granular License Control**: Different license tiers can enable different security features per domain
3. **Better Security**: No accidental credential leakage between domains
4. **Easier Configuration**: Clear configuration structure for each security concern
5. **Protocol Independence**: WoT security is protocol-agnostic
6. **Audit Trail**: Better security logging and audit capabilities
7. **Compliance**: Easier to meet compliance requirements with clear security domains

## Risk Mitigation

1. **Gradual Migration**: Implement alongside existing system with feature flags
2. **Comprehensive Testing**: Security changes require extensive testing
3. **Documentation**: Clear migration guide for existing deployments
4. **Fallback Options**: Ability to revert to current implementation if needed
5. **Security Review**: External security review of new architecture