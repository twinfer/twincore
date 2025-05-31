# Security Migration Guide

## Overview

This guide explains how to migrate from the complex go-authcrunch/caddy-security implementation to a simpler, Caddy-native approach.

## Problems with go-authcrunch

1. **Compilation Errors**: Version conflicts causing build failures
2. **Excessive Dependencies**: 50+ transitive dependencies
3. **Unused Features**: SAML, OAuth2, LDAP, MFA not needed
4. **Complexity**: Database-backed user stores for simple auth
5. **Maintenance**: Replace directive forcing old version

## New Approach

### 1. Use Caddy Admin API

Instead of programmatically building Caddy modules:
```go
// Old approach
security.AuthnMiddleware{
    PortalName: "default",
}

// New approach - Configure via Admin API
{
    "handler": "authentication",
    "providers": {
        "http_basic": {
            "accounts": {...}
        }
    }
}
```

### 2. Simplified Security Configuration

```go
// Old - Complex SecurityConfig with go-authcrunch types
type SecurityConfig struct {
    AuthenticationPortals    []*authn.PortalConfig
    IdentityStores          []*authn.IdentityStoreConfig
    TokenValidators         []*authn.TokenValidatorConfig
    AuthorizationGatekeepers []*authz.Config
}

// New - Simple configuration
type SimpleSecurityConfig struct {
    Enabled    bool
    BasicAuth  *BasicAuthConfig
    BearerAuth *BearerAuthConfig
    JWTAuth    *JWTAuthConfig
}
```

### 3. Bearer Token Authentication

For API endpoints requiring bearer tokens:

```json
{
    "match": [{
        "header": {
            "Authorization": ["Bearer *"]
        }
    }],
    "handle": [{
        "handler": "subroute",
        "routes": [...]
    }]
}
```

### 4. JWT Validation

Leverage existing JWT license validator:
```go
// internal/security/jwt_license_validator.go
validator := NewJWTLicenseValidator(publicKey)
license, err := validator.ValidateToken(token)
```

## Migration Steps

### Step 1: Update go.mod

Remove:
```
github.com/greenpau/caddy-security v1.1.31
github.com/greenpau/go-authcrunch v1.1.7
replace github.com/greenpau/go-authcrunch => github.com/greenpau/go-authcrunch v1.0.50
```

Keep:
```
github.com/golang-jwt/jwt/v4 v4.5.2  # For JWT validation
```

### Step 2: Update HTTP Service

Replace `http-service.go` with `http-service-v2.go` that uses:
- Caddy Admin API for all configuration
- Native Caddy handlers
- Simple security checks

### Step 3: Update Container

In `internal/container/container.go`:
```go
// Old
httpService := service.NewHTTPService(c.logger, c.db)

// New
httpService := service.NewHTTPServiceV2(c.logger)
```

### Step 4: Update Configuration

Example configuration:
```json
{
    "http": {
        "listen": [":8080"],
        "routes": [{
            "path": "/api/*",
            "requires_auth": true,
            "handler": "reverse_proxy",
            "config": {
                "upstream": "localhost:8090"
            }
        }],
        "security": {
            "enabled": true,
            "bearer_auth": {
                "tokens": ["${API_TOKEN}"]
            },
            "jwt_auth": {
                "public_key": "${JWT_PUBLIC_KEY}"
            }
        }
    }
}
```

## Benefits

1. **Simpler Code**: ~90% less security-related code
2. **Fewer Dependencies**: Remove 50+ transitive dependencies
3. **Better Performance**: Less overhead
4. **Easier Maintenance**: Standard Caddy configuration
5. **Flexible**: Use Caddy Admin API for dynamic updates

## Testing

Test the new implementation:

```bash
# Basic auth
curl -u user:pass http://localhost:8080/api/test

# Bearer token
curl -H "Authorization: Bearer ${TOKEN}" http://localhost:8080/api/test

# JWT
curl -H "Authorization: Bearer ${JWT_TOKEN}" http://localhost:8080/api/test
```

## Advanced Features

If you need more advanced authentication later:

1. **OAuth2**: Use Caddy's `forward_auth` to delegate to an OAuth2 proxy
2. **mTLS**: Configure via Caddy's TLS settings
3. **Custom Auth**: Write a simple Caddy module or use `forward_auth`

## Summary

The migration simplifies security by:
- Using Caddy's built-in features
- Removing unnecessary complexity
- Focusing on actual requirements (bearer tokens, JWT)
- Leveraging the Admin API for dynamic configuration

This approach is more maintainable, has fewer dependencies, and aligns better with TwinCore's actual security needs.