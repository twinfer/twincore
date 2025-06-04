# TwinCore Authentication API Plan using caddy-security

## Overview

TwinCore will leverage the caddy-security extension instead of implementing custom authentication. caddy-security provides a complete authentication system with built-in endpoints, user management, and middleware.

## ✅ Current Foundation

TwinCore already has:
- `CaddySecurityBridge` - Integration layer with caddy-security  
- `SystemSecurityManager` - User management and synchronization
- Authentication portal configuration
- Local user store with JSON file backend
- Authorization policies and RBAC

## 🎯 caddy-security Provided Endpoints

When properly configured, caddy-security automatically creates these endpoints:

### Authentication Endpoints
```
GET  /auth/login                 # Login form UI
POST /auth/login                 # Login form submission  
GET  /auth/logout                # Logout and redirect
GET  /auth/whoami                # Current user info (JSON)
POST /auth/refresh               # Token refresh (if JWT enabled)
```

### API Endpoints (with API config enabled)
```
GET  /auth/api/v1/whoami         # Current user info (JSON API)
POST /auth/api/v1/refresh        # Token refresh (JSON API)
GET  /auth/api/v1/users          # List users (admin only)
POST /auth/api/v1/users          # Create user (admin only)
PUT  /auth/api/v1/users/{id}     # Update user (admin only)
DELETE /auth/api/v1/users/{id}   # Delete user (admin only)
```

### Admin Portal Endpoints  
```
GET  /auth/portal                # Admin portal UI
GET  /auth/portal/users          # User management UI
GET  /auth/portal/settings       # Settings UI
POST /auth/portal/settings       # Update settings
```

## 🔧 Implementation Plan

### Phase 1: Enhanced caddy-security Configuration ✅

**Completed:**
- Enhanced authentication portal configuration with API endpoints
- Added JWT token configuration for API access
- Added user registry configuration
- Added UI customization with TwinCore branding
- Configured auto-redirect to TwinCore portal

**Configuration Features:**
```json
{
  "api": {
    "endpoint": "/auth/api/v1",
    "enabled": true
  },
  "token": {
    "jwt": {
      "token_name": "access_token",
      "token_issuer": "twincore",
      "token_audience": ["twincore-api"],
      "token_lifetime": 3600
    }
  },
  "ui": {
    "auto_redirect_url": "/portal",
    "links": [
      {"title": "TwinCore Portal", "link": "/portal"},
      {"title": "API Documentation", "link": "/docs"}
    ]
  }
}
```

### Phase 2: Route Configuration Updates

**Next Steps:**
1. **Update default routes** to include authentication middleware
2. **Configure protected API paths** - `/api/*` routes require authentication
3. **Add authentication routes** - Map `/auth/*` to caddy-security portal
4. **Configure public routes** - Allow `/portal/*`, `/setup/*`, `/health` without auth

### Phase 3: API Integration

**Integration Points:**
1. **JWT Token Validation** - Middleware to validate caddy-security JWT tokens
2. **User Context Injection** - Extract user info from JWT claims
3. **Role-Based Access** - Map caddy-security roles to TwinCore permissions
4. **Session Management** - Bridge caddy-security sessions with TwinCore state

### Phase 4: Portal Enhancement

**Portal Integration:**
1. **Update Portal Routes** - Point login/logout to caddy-security endpoints
2. **User Management UI** - Integrate caddy-security user management
3. **Authentication Status** - Show user status from caddy-security
4. **API Token Management** - Allow users to manage API tokens

## 📋 Required Configuration Changes

### 1. Update HTTP Routes Configuration

```go
// Add authentication routes
routes := []types.HTTPRoute{
    {
        Path:         "/auth/*",
        Handler:      "authentication_portal",
        RequiresAuth: false, // Portal handles its own auth
    },
    {
        Path:         "/api/*", 
        Handler:      "unified_wot_handler",
        RequiresAuth: true,  // Protect all API routes
        Config: map[string]interface{}{
            "auth_portal": "twincore_portal",
            "auth_policy": "twincore_policy",
        },
    },
    {
        Path:         "/portal/*",
        Handler:      "file_server", 
        RequiresAuth: false, // Portal handles auth via JavaScript
    },
}
```

### 2. Update Container Configuration

```go
// In container.go
func (c *Container) initializeHTTPService(cfg *types.Config) error {
    // Configure security bridge
    securityConfig := &types.SystemSecurityConfig{
        Enabled: true,
        AdminAuth: &types.AdminAuthConfig{
            Method: "local",
            Local: &types.LocalAuthConfig{
                Users: []types.LocalUser{
                    {
                        Username: "admin",
                        Password: "admin", // Hashed by SystemSecurityManager
                        Roles:    []string{"admin"},
                    },
                },
            },
        },
        APIAuth: &types.APIAuthConfig{
            Methods: []string{"bearer"},
            Policies: []types.APIPolicy{
                {
                    Principal: "role:admin",
                    Resources: ["/api/*"],
                    Actions:   ["read", "write"],
                },
            },
        },
    }
    
    // Create security bridge
    securityBridge := security.NewCaddySecurityBridge(
        c.SystemSecurityManager,
        securityConfig,
        c.Logger,
    )
    
    // Configure HTTP service with security
    c.HTTPService.SetSecurityBridge(securityBridge)
}
```

### 3. Update Portal JavaScript

```javascript
// In portal JavaScript
class AuthService {
    async login(username, password) {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: `username=${username}&password=${password}`
        });
        
        if (response.redirected && response.url.includes('/portal')) {
            window.location.href = '/portal';
        }
    }
    
    async getCurrentUser() {
        const response = await fetch('/auth/api/v1/whoami');
        return response.json();
    }
    
    async logout() {
        await fetch('/auth/logout');
        window.location.href = '/auth/login';
    }
}
```

## 🔐 Security Features

### JWT Token Support
- **Token Name**: `access_token`
- **Issuer**: `twincore`
- **Audience**: `["twincore-api"]`
- **Lifetime**: 1 hour (configurable)
- **Auto-refresh**: Available via `/auth/api/v1/refresh`

### Role-Based Access Control
- **Admin Role**: Full access to all APIs and user management
- **User Role**: Limited access to device interactions
- **Guest Role**: Read-only access to public APIs

### Authentication Methods
- **Local**: JSON file-based user store (current)
- **LDAP**: Enterprise directory integration (future)
- **SAML**: SSO integration (future)
- **OAuth2**: Social login (future)

## 📊 API Response Examples

### Current User Info
```json
GET /auth/api/v1/whoami
{
  "username": "admin",
  "email": "admin@twincore.local",
  "roles": ["admin"],
  "exp": 1672531200,
  "iat": 1672527600
}
```

### Token Refresh
```json
POST /auth/api/v1/refresh
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

## 🚀 Benefits of caddy-security Integration

1. **No Custom Code** - Leverage battle-tested authentication system
2. **Standard Compliance** - OAuth2, JWT, SAML standards support
3. **Security Features** - CSRF protection, secure cookies, session management
4. **Extensibility** - Easy to add LDAP, SAML, OAuth2 providers
5. **Admin UI** - Built-in user management interface
6. **API Support** - RESTful endpoints for programmatic access
7. **Middleware Integration** - Seamless Caddy v2 integration

## 📅 Implementation Timeline

- **Week 1**: Phase 2 - Route configuration updates
- **Week 2**: Phase 3 - API integration and JWT validation  
- **Week 3**: Phase 4 - Portal enhancement and testing
- **Week 4**: Documentation and deployment guides

## 🔍 Testing Strategy

1. **Unit Tests** - Test configuration generation and validation
2. **Integration Tests** - Test authentication flow end-to-end
3. **API Tests** - Test protected endpoints with JWT tokens
4. **UI Tests** - Test portal authentication integration
5. **Security Tests** - Test authorization policies and access control

This plan leverages caddy-security's robust authentication system while maintaining TwinCore's architectural principles and providing a seamless user experience.