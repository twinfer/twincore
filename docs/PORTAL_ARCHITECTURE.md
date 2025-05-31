# TwinCore Portal & Management API Architecture

## Overview

TwinCore needs to expose a management interface for:
1. **Portal UI** - Web interface for administrators
2. **API Clients** - Programmatic access for automation
3. **Service Integration** - Other services accessing TwinCore

## Architecture Options

### Option 1: Unified Gateway (Recommended)

Use Caddy as the single entry point for everything:

```
Client → Caddy (Port 80/443) → Routes:
  ├─ /portal/*     → Portal UI (static files)
  ├─ /api/*        → Management API (Go handlers)
  ├─ /things/*     → WoT endpoints (dynamic from TDs)
  └─ /auth/*       → Authentication endpoints
```

**Benefits:**
- Single entry point
- Unified security
- Easy TLS/certificate management
- Leverage Caddy's features

### Option 2: Separate Management Port

Keep management API on separate port:

```
Port 80/443 (Caddy):
  ├─ /things/*     → WoT endpoints
  └─ /portal/*     → Portal redirect

Port 8090 (Go HTTP):
  ├─ /api/*        → Management API
  └─ /auth/*       → Authentication
```

**Benefits:**
- Clear separation of concerns
- Can use different security policies
- Easier to firewall/restrict access

## Proposed Implementation

### 1. Portal UI Routes

```go
// Serve static portal files via Caddy
{
  "match": [{"path": ["/portal/*"]}],
  "handle": [{
    "handler": "file_server",
    "root": "/usr/share/twincore/portal",
    "strip_prefix": "/portal"
  }]
}

// Or serve via embedded files
{
  "match": [{"path": ["/portal/*"]}],
  "handle": [{
    "handler": "reverse_proxy",
    "upstreams": [{"dial": "localhost:8091"}]  // Portal server
  }]
}
```

### 2. Management API Routes

```go
// Protect management API with authentication
{
  "match": [{"path": ["/api/*"]}],
  "handle": [
    {
      "handler": "authentication",
      "providers": {
        "jwt": {
          "token_sources": ["header:Authorization"],
          "public_key": "${JWT_PUBLIC_KEY}"
        }
      }
    },
    {
      "handler": "reverse_proxy",
      "upstreams": [{"dial": "localhost:8090"}]
    }
  ]
}
```

### 3. Authentication Flow

```yaml
# Client authentication flow
1. Client → POST /auth/login → {username, password}
2. Server → Validate → Generate JWT/Session
3. Server → Response → {token, expires}
4. Client → Use token → Authorization: Bearer {token}

# Service authentication flow  
1. Service → Use pre-shared JWT → Authorization: Bearer {jwt}
2. Server → Validate JWT → Check claims/permissions
```

### 4. Portal UI Structure

```
/portal/
  ├── index.html          # SPA entry point
  ├── assets/            
  │   ├── js/            # React/Vue/Svelte app
  │   └── css/           # Styles
  └── config.json        # Runtime configuration
```

### 5. API Endpoint Structure

```
/api/v1/
  ├── /auth/
  │   ├── POST   /login      # User login
  │   ├── POST   /logout     # Logout
  │   └── POST   /refresh    # Token refresh
  │
  ├── /things/
  │   ├── GET    /           # List all things
  │   ├── POST   /           # Register new thing
  │   ├── GET    /{id}       # Get thing details
  │   ├── PUT    /{id}       # Update thing
  │   └── DELETE /{id}       # Remove thing
  │
  ├── /streams/
  │   ├── GET    /           # List streams
  │   ├── POST   /           # Create stream
  │   ├── GET    /{id}       # Get stream info
  │   ├── PUT    /{id}       # Update stream
  │   └── DELETE /{id}       # Delete stream
  │
  ├── /config/
  │   ├── GET    /caddy      # Get Caddy config
  │   ├── GET    /benthos    # Get Benthos config
  │   └── PUT    /license    # Update license
  │
  └── /system/
      ├── GET    /health     # Health check
      ├── GET    /metrics    # Prometheus metrics
      └── GET    /info       # System information
```

## Security Configuration

### 1. Authentication Methods

```go
type PortalSecurityConfig struct {
    // Public access (no auth required)
    PublicPaths []string `json:"public_paths"`
    
    // Authentication providers
    Auth AuthConfig `json:"auth"`
    
    // Authorization rules
    Authorization AuthzConfig `json:"authorization"`
}

type AuthConfig struct {
    // Local user database
    LocalUsers bool `json:"local_users"`
    
    // JWT validation
    JWT *JWTConfig `json:"jwt,omitempty"`
    
    // OAuth2/OIDC
    OAuth2 *OAuth2Config `json:"oauth2,omitempty"`
    
    // API Keys
    APIKeys []string `json:"api_keys,omitempty"`
}
```

### 2. Caddy Integration

```go
// Add portal routes to Caddy configuration
func (h *HTTPServiceV2) addPortalRoutes(routes []interface{}) []interface{} {
    // Portal UI
    routes = append(routes, map[string]interface{}{
        "match": []map[string]interface{}{
            {"path": []string{"/portal/*"}},
        },
        "handle": []map[string]interface{}{
            {
                "handler": "file_server",
                "root": "/usr/share/twincore/portal",
                "strip_prefix": "/portal",
            },
        },
    })
    
    // API with auth
    routes = append(routes, map[string]interface{}{
        "match": []map[string]interface{}{
            {"path": []string{"/api/*"}},
        },
        "handle": []map[string]interface{}{
            // Auth middleware
            {
                "handler": "subroute",
                "routes": h.buildAuthRoutes(),
            },
            // Reverse proxy to API server
            {
                "handler": "reverse_proxy",
                "upstreams": []map[string]interface{}{
                    {"dial": "localhost:8090"},
                },
            },
        },
    })
    
    return routes
}
```

### 3. User Management

```sql
-- Enhanced user table for portal access
CREATE TABLE portal_users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    roles TEXT NOT NULL, -- JSON array of roles
    permissions TEXT,    -- JSON object of permissions
    api_key TEXT UNIQUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    disabled BOOLEAN DEFAULT FALSE
);

-- Session management
CREATE TABLE user_sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES portal_users(id),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);
```

## Implementation Steps

### Phase 1: Basic Portal

1. Create static portal UI files
2. Configure Caddy to serve portal
3. Add basic authentication to API
4. Implement login endpoint

### Phase 2: Full Management API

1. Implement all CRUD endpoints
2. Add role-based access control
3. Integrate with existing services
4. Add audit logging

### Phase 3: Advanced Features

1. Real-time updates via WebSocket
2. Multi-tenant support
3. API key management
4. Metrics and monitoring dashboard

## Example Usage

### Portal Access
```bash
# Access portal UI
curl https://twincore.local/portal/

# Login
curl -X POST https://twincore.local/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secure123"}'

# Use API with token
curl https://twincore.local/api/v1/things \
  -H "Authorization: Bearer ${TOKEN}"
```

### Service Integration
```go
// Service client configuration
client := &TwinCoreClient{
    BaseURL: "https://twincore.local",
    APIKey:  "service-key-123",
    // or
    JWT:     serviceJWT,
}

// List things
things, err := client.ListThings()
```

## Security Considerations

1. **Portal UI Security**:
   - Content Security Policy headers
   - XSS protection
   - CSRF tokens for forms

2. **API Security**:
   - Rate limiting per user/IP
   - Request size limits
   - Audit logging

3. **Authentication**:
   - Password complexity requirements
   - Account lockout after failed attempts
   - Token expiration and refresh

4. **Authorization**:
   - Role-based access (admin, operator, viewer)
   - Resource-level permissions
   - API scope limitations

## Conclusion

The unified gateway approach using Caddy provides the best balance of:
- Security (single point for TLS, auth)
- Simplicity (one configuration)
- Flexibility (can add routes dynamically)
- Performance (Caddy is efficient)

This architecture allows TwinCore to expose a professional management interface while maintaining security and flexibility for different client types.