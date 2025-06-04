# Comprehensive TwinCore Authentication Implementation Plan

## 🎯 Project Overview

Implement a complete authentication system for TwinCore using caddy-security as the core authentication engine, with custom Go templates for the UI, seamless API integration, and role-based access control.

## 📋 Current State Analysis

### ✅ What We Have
- `CaddySecurityBridge` - Basic caddy-security integration
- `SystemSecurityManager` - User management interface
- Local user store with JSON backend
- Basic authentication portal configuration
- Authorization policies framework
- Container-based dependency injection

### ❌ What's Missing
- Complete caddy-security configuration
- Custom authentication portal templates
- Protected API routes with middleware
- Frontend authentication integration
- User management UI
- API documentation for authentication endpoints

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         TwinCore Gateway                        │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (Portal)           │  Authentication Layer            │
│  ┌─────────────────────────┐  │  ┌─────────────────────────────┐ │
│  │ Custom Login Templates  │◄─┤  │     caddy-security          │ │
│  │ User Management UI      │  │  │ ┌─────────────────────────┐ │ │
│  │ Dashboard & Navigation  │  │  │ │ Authentication Portal   │ │ │
│  └─────────────────────────┘  │  │ │ - Login/Logout          │ │ │
│                               │  │ │ - User Management       │ │ │
│  API Layer                    │  │ │ - JWT Token Management  │ │ │
│  ┌─────────────────────────┐  │  │ └─────────────────────────┘ │ │
│  │ WoT Runtime APIs        │◄─┤  │ ┌─────────────────────────┐ │ │
│  │ Admin Management APIs   │  │  │ │ Authorization Policies  │ │ │
│  │ Stream Management APIs  │  │  │ │ - Role-based Access     │ │ │
│  └─────────────────────────┘  │  │ │ - Resource Protection   │ │ │
│                               │  │ └─────────────────────────┘ │ │
│  Backend Services             │  │ ┌─────────────────────────┐ │ │
│  ┌─────────────────────────┐  │  │ │ User Store              │ │ │
│  │ SystemSecurityManager   │◄─┤  │ │ - Local JSON Store      │ │ │
│  │ ThingRegistry           │  │  │ │ - User Synchronization  │ │ │
│  │ StreamManager           │  │  │ │ - Password Management   │ │ │
│  └─────────────────────────┘  │  │ └─────────────────────────┘ │ │
│                               │  └─────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 📅 Implementation Phases

### Phase 1: caddy-security Core Configuration (Week 1)

#### 1.1 Complete Authentication Portal Setup
```go
// Enhanced portal configuration
{
  "cookie": {
    "domain": "",
    "path": "/",
    "lifetime": 86400,
    "secure": true,
    "httponly": true,
    "samesite": "lax"
  },
  "token": {
    "jwt": {
      "token_name": "twincore_token",
      "token_secret": "generate-secure-secret",
      "token_issuer": "twincore-gateway",
      "token_audience": ["twincore-api", "twincore-portal"],
      "token_lifetime": 3600,
      "token_claims": {
        "roles": "roles",
        "groups": "groups", 
        "email": "email"
      }
    }
  },
  "api": {
    "endpoint": "/auth/api/v1",
    "enabled": true,
    "middleware": ["auth", "cors", "ratelimit"]
  }
}
```

#### 1.2 User Store Configuration
```go
// Local user store with enhanced features
{
  "type": "local",
  "path": "./data/users.json",
  "config": {
    "password_policy": {
      "min_length": 8,
      "require_uppercase": true,
      "require_lowercase": true, 
      "require_numbers": true,
      "require_symbols": false,
      "max_age_days": 90
    },
    "lockout_policy": {
      "enabled": true,
      "max_attempts": 5,
      "lockout_duration": 300,
      "reset_duration": 3600
    }
  }
}
```

#### 1.3 Authorization Policies
```go
// RBAC policies for different user roles
{
  "default_action": "deny",
  "roles": {
    "admin": {
      "description": "Full system access",
      "permissions": ["*"]
    },
    "operator": {
      "description": "Device and stream management", 
      "permissions": ["wot:*", "streams:*", "dashboard:read"]
    },
    "viewer": {
      "description": "Read-only access",
      "permissions": ["wot:read", "streams:read", "dashboard:read"]
    }
  },
  "rules": [
    {
      "action": "allow",
      "conditions": {"roles": ["admin"]},
      "resources": ["/api/*", "/admin/*"],
      "methods": ["*"]
    },
    {
      "action": "allow", 
      "conditions": {"roles": ["operator"]},
      "resources": ["/api/things/*", "/api/streams/*"],
      "methods": ["GET", "POST", "PUT"]
    },
    {
      "action": "allow",
      "conditions": {"roles": ["viewer"]}, 
      "resources": ["/api/things/*", "/api/streams/*"],
      "methods": ["GET"]
    }
  ]
}
```

### Phase 2: Custom Authentication Templates (Week 1-2)

#### 2.1 Directory Structure
```
internal/security/templates/
├── base.html              # Base template with TwinCore branding
├── login.html             # Custom login form
├── portal.html            # User management portal
├── settings.html          # User settings page
├── error.html             # Error pages
└── static/
    ├── auth.css           # Authentication styles
    ├── auth.js            # Authentication JavaScript
    └── assets/
        ├── logo.png       # TwinCore logo
        └── favicon.ico    # TwinCore favicon
```

#### 2.2 Base Template (`base.html`)
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - TwinCore Gateway</title>
    <link rel="stylesheet" href="/auth/static/auth.css">
    <link rel="icon" href="/auth/static/assets/favicon.ico">
</head>
<body class="twincore-auth">
    <div class="auth-container">
        <div class="auth-header">
            <img src="/auth/static/assets/logo.png" alt="TwinCore" class="logo">
            <h1>TwinCore Gateway</h1>
            <p class="subtitle">Web of Things Runtime</p>
        </div>
        
        <main class="auth-content">
            {{template "content" .}}
        </main>
        
        <footer class="auth-footer">
            <p>&copy; 2025 TwinCore Gateway. Powered by Web of Things.</p>
        </footer>
    </div>
    
    <script src="/auth/static/auth.js"></script>
</body>
</html>
```

#### 2.3 Login Template (`login.html`)
```html
{{define "content"}}
<div class="login-form">
    <h2>Sign In</h2>
    
    {{if .Message}}
    <div class="alert alert-{{.MessageType}}">
        {{.Message}}
    </div>
    {{end}}
    
    <form method="POST" action="/auth/login">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required
                   value="{{.Username}}" autocomplete="username">
        </div>
        
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required
                   autocomplete="current-password">
        </div>
        
        <div class="form-group">
            <label class="checkbox">
                <input type="checkbox" name="remember" value="1">
                Remember me for 30 days
            </label>
        </div>
        
        <button type="submit" class="btn btn-primary">Sign In</button>
        
        <input type="hidden" name="redirect_url" value="{{.RedirectURL}}">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    </form>
    
    <div class="auth-links">
        <a href="/auth/forgot-password">Forgot Password?</a>
        {{if .AllowRegistration}}
        <a href="/auth/register">Create Account</a>
        {{end}}
    </div>
    
    <div class="auth-info">
        <h3>Portal Access</h3>
        <p>Access the TwinCore management portal to:</p>
        <ul>
            <li>Manage IoT devices and Thing Descriptions</li>
            <li>Configure data processing streams</li>
            <li>Monitor system health and metrics</li>
            <li>Administer users and permissions</li>
        </ul>
    </div>
</div>
{{end}}
```

#### 2.4 Portal Template (`portal.html`)
```html
{{define "content"}}
<div class="admin-portal">
    <div class="portal-header">
        <h2>Welcome, {{.User.Name}}</h2>
        <div class="user-info">
            <span class="user-role">{{.User.Role}}</span>
            <a href="/auth/logout" class="btn btn-secondary">Logout</a>
        </div>
    </div>
    
    <nav class="portal-nav">
        <a href="/portal" class="nav-link">
            <i class="icon-dashboard"></i> Dashboard
        </a>
        <a href="/auth/portal/users" class="nav-link">
            <i class="icon-users"></i> User Management
        </a>
        <a href="/auth/portal/settings" class="nav-link">
            <i class="icon-settings"></i> Settings
        </a>
        <a href="/docs" class="nav-link">
            <i class="icon-docs"></i> API Documentation
        </a>
    </nav>
    
    <div class="portal-content">
        {{if eq .Section "users"}}
            {{template "users" .}}
        {{else if eq .Section "settings"}}
            {{template "settings" .}}
        {{else}}
            {{template "dashboard" .}}
        {{end}}
    </div>
</div>
{{end}}
```

### Phase 3: Route Protection & Middleware (Week 2)

#### 3.1 Protected Route Configuration
```go
// Update HTTP route configuration
func (c *Container) configureProtectedRoutes() []types.HTTPRoute {
    return []types.HTTPRoute{
        // Authentication routes (public)
        {
            Path:         "/auth/*",
            Handler:      "security.authentication_portal",
            RequiresAuth: false,
            Config: map[string]interface{}{
                "portal_name": "twincore_portal",
                "templates_path": "./internal/security/templates",
                "static_path": "./internal/security/templates/static",
            },
        },
        
        // API routes (protected)
        {
            Path:         "/api/v1/things/*",
            Handler:      "unified_wot_handler", 
            RequiresAuth: true,
            Config: map[string]interface{}{
                "auth_policy": "wot_access",
                "required_roles": []string{"operator", "admin"},
            },
        },
        {
            Path:         "/api/v1/streams/*",
            Handler:      "unified_wot_handler",
            RequiresAuth: true, 
            Config: map[string]interface{}{
                "auth_policy": "stream_access",
                "required_roles": []string{"operator", "admin"},
            },
        },
        {
            Path:         "/api/v1/admin/*",
            Handler:      "unified_wot_handler",
            RequiresAuth: true,
            Config: map[string]interface{}{
                "auth_policy": "admin_access", 
                "required_roles": []string{"admin"},
            },
        },
        
        // Portal routes (public with client-side auth)
        {
            Path:         "/portal/*",
            Handler:      "file_server",
            RequiresAuth: false,
            Config: map[string]interface{}{
                "root": "./portal/dist",
                "index_files": []string{"index.html"},
            },
        },
        
        // Health and public routes
        {
            Path:         "/health",
            Handler:      "static_response",
            RequiresAuth: false,
            Config: map[string]interface{}{
                "body": `{"status":"ok","service":"twincore"}`,
                "status_code": 200,
            },
        },
    }
}
```

#### 3.2 JWT Validation Middleware
```go
// JWT validation middleware for API endpoints
type JWTValidationMiddleware struct {
    securityBridge *security.CaddySecurityBridge
    logger         logrus.FieldLogger
}

func (m *JWTValidationMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    // Extract JWT token from Authorization header
    token := extractBearerToken(r)
    if token == "" {
        return writeAuthError(w, "missing_token", "Authorization token required")
    }
    
    // Validate token via caddy-security
    claims, err := m.securityBridge.ValidateJWTToken(token)
    if err != nil {
        return writeAuthError(w, "invalid_token", "Invalid or expired token")
    }
    
    // Add user context to request
    ctx := context.WithValue(r.Context(), "user_claims", claims)
    ctx = context.WithValue(ctx, "user_id", claims.Subject)
    ctx = context.WithValue(ctx, "user_roles", claims.Roles)
    
    return next.ServeHTTP(w, r.WithContext(ctx))
}
```

### Phase 4: Frontend Integration (Week 2-3)

#### 4.1 Portal Authentication Service
```javascript
// Portal authentication service
class TwinCoreAuthService {
    constructor() {
        this.baseURL = '/auth/api/v1';
        this.token = localStorage.getItem('twincore_token');
    }
    
    async login(username, password) {
        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    username,
                    password,
                    redirect_url: '/portal'
                })
            });
            
            if (response.redirected) {
                window.location.href = response.url;
                return true;
            }
            
            throw new Error('Login failed');
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }
    
    async getCurrentUser() {
        const response = await this.fetch('/whoami');
        return response.json();
    }
    
    async refreshToken() {
        const response = await this.fetch('/refresh', {method: 'POST'});
        const data = await response.json();
        this.token = data.access_token;
        localStorage.setItem('twincore_token', this.token);
        return data;
    }
    
    async logout() {
        try {
            await fetch('/auth/logout', {method: 'POST'});
        } finally {
            localStorage.removeItem('twincore_token');
            window.location.href = '/auth/login';
        }
    }
    
    async fetch(url, options = {}) {
        const headers = {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        const response = await fetch(this.baseURL + url, {
            ...options,
            headers
        });
        
        if (response.status === 401) {
            this.logout();
            throw new Error('Authentication required');
        }
        
        return response;
    }
    
    isAuthenticated() {
        return !!this.token;
    }
}
```

#### 4.2 Portal Route Guards
```javascript
// Vue.js route guards for portal
const authService = new TwinCoreAuthService();

const router = new VueRouter({
    routes: [
        {
            path: '/login',
            component: LoginComponent,
            meta: { requiresAuth: false }
        },
        {
            path: '/dashboard',
            component: DashboardComponent,
            meta: { requiresAuth: true, roles: ['admin', 'operator', 'viewer'] }
        },
        {
            path: '/things',
            component: ThingsComponent,
            meta: { requiresAuth: true, roles: ['admin', 'operator'] }
        },
        {
            path: '/admin',
            component: AdminComponent,
            meta: { requiresAuth: true, roles: ['admin'] }
        }
    ]
});

// Navigation guard
router.beforeEach(async (to, from, next) => {
    const requiresAuth = to.matched.some(record => record.meta.requiresAuth);
    
    if (requiresAuth && !authService.isAuthenticated()) {
        next('/auth/login');
        return;
    }
    
    if (requiresAuth) {
        try {
            const user = await authService.getCurrentUser();
            const requiredRoles = to.meta.roles || [];
            
            if (requiredRoles.length > 0 && !user.roles.some(role => requiredRoles.includes(role))) {
                next('/dashboard');
                return;
            }
        } catch (error) {
            next('/auth/login');
            return;
        }
    }
    
    next();
});
```

### Phase 5: User Management API (Week 3)

#### 5.1 User Management Endpoints
```go
// User management API endpoints (admin only)
type UserManagementHandler struct {
    securityManager types.SystemSecurityManager
    logger          logrus.FieldLogger
}

// Routes:
// GET    /auth/api/v1/users           - List all users
// POST   /auth/api/v1/users           - Create user
// GET    /auth/api/v1/users/{id}      - Get user details  
// PUT    /auth/api/v1/users/{id}      - Update user
// DELETE /auth/api/v1/users/{id}      - Delete user
// POST   /auth/api/v1/users/{id}/password - Reset password
// POST   /auth/api/v1/users/{id}/roles    - Update user roles
```

#### 5.2 User Management UI Components
```javascript
// Vue.js user management components
const UserManagementComponent = {
    data() {
        return {
            users: [],
            selectedUser: null,
            showCreateDialog: false,
            showEditDialog: false
        };
    },
    
    async mounted() {
        await this.loadUsers();
    },
    
    methods: {
        async loadUsers() {
            const response = await authService.fetch('/users');
            this.users = await response.json();
        },
        
        async createUser(userData) {
            await authService.fetch('/users', {
                method: 'POST',
                body: JSON.stringify(userData)
            });
            await this.loadUsers();
        },
        
        async updateUser(userId, userData) {
            await authService.fetch(`/users/${userId}`, {
                method: 'PUT', 
                body: JSON.stringify(userData)
            });
            await this.loadUsers();
        },
        
        async deleteUser(userId) {
            if (confirm('Are you sure you want to delete this user?')) {
                await authService.fetch(`/users/${userId}`, {
                    method: 'DELETE'
                });
                await this.loadUsers();
            }
        }
    }
};
```

### Phase 6: Testing & Documentation (Week 4)

#### 6.1 Authentication Flow Tests
```go
// Integration tests for authentication flow
func TestAuthenticationFlow(t *testing.T) {
    // Test login flow
    t.Run("Login with valid credentials", func(t *testing.T) {
        response := testLogin("admin", "password")
        assert.Equal(t, 302, response.StatusCode)
        assert.Contains(t, response.Header.Get("Location"), "/portal")
    })
    
    // Test JWT validation
    t.Run("API access with valid JWT", func(t *testing.T) {
        token := getAuthToken("admin", "password")
        response := testAPICall("/api/v1/things", token)
        assert.Equal(t, 200, response.StatusCode)
    })
    
    // Test role-based access
    t.Run("Admin-only endpoint access", func(t *testing.T) {
        userToken := getAuthToken("user", "password")
        adminToken := getAuthToken("admin", "password")
        
        // User should be denied
        response := testAPICall("/api/v1/admin/users", userToken)
        assert.Equal(t, 403, response.StatusCode)
        
        // Admin should be allowed
        response = testAPICall("/api/v1/admin/users", adminToken)
        assert.Equal(t, 200, response.StatusCode)
    })
}
```

#### 6.2 API Documentation
```yaml
# OpenAPI specification for authentication endpoints
openapi: 3.0.3
info:
  title: TwinCore Authentication API
  version: 1.0.0
  description: Authentication and user management API

paths:
  /auth/login:
    post:
      summary: User login
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                username:
                  type: string
                password:
                  type: string
                redirect_url:
                  type: string
      responses:
        302:
          description: Successful login, redirect to portal
        401:
          description: Invalid credentials
  
  /auth/api/v1/whoami:
    get:
      summary: Get current user info
      security:
        - bearerAuth: []
      responses:
        200:
          description: Current user information
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        401:
          description: Authentication required

components:
  schemas:
    User:
      type: object
      properties:
        username:
          type: string
        email:
          type: string
        roles:
          type: array
          items:
            type: string
        groups:
          type: array
          items:
            type: string
  
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

## 🚀 Deployment Considerations

### Environment Configuration
```bash
# Environment variables for production
TWINCORE_AUTH_ENABLED=true
TWINCORE_JWT_SECRET=secure-random-secret
TWINCORE_SESSION_DOMAIN=twincore.example.com
TWINCORE_SESSION_SECURE=true
TWINCORE_AUTH_TEMPLATES_PATH=/opt/twincore/templates
TWINCORE_USERS_STORE_PATH=/opt/twincore/data/users.json
```

### Security Checklist
- [ ] HTTPS enforcement in production
- [ ] Secure JWT secret generation and storage
- [ ] CSRF protection enabled
- [ ] Rate limiting on authentication endpoints  
- [ ] Password policy enforcement
- [ ] Account lockout protection
- [ ] Audit logging for authentication events
- [ ] Regular security updates and monitoring

## 📊 Success Metrics

1. **Security**
   - Zero authentication bypass vulnerabilities
   - Proper JWT token validation
   - RBAC policy enforcement

2. **User Experience**
   - < 2 second login response time
   - Seamless portal integration
   - Intuitive user management interface

3. **API Integration**
   - 100% API endpoint protection coverage
   - Proper error handling and status codes
   - Comprehensive API documentation

4. **Maintainability**
   - Clean separation of concerns
   - Comprehensive test coverage (>90%)
   - Clear configuration management

This comprehensive plan ensures a secure, scalable, and maintainable authentication system that leverages caddy-security's capabilities while providing a seamless TwinCore experience.