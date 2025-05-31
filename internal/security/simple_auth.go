package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

func init() {
	caddy.RegisterModule(SimpleAuth{})
}

// SimpleAuth is a Caddy HTTP middleware for simple bearer token authentication
type SimpleAuth struct {
	// BearerTokens is a list of valid bearer tokens (for simple token auth)
	BearerTokens []string `json:"bearer_tokens,omitempty"`

	// JWTPublicKey is the public key for JWT validation (PEM format)
	JWTPublicKey string `json:"jwt_public_key,omitempty"`

	// RequireAuth determines if authentication is required
	RequireAuth bool `json:"require_auth,omitempty"`

	// logger is set during provisioning
	logger logrus.FieldLogger
}

// CaddyModule returns the Caddy module information.
func (SimpleAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.simple_auth",
		New: func() caddy.Module { return new(SimpleAuth) },
	}
}

// Provision sets up the module.
func (s *SimpleAuth) Provision(ctx caddy.Context) error {
	s.logger = logrus.WithField("module", "simple_auth")

	// Validate configuration
	if s.RequireAuth && len(s.BearerTokens) == 0 && s.JWTPublicKey == "" {
		return fmt.Errorf("authentication required but no bearer tokens or JWT public key configured")
	}

	return nil
}

// Validate ensures the module configuration is valid.
func (s *SimpleAuth) Validate() error {
	if s.JWTPublicKey != "" {
		// Try to parse the public key to ensure it's valid
		_, err := jwt.ParseRSAPublicKeyFromPEM([]byte(s.JWTPublicKey))
		if err != nil {
			return fmt.Errorf("invalid JWT public key: %w", err)
		}
	}
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (s *SimpleAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// If auth is not required, pass through
	if !s.RequireAuth {
		return next.ServeHTTP(w, r)
	}

	// Extract authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return s.unauthorized(w, "missing authorization header")
	}

	// Check if it's a bearer token
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return s.unauthorized(w, "invalid authorization format")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)

	// Try simple bearer token validation first
	if s.isValidBearerToken(token) {
		// Add authenticated flag to request context
		ctx := context.WithValue(r.Context(), "authenticated", true)
		return next.ServeHTTP(w, r.WithContext(ctx))
	}

	// Try JWT validation if public key is configured
	if s.JWTPublicKey != "" {
		if err := s.validateJWT(token); err == nil {
			// Add authenticated flag to request context
			ctx := context.WithValue(r.Context(), "authenticated", true)
			return next.ServeHTTP(w, r.WithContext(ctx))
		}
	}

	return s.unauthorized(w, "invalid token")
}

// isValidBearerToken checks if the token is in the list of valid tokens
func (s *SimpleAuth) isValidBearerToken(token string) bool {
	for _, validToken := range s.BearerTokens {
		if token == validToken {
			return true
		}
	}
	return false
}

// validateJWT validates a JWT token using the configured public key
func (s *SimpleAuth) validateJWT(tokenString string) error {
	// Parse public key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(s.JWTPublicKey))
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token is using RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

// unauthorized writes an unauthorized response
func (s *SimpleAuth) unauthorized(w http.ResponseWriter, message string) error {
	w.Header().Set("WWW-Authenticate", `Bearer realm="TwinCore"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]string{
		"error":   "unauthorized",
		"message": message,
	}

	json.NewEncoder(w).Encode(response)
	return nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
func (s *SimpleAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "bearer_tokens":
				s.BearerTokens = d.RemainingArgs()
				if len(s.BearerTokens) == 0 {
					return d.ArgErr()
				}
			case "jwt_public_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				s.JWTPublicKey = d.Val()
			case "require_auth":
				s.RequireAuth = true
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Module                = (*SimpleAuth)(nil)
	_ caddy.Provisioner           = (*SimpleAuth)(nil)
	_ caddy.Validator             = (*SimpleAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*SimpleAuth)(nil)
	_ caddyfile.Unmarshaler       = (*SimpleAuth)(nil)
)
