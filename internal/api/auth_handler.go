package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/pkg/types"
)

// AuthHandler handles authentication-related operations
// Note: Actual authentication is handled by caddy-security middleware
// This handler provides information about the current authentication state
type AuthHandler struct {
	logger *logrus.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		logger: logger,
	}
}

// handleAuthRoutes handles /api/auth/* routes
func (h *AuthHandler) handleAuthRoutes(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, path string) error {
	logger.Debug("Routing authentication request")

	// Remove /auth prefix
	path = path[5:] // Remove "/auth"

	switch path {
	case "/status":
		if r.Method == http.MethodGet {
			return h.getAuthStatus(logger, w, r)
		}
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	case "/profile":
		if r.Method == http.MethodGet {
			return h.getUserProfile(logger, w, r)
		}
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	default:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("authentication endpoint not found"))
	}
}

// @Summary Get authentication status
// @Description Get current authentication status and user information
// @Tags Auth
// @Produce json
// @Success 200 {object} types.AuthStatusResponse
// @Failure 401 {object} types.ErrorResponse "Not authenticated"
// @Security BearerAuth
// @Router /auth/status [get]
func (h *AuthHandler) getAuthStatus(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	// Extract user information from request context (set by caddy-security middleware)
	user := h.extractUserFromContext(r.Context())
	
	if user == nil {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	}

	status := &types.AuthStatusResponse{
		Authenticated: true,
		User:          *user,
		TokenType:     "Bearer",
		// Note: Token expiry and other details would be handled by caddy-security
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(status)
}

// @Summary Get user profile
// @Description Get current authenticated user's profile information
// @Tags Auth
// @Produce json
// @Success 200 {object} types.UserResponse
// @Failure 401 {object} types.ErrorResponse "Not authenticated"
// @Security BearerAuth
// @Router /auth/profile [get]
func (h *AuthHandler) getUserProfile(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	// Extract user information from request context (set by caddy-security middleware)
	user := h.extractUserFromContext(r.Context())
	
	if user == nil {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("not authenticated"))
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(user)
}

// extractUserFromContext extracts user information from the request context
// This assumes caddy-security middleware has populated the context with user details
func (h *AuthHandler) extractUserFromContext(ctx context.Context) *types.UserResponse {
	// TODO: Implement actual user extraction from caddy-security context
	// This is a placeholder implementation
	// 
	// caddy-security typically sets user information in the context or headers
	// We need to extract it according to how caddy-security provides it
	//
	// Common patterns:
	// 1. User info in JWT claims (already validated by caddy-security)
	// 2. User info in request headers set by caddy-security
	// 3. User info in context values set by caddy-security middleware
	
	// For now, return nil to indicate user extraction is not implemented
	// This should be implemented based on how caddy-security exposes user info
	return nil
}

