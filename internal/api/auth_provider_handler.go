package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/pkg/types"
)

// AuthProviderHandler handles authentication provider management operations
type AuthProviderHandler struct {
	securityManager types.SystemSecurityManager
	configManager   ConfigurationManager
	logger          *logrus.Logger
}

// NewAuthProviderHandler creates a new auth provider handler
func NewAuthProviderHandler(
	securityManager types.SystemSecurityManager,
	configManager ConfigurationManager,
	logger *logrus.Logger,
) *AuthProviderHandler {
	return &AuthProviderHandler{
		securityManager: securityManager,
		configManager:   configManager,
		logger:          logger,
	}
}

// handleAuthProviderRoutes handles /api/admin/auth/providers/* routes
func (h *AuthProviderHandler) handleAuthProviderRoutes(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, path string) error {
	logger.Debug("Routing auth provider management request")

	// Remove /providers prefix
	path = strings.TrimPrefix(path, "/providers")

	switch {
	case path == "" && r.Method == http.MethodGet:
		return h.listProviders(logger, w, r)
	case path == "" && r.Method == http.MethodPost:
		return h.createProvider(logger, w, r)
	case strings.HasPrefix(path, "/") && len(path) > 1:
		// Extract provider ID
		providerID := strings.TrimPrefix(path, "/")
		parts := strings.Split(providerID, "/")
		providerID = parts[0]

		if len(parts) == 1 {
			// Direct provider operations: /providers/{id}
			switch r.Method {
			case http.MethodGet:
				return h.getProvider(logger, w, r, providerID)
			case http.MethodPut:
				return h.updateProvider(logger, w, r, providerID)
			case http.MethodDelete:
				return h.deleteProvider(logger, w, r, providerID)
			default:
				return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			}
		} else if len(parts) == 2 {
			switch parts[1] {
			case "test":
				// Test provider connection: /providers/{id}/test
				if r.Method == http.MethodPost {
					return h.testProvider(logger, w, r, providerID)
				}
				return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			case "users":
				// List users from provider: /providers/{id}/users
				if r.Method == http.MethodGet {
					return h.listProviderUsers(logger, w, r, providerID)
				}
				return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			}
		}
	}

	return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown auth provider endpoint"))
}

// @Summary List all authentication providers
// @Description Retrieve all configured authentication providers
// @Tags Auth Providers
// @Produce json
// @Success 200 {object} types.AuthProviderListResponse
// @Failure 403 {object} types.ErrorResponse "Insufficient permissions"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /admin/auth/providers [get]
func (h *AuthProviderHandler) listProviders(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	providers, err := h.securityManager.ListAuthProviders(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to list auth providers")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	response := types.NewAuthProviderListResponse(providers)

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Create authentication provider
// @Description Create a new authentication provider configuration
// @Tags Auth Providers
// @Accept json
// @Produce json
// @Param provider body types.CreateAuthProviderRequest true "Provider configuration"
// @Success 201 {object} types.AuthProviderResponse
// @Failure 400 {object} types.ErrorResponse "Invalid request"
// @Failure 409 {object} types.ErrorResponse "Provider already exists"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /admin/auth/providers [post]
func (h *AuthProviderHandler) createProvider(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	defer r.Body.Close()

	var createReq types.CreateAuthProviderRequest
	if err := json.Unmarshal(body, &createReq); err != nil {
		logger.WithError(err).Error("Failed to parse request body")
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	// Validate request
	if err := createReq.Validate(); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Create provider
	provider := &types.AuthProvider{
		ID:       createReq.ID,
		Type:     createReq.Type,
		Name:     createReq.Name,
		Enabled:  createReq.Enabled,
		Priority: createReq.Priority,
		Config:   createReq.Config,
	}

	if err := h.securityManager.AddAuthProvider(ctx, provider); err != nil {
		logger.WithError(err).WithField("provider_id", createReq.ID).Error("Failed to create auth provider")
		if strings.Contains(err.Error(), "already exists") {
			return caddyhttp.Error(http.StatusConflict, err)
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Refresh auth configuration
	if err := h.securityManager.RefreshAuthConfiguration(ctx); err != nil {
		logger.WithError(err).Error("Failed to refresh auth configuration")
		// Don't fail the request, but log the error
	}

	response := types.NewAuthProviderResponse(provider)
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Get authentication provider
// @Description Retrieve a specific authentication provider by ID
// @Tags Auth Providers
// @Produce json
// @Param id path string true "Provider ID"
// @Success 200 {object} types.AuthProviderResponse
// @Failure 404 {object} types.ErrorResponse "Provider not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /admin/auth/providers/{id} [get]
func (h *AuthProviderHandler) getProvider(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, providerID string) error {
	ctx := r.Context()

	provider, err := h.securityManager.GetAuthProvider(ctx, providerID)
	if err != nil {
		logger.WithError(err).WithField("provider_id", providerID).Error("Failed to get auth provider")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	response := types.NewAuthProviderResponse(provider)
	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Update authentication provider
// @Description Update an existing authentication provider configuration
// @Tags Auth Providers
// @Accept json
// @Produce json
// @Param id path string true "Provider ID"
// @Param provider body types.UpdateAuthProviderRequest true "Updated provider configuration"
// @Success 200 {object} types.AuthProviderResponse
// @Failure 400 {object} types.ErrorResponse "Invalid request"
// @Failure 404 {object} types.ErrorResponse "Provider not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /admin/auth/providers/{id} [put]
func (h *AuthProviderHandler) updateProvider(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, providerID string) error {
	ctx := r.Context()

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	defer r.Body.Close()

	var updateReq types.UpdateAuthProviderRequest
	if err := json.Unmarshal(body, &updateReq); err != nil {
		logger.WithError(err).Error("Failed to parse request body")
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	// Convert to update map
	updates := make(map[string]any)
	if updateReq.Name != nil {
		updates["name"] = *updateReq.Name
	}
	if updateReq.Enabled != nil {
		updates["enabled"] = *updateReq.Enabled
	}
	if updateReq.Priority != nil {
		updates["priority"] = *updateReq.Priority
	}
	if updateReq.Config != nil {
		updates["config"] = updateReq.Config
	}

	// Update provider
	if err := h.securityManager.UpdateAuthProvider(ctx, providerID, updates); err != nil {
		logger.WithError(err).WithField("provider_id", providerID).Error("Failed to update auth provider")
		if strings.Contains(err.Error(), "not found") {
			return caddyhttp.Error(http.StatusNotFound, err)
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Refresh auth configuration
	if err := h.securityManager.RefreshAuthConfiguration(ctx); err != nil {
		logger.WithError(err).Error("Failed to refresh auth configuration")
		// Don't fail the request, but log the error
	}

	// Get updated provider
	provider, err := h.securityManager.GetAuthProvider(ctx, providerID)
	if err != nil {
		logger.WithError(err).WithField("provider_id", providerID).Error("Failed to retrieve updated provider")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	response := types.NewAuthProviderResponse(provider)
	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Delete authentication provider
// @Description Delete an authentication provider configuration
// @Tags Auth Providers
// @Param id path string true "Provider ID"
// @Success 204 "No Content"
// @Failure 404 {object} types.ErrorResponse "Provider not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /admin/auth/providers/{id} [delete]
func (h *AuthProviderHandler) deleteProvider(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, providerID string) error {
	ctx := r.Context()

	// Check if provider exists
	_, err := h.securityManager.GetAuthProvider(ctx, providerID)
	if err != nil {
		logger.WithError(err).WithField("provider_id", providerID).Debug("Provider not found for deletion")
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("provider not found"))
	}

	// Delete provider
	if err := h.securityManager.RemoveAuthProvider(ctx, providerID); err != nil {
		logger.WithError(err).WithField("provider_id", providerID).Error("Failed to delete auth provider")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Refresh auth configuration
	if err := h.securityManager.RefreshAuthConfiguration(ctx); err != nil {
		logger.WithError(err).Error("Failed to refresh auth configuration after deletion")
		// Don't fail the request, but log the error
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// @Summary Test authentication provider
// @Description Test connection and configuration for an authentication provider
// @Tags Auth Providers
// @Produce json
// @Param id path string true "Provider ID"
// @Success 200 {object} types.AuthProviderTestResult
// @Failure 404 {object} types.ErrorResponse "Provider not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /admin/auth/providers/{id}/test [post]
func (h *AuthProviderHandler) testProvider(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, providerID string) error {
	ctx := r.Context()

	result, err := h.securityManager.TestAuthProvider(ctx, providerID)
	if err != nil {
		logger.WithError(err).WithField("provider_id", providerID).Error("Failed to test auth provider")
		if strings.Contains(err.Error(), "not found") {
			return caddyhttp.Error(http.StatusNotFound, err)
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(result)
}

// @Summary List users from authentication provider
// @Description Retrieve users from an external authentication provider (if supported)
// @Tags Auth Providers
// @Produce json
// @Param id path string true "Provider ID"
// @Param search query string false "Search query"
// @Param limit query int false "Maximum number of users to return"
// @Success 200 {object} types.ProviderUserListResponse
// @Failure 404 {object} types.ErrorResponse "Provider not found"
// @Failure 501 {object} types.ErrorResponse "Provider does not support user listing"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /admin/auth/providers/{id}/users [get]
func (h *AuthProviderHandler) listProviderUsers(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, providerID string) error {
	ctx := r.Context()

	// Get search parameters
	search := r.URL.Query().Get("search")
	limitStr := r.URL.Query().Get("limit")
	limit := 100 // default
	if limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
	}

	users, err := h.securityManager.ListProviderUsers(ctx, providerID, search, limit)
	if err != nil {
		logger.WithError(err).WithField("provider_id", providerID).Error("Failed to list provider users")
		if strings.Contains(err.Error(), "not found") {
			return caddyhttp.Error(http.StatusNotFound, err)
		}
		if strings.Contains(err.Error(), "not supported") {
			return caddyhttp.Error(http.StatusNotImplemented, err)
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	response := types.NewProviderUserListResponse(users)
	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(response)
}
