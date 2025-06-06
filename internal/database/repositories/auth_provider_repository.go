package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/pkg/types"
)

// AuthProviderRepository handles database operations for auth providers
type AuthProviderRepository struct {
	db     database.DBInterface
	logger *logrus.Logger
}

// NewAuthProviderRepository creates a new auth provider repository
func NewAuthProviderRepository(db database.DBInterface, logger *logrus.Logger) database.AuthProviderRepository {
	return &AuthProviderRepository{
		db:     db,
		logger: logger,
	}
}

// CreateProvider creates a new auth provider
func (r *AuthProviderRepository) CreateProvider(ctx context.Context, provider *types.AuthProvider) error {
	configJSON, err := json.Marshal(provider.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	query := `
		INSERT INTO auth_providers (
			id, type, name, enabled, priority, config, created_at, updated_at
		) VALUES (
			?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
		)`

	_, err = r.db.ExecContext(ctx, query,
		provider.ID,
		provider.Type,
		provider.Name,
		provider.Enabled,
		provider.Priority,
		string(configJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to create auth provider: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"provider_id":   provider.ID,
		"provider_type": provider.Type,
	}).Info("Auth provider created")

	return nil
}

// GetProvider retrieves an auth provider by ID
func (r *AuthProviderRepository) GetProvider(ctx context.Context, id string) (*types.AuthProvider, error) {
	query := `
		SELECT 
			id, type, name, enabled, priority, config, created_at, updated_at
		FROM auth_providers 
		WHERE id = ?`

	var provider types.AuthProvider
	var configJSON string
	var createdAt, updatedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&provider.ID,
		&provider.Type,
		&provider.Name,
		&provider.Enabled,
		&provider.Priority,
		&configJSON,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("auth provider not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get auth provider: %w", err)
	}

	// Parse config JSON
	if err := json.Unmarshal([]byte(configJSON), &provider.Config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if createdAt.Valid {
		provider.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		provider.UpdatedAt = updatedAt.Time
	}

	return &provider, nil
}

// ListProviders retrieves all auth providers
func (r *AuthProviderRepository) ListProviders(ctx context.Context) ([]*types.AuthProvider, error) {
	query := `
		SELECT 
			id, type, name, enabled, priority, config, created_at, updated_at
		FROM auth_providers 
		ORDER BY priority ASC, created_at DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list auth providers: %w", err)
	}
	defer rows.Close()

	var providers []*types.AuthProvider
	for rows.Next() {
		var provider types.AuthProvider
		var configJSON string
		var createdAt, updatedAt sql.NullTime

		err := rows.Scan(
			&provider.ID,
			&provider.Type,
			&provider.Name,
			&provider.Enabled,
			&provider.Priority,
			&configJSON,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan auth provider: %w", err)
		}

		// Parse config JSON
		if err := json.Unmarshal([]byte(configJSON), &provider.Config); err != nil {
			r.logger.WithError(err).WithField("provider_id", provider.ID).Error("Failed to unmarshal config")
			continue
		}

		if createdAt.Valid {
			provider.CreatedAt = createdAt.Time
		}
		if updatedAt.Valid {
			provider.UpdatedAt = updatedAt.Time
		}

		providers = append(providers, &provider)
	}

	return providers, nil
}

// UpdateProvider updates an existing auth provider
func (r *AuthProviderRepository) UpdateProvider(ctx context.Context, id string, updates map[string]any) error {
	// Build dynamic update query
	setClauses := []string{"updated_at = CURRENT_TIMESTAMP"}
	args := []any{}

	if name, ok := updates["name"].(string); ok {
		setClauses = append(setClauses, "name = ?")
		args = append(args, name)
	}

	if enabled, ok := updates["enabled"].(bool); ok {
		setClauses = append(setClauses, "enabled = ?")
		args = append(args, enabled)
	}

	if priority, ok := updates["priority"].(int); ok {
		setClauses = append(setClauses, "priority = ?")
		args = append(args, priority)
	}

	if config, ok := updates["config"].(map[string]any); ok {
		configJSON, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		setClauses = append(setClauses, "config = ?")
		args = append(args, string(configJSON))
	}

	// Add ID as last argument
	args = append(args, id)

	query := fmt.Sprintf(`
		UPDATE auth_providers 
		SET %s
		WHERE id = ?`,
		joinStrings(setClauses, ", "),
	)

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update auth provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("auth provider not found: %s", id)
	}

	r.logger.WithFields(logrus.Fields{
		"provider_id": id,
		"updates":     len(updates),
	}).Info("Auth provider updated")

	return nil
}

// DeleteProvider deletes an auth provider
func (r *AuthProviderRepository) DeleteProvider(ctx context.Context, id string) error {
	// First delete associated data
	if err := r.deleteProviderAssociations(ctx, id); err != nil {
		return err
	}

	query := `DELETE FROM auth_providers WHERE id = ?`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete auth provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("auth provider not found: %s", id)
	}

	r.logger.WithField("provider_id", id).Info("Auth provider deleted")
	return nil
}

// AssociateUserWithProvider creates or updates a user-provider association
func (r *AuthProviderRepository) AssociateUserWithProvider(ctx context.Context, userID, providerID, externalID string, attributes map[string]any) error {
	attributesJSON, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	query := `
		INSERT INTO user_providers (
			user_id, provider_id, external_id, attributes, last_login
		) VALUES (
			?, ?, ?, ?, ?
		) ON CONFLICT (user_id, provider_id) DO UPDATE SET
			external_id = excluded.external_id,
			attributes = excluded.attributes,
			last_login = excluded.last_login`

	_, err = r.db.ExecContext(ctx, query,
		userID,
		providerID,
		externalID,
		string(attributesJSON),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to associate user with provider: %w", err)
	}

	return nil
}

// GetUserProviderAssociations retrieves all provider associations for a user
func (r *AuthProviderRepository) GetUserProviderAssociations(ctx context.Context, userID string) ([]*types.UserProviderAssociation, error) {
	query := `
		SELECT 
			user_id, provider_id, external_id, attributes, last_login
		FROM user_providers
		WHERE user_id = ?`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user provider associations: %w", err)
	}
	defer rows.Close()

	var associations []*types.UserProviderAssociation
	for rows.Next() {
		var assoc types.UserProviderAssociation
		var attributesJSON string
		var lastLogin sql.NullTime

		err := rows.Scan(
			&assoc.UserID,
			&assoc.ProviderID,
			&assoc.ExternalID,
			&attributesJSON,
			&lastLogin,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan association: %w", err)
		}

		// Parse attributes JSON
		if attributesJSON != "" {
			if err := json.Unmarshal([]byte(attributesJSON), &assoc.Attributes); err != nil {
				r.logger.WithError(err).Error("Failed to unmarshal attributes")
			}
		}

		if lastLogin.Valid {
			assoc.LastLogin = &lastLogin.Time
		}

		associations = append(associations, &assoc)
	}

	return associations, nil
}

// UpdateProviderMetadata updates provider metadata
func (r *AuthProviderRepository) UpdateProviderMetadata(ctx context.Context, providerID string, metadata map[string]any) error {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO provider_metadata (
			provider_id, metadata, last_updated
		) VALUES (
			?, ?, CURRENT_TIMESTAMP
		) ON CONFLICT (provider_id) DO UPDATE SET
			metadata = excluded.metadata,
			last_updated = CURRENT_TIMESTAMP`

	_, err = r.db.ExecContext(ctx, query, providerID, string(metadataJSON))
	if err != nil {
		return fmt.Errorf("failed to update provider metadata: %w", err)
	}

	return nil
}

// deleteProviderAssociations deletes all associations for a provider
func (r *AuthProviderRepository) deleteProviderAssociations(ctx context.Context, providerID string) error {
	// Delete user associations
	if _, err := r.db.ExecContext(ctx, "DELETE FROM user_providers WHERE provider_id = ?", providerID); err != nil {
		return fmt.Errorf("failed to delete user associations: %w", err)
	}

	// Delete metadata
	if _, err := r.db.ExecContext(ctx, "DELETE FROM provider_metadata WHERE provider_id = ?", providerID); err != nil {
		return fmt.Errorf("failed to delete provider metadata: %w", err)
	}

	return nil
}

// IsHealthy checks if the repository is healthy
func (r *AuthProviderRepository) IsHealthy(ctx context.Context) bool {
	// Simple health check - try to execute a basic query
	var result int
	err := r.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	return err == nil
}

// Helper function to join strings
func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
