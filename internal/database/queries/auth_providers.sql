-- auth_providers.sql
-- SQL queries for managing authentication provider configurations

-- name: CreateAuthProvider :exec
INSERT INTO auth_providers (
    id, type, name, enabled, priority, config, created_at, updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
);

-- name: GetAuthProvider :one
SELECT 
    id, type, name, enabled, priority, config, created_at, updated_at
FROM auth_providers 
WHERE id = ?;

-- name: ListAuthProviders :many
SELECT 
    id, type, name, enabled, priority, config, created_at, updated_at
FROM auth_providers 
ORDER BY priority ASC, created_at DESC;

-- name: ListEnabledAuthProviders :many
SELECT 
    id, type, name, enabled, priority, config, created_at, updated_at
FROM auth_providers 
WHERE enabled = true
ORDER BY priority ASC, created_at DESC;

-- name: UpdateAuthProvider :exec
UPDATE auth_providers 
SET 
    name = COALESCE(?, name),
    enabled = COALESCE(?, enabled),
    priority = COALESCE(?, priority),
    config = COALESCE(?, config),
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteAuthProvider :exec
DELETE FROM auth_providers WHERE id = ?;

-- name: AuthProviderExists :one
SELECT EXISTS(SELECT 1 FROM auth_providers WHERE id = ?) as exists;

-- name: CreateUserProviderAssociation :exec
INSERT INTO user_providers (
    user_id, provider_id, external_id, attributes, last_login
) VALUES (
    ?, ?, ?, ?, ?
) ON CONFLICT (user_id, provider_id) DO UPDATE SET
    external_id = excluded.external_id,
    attributes = excluded.attributes,
    last_login = excluded.last_login;

-- name: GetUserProviderAssociations :many
SELECT 
    user_id, provider_id, external_id, attributes, last_login
FROM user_providers
WHERE user_id = ?;

-- name: GetUserByProviderExternalID :one
SELECT 
    up.user_id, up.provider_id, up.external_id, up.attributes, up.last_login,
    lu.username, lu.email, lu.full_name, lu.roles
FROM user_providers up
JOIN local_users lu ON up.user_id = lu.id
WHERE up.provider_id = ? AND up.external_id = ?;

-- name: DeleteUserProviderAssociation :exec
DELETE FROM user_providers 
WHERE user_id = ? AND provider_id = ?;

-- name: DeleteProviderAssociations :exec
DELETE FROM user_providers WHERE provider_id = ?;

-- name: UpdateProviderMetadata :exec
INSERT INTO provider_metadata (
    provider_id, metadata, last_updated
) VALUES (
    ?, ?, CURRENT_TIMESTAMP
) ON CONFLICT (provider_id) DO UPDATE SET
    metadata = excluded.metadata,
    last_updated = CURRENT_TIMESTAMP;

-- name: GetProviderMetadata :one
SELECT 
    provider_id, metadata, last_updated
FROM provider_metadata
WHERE provider_id = ?;

-- name: DeleteProviderMetadata :exec
DELETE FROM provider_metadata WHERE provider_id = ?;