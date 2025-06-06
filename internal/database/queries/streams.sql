-- Stream Management Queries

-- name: CreateStreamsTable
CREATE TABLE IF NOT EXISTS stream_configs (
    stream_id TEXT PRIMARY KEY,
    thing_id TEXT NOT NULL,
    interaction_type TEXT NOT NULL,
    interaction_name TEXT NOT NULL,
    direction TEXT NOT NULL,
    input_config TEXT NOT NULL,
    output_config TEXT NOT NULL,
    processor_chain TEXT,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT,
    config_yaml TEXT,
    validation_error TEXT
);

-- name: CreateStreamsIndexes
CREATE INDEX IF NOT EXISTS idx_streams_thing_id ON stream_configs(thing_id);
CREATE INDEX IF NOT EXISTS idx_streams_status ON stream_configs(status);
CREATE INDEX IF NOT EXISTS idx_streams_interaction ON stream_configs(interaction_type, interaction_name);
CREATE INDEX IF NOT EXISTS idx_streams_updated ON stream_configs(updated_at);

-- name: CreatePropertyStateTable
CREATE TABLE IF NOT EXISTS property_state (
    thing_id TEXT NOT NULL,
    property_name TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (thing_id, property_name)
);

-- name: CreateActionStateTable
CREATE TABLE IF NOT EXISTS action_state (
    action_id TEXT PRIMARY KEY,
    thing_id TEXT NOT NULL,
    action_name TEXT NOT NULL,
    input TEXT,
    output TEXT,
    status TEXT DEFAULT 'pending',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT
);

-- name: CreateStateIndexes
CREATE INDEX IF NOT EXISTS idx_property_thing ON property_state(thing_id);
CREATE INDEX IF NOT EXISTS idx_property_updated ON property_state(updated_at);
CREATE INDEX IF NOT EXISTS idx_action_thing ON action_state(thing_id);
CREATE INDEX IF NOT EXISTS idx_action_status ON action_state(status);
CREATE INDEX IF NOT EXISTS idx_action_started ON action_state(started_at);

-- Stream Configuration Queries
-- name: InsertStreamConfig
INSERT INTO stream_configs (stream_id, thing_id, interaction_type, interaction_name, direction, input_config, output_config, processor_chain, status, created_at, updated_at, metadata, config_yaml, validation_error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?, ?);

-- name: GetStreamConfig
SELECT stream_id, thing_id, interaction_type, interaction_name, direction, input_config, output_config, processor_chain, status, created_at, updated_at, metadata, config_yaml, validation_error
FROM stream_configs
WHERE stream_id = ?;

-- name: UpdateStreamConfig
UPDATE stream_configs
SET thing_id = ?, interaction_type = ?, interaction_name = ?, direction = ?, input_config = ?, output_config = ?, processor_chain = ?, status = ?, updated_at = CURRENT_TIMESTAMP, metadata = ?, config_yaml = ?, validation_error = ?
WHERE stream_id = ?;

-- name: UpdateStreamStatus
UPDATE stream_configs
SET status = ?, updated_at = CURRENT_TIMESTAMP
WHERE stream_id = ?;

-- name: DeleteStreamConfig
UPDATE stream_configs
SET status = 'deleted', updated_at = CURRENT_TIMESTAMP
WHERE stream_id = ?;

-- name: HardDeleteStreamConfig
DELETE FROM stream_configs WHERE stream_id = ?;

-- name: ListActiveStreams
SELECT stream_id, thing_id, interaction_type, interaction_name, direction, input_config, output_config, processor_chain, status, created_at, updated_at, metadata, config_yaml, validation_error
FROM stream_configs
WHERE status != 'deleted'
ORDER BY created_at DESC;

-- name: ListStreamsByThing
SELECT stream_id, thing_id, interaction_type, interaction_name, direction, input_config, output_config, processor_chain, status, created_at, updated_at, metadata, config_yaml, validation_error
FROM stream_configs
WHERE thing_id = ? AND status != 'deleted'
ORDER BY created_at DESC;

-- name: ListStreamsByStatus
SELECT stream_id, thing_id, interaction_type, interaction_name, direction, input_config, output_config, processor_chain, status, created_at, updated_at, metadata, config_yaml, validation_error
FROM stream_configs
WHERE status = ?
ORDER BY created_at DESC;

-- name: CountActiveStreams
SELECT COUNT(*) FROM stream_configs WHERE status != 'deleted';

-- name: StreamExists
SELECT EXISTS(SELECT 1 FROM stream_configs WHERE stream_id = ? AND status != 'deleted');

-- name: UpdateValidationError
UPDATE stream_configs 
SET validation_error = ?, updated_at = CURRENT_TIMESTAMP
WHERE stream_id = ?;

-- name: LoadAllActiveStreams
SELECT stream_id, thing_id, interaction_type, interaction_name, direction,
       input_config, output_config, processor_chain, status,
       created_at, updated_at, metadata
FROM stream_configs
WHERE status != 'deleted';

-- Property State Queries
-- name: UpsertPropertyState
INSERT OR REPLACE INTO property_state (thing_id, property_name, value, updated_at)
VALUES (?, ?, ?, now());

-- name: GetPropertyState
SELECT thing_id, property_name, value, updated_at
FROM property_state
WHERE thing_id = ? AND property_name = ?;

-- name: GetThingProperties
SELECT property_name, value, updated_at
FROM property_state
WHERE thing_id = ?
ORDER BY property_name;

-- name: GetAllPropertyStates
SELECT thing_id, property_name, value, updated_at
FROM property_state
ORDER BY thing_id, property_name;

-- name: DeletePropertyState
DELETE FROM property_state
WHERE thing_id = ? AND property_name = ?;

-- name: DeleteThingProperties
DELETE FROM property_state WHERE thing_id = ?;

-- name: GetPropertyValue
SELECT value FROM property_state
WHERE thing_id = ? AND property_name = ?;

-- Action State Queries
-- name: InsertActionState
INSERT INTO action_state (action_id, thing_id, action_name, input, output, status, started_at, completed_at, error)
VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?);

-- name: GetActionState
SELECT action_id, thing_id, action_name, input, output, status, started_at, completed_at, error
FROM action_state
WHERE action_id = ?;

-- name: UpdateActionState
UPDATE action_state
SET output = ?, status = ?, completed_at = ?, error = ?
WHERE action_id = ?;

-- name: ListActionsByThing
SELECT action_id, thing_id, action_name, input, output, status, started_at, completed_at, error
FROM action_state
WHERE thing_id = ?
ORDER BY started_at DESC;

-- name: ListActionsByStatus
SELECT action_id, thing_id, action_name, input, output, status, started_at, completed_at, error
FROM action_state
WHERE status = ?
ORDER BY started_at DESC;

-- name: DeleteActionState
DELETE FROM action_state WHERE action_id = ?;

-- name: DeleteCompletedActions
DELETE FROM action_state 
WHERE status IN ('completed', 'failed') AND completed_at < ?;

-- Cleanup Queries
-- name: CleanupOldPropertyStates
DELETE FROM property_state WHERE updated_at < ?;

-- name: CleanupDeletedStreams
DELETE FROM stream_configs WHERE status = 'deleted' AND updated_at < ?;