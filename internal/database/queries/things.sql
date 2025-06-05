-- Things (Thing Descriptions) Management Queries

-- name: CreateThingsTable
CREATE TABLE IF NOT EXISTS things (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    td_jsonld TEXT NOT NULL,
    td_parsed TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- name: CreateThingsIndexes
CREATE INDEX IF NOT EXISTS idx_things_updated ON things(updated_at);
CREATE INDEX IF NOT EXISTS idx_things_title ON things(title);

-- name: InsertThing
INSERT INTO things (id, title, description, td_jsonld, td_parsed, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- name: GetThingByID
SELECT id, title, description, td_jsonld, td_parsed, created_at, updated_at
FROM things
WHERE id = ?;

-- name: GetThingParsedByID
SELECT td_parsed FROM things WHERE id = ?;

-- name: UpdateThing
UPDATE things
SET title = ?, description = ?, td_jsonld = ?, td_parsed = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteThing
DELETE FROM things WHERE id = ?;

-- name: ListAllThings
SELECT id, title, description, td_jsonld, td_parsed, created_at, updated_at
FROM things
ORDER BY updated_at DESC;

-- name: ListThingsParsed
SELECT td_parsed FROM things ORDER BY updated_at DESC;

-- name: CountThings
SELECT COUNT(*) FROM things;

-- name: ThingExists
SELECT EXISTS(SELECT 1 FROM things WHERE id = ?);

-- name: GetThingsByTitle
SELECT id, title, description, td_jsonld, td_parsed, created_at, updated_at
FROM things
WHERE title LIKE ?
ORDER BY updated_at DESC;