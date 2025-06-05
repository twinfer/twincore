package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/database"
)

// DatabaseManager interface to avoid import cycle
type DatabaseManager interface {
	Execute(ctx context.Context, queryName string, args ...any) (sql.Result, error)
	Query(ctx context.Context, queryName string, args ...any) (*sql.Rows, error)
	QueryRow(ctx context.Context, queryName string, args ...any) *sql.Row
}

// ThingRepository provides data access operations for Thing Descriptions
type ThingRepository struct {
	manager DatabaseManager
	logger  *logrus.Logger
}

// NewThingRepository creates a new Thing repository
func NewThingRepository(manager DatabaseManager, logger *logrus.Logger) *ThingRepository {
	return &ThingRepository{
		manager: manager,
		logger:  logger,
	}
}

// Create inserts a new Thing Description
func (tr *ThingRepository) Create(ctx context.Context, thing *database.ThingEntity) error {
	_, err := tr.manager.Execute(ctx, "InsertThing",
		thing.ID, thing.Title, thing.Description, thing.TDJSONLD, thing.TDParsed)

	if err != nil {
		tr.logger.WithError(err).WithField("thing_id", thing.ID).Error("Failed to create thing")
		return fmt.Errorf("failed to create thing %s: %w", thing.ID, err)
	}

	tr.logger.WithField("thing_id", thing.ID).Info("Thing created successfully")
	return nil
}

// GetByID retrieves a Thing Description by ID
func (tr *ThingRepository) GetByID(ctx context.Context, id string) (*database.ThingEntity, error) {
	row := tr.manager.QueryRow(ctx, "GetThingByID", id)

	var thing database.ThingEntity
	err := row.Scan(&thing.ID, &thing.Title, &thing.Description,
		&thing.TDJSONLD, &thing.TDParsed, &thing.CreatedAt, &thing.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("thing %s not found", id)
		}
		tr.logger.WithError(err).WithField("thing_id", id).Error("Failed to get thing")
		return nil, fmt.Errorf("failed to get thing %s: %w", id, err)
	}

	return &thing, nil
}

// GetParsedByID retrieves only the parsed TD content by ID (optimized for frequent access)
func (tr *ThingRepository) GetParsedByID(ctx context.Context, id string) (string, error) {
	row := tr.manager.QueryRow(ctx, "GetThingParsedByID", id)

	var tdParsed string
	err := row.Scan(&tdParsed)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("thing %s not found", id)
		}
		tr.logger.WithError(err).WithField("thing_id", id).Error("Failed to get parsed thing")
		return "", fmt.Errorf("failed to get parsed thing %s: %w", id, err)
	}

	return tdParsed, nil
}

// Update modifies an existing Thing Description
func (tr *ThingRepository) Update(ctx context.Context, thing *database.ThingEntity) error {
	result, err := tr.manager.Execute(ctx, "UpdateThing",
		thing.Title, thing.Description, thing.TDJSONLD, thing.TDParsed, thing.ID)

	if err != nil {
		tr.logger.WithError(err).WithField("thing_id", thing.ID).Error("Failed to update thing")
		return fmt.Errorf("failed to update thing %s: %w", thing.ID, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("thing %s not found", thing.ID)
	}

	tr.logger.WithField("thing_id", thing.ID).Info("Thing updated successfully")
	return nil
}

// Delete removes a Thing Description
func (tr *ThingRepository) Delete(ctx context.Context, id string) error {
	result, err := tr.manager.Execute(ctx, "DeleteThing", id)

	if err != nil {
		tr.logger.WithError(err).WithField("thing_id", id).Error("Failed to delete thing")
		return fmt.Errorf("failed to delete thing %s: %w", id, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("thing %s not found", id)
	}

	tr.logger.WithField("thing_id", id).Info("Thing deleted successfully")
	return nil
}

// List retrieves all Thing Descriptions with optional pagination
func (tr *ThingRepository) List(ctx context.Context, limit, offset int) ([]*database.ThingEntity, error) {
	// For now, use the basic list query. In the future, we can add pagination parameters
	rows, err := tr.manager.Query(ctx, "ListAllThings")
	if err != nil {
		tr.logger.WithError(err).Error("Failed to list things")
		return nil, fmt.Errorf("failed to list things: %w", err)
	}
	defer rows.Close()

	var things []*database.ThingEntity
	count := 0
	skipped := 0

	for rows.Next() {
		// Apply offset
		if skipped < offset {
			skipped++
			continue
		}

		// Apply limit
		if limit > 0 && count >= limit {
			break
		}

		var thing database.ThingEntity
		err := rows.Scan(&thing.ID, &thing.Title, &thing.Description,
			&thing.TDJSONLD, &thing.TDParsed, &thing.CreatedAt, &thing.UpdatedAt)
		if err != nil {
			tr.logger.WithError(err).Error("Failed to scan thing")
			return nil, fmt.Errorf("failed to scan thing: %w", err)
		}

		things = append(things, &thing)
		count++
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating things: %w", err)
	}

	tr.logger.WithField("count", len(things)).Debug("Things listed successfully")
	return things, nil
}

// ListParsedOnly retrieves only parsed TD content for all things (optimized for bulk operations)
func (tr *ThingRepository) ListParsedOnly(ctx context.Context) ([]string, error) {
	rows, err := tr.manager.Query(ctx, "ListThingsParsed")
	if err != nil {
		tr.logger.WithError(err).Error("Failed to list parsed things")
		return nil, fmt.Errorf("failed to list parsed things: %w", err)
	}
	defer rows.Close()

	var tdParsedList []string
	for rows.Next() {
		var tdParsed string
		if err := rows.Scan(&tdParsed); err != nil {
			tr.logger.WithError(err).Error("Failed to scan parsed thing")
			return nil, fmt.Errorf("failed to scan parsed thing: %w", err)
		}
		tdParsedList = append(tdParsedList, tdParsed)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating parsed things: %w", err)
	}

	return tdParsedList, nil
}

// Count returns the total number of Thing Descriptions
func (tr *ThingRepository) Count(ctx context.Context) (int, error) {
	row := tr.manager.QueryRow(ctx, "CountThings")

	var count int
	err := row.Scan(&count)
	if err != nil {
		tr.logger.WithError(err).Error("Failed to count things")
		return 0, fmt.Errorf("failed to count things: %w", err)
	}

	return count, nil
}

// Exists checks if a Thing Description exists
func (tr *ThingRepository) Exists(ctx context.Context, id string) (bool, error) {
	row := tr.manager.QueryRow(ctx, "ThingExists", id)

	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		tr.logger.WithError(err).WithField("thing_id", id).Error("Failed to check thing existence")
		return false, fmt.Errorf("failed to check if thing %s exists: %w", id, err)
	}

	return exists, nil
}

// SearchByTitle searches for Thing Descriptions by title pattern
func (tr *ThingRepository) SearchByTitle(ctx context.Context, titlePattern string) ([]*database.ThingEntity, error) {
	// Add SQL wildcards for LIKE search
	pattern := "%" + titlePattern + "%"

	rows, err := tr.manager.Query(ctx, "GetThingsByTitle", pattern)
	if err != nil {
		tr.logger.WithError(err).WithField("pattern", titlePattern).Error("Failed to search things by title")
		return nil, fmt.Errorf("failed to search things by title: %w", err)
	}
	defer rows.Close()

	var things []*database.ThingEntity
	for rows.Next() {
		var thing database.ThingEntity
		err := rows.Scan(&thing.ID, &thing.Title, &thing.Description,
			&thing.TDJSONLD, &thing.TDParsed, &thing.CreatedAt, &thing.UpdatedAt)
		if err != nil {
			tr.logger.WithError(err).Error("Failed to scan thing in search")
			return nil, fmt.Errorf("failed to scan thing: %w", err)
		}
		things = append(things, &thing)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating search results: %w", err)
	}

	tr.logger.WithFields(logrus.Fields{
		"pattern": titlePattern,
		"count":   len(things),
	}).Debug("Things search completed")

	return things, nil
}

// IsHealthy checks if the repository is healthy (implements RepositoryBase interface)
func (tr *ThingRepository) IsHealthy(ctx context.Context) bool {
	// Simple health check - try to count things
	_, err := tr.Count(ctx)
	return err == nil
}
