// internal/api/state_manager.go
package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "github.com/marcboeker/go-duckdb"
	"github.com/sirupsen/logrus"
)

// DuckDBStateManager implements StateManager using DuckDB
type DuckDBStateManager struct {
	db          *sql.DB
	logger      *logrus.Logger
	subscribers sync.Map // map[string][]chan PropertyUpdate
	mu          sync.RWMutex
}

type PropertyUpdate struct {
	ThingID      string      `json:"thingId"`
	PropertyName string      `json:"propertyName"`
	Value        interface{} `json:"value"`
	Timestamp    time.Time   `json:"timestamp"`
	Source       string      `json:"source"` // "http", "stream", "device"
}

func NewDuckDBStateManager(db *sql.DB, logger *logrus.Logger) (*DuckDBStateManager, error) {
	logger.Debug("Creating DuckDB state manager")

	return &DuckDBStateManager{
		db:     db,
		logger: logger,
	}, nil
}

func (m *DuckDBStateManager) GetProperty(thingID, propertyName string) (interface{}, error) {
	m.logger.Debugf("Getting property: %s/%s", thingID, propertyName)

	var valueJSON string
	err := m.db.QueryRow(`
        SELECT value FROM property_state 
        WHERE thing_id = ? AND property_name = ?
    `, thingID, propertyName).Scan(&valueJSON)

	if err == sql.ErrNoRows {
		m.logger.Debugf("Property not found: %s/%s", thingID, propertyName)
		return nil, fmt.Errorf("property not found")
	}
	if err != nil {
		m.logger.Errorf("Database error getting property: %v", err)
		return nil, err
	}

	var value interface{}
	if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
		m.logger.Errorf("Failed to unmarshal property value: %v", err)
		return nil, err
	}

	m.logger.Debugf("Retrieved property %s/%s: %v", thingID, propertyName, value)
	return value, nil
}

func (m *DuckDBStateManager) SetProperty(thingID, propertyName string, value interface{}) error {
	m.logger.Debugf("Setting property: %s/%s = %v", thingID, propertyName, value)

	valueJSON, err := json.Marshal(value)
	if err != nil {
		m.logger.Errorf("Failed to marshal property value: %v", err)
		return err
	}

	_, err = m.db.Exec(`
        INSERT OR REPLACE INTO property_state 
        (thing_id, property_name, value, updated_at)
        VALUES (?, ?, ?, ?)
    `, thingID, propertyName, string(valueJSON), time.Now())

	if err != nil {
		m.logger.Errorf("Database error setting property: %v", err)
		return err
	}

	m.logger.Infof("Property updated: %s/%s", thingID, propertyName)

	// Notify subscribers
	m.notifySubscribers(thingID, propertyName, value)

	return nil
}

func (m *DuckDBStateManager) SubscribeProperty(thingID, propertyName string) (<-chan PropertyUpdate, error) {
	ch := make(chan PropertyUpdate, 10)
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.logger.Debugf("New subscription for property: %s", key)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan PropertyUpdate)
		channels = append(channels, ch)
		m.subscribers.Store(key, channels)
		m.logger.Debugf("Added subscriber to existing list (total: %d)", len(channels))
	} else {
		m.subscribers.Store(key, []chan PropertyUpdate{ch})
		m.logger.Debugf("Created new subscriber list for %s", key)
	}

	return ch, nil
}

func (m *DuckDBStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan PropertyUpdate) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.logger.Debugf("Removing subscription for property: %s", key)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan PropertyUpdate)
		for i, c := range channels {
			if c == ch {
				channels = append(channels[:i], channels[i+1:]...)
				if len(channels) == 0 {
					m.subscribers.Delete(key)
					m.logger.Debugf("Removed last subscriber for %s", key)
				} else {
					m.subscribers.Store(key, channels)
					m.logger.Debugf("Removed subscriber (remaining: %d)", len(channels))
				}
				close(c.(chan PropertyUpdate))
				return // Exit after finding and removing the channel
			}
		}
	}
}

func (m *DuckDBStateManager) notifySubscribers(thingID, propertyName string, value interface{}) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan PropertyUpdate)

		m.logger.Debugf("Notifying %d subscribers for %s", len(channels), key)

		update := PropertyUpdate{
			ThingID:      thingID,
			PropertyName: propertyName,
			Value:        value,
			Timestamp:    time.Now(),
			Source:       "http",
		}

		for i, ch := range channels {
			select {
			case ch <- update:
				m.logger.Debugf("Notified subscriber %d", i)
			default:
				m.logger.Warnf("Subscriber %d channel full, skipping", i)
			}
		}
	} else {
		m.logger.Debugf("No subscribers for %s", key)
	}
}

// GetAllProperties returns all properties for a thing
func (m *DuckDBStateManager) GetAllProperties(thingID string) (map[string]interface{}, error) {
	m.logger.Debugf("Getting all properties for thing: %s", thingID)

	rows, err := m.db.Query(`
        SELECT property_name, value FROM property_state
        WHERE thing_id = ?
    `, thingID)
	if err != nil {
		m.logger.Errorf("Database error getting properties: %v", err)
		return nil, err
	}
	defer rows.Close()

	properties := make(map[string]interface{})
	for rows.Next() {
		var name, valueJSON string
		if err := rows.Scan(&name, &valueJSON); err != nil {
			m.logger.Errorf("Failed to scan property row: %v", err)
			continue
		}

		var value interface{}
		if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
			m.logger.Errorf("Failed to unmarshal property %s: %v", name, err)
			continue
		}

		properties[name] = value
	}

	m.logger.Debugf("Retrieved %d properties for thing %s", len(properties), thingID)
	return properties, nil
}
