// // internal/api/state_manager.go
package api

// import (
// 	"database/sql"
// 	"encoding/json"
// 	"fmt"
// 	"sync"
// 	"time"

// 	"github.com/benthosdev/benthos/v4/public/service"
// 	_ "github.com/marcboeker/go-duckdb"
// )

// // DuckDBStateManager implements StateManager using DuckDB
// type DuckDBStateManager struct {
// 	db          *sql.DB
// 	subscribers sync.Map // map[string][]chan PropertyUpdate
// 	mu          sync.RWMutex
// }

// type PropertyUpdate struct {
// 	ThingID      string      `json:"thingId"`
// 	PropertyName string      `json:"propertyName"`
// 	Value        interface{} `json:"value"`
// 	Timestamp    time.Time   `json:"timestamp"`
// 	Source       string      `json:"source"` // "http", "stream", "device"
// }

// func NewDuckDBStateManager(dbPath string) (*DuckDBStateManager, error) {
// 	db, err := sql.Open("duckdb", dbPath)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create tables
// 	if err := createStateTables(db); err != nil {
// 		return nil, err
// 	}

// 	return &DuckDBStateManager{
// 		db: db,
// 	}, nil
// }

// func (m *DuckDBStateManager) GetProperty(thingID, propertyName string) (interface{}, error) {
// 	var valueJSON string
// 	err := m.db.QueryRow(`
//         SELECT value FROM property_state
//         WHERE thing_id = ? AND property_name = ?
//     `, thingID, propertyName).Scan(&valueJSON)

// 	if err == sql.ErrNoRows {
// 		return nil, fmt.Errorf("property not found")
// 	}
// 	if err != nil {
// 		return nil, err
// 	}

// 	var value interface{}
// 	if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
// 		return nil, err
// 	}

// 	return value, nil
// }

// func (m *DuckDBStateManager) SetProperty(thingID, propertyName string, value interface{}) error {
// 	valueJSON, err := json.Marshal(value)
// 	if err != nil {
// 		return err
// 	}

// 	_, err = m.db.Exec(`
//         INSERT OR REPLACE INTO property_state
//         (thing_id, property_name, value, updated_at)
//         VALUES (?, ?, ?, ?)
//     `, thingID, propertyName, string(valueJSON), time.Now())

// 	if err != nil {
// 		return err
// 	}

// 	// Notify subscribers
// 	m.notifySubscribers(thingID, propertyName, value)

// 	return nil
// }

// func (m *DuckDBStateManager) SubscribeProperty(thingID, propertyName string) (<-chan PropertyUpdate, error) {
// 	ch := make(chan PropertyUpdate, 10)
// 	key := fmt.Sprintf("%s/%s", thingID, propertyName)

// 	m.mu.Lock()
// 	defer m.mu.Unlock()

// 	if subs, ok := m.subscribers.Load(key); ok {
// 		channels := subs.([]chan PropertyUpdate)
// 		channels = append(channels, ch)
// 		m.subscribers.Store(key, channels)
// 	} else {
// 		m.subscribers.Store(key, []chan PropertyUpdate{ch})
// 	}

// 	return ch, nil
// }

// func (m *DuckDBStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan PropertyUpdate) {
// 	key := fmt.Sprintf("%s/%s", thingID, propertyName)

// 	m.mu.Lock()
// 	defer m.mu.Unlock()

// 	if subs, ok := m.subscribers.Load(key); ok {
// 		channels := subs.([]chan PropertyUpdate)
// 		for i, c := range channels {
// 			if c == ch {
// 				channels = append(channels[:i], channels[i+1:]...)
// 				if len(channels) == 0 {
// 					m.subscribers.Delete(key)
// 				} else {
// 					m.subscribers.Store(key, channels)
// 				}
// 				close(c.(chan PropertyUpdate))
// 				break
// 			}
// 		}
// 	}
// }

// func (m *DuckDBStateManager) notifySubscribers(thingID, propertyName string, value interface{}) {
// 	key := fmt.Sprintf("%s/%s", thingID, propertyName)

// 	if subs, ok := m.subscribers.Load(key); ok {
// 		update := PropertyUpdate{
// 			ThingID:      thingID,
// 			PropertyName: propertyName,
// 			Value:        value,
// 			Timestamp:    time.Now(),
// 			Source:       "http",
// 		}

// 		channels := subs.([]chan PropertyUpdate)
// 		for _, ch := range channels {
// 			select {
// 			case ch <- update:
// 			default:
// 				// Channel full, skip
// 			}
// 		}
// 	}
// }

// func createStateTables(db *sql.DB) error {
// 	schema := `
//     CREATE TABLE IF NOT EXISTS property_state (
//         thing_id TEXT NOT NULL,
//         property_name TEXT NOT NULL,
//         value TEXT NOT NULL,
//         updated_at TIMESTAMP NOT NULL,
//         PRIMARY KEY (thing_id, property_name)
//     );

//     CREATE TABLE IF NOT EXISTS action_state (
//         action_id TEXT PRIMARY KEY,
//         thing_id TEXT NOT NULL,
//         action_name TEXT NOT NULL,
//         input TEXT,
//         output TEXT,
//         status TEXT NOT NULL,
//         started_at TIMESTAMP NOT NULL,
//         completed_at TIMESTAMP,
//         error TEXT
//     );

//     CREATE INDEX IF NOT EXISTS idx_action_status ON action_state(status);
//     CREATE INDEX IF NOT EXISTS idx_action_thing ON action_state(thing_id, action_name);
//     `

// 	_, err := db.Exec(schema)
// 	return err
// }

// // BenthosStreamBridge implements StreamBridge using Benthos
// type BenthosStreamBridge struct {
// 	streamBuilder *service.StreamBuilder
// 	stateManager  StateManager
// 	db            *sql.DB

// 	// Action result waiters
// 	actionWaiters sync.Map // map[actionID]chan ActionResult
// }

// type ActionResult struct {
// 	Output interface{} `json:"output"`
// 	Error  error       `json:"error"`
// }

// func NewBenthosStreamBridge(builder *service.StreamBuilder, stateManager StateManager, db *sql.DB) *BenthosStreamBridge {
// 	bridge := &BenthosStreamBridge{
// 		streamBuilder: builder,
// 		stateManager:  stateManager,
// 		db:            db,
// 	}

// 	// Start action result processor
// 	go bridge.processActionResults()

// 	return bridge
// }

// func (b *BenthosStreamBridge) PublishPropertyUpdate(thingID, propertyName string, value interface{}) error {
// 	message := map[string]interface{}{
// 		"type":         "property_update",
// 		"thingId":      thingID,
// 		"propertyName": propertyName,
// 		"value":        value,
// 		"timestamp":    time.Now(),
// 	}

// 	// Send to property update stream
// 	streamName := fmt.Sprintf("things.%s.properties.%s", thingID, propertyName)
// 	return b.sendToStream(streamName, message)
// }

// func (b *BenthosStreamBridge) PublishActionInvocation(thingID, actionName string, input interface{}) (string, error) {
// 	actionID := generateActionID()

// 	// Store action state
// 	inputJSON, _ := json.Marshal(input)
// 	_, err := b.db.Exec(`
//         INSERT INTO action_state
//         (action_id, thing_id, action_name, input, status, started_at)
//         VALUES (?, ?, ?, ?, ?, ?)
//     `, actionID, thingID, actionName, string(inputJSON), "pending", time.Now())

// 	if err != nil {
// 		return "", err
// 	}

// 	// Create waiter for result
// 	resultChan := make(chan ActionResult, 1)
// 	b.actionWaiters.Store(actionID, resultChan)

// 	// Send to action stream
// 	message := map[string]interface{}{
// 		"type":       "action_invocation",
// 		"actionId":   actionID,
// 		"thingId":    thingID,
// 		"actionName": actionName,
// 		"input":      input,
// 		"timestamp":  time.Now(),
// 	}

// 	streamName := fmt.Sprintf("things.%s.actions.%s", thingID, actionName)
// 	if err := b.sendToStream(streamName, message); err != nil {
// 		b.actionWaiters.Delete(actionID)
// 		return "", err
// 	}

// 	return actionID, nil
// }

// func (b *BenthosStreamBridge) PublishEvent(thingID, eventName string, data interface{}) error {
// 	message := map[string]interface{}{
// 		"type":      "event",
// 		"thingId":   thingID,
// 		"eventName": eventName,
// 		"data":      data,
// 		"timestamp": time.Now(),
// 	}

// 	streamName := fmt.Sprintf("things.%s.events.%s", thingID, eventName)
// 	return b.sendToStream(streamName, message)
// }

// func (b *BenthosStreamBridge) GetActionResult(actionID string, timeout time.Duration) (interface{}, error) {
// 	// Check if already completed
// 	var status, outputJSON sql.NullString
// 	var errorMsg sql.NullString

// 	err := b.db.QueryRow(`
//         SELECT status, output, error FROM action_state
//         WHERE action_id = ?
//     `, actionID).Scan(&status, &outputJSON, &errorMsg)

// 	if err != nil {
// 		return nil, err
// 	}

// 	if status.String == "completed" {
// 		if errorMsg.Valid {
// 			return nil, fmt.Errorf(errorMsg.String)
// 		}
// 		var output interface{}
// 		if outputJSON.Valid {
// 			json.Unmarshal([]byte(outputJSON.String), &output)
// 		}
// 		return output, nil
// 	}

// 	// Wait for result
// 	if waiter, ok := b.actionWaiters.Load(actionID); ok {
// 		resultChan := waiter.(chan ActionResult)

// 		select {
// 		case result := <-resultChan:
// 			b.actionWaiters.Delete(actionID)
// 			return result.Output, result.Error
// 		case <-time.After(timeout):
// 			b.actionWaiters.Delete(actionID)
// 			return nil, fmt.Errorf("action timeout")
// 		}
// 	}

// 	return nil, fmt.Errorf("action not found")
// }

// func (b *BenthosStreamBridge) sendToStream(streamName string, message interface{}) error {
// 	// This would integrate with Benthos stream
// 	// For now, just log
// 	fmt.Printf("Sending to stream %s: %v\n", streamName, message)
// 	return nil
// }

// func (b *BenthosStreamBridge) processActionResults() {
// 	// This would listen to action result streams
// 	// For now, simulate with a goroutine

// 	// In real implementation, this would be a Benthos stream
// 	// that listens to action result topics and updates the database
// }

// func generateActionID() string {
// 	return fmt.Sprintf("action_%d", time.Now().UnixNano())
// }

// // EventBroker implementation
// func (b *EventBroker) Subscribe(thingID, eventName string) <-chan Event {
// 	ch := make(chan Event, 10)
// 	key := fmt.Sprintf("%s/%s", thingID, eventName)

// 	b.mu.Lock()
// 	defer b.mu.Unlock()

// 	if subs, ok := b.subscribers.Load(key); ok {
// 		channels := subs.([]chan Event)
// 		channels = append(channels, ch)
// 		b.subscribers.Store(key, channels)
// 	} else {
// 		b.subscribers.Store(key, []chan Event{ch})
// 	}

// 	return ch
// }

// func (b *EventBroker) Unsubscribe(thingID, eventName string, ch <-chan Event) {
// 	key := fmt.Sprintf("%s/%s", thingID, eventName)

// 	b.mu.Lock()
// 	defer b.mu.Unlock()

// 	if subs, ok := b.subscribers.Load(key); ok {
// 		channels := subs.([]chan Event)
// 		for i, c := range channels {
// 			if c == ch {
// 				channels = append(channels[:i], channels[i+1:]...)
// 				if len(channels) == 0 {
// 					b.subscribers.Delete(key)
// 				} else {
// 					b.subscribers.Store(key, channels)
// 				}
// 				close(c.(chan Event))
// 				break
// 			}
// 		}
// 	}
// }

// func (b *EventBroker) Publish(event Event) {
// 	key := fmt.Sprintf("%s/%s", event.ThingID, event.EventName)

// 	if subs, ok := b.subscribers.Load(key); ok {
// 		channels := subs.([]chan Event)
// 		for _, ch := range channels {
// 			select {
// 			case ch <- event:
// 			default:
// 				// Channel full, skip
// 			}
// 		}
// 	}
// }
