// internal/api/core_provider.go
package api

import (
	"github.com/sirupsen/logrus"
)

// CoreProvider defines the interface for accessing core application components
// that are made available through a Caddy app module.
// This interface is implemented by caddy_app.TwinCoreApp and used by
// WoTHandler and BenthosBindingHandler to retrieve their dependencies without directly importing caddy_app.
type CoreProvider interface {
	GetLogger() *logrus.Logger
	GetStateManager() StateManager
	GetStreamBridge() StreamBridge
	GetThingRegistry() ThingRegistry
	GetEventBroker() *EventBroker
	GetBenthosStreamManager() BenthosStreamManager
}
