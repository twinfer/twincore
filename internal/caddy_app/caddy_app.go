package caddy_app

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/internal/container"

	"github.com/sirupsen/logrus"
)

// globalContainer holds the application's main container.
var globalContainer *container.Container

// SetGlobalContainer allows the main application to set the container instance.
func SetGlobalContainer(c *container.Container) {
	globalContainer = c
}

// TwinCoreApp is a Caddy app module to make core components available.
type TwinCoreApp struct {
	// These fields will be populated from the globalContainer during Provision.
	Logger        *logrus.Logger
	StateManager  api.StateManager
	StreamBridge  api.StreamBridge
	ThingRegistry api.ThingRegistry
	EventBroker   *api.EventBroker
}

// CaddyModule returns the Caddy module information.
func (tca *TwinCoreApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "twincore", // This is the name used in Caddy config and ctx.App()
		New: func() caddy.Module { return new(TwinCoreApp) },
	}
}

// Provision sets up the TwinCoreApp module.
func (tca *TwinCoreApp) Provision(ctx caddy.Context) error {
	if globalContainer == nil {
		return fmt.Errorf("twincore app: global container not set")
	}
	tca.Logger = globalContainer.Logger
	tca.StateManager = globalContainer.StateManager
	tca.StreamBridge = globalContainer.StreamBridge
	tca.ThingRegistry = globalContainer.ThingRegistry
	tca.EventBroker = globalContainer.EventBroker

	if tca.Logger != nil {
		tca.Logger.Info("TwinCoreApp provisioned successfully")
	}
	return nil
}

// Validate ensures the module is configured correctly.
func (tca *TwinCoreApp) Validate() error {
	if tca.Logger == nil || tca.StateManager == nil || tca.StreamBridge == nil || tca.ThingRegistry == nil || tca.EventBroker == nil {
		return fmt.Errorf("twincore app: one or more core dependencies are nil")
	}
	return nil
}

// Start is a part of the caddy.App interface.
func (tca *TwinCoreApp) Start() error {
	// This app primarily serves to make components available; no specific start action needed here.
	return nil
}

// Stop is a part of the caddy.App interface.
func (tca *TwinCoreApp) Stop() error {
	return nil
}

func init() {
	caddy.RegisterModule(&TwinCoreApp{})
}

// Interface guards
var (
	_ caddy.App = (*TwinCoreApp)(nil)
)
var (
	_ caddy.Provisioner = (*TwinCoreApp)(nil)
)
var (
	_ caddy.Validator = (*TwinCoreApp)(nil)
)
