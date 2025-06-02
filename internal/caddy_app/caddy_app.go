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
	logger               *logrus.Logger
	stateManager         api.StateManager
	streamBridge         api.StreamBridge
	thingRegistry        api.ThingRegistry
	eventBroker          *api.EventBroker
	benthosStreamManager api.BenthosStreamManager
	configurationManager api.ConfigurationManager // Added
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
	tca.logger = globalContainer.Logger
	tca.stateManager = globalContainer.StateManager
	tca.streamBridge = globalContainer.StreamBridge
	tca.thingRegistry = globalContainer.ThingRegistry
	tca.eventBroker = globalContainer.EventBroker
	tca.benthosStreamManager = globalContainer.BenthosStreamManager
	// Assuming globalContainer.ConfigManager (*config.ConfigManager) implements api.ConfigurationManager
	tca.configurationManager = globalContainer.ConfigManager

	if tca.logger != nil {
		tca.logger.Info("TwinCoreApp provisioned successfully")
	}
	return nil
}

// Validate ensures the module is configured correctly.
func (tca *TwinCoreApp) Validate() error {
	if tca.logger == nil || 
       tca.stateManager == nil || 
       tca.streamBridge == nil || 
       tca.thingRegistry == nil || 
       tca.eventBroker == nil || 
       tca.benthosStreamManager == nil || 
       tca.configurationManager == nil { // Added this check
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

// Implement api.CoreProvider
func (tca *TwinCoreApp) GetLogger() *logrus.Logger           { return tca.logger }
func (tca *TwinCoreApp) GetStateManager() api.StateManager   { return tca.stateManager }
func (tca *TwinCoreApp) GetStreamBridge() api.StreamBridge   { return tca.streamBridge }
func (tca *TwinCoreApp) GetThingRegistry() api.ThingRegistry { return tca.thingRegistry }
func (tca *TwinCoreApp) GetEventBroker() *api.EventBroker    { return tca.eventBroker }
func (tca *TwinCoreApp) GetBenthosStreamManager() api.BenthosStreamManager {
	return tca.benthosStreamManager
}
func (tca *TwinCoreApp) GetConfigurationManager() api.ConfigurationManager {
	return tca.configurationManager
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

var _ api.CoreProvider = (*TwinCoreApp)(nil) // Ensure it implements the CoreProvider interface from api package

/*

This Go file defines a custom Caddy app module named "twincore".
The primary purpose of this module is to act as a bridge, making core components of your TwinCore application
(like the StateManager, StreamBridge, ThingRegistry, EventBroker, and Logger) available to other Caddy modules, particularly your WoTHandler.

Here's a more detailed explanation:

globalContainer and SetGlobalContainer:

var globalContainer *container.Container:

	This is a package-level variable that holds a pointer to your main application's dependency container.
	Container. This container is initialized in your cmd/service/main.go and contains all the essential services and components of your application.

func SetGlobalContainer(c *container.Container):

	This function is called from main.go to set the globalContainer.
	It's a simple way to make the fully initialized container accessible to this Caddy app module.

TwinCoreApp Struct:

This struct defines the Caddy app module itself.
The fields (Logger, StateManager, StreamBridge, ThingRegistry, EventBroker) are pointers to
the interfaces or concrete types of your core application components.
These fields will be populated during the Provision phase.

CaddyModule() Method:

This is a standard method required by Caddy modules.
	ID: "twincore": This is the unique identifier for your app module.
		When other Caddy modules (like your WoTHandler) need to access this app, they will use this ID (e.g., ctx.App("twincore")).
	New: func() caddy.Module { return new(TwinCoreApp) }:
		This tells Caddy how to create a new instance of your app module.

Provision(ctx caddy.Context) Method:

	This method is called by Caddy when it's setting up modules.
	It's where your TwinCoreApp gets its dependencies.
	It first checks if globalContainer has been set (which it should have been by main.go).
	Then, it populates its own fields (tca.Logger, tca.StateManager, etc.) by accessing the corresponding components from the globalContainer.
	This is the crucial step that makes your application's core services available within the Caddy environment.

Validate() Method:

	This method is called by Caddy after provisioning to ensure the module is configured correctly.
	It simply checks if all the essential dependencies (Logger, StateManager, etc.) have been successfully populated.
	If any are nil, it means something went wrong during provisioning, and it returns an error.

Start() and Stop() Methods:

These are part of the caddy.App interface.
	In this specific TwinCoreApp module, they don't perform any actions.
	The app's main role is to hold and provide references to already running components managed by the globalContainer.
	The lifecycle (start/stop) of those components is handled by the main application container, not directly by this Caddy app module.

init() Function:

caddy.RegisterModule(&TwinCoreApp{}): This is the standard Go init function pattern used to register the TwinCoreApp module with Caddy when the package is imported. This makes Caddy aware of the "twincore" app module.
Interface Guards:

var _ caddy.App = (*TwinCoreApp)(nil)
var _ caddy.Provisioner = (*TwinCoreApp)(nil)
var _ caddy.Validator = (*TwinCoreApp)(nil)
These lines are a compile-time check to ensure that the TwinCoreApp struct correctly implements the necessary Caddy interfaces (caddy.App, caddy.Provisioner, caddy.Validator). If the methods were to change signature or be removed, the compiler would flag an error here.
How it fits together:

main.go initializes the main container.Container and then calls caddy_app.SetGlobalContainer() to make it available.
Caddy, when parsing its configuration, sees that an app named "twincore" is needed (or implicitly loaded if other modules depend on it).
Caddy creates an instance of TwinCoreApp and calls its Provision method.
TwinCoreApp.Provision accesses the globalContainer and copies references to the core services into its own fields.
Now, other Caddy modules (like your WoTHandler in wot_handler.go) can get a reference to this provisioned TwinCoreApp instance using ctx.App("twincore").
Once they have the TwinCoreApp instance, they can access its fields (e.g., twinCoreAppInstance.StateManager) to interact with your application's core logic.
In essence, caddy_app.go provides a clean way to inject dependencies from your main application into modules that are managed by the Caddy lifecycle. This avoids having to pass around the main container or individual services through complex Caddy configuration structures.

*/
