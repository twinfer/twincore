package api

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/models"
	"github.com/twinfer/twincore/pkg/types" // Added import
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/twinfer/twincore/pkg/wot/forms"
)

// ConfigurationManager defines the interface for managing application and Caddy configurations.
type ConfigurationManager interface {
	IsSetupComplete() bool
	CompleteSetup(logger logrus.FieldLogger) error
	GetAuthProviders(license License) []AuthProviderInfo
	ConfigureAuth(logger logrus.FieldLogger, req AuthConfigRequest) error
	GetConfiguration(logger logrus.FieldLogger) (map[string]interface{}, error)
	UpdateConfiguration(logger logrus.FieldLogger, section string, config map[string]interface{}) error
	RemoveThingRoutes(logger logrus.FieldLogger, thingID string) error
}

// License defines the interface for license feature checks.
type License interface {
	HasFeature(feature string) bool
}

// BenthosStreamManager defines the interface for managing Benthos streams.
type BenthosStreamManager interface {
	CreateStream(ctx context.Context, request types.StreamCreationRequest) (*types.StreamInfo, error)
	UpdateStream(ctx context.Context, streamID string, request types.StreamUpdateRequest) (*types.StreamInfo, error)
	DeleteStream(ctx context.Context, streamID string) error
	GetStream(ctx context.Context, streamID string) (*types.StreamInfo, error)
	ListStreams(ctx context.Context, filters types.StreamFilters) ([]types.StreamInfo, error)
	StartStream(ctx context.Context, streamID string) error
	StopStream(ctx context.Context, streamID string) error
	GetStreamStatus(ctx context.Context, streamID string) (*types.StreamStatus, error)
	CreateProcessorCollection(ctx context.Context, request types.ProcessorCollectionRequest) (*types.ProcessorCollection, error)
	GetProcessorCollection(ctx context.Context, collectionID string) (*types.ProcessorCollection, error)
	ListProcessorCollections(ctx context.Context) ([]types.ProcessorCollection, error)
}

// BindingGenerationService defines the interface for generating bindings from a Thing Description.
type BindingGenerationService interface {
	GenerateAllBindings(logger logrus.FieldLogger, td *wot.ThingDescription) (*forms.AllBindings, error)
}

// StateManager handles property state and synchronization
type StateManager interface {
	GetProperty(thingID, propertyName string) (interface{}, error)
	SetProperty(logger logrus.FieldLogger, thingID, propertyName string, value interface{}) error
	SetPropertyWithContext(logger logrus.FieldLogger, ctx context.Context, thingID, propertyName string, value interface{}) error
	SubscribeProperty(thingID, propertyName string) (<-chan models.PropertyUpdate, error)
	UnsubscribeProperty(thingID, propertyName string, ch <-chan models.PropertyUpdate)
}

// StreamBridge connects HTTP handlers to Benthos streams
type StreamBridge interface {
	PublishPropertyUpdate(logger logrus.FieldLogger, thingID, propertyName string, value interface{}) error
	PublishPropertyUpdateWithContext(logger logrus.FieldLogger, ctx context.Context, thingID, propertyName string, value interface{}) error
	PublishActionInvocation(logger logrus.FieldLogger, thingID, actionName string, input interface{}) (string, error)
	PublishEvent(logger logrus.FieldLogger, thingID, eventName string, data interface{}) error
	GetActionResult(logger logrus.FieldLogger, actionID string, timeout time.Duration) (interface{}, error)
	ProcessActionResult(logger logrus.FieldLogger, result map[string]interface{}) error
}

// ThingRegistry provides access to Thing Descriptions
type ThingRegistry interface {
	GetThing(thingID string) (*wot.ThingDescription, error)
	GetProperty(thingID, propertyName string) (wot.PropertyAffordance, error)
	GetAction(thingID, actionName string) (wot.ActionAffordance, error)
	GetEvent(thingID, eventName string) (wot.EventAffordance, error)
}

// SchemaValidator validates inputs against WoT schemas
type SchemaValidator interface {
	ValidateProperty(logger logrus.FieldLogger, propertyName string, propertySchema wot.DataSchema, value interface{}) error
	ValidateActionInput(logger logrus.FieldLogger, schema wot.DataSchema, input interface{}) error
	ValidateEventData(logger logrus.FieldLogger, schema wot.DataSchema, data interface{}) error
}

// ThingRegistryExt extends ThingRegistry with registration methods
type ThingRegistryExt interface {
	ThingRegistry
	RegisterThing(tdJSONLD string) (*wot.ThingDescription, error)
	UpdateThing(thingID string, tdJSONLD string) (*wot.ThingDescription, error)
	DeleteThing(thingID string) error
	ListThings() ([]*wot.ThingDescription, error)
}

// ThingRegistrationService orchestrates the complete Thing registration process including stream composition
type ThingRegistrationService interface {
	RegisterThing(logger logrus.FieldLogger, ctx context.Context, tdJSONLD string) (*ThingRegistrationResult, error)
	UpdateThing(logger logrus.FieldLogger, ctx context.Context, thingID string, tdJSONLD string) (*ThingRegistrationResult, error)
	UnregisterThing(logger logrus.FieldLogger, ctx context.Context, thingID string) error
	GetThingWithStreams(logger logrus.FieldLogger, ctx context.Context, thingID string) (*ThingWithStreams, error)
}

// TDStreamCompositionService orchestrates the complete flow from Thing Description to active streams
type TDStreamCompositionService interface {
	ProcessThingDescription(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error)
	UpdateStreamsForThing(logger logrus.FieldLogger, ctx context.Context, td *wot.ThingDescription) (*StreamCompositionResult, error)
	RemoveStreamsForThing(logger logrus.FieldLogger, ctx context.Context, thingID string) error
	GetStreamCompositionStatus(logger logrus.FieldLogger, ctx context.Context, thingID string) (*StreamCompositionStatus, error)
}

// CoreProvider defines the interface for accessing core application components
// that are made available through a Caddy app module.
type CoreProvider interface {
	GetLogger() *logrus.Logger
	GetStateManager() StateManager
	GetStreamBridge() StreamBridge
	GetThingRegistry() ThingRegistry // Should this be ThingRegistryExt if that's what services need? For now, keeping as ThingRegistry.
	GetEventBroker() *EventBroker    // EventBroker is a concrete type, not an interface here.
	GetBenthosStreamManager() BenthosStreamManager
	GetConfigurationManager() ConfigurationManager // Added
	// GetThingRegistrationService() ThingRegistrationService - Consider if this should be here
	// GetTDStreamCompositionService() TDStreamCompositionService - Consider if this should be here
	// GetBindingGenerationService() BindingGenerationService - Unlikely to be a direct CoreProvider dep
}
