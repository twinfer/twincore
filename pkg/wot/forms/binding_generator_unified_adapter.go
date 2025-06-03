package forms

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// UnifiedBindingGeneratorAdapter adapts the new BindingGeneratorV2 to the existing BindingGenerationService interface
type UnifiedBindingGeneratorAdapter struct {
	generator *BindingGeneratorV2
	logger    logrus.FieldLogger
}

// NewUnifiedBindingGeneratorAdapter creates a new adapter that uses the unified stream generator
func NewUnifiedBindingGeneratorAdapter(logger logrus.FieldLogger, licenseChecker LicenseChecker, streamManager StreamManager) *UnifiedBindingGeneratorAdapter {
	return &UnifiedBindingGeneratorAdapter{
		generator: NewBindingGeneratorV2(logger, licenseChecker, streamManager),
		logger:    logger,
	}
}

// SetPersistenceConfig configures data persistence
func (a *UnifiedBindingGeneratorAdapter) SetPersistenceConfig(config PersistenceConfig) {
	a.generator.SetPersistenceConfig(config)
}

// GenerateAllBindings implements the BindingGenerationService interface
func (a *UnifiedBindingGeneratorAdapter) GenerateAllBindings(logger logrus.FieldLogger, td *wot.ThingDescription) (*types.AllBindings, error) {
	// Use the provided logger if available, otherwise use the adapter's logger
	if logger == nil {
		logger = a.logger
	}

	logger.WithField("thing_id", td.ID).Info("Generating bindings using unified stream generator")

	// Create a context for stream generation
	ctx := context.Background()

	// Generate all bindings using the new unified generator
	bindings, err := a.generator.GenerateAllBindings(ctx, td)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bindings: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"thing_id":    td.ID,
		"http_routes": len(bindings.HTTPRoutes),
		"streams":     len(bindings.Streams),
		"processors":  len(bindings.Processors),
	}).Info("Successfully generated bindings")

	return bindings, nil
}

// ConfigureFromLegacy configures the adapter based on legacy configuration parameters
func (a *UnifiedBindingGeneratorAdapter) ConfigureFromLegacy(parquetConfig types.ParquetConfig, kafkaConfig types.KafkaConfig, mqttConfig types.MQTTConfig) {
	// Convert legacy Parquet config to persistence config
	if parquetConfig.BasePath != "" {
		persistenceConfig := PersistenceConfig{
			Enabled:    true,
			Format:     "parquet",
			BasePath:   parquetConfig.BasePath,
			Partitions: []string{"year", "month", "day"},
		}
		a.SetPersistenceConfig(persistenceConfig)
	}

	// Note: Kafka and MQTT configs would be used by the stream generator
	// when creating protocol-specific endpoints. These could be stored
	// as default configurations if needed.
}
