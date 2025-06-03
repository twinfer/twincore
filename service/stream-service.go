// internal/service/stream_service.go
package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/twinfer/twincore/pkg/wot/forms"
)

type StreamService struct {
	env                 *service.Environment
	streams             map[string]*service.Stream
	configs             map[string]string          // Store YAML configs
	streamConfigBuilder *forms.StreamConfigBuilder // Unified stream configuration
	schemaRegistry      *forms.SchemaRegistry      // Schema management
	currentConfig       *types.ServiceConfig       // Current service configuration
	mu                  sync.RWMutex
	running             bool
	ctx                 context.Context
	cancel              context.CancelFunc
	logger              *logrus.Logger
}

// NewStreamService creates a new StreamService.
// It requires a Benthos service environment to build streams.
func NewStreamService(env *service.Environment, logger *logrus.Logger) types.Service {
	// Initialize unified stream configuration components
	schemaRegistry := forms.NewSchemaRegistry()
	streamConfigBuilder := forms.NewStreamConfigBuilder(logger)

	return &StreamService{
		env:                 env,
		streams:             make(map[string]*service.Stream),
		configs:             make(map[string]string),
		streamConfigBuilder: streamConfigBuilder,
		schemaRegistry:      schemaRegistry,
		logger:              logger,
	}
}

// MockLicenseAdapter provides a simple license adapter for stream service
type MockLicenseAdapter struct {
	logger *logrus.Logger
}

func (m *MockLicenseAdapter) IsFeatureEnabled(category, feature string) (bool, error) {
	// For now, allow all features - in real implementation this should check actual license
	return true, nil
}

func (m *MockLicenseAdapter) CheckLimit(resource string, currentCount int) (bool, error) {
	// For now, allow unlimited - in real implementation this should check actual limits
	return true, nil
}

func (m *MockLicenseAdapter) GetAllowedFeatures() (map[string]interface{}, error) {
	return map[string]interface{}{
		"streaming": []string{"benthos", "kafka", "mqtt"},
		"protocols": []string{"http", "kafka", "mqtt"},
	}, nil
}

func (m *MockLicenseAdapter) IsFeatureAvailable(feature string) bool {
	return true // Allow all features for now
}

func (m *MockLicenseAdapter) GetFeatureConfig(feature string) map[string]interface{} {
	return make(map[string]interface{})
}

func (s *StreamService) Name() string {
	return "stream"
}

func (s *StreamService) RequiredLicense() []string {
	return []string{"core", "streaming"}
}

func (s *StreamService) Dependencies() []string {
	return []string{}
}

func (s *StreamService) Start(ctx context.Context, config types.ServiceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("stream service already running")
	}

	s.logger.Info("StreamService starting...")
	s.currentConfig = &config

	// Initialize context for managing stream lifecycles
	s.ctx, s.cancel = context.WithCancel(ctx)

	// Process stream configuration if provided
	if err := s.processStreamConfiguration(config); err != nil {
		s.cleanup()
		return fmt.Errorf("failed to process stream configuration: %w", err)
	}

	s.running = true
	s.logger.WithFields(logrus.Fields{
		"active_streams": len(s.streams),
		"config_name":    config.Name,
	}).Info("StreamService started successfully")
	return nil
}

// processStreamConfiguration handles the stream configuration processing
func (s *StreamService) processStreamConfiguration(config types.ServiceConfig) error {
	// Extract stream configurations
	streamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		s.logger.Info("No 'stream' configuration found. Service will run without initial streams.")
		return nil
	}

	s.logger.WithFields(logrus.Fields{
		"topics":   len(streamConfig.Topics),
		"commands": len(streamConfig.Commands),
	}).Info("Processing stream configuration")

	// Process all topics using unified stream configuration
	for _, topic := range streamConfig.Topics {
		if err := s.createUnifiedStreamFromTopic(topic); err != nil {
			s.logger.WithError(err).Errorf("Failed to create unified stream for topic %s", topic.Name)
			return fmt.Errorf("failed to create stream for topic %s: %w", topic.Name, err)
		}
	}

	// Process all commands using unified stream configuration
	for _, command := range streamConfig.Commands {
		if err := s.createUnifiedStreamFromCommand(command); err != nil {
			s.logger.WithError(err).Errorf("Failed to create unified stream for command %s", command.Name)
			return fmt.Errorf("failed to create stream for command %s: %w", command.Name, err)
		}
	}

	return nil
}

// cleanup performs cleanup operations
func (s *StreamService) cleanup() {
	if s.cancel != nil {
		s.cancel()
	}
	s.stopAllStreams(context.Background())
}

func (s *StreamService) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	// Signal all running streams to stop
	if s.cancel != nil {
		s.cancel()
	}

	// Stop all streams, using the provided context for the stop operation itself
	s.stopAllStreams(ctx)

	s.running = false
	// Reset fields
	s.streams = make(map[string]*service.Stream)
	s.configs = make(map[string]string)
	s.ctx = nil
	s.cancel = nil
	s.logger.Info("StreamService stopped.")
	return nil
}

func (s *StreamService) UpdateConfig(config types.ServiceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("service not running, cannot update config")
	}

	s.logger.Info("StreamService: Updating configuration - streams will be recreated")

	newStreamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		// If new config has no stream section, stop all existing streams
		s.logger.Info("StreamService: New configuration has no 'stream' section. Stopping all existing streams.")
		s.stopAllStreams(context.Background())
		s.configs = make(map[string]string) // Clear stored configs
		s.currentConfig = &config
		return nil
	}

	// Create maps for easy lookup of new and existing streams
	newTopics := make(map[string]types.StreamTopic)
	for _, t := range newStreamConfig.Topics {
		newTopics[t.Name] = t
	}
	newCommands := make(map[string]types.CommandStream)
	for _, c := range newStreamConfig.Commands {
		newCommands[c.Name] = c
	}

	// Stop and remove streams that are not in the new config
	for name, stream := range s.streams {
		_, isTopic := newTopics[name]
		_, isCommand := newCommands[name]
		if !isTopic && !isCommand {
			s.logger.WithField("stream_name", name).Info("Removing stream not present in new configuration")
			if err := stream.Stop(context.Background()); err != nil {
				s.logger.WithError(err).Errorf("StreamService: Error stopping stream %s during config update", name)
			}
			delete(s.streams, name)
			delete(s.configs, name)
		}
	}

	// Recreate all topic streams with unified configuration
	for _, topic := range newStreamConfig.Topics {
		if oldStream, exists := s.streams[topic.Name]; exists {
			s.logger.WithField("topic_name", topic.Name).Debug("Recreating topic stream with new configuration")
			if err := oldStream.Stop(context.Background()); err != nil {
				s.logger.WithError(err).Warnf("StreamService: Error stopping existing stream %s for recreation", topic.Name)
			}
			delete(s.streams, topic.Name) // Remove before re-creating
		}

		// Create unified stream
		if err := s.createUnifiedStreamFromTopic(topic); err != nil {
			s.logger.WithError(err).Errorf("StreamService: Failed to create unified stream for topic %s", topic.Name)
		}
	}

	// Recreate all command streams with unified configuration
	for _, command := range newStreamConfig.Commands {
		s.logger.WithField("command_name", command.Name).Debug("Recreating command stream with new configuration")
		if oldStream, exists := s.streams[command.Name]; exists {
			if err := oldStream.Stop(context.Background()); err != nil {
				s.logger.WithError(err).Warnf("StreamService: Error stopping existing stream %s for recreation", command.Name)
			}
			delete(s.streams, command.Name) // Remove before re-creating
		}

		// Create unified stream
		if err := s.createUnifiedStreamFromCommand(command); err != nil {
			s.logger.WithError(err).Errorf("StreamService: Failed to create unified stream for command %s", command.Name)
		}
	}

	// Update current configuration
	s.currentConfig = &config
	s.logger.WithFields(logrus.Fields{
		"active_streams": len(s.streams),
		"topics":         len(newStreamConfig.Topics),
		"commands":       len(newStreamConfig.Commands),
	}).Info("StreamService configuration updated successfully")

	return nil
}

func (s *StreamService) HealthCheck() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return fmt.Errorf("service not running")
	}

	// Check if schema registry is healthy
	if s.schemaRegistry == nil {
		return fmt.Errorf("schema registry is nil")
	}

	// Check if stream config builder is healthy
	if s.streamConfigBuilder == nil {
		return fmt.Errorf("stream config builder is nil")
	}

	// Check if Benthos environment is healthy
	if s.env == nil {
		return fmt.Errorf("benthos environment is nil")
	}

	s.logger.Debug("StreamService health check: OK")
	return nil
}

// createStreamFromTopic creates a Benthos stream from a WoT topic configuration
// This function no longer takes context as an argument; it uses s.ctx.
func (s *StreamService) createStreamFromTopic(topic types.StreamTopic) error {
	// Get form configurations from topic
	forms, ok := topic.Config["forms"].([]wot.Form)
	if !ok || len(forms) == 0 {
		s.logger.Warnf("StreamService: No forms defined for topic %s, stream not created.", topic.Name)
		return fmt.Errorf("no forms defined for topic %s", topic.Name)
	}

	// Get security definitions
	securityDefs, _ := topic.Config["securityDefinitions"].(map[string]wot.SecurityScheme)

	// Generate Benthos configuration from forms
	yamlConfig, err := s.generateConfigFromForms(forms, securityDefs, "topic")
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to generate Benthos config for topic %s", topic.Name)
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Build and run stream
	builder := service.NewStreamBuilder() // Changed: Use NewStreamBuilder()
	if err := builder.SetYAML(yamlConfig); err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to set YAML for stream %s", topic.Name)
		return fmt.Errorf("failed to set YAML for stream %s: %w", topic.Name, err)
	}

	stream, err := builder.Build()
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to build stream %s", topic.Name)
		return fmt.Errorf("failed to build stream %s: %w", topic.Name, err)
	}

	go func() {
		s.logger.Infof("StreamService: Starting stream %s", topic.Name)
		if runErr := stream.Run(s.ctx); runErr != nil {
			// Log if context was not cancelled (i.e., unexpected exit)
			if s.ctx.Err() == nil {
				s.logger.WithError(runErr).Errorf("StreamService: Stream %s exited with error", topic.Name)
			} else {
				s.logger.Infof("StreamService: Stream %s stopped.", topic.Name)
			}
		}
		s.logger.Infof("StreamService: Stream %s goroutine finished.", topic.Name)
	}()

	s.streams[topic.Name] = stream
	s.configs[topic.Name] = yamlConfig // Keep storing YAML for reference
	s.logger.Infof("StreamService: Stream %s created and runner started.", topic.Name)
	return nil
}

// createStreamFromCommand creates a Benthos stream from a WoT command configuration
// This function no longer takes context as an argument; it uses s.ctx.
func (s *StreamService) createStreamFromCommand(command types.CommandStream) error {
	forms, ok := command.Config["forms"].([]wot.Form)
	if !ok || len(forms) == 0 {
		s.logger.Warnf("StreamService: No forms defined for command %s, stream not created.", command.Name)
		return fmt.Errorf("no forms defined for command %s", command.Name)
	}

	securityDefs, _ := command.Config["securityDefinitions"].(map[string]wot.SecurityScheme)

	yamlConfig, err := s.generateConfigFromForms(forms, securityDefs, "command")
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to generate Benthos config for command %s", command.Name)
		return fmt.Errorf("failed to generate config for command %s: %w", command.Name, err)
	}

	// Build and run stream
	builder := service.NewStreamBuilder() // Changed: Use NewStreamBuilder()
	if err := builder.SetYAML(yamlConfig); err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to set YAML for stream %s", command.Name)
		return fmt.Errorf("failed to set YAML for stream %s: %w", command.Name, err)
	}

	stream, err := builder.Build()
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to build stream %s", command.Name)
		return fmt.Errorf("failed to build stream %s: %w", command.Name, err)
	}

	go func() {
		s.logger.Infof("StreamService: Starting stream %s", command.Name)
		if runErr := stream.Run(s.ctx); runErr != nil {
			if s.ctx.Err() == nil {
				s.logger.WithError(runErr).Errorf("StreamService: Stream %s exited with error", command.Name)
			} else {
				s.logger.Infof("StreamService: Stream %s stopped.", command.Name)
			}
		}
		s.logger.Infof("StreamService: Stream %s goroutine finished.", command.Name)
	}()

	s.streams[command.Name] = stream
	s.configs[command.Name] = yamlConfig
	s.logger.Infof("StreamService: Stream %s created and runner started.", command.Name)
	return nil
}

// generateConfigFromForms generates Benthos YAML config from WoT forms
func (s *StreamService) generateConfigFromForms(forms []wot.Form, securityDefs map[string]wot.SecurityScheme, streamType string) (string, error) {
	// Find appropriate forms for input and output
	var inputForm, outputForm wot.Form

	for _, form := range forms {
		ops := form.GetOp()
		for _, op := range ops {
			switch op {
			case "readproperty", "subscribeevent":
				inputForm = form
			case "writeproperty", "invokeaction":
				outputForm = form
			}
		}
	}

	if inputForm == nil && outputForm == nil {
		return "", fmt.Errorf("no valid forms found")
	}

	// Generate configurations
	var inputConfig, outputConfig map[string]interface{}
	var err error

	if inputForm != nil {
		inputConfig, err = inputForm.GenerateConfig(securityDefs)
		if err != nil {
			return "", fmt.Errorf("failed to generate input config: %w", err)
		}
	}

	if outputForm != nil {
		outputConfig, err = outputForm.GenerateConfig(securityDefs)
		if err != nil {
			return "", fmt.Errorf("failed to generate output config: %w", err)
		}
	}

	// Combine into full Benthos config
	return s.combineConfigs(inputConfig, outputConfig, streamType)
}

// combineConfigs combines input and output configs into complete Benthos YAML
func (s *StreamService) combineConfigs(input, output map[string]interface{}, streamType string) (string, error) {
	config := ""

	if input != nil {
		if yamlStr, ok := input["yaml"].(string); ok {
			config += yamlStr + "\n"
		}
	}

	// Add default processor pipeline
	config += `
pipeline:
  processors:
    - bloblang: |
        root = this
        root.processed_at = now()
        root.stream_type = "` + streamType + `"
`

	if output != nil {
		if yamlStr, ok := output["yaml"].(string); ok {
			config += "\n" + yamlStr
		}
	}

	return config, nil
}

// stopAllStreams stops all running streams.
// The context passed here is for the stop operation itself.
func (s *StreamService) stopAllStreams(ctx context.Context) {
	var wg sync.WaitGroup
	for name, stream := range s.streams {
		wg.Add(1)
		go func(sName string, st *service.Stream) {
			defer wg.Done()
			// Use the provided context for the stop operation
			if err := st.Stop(ctx); err != nil {
				s.logger.WithError(err).Errorf("StreamService: Error stopping stream %s", sName)
			} else {
				s.logger.Infof("StreamService: Stream %s stopped successfully via stopAllStreams.", sName)
			}
		}(name, stream)
	}
	wg.Wait() // Wait for all stop operations to complete

	// Clear the maps after all streams are stopped
	s.streams = make(map[string]*service.Stream)
	s.configs = make(map[string]string)
}

// createUnifiedStreamFromTopic creates a unified stream from a topic using the modern stream configuration system
func (s *StreamService) createUnifiedStreamFromTopic(topic types.StreamTopic) error {
	// Convert topic configuration to StreamBuildConfig
	buildConfig, err := s.convertTopicToStreamBuildConfig(topic)
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to convert topic config for %s", topic.Name)
		return fmt.Errorf("failed to convert topic config: %w", err)
	}

	// Use the unified stream configuration builder
	streamRequest, err := s.streamConfigBuilder.BuildStream(buildConfig)
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to build unified stream config for topic %s", topic.Name)
		return fmt.Errorf("failed to build unified stream config: %w", err)
	}

	// Convert the StreamCreationRequest to YAML and create stream
	yamlConfig, err := s.convertStreamRequestToYAML(streamRequest)
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to convert stream request to YAML for topic %s", topic.Name)
		return fmt.Errorf("failed to convert stream request to YAML: %w", err)
	}

	// Create and start the stream using the unified configuration
	return s.createAndRunStream(topic.Name, yamlConfig)
}

// createUnifiedStreamFromCommand creates a unified stream from a command using the modern stream configuration system
func (s *StreamService) createUnifiedStreamFromCommand(command types.CommandStream) error {
	// Convert command configuration to StreamBuildConfig
	buildConfig, err := s.convertCommandToStreamBuildConfig(command)
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to convert command config for %s", command.Name)
		return fmt.Errorf("failed to convert command config: %w", err)
	}

	// Use the unified stream configuration builder
	streamRequest, err := s.streamConfigBuilder.BuildStream(buildConfig)
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to build unified stream config for command %s", command.Name)
		return fmt.Errorf("failed to build unified stream config: %w", err)
	}

	// Convert the StreamCreationRequest to YAML and create stream
	yamlConfig, err := s.convertStreamRequestToYAML(streamRequest)
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to convert stream request to YAML for command %s", command.Name)
		return fmt.Errorf("failed to convert stream request to YAML: %w", err)
	}

	// Create and start the stream using the unified configuration
	return s.createAndRunStream(command.Name, yamlConfig)
}

// createAndRunStream creates and starts a Benthos stream with the given configuration
func (s *StreamService) createAndRunStream(name, yamlConfig string) error {
	// Build stream using Benthos StreamBuilder
	builder := service.NewStreamBuilder()
	if err := builder.SetYAML(yamlConfig); err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to set YAML for stream %s", name)
		return fmt.Errorf("failed to set YAML for stream %s: %w", name, err)
	}

	stream, err := builder.Build()
	if err != nil {
		s.logger.WithError(err).Errorf("StreamService: Failed to build stream %s", name)
		return fmt.Errorf("failed to build stream %s: %w", name, err)
	}

	// Start stream in a goroutine
	go func() {
		s.logger.Infof("StreamService: Starting unified stream %s", name)
		if runErr := stream.Run(s.ctx); runErr != nil {
			if s.ctx.Err() == nil {
				s.logger.WithError(runErr).Errorf("StreamService: Unified stream %s exited with error", name)
			} else {
				s.logger.Infof("StreamService: Unified stream %s stopped", name)
			}
		}
		s.logger.Infof("StreamService: Unified stream %s goroutine finished", name)
	}()

	// Store stream and configuration
	s.streams[name] = stream
	s.configs[name] = yamlConfig
	s.logger.WithField("stream_name", name).Info("StreamService: Unified stream created and started successfully")
	return nil
}

// GetStreamMetrics returns metrics for all streams
func (s *StreamService) GetStreamMetrics() (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metrics := make(map[string]interface{})

	for name := range s.streams {
		// StreamBuilder doesn't expose direct metrics, but we can track status
		metrics[name] = map[string]interface{}{
			"running": true,
			"config":  s.configs[name],
		}
	}

	return metrics, nil
}

// GetServiceStatus returns detailed status information for the StreamService
func (s *StreamService) GetServiceStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := map[string]interface{}{
		"running":             s.running,
		"active_streams":      len(s.streams),
		"stored_configs":      len(s.configs),
		"has_benthos_env":     s.env != nil,
		"has_schema_registry": s.schemaRegistry != nil,
		"has_stream_builder":  s.streamConfigBuilder != nil,
		"has_current_config":  s.currentConfig != nil,
	}

	if s.currentConfig != nil {
		status["config_name"] = s.currentConfig.Name
	}

	// Add individual stream status
	streamStatus := make(map[string]interface{})
	for name := range s.streams {
		streamStatus[name] = map[string]interface{}{
			"has_config": s.configs[name] != "",
			"running":    true, // If it's in the map, it's considered running
		}
	}
	status["streams"] = streamStatus

	return status
}

// Helper methods for converting between old and new configuration formats

// convertTopicToStreamBuildConfig converts a StreamTopic to StreamBuildConfig
func (s *StreamService) convertTopicToStreamBuildConfig(topic types.StreamTopic) (forms.StreamBuildConfig, error) {
	// Extract forms from topic configuration
	wotForms, ok := topic.Config["forms"].([]wot.Form)
	if !ok || len(wotForms) == 0 {
		return forms.StreamBuildConfig{}, fmt.Errorf("no forms defined for topic %s", topic.Name)
	}

	// For simplicity, use the first form for now
	// In a real implementation, you might want to handle multiple forms
	form := wotForms[0]

	// Extract basic information
	buildConfig := forms.StreamBuildConfig{
		ThingID:         topic.Name, // Use topic name as thing ID for now
		InteractionType: "property", // Default to property for topics
		InteractionName: topic.Name,
		Purpose:         forms.PurposeObservation,
		Direction:       forms.DirectionInput,
		StreamType:      types.BenthosStreamType(topic.Type),
		Metadata: map[string]interface{}{
			"original_topic_config": topic.Config,
		},
	}

	// Convert WoT form to input configuration
	inputConfig, err := s.convertFormToEndpointParams(form, true)
	if err != nil {
		return forms.StreamBuildConfig{}, fmt.Errorf("failed to convert form to input config: %w", err)
	}
	buildConfig.InputConfig = inputConfig

	// Set a default output configuration (could be stream_bridge or logging)
	buildConfig.OutputConfig = forms.StreamEndpointParams{
		Type: "stream_bridge",
		Config: map[string]interface{}{
			"topic": topic.Name + "_processed",
		},
	}

	return buildConfig, nil
}

// convertCommandToStreamBuildConfig converts a CommandStream to StreamBuildConfig
func (s *StreamService) convertCommandToStreamBuildConfig(command types.CommandStream) (forms.StreamBuildConfig, error) {
	// Extract forms from command configuration
	wotForms, ok := command.Config["forms"].([]wot.Form)
	if !ok || len(wotForms) == 0 {
		return forms.StreamBuildConfig{}, fmt.Errorf("no forms defined for command %s", command.Name)
	}

	// For simplicity, use the first form for now
	form := wotForms[0]

	// Extract basic information
	buildConfig := forms.StreamBuildConfig{
		ThingID:         command.Name, // Use command name as thing ID for now
		InteractionType: "action",     // Commands are actions
		InteractionName: command.Name,
		Purpose:         forms.PurposeCommand,
		Direction:       forms.DirectionOutput,
		StreamType:      types.BenthosStreamType(command.Type),
		Metadata: map[string]interface{}{
			"original_command_config": command.Config,
		},
	}

	// Convert WoT form to output configuration
	outputConfig, err := s.convertFormToEndpointParams(form, false)
	if err != nil {
		return forms.StreamBuildConfig{}, fmt.Errorf("failed to convert form to output config: %w", err)
	}
	buildConfig.OutputConfig = outputConfig

	// Set a default input configuration (could be stream_bridge or HTTP)
	buildConfig.InputConfig = forms.StreamEndpointParams{
		Type: "stream_bridge",
		Config: map[string]interface{}{
			"topic": command.Name + "_input",
		},
	}

	return buildConfig, nil
}

// convertFormToEndpointParams converts a WoT form to StreamEndpointParams
func (s *StreamService) convertFormToEndpointParams(form wot.Form, isInput bool) (forms.StreamEndpointParams, error) {
	href := form.GetHref()
	if href == "" {
		return forms.StreamEndpointParams{}, fmt.Errorf("form has no href")
	}

	// Determine protocol type from href
	var protocolType string
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		protocolType = "http"
	} else if strings.HasPrefix(href, "mqtt://") || strings.HasPrefix(href, "mqtts://") {
		protocolType = "mqtt"
	} else if strings.HasPrefix(href, "kafka://") {
		protocolType = "kafka"
	} else {
		// Default to HTTP
		protocolType = "http"
	}

	// Get content type
	contentType := form.GetContentType()
	if contentType == "" {
		contentType = "application/json"
	}

	// Create form configuration
	formConfig := forms.FormConfiguration{
		Href:        href,
		ContentType: contentType,
	}

	// Set method for HTTP
	if protocolType == "http" {
		if isInput {
			formConfig.Method = "GET" // Default for input
		} else {
			formConfig.Method = "POST" // Default for output
		}
	}

	return forms.StreamEndpointParams{
		Type:       protocolType,
		Protocol:   protocolType,
		Config:     make(map[string]interface{}),
		FormConfig: formConfig,
	}, nil
}

// convertStreamRequestToYAML converts a StreamCreationRequest to Benthos YAML
func (s *StreamService) convertStreamRequestToYAML(request *types.StreamCreationRequest) (string, error) {
	// This is a simplified conversion - in a real implementation,
	// you would use the existing stream manager's YAML generation logic

	var config string

	// Add input section
	if request.Input.Type != "" {
		config += fmt.Sprintf("input:\n  %s:\n", request.Input.Type)
		for k, v := range request.Input.Config {
			config += fmt.Sprintf("    %s: %v\n", k, v)
		}
	}

	// Add processor section
	if len(request.ProcessorChain) > 0 {
		config += "\npipeline:\n  processors:\n"
		for _, proc := range request.ProcessorChain {
			config += fmt.Sprintf("    - %s:\n", proc.Type)
			for k, v := range proc.Config {
				config += fmt.Sprintf("        %s: %v\n", k, v)
			}
		}
	}

	// Add output section
	if request.Output.Type != "" {
		config += fmt.Sprintf("\noutput:\n  %s:\n", request.Output.Type)
		for k, v := range request.Output.Config {
			config += fmt.Sprintf("    %s: %v\n", k, v)
		}
	}

	return config, nil
}
