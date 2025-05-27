// internal/service/stream_service.go
package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

type StreamService struct {
	env     *service.Environment
	streams map[string]*service.Stream
	configs map[string]string // Store YAML configs
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *logrus.Logger
}

// NewStreamService creates a new StreamService.
// It requires a Benthos service environment to build streams.
func NewStreamService(env *service.Environment, logger *logrus.Logger) types.Service {
	return &StreamService{
		env:     env,
		streams: make(map[string]*service.Stream),
		configs: make(map[string]string), // To store YAML for potential debugging or re-config
		logger:  logger,
	}
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

	// Initialize context for managing stream lifecycles
	s.ctx, s.cancel = context.WithCancel(ctx) // Use the provided context for cancellation

	// Extract stream configurations
	streamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		s.logger.Info("StreamService: No 'stream' configuration found. Service will run without streams.")
		// If no stream config, there's nothing to do, but service can still be "running"
		s.running = true
		return nil // Or return an error if stream config is mandatory
	}

	// Process all topics
	for _, topic := range streamConfig.Topics {
		if err := s.createStreamFromTopic(topic); err != nil {
			s.stopAllStreams(context.Background()) // Use background context for cleanup
			s.cancel()                             // Cancel the main context
			s.logger.WithError(err).Errorf("StreamService: Failed to start stream for topic %s", topic.Name)
			return fmt.Errorf("failed to create stream for topic %s: %w", topic.Name, err)
		}
	}

	// Process all commands
	for _, command := range streamConfig.Commands {
		if err := s.createStreamFromCommand(command); err != nil {
			s.stopAllStreams(context.Background()) // Use background context for cleanup
			s.cancel()                             // Cancel the main context
			s.logger.WithError(err).Errorf("StreamService: Failed to start stream for command %s", command.Name)
			return fmt.Errorf("failed to create stream for command %s: %w", command.Name, err)
		}
	}

	s.running = true
	s.logger.Info("StreamService started successfully.")
	return nil
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

	newStreamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		// If new config has no stream section, stop all existing streams
		s.logger.Info("StreamService: New configuration has no 'stream' section. Stopping all existing streams.")
		s.stopAllStreams(context.Background())
		s.configs = make(map[string]string) // Clear stored configs
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

	existingStreamNames := make(map[string]struct{})
	for name := range s.streams {
		existingStreamNames[name] = struct{}{}
	}

	// Stop and remove streams that are not in the new config
	for name, stream := range s.streams {
		_, isTopic := newTopics[name]
		_, isCommand := newCommands[name]
		if !isTopic && !isCommand {
			// Stream is not in the new config, stop and remove it
			// Use a background context for stopping individual streams during an update
			if err := stream.Stop(context.Background()); err != nil {
				// Log error but continue, attempt to update other streams
				s.logger.WithError(err).Errorf("StreamService: Error stopping stream %s during config update", name)
			}
			delete(s.streams, name)
			delete(s.configs, name)
		}
	}

	// Update existing or create new topic streams
	for _, topic := range newStreamConfig.Topics {
		if oldStream, exists := s.streams[topic.Name]; exists {
			// Check if config has changed (simplified check: assume any mention means re-create)
			// A more sophisticated check would compare old and new YAML/config structures.
			// For now, always stop and re-create if it exists in the new config.
			s.logger.Debugf("StreamService: Re-creating stream for topic %s", topic.Name)
			if err := oldStream.Stop(context.Background()); err != nil {
				s.logger.WithError(err).Warnf("StreamService: Error stopping existing stream %s for update. Will attempt to re-create.", topic.Name)
				// Continue to try and create the new one
			}
			delete(s.streams, topic.Name) // Remove before re-creating
		}
		if err := s.createStreamFromTopic(topic); err != nil {
			s.logger.WithError(err).Errorf("StreamService: Failed to update/create stream for topic %s", topic.Name)
			// Consider if partial update is acceptable or if we should roll back/stop service
		}
	}

	// Update existing or create new command streams
	for _, command := range newStreamConfig.Commands {
		s.logger.Debugf("StreamService: Re-creating stream for command %s", command.Name)
		if oldStream, exists := s.streams[command.Name]; exists {
			if err := oldStream.Stop(context.Background()); err != nil {
				s.logger.WithError(err).Warnf("StreamService: Error stopping existing stream %s for update. Will attempt to re-create.", command.Name)
			}
			delete(s.streams, command.Name) // Remove before re-creating
		}
		if err := s.createStreamFromCommand(command); err != nil {
			s.logger.WithError(err).Errorf("StreamService: Failed to update/create stream for command %s", command.Name)
		}
	}
	s.logger.Info("StreamService configuration updated.")

	return nil
}

func (s *StreamService) HealthCheck() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return fmt.Errorf("service not running")
	}

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
