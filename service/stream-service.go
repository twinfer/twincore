// internal/service/stream_service.go
package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

type StreamService struct {
	builder *service.StreamBuilder
	streams map[string]*service.Stream
	configs map[string]string // Store YAML configs
	mu      sync.RWMutex
	running bool
}

func NewStreamService() types.Service {
	return &StreamService{
		builder: service.NewStreamBuilder(),
		streams: make(map[string]*service.Stream),
		configs: make(map[string]string),
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

	// Extract stream configurations
	streamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		return fmt.Errorf("missing stream configuration")
	}

	// Process all topics
	for _, topic := range streamConfig.Topics {
		if err := s.createStreamFromTopic(ctx, topic); err != nil {
			s.stopAllStreams(ctx)
			return fmt.Errorf("failed to create stream for topic %s: %w", topic.Name, err)
		}
	}

	// Process all commands
	for _, command := range streamConfig.Commands {
		if err := s.createStreamFromCommand(ctx, command); err != nil {
			s.stopAllStreams(ctx)
			return fmt.Errorf("failed to create stream for command %s: %w", command.Name, err)
		}
	}

	s.running = true
	return nil
}

func (s *StreamService) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.stopAllStreams(ctx)
	s.running = false
	return nil
}

func (s *StreamService) UpdateConfig(config types.ServiceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("service not running")
	}

	// For updates, we'll stop affected streams and recreate them
	ctx := context.Background()

	streamConfig, ok := config.Config["stream"].(types.StreamConfig)
	if !ok {
		return fmt.Errorf("missing stream configuration")
	}

	// Update topics
	for _, topic := range streamConfig.Topics {
		// Stop existing stream if any
		if stream, exists := s.streams[topic.Name]; exists {
			stream.Stop(ctx)
			delete(s.streams, topic.Name)
		}

		// Create new stream
		if err := s.createStreamFromTopic(ctx, topic); err != nil {
			return fmt.Errorf("failed to update stream for topic %s: %w", topic.Name, err)
		}
	}

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
func (s *StreamService) createStreamFromTopic(ctx context.Context, topic types.StreamTopic) error {
	// Get form configurations from topic
	forms, ok := topic.Config["forms"].([]wot.Form)
	if !ok || len(forms) == 0 {
		return fmt.Errorf("no forms defined for topic %s", topic.Name)
	}

	// Get security definitions
	securityDefs, _ := topic.Config["securityDefinitions"].(map[string]wot.SecurityScheme)

	// Generate Benthos configuration from forms
	yamlConfig, err := s.generateConfigFromForms(forms, securityDefs, "topic")
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Build and run stream using StreamBuilder
	stream, err := s.builder.AddStreamFromConfig(topic.Name, yamlConfig)
	if err != nil {
		return fmt.Errorf("failed to build stream: %w", err)
	}

	if err := s.builder.RunStream(topic.Name); err != nil {
		return fmt.Errorf("failed to run stream: %w", err)
	}

	s.streams[topic.Name] = stream
	s.configs[topic.Name] = yamlConfig
	return nil
}

// createStreamFromCommand creates a Benthos stream from a WoT command configuration
func (s *StreamService) createStreamFromCommand(ctx context.Context, command types.CommandStream) error {
	forms, ok := command.Config["forms"].([]wot.Form)
	if !ok || len(forms) == 0 {
		return fmt.Errorf("no forms defined for command %s", command.Name)
	}

	securityDefs, _ := command.Config["securityDefinitions"].(map[string]wot.SecurityScheme)

	yamlConfig, err := s.generateConfigFromForms(forms, securityDefs, "command")
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	stream, err := s.builder.AddStreamFromConfig(command.Name, yamlConfig)
	if err != nil {
		return fmt.Errorf("failed to build stream: %w", err)
	}

	if err := s.builder.RunStream(command.Name); err != nil {
		return fmt.Errorf("failed to run stream: %w", err)
	}

	s.streams[command.Name] = stream
	s.configs[command.Name] = yamlConfig
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

// stopAllStreams stops all running streams
func (s *StreamService) stopAllStreams(ctx context.Context) {
	for name := range s.streams {
		if err := s.builder.StopStream(name, ctx); err != nil {
			fmt.Printf("Error stopping stream %s: %v\n", name, err)
		}
	}
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
