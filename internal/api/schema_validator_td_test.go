package api

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/twinfer/twincore/pkg/wot"
)

func TestJSONSchemaValidator_ValidateThingDescription(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	validator := NewJSONSchemaValidator()

	tests := []struct {
		name    string
		td      *wot.ThingDescription
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid minimal TD",
			td: &wot.ThingDescription{
				Context:  "https://www.w3.org/2022/wot/td/v1.1",
				Title:    "Test Thing",
				Security: []string{"nosec"},
				SecurityDefinitions: map[string]wot.SecurityScheme{
					"nosec": {
						Scheme: "nosec",
					},
				},
				Properties: map[string]*wot.PropertyAffordance{
					"dummy": {
						InteractionAffordance: wot.InteractionAffordance{
							Forms: []wot.Form{
								&wot.TestForm{
									HrefValue:        "http://example.com/properties/dummy",
									ContentTypeValue: "application/json",
									OpValue:          []string{"readproperty"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid TD with properties",
			td: &wot.ThingDescription{
				Context:  "https://www.w3.org/2022/wot/td/v1.1",
				ID:       "urn:example:thing123",
				Title:    "Test Thing with Properties",
				Security: []string{"basic_sc"},
				SecurityDefinitions: map[string]wot.SecurityScheme{
					"basic_sc": {
						Scheme: "basic",
						In:     "header",
					},
				},
				Properties: map[string]*wot.PropertyAffordance{
					"temperature": {
						InteractionAffordance: wot.InteractionAffordance{
							Title:       "Temperature",
							Description: "Current temperature value",
							Forms: []wot.Form{
								&wot.TestForm{
									HrefValue:        "http://example.com/properties/temperature",
									ContentTypeValue: "application/json",
									OpValue:          []string{"readproperty"},
								},
							},
						},
						DataSchemaCore: wot.DataSchemaCore{
							Type: "number",
							Unit: "celsius",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Missing title",
			td: &wot.ThingDescription{
				Context:  "https://www.w3.org/2022/wot/td/v1.1",
				Security: []string{"nosec"},
				SecurityDefinitions: map[string]wot.SecurityScheme{
					"nosec": {
						Scheme: "nosec",
					},
				},
			},
			wantErr: true,
			errMsg:  "missing mandatory 'title' field",
		},
		{
			name: "Missing security",
			td: &wot.ThingDescription{
				Context:             "https://www.w3.org/2022/wot/td/v1.1",
				Title:               "Test Thing",
				SecurityDefinitions: map[string]wot.SecurityScheme{},
			},
			wantErr: true,
			errMsg:  "missing mandatory 'security' field",
		},
		{
			name: "Missing context",
			td: &wot.ThingDescription{
				Title:               "Test Thing",
				Security:            []string{"nosec"},
				SecurityDefinitions: map[string]wot.SecurityScheme{},
			},
			wantErr: true,
			errMsg:  "missing mandatory '@context' field",
		},
		{
			name: "Undefined security scheme",
			td: &wot.ThingDescription{
				Context:  "https://www.w3.org/2022/wot/td/v1.1",
				Title:    "Test Thing",
				Security: []string{"undefined_scheme"},
				SecurityDefinitions: map[string]wot.SecurityScheme{
					"basic_sc": {
						Scheme: "basic",
					},
				},
				Properties: map[string]*wot.PropertyAffordance{
					"test": {
						InteractionAffordance: wot.InteractionAffordance{
							Forms: []wot.Form{
								&wot.TestForm{
									HrefValue: "http://example.com/test",
									OpValue:   []string{"readproperty"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "security scheme 'undefined_scheme' is not defined",
		},
		{
			name: "Invalid property operation",
			td: &wot.ThingDescription{
				Context:             "https://www.w3.org/2022/wot/td/v1.1",
				Title:               "Test Thing",
				Security:            []string{"nosec"},
				SecurityDefinitions: map[string]wot.SecurityScheme{},
				Properties: map[string]*wot.PropertyAffordance{
					"test": {
						InteractionAffordance: wot.InteractionAffordance{
							Forms: []wot.Form{
								&wot.TestForm{
									HrefValue: "http://example.com/test",
									OpValue:   []string{"invokeaction"}, // Invalid for property
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "must be one of the following: \"readproperty\", \"writeproperty\", \"observeproperty\", \"unobserveproperty\"",
		},
		{
			name: "Property without forms",
			td: &wot.ThingDescription{
				Context:             "https://www.w3.org/2022/wot/td/v1.1",
				Title:               "Test Thing",
				Security:            []string{"nosec"},
				SecurityDefinitions: map[string]wot.SecurityScheme{},
				Properties: map[string]*wot.PropertyAffordance{
					"test": {
						InteractionAffordance: wot.InteractionAffordance{
							Forms: []wot.Form{}, // Empty forms
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "Array must have at least 1 items",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateThingDescription(logger, tt.td)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
