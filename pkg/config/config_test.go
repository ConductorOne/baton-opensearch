package config

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/stretchr/testify/assert"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Opensearch
		wantErr bool
	}{
		{
			name:   "valid config",
			config: &Opensearch{
				Address:  "http://localhost:9200",
				Username: "admin",
				Password: "admin",
			},
			wantErr: false,
		},
		{
			name:   "invalid config - missing required fields",
			config: &Opensearch{
				Address: "http://localhost:9200",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := field.Validate(Config, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), "username of type string is marked as required but it has a zero-value")
					assert.Contains(t, err.Error(), "password of type string is marked as required but it has a zero-value")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
