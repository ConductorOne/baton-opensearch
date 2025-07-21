package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name               string
		address            string
		username           string
		password           string
		userMatchKey       string
		insecureSkipVerify bool
		caCertPath         string
		caCert             string
		wantErr            bool
	}{
		{
			name:               "valid client with insecure skip verify",
			address:            "http://localhost:9200",
			username:           "admin",
			password:           "admin",
			userMatchKey:       "username",
			insecureSkipVerify: true,
			wantErr:            false,
		},
		{
			name:               "valid client with secure connection",
			address:            "https://localhost:9200",
			username:           "admin",
			password:           "admin",
			userMatchKey:       "username",
			insecureSkipVerify: false,
			wantErr:            false,
		},
		{
			name:               "invalid address",
			address:            "://invalid-url",
			username:           "admin",
			password:           "admin",
			userMatchKey:       "username",
			insecureSkipVerify: true,
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(context.Background(), tt.address, tt.username, tt.password, tt.userMatchKey, tt.insecureSkipVerify, tt.caCertPath, tt.caCert)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.username, client.username)
				assert.Equal(t, tt.password, client.password)
				assert.Equal(t, tt.userMatchKey, client.userMatchKey)
			}
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	tests := []struct {
		name               string
		insecureSkipVerify bool
		caCertPath         string
		caCert             string
		wantErr            bool
	}{
		{
			name:               "insecure skip verify",
			insecureSkipVerify: true,
			wantErr:            false,
		},
		{
			name:               "system cert pool",
			insecureSkipVerify: false,
			wantErr:            false,
		},
		{
			name:               "invalid CA cert path",
			insecureSkipVerify: false,
			caCertPath:         "/nonexistent/path",
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := getTLSConfig(tt.insecureSkipVerify, tt.caCertPath, tt.caCert)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, config)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
				if tt.insecureSkipVerify {
					assert.True(t, config.InsecureSkipVerify)
				} else {
					assert.False(t, config.InsecureSkipVerify)
				}
			}
		})
	}
}

func TestGetPath(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		elem    []string
		wantErr bool
	}{
		{
			name:    "valid path",
			base:    "http://localhost:9200",
			elem:    []string{"_plugins", "_security", "api", "users"},
			wantErr: false,
		},
		{
			name:    "invalid base URL",
			base:    "://invalid",
			elem:    []string{"test"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := getPath(tt.base, tt.elem...)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, url)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, url)
			}
		})
	}
}

func TestGetUserMatchKey(t *testing.T) {
	client := &Client{
		userMatchKey: "username",
	}
	assert.Equal(t, "username", client.GetUserMatchKey())
}
