package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/stretchr/testify/assert"
)

// createTestServer creates a test server with the given response or behavior.
func createTestServer(mockResponse interface{}, serverBehavior func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	if serverBehavior != nil {
		return httptest.NewServer(http.HandlerFunc(serverBehavior))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name               string
		address            string
		username           string
		password           string
		userMatchKey       string
		insecureSkipVerify bool
		caCertData         []byte
		wantErr            bool
	}{
		{
			name:               "valid client with insecure skip verify",
			address:            "http://localhost:9200",
			username:           "admin",
			password:           "admin",
			userMatchKey:       "username",
			insecureSkipVerify: true,
			caCertData:         nil,
			wantErr:            false,
		},
		{
			name:               "valid client with secure connection",
			address:            "https://localhost:9200",
			username:           "admin",
			password:           "admin",
			userMatchKey:       "username",
			insecureSkipVerify: false,
			caCertData:         nil,
			wantErr:            false,
		},
		{
			name:               "invalid address",
			address:            "://invalid-url",
			username:           "admin",
			password:           "admin",
			userMatchKey:       "username",
			insecureSkipVerify: true,
			caCertData:         nil,
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(context.Background(), tt.address, tt.username, tt.password, tt.userMatchKey, tt.insecureSkipVerify, tt.caCertData)
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
		credentials        []byte
		wantErr            bool
	}{
		{
			name:               "insecure skip verify",
			insecureSkipVerify: true,
			credentials:        nil,
			wantErr:            false,
		},
		{
			name:               "system cert pool",
			insecureSkipVerify: false,
			credentials:        nil,
			wantErr:            false,
		},
		{
			name:               "invalid CA cert data",
			insecureSkipVerify: false,
			credentials:        []byte("invalid-certificate-data"),
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := getTLSConfig(context.Background(), tt.insecureSkipVerify, tt.credentials)
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

func TestDetectSecurityAPIPath(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   interface{}
		expectedPath   string
		expectError    bool
		serverBehavior func(w http.ResponseWriter, r *http.Request)
	}{
		{
			name: "opensearch distribution",
			mockResponse: map[string]interface{}{
				"version": map[string]interface{}{
					"distribution": "opensearch",
					"number":       "2.0.0",
				},
			},
			expectedPath: "/_plugins/_security/api",
			expectError:  false,
		},
		{
			name: "elasticsearch with no distribution field",
			mockResponse: map[string]interface{}{
				"version": map[string]interface{}{
					"number": "7.10.2",
				},
			},
			expectedPath: "/_opendistro/_security/api",
			expectError:  false,
		},
		{
			name: "elasticsearch with different distribution",
			mockResponse: map[string]interface{}{
				"version": map[string]interface{}{
					"distribution": "elasticsearch",
					"number":       "7.10.2",
				},
			},
			expectedPath: "/_opendistro/_security/api",
			expectError:  false,
		},
		{
			name: "empty version info",
			mockResponse: map[string]interface{}{
				"version": map[string]interface{}{},
			},
			expectedPath: "/_opendistro/_security/api",
			expectError:  false,
		},
		{
			name: "unauthorized response",
			serverBehavior: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectedPath: "/_plugins/_security/api", // Should use default
			expectError:  true,
		},
		{
			name: "invalid JSON response",
			serverBehavior: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("invalid json"))
			},
			expectedPath: "/_plugins/_security/api", // Should use default
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := createTestServer(tt.mockResponse, tt.serverBehavior)
			defer server.Close()

			// Create client with test server URL
			parsedURL, _ := url.Parse(server.URL)

			// Create a proper HTTP client for testing
			httpClient := &http.Client{}
			baseClient, _ := uhttp.NewBaseHttpClientWithContext(context.Background(), httpClient)

			client := &Client{
				httpClient:   baseClient,
				baseURL:      parsedURL,
				username:     "test",
				password:     "test",
				securityPath: "/_plugins/_security/api", // Default path
			}

			// Test the detection
			err := client.detectSecurityAPIPath(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				// Should still have the default path
				assert.Equal(t, "/_plugins/_security/api", client.securityPath)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPath, client.securityPath)
			}
		})
	}
}

func TestNewClientWithSecurityPathDetection(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   interface{}
		expectedPath   string
		expectError    bool
		serverBehavior func(w http.ResponseWriter, r *http.Request)
	}{
		{
			name: "successful opensearch detection",
			mockResponse: map[string]interface{}{
				"version": map[string]interface{}{
					"distribution": "opensearch",
					"number":       "2.0.0",
				},
			},
			expectedPath: "/_plugins/_security/api",
			expectError:  false,
		},
		{
			name: "successful elasticsearch detection",
			mockResponse: map[string]interface{}{
				"version": map[string]interface{}{
					"number": "7.10.2",
				},
			},
			expectedPath: "/_opendistro/_security/api",
			expectError:  false,
		},
		{
			name: "detection fails but client still created",
			serverBehavior: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedPath: "/_plugins/_security/api", // Should use default
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := createTestServer(tt.mockResponse, tt.serverBehavior)
			defer server.Close()

			// Create client
			client, err := NewClient(
				context.Background(),
				server.URL,
				"test",
				"test",
				"username",
				true, // insecureSkipVerify
				nil,  // no cert data
			)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.expectedPath, client.securityPath)
			}
		})
	}
}

func TestGetPathWithSecurityPath(t *testing.T) {
	tests := []struct {
		name         string
		base         string
		securityPath string
		endpoint     string
		expected     string
		wantErr      bool
	}{
		{
			name:         "opensearch users endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			endpoint:     "internalusers",
			expected:     "https://localhost:9200/_plugins/_security/api/internalusers",
			wantErr:      false,
		},
		{
			name:         "elasticsearch users endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_opendistro/_security/api",
			endpoint:     "internalusers",
			expected:     "https://localhost:9200/_opendistro/_security/api/internalusers",
			wantErr:      false,
		},
		{
			name:         "opensearch roles endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			endpoint:     "roles",
			expected:     "https://localhost:9200/_plugins/_security/api/roles",
			wantErr:      false,
		},
		{
			name:         "elasticsearch roles endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_opendistro/_security/api",
			endpoint:     "roles",
			expected:     "https://localhost:9200/_opendistro/_security/api/roles",
			wantErr:      false,
		},
		{
			name:         "opensearch specific role endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			endpoint:     "roles/admin",
			expected:     "https://localhost:9200/_plugins/_security/api/roles/admin",
			wantErr:      false,
		},
		{
			name:         "opensearch specific role endpoint with separate segments",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			endpoint:     "roles",
			expected:     "https://localhost:9200/_plugins/_security/api/roles",
			wantErr:      false,
		},
		{
			name:         "elasticsearch specific role endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_opendistro/_security/api",
			endpoint:     "roles/admin",
			expected:     "https://localhost:9200/_opendistro/_security/api/roles/admin",
			wantErr:      false,
		},
		{
			name:         "opensearch role mappings endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			endpoint:     "rolesmapping",
			expected:     "https://localhost:9200/_plugins/_security/api/rolesmapping",
			wantErr:      false,
		},
		{
			name:         "elasticsearch role mappings endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_opendistro/_security/api",
			endpoint:     "rolesmapping",
			expected:     "https://localhost:9200/_opendistro/_security/api/rolesmapping",
			wantErr:      false,
		},
		{
			name:         "opensearch specific role mapping endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			endpoint:     "rolesmapping/admin",
			expected:     "https://localhost:9200/_plugins/_security/api/rolesmapping/admin",
			wantErr:      false,
		},
		{
			name:         "elasticsearch specific role mapping endpoint",
			base:         "https://localhost:9200",
			securityPath: "/_opendistro/_security/api",
			endpoint:     "rolesmapping/admin",
			expected:     "https://localhost:9200/_opendistro/_security/api/rolesmapping/admin",
			wantErr:      false,
		},
		{
			name:         "invalid base URL",
			base:         "://invalid",
			securityPath: "/_plugins/_security/api",
			endpoint:     "roles",
			expected:     "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the path construction that matches how it's used in the client
			url, err := getPath(tt.base, tt.securityPath, tt.endpoint)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, url)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, url)
				assert.Equal(t, tt.expected, url.String())
			}
		})
	}
}

func TestGetPathWithMultipleSegments(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		segments []string
		expected string
		wantErr  bool
	}{
		{
			name:     "opensearch path with multiple segments",
			base:     "https://localhost:9200",
			segments: []string{"/_plugins/_security/api", "roles", "admin"},
			expected: "https://localhost:9200/_plugins/_security/api/roles/admin",
			wantErr:  false,
		},
		{
			name:     "elasticsearch path with multiple segments",
			base:     "https://localhost:9200",
			segments: []string{"/_opendistro/_security/api", "roles", "admin"},
			expected: "https://localhost:9200/_opendistro/_security/api/roles/admin",
			wantErr:  false,
		},
		{
			name:     "path with leading slash in segments",
			base:     "https://localhost:9200",
			segments: []string{"/_plugins/_security/api", "/roles", "/admin"},
			expected: "https://localhost:9200/_plugins/_security/api/roles/admin",
			wantErr:  false,
		},
		{
			name:     "path with trailing slash in base",
			base:     "https://localhost:9200/",
			segments: []string{"_plugins/_security/api", "roles", "admin"},
			expected: "https://localhost:9200/_plugins/_security/api/roles/admin",
			wantErr:  false,
		},
		{
			name:     "specific role with opensearch path",
			base:     "https://localhost:9200",
			segments: []string{"/_plugins/_security/api", "roles", "admin"},
			expected: "https://localhost:9200/_plugins/_security/api/roles/admin",
			wantErr:  false,
		},
		{
			name:     "specific role with elasticsearch path",
			base:     "https://localhost:9200",
			segments: []string{"/_opendistro/_security/api", "roles", "admin"},
			expected: "https://localhost:9200/_opendistro/_security/api/roles/admin",
			wantErr:  false,
		},
		{
			name:     "specific role mapping with opensearch path",
			base:     "https://localhost:9200",
			segments: []string{"/_plugins/_security/api", "rolesmapping", "admin"},
			expected: "https://localhost:9200/_plugins/_security/api/rolesmapping/admin",
			wantErr:  false,
		},
		{
			name:     "specific role mapping with elasticsearch path",
			base:     "https://localhost:9200",
			segments: []string{"/_opendistro/_security/api", "rolesmapping", "admin"},
			expected: "https://localhost:9200/_opendistro/_security/api/rolesmapping/admin",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := getPath(tt.base, tt.segments...)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, url)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, url)
				assert.Equal(t, tt.expected, url.String())
			}
		})
	}
}

func TestGetPathExactClientUsage(t *testing.T) {
	tests := []struct {
		name         string
		base         string
		securityPath string
		resourceType string
		resourceName string
		expected     string
		wantErr      bool
	}{
		{
			name:         "GetRole - opensearch",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			resourceType: "roles",
			resourceName: "admin",
			expected:     "https://localhost:9200/_plugins/_security/api/roles/admin",
			wantErr:      false,
		},
		{
			name:         "GetRole - elasticsearch",
			base:         "https://localhost:9200",
			securityPath: "/_opendistro/_security/api",
			resourceType: "roles",
			resourceName: "admin",
			expected:     "https://localhost:9200/_opendistro/_security/api/roles/admin",
			wantErr:      false,
		},
		{
			name:         "GetRoleMapping - opensearch",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			resourceType: "rolesmapping",
			resourceName: "admin",
			expected:     "https://localhost:9200/_plugins/_security/api/rolesmapping/admin",
			wantErr:      false,
		},
		{
			name:         "GetRoleMapping - elasticsearch",
			base:         "https://localhost:9200",
			securityPath: "/_opendistro/_security/api",
			resourceType: "rolesmapping",
			resourceName: "admin",
			expected:     "https://localhost:9200/_opendistro/_security/api/rolesmapping/admin",
			wantErr:      false,
		},
		{
			name:         "GetRole with special characters in name",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			resourceType: "roles",
			resourceName: "admin-role",
			expected:     "https://localhost:9200/_plugins/_security/api/roles/admin-role",
			wantErr:      false,
		},
		{
			name:         "GetRole with underscore in name",
			base:         "https://localhost:9200",
			securityPath: "/_plugins/_security/api",
			resourceType: "roles",
			resourceName: "admin_role",
			expected:     "https://localhost:9200/_plugins/_security/api/roles/admin_role",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the exact pattern used in GetRole and GetRoleMapping:
			// getPath(c.baseURL.String(), c.securityPath, resourceType, resourceName)
			url, err := getPath(tt.base, tt.securityPath, tt.resourceType, tt.resourceName)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, url)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, url)
				assert.Equal(t, tt.expected, url.String())
			}
		})
	}
}
