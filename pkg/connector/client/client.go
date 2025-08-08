package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type Client struct {
	httpClient   *uhttp.BaseHttpClient
	baseURL      *url.URL
	username     string
	password     string
	userMatchKey string
	securityPath string
}

func (c *Client) detectSecurityAPIPath(ctx context.Context) error {
	rootUrl, err := getPath(c.baseURL.String(), "/")
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rootUrl.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("unauthorized: check credentials")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var versionInfo struct {
		Version struct {
			Distribution string `json:"distribution"`
			Number       string `json:"number"`
		} `json:"version"`
	}

	if err := json.Unmarshal(body, &versionInfo); err != nil {
		return fmt.Errorf("failed to parse version info: %w", err)
	}

	// Check if distribution field exists and is "opensearch"
	if versionInfo.Version.Distribution != "" && strings.EqualFold(versionInfo.Version.Distribution, "opensearch") {
		c.securityPath = "/_plugins/_security/api"
	} else {
		// If there is no distribution field, or it is not "opensearch", use the OpenDistro security API for Elasticsearch
		c.securityPath = "/_opendistro/_security/api"
	}
	return nil
}

func NewClient(ctx context.Context, address string, username, password, userMatchKey string, insecureSkipVerify bool, credentials []byte) (*Client, error) {
	tlsConfig, err := getTLSConfig(ctx, insecureSkipVerify, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	baseClient, err := uhttp.NewBaseHttpClientWithContext(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create http client: %w", err)
	}

	parsedURL, err := url.Parse(address)
	if err != nil {
		return nil, err
	}

	c := &Client{
		httpClient:   baseClient,
		baseURL:      parsedURL,
		username:     username,
		password:     password,
		userMatchKey: userMatchKey,
		// Set a default security path in case detection fails
		securityPath: "/_plugins/_security/api",
	}

	// Try to detect the security API path, but don't fail if it doesn't work
	if err := c.detectSecurityAPIPath(ctx); err != nil {
		l := ctxzap.Extract(ctx)
		l.Debug("failed to detect security API path, using default", zap.Error(err))
		// Keep the default path that was set above
	}

	return c, nil
}

// getTLSConfig creates a TLS configuration based on the provided parameters.
func getTLSConfig(ctx context.Context, insecureSkipVerify bool, credentials []byte) (*tls.Config, error) {
	l := ctxzap.Extract(ctx)

	// If insecure skip verify is enabled, use minimal TLS config
	if insecureSkipVerify {
		l.Debug("insecureSkipVerify is true, returning minimal TLS config")
		return &tls.Config{
			InsecureSkipVerify: true, //#nosec G402 // Intentionally allowing insecure connections when requested
		}, nil
	}

	// If no certificate data provided, use the system certificate pool
	if len(credentials) == 0 {
		l.Debug("no certificate data provided, using system certificate pool")
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system certificate pool: %w", err)
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    systemPool,
		}, nil
	}

	// Use the provided certificate data
	l.Debug("using provided certificate data", zap.Int("bytes", len(credentials)))
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(credentials); !ok {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	l.Debug("returning TLS config with minimal version and root CA")
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}, nil
}

func getPath(base string, elem ...string) (*url.URL, error) {
	fullPath, err := url.JoinPath(base, elem...)
	if err != nil {
		return nil, err
	}

	return url.Parse(fullPath)
}

// GetUsers retrieves all users from OpenSearch using the Security API.
func (c *Client) GetUsers(ctx context.Context) ([]User, error) {
	l := ctxzap.Extract(ctx)

	usersUrl, err := getPath(c.baseURL.String(), c.securityPath, "internalusers")
	if err != nil {
		return nil, fmt.Errorf("failed to get users url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, usersUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	raw := map[string]User{}
	resp, err := c.httpClient.Do(req, uhttp.WithJSONResponse(&raw))
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer resp.Body.Close()

	var users []User
	for userIdentifier, user := range raw {
		user.UserIdentifier = userIdentifier
		users = append(users, user)
	}

	l.Debug("retrieved users", zap.Int("count", len(users)))
	return users, nil
}

// GetRoles retrieves all roles from OpenSearch using the Security API.
func (c *Client) GetRoles(ctx context.Context) ([]Role, error) {
	l := ctxzap.Extract(ctx)

	rolesUrl, err := getPath(c.baseURL.String(), c.securityPath, "roles")
	if err != nil {
		return nil, fmt.Errorf("failed to get roles url: %w", err)
	}

	l.Debug("making request to URL", zap.String("url", rolesUrl.String()))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rolesUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	raw := map[string]Role{}
	resp, err := c.httpClient.Do(req, uhttp.WithJSONResponse(&raw))
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	defer resp.Body.Close()

	var roles []Role
	for roleName, role := range raw {
		role.Name = roleName
		roles = append(roles, role)
	}

	l.Debug("retrieved roles", zap.Int("count", len(roles)))
	return roles, nil
}

// GetRole returns a single role by name.
func (c *Client) GetRole(ctx context.Context, name string) (*Role, error) {
	rolesUrl, err := getPath(c.baseURL.String(), c.securityPath, "roles", name)
	if err != nil {
		return nil, fmt.Errorf("failed to get role url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rolesUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	role := &Role{}
	resp, err := c.httpClient.Do(req, uhttp.WithJSONResponse(role))
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	defer resp.Body.Close()

	role.Name = name
	return role, nil
}

// GetRoleMappings retrieves all role mappings from OpenSearch using the Security API.
func (c *Client) GetRoleMappings(ctx context.Context) ([]RoleMapping, error) {
	l := ctxzap.Extract(ctx)

	roleMappingsUrl, err := getPath(c.baseURL.String(), c.securityPath, "rolesmapping")
	if err != nil {
		return nil, fmt.Errorf("failed to get role mappings url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, roleMappingsUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	raw := map[string]RoleMapping{}
	resp, err := c.httpClient.Do(req, uhttp.WithJSONResponse(&raw))
	if err != nil {
		return nil, fmt.Errorf("failed to get role mappings: %w", err)
	}
	defer resp.Body.Close()

	var roleMappings []RoleMapping
	for roleName, roleMapping := range raw {
		roleMapping.Name = roleName
		roleMappings = append(roleMappings, roleMapping)
	}

	l.Debug("retrieved role mappings", zap.Int("count", len(roleMappings)))
	return roleMappings, nil
}

// GetRoleMapping returns a single role mapping by name.
func (c *Client) GetRoleMapping(ctx context.Context, name string) (*RoleMapping, error) {
	roleMappingUrl, err := getPath(c.baseURL.String(), c.securityPath, "rolesmapping", name)
	if err != nil {
		return nil, fmt.Errorf("failed to get role mapping url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, roleMappingUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	// The API returns a nested structure: {"role_name": {...}}
	raw := map[string]RoleMapping{}
	resp, err := c.httpClient.Do(req, uhttp.WithJSONResponse(&raw))
	if err != nil {
		return nil, fmt.Errorf("failed to get role mapping: %w", err)
	}
	defer resp.Body.Close()

	// Extract the role mapping from the nested structure
	roleMapping, exists := raw[name]
	if !exists {
		return nil, fmt.Errorf("role mapping %s not found in response", name)
	}

	roleMapping.Name = name
	return &roleMapping, nil
}

func (c *Client) GetUserMatchKey() string {
	return c.userMatchKey
}
