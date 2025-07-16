package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

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
}

func NewClient(ctx context.Context, address string, username, password, userMatchKey string) (*Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing only. Use certificate for validation in production.
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

	return &Client{
		httpClient:   baseClient,
		baseURL:      parsedURL,
		username:     username,
		password:     password,
		userMatchKey: userMatchKey,
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

	usersUrl, err := getPath(c.baseURL.String(), "_plugins/_security/api/internalusers")
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

	rolesUrl, err := getPath(c.baseURL.String(), "_plugins/_security/api/roles")
	if err != nil {
		return nil, fmt.Errorf("failed to get roles url: %w", err)
	}

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
	rolesUrl, err := getPath(c.baseURL.String(), fmt.Sprintf("_plugins/_security/api/roles/%s", name))
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

	roleMappingsUrl, err := getPath(c.baseURL.String(), "_plugins/_security/api/rolesmapping")
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
	roleMappingUrl, err := getPath(c.baseURL.String(), fmt.Sprintf("_plugins/_security/api/rolesmapping/%s", name))
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
