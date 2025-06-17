package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type Client struct {
	httpClient *uhttp.BaseHttpClient
	baseURL    *url.URL
	username   string
	password   string
}

func NewClient(ctx context.Context, address string, username, password string) (*Client, error) {
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
		httpClient: baseClient,
		baseURL:    parsedURL,
		username:   username,
		password:   password,
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

	req, err := http.NewRequestWithContext(ctx, "GET", usersUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get users failed with status: %s, body: %s", resp.Status, string(body))
	}

	raw := map[string]User{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var users []User
	for username, user := range raw {
		user.Username = username
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

	req, err := http.NewRequestWithContext(ctx, "GET", rolesUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get roles failed with status: %s, body: %s", resp.Status, string(body))
	}

	raw := map[string]Role{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

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

	req, err := http.NewRequestWithContext(ctx, "GET", rolesUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get role failed with status: %s, body: %s", resp.Status, string(body))
	}

	role := &Role{}
	if err := json.NewDecoder(resp.Body).Decode(role); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	role.Name = name
	return role, nil
}
