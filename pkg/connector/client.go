package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/opensearch-project/opensearch-go/v4"
)

type Client struct {
	client *opensearch.Client
}

func NewClient(addresses []string, username, password string) (*Client, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("at least one OpenSearch address is required")
	}

	// Create a custom transport with timeouts
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing only. Use certificate for validation in production.
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	config := opensearch.Config{
		Transport: transport,
		Addresses: addresses,
		Username:  username,
		Password:  password,
		// Enable retry on timeout
		EnableRetryOnTimeout: true,
		MaxRetries:           3,
		RetryOnStatus:        []int{502, 503, 504, 429},
	}

	client, err := opensearch.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenSearch client: %w", err)
	}

	return &Client{
		client: client,
	}, nil
}

// GetUsers retrieves all users from OpenSearch using the Security API
func (c *Client) GetUsers(ctx context.Context) ([]map[string]interface{}, error) {
	// No headers needed for GET
	req, err := opensearch.BuildRequest("GET", "/_plugins/_security/api/internalusers", nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	resp, err := c.client.Perform(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get users failed with status: %s, body: %s", resp.Status, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	users := make([]map[string]interface{}, 0, len(result))
	for username, userData := range result {
		userMap, ok := userData.(map[string]interface{})
		if !ok {
			continue
		}
		userMap["username"] = username
		users = append(users, userMap)
	}

	return users, nil
}
