package connector

import (
	"context"
	"fmt"
	"io"

	cfg "github.com/conductorone/baton-opensearch/pkg/config"
	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

type Connector struct {
	client *client.Client
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		newRoleBuilder(d.client),
	}
}

// Asset takes an input AssetRef and attempts to fetch it using the connector's authenticated http client
// It streams a response, always starting with a metadata object, following by chunked payloads for the asset.
func (d *Connector) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "OpenSearch Connector",
		Description: "A connector for OpenSearch that syncs users and their permissions",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, cc *cfg.Opensearch, _ *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	var credentials []byte
	if cc.InsecureSkipVerify {
		if len(cc.CaCertPath) > 0 {
			ctxzap.Extract(ctx).Warn("baton-opensearch: ca-cert-path is ignored because insecure-skip-verify is enabled")
		}
	} else {
		credentials = cc.CaCertPath
	}

	client, err := client.NewClient(ctx, cc.Address, cc.Username, cc.Password, cc.UserMatchKey, cc.InsecureSkipVerify, credentials)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-opensearch: failed to create client: %w", err)
	}

	return &Connector{
		client: client,
	}, nil, nil
}
