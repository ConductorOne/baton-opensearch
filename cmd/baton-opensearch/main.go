//go:build !generate

package main

import (
	"context"
	"fmt"
	"os"

	cfg "github.com/conductorone/baton-opensearch/pkg/config"
	"github.com/conductorone/baton-opensearch/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		"baton-opensearch",
		getConnector,
		cfg.Config,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, osc *cfg.Opensearch) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	if err := field.Validate(cfg.Config, osc); err != nil {
		return nil, err
	}

	var address, username, password string
	address = osc.Address
	username = osc.Username
	password = osc.Password
	userMatchKey := osc.UserMatchKey
	insecureSkipVerify := osc.InsecureSkipVerify
	caCertPath := osc.CaCertPath

	// Process certificates if provided and not skipping verification
	var credentials []byte
	if !insecureSkipVerify {
		if caCertPath != "" {
			// Read certificate from file path
			l.Debug("reading certificate from file", zap.String("caCertPath", caCertPath))
			fileContent, err := os.ReadFile(caCertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read certificate file %s: %w", caCertPath, err)
			}
			l.Debug("successfully read certificate file")
			credentials = fileContent
		}
	}

	cb, err := connector.New(ctx, address, username, password, userMatchKey, insecureSkipVerify, credentials)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	return connector, nil
}
