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
	caCertPathStr := osc.CaCertPath

	l.Debug("ConductorOne config", zap.String("Address", address), zap.String("Username", username), zap.Bool("InsecureSkipVerify", insecureSkipVerify), zap.String("CaCertPath", caCertPathStr))

	// If insecure skip verify is true, ignore any certificate path
	var caCertPath []byte
	if !insecureSkipVerify && caCertPathStr != "" {
		// Only process certificate if we're not skipping verification
		l.Debug("certificate provided but not processing due to insecure skip verify")
		caCertPath = []byte(caCertPathStr)
	}

	cb, err := connector.New(ctx, address, username, password, userMatchKey, insecureSkipVerify, caCertPath)
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
