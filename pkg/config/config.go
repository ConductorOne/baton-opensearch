package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	// Add the SchemaFields for the Config.
	addressField  = field.StringField(
		"address",
		field.WithDescription("OpenSearch server address (e.g. http://localhost:9200)"),
		field.WithRequired(true),
		field.WithDisplayName("Address"),
	)
	usernameField = field.StringField(
		"username",
		field.WithDescription("OpenSearch username"),
		field.WithRequired(true),
		field.WithDisplayName("Username"),
	)
	passwordField = field.StringField(
		"password",
		field.WithDescription("OpenSearch password"),
		field.WithRequired(true),
		field.WithIsSecret(true),
		field.WithDisplayName("Password"),
	)

	ConfigurationFields = []field.SchemaField{
		addressField,
		usernameField,
		passwordField,
	}
)

//go:generate go run -tags=generate ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConnectorDisplayName("OpenSearch"),
	field.WithHelpUrl("/docs/baton/opensearch"),
	field.WithIconUrl("/static/app-icons.opensearch.svg"),
)
