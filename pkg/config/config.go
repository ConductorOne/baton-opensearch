package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	// Add the SchemaFields for the Config.
	addressField = field.StringField(
		"address",
		field.WithDescription("OpenSearch server address"),
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
	userMatchKeyField = field.StringField(
		"user-match-key",
		field.WithDescription("The field name to use for matching users (e.g. 'email', 'name', 'id'). Default is 'email'."),
		field.WithRequired(false),
		field.WithDefaultValue("email"),
		field.WithDisplayName("User match key"),
	)
	insecureSkipVerifyField = field.BoolField(
		"insecure-skip-verify",
		field.WithDescription("Skip TLS certificate verification."),
		field.WithRequired(false),
		field.WithDefaultValue(false),
		field.WithDisplayName("Insecure skip verify"),
	)
	caCertPathField = field.FileUploadField(
		"ca-cert-path",
		[]string{".pem"},
		field.WithDescription("PEM-encoded CA certificate for TLS connections"),
		field.WithRequired(false),
		field.WithIsSecret(true),
		field.WithDisplayName("CA Certificate"),
	)

	fieldRelationships = []field.SchemaFieldRelationship{
		field.FieldsAtLeastOneUsed(insecureSkipVerifyField, caCertPathField),
	}

	ConfigurationFields = []field.SchemaField{
		addressField,
		usernameField,
		passwordField,
		userMatchKeyField,
		insecureSkipVerifyField,
		caCertPathField,
	}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(fieldRelationships...),
	field.WithConnectorDisplayName("OpenSearch"),
	field.WithHelpUrl("/docs/baton/opensearch"),
	field.WithIconUrl("/static/app-icons/opensearch.svg"),
	field.WithSupportsExternalResources(true),
	field.WithRequiresExternalConnector(true),
)
