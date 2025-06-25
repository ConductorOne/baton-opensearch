package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	client       *client.Client
	resourceType *v2.ResourceType
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var resources []*v2.Resource
	users, err := o.client.GetUsers(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get users: %w", err)
	}

	for _, user := range users {
		// Convert backend roles to interface{} slice
		backendRoles := make([]interface{}, len(user.BackendRoles))
		for i, role := range user.BackendRoles {
			backendRoles[i] = role
		}

		// Convert opendistro security roles to interface{} slice
		securityRoles := make([]interface{}, len(user.OpendistroSecurityRoles))
		for i, role := range user.OpendistroSecurityRoles {
			securityRoles[i] = role
		}

		// Convert attributes to map[string]interface{}
		attributes := make(map[string]interface{})
		for k, v := range user.Attributes {
			attributes[k] = v
		}

		// TODO [MB]: Figure out how to handle different role types. Figure out what useful info we may get from attributes.
		traitOpts := []resource.UserTraitOption{
			resource.WithUserProfile(map[string]interface{}{
				"display_name":              user.Username,
				"login":                     user.Username,
				"description":               user.Description,
				"reserved":                  user.Reserved, // Can't be changed.
				"hidden":                    user.Hidden,   // TODO [MB]: Don't need this since hidden users won't be returned by API.
				"static":                    user.Static,
				"backend_roles":             backendRoles,
				"opendistro_security_roles": securityRoles,
				"attributes":                attributes,
			}),
		}

		// Add email if present in attributes
		if email, ok := user.Attributes["email"].(string); ok && email != "" {
			traitOpts = append(traitOpts, resource.WithEmail(email, true))
		}

		userResource, err := resource.NewUserResource(
			user.Username,
			o.resourceType,
			user.Username,
			traitOpts,
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to create user resource: %w", err)
		}

		resources = append(resources, userResource)
	}

	return resources, "", nil, nil
}

// Entitlements always returns an empty slice for users.
func (o *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since access is granted through role mappings.
func (o *userBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newUserBuilder(client *client.Client) *userBuilder {
	return &userBuilder{
		client:       client,
		resourceType: userResourceType,
	}
}
