package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	client       *client.Client
	resourceType *v2.ResourceType
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

// List returns all the users from OpenSearch as resource objects.
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

		userResource, err := resource.NewUserResource(
			user.Username,
			o.resourceType,
			user.Username,
			[]resource.UserTraitOption{
				resource.WithUserProfile(map[string]interface{}{
					"display_name":              user.Username,
					"login":                     user.Username,
					"description":               user.Description,
					"reserved":                  user.Reserved,
					"hidden":                    user.Hidden,
					"static":                    user.Static,
					"backend_roles":             backendRoles,
					"opendistro_security_roles": securityRoles,
					"attributes":                attributes,
				}),
			},
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

// Grants returns the grants for a user.
func (o *userBuilder) Grants(ctx context.Context, userResource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant

	// Get the user's backend roles from their profile
	userTrait, err := resource.GetUserTrait(userResource)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get user trait: %w", err)
	}

	backendRolesList := userTrait.Profile.Fields["backend_roles"].GetListValue()
	if backendRolesList == nil {
		return nil, "", nil, fmt.Errorf("failed to get backend roles")
	}

	// Get all roles to find the role resources
	roles, err := o.client.GetRoles(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get roles: %w", err)
	}

	// Create a grant for each backend role
	for _, roleValue := range backendRolesList.Values {
		roleName := roleValue.GetStringValue()

		// Find the role resource
		var roleResource *v2.Resource
		for _, role := range roles {
			if role.Name == roleName {
				roleResource, err = resource.NewRoleResource(
					role.Name,
					roleResourceType,
					role.Name,
					[]resource.RoleTraitOption{
						resource.WithRoleProfile(map[string]interface{}{
							"description": role.Description,
							"hidden":      role.Hidden,
							"static":      role.Static,
						}),
					},
				)
				if err != nil {
					return nil, "", nil, fmt.Errorf("failed to create role resource: %w", err)
				}
				break
			}
		}

		if roleResource == nil {
			continue // Skip if role not found
		}

		// Create the grant
		grant := grant.NewGrant(
			userResource,
			fmt.Sprintf("%s:role", roleName),
			roleResource,
		)
		grants = append(grants, grant)
	}

	return grants, "", nil, nil
}

func newUserBuilder(client *client.Client) *userBuilder {
	return &userBuilder{
		client:       client,
		resourceType: userResourceType,
	}
}
