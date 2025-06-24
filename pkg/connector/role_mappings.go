package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type roleMappingBuilder struct {
	client       *client.Client
	resourceType *v2.ResourceType
}

func (o *roleMappingBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *roleMappingBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var resources []*v2.Resource
	roleMappings, err := o.client.GetRoleMappings(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role mappings: %w", err)
	}

	for _, roleMapping := range roleMappings {
		// Convert backend roles to interface{} slice for profile
		backendRoles := make([]interface{}, len(roleMapping.BackendRoles))
		for i, role := range roleMapping.BackendRoles {
			backendRoles[i] = role
		}

		// Convert users to interface{} slice for profile
		users := make([]interface{}, len(roleMapping.Users))
		for i, user := range roleMapping.Users {
			users[i] = user
		}

		// Convert hosts to interface{} slice for profile
		hosts := make([]interface{}, len(roleMapping.Hosts))
		for i, host := range roleMapping.Hosts {
			hosts[i] = host
		}

		// Convert and backend roles to interface{} slice for profile
		andBackendRoles := make([]interface{}, len(roleMapping.AndBackendRoles))
		for i, role := range roleMapping.AndBackendRoles {
			andBackendRoles[i] = role
		}

		roleMappingResource, err := resource.NewRoleResource(
			roleMapping.Name,
			o.resourceType,
			roleMapping.Name,
			[]resource.RoleTraitOption{
				resource.WithRoleProfile(map[string]interface{}{
					"display_name":      roleMapping.Name,
					"description":       fmt.Sprintf("Role mapping for %s", roleMapping.Name),
					"reserved":          roleMapping.Reserved,
					"hidden":            roleMapping.Hidden,
					"static":            roleMapping.Static,
					"backend_roles":     backendRoles,
					"users":             users,
					"hosts":             hosts,
					"and_backend_roles": andBackendRoles,
				}),
			},
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to create role mapping resource: %w", err)
		}

		resources = append(resources, roleMappingResource)
	}

	return resources, "", nil, nil
}

// Entitlements returns entitlements for role mappings.
func (o *roleMappingBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Get the role mapping from the client
	roleMapping, err := o.client.GetRoleMapping(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role mapping: %w", err)
	}

	if roleMapping == nil {
		return nil, "", nil, fmt.Errorf("role mapping not found: %s", resource.DisplayName)
	}

	// Create entitlements for backend roles
	for _, backendRole := range roleMapping.BackendRoles {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			fmt.Sprintf("Backend Role Assignment: %s", backendRole),
			entitlement.WithGrantableTo(userResourceType),
		)
		entitlements = append(entitlements, ent)
	}

	// Create entitlements for users
	for _, user := range roleMapping.Users {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			fmt.Sprintf("User Assignment: %s", user),
			entitlement.WithGrantableTo(userResourceType),
		)
		entitlements = append(entitlements, ent)
	}

	return entitlements, "", nil, nil
}

// Grants returns grants for role mappings.
func (o *roleMappingBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant

	// Get the role mapping from the client
	roleMapping, err := o.client.GetRoleMapping(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role mapping: %w", err)
	}

	if roleMapping == nil {
		return nil, "", nil, fmt.Errorf("role mapping not found: %s", resource.DisplayName)
	}

	// Create grants for users assigned to this role mapping
	for _, username := range roleMapping.Users {
		// Create a reference to the user resource by ID
		userResourceId := &v2.ResourceId{
			ResourceType: "user",
			Resource:     username,
		}

		// Create the grant with external resource matching annotation
		grantOpts := []grant.GrantOption{}

		// Add external resource matching annotation to match by username
		externalMatch := &v2.ExternalResourceMatch{
			ResourceType: v2.ResourceType_TRAIT_USER,
			Key:          "username",
			Value:        username,
		}
		grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))

		// Create the grant referencing the user by ID
		grant := grant.NewGrant(
			resource,
			fmt.Sprintf("%s:user:%s", resource.DisplayName, username),
			userResourceId,
			grantOpts...,
		)
		grants = append(grants, grant)
	}

	return grants, "", nil, nil
}

func newRoleMappingBuilder(client *client.Client) *roleMappingBuilder {
	return &roleMappingBuilder{
		client:       client,
		resourceType: roleMappingResourceType,
	}
}
