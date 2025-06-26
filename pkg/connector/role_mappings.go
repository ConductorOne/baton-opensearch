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

	// Get the actual role to see what permissions it provides
	role, err := o.client.GetRole(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role: %w", err)
	}

	if role != nil {
		// Create individual entitlements for cluster permissions (for grant expansion)
		for _, perm := range role.ClusterPermissions {
			ent := entitlement.NewPermissionEntitlement(
				resource,
				fmt.Sprintf("cluster_permission:%s", perm),
				entitlement.WithGrantableTo(userResourceType),
			)
			entitlements = append(entitlements, ent)
		}

		// Create individual entitlements for index permissions (for grant expansion)
		for _, perm := range role.IndexPermissions {
			for _, action := range perm.AllowedActions {
				ent := entitlement.NewPermissionEntitlement(
					resource,
					fmt.Sprintf("index_permission:%s", action),
					entitlement.WithGrantableTo(userResourceType),
				)
				entitlements = append(entitlements, ent)
			}
		}
	}

	// Create entitlements for backend roles (external identity mappings)
	for _, backendRole := range roleMapping.BackendRoles {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			fmt.Sprintf("Backend Role Assignment: %s", backendRole),
			entitlement.WithGrantableTo(userResourceType),
		)
		entitlements = append(entitlements, ent)
	}

	// Create entitlements for direct user assignments
	for _, user := range roleMapping.Users {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			fmt.Sprintf("User Assignment: %s", user),
			entitlement.WithGrantableTo(userResourceType),
		)
		entitlements = append(entitlements, ent)
	}

	// Always create a basic role mapping entitlement even if no users are assigned
	// This shows what the role mapping provides
	basicEnt := entitlement.NewPermissionEntitlement(
		resource,
		"Role Mapping Access",
		entitlement.WithGrantableTo(userResourceType),
	)
	entitlements = append(entitlements, basicEnt)

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

	// Get the actual role to see what permissions it provides
	role, err := o.client.GetRole(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role: %w", err)
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

		// Add grant expansion annotation if the role has permissions
		if role != nil && (len(role.ClusterPermissions) > 0 || len(role.IndexPermissions) > 0) {
			// Create entitlement IDs for the permissions that this grant can expand into
			var expandableEntitlementIDs []string

			// Add cluster permission entitlements
			for _, perm := range role.ClusterPermissions {
				entitlementId := fmt.Sprintf("%s:cluster_permission:%s", resource.DisplayName, perm)
				expandableEntitlementIDs = append(expandableEntitlementIDs, entitlementId)
			}

			// Add index permission entitlements
			for _, perm := range role.IndexPermissions {
				for _, action := range perm.AllowedActions {
					entitlementId := fmt.Sprintf("%s:index_permission:%s", resource.DisplayName, action)
					expandableEntitlementIDs = append(expandableEntitlementIDs, entitlementId)
				}
			}

			// Add the grant expansion annotation
			expandable := &v2.GrantExpandable{
				EntitlementIds:  expandableEntitlementIDs,
				Shallow:         true,             // Only expand direct grants, not inherited ones
				ResourceTypeIds: []string{"user"}, // Only expand for user resources
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(expandable))
		}

		// Create the grant referencing the "User Assignment" entitlement
		userAssignmentEntitlementId := fmt.Sprintf("role_mapping:%s:User Assignment: %s", resource.DisplayName, username)
		userAssignmentEntitlement := &v2.Entitlement{
			Id:          userAssignmentEntitlementId,
			Resource:    resource,
			DisplayName: fmt.Sprintf("User Assignment: %s", username),
		}

		grant := grant.NewGrant(
			resource,
			fmt.Sprintf("%s:user:%s", resource.DisplayName, username),
			userResourceId,
			grantOpts...,
		)
		// Set the entitlement directly
		grant.Entitlement = userAssignmentEntitlement
		grants = append(grants, grant)
	}

	// Create grants for backend roles (external identity mappings)
	// This is common in SAML scenarios where backend roles come from the identity provider
	for _, backendRole := range roleMapping.BackendRoles {
		// Create a reference to a generic user resource for backend role matching
		userResourceId := &v2.ResourceId{
			ResourceType: "user",
			Resource:     fmt.Sprintf("backend_role:%s", backendRole),
		}

		// Create the grant with external resource matching annotation for backend role
		grantOpts := []grant.GrantOption{}

		// Add external resource matching annotation to match by backend role
		externalMatch := &v2.ExternalResourceMatch{
			ResourceType: v2.ResourceType_TRAIT_USER,
			Key:          "backend_role",
			Value:        backendRole,
		}
		grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))

		// Add grant expansion annotation if the role has permissions
		if role != nil && (len(role.ClusterPermissions) > 0 || len(role.IndexPermissions) > 0) {
			// Create entitlement IDs for the permissions that this grant can expand into
			var expandableEntitlementIDs []string

			// Add cluster permission entitlements
			for _, perm := range role.ClusterPermissions {
				entitlementId := fmt.Sprintf("%s:cluster_permission:%s", resource.DisplayName, perm)
				expandableEntitlementIDs = append(expandableEntitlementIDs, entitlementId)
			}

			// Add index permission entitlements
			for _, perm := range role.IndexPermissions {
				for _, action := range perm.AllowedActions {
					entitlementId := fmt.Sprintf("%s:index_permission:%s", resource.DisplayName, action)
					expandableEntitlementIDs = append(expandableEntitlementIDs, entitlementId)
				}
			}

			// Add the grant expansion annotation
			expandable := &v2.GrantExpandable{
				EntitlementIds:  expandableEntitlementIDs,
				Shallow:         true,             // Only expand direct grants, not inherited ones
				ResourceTypeIds: []string{"user"}, // Only expand for user resources
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(expandable))
		}

		// Create the grant referencing the backend role
		backendRoleEntitlementId := fmt.Sprintf("role_mapping:%s:Backend Role Assignment: %s", resource.DisplayName, backendRole)
		backendRoleEntitlement := &v2.Entitlement{
			Id:          backendRoleEntitlementId,
			Resource:    resource,
			DisplayName: fmt.Sprintf("Backend Role Assignment: %s", backendRole),
		}

		grant := grant.NewGrant(
			resource,
			fmt.Sprintf("%s:backend_role:%s", resource.DisplayName, backendRole),
			userResourceId,
			grantOpts...,
		)
		// Set the entitlement directly
		grant.Entitlement = backendRoleEntitlement
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
