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

type roleBuilder struct {
	client       *client.Client
	resourceType *v2.ResourceType
}

func (o *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var resources []*v2.Resource
	roles, err := o.client.GetRoles(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get roles: %w", err)
	}

	for _, role := range roles {
		traitOpts := []resource.RoleTraitOption{
			resource.WithRoleProfile(map[string]interface{}{
				"description": role.Description,
				"hidden":      role.Hidden, // TODO [MB]: Don't need this since hidden roles won't be returned by API.
				"static":      role.Static,
			}),
		}
		roleResource, err := resource.NewRoleResource(
			role.Name,
			o.resourceType,
			role.Name,
			traitOpts,
		)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to create role resource: %w", err)
		}

		resources = append(resources, roleResource)
	}

	return resources, "", nil, nil
}

// Entitlements returns entitlements for roles based on their role mappings and permissions.
func (o *roleBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Get the role mapping from the client
	roleMapping, err := o.client.GetRoleMapping(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role mapping: %w", err)
	}

	// Get the actual role to see what permissions it provides
	role, err := o.client.GetRole(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Only create entitlements if we have both a role and a role mapping
	if role != nil && roleMapping != nil {
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

		// Create entitlements for backend roles (treating them as groups)
		for _, backendRole := range roleMapping.BackendRoles {
			ent := entitlement.NewPermissionEntitlement(
				resource,
				fmt.Sprintf("Group Assignment: %s", backendRole),
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
	}

	return entitlements, "", nil, nil
}

// Grants returns grants for roles based on their role mappings.
func (o *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant

	// Get the role mapping from the client
	roleMapping, err := o.client.GetRoleMapping(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role mapping: %w", err)
	}

	// Get the actual role to see what permissions it provides
	role, err := o.client.GetRole(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Only create grants if we have both a role and a role mapping
	if role != nil && roleMapping != nil {
		// Create grants for backend roles (treating them as groups)
		// These will be matched by external resource matching in baton-sdk
		for _, backendRole := range roleMapping.BackendRoles {
			// Create a reference to a user resource (the grant target)
			// The external match annotation will handle the group-to-user mapping
			userResourceId := &v2.ResourceId{
				ResourceType: "user",
				Resource:     fmt.Sprintf("group_member:%s", backendRole),
			}

			grantOpts := []grant.GrantOption{}

			// Add external resource matching annotation to match by group membership
			// This tells baton-sdk: "any user who is a member of this group should get this grant"
			externalMatch := &v2.ExternalResourceMatch{
				ResourceType: v2.ResourceType_TRAIT_GROUP,
				Key:          "name",
				Value:        backendRole,
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))

			// Add grant expansion annotation if the role has permissions
			if len(role.ClusterPermissions) > 0 || len(role.IndexPermissions) > 0 {
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

			// Create the grant referencing the "Group Assignment" entitlement
			groupAssignmentEntitlementId := fmt.Sprintf("%s:Group Assignment: %s", resource.DisplayName, backendRole)
			groupAssignmentEntitlement := &v2.Entitlement{
				Id:          groupAssignmentEntitlementId,
				Resource:    resource,
				DisplayName: fmt.Sprintf("Group Assignment: %s", backendRole),
			}

			grant := grant.NewGrant(
				resource,
				fmt.Sprintf("%s:group:%s", resource.DisplayName, backendRole),
				userResourceId,
				grantOpts...,
			)
			// Set the entitlement directly
			grant.Entitlement = groupAssignmentEntitlement
			grants = append(grants, grant)
		}

		// Create grants for direct user assignments
		for _, username := range roleMapping.Users {
			// Create a reference to the user resource by ID
			userResourceId := &v2.ResourceId{
				ResourceType: "user",
				Resource:     username,
			}

			grantOpts := []grant.GrantOption{}

			// Add external resource matching annotation to match by username
			externalMatch := &v2.ExternalResourceMatch{
				ResourceType: v2.ResourceType_TRAIT_USER,
				Key:          "username",
				Value:        username,
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))

			// Add grant expansion annotation if the role has permissions
			if len(role.ClusterPermissions) > 0 || len(role.IndexPermissions) > 0 {
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
			userAssignmentEntitlementId := fmt.Sprintf("%s:User Assignment: %s", resource.DisplayName, username)
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
	}

	return grants, "", nil, nil
}

func newRoleBuilder(client *client.Client) *roleBuilder {
	return &roleBuilder{
		client:       client,
		resourceType: roleResourceType,
	}
}
