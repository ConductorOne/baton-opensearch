package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/bid"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
)

func createRoleEntitlements(ctx context.Context, roleResource *v2.Resource, role *client.Role, roleMapping *client.RoleMapping) ([]*v2.Entitlement, error) {
	var entitlements []*v2.Entitlement

	for _, perm := range role.ClusterPermissions {
		ent := entitlement.NewPermissionEntitlement(
			roleResource,
			fmt.Sprintf("cluster_permission:%s", perm),
			entitlement.WithGrantableTo(userResourceType),
		)

		entitlements = append(entitlements, ent)
	}

	// Create individual entitlements for index permissions (for grant expansion)
	for _, perm := range role.IndexPermissions {
		for _, action := range perm.AllowedActions {
			ent := entitlement.NewPermissionEntitlement(
				roleResource,
				fmt.Sprintf("index_permission:%s", action),
				entitlement.WithGrantableTo(userResourceType),
			)

			entitlements = append(entitlements, ent)
		}
	}

	// Create entitlements for backend roles (treating them as groups)
	for _, backendRole := range roleMapping.BackendRoles {
		ent := entitlement.NewAssignmentEntitlement(
			roleResource,
			fmt.Sprintf("Group Assignment: %s", backendRole),
			entitlement.WithGrantableTo(userResourceType),
		)

		entitlements = append(entitlements, ent)
	}

	// Create entitlements for direct user assignments
	for _, user := range roleMapping.Users {
		ent := entitlement.NewAssignmentEntitlement(
			roleResource,
			fmt.Sprintf("User Assignment: %s", user),
			entitlement.WithGrantableTo(userResourceType),
		)

		entitlements = append(entitlements, ent)
	}

	return entitlements, nil
}

func createRoleGrants(ctx context.Context, roleResource *v2.Resource, role *client.Role, roleMapping *client.RoleMapping) ([]*v2.Grant, error) {
	var grants []*v2.Grant

	// Create grants for backend roles (treating them as groups)
	for _, backendRole := range roleMapping.BackendRoles {
		// Create a reference to a user resource (the grant target)
		userResourceId := &v2.ResourceId{
			ResourceType: "user",
			Resource:     fmt.Sprintf("group_member:%s", backendRole),
		}

		grantOpts := []grant.GrantOption{}

		// Add external resource matching annotation to match by group membership
		externalMatch := &v2.ExternalResourceMatch{
			ResourceType: v2.ResourceType_TRAIT_GROUP,
			Key:          "name",
			Value:        backendRole,
		}
		grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))

		// Create the entitlement for this backend role assignment
		groupAssignmentEntitlement := entitlement.NewAssignmentEntitlement(
			roleResource,
			fmt.Sprintf("Group Assignment: %s", backendRole),
			entitlement.WithGrantableTo(userResourceType),
		)

		// Create baton ID for the entitlement
		groupAssignmentBidEnt, err := bid.MakeBid(groupAssignmentEntitlement)
		if err != nil {
			return nil, fmt.Errorf("error generating bid for group assignment entitlement: %w", err)
		}

		// Add grant expansion annotation to expand the group membership entitlement
		// This allows users who are members of the backend role (Okta group) to get the role's permissions
		expandable := &v2.GrantExpandable{
			EntitlementIds:  []string{groupAssignmentBidEnt},
			Shallow:         true,
			ResourceTypeIds: []string{"user"},
		}
		grantOpts = append(grantOpts, grant.WithAnnotation(expandable))

		// Create the grant with a unique grant ID
		grant := grant.NewGrant(
			roleResource,
			fmt.Sprintf("grant:%s:group:%s", roleResource.DisplayName, backendRole), // Unique grant ID
			userResourceId,
			grantOpts...,
		)
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

		// Create the entitlement for this user assignment
		userAssignmentEntitlement := entitlement.NewAssignmentEntitlement(
			roleResource,
			fmt.Sprintf("User Assignment: %s", username),
			entitlement.WithGrantableTo(userResourceType),
		)

		// Create baton ID for the entitlement
		userAssignmentBidEnt, err := bid.MakeBid(userAssignmentEntitlement)
		if err != nil {
			return nil, fmt.Errorf("error generating bid for user assignment entitlement: %w", err)
		}

		// Add grant expansion annotation to expand the user assignment entitlement
		// This allows the specific user to get the role's permissions
		expandable := &v2.GrantExpandable{
			EntitlementIds:  []string{userAssignmentBidEnt},
			Shallow:         true,
			ResourceTypeIds: []string{"user"},
		}
		grantOpts = append(grantOpts, grant.WithAnnotation(expandable))

		// Create the grant with a unique grant ID
		grant := grant.NewGrant(
			roleResource,
			fmt.Sprintf("grant:%s:user:%s", roleResource.DisplayName, username), // Unique grant ID
			userResourceId,
			grantOpts...,
		)
		grants = append(grants, grant)
	}

	return grants, nil
}
