package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/bid"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// makeBidEntitlement creates a baton ID for an entitlement and returns both the entitlement and its ID
func makeBidEntitlement(ent *v2.Entitlement) (string, error) {
	bidEnt, err := bid.MakeBid(ent)
	if err != nil {
		return "", fmt.Errorf("error making bid for entitlement: %w", err)
	}
	return bidEnt, nil
}

// createRoleEntitlements creates entitlements for a role with proper baton IDs
func createRoleEntitlements(ctx context.Context, roleResource *v2.Resource, role *client.Role, roleMapping *client.RoleMapping) ([]*v2.Entitlement, map[string]string, error) {
	var entitlements []*v2.Entitlement
	entitlementBidMap := make(map[string]string) // Maps entitlement ID to baton ID
	l := ctxzap.Extract(ctx)

	// Create individual entitlements for cluster permissions (for grant expansion)
	for _, perm := range role.ClusterPermissions {
		ent := entitlement.NewPermissionEntitlement(
			roleResource,
			fmt.Sprintf("cluster_permission:%s", perm),
			entitlement.WithGrantableTo(userResourceType),
		)

		bidEnt, err := makeBidEntitlement(ent)
		if err != nil {
			l.Error("error making bid for cluster permission entitlement",
				zap.String("permission", perm),
				zap.Error(err))
			return nil, nil, fmt.Errorf("error generating bid for cluster permission entitlement: %w", err)
		}

		entitlements = append(entitlements, ent)
		entitlementBidMap[ent.Id] = bidEnt
	}

	// Create individual entitlements for index permissions (for grant expansion)
	for _, perm := range role.IndexPermissions {
		for _, action := range perm.AllowedActions {
			ent := entitlement.NewPermissionEntitlement(
				roleResource,
				fmt.Sprintf("index_permission:%s", action),
				entitlement.WithGrantableTo(userResourceType),
			)

			bidEnt, err := makeBidEntitlement(ent)
			if err != nil {
				l.Error("error making bid for index permission entitlement",
					zap.String("action", action),
					zap.Error(err))
				return nil, nil, fmt.Errorf("error generating bid for index permission entitlement: %w", err)
			}

			entitlements = append(entitlements, ent)
			entitlementBidMap[ent.Id] = bidEnt
		}
	}

	// Create entitlements for backend roles (treating them as groups)
	for _, backendRole := range roleMapping.BackendRoles {
		ent := entitlement.NewAssignmentEntitlement(
			roleResource,
			fmt.Sprintf("Group Assignment: %s", backendRole),
			entitlement.WithGrantableTo(userResourceType),
		)

		bidEnt, err := makeBidEntitlement(ent)
		if err != nil {
			l.Error("error making bid for backend role assignment entitlement",
				zap.String("backendRole", backendRole),
				zap.Error(err))
			return nil, nil, fmt.Errorf("error generating bid for backend role assignment entitlement: %w", err)
		}

		entitlements = append(entitlements, ent)
		entitlementBidMap[ent.Id] = bidEnt
	}

	// Create entitlements for direct user assignments
	for _, user := range roleMapping.Users {
		ent := entitlement.NewAssignmentEntitlement(
			roleResource,
			fmt.Sprintf("User Assignment: %s", user),
			entitlement.WithGrantableTo(userResourceType),
		)

		bidEnt, err := makeBidEntitlement(ent)
		if err != nil {
			l.Error("error making bid for user assignment entitlement",
				zap.String("user", user),
				zap.Error(err))
			return nil, nil, fmt.Errorf("error generating bid for user assignment entitlement: %w", err)
		}

		entitlements = append(entitlements, ent)
		entitlementBidMap[ent.Id] = bidEnt
	}

	return entitlements, entitlementBidMap, nil
}

// createRoleGrants creates grants for a role with proper baton ID references
func createRoleGrants(ctx context.Context, roleResource *v2.Resource, role *client.Role, roleMapping *client.RoleMapping, entitlementBidMap map[string]string) ([]*v2.Grant, error) {
	var grants []*v2.Grant
	l := ctxzap.Extract(ctx)

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

		// Add grant expansion annotation if the role has permissions
		if len(role.ClusterPermissions) > 0 || len(role.IndexPermissions) > 0 {
			var expandableEntitlementIDs []string

			// Add cluster permission entitlements
			for _, perm := range role.ClusterPermissions {
				entitlementId := fmt.Sprintf("%s:cluster_permission:%s", roleResource.DisplayName, perm)
				if bidEnt, exists := entitlementBidMap[entitlementId]; exists {
					expandableEntitlementIDs = append(expandableEntitlementIDs, bidEnt)
				}
			}

			// Add index permission entitlements
			for _, perm := range role.IndexPermissions {
				for _, action := range perm.AllowedActions {
					entitlementId := fmt.Sprintf("%s:index_permission:%s", roleResource.DisplayName, action)
					if bidEnt, exists := entitlementBidMap[entitlementId]; exists {
						expandableEntitlementIDs = append(expandableEntitlementIDs, bidEnt)
					}
				}
			}

			// Add the grant expansion annotation
			expandable := &v2.GrantExpandable{
				EntitlementIds:  expandableEntitlementIDs,
				Shallow:         true,
				ResourceTypeIds: []string{"user"},
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(expandable))
		}

		// Create the grant referencing the "Group Assignment" entitlement
		groupAssignmentEntitlementId := fmt.Sprintf("%s:Group Assignment: %s", roleResource.DisplayName, backendRole)
		groupAssignmentEntitlement := &v2.Entitlement{
			Id:          groupAssignmentEntitlementId,
			Resource:    roleResource,
			DisplayName: fmt.Sprintf("Group Assignment: %s", backendRole),
		}

		// Get the baton ID for this entitlement
		bidEnt, err := makeBidEntitlement(groupAssignmentEntitlement)
		if err != nil {
			l.Error("error making bid for group assignment grant entitlement",
				zap.String("backendRole", backendRole),
				zap.Error(err))
			return nil, fmt.Errorf("error generating bid for group assignment grant entitlement: %w", err)
		}

		grant := grant.NewGrant(
			roleResource,
			bidEnt, // Use the baton ID as the grant ID
			userResourceId,
			grantOpts...,
		)
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
			var expandableEntitlementIDs []string

			// Add cluster permission entitlements
			for _, perm := range role.ClusterPermissions {
				entitlementId := fmt.Sprintf("%s:cluster_permission:%s", roleResource.DisplayName, perm)
				if bidEnt, exists := entitlementBidMap[entitlementId]; exists {
					expandableEntitlementIDs = append(expandableEntitlementIDs, bidEnt)
				}
			}

			// Add index permission entitlements
			for _, perm := range role.IndexPermissions {
				for _, action := range perm.AllowedActions {
					entitlementId := fmt.Sprintf("%s:index_permission:%s", roleResource.DisplayName, action)
					if bidEnt, exists := entitlementBidMap[entitlementId]; exists {
						expandableEntitlementIDs = append(expandableEntitlementIDs, bidEnt)
					}
				}
			}

			// Add the grant expansion annotation
			expandable := &v2.GrantExpandable{
				EntitlementIds:  expandableEntitlementIDs,
				Shallow:         true,
				ResourceTypeIds: []string{"user"},
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(expandable))
		}

		// Create the grant referencing the "User Assignment" entitlement
		userAssignmentEntitlementId := fmt.Sprintf("%s:User Assignment: %s", roleResource.DisplayName, username)
		userAssignmentEntitlement := &v2.Entitlement{
			Id:          userAssignmentEntitlementId,
			Resource:    roleResource,
			DisplayName: fmt.Sprintf("User Assignment: %s", username),
		}

		// Get the baton ID for this entitlement
		bidEnt, err := makeBidEntitlement(userAssignmentEntitlement)
		if err != nil {
			l.Error("error making bid for user assignment grant entitlement",
				zap.String("username", username),
				zap.Error(err))
			return nil, fmt.Errorf("error generating bid for user assignment grant entitlement: %w", err)
		}

		grant := grant.NewGrant(
			roleResource,
			bidEnt, // Use the baton ID as the grant ID
			userResourceId,
			grantOpts...,
		)
		grant.Entitlement = userAssignmentEntitlement
		grants = append(grants, grant)
	}

	return grants, nil
}
