package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/bid"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func (o *roleBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// Get the role to see what permissions it provides
	role, err := o.client.GetRole(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Get the role mapping to see what assignments are possible
	roleMapping, err := o.client.GetRoleMapping(ctx, resource.DisplayName)
	if err != nil {
		l := ctxzap.Extract(ctx)
		// Check if this is a NotFound error (404) - not all roles may have mappings
		if status.Code(err) == codes.NotFound {
			l.Debug("role mapping not found (normal for unmapped roles)", zap.String("role", resource.DisplayName))
			// Continue without role mapping - we'll still create permission entitlements
		} else {
			l.Error("error getting role mapping", zap.String("role", resource.DisplayName), zap.Error(err))
			return nil, "", nil, fmt.Errorf("failed to get role mapping: %w", err)
		}
	}

	var entitlements []*v2.Entitlement

	// Create entitlements for the role's permissions
	if role != nil {
		// Create individual entitlements for cluster permissions
		for _, perm := range role.ClusterPermissions {
			ent := entitlement.NewPermissionEntitlement(
				resource,
				fmt.Sprintf("cluster_permission:%s", perm),
				entitlement.WithGrantableTo(userResourceType),
			)
			entitlements = append(entitlements, ent)
		}

		// Create individual entitlements for index permissions
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

	// Create entitlements for role assignments (if role mapping exists)
	if roleMapping != nil {
		// Create entitlements for backend role assignments (group assignments)
		for _, backendRole := range roleMapping.BackendRoles {
			ent := entitlement.NewAssignmentEntitlement(
				resource,
				fmt.Sprintf("group_assignment:%s", backendRole),
				entitlement.WithGrantableTo(userResourceType),
			)
			entitlements = append(entitlements, ent)
		}
	}

	return entitlements, "", nil, nil
}

func (o *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	// Get the role mapping from the client
	roleMapping, err := o.client.GetRoleMapping(ctx, resource.DisplayName)
	if err != nil {
		l := ctxzap.Extract(ctx)
		// Check if this is a NotFound error (404) - not all roles may have mappings
		if status.Code(err) == codes.NotFound {
			l.Debug("role mapping not found (normal for unmapped roles)", zap.String("role", resource.DisplayName))
			return nil, "", nil, nil
		}
		l.Error("error getting role mapping", zap.String("role", resource.DisplayName), zap.Error(err))
		return nil, "", nil, fmt.Errorf("failed to get role mapping: %w", err)
	}

	// Get the role to see what permissions it provides
	role, err := o.client.GetRole(ctx, resource.DisplayName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role: %w", err)
	}

	// If no role mapping exists, return empty grants
	if roleMapping == nil {
		return nil, "", nil, nil
	}

	if role != nil {
		var grants []*v2.Grant

		// Create grants for backend roles (treating them as groups)
		for _, backendRole := range roleMapping.BackendRoles {
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

			// Create the group assignment entitlement for grant expansion
			groupAssignmentEntitlement := entitlement.NewAssignmentEntitlement(
				resource,
				fmt.Sprintf("group_assignment:%s", backendRole),
				entitlement.WithGrantableTo(userResourceType),
			)
			bidEnt, err := bid.MakeBid(groupAssignmentEntitlement)
			if err != nil {
				return nil, "", nil, fmt.Errorf("error generating bid for group assignment entitlement: %w", err)
			}

			expandable := &v2.GrantExpandable{
				EntitlementIds:  []string{bidEnt},
				Shallow:         true,
				ResourceTypeIds: []string{"user"},
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(expandable))

			grant := grant.NewGrant(
				resource,
				fmt.Sprintf("group_assignment:%s", backendRole),
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

			// Create the grant (no specific entitlement since we're expanding permissions directly)
			grant := grant.NewGrant(
				resource,
				fmt.Sprintf("user_assignment:%s", username),
				userResourceId,
				grantOpts...,
			)
			grants = append(grants, grant)
		}

		return grants, "", nil, nil
	}

	return nil, "", nil, nil
}

func newRoleBuilder(client *client.Client) *roleBuilder {
	return &roleBuilder{
		client:       client,
		resourceType: roleResourceType,
	}
}
