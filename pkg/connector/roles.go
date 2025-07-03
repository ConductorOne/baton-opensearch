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
	batonResource "github.com/conductorone/baton-sdk/pkg/types/resource"
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
		traitOpts := []batonResource.RoleTraitOption{
			batonResource.WithRoleProfile(map[string]interface{}{
				"description": role.Description,
				"static":      role.Static,
			}),
		}
		roleResource, err := batonResource.NewRoleResource(
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
	ent := entitlement.NewAssignmentEntitlement(
		resource,
		"assigned",
		entitlement.WithGrantableTo(userResourceType, groupResourceType),
	)

	return []*v2.Entitlement{ent}, "", nil, nil
}

func (o *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	// Get the role mapping from the client
	roleMapping, err := o.client.GetRoleMapping(ctx, resource.DisplayName)
	if err != nil {
		l := ctxzap.Extract(ctx)
		// Check if this is a NotFound error (404) - not all roles may have mappings
		if status.Code(err) == codes.NotFound {
			l.Debug("role mapping not found (normal for unmapped roles)", zap.String("role", resource.DisplayName))
			return []*v2.Grant{}, "", nil, nil
		}
		l.Error("error getting role mapping", zap.String("role", resource.DisplayName), zap.Error(err))
		return nil, "", nil, fmt.Errorf("failed to get role mapping: %w", err)
	}

	var grants []*v2.Grant

	// Create grants for backend roles (treating them as groups)
	for _, backendRole := range roleMapping.BackendRoles {
		groupResourceId, err := batonResource.NewResourceID(groupResourceType, backendRole)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error creating group resource ID: %w", err)
		}

		grantOpts := []grant.GrantOption{}

		// Add external resource matching annotation to match by group membership
		externalMatch := &v2.ExternalResourceMatch{
			ResourceType: v2.ResourceType_TRAIT_GROUP,
			Key:          "name",
			Value:        backendRole,
		}
		grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))

		// Add grant expansion annotation for the role assignment entitlement
		ent := entitlement.NewAssignmentEntitlement(
			resource,
			"assigned",
			entitlement.WithGrantableTo(userResourceType, groupResourceType),
		)
		bidEnt, err := bid.MakeBid(ent)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error generating bid for role assignment entitlement: %w", err)
		}

		expandable := &v2.GrantExpandable{
			EntitlementIds: []string{bidEnt},
			Shallow:        true,
		}
		grantOpts = append(grantOpts, grant.WithAnnotation(expandable))

		grant := grant.NewGrant(
			resource,
			"assigned",
			groupResourceId,
			grantOpts...,
		)
		grants = append(grants, grant)
	}

	// Create grants for direct user assignments
	for _, userIdentifier := range roleMapping.Users {
		// Create a reference to the user resource by ID
		userResourceId, err := batonResource.NewResourceID(userResourceType, userIdentifier)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error creating user resource ID: %w", err)
		}

		grantOpts := []grant.GrantOption{}

		// Handle wildcard case where "*" means all users
		if userIdentifier == "*" {
			externalMatch := &v2.ExternalResourceMatchAll{
				ResourceType: v2.ResourceType_TRAIT_USER,
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))
		}

		// Add external resource matching annotation to match by userIdentifier
		userMatchKey := o.client.GetUserMatchKey()
		if userMatchKey == "id" {
			externalMatch := &v2.ExternalResourceMatchID{
				Id: userIdentifier,
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))
		} else {
			externalMatch := &v2.ExternalResourceMatch{
				ResourceType: v2.ResourceType_TRAIT_USER,
				Key:          userMatchKey,
				Value:        userIdentifier,
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))
		}

		// Create the grant
		grant := grant.NewGrant(
			resource,
			"assigned",
			userResourceId,
			grantOpts...,
		)
		grants = append(grants, grant)
	}

	return grants, "", nil, nil
}

func newRoleBuilder(client *client.Client) *roleBuilder {
	return &roleBuilder{
		client:       client,
		resourceType: roleResourceType,
	}
}
