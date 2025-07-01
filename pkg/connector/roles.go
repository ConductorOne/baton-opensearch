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

type roleBuilder struct {
	client              *client.Client
	resourceType        *v2.ResourceType
	entitlementBidCache map[string]map[string]string // resource ID -> entitlement ID -> baton ID
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

	// Clear the cache for new sync
	o.entitlementBidCache = make(map[string]map[string]string)

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
		entitlements, entitlementBidMap, err := createRoleEntitlements(ctx, resource, role, roleMapping)
		if err != nil {
			return nil, "", nil, err
		}

		// Cache the baton ID mapping for use in Grants
		o.entitlementBidCache[resource.Id.Resource] = entitlementBidMap

		return entitlements, "", nil, nil
	}

	return nil, "", nil, nil
}

// Grants returns grants for roles based on their role mappings.
func (o *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
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
		// Use cached baton ID mapping from Entitlements
		entitlementBidMap, exists := o.entitlementBidCache[resource.Id.Resource]
		if !exists {
			// If not in cache, create entitlements to get the mapping
			_, entitlementBidMap, err = createRoleEntitlements(ctx, resource, role, roleMapping)
			if err != nil {
				return nil, "", nil, err
			}
			o.entitlementBidCache[resource.Id.Resource] = entitlementBidMap
		}

		// Create grants using the baton ID mapping
		grants, err := createRoleGrants(ctx, resource, role, roleMapping, entitlementBidMap)
		if err != nil {
			return nil, "", nil, err
		}

		return grants, "", nil, nil
	}

	return nil, "", nil, nil
}

func newRoleBuilder(client *client.Client) *roleBuilder {
	return &roleBuilder{
		client:              client,
		resourceType:        roleResourceType,
		entitlementBidCache: make(map[string]map[string]string),
	}
}
