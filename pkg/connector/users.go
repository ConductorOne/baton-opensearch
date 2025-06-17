package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	client *Client
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// List returns all the users from OpenSearch as resource objects.
func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	users, err := o.client.GetUsers(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get users: %w", err)
	}

	var resources []*v2.Resource
	for _, user := range users {
		username, ok := user["username"].(string)
		if !ok {
			continue
		}

		userResource, err := resource.NewUserResource(
			username,
			userResourceType,
			username,
			[]resource.UserTraitOption{
				resource.WithUserProfile(map[string]interface{}{
					"display_name": username,
					"login":        username,
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

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newUserBuilder(client *Client) *userBuilder {
	return &userBuilder{
		client: client,
	}
}
