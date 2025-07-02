package connector

import (
	"context"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

type userBuilder struct {
	client       *client.Client
	resourceType *v2.ResourceType
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Entitlements always returns an empty slice for users.
func (o *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since access is granted through role mappings.
func (o *userBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newUserBuilder(client *client.Client) *userBuilder {
	return &userBuilder{
		client:       client,
		resourceType: userResourceType,
	}
}
