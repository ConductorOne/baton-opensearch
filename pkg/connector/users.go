package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-opensearch/pkg/connector/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	client       *client.Client
	resourceType *v2.ResourceType
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var resources []*v2.Resource
	users, err := o.client.GetUsers(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get users: %w", err)
	}

	for _, user := range users {
		// Convert backend roles to interface{} slice
		backendRoles := make([]interface{}, len(user.BackendRoles))
		for i, role := range user.BackendRoles {
			backendRoles[i] = role
		}

		// Convert opendistro security roles to interface{} slice
		securityRoles := make([]interface{}, len(user.OpendistroSecurityRoles))
		for i, role := range user.OpendistroSecurityRoles {
			securityRoles[i] = role
		}

		// Convert attributes to map[string]interface{}
		attributes := make(map[string]interface{})
		for k, v := range user.Attributes {
			attributes[k] = v
		}

		// TODO [MB]: Figure out how to handle different role types. Figure out what useful info we may get from attributes.
		traitOpts := []resource.UserTraitOption{
			resource.WithUserProfile(map[string]interface{}{
				"display_name":              user.Username,
				"login":                     user.Username,
				"description":               user.Description,
				"reserved":                  user.Reserved, // Can't be changed.
				"hidden":                    user.Hidden,   // TODO [MB]: Don't need this since hidden users won't be returned by API.
				"static":                    user.Static,
				"backend_roles":             backendRoles,
				"opendistro_security_roles": securityRoles,
				"attributes":                attributes,
			}),
		}

		// Add email if present in attributes
		if email, ok := user.Attributes["email"].(string); ok && email != "" {
			traitOpts = append(traitOpts, resource.WithEmail(email, true))
		}

		userResource, err := resource.NewUserResource(
			user.Username,
			o.resourceType,
			user.Username,
			traitOpts,
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

// Grants returns the grants for a user.
func (o *userBuilder) Grants(ctx context.Context, userResource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var grants []*v2.Grant

	// Get the user's backend roles from their profile
	userTrait, err := resource.GetUserTrait(userResource)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get user trait: %w", err)
	}

	backendRolesList := userTrait.Profile.Fields["backend_roles"].GetListValue()
	if backendRolesList == nil {
		return nil, "", nil, fmt.Errorf("failed to get backend roles")
	}

	// Get user email for external ID matching
	var userEmail string
	if len(userTrait.Emails) > 0 {
		// Get the primary email or the first email if no primary is set
		for _, email := range userTrait.Emails {
			if email.IsPrimary {
				userEmail = email.Address
				break
			}
		}
		// If no primary email found, use the first one
		if userEmail == "" {
			userEmail = userTrait.Emails[0].Address
		}
	}

	// Create a grant for each backend role
	for _, roleValue := range backendRolesList.Values {
		roleName := roleValue.GetStringValue()

		// Create a reference to the role resource by ID
		roleResourceId := &v2.ResourceId{
			ResourceType: "role",
			Resource:     roleName,
		}

		// Create the grant with external resource matching annotation if email is available
		grantOpts := []grant.GrantOption{}

		if userEmail != "" {
			// Add external resource matching annotation to match by email
			externalMatch := &v2.ExternalResourceMatch{
				ResourceType: v2.ResourceType_TRAIT_USER,
				Key:          "email",
				Value:        userEmail,
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))
		} else {
			// TODO [MB]: Remove this once we have a way to match by email.
			externalMatch := &v2.ExternalResourceMatch{
				ResourceType: v2.ResourceType_TRAIT_USER,
				Key:          "username",
				Value:        userResource.DisplayName,
			}
			grantOpts = append(grantOpts, grant.WithAnnotation(externalMatch))
		}

		grant := grant.NewGrant(
			userResource,
			fmt.Sprintf("%s:role:%s", userResource.DisplayName, roleName),
			roleResourceId,
			grantOpts...,
		)
		grants = append(grants, grant)
	}

	return grants, "", nil, nil
}

func newUserBuilder(client *client.Client) *userBuilder {
	return &userBuilder{
		client:       client,
		resourceType: userResourceType,
	}
}
