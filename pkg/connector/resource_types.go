package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// The user resource type is for all user objects from the database.
var userResourceType = &v2.ResourceType{
	Id:          "user",
	DisplayName: "User",
	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
	Annotations: annotations.New(&v2.SkipEntitlementsAndGrants{}),
}

var roleResourceType = &v2.ResourceType{
	Id:          "role",
	DisplayName: "Role",
	Description: "OpenSearch role with permissions",
	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
	Annotations: annotations.New(&v2.SkipEntitlementsAndGrants{}),
}

var roleMappingResourceType = &v2.ResourceType{
	Id:          "role_mapping",
	DisplayName: "Role Mapping",
	Description: "OpenSearch role mapping that connects external identities to roles",
	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
}
