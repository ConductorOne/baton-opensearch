package client

type User struct {
	UserIdentifier          string                 `json:"user_identifier"`
	Description             string                 `json:"description,omitempty"`
	Reserved                bool                   `json:"reserved,omitempty"`
	Hidden                  bool                   `json:"hidden,omitempty"`
	Static                  bool                   `json:"static,omitempty"`
	BackendRoles            []string               `json:"backend_roles"`
	OpendistroSecurityRoles []string               `json:"opendistro_security_roles"`
	Attributes              map[string]interface{} `json:"attributes,omitempty"`
}

type Role struct {
	Name               string             `json:"name"`
	Reserved           bool               `json:"reserved,omitempty"`
	Hidden             bool               `json:"hidden,omitempty"`
	Static             bool               `json:"static,omitempty"`
	Description        string             `json:"description,omitempty"`
	ClusterPermissions []string           `json:"cluster_permissions"`
	IndexPermissions   []indexPermission  `json:"index_permissions"`
	TenantPermissions  []tenantPermission `json:"tenant_permissions"`
}

type RoleMapping struct {
	Name            string   `json:"name"`
	Reserved        bool     `json:"reserved,omitempty"`
	Hidden          bool     `json:"hidden,omitempty"`
	Static          bool     `json:"static,omitempty"`
	BackendRoles    []string `json:"backend_roles"`
	Hosts           []string `json:"hosts,omitempty"`
	Users           []string `json:"users,omitempty"`
	AndBackendRoles []string `json:"and_backend_roles,omitempty"`
}

type indexPermission struct {
	IndexPatterns  []string `json:"index_patterns"`
	FLS            []string `json:"fls,omitempty"`
	MaskedFields   []string `json:"masked_fields,omitempty"`
	AllowedActions []string `json:"allowed_actions"`
}

type tenantPermission struct {
	TenantPatterns []string `json:"tenant_patterns,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
}
