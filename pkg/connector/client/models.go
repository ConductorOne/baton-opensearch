package client

type User struct {
	Username                string                 `json:"username"`
	BackendRoles            []string               `json:"backend_roles"`
	OpendistroSecurityRoles []string               `json:"opendistro_security_roles"`
	Attributes              map[string]interface{} `json:"attributes,omitempty"`
	Description             string                 `json:"description,omitempty"`
	Hash                    string                 `json:"hash,omitempty"`
	Reserved                bool                   `json:"reserved,omitempty"`
	Hidden                  bool                   `json:"hidden,omitempty"`
	Static                  bool                   `json:"static,omitempty"`
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
