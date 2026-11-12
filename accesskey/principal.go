package accesskey

import "slices"

// Principal is the common backend identity for user sessions and access keys.
// Key assertions never supply groups; authorization must also bind Project.
type Principal struct {
	Kind    string
	Subject string
	Scopes  []string
	Groups  []string
	KeyName string
	Project string
}

// Has checks an exact app permission for either a person or an access key.
// Groups, Project roles and wildcard-like strings never imply permissions.
func (p Principal) Has(permission string) bool {
	return permission != "" && slices.Contains(p.Scopes, permission)
}

func (c Claims) Principal() Principal {
	return Principal{
		Kind: "key", Subject: c.Subject.String(), Scopes: c.Scopes,
		KeyName: c.KeyName, Project: c.Project,
	}
}
