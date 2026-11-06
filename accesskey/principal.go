package accesskey

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

func (c Claims) Principal() Principal {
	return Principal{
		Kind: "key", Subject: c.Subject.String(), Scopes: c.Scopes,
		KeyName: c.KeyName, Project: c.Project,
	}
}
