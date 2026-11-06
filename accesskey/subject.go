package accesskey

import (
	"fmt"
	"strings"
)

type SubjectKind string

const (
	SubjectUser      SubjectKind = "user"
	SubjectComponent SubjectKind = "component"
	SubjectExternal  SubjectKind = "external"
	SubjectCluster   SubjectKind = "cluster"
)

// Subject identifies the principal for which a key was issued.
type Subject struct {
	Kind SubjectKind
	ID   string
}

func (s Subject) String() string { return string(s.Kind) + ":" + s.ID }

func ParseSubject(raw string) (Subject, error) {
	kind, id, ok := strings.Cut(raw, ":")
	if ok && id != "" {
		switch SubjectKind(kind) {
		case SubjectUser, SubjectComponent, SubjectExternal, SubjectCluster:
			return Subject{Kind: SubjectKind(kind), ID: id}, nil
		}
	}
	return Subject{}, fmt.Errorf("%w: subject", ErrMalformed)
}
