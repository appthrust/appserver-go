package accesskey

import (
	"errors"
	"testing"
)

func TestSubjectRoundTrip(t *testing.T) {
	for _, kind := range []SubjectKind{SubjectUser, SubjectComponent, SubjectExternal, SubjectCluster} {
		for _, id := range []string{"id-123", "id:with:colons"} {
			t.Run(string(kind)+"/"+id, func(t *testing.T) {
				want := Subject{Kind: kind, ID: id}
				if want.String() != string(kind)+":"+id {
					t.Fatal("incorrect subject format")
				}
				got, err := ParseSubject(want.String())
				if err != nil || got != want {
					t.Fatalf("ParseSubject = %#v, %v", got, err)
				}
			})
		}
	}
}

func TestSubjectMalformed(t *testing.T) {
	for _, raw := range []string{"", "user", "user:", ":id", "User:id", "unknown:id"} {
		if _, err := ParseSubject(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseSubject(%q) error = %v", raw, err)
		}
	}
}
