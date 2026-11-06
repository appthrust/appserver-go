// Package link resolves declared built-in app bindings and forwards the viewer's bearer
// to callee-owned operations. It never derives internal Service addresses.
package link

import (
	"errors"
	"fmt"
	"net/url"
)

type State string

const (
	StateAbsent      State = "Absent"
	StateInstalling  State = "Installing"
	StateReady       State = "Ready"
	StateUnsupported State = "Unsupported"
)

type Binding struct {
	Definition   string
	Required     bool
	Capabilities []string
	State        State
	InternalURL  string
	PublicURL    string
}

type Required struct{ URLEnv, PublicURLEnv string }
type Param struct {
	Name     string
	In       string
	Type     string
	Required bool
}

// Operation targets exactly one definition or capability. An empty Base targets
// the provider root; capability operations are called with Client.DoAt.
type Operation struct {
	Definition string
	Capability string
	ID         string
	Method     string
	Base       string
	Path       string
	ResultPath string
	Params     []Param
	Summary    string
}

func (op Operation) validateTarget() error {
	if (op.Definition == "") == (op.Capability == "") {
		return errors.New("link operation must set exactly one of Definition or Capability")
	}
	return nil
}

type Params struct {
	Path  map[string]string
	Query url.Values
}

var ErrAbsent = errors.New("link absent")
var ErrUnavailable = errors.New("link unavailable")

type DeniedError struct{ Status int }

func (e *DeniedError) Error() string { return fmt.Sprintf("link denied: HTTP %d", e.Status) }

type RejectedError struct {
	Status  int
	Code    string
	Message string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("link rejected: HTTP %d: %s: %s", e.Status, e.Code, e.Message)
}
