package launcher

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/appthrust/appserver-go/appserver/platformclient"
)

var ErrUnavailable = errors.New("launcher unavailable")

// DeniedError preserves an authorization denial from the Platform API.
type DeniedError struct {
	Status int
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("launcher denied: HTTP %d", e.Status)
}

func classifyError(err error) error {
	var responseError *platformclient.HTTPError
	if errors.As(err, &responseError) &&
		(responseError.StatusCode == http.StatusUnauthorized || responseError.StatusCode == http.StatusForbidden) {
		return &DeniedError{Status: responseError.StatusCode}
	}
	return ErrUnavailable
}
