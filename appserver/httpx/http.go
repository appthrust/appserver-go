// Package httpx contains the envelope and error contract shared by built-in app APIs.
package httpx

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"message"`
	// RetryAfter is an optional HTTP Retry-After hint, not part of the envelope.
	RetryAfter string `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func Fail(status int, code, message string) error {
	return &Error{Status: status, Code: code, Message: message}
}
func Invalid(message string) error { return Fail(400, "invalid_request", message) }
func NotFound() error              { return Fail(404, "not_found", "The requested resource was not found") }
func Forbidden() error             { return Fail(403, "forbidden", "You do not have permission for this action") }
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func WriteError(w http.ResponseWriter, err error, service string) {
	var apiError *Error
	if !errors.As(err, &apiError) {
		log.Printf("%s request failed: %v", service, err)
		apiError = &Error{Status: 500, Code: "internal_error", Message: "The " + service + " could not complete this request"}
	}
	if apiError.RetryAfter != "" {
		w.Header().Set("Retry-After", apiError.RetryAfter)
	}
	WriteJSON(w, apiError.Status, apiError)
}

func Data[T any](items []T) any {
	return struct {
		Data []T `json:"data"`
	}{items}
}

func Conflict(message string) error { return Fail(409, "conflict", message) }
