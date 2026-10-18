// Package platformerr defines safe errors for new unified-module boundaries.
package platformerr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type Code string

const (
	InvalidArgument          Code = "invalid_argument"
	Unauthenticated          Code = "unauthenticated"
	Forbidden                Code = "forbidden"
	NotFound                 Code = "not_found"
	Conflict                 Code = "conflict"
	CredentialDisabled       Code = "credential_disabled"
	CredentialVersionInvalid Code = "credential_version_invalid"
	ProviderFailure          Code = "provider_failure"
	Canceled                 Code = "canceled"
	Timeout                  Code = "timeout"
	Unavailable              Code = "unavailable"
	Internal                 Code = "internal"
)

// Error deliberately excludes raw provider errors from formatting and JSON.
// Unwrap is for in-process classification, never for API or audit serialization.
type Error struct {
	Code        Code   `json:"code"`
	Message     string `json:"message"`
	OperationID string `json:"operation_id,omitempty"`
	Retryable   bool   `json:"retryable"`
	cause       error
}

func New(code Code, operationID string, cause error) *Error {
	message, status := describe(code)
	if status == http.StatusInternalServerError {
		code = Internal
	}
	return &Error{Code: code, Message: message, OperationID: operationID, Retryable: code == Unavailable || code == Timeout, cause: cause}
}

func (e *Error) Error() string                 { return string(e.Code) + ": " + e.Message }
func (e *Error) Unwrap() error                 { return e.cause }
func (e Error) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(e.Error())) }
func (e *Error) HTTPStatus() int {
	_, status := describe(e.Code)
	return status
}

// From preserves a known code while rebuilding its safe public message.
func From(err error, operationID string) *Error {
	var known *Error
	if errors.As(err, &known) {
		return New(known.Code, operationID, err)
	}
	if errors.Is(err, context.Canceled) {
		return New(Canceled, operationID, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return New(Timeout, operationID, err)
	}
	return New(Internal, operationID, err)
}

func describe(code Code) (string, int) {
	switch code {
	case InvalidArgument:
		return "Invalid request", http.StatusBadRequest
	case Unauthenticated:
		return "Authentication required", http.StatusUnauthorized
	case Forbidden:
		return "Permission denied", http.StatusForbidden
	case NotFound:
		return "Resource not found", http.StatusNotFound
	case Conflict:
		return "Resource conflict", http.StatusConflict
	case CredentialDisabled:
		return "Credential is disabled", http.StatusConflict
	case CredentialVersionInvalid:
		return "Credential version is no longer valid", http.StatusConflict
	case ProviderFailure:
		return "Provider operation failed", http.StatusBadGateway
	case Canceled:
		return "Operation canceled", http.StatusRequestTimeout
	case Timeout:
		return "Operation timed out", http.StatusGatewayTimeout
	case Unavailable:
		return "Service unavailable", http.StatusServiceUnavailable
	default:
		return "Internal error", http.StatusInternalServerError
	}
}
