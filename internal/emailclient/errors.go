package emailclient

import (
	"errors"
	"fmt"
)

// EmailServiceError represents an error from the email service API
type EmailServiceError struct {
	StatusCode int
	ErrorCode  string
	Message    string
}

func (e *EmailServiceError) Error() string {
	return fmt.Sprintf("email service error [%d]: %s - %s", e.StatusCode, e.ErrorCode, e.Message)
}

// Sentinel errors for type checking
var (
	ErrUnauthorized       = errors.New("email service: unauthorized")
	ErrNotFound           = errors.New("email service: not found")
	ErrValidation         = errors.New("email service: validation failed")
	ErrServiceUnavailable = errors.New("email service: unavailable")
	ErrTimeout            = errors.New("email service: request timeout")
	ErrInvalidEmail       = errors.New("email service: invalid email format")
)
