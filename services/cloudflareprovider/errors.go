package cloudflareprovider

import (
	"errors"
	"fmt"
	"time"
)

type ErrorKind string

const (
	ErrorValidation       ErrorKind = "validation"
	ErrorAuthentication   ErrorKind = "authentication"
	ErrorPermission       ErrorKind = "permission"
	ErrorAccountScope     ErrorKind = "account_scope"
	ErrorNotFound         ErrorKind = "not_found"
	ErrorConflict         ErrorKind = "conflict"
	ErrorRateLimited      ErrorKind = "rate_limited"
	ErrorProvider         ErrorKind = "provider"
	ErrorResponseTooLarge ErrorKind = "response_too_large"
	ErrorTimeout          ErrorKind = "timeout"
	ErrorTransport        ErrorKind = "transport"
	ErrorRedirect         ErrorKind = "redirect"
	ErrorCancelled        ErrorKind = "cancelled"
)

// Error omits request headers, token, URL query, response body, and provider
// messages. Numeric provider error codes are retained for support correlation.
type Error struct {
	Kind         ErrorKind
	Operation    string
	StatusCode   int
	ProviderCode int
	Retryable    bool
	RetryAfter   time.Duration
}

func (e *Error) Error() string {
	if e == nil {
		return "cloudflare provider error"
	}
	if e.StatusCode != 0 && e.ProviderCode != 0 {
		return fmt.Sprintf("cloudflare %s failed: %s (http=%d code=%d)", e.Operation, e.Kind, e.StatusCode, e.ProviderCode)
	}
	if e.StatusCode != 0 {
		return fmt.Sprintf("cloudflare %s failed: %s (http=%d)", e.Operation, e.Kind, e.StatusCode)
	}
	return fmt.Sprintf("cloudflare %s failed: %s", e.Operation, e.Kind)
}

func IsKind(err error, kind ErrorKind) bool {
	var providerErr *Error
	return errors.As(err, &providerErr) && providerErr.Kind == kind
}

func validationError(operation string) error {
	return &Error{Kind: ErrorValidation, Operation: operation}
}
