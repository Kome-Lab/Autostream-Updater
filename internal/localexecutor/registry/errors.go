package registry

import "errors"

// Code describes the failed boundary without leaking raw store errors or inputs.
type Code string

const (
	CodeInvalid         Code = "invalid"
	CodeBindingConflict Code = "binding_conflict"
	CodeUnauthorized    Code = "unauthorized"
	CodeUnavailable     Code = "unavailable"
	CodeEvidenceUnknown Code = "evidence_unknown"
)

// Error is safe to return from this internal boundary. It never implies that a
// mutation was not started, that a grant is unused, or that retry is authorized.
type Error struct {
	Code  Code
	Field string
}

func (e *Error) Error() string {
	if e == nil {
		return "registry_error"
	}
	return "registry_" + string(e.Code) + ":" + e.Field
}

func fault(code Code, field string) error {
	return &Error{Code: code, Field: field}
}

func invalid(field string) error {
	return fault(CodeInvalid, field)
}

func collision(field string) error {
	return fault(CodeBindingConflict, field)
}

// IsCode works through wrapping; context/storage failures are not retry grants.
func IsCode(err error, code Code) bool {
	var target *Error
	return errors.As(err, &target) && target != nil && target.Code == code
}
