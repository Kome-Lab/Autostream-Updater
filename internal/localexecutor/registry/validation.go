package registry

import (
	"errors"
	"math"
	"unicode/utf8"

	evidence "github.com/Kome-Lab/Autostream-Contracts/v3evidence"
)

const maxRequestBytes = evidence.MaxRequestBytes

// ValidateExecutionKey checks only the opaque identifier's representation.
// Global uniqueness and ownership are storage/verifier obligations, not syntax.
func ValidateExecutionKey(key ID) error {
	return validateID(key, "execution.execution_key")
}

// ValidateScope accepts canonical, opaque resource identities, never OS paths.
func ValidateScope(scope Scope) error {
	for _, item := range []struct {
		value ID
		field string
	}{
		{scope.Realm, "scope.realm"},
		{scope.Host, "scope.host"},
		{scope.Resource, "scope.resource"},
		{scope.Backend, "scope.backend"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

func ValidateExecution(execution Execution) error {
	if err := ValidateExecutionKey(execution.ExecutionKey); err != nil {
		return err
	}
	for _, item := range []struct {
		value ID
		field string
	}{
		{execution.RequestID, "execution.request_id"},
		{execution.OperationID, "execution.operation_id"},
		{execution.AttemptID, "execution.attempt_id"},
		{execution.StepID, "execution.step_id"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

// validateID deliberately rejects case folding, Unicode normalization, paths,
// whitespace, and empty values. DecodeRequest separately rejects JSON null. The value is never echoed in an error.
func validateID(value ID, field string) error {
	if len(value) == 0 || len(value) > 128 {
		return invalid(field)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alphanumeric && (i == 0 || c != '.' && c != '_' && c != ':' && c != '-') {
			return invalid(field)
		}
	}
	return nil
}

func validateCall(call Call) error {
	for _, item := range []struct {
		value ID
		field string
	}{
		{call.Principal, "call.principal"},
		{call.Capability, "call.capability"},
		{call.CorrelationID, "call.correlation_id"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidence(evidence Evidence) error {
	for _, item := range []struct {
		value ID
		field string
	}{
		{evidence.Issuer, "evidence.issuer"},
		{evidence.ServingIncarnation, "evidence.serving_incarnation"},
		{evidence.Generation, "evidence.generation"},
		{evidence.SnapshotID, "evidence.snapshot_id"},
		{evidence.FreshnessProof, "evidence.freshness_proof"},
		{evidence.ObservationProof, "evidence.observation_proof"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

// All conversions are explicit, lossless views of the reviewed shared contract.
// Named ID/Binding types and C10 public signatures remain unchanged.
func sharedCommand(c Command) evidence.Command {
	return evidence.Command{
		Schema: c.Schema, Operation: c.Operation,
		Scope:               evidence.Scope{Realm: string(c.Scope.Realm), Host: string(c.Scope.Host), Resource: string(c.Scope.Resource), Backend: string(c.Scope.Backend)},
		Execution:           evidence.Execution{RequestID: string(c.Execution.RequestID), ExecutionKey: string(c.Execution.ExecutionKey), OperationID: string(c.Execution.OperationID), AttemptID: string(c.Execution.AttemptID), StepID: string(c.Execution.StepID)},
		RequestingPrincipal: string(c.RequestingPrincipal), AuthorizationIssuer: string(c.AuthorizationIssuer),
		CandidateRevision: string(c.CandidateRevision), CandidateContentPin: string(c.CandidateContentPin),
		Expected:      evidence.ExpectedReference{Revision: string(c.Expected.Revision), StateVersion: c.Expected.StateVersion},
		RequiredGuard: evidence.RequiredGuard{Policy: string(c.RequiredGuard.Policy), Trust: string(c.RequiredGuard.Trust), Membership: string(c.RequiredGuard.Membership), OwnershipEpoch: string(c.RequiredGuard.OwnershipEpoch), FenceEpoch: string(c.RequiredGuard.FenceEpoch), Generation: string(c.RequiredGuard.Generation), BootID: string(c.RequiredGuard.BootID), ProcessIncarnation: string(c.RequiredGuard.ProcessIncarnation)},
		Timing:        evidence.CommandTiming{TimeBase: string(c.Timing.TimeBase), DeadlineTick: c.Timing.DeadlineTick}, OriginalBudget: string(c.OriginalBudget),
	}
}
func registryCommand(c evidence.Command) Command {
	return Command{
		Schema: c.Schema, Operation: c.Operation,
		Scope:               Scope{Realm: ID(c.Scope.Realm), Host: ID(c.Scope.Host), Resource: ID(c.Scope.Resource), Backend: ID(c.Scope.Backend)},
		Execution:           Execution{RequestID: ID(c.Execution.RequestID), ExecutionKey: ID(c.Execution.ExecutionKey), OperationID: ID(c.Execution.OperationID), AttemptID: ID(c.Execution.AttemptID), StepID: ID(c.Execution.StepID)},
		RequestingPrincipal: ID(c.RequestingPrincipal), AuthorizationIssuer: ID(c.AuthorizationIssuer),
		CandidateRevision: ID(c.CandidateRevision), CandidateContentPin: ID(c.CandidateContentPin),
		Expected:      Reference{Revision: ID(c.Expected.Revision), StateVersion: c.Expected.StateVersion},
		RequiredGuard: Guard{Policy: ID(c.RequiredGuard.Policy), Trust: ID(c.RequiredGuard.Trust), Membership: ID(c.RequiredGuard.Membership), OwnershipEpoch: ID(c.RequiredGuard.OwnershipEpoch), FenceEpoch: ID(c.RequiredGuard.FenceEpoch), Generation: ID(c.RequiredGuard.Generation), BootID: ID(c.RequiredGuard.BootID), ProcessIncarnation: ID(c.RequiredGuard.ProcessIncarnation)},
		Timing:        Timing{TimeBase: ID(c.Timing.TimeBase), DeadlineTick: c.Timing.DeadlineTick}, OriginalBudget: ID(c.OriginalBudget),
	}
}
func validateCommand(c Command) error {
	if err := evidence.ValidateCommand(sharedCommand(c)); err != nil {
		return commandContractError(err, c)
	}
	return nil
}

// CanonicalBinding delegates the literal Schema1/Profile1 bytes to Contracts.
// This does not authenticate a principal, select a signature or authorize mutation.
func CanonicalBinding(c Command) (Binding, error) {
	binding, err := evidence.ComputeBinding(sharedCommand(c))
	if err != nil {
		return "", commandContractError(err, c)
	}
	return Binding(binding), nil
}
func ValidateRequest(r Request) error {
	err := evidence.ValidateRequest(evidence.Request{Command: sharedCommand(r.Command), Binding: string(r.Binding)})
	if err == nil {
		return nil
	}
	var failure *evidence.Error
	if errors.As(err, &failure) && failure != nil && failure.Code == "request_binding" {
		return bindingContractError(r.Binding)
	}
	return commandContractError(err, r.Command)
}

// DecodeRequest never constructs a successful C10 Request from diagnostics.
// Only a successful shared DecodeRequest can reach registryCommand.
func DecodeRequest(data []byte) (Request, error) {
	request, diagnostic, err := evidence.DecodeRequestWithDiagnostic(data)
	if err != nil {
		return Request{}, decodeContractError(err, diagnostic)
	}
	if diagnostic != evidence.RequestDiagnosticNone {
		return Request{}, invalid("request.json")
	}
	return Request{Command: registryCommand(request.Command), Binding: Binding(request.Binding)}, nil
}
func bindingContractError(binding Binding) error {
	if len(binding) == 0 || len(binding) > maxRequestBytes || !utf8.ValidString(string(binding)) {
		return invalid("request.binding")
	}
	return collision("request.binding")
}

// Rejection-only mapping. No input JSON/Binding/Command is reparsed here.
func decodeContractError(err error, diagnostic evidence.RequestDiagnostic) error {
	var failure *evidence.Error
	if !errors.As(err, &failure) || failure == nil {
		return invalid("request.json")
	}
	switch diagnostic {
	case evidence.RequestDiagnosticBindingConflict:
		if failure.Code == "request_binding" || failure.Code == "encoding" {
			return collision("request.binding")
		}
	case evidence.RequestDiagnosticBindingInvalid:
		if failure.Code == "request_binding" {
			return invalid("request.binding")
		}
	case evidence.RequestDiagnosticInvalid:
		switch failure.Code {
		case "request_version":
			return invalid("command.schema")
		case "request_operation":
			return invalid("command.operation")
		}
	}
	// None with an error, unknown enum/Code and contradictory diagnostics fail
	// closed. Even a known Binding diagnostic cannot override an unknown error.
	return invalid("request.json")
}

// commandContractError is rejection-only diagnostic metadata. Shared validation
// is the SOLE acceptance predicate. Unknown shared codes stay fail-closed.
func commandContractError(err error, c Command) error {
	var failure *evidence.Error
	if !errors.As(err, &failure) || failure == nil {
		return invalid("command")
	}
	switch failure.Code {
	case "request_version":
		return invalid("command.schema")
	case "request_operation":
		return invalid("command.operation")
	case "request_identity":
		if e := ValidateScope(c.Scope); e != nil {
			return e
		}
		if e := ValidateExecution(c.Execution); e != nil {
			return e
		}
		for _, item := range []struct {
			value ID
			field string
		}{
			{c.RequestingPrincipal, "command.requesting_principal"}, {c.AuthorizationIssuer, "command.authorization_issuer"},
			{c.CandidateRevision, "command.candidate_revision"}, {c.CandidateContentPin, "command.candidate_content_pin"},
			{c.Expected.Revision, "command.expected.revision"}, {c.RequiredGuard.Policy, "command.guard.policy"},
			{c.RequiredGuard.Trust, "command.guard.trust"}, {c.RequiredGuard.Membership, "command.guard.membership"},
			{c.RequiredGuard.OwnershipEpoch, "command.guard.ownership_epoch"}, {c.RequiredGuard.FenceEpoch, "command.guard.fence_epoch"},
			{c.RequiredGuard.Generation, "command.guard.generation"}, {c.RequiredGuard.BootID, "command.guard.boot_id"},
			{c.RequiredGuard.ProcessIncarnation, "command.guard.process_incarnation"}, {c.Timing.TimeBase, "command.timing.time_base"}, {c.OriginalBudget, "command.original_budget"},
		} {
			if e := validateID(item.value, item.field); e != nil {
				return e
			}
		}
	case "request_number":
		if c.Expected.StateVersion == math.MaxUint64 {
			return invalid("command.expected.state_version")
		}
		if c.Timing.DeadlineTick == 0 {
			return invalid("command.timing.deadline_tick")
		}
	}
	return invalid("command")
}
