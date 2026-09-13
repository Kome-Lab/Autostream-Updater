package hostruntime

import (
	"bytes"
	"strings"
	"testing"
)

func TestLocalExecutorRequestIsProbeOnlyAndStrict(t *testing.T) {
	valid := `{"version":1,"operation":"probe","service_id":"worker-01"}`
	request, err := DecodeLocalExecutorRequest(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("DecodeLocalExecutorRequest: %v", err)
	}
	if request != (LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: "worker-01"}) {
		t.Fatalf("request=%+v", request)
	}

	for name, payload := range map[string]string{
		"mutation":       `{"version":1,"operation":"apply","service_id":"worker-01"}`,
		"unknown":        `{"version":1,"operation":"probe","service_id":"worker-01","command":"/bin/sh"}`,
		"path":           `{"version":1,"operation":"probe","service_id":"worker-01","path":"/tmp/payload"}`,
		"unit":           `{"version":1,"operation":"probe","service_id":"worker-01","unit":"attacker.service"}`,
		"url":            `{"version":1,"operation":"probe","service_id":"worker-01","url":"http://127.0.0.1:1"}`,
		"image":          `{"version":1,"operation":"probe","service_id":"worker-01","image":"attacker/image"}`,
		"credential":     `{"version":1,"operation":"probe","service_id":"worker-01","mutation_grant":"secret"}`,
		"second request": valid + "\n" + valid,
		"trailing":       valid + "x",
		"bad identity":   `{"version":1,"operation":"probe","service_id":"../worker"}`,
		"wrong version":  `{"version":2,"operation":"probe","service_id":"worker-01"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalExecutorRequest(strings.NewReader(payload)); err == nil {
				t.Fatal("malformed or privileged request was accepted")
			}
		})
	}

	oversize := `{"version":1,"operation":"probe","service_id":"` +
		strings.Repeat("a", LocalExecutorProtocolMaxFrameBytes) + `"}`
	if _, err := DecodeLocalExecutorRequest(strings.NewReader(oversize)); err == nil {
		t.Fatal("oversized request was accepted")
	}
}

func TestLocalExecutorResponseFromOutcomePreservesSafeFailureMessage(t *testing.T) {
	response := localExecutorResponseFromOutcome(executorMutationOutcome{
		Error: &executorMutationFailure{
			Code:    "stage_failed",
			Message: "candidate binary smoke execution failed",
		},
	})
	if err := response.Validate(); err != nil {
		t.Fatalf("response.Validate: %v", err)
	}
	if response.Error == nil || response.Error.Code != "stage_failed" || response.Error.Message != "candidate binary smoke execution failed" {
		t.Fatalf("response=%+v", response)
	}
	versionMismatch := localExecutorResponseFromOutcome(executorMutationOutcome{
		Error: &executorMutationFailure{
			Code:    "stage_failed",
			Message: "candidate binary version output mismatch",
		},
	})
	if err := versionMismatch.Validate(); err != nil {
		t.Fatalf("versionMismatch.Validate: %v", err)
	}
	if versionMismatch.Error == nil || versionMismatch.Error.Code != "stage_failed" || versionMismatch.Error.Message != "candidate binary version output mismatch" {
		t.Fatalf("versionMismatch=%+v", versionMismatch)
	}
}

func TestLocalExecutorMutationProtocolCarriesOnlyBoundedPlanAndEphemeralGrant(t *testing.T) {
	plan := validMutationPlan()
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: "stage", ServiceID: plan.TargetID,
		Plan: &plan, SourcePolicyRevision: 5, OwnershipEpoch: 7,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 13,
	}
	var encoded bytes.Buffer
	if err := EncodeLocalExecutorRequest(&encoded, request); err != nil {
		t.Fatalf("EncodeLocalExecutorRequest: %v", err)
	}
	payload := encoded.String()
	if strings.Contains(payload, "credential") || strings.Contains(payload, "[REDACTED]") {
		t.Fatalf("stage transferred a credential: %q", payload)
	}
	decoded, err := DecodeLocalExecutorRequest(&encoded)
	if err != nil {
		t.Fatalf("DecodeLocalExecutorRequest: %v", err)
	}
	if decoded.Plan == nil || decoded.Plan.PlanSHA256 != plan.PlanSHA256 ||
		decoded.SourcePolicyRevision != 5 ||
		decoded.OwnershipEpoch != 7 ||
		decoded.OwnershipPolicyRevision != 11 ||
		decoded.ExecutorPolicyRevision != 13 {
		t.Fatalf("decoded=%+v", decoded)
	}

	for name, payload := range map[string]string{
		"version one mutation": `{"version":1,"operation":"apply","service_id":"worker-01"}`,
		"arbitrary command":    `{"version":2,"operation":"apply","service_id":"worker-01","command":"/bin/sh"}`,
		"arbitrary path":       `{"version":2,"operation":"apply","service_id":"worker-01","path":"/tmp/payload"}`,
		"arbitrary unit":       `{"version":2,"operation":"apply","service_id":"worker-01","unit":"attacker.service"}`,
		"arbitrary url":        `{"version":2,"operation":"apply","service_id":"worker-01","url":"https://attacker.example"}`,
		"arbitrary image":      `{"version":2,"operation":"apply","service_id":"worker-01","image":"attacker/image"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalExecutorRequest(strings.NewReader(payload)); err == nil {
				t.Fatal("unbounded privileged input was accepted")
			}
		})
	}

	apply := request
	apply.Operation = "apply"
	apply.MutationGrant = NewBoundedSecret("one-time-mutation-grant")
	encoded.Reset()
	if err := EncodeLocalExecutorRequest(&encoded, apply); err != nil {
		t.Fatalf("encode apply: %v", err)
	}
	if _, err := DecodeLocalExecutorRequest(&encoded); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
}

func TestLocalExecutorResponseIsBoundedAndStrict(t *testing.T) {
	response := LocalExecutorResponse{
		Version: LocalExecutorProtocolVersion,
		Probe: &LocalExecutorProbe{
			ServiceID:       "worker-01",
			ServiceType:     "worker",
			DeploymentMode:  ModeSystemd,
			PolicyRevision:  7,
			PolicySHA256:    "sha256:" + strings.Repeat("a", 64),
			ConfigRevision:  11,
			CurrentVersion:  "v1.2.3",
			MainPID:         101,
			ListenerPID:     102,
			ControlGroup:    "/system.slice/autostream-worker.service",
			ListenerAddress: "127.0.0.1:18084",
		},
	}
	var encoded bytes.Buffer
	if err := EncodeLocalExecutorResponse(&encoded, response); err != nil {
		t.Fatalf("EncodeLocalExecutorResponse: %v", err)
	}
	decoded, err := DecodeLocalExecutorResponse(&encoded)
	if err != nil {
		t.Fatalf("DecodeLocalExecutorResponse: %v", err)
	}
	if decoded.Probe == nil || decoded.Probe.ServiceID != "worker-01" {
		t.Fatalf("decoded=%+v", decoded)
	}

	for name, payload := range map[string]string{
		"unknown": `{"version":1,"error":{"code":"invalid_request","message":"request rejected","secret":"no"}}`,
		"both":    `{"version":1,"probe":` + mustJSON(t, response.Probe) + `,"error":{"code":"invalid_request","message":"request rejected"}}`,
		"bad code": `{"version":1,"error":{"code":"arbitrary",
			"message":"request rejected"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalExecutorResponse(strings.NewReader(payload)); err == nil {
				t.Fatal("invalid response was accepted")
			}
		})
	}
}
