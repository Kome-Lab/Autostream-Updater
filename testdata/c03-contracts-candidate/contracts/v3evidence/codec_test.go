package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Every issuer, proof, time point and actor in this file is synthetic data.
// Passing a Codec test is not authentication, expiry qualification, CP business
// authorization, a deployed Producer or an independent Continuity result.
func evidenceTestKinds() []Kind {
	return []Kind{CPAuthorizationKind, PolicyKind, TrustKind, MembershipKind,
		OwnershipKind, FenceKind, GenerationKind, BootKind, ProcessKind,
		PAdmissionKind, DrainKind, CandidateKind, BusinessAdmissionKind}
}

func evidenceTestRaw(kind Kind) []byte {
	common := fmt.Sprintf(`{"protocol_version":3,"evidence_id":"evidence-1","kind":%q,"issuer":"synthetic-owner","audience":"synthetic-executor","scope":{"realm":"realm-1","host":"host-1","resource":"resource-1","backend":"registry-1"},"execution":{"request_id":"request-1","execution_key":"execution-1","operation_id":"operation-1","attempt_id":"attempt-1","step_id":"step-1"},"binding":"synthetic-immutable-binding","backend_read_frame":{"issuer":"backend-observer","serving_incarnation":"backend-process-1","generation":"generation-1","snapshot_id":"snapshot-1","observation_proof":"observation-proof-1"},"validity":{"status":"SPECIFIED","issued":{"time_base":"synthetic-clock","boot_id":"boot-1","tick":0},"expiry":{"time_base":"synthetic-clock","boot_id":"boot-1","tick":100},"qualification_proof":"synthetic-clock-proof"},"integrity":{"profile_id":"synthetic-profile","key_id":"synthetic-key","key_revision":"key-revision-1","proof":"synthetic-integrity-proof"},`, kind)
	payloads := map[Kind]string{
		CPAuthorizationKind:   `"cp_authorization":{"action":"registry.reference_only","decision":"AUTHORIZED","policy_revision":"policy-1","trust_revision":"trust-1"}`,
		PolicyKind:            `"policy":{"revision":"policy-1","revocation":"ACTIVE","subject_evidence_id":"authorization-1"}`,
		TrustKind:             `"trust":{"revision":"trust-1","revocation":"ACTIVE","subject_evidence_id":"authorization-1"}`,
		MembershipKind:        `"membership":{"domain_id":"domain-1","revision":"membership-1","state":"MEMBER"}`,
		OwnershipKind:         `"ownership":{"owner_id":"owner-1","ownership_epoch":"ownership-1","fence_epoch":"fence-1","boot_id":"boot-1","process_incarnation":"incarnation-1","state":"CURRENT"}`,
		FenceKind:             `"fence":{"owner_id":"owner-1","ownership_epoch":"ownership-1","fence_epoch":"fence-1","boot_id":"boot-1","process_incarnation":"incarnation-1","state":"CURRENT"}`,
		GenerationKind:        `"generation":{"generation":"generation-1","state":"ACTIVE"}`,
		BootKind:              `"boot":{"boot_id":"boot-1","actor_id":"executor-1","actor_role":"LOCAL_EXECUTOR"}`,
		ProcessKind:           `"process":{"boot_id":"boot-1","process_id":123,"start_ticks":456,"incarnation":"incarnation-1","actor_id":"executor-1","actor_role":"LOCAL_EXECUTOR"}`,
		PAdmissionKind:        `"p_admission":{"admission_epoch":"admission-1","state":"OPEN","consumption":"UNCONSUMED","revocation":"ACTIVE"}`,
		DrainKind:             `"drain":{"domain_id":"domain-1","resource_ids":["resource-1","resource-2"],"drain_epoch":"drain-1","membership_revision":"membership-1","state":"READY","seal":"drain-seal-1","completion_proof":"completion-proof-1"}`,
		CandidateKind:         `"candidate":{"candidate_id":"candidate-1","approval":"APPROVED","revision":"revision-2","content_hash":"opaque-content-1","resource_id":"resource-1","approver_id":"approver-1"}`,
		BusinessAdmissionKind: `"business_admission":{"state":"CLOSED","authority_revision":"business-1"}`,
	}
	return []byte(common + payloads[kind] + "}")
}

func evidenceTestDecode(t *testing.T, raw []byte) Envelope {
	t.Helper()
	value, err := Decode(raw)
	if err != nil {
		t.Fatalf("synthetic envelope Decode failed: %v", err)
	}
	return value
}

func evidenceTestEdit(t *testing.T, raw []byte, change func(map[string]json.RawMessage)) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	change(object)
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func evidenceTestNestedEdit(t *testing.T, raw []byte, key string, change func(map[string]json.RawMessage)) []byte {
	t.Helper()
	return evidenceTestEdit(t, raw, func(object map[string]json.RawMessage) {
		object[key] = evidenceTestEdit(t, object[key], change)
	})
}

func evidenceTestRejected(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := Decode(raw); err == nil {
		t.Fatal("strict Decode accepted malformed or unsupported evidence")
	}
}

func TestEvidenceEachKindIndependentGoldenDecode(t *testing.T) {
	for _, kind := range evidenceTestKinds() {
		t.Run(string(kind), func(t *testing.T) {
			raw := evidenceTestRaw(kind)
			original := append([]byte(nil), raw...)
			value := evidenceTestDecode(t, raw)
			if value.ProtocolVersion != 3 || value.Kind != kind || value.EvidenceID != "evidence-1" ||
				value.Issuer != "synthetic-owner" || value.Audience != "synthetic-executor" ||
				value.Scope != (Scope{Realm: "realm-1", Host: "host-1", Resource: "resource-1", Backend: "registry-1"}) ||
				value.Execution != (Execution{RequestID: "request-1", ExecutionKey: "execution-1", OperationID: "operation-1", AttemptID: "attempt-1", StepID: "step-1"}) ||
				value.Binding != "synthetic-immutable-binding" {
				t.Fatalf("decoded common contract mismatch: %+v", value)
			}
			if value.Frame != (BackendReadFrame{Issuer: "backend-observer", ServingIncarnation: "backend-process-1", Generation: "generation-1", SnapshotID: "snapshot-1", ObservationProof: "observation-proof-1"}) {
				t.Fatal("backend frame lost or reinterpreted")
			}
			if value.Validity.Status != "SPECIFIED" || value.Validity.Issued == nil || value.Validity.Expiry == nil ||
				value.Validity.Issued.Tick != 0 || value.Validity.Expiry.Tick != 100 ||
				value.Integrity.Proof != "synthetic-integrity-proof" {
				t.Fatal("issuance, expiry or integrity data lost")
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("Decode modified caller bytes")
			}
			encoded, err := Encode(value)
			if err != nil {
				t.Fatal(err)
			}
			again := evidenceTestDecode(t, encoded)
			if !reflect.DeepEqual(value, again) {
				t.Fatal("typed envelope round trip changed content")
			}
		})
	}
}

func TestEvidenceUnknownProtocolAndKind(t *testing.T) {
	for _, version := range []string{"0", "2", "4", "4294967296", "-1", "3.0", "3e0", `"3"`, "null"} {
		t.Run("version-"+version, func(t *testing.T) {
			raw := evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) { object["protocol_version"] = json.RawMessage(version) })
			evidenceTestRejected(t, raw)
		})
	}
	for _, kind := range []string{"", "continuity", "witness", "outstanding_liability", "cp_Authorization", "v2_mutation_grant", "unknown"} {
		t.Run("kind-"+kind, func(t *testing.T) {
			raw := evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) { object["kind"], _ = json.Marshal(kind) })
			evidenceTestRejected(t, raw)
		})
	}
}

func TestEvidenceDuplicateAndEscapedKeysRejectedRecursively(t *testing.T) {
	base := evidenceTestRaw(CPAuthorizationKind)
	for _, tc := range []struct{ name, old, replacement string }{
		{"top-level", `"issuer":"synthetic-owner"`, `"issuer":"other","issuer":"synthetic-owner"`},
		{"same-value", `"issuer":"synthetic-owner"`, `"issuer":"synthetic-owner","issuer":"synthetic-owner"`},
		{"escaped-key-alias", `"issuer":"synthetic-owner"`, `"issuer":"synthetic-owner","\u0069ssuer":"synthetic-owner"`},
		{"nested-scope", `"resource":"resource-1"`, `"resource":"resource-1","resource":"resource-1"`},
		{"nested-validity", `"tick":0`, `"tick":0,"tick":0`},
		{"nested-integrity", `"proof":"synthetic-integrity-proof"`, `"proof":"synthetic-integrity-proof","proof":"another-proof"`},
		{"nested-payload", `"decision":"AUTHORIZED"`, `"decision":"DENIED","decision":"AUTHORIZED"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(base, []byte(tc.old)) {
				t.Fatal("bad duplicate fixture")
			}
			evidenceTestRejected(t, bytes.Replace(base, []byte(tc.old), []byte(tc.replacement), 1))
		})
	}
}

func TestEvidenceExactFieldCaseAndExtraFields(t *testing.T) {
	for _, key := range []string{"Issuer", "ISSUER", "issuer_url", "path", "sql", "continuity", "witness", "extra"} {
		t.Run(key, func(t *testing.T) {
			raw := evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) {
				if key == "Issuer" || key == "ISSUER" {
					object[key] = object["issuer"]
					delete(object, "issuer")
				} else {
					object[key] = json.RawMessage("null")
				}
			})
			evidenceTestRejected(t, raw)
		})
	}
	for _, key := range []string{"scope", "execution", "backend_read_frame", "validity", "integrity", "cp_authorization"} {
		t.Run("nested-"+key, func(t *testing.T) {
			raw := evidenceTestNestedEdit(t, evidenceTestRaw(CPAuthorizationKind), key, func(object map[string]json.RawMessage) { object["Extra"] = json.RawMessage(`"forbidden"`) })
			evidenceTestRejected(t, raw)
		})
	}
	raw := bytes.Replace(evidenceTestRaw(CPAuthorizationKind), []byte(`"tick":0`), []byte(`"Tick":0`), 1)
	evidenceTestRejected(t, raw)
}

func TestEvidenceRequiredFieldsAndNullRejected(t *testing.T) {
	for _, field := range []string{"protocol_version", "evidence_id", "kind", "issuer", "audience", "scope", "execution", "binding", "backend_read_frame", "validity", "integrity", "cp_authorization"} {
		for _, mode := range []string{"missing", "null"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				raw := evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) {
					if mode == "missing" {
						delete(object, field)
					} else {
						object[field] = json.RawMessage("null")
					}
				})
				evidenceTestRejected(t, raw)
			})
		}
	}
	for key, fields := range map[string][]string{
		"scope":              {"realm", "host", "resource", "backend"},
		"execution":          {"request_id", "execution_key", "operation_id", "attempt_id", "step_id"},
		"backend_read_frame": {"issuer", "serving_incarnation", "generation", "snapshot_id", "observation_proof"},
		"integrity":          {"profile_id", "key_id", "key_revision", "proof"},
		"cp_authorization":   {"action", "decision", "policy_revision", "trust_revision"},
	} {
		for _, field := range fields {
			t.Run(key+"/"+field, func(t *testing.T) {
				raw := evidenceTestNestedEdit(t, evidenceTestRaw(CPAuthorizationKind), key, func(object map[string]json.RawMessage) { delete(object, field) })
				evidenceTestRejected(t, raw)
			})
		}
	}
}

func TestEvidenceDiscriminatedPayloadRejectsAmbiguity(t *testing.T) {
	base := evidenceTestRaw(CPAuthorizationKind)
	for _, mode := range []string{"wrong-kind", "two-payloads", "unknown-payload", "payload-null", "bad-action", "extra-owner-epoch"} {
		t.Run(mode, func(t *testing.T) {
			raw := evidenceTestEdit(t, base, func(object map[string]json.RawMessage) {
				switch mode {
				case "wrong-kind":
					object["kind"] = json.RawMessage(`"trust"`)
				case "two-payloads":
					object["policy"] = json.RawMessage(`{"revision":"policy-1","revocation":"ACTIVE","subject_evidence_id":"authorization-1"}`)
				case "unknown-payload":
					object["payload"] = object["cp_authorization"]
				case "payload-null":
					object["cp_authorization"] = json.RawMessage("null")
				case "bad-action":
					object["cp_authorization"] = json.RawMessage(`{"action":"service.restart","decision":"AUTHORIZED","policy_revision":"policy-1","trust_revision":"trust-1"}`)
				case "extra-owner-epoch":
					object["cp_authorization"] = json.RawMessage(`{"action":"registry.reference_only","decision":"AUTHORIZED","policy_revision":"policy-1","trust_revision":"trust-1","ownership_epoch":"ownership-1"}`)
				}
			})
			evidenceTestRejected(t, raw)
		})
	}
}

func TestEvidenceUint64PrecisionAndCanonicalNumericSyntax(t *testing.T) {
	maximum := "18446744073709551615"
	raw := bytes.Replace(evidenceTestRaw(CPAuthorizationKind), []byte(`"tick":100`), []byte(`"tick":`+maximum), 1)
	value := evidenceTestDecode(t, raw)
	if value.Validity.Expiry.Tick != ^uint64(0) {
		t.Fatal("uint64 maximum lost precision")
	}
	for _, number := range []string{"18446744073709551616", "-1", "100.0", "1e2", `"100"`, "null", "true"} {
		t.Run(number, func(t *testing.T) {
			raw := bytes.Replace(evidenceTestRaw(CPAuthorizationKind), []byte(`"tick":100`), []byte(`"tick":`+number), 1)
			evidenceTestRejected(t, raw)
		})
	}
	process := bytes.Replace(evidenceTestRaw(ProcessKind), []byte(`"start_ticks":456`), []byte(`"start_ticks":`+maximum), 1)
	if evidenceTestDecode(t, process).Process.StartTicks != ^uint64(0) {
		t.Fatal("raw OS numeric fact lost precision")
	}
}

func TestEvidenceValidityAndRevocationUnknownRemainData(t *testing.T) {
	raw := evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) { object["validity"] = json.RawMessage(`{"status":"UNKNOWN"}`) })
	value := evidenceTestDecode(t, raw)
	if value.Validity.Status != "UNKNOWN" || value.Validity.Issued != nil || value.Validity.Expiry != nil || value.Validity.QualificationProof != "" {
		t.Fatal("unknown validity was filled from a clock or Context")
	}
	for _, kind := range []Kind{PolicyKind, TrustKind, PAdmissionKind} {
		t.Run(string(kind), func(t *testing.T) {
			key := string(kind)
			raw := evidenceTestNestedEdit(t, evidenceTestRaw(kind), key, func(object map[string]json.RawMessage) { object["revocation"] = json.RawMessage(`"UNKNOWN"`) })
			value := evidenceTestDecode(t, raw)
			encoded, err := Encode(value)
			if err != nil || !bytes.Contains(encoded, []byte(`"revocation":"UNKNOWN"`)) {
				t.Fatal("unknown revocation upgraded or lost")
			}
		})
	}
	for _, validity := range []string{
		`{"status":"UNKNOWN","issued":{"time_base":"clock","boot_id":"boot","tick":1}}`,
		`{"status":"UNKNOWN","qualification_proof":"not-allowed"}`,
		`{"status":"SPECIFIED"}`,
		`{"status":"unrecognized"}`,
	} {
		evidenceTestRejected(t, evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) { object["validity"] = json.RawMessage(validity) }))
	}
}

func TestEvidencePayloadConditionalRequirements(t *testing.T) {
	for _, mode := range []string{"ready-no-seal", "ready-no-completion", "held-with-seal", "duplicate-resource", "missing-resource", "approved-no-approver", "pending-with-approver", "unknown-business"} {
		t.Run(mode, func(t *testing.T) {
			kind, key := DrainKind, "drain"
			if strings.HasPrefix(mode, "approved") || strings.HasPrefix(mode, "pending") {
				kind, key = CandidateKind, "candidate"
			}
			if mode == "unknown-business" {
				kind, key = BusinessAdmissionKind, "business_admission"
			}
			raw := evidenceTestNestedEdit(t, evidenceTestRaw(kind), key, func(object map[string]json.RawMessage) {
				switch mode {
				case "ready-no-seal":
					delete(object, "seal")
				case "ready-no-completion":
					delete(object, "completion_proof")
				case "held-with-seal":
					object["state"] = json.RawMessage(`"HELD"`)
				case "duplicate-resource":
					object["resource_ids"] = json.RawMessage(`["resource-1","resource-1"]`)
				case "missing-resource":
					object["resource_ids"] = json.RawMessage(`["different-resource"]`)
				case "approved-no-approver":
					delete(object, "approver_id")
				case "pending-with-approver":
					object["approval"] = json.RawMessage(`"PENDING"`)
				case "unknown-business":
					object["state"] = json.RawMessage(`"unrecognized"`)
				}
			})
			evidenceTestRejected(t, raw)
		})
	}
	unknownBusiness := evidenceTestNestedEdit(t, evidenceTestRaw(BusinessAdmissionKind), "business_admission", func(object map[string]json.RawMessage) { object["state"] = json.RawMessage(`"UNKNOWN"`) })
	if evidenceTestDecode(t, unknownBusiness).BusinessAdmission.State != "UNKNOWN" {
		t.Fatal("unknown business admission upgraded")
	}
}

func TestEvidenceTrailingJSONUTF8AndSizeBound(t *testing.T) {
	base := evidenceTestRaw(CPAuthorizationKind)
	for _, raw := range [][]byte{nil, {}, []byte("null"), []byte("[]"), append(append([]byte(nil), base...), []byte(" {}")...), append(append([]byte(nil), base...), 0xff)} {
		evidenceTestRejected(t, raw)
	}
	invalidUTF8 := append([]byte(nil), base...)
	index := bytes.Index(invalidUTF8, []byte("synthetic-immutable-binding"))
	invalidUTF8[index] = 0xff
	evidenceTestRejected(t, invalidUTF8)
	oversized := append([]byte(strings.Repeat(" ", MaxEnvelopeBytes)), base...)
	evidenceTestRejected(t, oversized)
}

func TestEvidenceCloneDeepAndCallerDetachment(t *testing.T) {
	for _, kind := range evidenceTestKinds() {
		t.Run(string(kind), func(t *testing.T) {
			value := evidenceTestDecode(t, evidenceTestRaw(kind))
			copy := Clone(value)
			if !reflect.DeepEqual(value, copy) {
				t.Fatal("Clone changed typed evidence")
			}
			if copy.Validity.Issued == value.Validity.Issued || copy.Validity.Expiry == value.Validity.Expiry {
				t.Fatal("Clone shares validity pointers")
			}
			originalValue, copiedValue := reflect.ValueOf(value), reflect.ValueOf(copy)
			for _, field := range []string{"CPAuthorization", "Policy", "Trust", "Membership", "Ownership", "Fence", "Generation", "Boot", "Process", "PAdmission", "Drain", "Candidate", "BusinessAdmission"} {
				before, after := originalValue.FieldByName(field), copiedValue.FieldByName(field)
				if !before.IsNil() && before.Pointer() == after.Pointer() {
					t.Fatalf("Clone shares %s payload", field)
				}
			}
			copy.Validity.Issued.Tick = 1
			if value.Validity.Issued.Tick != 0 {
				t.Fatal("Clone changed original issuance")
			}
			if kind == DrainKind {
				copy.Drain.ResourceIDs[0] = "changed-resource"
				if value.Drain.ResourceIDs[0] != "resource-1" {
					t.Fatal("Clone shares ResourceIDs backing storage")
				}
			}
		})
	}
	raw := evidenceTestRaw(CPAuthorizationKind)
	value := evidenceTestDecode(t, raw)
	before := Clone(value)
	for index := range raw {
		raw[index] = 'x'
	}
	if !reflect.DeepEqual(value, before) {
		t.Fatal("decoded envelope retained mutable input bytes")
	}
}

func TestEvidenceEncodeRejectsInvalidTypedModels(t *testing.T) {
	for _, mode := range []string{"version", "multiple", "issuer", "action", "proof", "interval"} {
		t.Run(mode, func(t *testing.T) {
			value := evidenceTestDecode(t, evidenceTestRaw(CPAuthorizationKind))
			switch mode {
			case "version":
				value.ProtocolVersion++
			case "multiple":
				value.Policy = &RevisionPayload{Revision: "policy-1", Revocation: "ACTIVE", SubjectEvidenceID: "authorization-1"}
			case "issuer":
				value.Issuer = ""
			case "action":
				value.CPAuthorization.Action = "service.restart"
			case "proof":
				value.Integrity.Proof = ""
			case "interval":
				value.Validity.Expiry.Tick = value.Validity.Issued.Tick
			}
			if _, err := Encode(value); err == nil {
				t.Fatal("Encode accepted invalid programmatic evidence")
			}
		})
	}
}

func TestEvidenceSafeErrorsDoNotEchoUntrustedData(t *testing.T) {
	raw := evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) {
		object["secret-private-path-SQL-token"] = json.RawMessage(`"untrusted-personal-payload"`)
	})
	_, err := Decode(raw)
	if err == nil {
		t.Fatal("bad fixture accepted")
	}
	for _, secret := range []string{"secret-private", "SQL", "token", "untrusted-personal-payload"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("raw untrusted input leaked through error")
		}
	}
}

func TestEvidenceEveryPayloadRequiredField(t *testing.T) {
	cases := []struct {
		kind   Kind
		key    string
		fields []string
	}{
		{CPAuthorizationKind, "cp_authorization", []string{"action", "decision", "policy_revision", "trust_revision"}},
		{PolicyKind, "policy", []string{"revision", "revocation", "subject_evidence_id"}},
		{TrustKind, "trust", []string{"revision", "revocation", "subject_evidence_id"}},
		{MembershipKind, "membership", []string{"domain_id", "revision", "state"}},
		{OwnershipKind, "ownership", []string{"owner_id", "ownership_epoch", "fence_epoch", "boot_id", "process_incarnation", "state"}},
		{FenceKind, "fence", []string{"owner_id", "ownership_epoch", "fence_epoch", "boot_id", "process_incarnation", "state"}},
		{GenerationKind, "generation", []string{"generation", "state"}},
		{BootKind, "boot", []string{"boot_id", "actor_id", "actor_role"}},
		{ProcessKind, "process", []string{"boot_id", "process_id", "start_ticks", "incarnation", "actor_id", "actor_role"}},
		{PAdmissionKind, "p_admission", []string{"admission_epoch", "state", "consumption", "revocation"}},
		{DrainKind, "drain", []string{"domain_id", "resource_ids", "drain_epoch", "membership_revision", "state", "seal", "completion_proof"}},
		{CandidateKind, "candidate", []string{"candidate_id", "approval", "revision", "content_hash", "resource_id", "approver_id"}},
		{BusinessAdmissionKind, "business_admission", []string{"state", "authority_revision"}},
	}
	for _, tc := range cases {
		for _, field := range tc.fields {
			for _, mode := range []string{"missing", "null"} {
				t.Run(tc.key+"/"+field+"/"+mode, func(t *testing.T) {
					raw := evidenceTestNestedEdit(t, evidenceTestRaw(tc.kind), tc.key, func(object map[string]json.RawMessage) {
						if mode == "missing" {
							delete(object, field)
						} else {
							object[field] = json.RawMessage("null")
						}
					})
					evidenceTestRejected(t, raw)
				})
			}
		}
	}
}

func TestEvidenceIdentifierProfileRejectsPathsAndNonCanonicalIDs(t *testing.T) {
	for _, value := range []string{"", "../private", "https://unapproved.invalid", "SELECT *", "UPPERCASE", "identity with space", "identity\nline", strings.Repeat("a", 129)} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			raw := evidenceTestEdit(t, evidenceTestRaw(CPAuthorizationKind), func(object map[string]json.RawMessage) { object["issuer"], _ = json.Marshal(value) })
			evidenceTestRejected(t, raw)
		})
	}
}
