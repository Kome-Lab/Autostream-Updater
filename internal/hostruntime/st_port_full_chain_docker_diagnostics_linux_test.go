//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type stPortChainDockerFailureEvidence struct {
	disposition, rejectionStage string
	classes                     []string
	capturedBytes               int
	truncated                   bool
}

func stPortChainDockerOutputEvidence(output string, truncated, daemonState bool) stPortChainDockerFailureEvidence {
	evidence := stPortChainDockerFailureEvidence{
		disposition: "unmatched", rejectionStage: "unknown", capturedBytes: len(output), truncated: truncated,
	}
	lower := strings.ToLower(output)
	if strings.TrimSpace(lower) == "" {
		evidence.disposition = "empty"
		return evidence
	}
	// These names describe observed text, not a guessed cause from exit status.
	// All matches stay in a closed vocabulary; unmatched output is never echoed.
	for _, candidate := range []struct{ text, class string }{
		{"connection refused", "connection_refused"}, {"x509:", "tls_validation_failed"},
		{"unauthorized", "authorization_failed"}, {"unknown flag:", "unsupported_flag"},
		{"client version", "api_version_mismatch"}, {"no such host", "dns_failed"},
		{"network is unreachable", "network_unreachable"}, {"permission denied", "permission_denied"},
		{"no such file or directory", "file_missing"}, {"read-only file system", "read_only_filesystem"},
		{"operation not permitted", "operation_not_permitted"}, {"invalid argument", "invalid_argument"},
		{"address already in use", "address_in_use"}, {"no space left on device", "space_exhausted"},
		{"cannot allocate memory", "memory_exhausted"}, {"operation not supported", "operation_unsupported"},
		{"failed to create task", "task_create_failed"}, {"oci runtime create failed", "oci_create_failed"},
		{"failed to start shim", "shim_start_failed"}, {"error mounting", "mount_failed"},
		{"failed to create network", "network_create_failed"}, {"failed to set up container networking", "network_setup_failed"},
		{"cgroup", "cgroup_mentioned"}, {"apparmor", "apparmor_mentioned"},
		{"seccomp", "seccomp_mentioned"}, {"invalid mount config", "mount_config_invalid"},
		{"invalid reference format", "image_reference_invalid"}, {"additional property", "compose_property_rejected"},
		{"invalid compose project", "compose_project_invalid"}, {"invalid interpolation format", "compose_interpolation_invalid"},
	} {
		if strings.Contains(lower, candidate.text) {
			evidence.classes = append(evidence.classes, candidate.class)
		}
	}
	// A phase requires the CLI's error envelope or the selected container's
	// daemon-owned State.Error. Container absence or exit=1 alone proves no phase.
	for _, line := range strings.Split(lower, "\n") {
		line = strings.TrimSpace(line)
		daemonEnvelope := strings.HasPrefix(line, "error response from daemon:")
		if daemonEnvelope || daemonState {
			if evidence.rejectionStage != "oci" {
				evidence.rejectionStage = "daemon"
			}
			if strings.Contains(line, "oci runtime create failed") || strings.Contains(line, "runc create failed") {
				evidence.rejectionStage = "oci"
			}
		} else if evidence.rejectionStage == "unknown" &&
			(strings.HasPrefix(line, "validating ") || strings.HasPrefix(line, "yaml:") ||
				strings.HasPrefix(line, "failed to parse ") || strings.HasPrefix(line, "invalid interpolation format") ||
				strings.HasSuffix(line, ": invalid compose project")) {
			evidence.rejectionStage = "compose_input"
		}
	}
	if len(evidence.classes) > 0 || evidence.rejectionStage != "unknown" {
		evidence.disposition = "matched"
	}
	return evidence
}

func (e stPortChainDockerFailureEvidence) summary() string {
	classes := "none"
	if len(e.classes) > 0 {
		classes = strings.Join(e.classes, ",")
	}
	return fmt.Sprintf("disposition=%s truncated=%t captured_bytes=%d rejection_stage=%s classes=%s",
		e.disposition, e.truncated, e.capturedBytes, e.rejectionStage, classes)
}

// The inspection template requests only this fixed fixture's identity and
// selected state fields. State.Error remains bounded in memory for the same
// closed classifier; no ID, image value, label, timestamp or raw error is logged.
const stPortChainDockerInitialInspectFormat = `{"id":{{json .Id}},"image":{{json .Image}},"config_image":{{json .Config.Image}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"status":{{json .State.Status}},"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},"oom_killed":{{json .State.OOMKilled}},"exit_code":{{json .State.ExitCode}},"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},"error":{{json .State.Error}}}`

type stPortChainDockerInitialInspect struct {
	ID          string `json:"id"`
	Image       string `json:"image"`
	ConfigImage string `json:"config_image"`
	Project     string `json:"project"`
	Service     string `json:"service"`
	Status      string `json:"status"`
	Running     bool   `json:"running"`
	Paused      bool   `json:"paused"`
	Restarting  bool   `json:"restarting"`
	Dead        bool   `json:"dead"`
	OOMKilled   bool   `json:"oom_killed"`
	ExitCode    int    `json:"exit_code"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	Error       string `json:"error"`
}

type stPortChainDockerContainerEvidence struct {
	observation, phase, status                                                    string
	running, paused, restarting, dead, oomKilled, started, finished, errorPresent bool
	exitCode                                                                      int
}

func stPortChainDockerInitialContainer(output string, truncated bool, id, imageID, imageRef string) (stPortChainDockerContainerEvidence, stPortChainDockerFailureEvidence) {
	evidence := stPortChainDockerContainerEvidence{observation: "invalid_state", phase: "unknown", status: "unknown", exitCode: -1}
	unknownError := stPortChainDockerFailureEvidence{disposition: "unavailable", rejectionStage: "unknown"}
	var state stPortChainDockerInitialInspect
	if truncated || json.Unmarshal([]byte(output), &state) != nil {
		if truncated {
			evidence.observation = "truncated_state"
		}
		return evidence, unknownError
	}
	if state.ID != id || state.Project != "autostream" || state.Service != "worker" || state.Image != imageID || state.ConfigImage != imageRef {
		evidence.observation = "identity_mismatch"
		return evidence, unknownError
	}
	started, startErr := time.Parse(time.RFC3339Nano, state.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, state.FinishedAt)
	if startErr != nil || finishErr != nil || state.ExitCode < 0 || state.ExitCode > 255 {
		return evidence, unknownError
	}
	evidence.observation = "observed"
	evidence.running, evidence.paused, evidence.restarting, evidence.dead = state.Running, state.Paused, state.Restarting, state.Dead
	evidence.oomKilled, evidence.started, evidence.finished, evidence.errorPresent = state.OOMKilled, !started.IsZero(), !finished.IsZero(), state.Error != ""
	evidence.exitCode = state.ExitCode
	switch state.Status {
	case "created", "running", "paused", "restarting", "removing", "exited", "dead":
		evidence.status = state.Status
	}
	switch {
	case state.Status == "created" && !state.Running && !evidence.started && !evidence.finished:
		evidence.phase = "created"
	case state.Status == "running" && state.Running && evidence.started && !evidence.finished && !state.Dead:
		evidence.phase = "running"
	case (state.Status == "exited" || state.Status == "dead") && !state.Running && evidence.started && evidence.finished:
		evidence.phase = "exited"
	}
	return evidence, stPortChainDockerOutputEvidence(state.Error, false, true)
}

func (e stPortChainDockerContainerEvidence) summary() string {
	return fmt.Sprintf("observation=%s phase=%s status=%s running=%t paused=%t restarting=%t dead=%t oom_killed=%t started=%t finished=%t exit_code=%d error_present=%t",
		e.observation, e.phase, e.status, e.running, e.paused, e.restarting, e.dead, e.oomKilled, e.started, e.finished, e.exitCode, e.errorPresent)
}

func (f *stPortChainDockerFixture) observeInitialFailure(t *testing.T, ctx context.Context) {
	t.Helper()
	// The original initial_up has already returned. Both commands below are
	// read-only and scoped to its fixed project/service, then its one exact ID.
	if f.target.ComposeProject != "autostream" || f.target.Service != "worker" || f.target.ImageRepo != dockerPortSmokeImageRepo ||
		!digestPattern.MatchString(f.imageID) || !digestPattern.MatchString(f.repositoryDigest) {
		t.Log("ST-PORT Docker initial container: observation=invalid_target phase=unknown")
		return
	}
	runner := OSCommandRunner{NewProcessGroup: true}
	output, truncated, err := runner.runWithOutputMetadata(ctx, "", dockerCommandEnv(), "/usr/bin/docker", "ps", "-aq", "--no-trunc",
		"--filter", "label=com.docker.compose.project=autostream", "--filter", "label=com.docker.compose.service=worker")
	if err != nil || truncated {
		t.Logf("ST-PORT Docker initial query: kind=selection succeeded=%t truncated=%t deadline_exceeded=%t", err == nil, truncated, ctx.Err() == context.DeadlineExceeded)
		t.Log("ST-PORT Docker initial container: observation=selection_unavailable phase=unknown")
		return
	}
	ids := strings.Fields(output)
	if len(ids) == 0 {
		t.Log("ST-PORT Docker initial container: observation=observed phase=absent")
		return
	}
	if len(ids) != 1 || len(ids[0]) != 64 || strings.Trim(ids[0], "0123456789abcdef") != "" {
		t.Log("ST-PORT Docker initial container: observation=selection_ambiguous phase=unknown")
		return
	}
	output, truncated, err = runner.runWithOutputMetadata(ctx, "", dockerCommandEnv(), "/usr/bin/docker", "inspect", "--type=container", "--format", stPortChainDockerInitialInspectFormat, ids[0])
	if err != nil {
		t.Logf("ST-PORT Docker initial query: kind=state succeeded=false truncated=%t deadline_exceeded=%t", truncated, ctx.Err() == context.DeadlineExceeded)
		t.Log("ST-PORT Docker initial container: observation=state_unavailable phase=unknown")
		return
	}
	state, stateError := stPortChainDockerInitialContainer(output, truncated, ids[0], f.imageID, dockerPortSmokeImageRepo+"@"+f.repositoryDigest)
	t.Log("ST-PORT Docker initial container: " + state.summary())
	t.Log("ST-PORT Docker initial state error: " + stateError.summary())
}

func TestSTPortDockerCommandOutputBoundaries(t *testing.T) {
	const maximum = 1 << 20
	for _, test := range []struct {
		name          string
		chunks        []int
		wantLength    int
		wantTruncated bool
	}{
		{"empty", []int{0}, 0, false},
		{"exact_limit", []int{maximum, 0}, maximum, false},
		{"discard_in_first_write", []int{maximum + 1}, maximum, true},
		{"discard_in_later_write", []int{maximum - 1, 1, 1, 0}, maximum, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var buffer limitedBuffer
			for _, length := range test.chunks {
				written, err := buffer.Write([]byte(strings.Repeat("x", length)))
				if err != nil || written != length {
					t.Fatal("bounded capture changed writer completion semantics")
				}
			}
			if buffer.Len() != test.wantLength || buffer.truncated != test.wantTruncated {
				t.Fatal("bounded capture did not distinguish a full buffer from discarded bytes")
			}
		})
	}
}

func TestSTPortDockerFailureEvidencePreservesUnknownAndStages(t *testing.T) {
	const sensitive = "DO_NOT_PUBLISH_FIXTURE_CREDENTIAL"
	for _, test := range []struct {
		name, output, disposition, stage string
		truncated                        bool
	}{
		{"empty", " \n", "empty", "unknown", false},
		{"unknown", sensitive, "unmatched", "unknown", false},
		{"truncated_unknown", sensitive, "unmatched", "unknown", true},
		{"class_is_not_phase", "permission denied: " + sensitive, "matched", "unknown", false},
		{"compose", "validating " + sensitive + ": additional property example is not allowed", "matched", "compose_input", false},
		{"daemon", "Error response from daemon: " + sensitive, "matched", "daemon", false},
		{"task_is_not_oci", "Error response from daemon: failed to create task for container: " + sensitive, "matched", "daemon", false},
		{"oci", "Error response from daemon: failed to create task for container: OCI runtime create failed: " + sensitive, "matched", "oci", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := stPortChainDockerOutputEvidence(test.output, test.truncated, false)
			if evidence.disposition != test.disposition || evidence.rejectionStage != test.stage || evidence.truncated != test.truncated || evidence.capturedBytes != len(test.output) {
				t.Fatal("failure evidence did not preserve the observed output shape and phase")
			}
			if strings.Contains(evidence.summary(), sensitive) {
				t.Fatal("failure summary exposed untrusted command output")
			}
		})
	}
}

func TestSTPortDockerContainerEvidenceRequiresExactIdentity(t *testing.T) {
	id, imageID, imageRef := strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), dockerPortSmokeImageRepo+"@sha256:"+strings.Repeat("c", 64)
	const sensitive = "DO_NOT_PUBLISH_FIXTURE_CREDENTIAL"
	const zero = "0001-01-01T00:00:00Z"
	for _, test := range []struct {
		name, status, started, finished, phase string
		running                                bool
	}{
		{"created", "created", zero, zero, "created", false},
		{"running", "running", "2026-01-01T00:00:00Z", zero, "running", true},
		{"exited", "exited", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", "exited", false},
		{"inconsistent", "running", zero, zero, "unknown", true},
		{"unlisted_status", sensitive, zero, zero, "unknown", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := stPortChainDockerInitialInspect{ID: id, Image: imageID, ConfigImage: imageRef, Project: "autostream", Service: "worker",
				Status: test.status, Running: test.running, StartedAt: test.started, FinishedAt: test.finished, Error: "OCI runtime create failed: " + sensitive}
			body, err := json.Marshal(state)
			if err != nil {
				t.Fatal("encode fixed state fixture")
			}
			evidence, stateError := stPortChainDockerInitialContainer(string(body), false, id, imageID, imageRef)
			if evidence.observation != "observed" || evidence.phase != test.phase || stateError.rejectionStage != "oci" {
				t.Fatal("selected container state did not preserve its observed lifecycle")
			}
			for _, forbidden := range []string{sensitive, id, imageID, imageRef, test.started} {
				if strings.Contains(evidence.summary()+stateError.summary(), forbidden) {
					t.Fatal("container summary exposed a non-allowlisted value")
				}
			}
			for _, mismatch := range []struct{ id, imageID, imageRef string }{{id + "d", imageID, imageRef}, {id, imageID + "d", imageRef}, {id, imageID, imageRef + "d"}} {
				mismatchEvidence, mismatchError := stPortChainDockerInitialContainer(string(body), false, mismatch.id, mismatch.imageID, mismatch.imageRef)
				if mismatchEvidence.observation != "identity_mismatch" || mismatchEvidence.phase != "unknown" || mismatchError.disposition != "unavailable" {
					t.Fatal("another container identity was accepted as the fixed target")
				}
			}
			for _, truncated := range []bool{false, true} {
				invalid, invalidError := stPortChainDockerInitialContainer("{", truncated, id, imageID, imageRef)
				if invalid.phase != "unknown" || invalid.observation == "observed" || invalidError.disposition != "unavailable" {
					t.Fatal("unavailable state was converted into a container phase")
				}
			}
		})
	}
}
