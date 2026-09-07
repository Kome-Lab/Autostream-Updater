//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
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

func (f *stPortChainDockerFixture) observeInitialFailure(t *testing.T, ctx context.Context, failureOutput string, failureTruncated bool) {
	t.Helper()
	// The original initial_up has already returned. All commands below are
	// read-only within its shared observation budget and fixed fixture targets.
	if f.target.ComposeProject != "autostream" || f.target.Service != "worker" || f.target.ImageRepo != dockerPortSmokeImageRepo ||
		!digestPattern.MatchString(f.imageID) || !digestPattern.MatchString(f.repositoryDigest) {
		t.Log("ST-PORT Docker initial container: observation=invalid_target phase=unknown")
		return
	}
	stPortChainDockerInitialProgress(t, failureOutput, failureTruncated)
	stPortChainDockerInitialStorage(t, ctx)
	stPortChainDockerInitialNetwork(t, ctx)
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

type stPortChainDockerProgress struct {
	first, last                                          string
	count                                                int
	creating, created, starting, started, failed, capped bool
}

func stPortChainDockerProgressFor(output, kind, name string) stPortChainDockerProgress {
	progress := stPortChainDockerProgress{first: "none", last: "none"}
	// Plain Compose progress names only the fixed resource. Strip display
	// escapes in memory and ignore all free-form suffixes and other resources.
	output = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`).ReplaceAllString(output, "")
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != kind || fields[1] != name {
			continue
		}
		phase := strings.ToLower(fields[2])
		switch phase {
		case "creating", "created", "starting", "started", "running", "error":
		default:
			phase = "unknown"
		}
		if progress.count == 0 {
			progress.first = phase
		}
		progress.last = phase
		progress.creating = progress.creating || phase == "creating"
		progress.created = progress.created || phase == "created"
		progress.starting = progress.starting || phase == "starting"
		progress.started = progress.started || phase == "started" || phase == "running"
		progress.failed = progress.failed || phase == "error"
		if progress.count < 32 {
			progress.count++
		} else {
			progress.capped = true
		}
	}
	return progress
}

func stPortChainDockerInitialProgress(t *testing.T, output string, truncated bool) {
	t.Helper()
	for _, target := range []struct{ kind, name, label string }{
		{"Network", "autostream_default", "network"},
		{"Container", "autostream-worker-1", "container"},
	} {
		progress := stPortChainDockerProgressFor(output, target.kind, target.name)
		t.Logf("ST-PORT Docker initial progress: target=%s observed=%t first=%s last=%s creating=%t created=%t starting=%t started=%t failed=%t records=%d capped=%t input_truncated=%t",
			target.label, progress.count > 0, progress.first, progress.last, progress.creating, progress.created, progress.starting, progress.started, progress.failed, progress.count, progress.capped, truncated)
	}
}

func stPortChainDockerInitialNetwork(t *testing.T, ctx context.Context) {
	t.Helper()
	runner := OSCommandRunner{NewProcessGroup: true}
	output, truncated, err := runner.runWithOutputMetadata(ctx, "", dockerCommandEnv(), "/usr/bin/docker", "network", "ls", "--no-trunc", "--format", `{{if eq .Name "autostream_default"}}{{.ID}}{{end}}`,
		"--filter", "name=autostream_default")
	if err != nil || truncated {
		t.Logf("ST-PORT Docker initial network: observation=selection_unavailable truncated=%t deadline_exceeded=%t", truncated, ctx.Err() == context.DeadlineExceeded)
		return
	}
	ids := strings.Fields(output)
	if len(ids) == 0 {
		t.Log("ST-PORT Docker initial network: observation=observed present=false")
		return
	}
	if len(ids) != 1 || len(ids[0]) != 64 || strings.Trim(ids[0], "0123456789abcdef") != "" {
		t.Log("ST-PORT Docker initial network: observation=selection_ambiguous")
		return
	}
	const format = `{"identity_matches":{{and (eq .Name "autostream_default") (eq (index .Labels "com.docker.compose.project") "autostream") (eq (index .Labels "com.docker.compose.network") "default")}},"driver":{{json .Driver}},"internal":{{json .Internal}},"attachable":{{json .Attachable}},"ipv6":{{json .EnableIPv6}},"ipam_driver":{{json .IPAM.Driver}},"ipam_configs":{{len .IPAM.Config}},"endpoints":{{len .Containers}}}`
	output, truncated, err = runner.runWithOutputMetadata(ctx, "", dockerCommandEnv(), "/usr/bin/docker", "network", "inspect", "--format", format, ids[0])
	var state struct {
		IdentityMatches bool   `json:"identity_matches"`
		Driver          string `json:"driver"`
		Internal        bool   `json:"internal"`
		Attachable      bool   `json:"attachable"`
		IPv6            bool   `json:"ipv6"`
		IPAMDriver      string `json:"ipam_driver"`
		IPAMConfigs     int    `json:"ipam_configs"`
		Endpoints       int    `json:"endpoints"`
	}
	if err != nil || truncated || json.Unmarshal([]byte(output), &state) != nil {
		t.Logf("ST-PORT Docker initial network: observation=state_unavailable truncated=%t deadline_exceeded=%t", truncated, ctx.Err() == context.DeadlineExceeded)
		return
	}
	if !state.IdentityMatches {
		t.Log("ST-PORT Docker initial network: observation=identity_mismatch")
		return
	}
	driver, ipam := "unknown", "unknown"
	if state.Driver == "bridge" {
		driver = "bridge"
	}
	if state.IPAMDriver == "default" {
		ipam = "default"
	}
	if state.IPAMConfigs < 0 || state.IPAMConfigs > 16 {
		state.IPAMConfigs = -1
	}
	if state.Endpoints < 0 || state.Endpoints > 64 {
		state.Endpoints = -1
	}
	t.Logf("ST-PORT Docker initial network: observation=observed present=true driver=%s internal=%t attachable=%t ipv6=%t ipam_driver=%s ipam_configs=%d endpoints=%d",
		driver, state.Internal, state.Attachable, state.IPv6, ipam, state.IPAMConfigs, state.Endpoints)
}

func stPortChainDockerInitialStorage(t *testing.T, ctx context.Context) {
	t.Helper()
	// Only recognized DriverStatus keys are returned, and all text values are
	// projected again before logging. The daemon's root is compared in-template.
	const format = `{{ $backing := "" }}{{ $dtype := "" }}{{ $native := "" }}{{ $userxattr := "" }}{{ $type := "" }}{{range .DriverStatus}}{{if eq (index . 0) "Backing Filesystem"}}{{ $backing = index . 1 }}{{end}}{{if eq (index . 0) "Supports d_type"}}{{ $dtype = index . 1 }}{{end}}{{if eq (index . 0) "Native Overlay Diff"}}{{ $native = index . 1 }}{{end}}{{if eq (index . 0) "userxattr"}}{{ $userxattr = index . 1 }}{{end}}{{if eq (index . 0) "driver-type"}}{{ $type = index . 1 }}{{end}}{{end}}{"driver":{{json .Driver}},"root_expected":{{eq .DockerRootDir "/var/lib/docker"}},"backing":{{json $backing}},"dtype":{{json $dtype}},"native":{{json $native}},"userxattr":{{json $userxattr}},"type":{{json $type}}}`
	output, truncated, err := (OSCommandRunner{NewProcessGroup: true}).runWithOutputMetadata(ctx, "", dockerCommandEnv(), "/usr/bin/docker", "info", "--format", format)
	var state struct {
		Driver, Backing, Dtype, Native, Userxattr, Type string
		RootExpected                                    bool `json:"root_expected"`
	}
	if err != nil || truncated || json.Unmarshal([]byte(output), &state) != nil {
		t.Logf("ST-PORT Docker initial storage: observation=unavailable truncated=%t deadline_exceeded=%t", truncated, ctx.Err() == context.DeadlineExceeded)
	} else {
		driver, driverType := "unknown", "unknown"
		switch state.Driver {
		case "overlay2", "overlayfs", "fuse-overlayfs", "vfs", "btrfs", "zfs", "devicemapper":
			driver = state.Driver
		}
		if state.Type == "io.containerd.snapshotter.v1" {
			driverType = "containerd_snapshotter"
		}
		triState := func(value string) string {
			switch value {
			case "true", "false":
				return value
			case "":
				return "unavailable"
			default:
				return "unknown"
			}
		}
		t.Logf("ST-PORT Docker initial storage: observation=observed driver=%s root_expected=%t backing_fs=%s supports_dtype=%s native_overlay_diff=%s userxattr=%s driver_type=%s",
			driver, state.RootExpected, stPortChainDockerFilesystem(state.Backing), triState(state.Dtype), triState(state.Native), triState(state.Userxattr), driverType)
	}
	// These are fixed paths in the fixture's namespace, not a claim about an
	// arbitrary daemon root. Keep both possible stores distinct even when one
	// is absent; the daemon driver and root comparison above remain separate.
	targets := []struct{ label, path string }{
		{"docker", "/var/lib/docker"},
		{"containerd", "/var/lib/containerd"},
	}
	if ctx.Err() != nil {
		for _, target := range targets {
			t.Logf("ST-PORT Docker initial storage mount: target=%s observation=unavailable deadline_exceeded=%t", target.label, ctx.Err() == context.DeadlineExceeded)
		}
		return
	}
	var root syscall.Statfs_t
	rootErr := syscall.Statfs("/", &root)
	mountObserved, mountTruncated := false, false
	var independentMount [2]bool
	if ctx.Err() == nil {
		if file, openErr := os.Open("/proc/self/mountinfo"); openErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(file, (256<<10)+1))
			_ = file.Close()
			mountTruncated = len(body) > 256<<10
			if readErr == nil && !mountTruncated {
				mountObserved = true
				for _, line := range strings.Split(string(body), "\n") {
					fields := strings.Fields(line)
					for i, target := range targets {
						if len(fields) >= 10 && fields[4] == target.path {
							independentMount[i] = true
						}
					}
				}
			}
		}
	}
	for i, target := range targets {
		if ctx.Err() != nil {
			t.Logf("ST-PORT Docker initial storage mount: target=%s observation=unavailable deadline_exceeded=%t", target.label, ctx.Err() == context.DeadlineExceeded)
			continue
		}
		var data syscall.Statfs_t
		dataErr := syscall.Statfs(target.path, &data)
		filesystem := "unavailable"
		if dataErr == nil {
			switch uint32(data.Type) {
			case 0x794c7630:
				filesystem = "overlayfs"
			case 0xef53:
				filesystem = "extfs"
			case 0x58465342:
				filesystem = "xfs"
			case 0x9123683e:
				filesystem = "btrfs"
			case 0x01021994:
				filesystem = "tmpfs"
			default:
				filesystem = "other"
			}
		}
		t.Logf("ST-PORT Docker initial storage mount: target=%s fixture_statfs_available=%t fixture_data_fs=%s fixture_data_same_root_fs=%t fixture_mountinfo_available=%t fixture_mountinfo_truncated=%t fixture_data_independent_mount=%t",
			target.label, rootErr == nil && dataErr == nil, filesystem, rootErr == nil && dataErr == nil && root.Fsid == data.Fsid, mountObserved, mountTruncated, independentMount[i])
	}
}

func stPortChainDockerFilesystem(value string) string {
	switch value {
	case "extfs", "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "overlay", "overlayfs", "tmpfs":
		return value
	case "":
		return "unavailable"
	default:
		return "unknown"
	}
}

func TestSTPortDockerProgressUsesFixedTargetsAndPhases(t *testing.T) {
	const sensitive = "DO_NOT_PUBLISH_FIXTURE_CREDENTIAL"
	output := "\x1b[32m Network autostream_default Creating\x1b[0m\n" +
		" Network other_default Created\n" +
		" Container autostream-worker-1 Created\n" +
		" Network autostream_default Error " + sensitive + "\n"
	progress := stPortChainDockerProgressFor(output, "Network", "autostream_default")
	if progress.count != 2 || progress.first != "creating" || progress.last != "error" || !progress.creating || !progress.failed || progress.created {
		t.Fatal("fixed network progress accepted another resource or ignored its observed boundary")
	}
	unknown := stPortChainDockerProgressFor("Network autostream_default "+sensitive, "Network", "autostream_default")
	if unknown.first != "unknown" || unknown.last != "unknown" || unknown.created || unknown.started || unknown.failed {
		t.Fatal("unrecognized progress was promoted to a known phase")
	}
	capped := stPortChainDockerProgressFor(strings.Repeat("Network autostream_default Creating\n", 40), "Network", "autostream_default")
	if capped.count != 32 || !capped.capped {
		t.Fatal("progress record count exceeded its diagnostic bound")
	}
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
