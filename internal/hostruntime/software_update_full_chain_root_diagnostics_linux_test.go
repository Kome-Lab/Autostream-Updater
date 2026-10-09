//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var softwareUpdateChainInvocationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var softwareUpdateChainLogDatePattern = regexp.MustCompile(`^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} $`)

type softwareUpdateChainRootJournalWindow struct {
	invocation string
	start      int64
}

func softwareUpdateChainRootJournalStart() softwareUpdateChainRootJournalWindow {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	body, err := (OSCommandRunner{}).Run(ctx, "/", nil, "/usr/bin/systemctl", "show", "--property=InvocationID", "--value", hostSelfUpdateExecutorServiceUnit)
	value := strings.TrimSpace(body)
	if err != nil || !softwareUpdateChainInvocationPattern.MatchString(value) {
		return softwareUpdateChainRootJournalWindow{}
	}
	return softwareUpdateChainRootJournalWindow{value, time.Now().UTC().UnixMicro()}
}

func softwareUpdateChainParseRootRefusal(line []byte, window softwareUpdateChainRootJournalWindow, end int64, requestSHA string) (softwareClaimRecoveryRootRefusal, bool) {
	var empty softwareClaimRecoveryRootRefusal
	if len(line) > 16<<10 || !softwareUpdateChainInvocationPattern.MatchString(window.invocation) || window.start < 1 || end < window.start {
		return empty, false
	}
	var journal struct {
		Unit       string `json:"_SYSTEMD_UNIT"`
		UID        string `json:"_UID"`
		Invocation string `json:"_SYSTEMD_INVOCATION_ID"`
		Timestamp  string `json:"__REALTIME_TIMESTAMP"`
		Message    string `json:"MESSAGE"`
	}
	if json.Unmarshal(line, &journal) != nil || journal.Unit != hostSelfUpdateExecutorServiceUnit || journal.UID != "0" || journal.Invocation != window.invocation {
		return empty, false
	}
	stamp, err := strconv.ParseInt(journal.Timestamp, 10, 64)
	if err != nil || stamp < window.start || stamp > end || strings.ContainsAny(journal.Message, "\r\n") {
		return empty, false
	}
	position := strings.Index(journal.Message, softwareClaimRecoveryRefusalPrefix)
	if position != 0 && (position != 20 || !softwareUpdateChainLogDatePattern.MatchString(journal.Message[:position])) {
		return empty, false
	}
	payload := []byte(journal.Message[position+len(softwareClaimRecoveryRefusalPrefix):])
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record softwareClaimRecoveryRootRefusal
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || !record.valid() || record.RequestSHA256 != requestSHA {
		return empty, false
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(payload, canonical) {
		return empty, false
	}
	return record, true
}

// Read the installed unit's own refusal, before auxiliary observation. Raw
// journal bytes and unrelated metadata never cross into the Go artifact.
func softwareUpdateChainLogActualRootRefusal(t *testing.T, window softwareUpdateChainRootJournalWindow, request SoftwareClaimRecoveryRequest) {
	t.Helper()
	end := time.Now().UTC().UnixMicro()
	if !softwareUpdateChainInvocationPattern.MatchString(window.invocation) {
		t.Log("SOFTWARE actual root refusal: actual_unit=false capture=window_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	body, err := (OSCommandRunner{}).Run(ctx, "/", nil, "/usr/bin/journalctl", "--unit="+hostSelfUpdateExecutorServiceUnit, "--no-pager", "--lines=64", "--output=json", "_SYSTEMD_INVOCATION_ID="+window.invocation)
	if err != nil || len(body) > 64<<10 {
		t.Log("SOFTWARE actual root refusal: actual_unit=false capture=journal_unavailable")
		return
	}
	var matches []softwareClaimRecoveryRootRefusal
	for _, line := range bytes.Split([]byte(body), []byte{'\n'}) {
		if record, valid := softwareUpdateChainParseRootRefusal(line, window, end, request.sha256()); valid {
			matches = append(matches, record)
		}
	}
	if len(matches) != 1 {
		t.Logf("SOFTWARE actual root refusal: actual_unit=false capture=missing_or_ambiguous bounded_matches=%d", softwareUpdateChainSafeCount(int64(len(matches))))
		return
	}
	encoded, err := json.Marshal(matches[0])
	if err == nil {
		t.Logf("SOFTWARE actual root refusal: actual_unit=true captured_original_guard=true record=%s", encoded)
		t.Logf("SOFTWARE recovery stage inference: inferred_from_ordinal_only=true stage=%s", softwareUpdateChainRecoveryStageInference(matches[0].Ordinal))
	}
}

func softwareUpdateChainRecoveryStageInference(ordinal int64) string {
	switch ordinal {
	case 1:
		return "before_intent"
	case 2:
		return "intent_saved"
	case 3:
		return "before_same_job_claim"
	case 4:
		return "claim_validated_before_cursor_save"
	case 5:
		return "cursor_saved_before_failed_report"
	case 6:
		return "terminal_clear_received_before_local_settle"
	default:
		return "unknown"
	}
}

// Already obtained by this same recover call; no additional CP/root request.
func softwareUpdateChainLogRecoveryReach(t *testing.T, response stPortChainResponse, calls softwareUpdateChainCalls, settled softwareUpdateChainJob, job string) {
	t.Helper()
	t.Logf("SOFTWARE recovery reach observed: central_status=%s central_code=%s central_same_job=%t central_generation=%d local_active_present=%t local_active_same_job=%t local_plan_present=%t stage=%d apply=%d reconcile=%d inspections=%d response_ok=%t",
		softwareUpdateChainSafeStatus(settled.Status), softwareUpdateChainSafeCode(settled.Code), settled.ID == job, softwareUpdateChainSafeGeneration(settled.LeaseGeneration), response.ActiveJobID != "", response.ActiveJobID == job, response.ActivePlanPresent,
		softwareUpdateChainSafeCount(int64(calls.Stage)), softwareUpdateChainSafeCount(int64(calls.Apply)), softwareUpdateChainSafeCount(int64(calls.Reconcile)), softwareUpdateChainSafeCount(int64(calls.Inspections)), response.OK)
}

func softwareUpdateChainRootJournalParserChecks(t *testing.T) {
	t.Run("actual_root_journal_process_observation", func(t *testing.T) {
		window := softwareUpdateChainRootJournalWindow{strings.Repeat("a", 32), 100}
		d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
		d.LifecycleHeld, d.Phase, d.WatchdogGuard = true, "watchdog_guard", "process_cgroup"
		d.observeProcess(1, softwareClaimRecoveryWatchdogUnit{slot: "a", mainPID: 42}, "initial_members")
		d.Process.ReaderStage, d.Process.Errno, d.Process.Refused = "open", "ENOENT", true
		encoded, _ := json.Marshal(d)
		journal := map[string]string{"_SYSTEMD_UNIT": hostSelfUpdateExecutorServiceUnit, "_UID": "0", "_SYSTEMD_INVOCATION_ID": window.invocation, "__REALTIME_TIMESTAMP": "101", "MESSAGE": softwareClaimRecoveryRefusalPrefix + string(encoded)}
		body, _ := json.Marshal(journal)
		if got, ok := softwareUpdateChainParseRootRefusal(body, window, 102, d.RequestSHA256); !ok || !reflect.DeepEqual(got, d) {
			t.Fatal("closed actual-unit process observation lost typed site/errno")
		}
		for _, bad := range []string{"errno", "stage", "namespace", "raw_field"} {
			copy := d
			p := *d.Process
			copy.Process = &p
			switch bad {
			case "errno":
				p.Errno = "private-error"
			case "stage":
				p.ReaderStage = "private-site"
			case "namespace":
				p.Namespaces[0].Mount = "private-path"
			}
			poison, _ := json.Marshal(copy)
			if bad == "raw_field" {
				poison = []byte(strings.TrimSuffix(string(poison), "}") + `,"raw_path":"private"}`)
			}
			journal["MESSAGE"] = softwareClaimRecoveryRefusalPrefix + string(poison)
			body, _ = json.Marshal(journal)
			if _, ok := softwareUpdateChainParseRootRefusal(body, window, 102, d.RequestSHA256); ok {
				t.Fatal("raw/unbounded process journal metadata was accepted")
			}
		}
	})
	t.Run("actual_root_journal_parser", func(t *testing.T) {
		window := softwareUpdateChainRootJournalWindow{strings.Repeat("a", 32), 100}
		d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
		d.Phase, d.LifecycleHeld = "recovery_service", true
		encoded, _ := json.Marshal(d)
		journal := map[string]string{"_SYSTEMD_UNIT": hostSelfUpdateExecutorServiceUnit, "_UID": "0", "_SYSTEMD_INVOCATION_ID": window.invocation, "__REALTIME_TIMESTAMP": "101", "MESSAGE": "2026/10/09 00:00:00 " + softwareClaimRecoveryRefusalPrefix + string(encoded)}
		body, _ := json.Marshal(journal)
		if got, ok := softwareUpdateChainParseRootRefusal(body, window, 102, d.RequestSHA256); !ok || got != d {
			t.Fatal("valid installed-unit closed diagnostic was rejected")
		}
		for _, poison := range []string{"unit", "uid", "invocation", "timestamp", "sha", "unknown_field", "trailing", "newline", "prefix", "oversize", "invalid_record"} {
			copy := make(map[string]string)
			for key, value := range journal {
				copy[key] = value
			}
			sha := d.RequestSHA256
			switch poison {
			case "unit":
				copy["_SYSTEMD_UNIT"] = "private-other-unit"
			case "uid":
				copy["_UID"] = "1000"
			case "invocation":
				copy["_SYSTEMD_INVOCATION_ID"] = strings.Repeat("b", 32)
			case "timestamp":
				copy["__REALTIME_TIMESTAMP"] = "99"
			case "sha":
				sha = "sha256:" + strings.Repeat("c", 64)
			case "unknown_field":
				copy["MESSAGE"] = softwareClaimRecoveryRefusalPrefix + strings.TrimSuffix(string(encoded), "}") + `,"private_key":"sentinel"}`
			case "trailing":
				copy["MESSAGE"] += `{}`
			case "newline":
				copy["MESSAGE"] += "\nprivate-sentinel"
			case "prefix":
				copy["MESSAGE"] = "private-sentinel " + softwareClaimRecoveryRefusalPrefix + string(encoded)
			case "oversize":
				copy["MESSAGE"] = strings.Repeat("x", 17<<10)
			case "invalid_record":
				copy["MESSAGE"] = softwareClaimRecoveryRefusalPrefix + `{"schema_version":1}`
			}
			body, err := json.Marshal(copy)
			if err != nil {
				t.Fatal("create bounded invalid journal fixture")
			}
			if _, ok := softwareUpdateChainParseRootRefusal(body, window, 102, sha); ok {
				t.Fatal("foreign, malformed or unbounded journal event was accepted")
			}
		}
	})
}
