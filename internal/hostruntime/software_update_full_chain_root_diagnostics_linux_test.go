//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	}
}

func softwareUpdateChainRootJournalParserChecks(t *testing.T) {
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
