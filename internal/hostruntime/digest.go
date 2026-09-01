package hostruntime

import "strings"

func normalizeDigest(digest string) string {
	digest = strings.TrimSpace(strings.ToLower(digest))
	if len(digest) == 64 && !strings.HasPrefix(digest, "sha256:") {
		return "sha256:" + digest
	}
	return digest
}

func canonicalReportDigest(value string) string {
	value = normalizeDigest(value)
	if value != "" && !digestPattern.MatchString(value) {
		return ""
	}
	return value
}

func isTerminalUpdateStatus(status string) bool {
	return status == "succeeded" || status == "rolled_back" || status == "failed"
}
