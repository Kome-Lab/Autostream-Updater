package hostruntime

import (
	"strconv"
	"strings"
)

type updaterReleaseSemver struct {
	core       [3]uint64
	prerelease []string
}

func updaterReleaseSemverAtLeast(current, minimum string) bool {
	actual, actualOK := parseUpdaterReleaseSemver(current)
	required, requiredOK := parseUpdaterReleaseSemver(minimum)
	if !actualOK || !requiredOK {
		return false
	}
	for i := range actual.core {
		if actual.core[i] != required.core[i] {
			return actual.core[i] > required.core[i]
		}
	}
	return compareUpdaterReleasePrerelease(actual.prerelease, required.prerelease) >= 0
}

func parseUpdaterReleaseSemver(value string) (updaterReleaseSemver, bool) {
	if !versionPattern.MatchString(value) {
		return updaterReleaseSemver{}, false
	}
	value = strings.TrimPrefix(value, "v")
	core, prerelease, hasPrerelease := strings.Cut(value, "-")
	coreParts := strings.Split(core, ".")
	if len(coreParts) != 3 {
		return updaterReleaseSemver{}, false
	}
	var parsed updaterReleaseSemver
	for i, part := range coreParts {
		if len(part) > 1 && part[0] == '0' {
			return updaterReleaseSemver{}, false
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return updaterReleaseSemver{}, false
		}
		parsed.core[i] = number
	}
	if !hasPrerelease {
		return parsed, true
	}
	parsed.prerelease = strings.Split(prerelease, ".")
	for _, identifier := range parsed.prerelease {
		if identifier == "" || (decimalIdentifier(identifier) && len(identifier) > 1 && identifier[0] == '0') {
			return updaterReleaseSemver{}, false
		}
	}
	return parsed, true
}

func compareUpdaterReleasePrerelease(actual, required []string) int {
	if len(actual) == 0 && len(required) == 0 {
		return 0
	}
	if len(actual) == 0 {
		return 1
	}
	if len(required) == 0 {
		return -1
	}
	for i := 0; i < len(actual) && i < len(required); i++ {
		if actual[i] == required[i] {
			continue
		}
		actualNumeric := decimalIdentifier(actual[i])
		requiredNumeric := decimalIdentifier(required[i])
		switch {
		case actualNumeric && requiredNumeric:
			if len(actual[i]) != len(required[i]) {
				if len(actual[i]) > len(required[i]) {
					return 1
				}
				return -1
			}
		case actualNumeric:
			return -1
		case requiredNumeric:
			return 1
		}
		if actual[i] > required[i] {
			return 1
		}
		return -1
	}
	if len(actual) > len(required) {
		return 1
	}
	if len(actual) < len(required) {
		return -1
	}
	return 0
}

func decimalIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
