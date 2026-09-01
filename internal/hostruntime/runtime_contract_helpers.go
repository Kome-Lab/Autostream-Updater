package hostruntime

import (
	"errors"
	"strings"
)

const PolicyStatusApplied = "applied"

var ErrLeaseLost = errors.New("system update execution lease was lost")

func responseNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}

func dockerImageRepoForService(serviceType string) (string, error) {
	service := dockerManifestService(serviceType)
	switch service {
	case "control-panel", "worker", "encoder-recorder", "discord-bot", "observability":
		return "ghcr.io/kome-lab/autostream-docker/" + service, nil
	default:
		return "", errors.New("service type has no fixed Docker image repository")
	}
}
