package hostruntime

import "regexp"

var databaseNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type standardSystemdProfile struct {
	port             int
	unit             string
	releaseRoot      string
	currentLink      string
	binaryPath       string
	requiredPaths    []string
	backupExecutable string
}

// standardSystemdProfileFor is compiled root authority. The Control Panel may
// select a service identity, but cannot supply a unit, executable, or path.
func standardSystemdProfileFor(serviceType string) (standardSystemdProfile, bool) {
	switch serviceType {
	case "control_panel":
		return standardSystemdProfile{
			port:             8080,
			unit:             "autostream-control-panel.service",
			releaseRoot:      "/opt/autostream/control-panel/releases",
			currentLink:      "/opt/autostream/control-panel/current",
			binaryPath:       "bin/control-panel",
			requiredPaths:    []string{"share/autostream-control-panel"},
			backupExecutable: "/usr/local/sbin/autostream-backup-control-panel",
		}, true
	case "encoder_recorder":
		return standardSystemdProfile{
			port:        8081,
			unit:        "autostream-encoder-recorder.service",
			releaseRoot: "/opt/autostream/encoder-recorder/releases",
			currentLink: "/opt/autostream/encoder-recorder/current",
			binaryPath:  "bin/autostream-encoder-recorder",
		}, true
	case "observability":
		return standardSystemdProfile{
			port:             8082,
			unit:             "autostream-observability.service",
			releaseRoot:      "/opt/autostream/observability/releases",
			currentLink:      "/opt/autostream/observability/current",
			binaryPath:       "bin/autostream-observability",
			backupExecutable: "/usr/local/sbin/autostream-backup-observability",
		}, true
	case "discord_bot":
		return standardSystemdProfile{
			port:        8083,
			unit:        "autostream-discord-bot.service",
			releaseRoot: "/opt/autostream/discord-bot/releases",
			currentLink: "/opt/autostream/discord-bot/current",
			binaryPath:  "bin/autostream-discord-bot",
		}, true
	case "worker":
		return standardSystemdProfile{
			port:        8084,
			unit:        "autostream-worker.service",
			releaseRoot: "/opt/autostream/worker/releases",
			currentLink: "/opt/autostream/worker/current",
			binaryPath:  "bin/autostream-worker",
		}, true
	default:
		return standardSystemdProfile{}, false
	}
}
