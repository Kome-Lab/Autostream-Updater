package hostruntime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type initialSystemdPortSidecarPlan struct {
	ServiceID string
	Path      string
	Body      []byte
	SHA256    string
}

type initialSystemdPortSidecarSnapshot struct {
	Existed bool
	Body    []byte
}

func initialSystemdPortSidecarPlans(
	policy LocalExecutorPolicy,
	parent string,
) ([]initialSystemdPortSidecarPlan, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion {
		return nil, errors.New("initial systemd port sidecars require the mutation policy protocol")
	}
	if !cleanAbsoluteSystemdSidecarDirectory(parent) {
		return nil, errors.New("systemd port sidecar directory must be a clean absolute path")
	}
	plans := make([]initialSystemdPortSidecarPlan, 0, len(policy.Targets))
	seen := make(map[string]struct{}, len(policy.Targets))
	for _, target := range policy.Targets {
		if target.DeploymentMode != ModeSystemd {
			continue
		}
		if target.Systemd == nil {
			return nil, errors.New("systemd target is missing its fixed service definition")
		}
		adapter, err := hostAgentConfigureSystemdPortAdapterFor(
			target.ServiceType,
			target.Systemd.Unit,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"derive initial systemd port sidecar for %s: %w",
				target.ServiceID,
				err,
			)
		}
		if path.Dir(adapter.SidecarPath) != defaultSystemdPortSidecarDirectory {
			return nil, errors.New("fixed systemd port sidecar escaped its canonical directory")
		}
		sidecarPath := joinSystemdSidecarPath(
			parent,
			path.Base(adapter.SidecarPath),
		)
		if _, exists := seen[sidecarPath]; exists {
			return nil, errors.New("duplicate fixed systemd port sidecar path")
		}
		seen[sidecarPath] = struct{}{}
		body := systemdPortSidecarBytes(
			adapter.ServiceType,
			target.LocalListen.Host,
			target.LocalListen.Port,
			target.ConfigRevision,
		)
		digest := systemdPortSidecarSHA256(body)
		if target.ConfigSHA256 != digest {
			return nil, fmt.Errorf(
				"canonical systemd port sidecar digest does not match target %s",
				target.ServiceID,
			)
		}
		lineCount := 1
		if target.ServiceType == "control_panel" {
			lineCount = 2
		}
		if bytes.Count(body, []byte{'\n'}) != lineCount ||
			len(body) == 0 ||
			len(body) > systemdPortSidecarConfigureMaxBytes ||
			body[len(body)-1] != '\n' {
			return nil, errors.New("canonical systemd listener projection has an invalid bounded encoding")
		}
		plans = append(plans, initialSystemdPortSidecarPlan{
			ServiceID: target.ServiceID,
			Path:      sidecarPath,
			Body:      append([]byte(nil), body...),
			SHA256:    digest,
		})
	}
	sort.Slice(plans, func(i, j int) bool {
		return plans[i].Path < plans[j].Path
	})
	return plans, nil
}

type preparedSystemdPortSidecar struct {
	path          string
	existed       bool
	existing      []byte
	existingInfo  os.FileInfo
	tempPath      string
	temp          *os.File
	tempInfo      os.FileInfo
	created       bool
	createdInfo   os.FileInfo
	installedBody []byte
}

type preparedSystemdPortSidecars struct {
	parent                  string
	entries                 map[string]*preparedSystemdPortSidecar
	replacementTempPath     string
	replacementTemp         *os.File
	replacementTempInfo     os.FileInfo
	replacementBody         []byte
	replacedEntry           *preparedSystemdPortSidecar
	replaced                bool
	replacementAmbiguous    bool
	finalized               bool
	exchange                func(string, string) error
	syncParent              func(string) error
	replacementPairVerifier func(*preparedSystemdPortSidecar, bool) bool
	verifyLive              hostAgentLiveSystemdSidecarVerifier
	rollbackAuthority       *hostAgentSystemdSidecarRollbackAuthority
	committed               bool
}

type hostAgentSystemdSidecarRollbackAuthority struct {
	verify        hostAgentLiveSystemdSidecarVerifier
	currentPolicy LocalExecutorPolicy
	stagedPolicy  LocalExecutorPolicy
	currentTarget LocalExecutorTarget
	stagedTarget  LocalExecutorTarget
	acceptedProof hostAgentLiveSystemdSidecarProof
}

func canonicalSystemdPortSidecarPaths(parent string) ([]string, error) {
	fixed := []struct {
		serviceType string
		unit        string
	}{
		{serviceType: "control_panel", unit: "autostream-control-panel.service"},
		{serviceType: "worker", unit: "autostream-worker.service"},
		{serviceType: "encoder_recorder", unit: "autostream-encoder-recorder.service"},
		{serviceType: "discord_bot", unit: "autostream-discord-bot.service"},
		{serviceType: "observability", unit: "autostream-observability.service"},
	}
	paths := make([]string, 0, len(fixed))
	for _, item := range fixed {
		adapter, err := hostAgentConfigureSystemdPortAdapterFor(
			item.serviceType,
			item.unit,
		)
		if err != nil {
			return nil, err
		}
		if path.Dir(adapter.SidecarPath) != defaultSystemdPortSidecarDirectory {
			return nil, errors.New("fixed systemd port sidecar escaped its canonical directory")
		}
		paths = append(
			paths,
			joinSystemdSidecarPath(parent, path.Base(adapter.SidecarPath)),
		)
	}
	sort.Strings(paths)
	return paths, nil
}

func cleanAbsoluteSystemdSidecarDirectory(value string) bool {
	if strings.HasPrefix(value, "/") {
		return path.IsAbs(value) && path.Clean(value) == value
	}
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}

func joinSystemdSidecarPath(parent, name string) string {
	if strings.HasPrefix(parent, "/") {
		return path.Join(parent, name)
	}
	return filepath.Join(parent, name)
}
