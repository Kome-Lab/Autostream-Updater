package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func verifyTrustedStagedDockerInputsWithOwnerCheck(ctx context.Context, runner CommandRunner, d *DockerTarget, frozenPath, digestRef, expectedPlatformDigest string, trustedOwner func(os.FileInfo) bool) (string, error) {
	if err := validateTrustedFrozenComposeWithOwnerCheck(frozenPath, d, digestRef, trustedOwner); err != nil {
		return "", err
	}
	newIDOut, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{.Id}}", digestRef)
	if inspectErr != nil || !digestPattern.MatchString(strings.ToLower(strings.TrimSpace(newIDOut))) {
		return "", errors.New("staged Docker image ID is not a canonical SHA256 digest")
	}
	newID := strings.ToLower(strings.TrimSpace(newIDOut))
	repoDigests, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{json .RepoDigests}}", digestRef)
	if inspectErr != nil || !repositoryHasDigest(repoDigests, d.ImageRepo, expectedPlatformDigest) {
		return "", errors.New("staged Docker image RepoDigest does not match trusted release manifest")
	}
	return newID, nil
}

func composeArgs(d *DockerTarget, overridePath string) []string {
	args := []string{"compose"}
	if d.BaseEnvFile != "" {
		args = append(args, "--env-file", d.BaseEnvFile)
	}
	args = append(args, "--env-file", d.VersionEnvFile)
	if d.PortEnvFile != "" {
		args = append(args, "--env-file", d.PortEnvFile)
	}
	args = append(args, "--project-directory", d.ProjectDir, "-p", d.ComposeProject)
	for _, file := range d.ComposeFiles {
		args = append(args, "-f", file)
	}
	if overridePath != "" {
		args = append(args, "-f", overridePath)
	}
	return args
}

func composeFrozenArgs(d *DockerTarget, frozenPath string) []string {
	args := []string{"compose"}
	if d.BaseEnvFile != "" {
		args = append(args, "--env-file", d.BaseEnvFile)
	}
	args = append(args, "--env-file", d.VersionEnvFile)
	if d.PortEnvFile != "" {
		args = append(args, "--env-file", d.PortEnvFile)
	}
	return append(args, "--project-directory", d.ProjectDir, "-p", d.ComposeProject, "-f", frozenPath)
}

func writeDockerOverride(path, service, image string) error {
	if !identifierPattern.MatchString(service) || !(digestPattern.MatchString(image) || strings.Contains(image, "@sha256:")) {
		return errors.New("Docker override identity is invalid")
	}
	payload, err := json.Marshal(map[string]any{"services": map[string]any{service: map[string]string{"image": image}}})
	if err != nil {
		return err
	}
	return writeAtomicFile(path, append(payload, '\n'), 0o600)
}

func verifyComposeConfig(ctx context.Context, runner CommandRunner, d *DockerTarget, base []string, expectedImage, frozenPath string) error {
	out, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(base, "config", "--format", "json", "--no-env-resolution")...)
	if err != nil {
		return fmt.Errorf("compose configuration validation failed: %w", err)
	}
	var cfg struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if json.Unmarshal([]byte(out), &cfg) != nil || cfg.Services[d.Service].Image != expectedImage {
		return errors.New("compose configuration did not resolve the managed service to the trusted image digest")
	}
	if err := validateComposeModelSecurity([]byte(out), d); err != nil {
		return err
	}
	if digest, err := composeModelHash([]byte(out), d.Service); err != nil || digest != d.ComposeConfigSHA256 {
		return errors.New("resolved compose project differs from the root-approved configuration digest")
	}
	if err := writeAtomicFile(frozenPath, []byte(out), 0o600); err != nil {
		return fmt.Errorf("freeze validated compose model: %w", err)
	}
	return nil
}

func validateTrustedFrozenCompose(path string, d *DockerTarget, expectedImage string) error {
	return validateTrustedFrozenComposeWithOwnerCheck(path, d, expectedImage, isRootOwner)
}

func validateTrustedFrozenComposeWithOwnerCheck(path string, d *DockerTarget, expectedImage string, trustedOwner func(os.FileInfo) bool) error {
	if trustedOwner == nil {
		return errors.New("trusted frozen compose model is unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<20 || !trustedOwner(info) {
		return errors.New("trusted frozen compose model is unavailable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read trusted frozen compose model")
	}
	var cfg struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.Services[d.Service].Image != expectedImage {
		return errors.New("trusted frozen compose image binding is invalid")
	}
	if err := validateComposeModelSecurity(raw, d); err != nil {
		return err
	}
	digest, err := composeModelHash(raw, d.Service)
	if err != nil || digest != d.ComposeConfigSHA256 {
		return errors.New("trusted frozen compose model differs from root policy")
	}
	return nil
}

func verifyComposeModel(ctx context.Context, runner CommandRunner, d *DockerTarget, args []string) error {
	out, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(args, "config", "--format", "json", "--no-env-resolution")...)
	if err != nil {
		return fmt.Errorf("base compose configuration validation failed: %w", err)
	}
	digest, err := composeModelHash([]byte(out), d.Service)
	if err != nil || digest != d.ComposeConfigSHA256 {
		return errors.New("base compose project differs from the root-approved configuration digest")
	}
	if err := validateComposeModelSecurity([]byte(out), d); err != nil {
		return err
	}
	return nil
}

func composeModelHash(raw []byte, service string) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model map[string]any
	if err := decoder.Decode(&model); err != nil {
		return "", err
	}
	services, ok := model["services"].(map[string]any)
	if !ok {
		return "", errors.New("compose model has no services")
	}
	if _, ok := services[service].(map[string]any); !ok {
		return "", errors.New("compose model has no managed service")
	}
	canonicalRepos := map[string]bool{
		"ghcr.io/kome-lab/autostream-docker/control-panel":    true,
		"ghcr.io/kome-lab/autostream-docker/worker":           true,
		"ghcr.io/kome-lab/autostream-docker/encoder-recorder": true,
		"ghcr.io/kome-lab/autostream-docker/discord-bot":      true,
		"ghcr.io/kome-lab/autostream-docker/observability":    true,
	}
	for name, rawService := range services {
		serviceModel, ok := rawService.(map[string]any)
		if !ok {
			return "", errors.New("compose service model is invalid")
		}
		image, _ := serviceModel["image"].(string)
		if name == service {
			if image == "" {
				return "", errors.New("managed compose service has no image")
			}
			serviceModel["image"] = "__AUTOSTREAM_MANAGED_IMAGE__"
		} else if repo := strings.ToLower(dockerImageBase(image)); strings.HasPrefix(repo, "ghcr.io/kome-lab/autostream-docker/") {
			if !canonicalRepos[repo] {
				return "", errors.New("compose model contains a noncanonical AutoStream image repository")
			}
			serviceModel["image"] = repo + ":__AUTOSTREAM_BUNDLE__"
		}
	}
	canonical, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func validateComposeModelSecurity(raw []byte, d *DockerTarget) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model map[string]any
	if err := decoder.Decode(&model); err != nil {
		return errors.New("compose model is invalid JSON")
	}
	canonical, _ := json.Marshal(model)
	if strings.Contains(strings.ToLower(string(canonical)), "docker.sock") {
		return errors.New("compose model may not reference the Docker socket")
	}
	services, ok := model["services"].(map[string]any)
	if !ok || len(services) > 64 {
		return errors.New("compose model service set is invalid")
	}
	managed, ok := services[d.Service].(map[string]any)
	if !ok {
		return errors.New("compose model has no managed service")
	}
	if _, err := validateDockerComposePortMappings(raw, d); err != nil {
		return err
	}
	managedImage, _ := managed["image"].(string)
	if !strings.EqualFold(dockerImageBase(managedImage), d.ImageRepo) && !digestPattern.MatchString(strings.ToLower(managedImage)) {
		return errors.New("managed compose service image repository differs from fixed image_repo")
	}
	if value, _ := managed["privileged"].(bool); value {
		return errors.New("managed compose service may not be privileged")
	}
	for _, field := range []string{"cap_add", "devices"} {
		if values, ok := managed[field].([]any); ok && len(values) > 0 {
			return fmt.Errorf("managed compose service may not set %s", field)
		}
	}
	for _, field := range []string{"pid", "ipc", "network_mode"} {
		if value, _ := managed[field].(string); strings.EqualFold(value, "host") {
			return fmt.Errorf("managed compose service may not use host %s", field)
		}
	}
	if options, ok := managed["security_opt"].([]any); ok {
		for _, option := range options {
			if strings.Contains(strings.ToLower(fmt.Sprint(option)), "unconfined") {
				return errors.New("managed compose service may not disable confinement")
			}
		}
	}
	pathCount := 0
	if path, ok := managed["env_file"].(string); ok {
		if err := validateComposeHostReference(path, false, &pathCount); err != nil {
			return fmt.Errorf("compose env_file: %w", err)
		}
	} else if envFiles, ok := managed["env_file"].([]any); ok {
		for _, item := range envFiles {
			path := ""
			switch value := item.(type) {
			case string:
				path = value
			case map[string]any:
				path, _ = value["path"].(string)
			}
			if err := validateComposeHostReference(path, false, &pathCount); err != nil {
				return fmt.Errorf("compose env_file: %w", err)
			}
		}
	}
	if volumes, ok := managed["volumes"].([]any); ok {
		for _, item := range volumes {
			volume, ok := item.(map[string]any)
			if !ok || volume["type"] != "bind" {
				continue
			}
			source, _ := volume["source"].(string)
			readOnly, _ := volume["read_only"].(bool)
			if !readOnly || filepath.Clean(source) == filepath.Clean(string(filepath.Separator)) {
				return errors.New("managed compose bind mounts must be read-only and may not mount the host root")
			}
			if err := validateComposeHostReference(source, true, &pathCount); err != nil {
				return fmt.Errorf("compose bind mount: %w", err)
			}
		}
	}
	for _, kind := range []string{"configs", "secrets"} {
		refs, _ := managed[kind].([]any)
		definitions, _ := model[kind].(map[string]any)
		for _, item := range refs {
			ref, _ := item.(map[string]any)
			source, _ := ref["source"].(string)
			definition, _ := definitions[source].(map[string]any)
			if kind == "configs" && ref["target"] == "/run/autostream-credentials/node-listener.json" {
				content, _ := definition["content"].(string)
				_, hasFile := definition["file"]
				_, hasEnvironment := definition["environment"]
				_, hasExternal := definition["external"]
				if content == "" || len(content) > 64<<10 || hasFile || hasEnvironment || hasExternal {
					return errors.New("compose Node listener must be a bounded inline configuration")
				}
				continue
			}
			path, _ := definition["file"].(string)
			if err := validateComposeHostReference(path, false, &pathCount); err != nil {
				return fmt.Errorf("compose %s reference: %w", kind, err)
			}
		}
	}
	return nil
}

func validateComposeHostReference(path string, allowDirectory bool, count *int) error {
	*count++
	if *count > 64 || !filepath.IsAbs(path) {
		return errors.New("host reference is missing, relative, or exceeds the bounded path count")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("host reference must exist and may not be a symlink")
	}
	if info.IsDir() {
		if !allowDirectory {
			return errors.New("host reference must be a regular file")
		}
	} else if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return errors.New("host reference must be a bounded regular file")
	}
	if err := validateSecureRootPath(path, info.IsDir()); err != nil {
		return err
	}
	if info.IsDir() {
		return validateComposeHostTree(path)
	}
	return nil
}

func validateComposeHostTree(root string) error {
	entries := 0
	var total int64
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 256 || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("bind source tree is too large or contains a symlink")
		}
		info, err := entry.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) || !isRootOwner(info) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("bind source tree must contain only root-owned non-writable regular files and directories")
		}
		if info.Mode().IsRegular() {
			total += info.Size()
			if total > 64<<20 {
				return errors.New("bind source tree exceeds the size limit")
			}
		}
		return nil
	})
}
