//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newDockerPortSmokeRunner(
	t *testing.T,
	imageID, repositoryDigest, captureDir string,
	adapter dockerPortAdapter,
) *dockerPortSmokeRunner {
	t.Helper()
	if !digestPattern.MatchString(imageID) ||
		!digestPattern.MatchString(repositoryDigest) ||
		!filepath.IsAbs(captureDir) {
		t.Fatal("Docker port smoke runner identity is invalid")
	}
	return &dockerPortSmokeRunner{
		base:    OSCommandRunner{NewProcessGroup: true},
		imageID: imageID, repositoryDigest: repositoryDigest,
		captureDir: captureDir, adapter: adapter,
	}
}

func (r *dockerPortSmokeRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (output string, err error) {
	observation := dockerPortSmokeRunnerObservation{phase: "command"}
	r.mu.Lock()
	scope := r.legacyDiagnostic
	r.mu.Unlock()
	defer func() {
		r.observeSTPortRunner(observation, err != nil)
		scope.observeRunner(observation, err != nil)
	}()
	if len(args) == 4 &&
		args[0] == "image" &&
		args[1] == "inspect" &&
		args[2] == "--format={{json .RepoDigests}}" &&
		strings.EqualFold(args[3], r.imageID) {
		r.mu.Lock()
		r.repositoryCalls++
		r.mu.Unlock()
		raw, _ := json.Marshal([]string{
			dockerPortSmokeImageRepo + "@" + r.repositoryDigest,
		})
		return string(raw), nil
	}
	frozenPath := dockerPortSmokeFrozenComposePath(args)
	if frozenPath != "" {
		observation.phase = "compose_capture"
		if err := r.captureExecution(frozenPath); err != nil {
			return "", err
		}
	}
	observation.phase = "command"
	output, err = r.base.Run(ctx, dir, env, name, args...)
	if err == nil && frozenPath != "" {
		observation.phase = "mapping_read"
		body, readErr := os.ReadFile(r.adapter.PortEnvFile)
		if readErr != nil {
			return output, readErr
		}
		observation.phase = "mapping_parse"
		publishedPort, _, _, parseErr := parseDockerPortEnv(
			r.adapter, body,
		)
		if parseErr != nil {
			return output, parseErr
		}
		observation.phase = "listener_tcp"
		if waitErr := waitForDockerPortTCP(ctx, publishedPort); waitErr != nil {
			return output, waitErr
		}
		observation.phase = "listener_identity"
		if verifyErr := r.verifyMountedListener(ctx, frozenPath, publishedPort, &observation); verifyErr != nil {
			return output, verifyErr
		}
	}
	return output, err
}

func (r *dockerPortSmokeRunner) repoDigestCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.repositoryCalls
}

type dockerPortSmokeListenerRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func dockerPortSmokeListenerIdentity(path string) (dockerPortSmokeListenerRecord, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 || validateSecureRootPath(path, false) != nil {
		return dockerPortSmokeListenerRecord{}, errors.New("smoke listener file is not immutable and root-owned")
	}
	file, err := os.Open(path)
	if err != nil {
		return dockerPortSmokeListenerRecord{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return dockerPortSmokeListenerRecord{}, errors.New("smoke listener inode changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, dockerNodeListenerMaxBytes+1))
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if err != nil || !ok || len(body) > dockerNodeListenerMaxBytes {
		return dockerPortSmokeListenerRecord{}, errors.New("smoke listener identity unavailable")
	}
	digest := sha256.Sum256(body)
	return dockerPortSmokeListenerRecord{path, hex.EncodeToString(digest[:]), uint64(stat.Dev), stat.Ino}, nil
}

func (r *dockerPortSmokeRunner) captureExecution(path string) error {
	canonicalPath := strings.TrimSuffix(path, "-execution.json") + ".json"
	canonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		return err
	}
	execution, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	target := dockerPortSmokeTarget()
	target.ComposeConfigSHA256, err = composeModelHash(canonical, target.Service)
	if err != nil {
		return err
	}
	store := defaultDockerNodeListenerStore()
	store.root = filepath.Join(filepath.Dir(r.captureDir), "docker-listener-configs")
	plan, err := store.prepare(canonical, &target)
	if err != nil {
		return err
	}
	if err := store.validate(plan, canonical, execution, &target); err != nil {
		return err
	}
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	for kind, source := range map[string]string{"canonical": canonicalPath, "execution": path} {
		if err := os.Link(source, filepath.Join(r.captureDir, "compose-"+kind+"-"+suffix+".json")); err != nil {
			return errors.New("capture canonical and actual execution Compose inodes")
		}
	}
	record, err := dockerPortSmokeListenerIdentity(plan.path)
	if err != nil {
		return err
	}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(filepath.Dir(r.captureDir), "listener-generations.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(body, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	return firstError(writeErr, syncErr, closeErr)
}

func (r *dockerPortSmokeRunner) verifyMountedListener(ctx context.Context, path string, publishedPort int, observation *dockerPortSmokeRunnerObservation) error {
	observation.atListenerStage("execution_read")
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var model struct {
		Configs map[string]struct {
			File string `json:"file"`
		} `json:"configs"`
	}
	observation.atListenerStage("execution_decode")
	if json.Unmarshal(body, &model) != nil || len(model.Configs) != 1 {
		return errors.New("smoke execution listener source is ambiguous")
	}
	for _, config := range model.Configs {
		observation.atListenerStage("listener_source")
		if filepath.Dir(config.File) != filepath.Join(filepath.Dir(r.captureDir), "docker-listener-configs", "worker") {
			return errors.New("smoke listener source escaped task storage")
		}
		observation.atListenerStage("context")
		if err := ctx.Err(); err != nil {
			return err
		}
		return verifyDockerPortSmokeListenerFileObserved(config.File, publishedPort, observation)
	}
	return errors.New("smoke execution listener is missing")
}

func verifyDockerPortSmokeListenerFile(path string, publishedPort int) error {
	return verifyDockerPortSmokeListenerFileObserved(path, publishedPort, nil)
}

func verifyDockerPortSmokeListenerFileObserved(path string, publishedPort int, observation *dockerPortSmokeRunnerObservation) error {
	observation.atListenerStage("listener_file")
	record, err := dockerPortSmokeListenerIdentity(path)
	if err != nil {
		return err
	}
	var actual struct {
		SHA256 string `json:"listener_sha256"`
		Device uint64 `json:"listener_device"`
		Inode  uint64 `json:"listener_inode"`
	}
	observation.atListenerStage("fixture_http")
	if err := getDockerPortFixtureJSON(&http.Client{Timeout: time.Second}, fmt.Sprintf("http://127.0.0.1:%d/config", publishedPort), &actual); err != nil {
		return err
	}
	observation.atListenerStage("identity_match")
	observation.observeListenerMatch(record, actual.SHA256, actual.Device, actual.Inode)
	if actual.SHA256 != record.SHA256 || actual.Device != record.Device || actual.Inode != record.Inode {
		return errors.New("Docker daemon and executor do not observe the same listener bytes and inode")
	}
	return nil
}

func cleanupDockerPortSmokeListeners(t *testing.T, runner OSCommandRunner, stateDir, foreignContainer string) {
	t.Helper()
	// Only remove recorded files after both managed and foreign containers
	// (including stopped containers) have been removed successfully.
	for _, filter := range []string{"label=com.docker.compose.project=autostream", "name=^/" + foreignContainer + "$"} {
		out, err := runner.Run(context.Background(), "", dockerCommandEnv(), "/usr/bin/docker", "ps", "-aq", "--filter", filter)
		if err != nil || strings.TrimSpace(out) != "" {
			t.Error("listener cleanup requires removal of all fixture containers")
			return
		}
	}
	body, err := os.ReadFile(filepath.Join(stateDir, "listener-generations.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil || len(body) > 1<<20 {
		t.Error("listener cleanup inventory is unavailable or oversized")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	records := map[string]dockerPortSmokeListenerRecord{}
	for index := 0; ; index++ {
		var record dockerPortSmokeListenerRecord
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || index > 256 || filepath.Dir(record.Path) != filepath.Join(stateDir, "docker-listener-configs", "worker") || filepath.Base(record.Path) != record.SHA256+".json" {
			t.Error("listener cleanup inventory escaped task ownership")
			return
		}
		current, err := dockerPortSmokeListenerIdentity(record.Path)
		if err != nil || current != record {
			t.Error("listener cleanup inode changed")
			return
		}
		records[record.Path] = record
	}
	for path := range records {
		if err := os.Remove(path); err != nil {
			t.Error("remove recorded listener generation")
			return
		}
	}
	serviceDir := filepath.Join(stateDir, "docker-listener-configs", "worker")
	lockPath := filepath.Join(serviceDir, ".generation.lock")
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !isRootOwner(info) || info.Size() != 0 {
			t.Error("task generation lock changed")
			return
		}
		if err := os.Remove(lockPath); err != nil {
			t.Error(err)
			return
		}
	}
	for _, path := range []string{serviceDir, filepath.Dir(serviceDir)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error("listener cleanup found unrecorded files")
			return
		}
	}
	foreignPath := filepath.Join(stateDir, "foreign-listener", "node-listener.json")
	if _, err := os.Lstat(foreignPath); err == nil {
		if _, err := dockerPortSmokeListenerIdentity(foreignPath); err != nil {
			t.Error(err)
			return
		}
		if err := os.Remove(foreignPath); err != nil {
			t.Error(err)
			return
		}
		if err := os.Remove(filepath.Dir(foreignPath)); err != nil {
			t.Error(err)
		}
	}
}

func dockerPortSmokeFrozenComposePath(args []string) string {
	hasUp := false
	frozenPath := ""
	for index := range args {
		if args[index] == "up" {
			hasUp = true
		}
		if args[index] == "-f" && index+1 < len(args) {
			candidate := args[index+1]
			if filepath.Base(candidate) == "compose-frozen-execution.json" {
				frozenPath = candidate
			}
		}
	}
	if !hasUp {
		return ""
	}
	return frozenPath
}

func waitForDockerPortTCP(ctx context.Context, port int) error {
	deadline := time.Now().Add(10 * time.Second)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		connection, err := (&net.Dialer{
			Timeout: 200 * time.Millisecond,
		}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("Docker fixture did not listen on %s", address)
}

func dockerPortSmokeTarget() DockerTarget {
	return DockerTarget{
		DockerPath:              "/usr/bin/docker",
		ComposeProject:          "autostream",
		ProjectDir:              dockerPortSmokeProjectDir,
		ComposeFiles:            []string{"/opt/autostream/compose.yml"},
		Service:                 "worker",
		ImageRepo:               dockerPortSmokeImageRepo,
		ImageVariable:           "AUTOSTREAM_DOCKER_VERSION",
		BaseEnvFile:             "/opt/autostream/.env",
		VersionEnvFile:          "/opt/autostream/local-executor/docker/worker.env",
		PortEnvFile:             "/opt/autostream/local-executor/docker/ports/worker.env",
		ComposeConfigSHA256:     strings.Repeat("0", 64),
		PortComposePolicySHA256: strings.Repeat("0", 64),
		PortComposeRevision:     13,
		CurrentVersion:          "v1.0.0",
		Channel:                 "docker",
	}
}
