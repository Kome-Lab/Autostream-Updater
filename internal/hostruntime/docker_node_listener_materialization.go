package hostruntime

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

const (
	dockerNodeListenerConfigRoot     = "/var/lib/autostream-local-executor/docker-listener-configs"
	dockerNodeListenerMaxBytes       = 64 << 10
	dockerNodeListenerMaxGenerations = 256
)

// This is an executor construction detail, never a request or policy input.
// Tests can supply an isolated root; production always uses the fixed root.
type dockerNodeListenerStore struct {
	root         string
	trustedOwner func(os.FileInfo) bool
	checkParents bool
}

func defaultDockerNodeListenerStore() dockerNodeListenerStore {
	return dockerNodeListenerStore{dockerNodeListenerConfigRoot, isRootOwner, true}
}

type dockerNodeListenerExecution struct {
	canonical []byte
	execution []byte
	content   []byte
	path      string
	service   string
}

// prepare is pure: approval and hashes continue to describe the inline model.
// Only the exact listener config definition changes in the derived model.
func (s dockerNodeListenerStore) prepare(raw []byte, target *DockerTarget) (dockerNodeListenerExecution, error) {
	if target == nil || s.trustedOwner == nil || !utf8.Valid(raw) {
		return dockerNodeListenerExecution{}, errors.New("Docker listener execution authority is unavailable")
	}
	if err := validateComposeModelSecurity(raw, target); err != nil {
		return dockerNodeListenerExecution{}, err
	}
	digest, err := composeModelHash(raw, target.Service)
	if err != nil || digest != target.ComposeConfigSHA256 {
		return dockerNodeListenerExecution{}, errors.New("Docker listener canonical model differs from root approval")
	}
	result := dockerNodeListenerExecution{canonical: bytes.Clone(raw), execution: bytes.Clone(raw)}
	if !isCanonicalNodeDockerPortTarget(target) {
		return result, nil
	}
	if !filepath.IsAbs(s.root) || filepath.Clean(s.root) != s.root {
		return dockerNodeListenerExecution{}, errors.New("Docker listener storage root is invalid")
	}
	_, source, err := dockerNodeListenerFromCompose(raw, target.Service)
	if err != nil {
		return dockerNodeListenerExecution{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model map[string]any
	if decoder.Decode(&model) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return dockerNodeListenerExecution{}, errors.New("Docker listener canonical model is invalid")
	}
	configs, _ := model["configs"].(map[string]any)
	definition, _ := configs[source].(map[string]any)
	content, _ := definition["content"].(string)
	if len(content) == 0 || len(content) > dockerNodeListenerMaxBytes || !utf8.ValidString(content) {
		return dockerNodeListenerExecution{}, errors.New("Docker listener bytes are invalid or oversized")
	}
	// Count every use, including another target in the same service. The
	// canonical parser already rejects another service and ambiguous targets.
	uses := 0
	services, _ := model["services"].(map[string]any)
	for _, value := range services {
		service, _ := value.(map[string]any)
		mounts, _ := service["configs"].([]any)
		for _, value := range mounts {
			mount, _ := value.(map[string]any)
			if mount["source"] == source {
				uses++
			}
		}
	}
	if uses != 1 {
		return dockerNodeListenerExecution{}, errors.New("Docker listener source must have exactly one mount")
	}
	hash := sha256.Sum256([]byte(content))
	result.path = filepath.Join(s.root, target.Service, hex.EncodeToString(hash[:])+".json")
	result.service, result.content = target.Service, []byte(content)
	configs[source] = map[string]any{"file": result.path}
	result.execution, err = json.Marshal(model)
	if err != nil {
		return dockerNodeListenerExecution{}, errors.New("derive Docker listener execution model")
	}
	return result, nil
}

func (s dockerNodeListenerStore) directory(path string, private, create bool) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || s.trustedOwner == nil {
		return nil, errors.New("Docker listener directory is invalid")
	}
	if s.checkParents {
		parent := filepath.Dir(path)
		if parent != path {
			root, err := s.directory(parent, false, create)
			if err != nil {
				return nil, err
			}
			defer root.Close()
			if create {
				if err := root.Mkdir(filepath.Base(path), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
					return nil, errors.New("create Docker listener directory")
				} else if err == nil {
					if err := syncDirectory(parent); err != nil {
						return nil, errors.New("sync Docker listener parent directory")
					}
				}
			}
		}
	} else if create {
		// The explicit test anchor must already exist. Never create ancestors
		// through this seam, and still check every directory below that anchor.
		if path != s.root && filepath.Dir(path) != s.root {
			return nil, errors.New("Docker listener test directory escapes its anchor")
		}
		if path != s.root {
			anchor, err := s.directory(s.root, true, false)
			if err != nil {
				return nil, err
			}
			defer anchor.Close()
			if err := anchor.Mkdir(filepath.Base(path), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, errors.New("create Docker listener service directory")
			}
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!s.trustedOwner(info) || info.Mode().Perm()&0o022 != 0 || (private && info.Mode().Perm() != 0o700) {
		return nil, errors.New("Docker listener directory is not root-controlled")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("open Docker listener directory")
	}
	opened, err := root.Stat(".")
	current, currentErr := os.Lstat(path)
	if err != nil || currentErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, current) {
		root.Close()
		return nil, errors.New("Docker listener directory identity changed")
	}
	return root, nil
}

func (s dockerNodeListenerStore) read(root *os.Root, name string, mode os.FileMode, maximum int64) ([]byte, os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode || !s.trustedOwner(info) || info.Size() > maximum {
		return nil, nil, errors.New("Docker listener file metadata is invalid")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, errors.New("open Docker listener file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, errors.New("Docker listener file identity changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	after, afterErr := root.Lstat(name)
	if err != nil || int64(len(body)) > maximum || afterErr != nil ||
		!os.SameFile(info, after) || after.Mode() != info.Mode() || !s.trustedOwner(after) {
		return nil, nil, errors.New("Docker listener file changed while reading")
	}
	return body, info, nil
}

func (s dockerNodeListenerStore) verifyFile(plan dockerNodeListenerExecution) error {
	if plan.path == "" {
		return nil
	}
	anchor, err := s.directory(s.root, true, false)
	if err != nil {
		return err
	}
	defer anchor.Close()
	root, err := s.directory(filepath.Dir(plan.path), true, false)
	if err != nil {
		return err
	}
	defer root.Close()
	body, _, err := s.read(root, filepath.Base(plan.path), 0o444, dockerNodeListenerMaxBytes)
	if err != nil || !bytes.Equal(body, plan.content) {
		return errors.New("materialized Docker listener does not match approved bytes")
	}
	return nil
}

func (s dockerNodeListenerStore) materialize(plan dockerNodeListenerExecution) error {
	if plan.path == "" {
		return nil
	}
	anchor, err := s.directory(s.root, true, true)
	if err != nil {
		return err
	}
	defer anchor.Close()
	root, err := s.directory(filepath.Dir(plan.path), true, true)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(plan.path)
	if _, err := root.Lstat(name); err == nil {
		return s.verifyFile(plan)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect Docker listener generation")
	}
	// A permanent inode plus the existing OS lock serializes creation across
	// processes. A process crash releases the lock without deleting generations.
	lock, err := root.OpenFile(".generation.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		err = lock.Close()
	} else if errors.Is(err, os.ErrExist) {
		err = nil
	}
	if err != nil {
		return errors.New("create Docker listener generation lock")
	}
	_, lockInfo, err := s.read(root, ".generation.lock", 0o600, 0)
	if err != nil {
		return err
	}
	unlock, err := lockFile(filepath.Join(filepath.Dir(plan.path), ".generation.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	_, currentLock, err := s.read(root, ".generation.lock", 0o600, 0)
	if err != nil || !os.SameFile(lockInfo, currentLock) {
		return errors.New("Docker listener generation lock changed")
	}
	if _, err := root.Lstat(name); err == nil {
		return s.verifyFile(plan)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(dockerNodeListenerMaxGenerations + 2)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("count Docker listener generations")
	}
	count := 0
	for _, entry := range entries {
		if entry.Name() != ".generation.lock" {
			count++
		}
	}
	if count >= dockerNodeListenerMaxGenerations {
		return errors.New("Docker listener generation capacity reached")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("allocate Docker listener generation")
	}
	temporary := ".pending-" + hex.EncodeToString(nonce[:])
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("create Docker listener generation")
	}
	defer root.Remove(temporary) // only the file allocated by this invocation
	_, writeErr := file.Write(plan.content)
	modeErr := file.Chmod(0o444)
	syncErr := file.Sync()
	closeErr := file.Close()
	if firstError(writeErr, modeErr, syncErr, closeErr) != nil {
		return errors.New("persist Docker listener generation")
	}
	// Link is no-replace: an existing generation can never be overwritten.
	if err := root.Link(temporary, name); err != nil {
		return errors.New("publish immutable Docker listener generation")
	}
	if err := root.Remove(temporary); err != nil {
		return errors.New("unlink Docker listener temporary name")
	}
	if err := syncDirectory(filepath.Dir(plan.path)); err != nil {
		return errors.New("sync Docker listener generation directory")
	}
	return s.verifyFile(plan)
}

func (s dockerNodeListenerStore) validate(plan dockerNodeListenerExecution, canonical, execution []byte, target *DockerTarget) error {
	if !bytes.Equal(plan.canonical, canonical) || !bytes.Equal(plan.execution, execution) {
		return errors.New("Docker canonical or execution model changed before launch")
	}
	expected, err := s.prepare(canonical, target)
	if err != nil || !bytes.Equal(expected.execution, execution) || expected.path != plan.path {
		return errors.New("Docker execution model is not the approved listener projection")
	}
	return s.verifyFile(plan)
}

type dockerFrozenExecution struct {
	plan          dockerNodeListenerExecution
	canonicalPath string
	path          string
}

func (s dockerNodeListenerStore) freeze(canonicalPath string, target *DockerTarget) (dockerFrozenExecution, error) {
	raw, err := readDockerExecutionModel(canonicalPath, s.trustedOwner)
	if err != nil {
		return dockerFrozenExecution{}, err
	}
	plan, err := s.prepare(raw, target)
	if err != nil {
		return dockerFrozenExecution{}, err
	}
	if err := s.materialize(plan); err != nil {
		return dockerFrozenExecution{}, err
	}
	result := dockerFrozenExecution{plan: plan, canonicalPath: canonicalPath, path: canonicalPath}
	if plan.path != "" {
		result.path = strings.TrimSuffix(canonicalPath, ".json") + "-execution.json"
		if err := writeAtomicFile(result.path, plan.execution, 0o600); err != nil {
			return dockerFrozenExecution{}, err
		}
	}
	return result, nil
}

func (s dockerNodeListenerStore) validateFrozen(frozen dockerFrozenExecution, target *DockerTarget) error {
	canonical, err := readDockerExecutionModel(frozen.canonicalPath, s.trustedOwner)
	if err != nil {
		return err
	}
	execution, err := readDockerExecutionModel(frozen.path, s.trustedOwner)
	if err != nil {
		return err
	}
	return s.validate(frozen.plan, canonical, execution, target)
}

func readDockerExecutionModel(path string, owner func(os.FileInfo) bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || owner == nil || !owner(info) || !info.Mode().IsRegular() ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0) || info.Size() > 16<<20 {
		return nil, errors.New("Docker frozen model is not a bounded executor-owned regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open Docker frozen model")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("Docker frozen model identity changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	after, afterErr := os.Lstat(path)
	if err != nil || len(body) > 16<<20 || afterErr != nil || !os.SameFile(info, after) {
		return nil, errors.New("Docker frozen model changed while reading")
	}
	return body, nil
}
