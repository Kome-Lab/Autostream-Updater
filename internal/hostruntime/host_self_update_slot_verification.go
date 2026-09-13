package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func hostSelfUpdateArtifactBinaryDigests(
	artifactRoot string,
) (hostSelfUpdateSlotDigests, error) {
	if !filepath.IsAbs(artifactRoot) {
		return hostSelfUpdateSlotDigests{},
			errors.New("host self-update artifact root is invalid")
	}
	var digests hostSelfUpdateSlotDigests
	for _, binary := range []struct {
		name        string
		destination *string
	}{
		{"autostream-host-agent", &digests.AgentSHA256},
		{"autostream-local-executor", &digests.ExecutorSHA256},
	} {
		path := filepath.Join(artifactRoot, "bin", binary.name)
		if !pathWithin(artifactRoot, path) {
			return hostSelfUpdateSlotDigests{},
				errors.New("host self-update artifact binary escaped its root")
		}
		info, err := os.Lstat(path)
		if err != nil ||
			!info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 {
			return hostSelfUpdateSlotDigests{},
				fmt.Errorf("host self-update artifact %s is unsafe", binary.name)
		}
		digest, err := hashFile(path)
		if err != nil || !isCanonicalBareSHA256(digest) {
			return hostSelfUpdateSlotDigests{},
				fmt.Errorf("hash host self-update artifact %s", binary.name)
		}
		*binary.destination = digest
	}
	if err := digests.validate(); err != nil {
		return hostSelfUpdateSlotDigests{}, err
	}
	return digests, nil
}

func (rt hostSelfUpdateExecutorRuntime) syncHostSelfUpdateDirectory(
	path string,
) error {
	if rt.syncDir != nil {
		return rt.syncDir(path)
	}
	return syncDirectory(path)
}

func (rt hostSelfUpdateExecutorRuntime) removeHostSelfUpdateSlotArtifact(
	path string,
) error {
	if !pathWithin(rt.slotsRoot, path) ||
		filepath.Dir(filepath.Clean(path)) != filepath.Clean(rt.slotsRoot) {
		return errors.New("host self-update slot artifact escaped the slots root")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return rt.syncHostSelfUpdateDirectory(rt.slotsRoot)
}

func (rt hostSelfUpdateExecutorRuntime) restoreHostSelfUpdateSlot(
	slotRoot, temporary, backup string,
	hadBackup bool,
) error {
	if info, err := os.Lstat(slotRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("failed host self-update slot is unsafe")
		}
		if _, temporaryErr := os.Lstat(temporary); temporaryErr == nil {
			if err := os.RemoveAll(temporary); err != nil {
				return err
			}
		} else if !errors.Is(temporaryErr, os.ErrNotExist) {
			return temporaryErr
		}
		if err := os.Rename(slotRoot, temporary); err != nil {
			return err
		}
		if err := rt.syncHostSelfUpdateDirectory(rt.slotsRoot); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hadBackup {
		info, err := os.Lstat(backup)
		if err != nil ||
			!info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 {
			return errors.New("host self-update slot backup is unavailable")
		}
		if err := os.Rename(backup, slotRoot); err != nil {
			return err
		}
		if err := rt.syncHostSelfUpdateDirectory(rt.slotsRoot); err != nil {
			return err
		}
	}
	return nil
}

func hostSelfUpdateSlotMarkers(
	request HostSelfUpdateRequest,
	binaryDigests map[string]string,
) (map[string][]byte, error) {
	if err := request.validate(); err != nil ||
		!isCanonicalBareSHA256(
			binaryDigests["autostream-host-agent"],
		) ||
		!isCanonicalBareSHA256(
			binaryDigests["autostream-local-executor"],
		) {
		return nil, errors.New("host self-update slot binding is invalid")
	}
	releaseJSON, err := json.Marshal(request.Release)
	if err != nil {
		return nil, err
	}
	line := func(value string) []byte {
		return []byte(value + "\n")
	}
	return map[string][]byte{
		".generation":            line(request.Generation),
		".agent-version":         line(request.AgentVersion),
		".executor-version":      line(request.ExecutorVersion),
		".commit":                line(request.Commit),
		".artifact-sha256":       line(request.ArtifactSHA256),
		".agent-protocol":        line(strconv.Itoa(request.AgentProtocolVersion)),
		".executor-protocol":     line(strconv.Itoa(request.ExecutorProtocolVersion)),
		".mutation-protocol":     line(strconv.Itoa(request.MutationProtocolVersion)),
		".recovery-protocol":     line(strconv.Itoa(request.RecoveryProtocolVersion)),
		".agent-sha256":          line(binaryDigests["autostream-host-agent"]),
		".local-executor-sha256": line(binaryDigests["autostream-local-executor"]),
		".release-binding.json":  append(releaseJSON, '\n'),
	}, nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyHostSelfUpdateSlot(
	ctx context.Context,
	slot, slotRoot string,
	request HostSelfUpdateRequest,
	slotDigests hostSelfUpdateSlotDigests,
) error {
	if !validHostSelfUpdateSlot(slot) ||
		filepath.Clean(slotRoot) != filepath.Join(rt.slotsRoot, slot) &&
			filepath.Dir(filepath.Clean(slotRoot)) != filepath.Clean(rt.slotsRoot) ||
		!pathWithin(rt.slotsRoot, slotRoot) ||
		request.validate() != nil ||
		slotDigests.validate() != nil {
		return errors.New("host self-update slot verification identity is invalid")
	}
	if err := rt.validateHostSelfUpdateSlotTreeRoot(slotRoot); err != nil {
		return err
	}
	releaseJSON, err := json.Marshal(request.Release)
	if err != nil {
		return err
	}
	expected := map[string][]byte{
		".generation":           []byte(request.Generation + "\n"),
		".agent-version":        []byte(request.AgentVersion + "\n"),
		".executor-version":     []byte(request.ExecutorVersion + "\n"),
		".commit":               []byte(request.Commit + "\n"),
		".artifact-sha256":      []byte(request.ArtifactSHA256 + "\n"),
		".agent-protocol":       []byte(strconv.Itoa(request.AgentProtocolVersion) + "\n"),
		".executor-protocol":    []byte(strconv.Itoa(request.ExecutorProtocolVersion) + "\n"),
		".mutation-protocol":    []byte(strconv.Itoa(request.MutationProtocolVersion) + "\n"),
		".recovery-protocol":    []byte(strconv.Itoa(request.RecoveryProtocolVersion) + "\n"),
		".release-binding.json": append(releaseJSON, '\n'),
	}
	for name, want := range expected {
		got, err := readHostSelfUpdateSlotMarker(
			filepath.Join(slotRoot, name),
			!rt.allowTestPaths,
		)
		if err != nil || !bytes.Equal(got, want) {
			return fmt.Errorf("host self-update slot marker %s is invalid", name)
		}
	}
	for _, binary := range []struct {
		name         string
		version      string
		digestMarker string
	}{
		{
			"autostream-host-agent",
			request.AgentVersion,
			".agent-sha256",
		},
		{
			"autostream-local-executor",
			request.ExecutorVersion,
			".local-executor-sha256",
		},
	} {
		digestBytes, err := readHostSelfUpdateSlotMarker(
			filepath.Join(slotRoot, binary.digestMarker),
			!rt.allowTestPaths,
		)
		digest := strings.TrimSuffix(string(digestBytes), "\n")
		if err != nil || !isCanonicalBareSHA256(digest) {
			return fmt.Errorf(
				"host self-update slot digest %s is invalid",
				binary.digestMarker,
			)
		}
		binaryPath := filepath.Join(slotRoot, "bin", binary.name)
		actualDigest, err := hashFile(binaryPath)
		if err != nil || actualDigest != digest {
			return fmt.Errorf(
				"host self-update slot binary %s digest is invalid",
				binary.name,
			)
		}
		expectedDigest := slotDigests.AgentSHA256
		if binary.name == "autostream-local-executor" {
			expectedDigest = slotDigests.ExecutorSHA256
		}
		if digest != expectedDigest {
			return fmt.Errorf(
				"host self-update slot binary %s digest contradicts durable state",
				binary.name,
			)
		}
		if err := rt.verifyHostSelfUpdateBinaryIdentity(
			ctx,
			slotRoot,
			binary.name,
			binary.version,
			request,
		); err != nil {
			return err
		}
	}
	return nil
}

func readHostSelfUpdateSlotMarker(
	path string,
	requireRootOwner bool,
) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o444) ||
		(requireRootOwner && !isRootOwner(info)) {
		return nil, errors.New("host self-update slot marker is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 ||
		body[len(body)-1] != '\n' ||
		bytes.Contains(body[:len(body)-1], []byte{'\n'}) {
		return nil, errors.New("host self-update slot marker is invalid")
	}
	return body, nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyHostSelfUpdateBinaryIdentity(
	ctx context.Context,
	slotRoot, binary, version string,
	request HostSelfUpdateRequest,
) error {
	binaryPath := filepath.Join(slotRoot, "bin", binary)
	if err := validateHostSelfUpdateSlotBinary(
		binaryPath,
		!rt.allowTestPaths,
	); err != nil {
		return fmt.Errorf("staged %s is unsafe", binary)
	}
	// The two fixed slot binaries are checked sequentially. Bounding each
	// identity command at two seconds keeps the complete server-side process
	// validation budget below the Local Executor client's five-second
	// deadline, including the identity runner's short WaitDelay.
	identityContext, cancel := context.WithTimeout(
		ctx,
		hostSelfUpdateBinaryIdentityTimeout,
	)
	defer cancel()
	output, err := hostSelfUpdateIdentityRunner(
		rt.identityRunner,
		rt.runner,
	).Run(
		identityContext,
		slotRoot,
		nil,
		binaryPath,
		"--version",
	)
	if err != nil ||
		!hostSelfUpdateVersionOutputHasLine(
			output,
			binary+" "+version,
		) ||
		!hostSelfUpdateVersionOutputHasLine(
			output,
			"commit: "+request.Commit,
		) {
		return fmt.Errorf("staged %s did not report the trusted identity", binary)
	}
	if binary == "autostream-local-executor" &&
		(!hostSelfUpdateVersionOutputHasLine(
			output,
			fmt.Sprintf(
				"mutation_protocol: %d",
				request.MutationProtocolVersion,
			),
		) ||
			!hostSelfUpdateVersionOutputHasLine(
				output,
				fmt.Sprintf(
					"recovery_protocol: %d",
					request.RecoveryProtocolVersion,
				),
			)) {
		return errors.New(
			"staged autostream-local-executor protocol identity is invalid",
		)
	}
	return nil
}

func hostSelfUpdateVersionOutputHasLine(output, want string) bool {
	for _, line := range strings.Split(
		strings.ReplaceAll(output, "\r\n", "\n"),
		"\n",
	) {
		if line == want {
			return true
		}
	}
	return false
}

func isCanonicalBareSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func copyHostSelfUpdateBinary(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 {
		return errors.New("host self-update binary source is unsafe")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(
		destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755,
	)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = output.Close()
		if remove {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Chmod(0o755); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}
