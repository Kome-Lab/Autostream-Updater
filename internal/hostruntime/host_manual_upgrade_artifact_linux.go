//go:build linux

package hostruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type manualHostArtifactManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	SourceVersion string `json:"source_version"`
	Commit        string `json:"commit"`
	BuildDate     string `json:"build_date"`
	Platform      struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"platform"`
	Archive struct {
		Name string `json:"name"`
		Root string `json:"root"`
	} `json:"archive"`
	Compatibility struct {
		MinimumAgentVersion *string `json:"minimum_agent_version"`
		MinimumPanelVersion string  `json:"minimum_panel_version"`
		RollbackCompatible  bool    `json:"rollback_compatible"`
		DatabaseSchema      string  `json:"database_schema"`
	} `json:"compatibility"`
}

func inspectManualHostUpgradeArtifact(
	ctx context.Context,
	input ManualHostUpgradeRequest,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeArtifact, error) {
	root := filepath.Clean(input.ArtifactRoot)
	if !filepath.IsAbs(root) || root == string(filepath.Separator) ||
		!isCanonicalBareSHA256(strings.TrimSpace(input.ArchiveSHA256)) ||
		input.ArchiveSize < 1 || input.ArchiveSize > defaultMaxArtifactBytes {
		return manualHostUpgradeArtifact{}, errors.New(
			"manual Host runtime bundle arguments are invalid",
		)
	}
	if err := validateManualHostUpgradeArtifactTree(root, rt.allowTestPaths); err != nil {
		return manualHostUpgradeArtifact{}, err
	}
	if err := verifyManualHostUpgradeChecksumInventory(root); err != nil {
		return manualHostUpgradeArtifact{}, err
	}
	manifestPath := filepath.Join(root, "artifact-manifest.json")
	manifestPayload, err := readBoundedManualHostUpgradeFile(
		manifestPath, 64<<10,
	)
	if err != nil {
		return manualHostUpgradeArtifact{}, errors.New(
			"read manual Host runtime artifact manifest",
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestPayload))
	decoder.DisallowUnknownFields()
	var manifest manualHostArtifactManifest
	if err := decoder.Decode(&manifest); err != nil {
		return manualHostUpgradeArtifact{}, errors.New(
			"decode manual Host runtime artifact manifest",
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return manualHostUpgradeArtifact{}, errors.New(
			"manual Host runtime artifact manifest contains trailing data",
		)
	}
	buildDate, err := time.Parse("2006-01-02T15:04:05Z", manifest.BuildDate)
	if err != nil || buildDate.Format("2006-01-02T15:04:05Z") != manifest.BuildDate {
		return manualHostUpgradeArtifact{}, errors.New(
			"manual Host runtime artifact build date is invalid",
		)
	}
	expectedRoot := "autostream-host-agent_" + manifest.SourceVersion +
		"_linux_" + manifest.Platform.Arch
	expectedArchive := expectedRoot + ".tar.gz"
	if manifest.SchemaVersion != 1 || manifest.Component != "host-agent" ||
		!versionPattern.MatchString(manifest.SourceVersion) ||
		!updaterReleaseCommitPattern.MatchString(manifest.Commit) ||
		manifest.Platform.OS != "linux" ||
		(manifest.Platform.Arch != "amd64" && manifest.Platform.Arch != "arm64") ||
		manifest.Platform.Arch != rt.selfUpdate.arch ||
		manifest.Archive.Name != expectedArchive ||
		manifest.Archive.Root != expectedRoot ||
		(!rt.allowTestPaths && filepath.Base(root) != expectedRoot) ||
		manifest.Compatibility.MinimumAgentVersion != nil ||
		manifest.Compatibility.MinimumPanelVersion != manifest.SourceVersion ||
		!manifest.Compatibility.RollbackCompatible ||
		manifest.Compatibility.DatabaseSchema != "none" {
		return manualHostUpgradeArtifact{}, errors.New(
			"artifact-manifest.json does not authorize this manual Host runtime bundle",
		)
	}
	manifestDigest := sha256.Sum256(manifestPayload)
	checksumsPayload, err := readBoundedManualHostUpgradeFile(
		filepath.Join(root, "checksums.txt"), 4<<20,
	)
	if err != nil {
		return manualHostUpgradeArtifact{}, errors.New(
			"read manual Host runtime checksum inventory",
		)
	}
	checksumsDigest := sha256.Sum256(checksumsPayload)
	artifact := manualHostUpgradeArtifact{
		Version:         manifest.SourceVersion,
		Commit:          manifest.Commit,
		BuildDate:       buildDate.UTC(),
		Arch:            manifest.Platform.Arch,
		MinimumPanel:    manifest.Compatibility.MinimumPanelVersion,
		ManifestSHA256:  hex.EncodeToString(manifestDigest[:]),
		ChecksumsSHA256: hex.EncodeToString(checksumsDigest[:]),
	}
	if err := artifact.validate(); err != nil {
		return manualHostUpgradeArtifact{}, err
	}
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		identity, identityErr := readManualHostBinaryIdentity(
			ctx,
			filepath.Join(root, "bin", binary),
			binary,
			rt.identityRunner,
		)
		if identityErr != nil || identity.Version != artifact.Version ||
			identity.Commit != artifact.Commit ||
			!identity.BuildDate.Equal(artifact.BuildDate) ||
			(binary == "autostream-local-executor" &&
				(identity.MutationProtocol != LocalExecutorMutationProtocolVersion ||
					identity.RecoveryProtocol != HostSelfUpdateRecoveryProtocolVersion)) {
			return manualHostUpgradeArtifact{}, fmt.Errorf(
				"%s does not match the verified manual Host runtime identity",
				binary,
			)
		}
	}
	return artifact, nil
}

func validateManualHostUpgradeArtifactTree(root string, allowTestPaths bool) error {
	if err := validateManualHostUpgradeArtifactStagingPath(
		root,
		allowTestPaths,
	); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("manual Host runtime artifact root is unsafe")
	}
	if !allowTestPaths && !isRootOwner(rootInfo) {
		return errors.New("manual Host runtime artifact root is not root-owned")
	}
	count := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 4096 || !pathWithin(root, path) {
			return errors.New("manual Host runtime artifact tree is too large")
		}
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) ||
			info.Mode().Perm()&0o022 != 0 ||
			(!allowTestPaths && !isRootOwner(info)) {
			return errors.New("manual Host runtime artifact tree contains an unsafe entry")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func validateManualHostUpgradeArtifactStagingPath(
	root string,
	allowTestPaths bool,
) error {
	if allowTestPaths {
		return nil
	}
	const stagingParent = "/var/tmp"
	unpack := filepath.Dir(root)
	stage := filepath.Dir(unpack)
	if filepath.Clean(root) != root || filepath.Base(root) == "." ||
		filepath.Base(root) == string(filepath.Separator) ||
		filepath.Base(unpack) != "unpack" || filepath.Dir(stage) != stagingParent ||
		!isManualHostInstallerStageName(filepath.Base(stage)) {
		return errors.New(
			"manual Host runtime artifact root is outside the installer staging directory",
		)
	}
	if err := validateSecureRootPath("/var", true); err != nil {
		return errors.New("manual Host runtime staging parent is unsafe")
	}
	varTmpInfo, err := os.Lstat(stagingParent)
	if err != nil || !varTmpInfo.IsDir() ||
		varTmpInfo.Mode()&os.ModeSymlink != 0 || !isRootOwner(varTmpInfo) ||
		varTmpInfo.Mode().Perm() != 0o777 ||
		varTmpInfo.Mode()&os.ModeSticky == 0 {
		return errors.New("manual Host runtime staging parent is unsafe")
	}
	for _, path := range []string{stage, unpack} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			!isRootOwner(info) || info.Mode().Perm() != 0o700 {
			return errors.New(
				"manual Host runtime installer staging directory is unsafe",
			)
		}
	}
	return nil
}

func isManualHostInstallerStageName(name string) bool {
	const prefix = "autostream-host-agent-install."
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == name || len(suffix) != 8 {
		return false
	}
	for _, character := range suffix {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func verifyManualHostUpgradeChecksumInventory(root string) error {
	checksumsPath := filepath.Join(root, "checksums.txt")
	payload, err := readBoundedManualHostUpgradeFile(checksumsPath, 4<<20)
	if err != nil || len(payload) == 0 || payload[len(payload)-1] != '\n' {
		return errors.New("manual Host runtime checksum inventory is invalid")
	}
	listed := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 69 || line[64:68] != "  ./" ||
			!isCanonicalBareSHA256(line[:64]) {
			return errors.New("manual Host runtime checksum entry is invalid")
		}
		name := line[68:]
		clean := filepath.Clean(filepath.FromSlash(name))
		if name == "" || name == "checksums.txt" || clean == "." ||
			filepath.IsAbs(clean) || clean != filepath.FromSlash(name) ||
			strings.Contains(name, "\\") ||
			strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
			listed[clean] != "" {
			return errors.New("manual Host runtime checksum path is unsafe or duplicated")
		}
		path := filepath.Join(root, clean)
		if !pathWithin(root, path) {
			return errors.New("manual Host runtime checksum path escaped its root")
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 {
			return errors.New("manual Host runtime checksum path is not a regular file")
		}
		digest, hashErr := hashFile(path)
		if hashErr != nil || digest != line[:64] {
			return errors.New("manual Host runtime checksum verification failed")
		}
		listed[clean] = digest
	}
	if err := scanner.Err(); err != nil || len(listed) == 0 {
		return errors.New("manual Host runtime checksum inventory is unreadable")
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Clean(path) == filepath.Clean(checksumsPath) {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || listed[relative] == "" {
			return errors.New("manual Host runtime file is absent from checksums.txt")
		}
		return nil
	})
	return err
}

func readBoundedManualHostUpgradeFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 ||
		info.Size() > maximum {
		return nil, errors.New("manual Host runtime file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, errors.New("manual Host runtime file is unreadable")
	}
	return payload, nil
}

func readManualHostBinaryIdentity(
	ctx context.Context,
	path, name string,
	runner CommandRunner,
) (manualHostBinaryIdentity, error) {
	if runner == nil || (name != "autostream-host-agent" &&
		name != "autostream-local-executor") {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity request is invalid",
		)
	}
	identityContext, cancel := context.WithTimeout(
		ctx, hostSelfUpdateBinaryIdentityTimeout,
	)
	defer cancel()
	output, err := runner.Run(identityContext, "/", nil, path, "--version")
	if err != nil {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity command failed",
		)
	}
	lines := strings.Split(strings.TrimSuffix(
		strings.ReplaceAll(output, "\r\n", "\n"), "\n",
	), "\n")
	expectedLines := 3
	if name == "autostream-local-executor" {
		expectedLines = 5
	}
	if len(lines) != expectedLines || !strings.HasPrefix(lines[0], name+" ") {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity output is invalid",
		)
	}
	identity := manualHostBinaryIdentity{
		Name:    name,
		Version: strings.TrimPrefix(lines[0], name+" "),
	}
	seen := make(map[string]bool)
	for _, line := range lines[1:] {
		key, value, found := strings.Cut(line, ": ")
		if !found || seen[key] {
			return manualHostBinaryIdentity{}, errors.New(
				"manual Host runtime binary identity output is invalid",
			)
		}
		seen[key] = true
		switch key {
		case "commit":
			identity.Commit = value
		case "build_date":
			identity.BuildDate, err = time.Parse("2006-01-02T15:04:05Z", value)
		case "mutation_protocol":
			identity.MutationProtocol, err = strconv.Atoi(value)
		case "recovery_protocol":
			identity.RecoveryProtocol, err = strconv.Atoi(value)
		default:
			err = errors.New("unexpected identity field")
		}
		if err != nil {
			return manualHostBinaryIdentity{}, errors.New(
				"manual Host runtime binary identity output is invalid",
			)
		}
	}
	if !versionPattern.MatchString(identity.Version) ||
		!updaterReleaseCommitPattern.MatchString(identity.Commit) ||
		identity.BuildDate.IsZero() || identity.BuildDate.Location() != time.UTC ||
		!seen["commit"] || !seen["build_date"] ||
		(name == "autostream-local-executor" &&
			(!seen["mutation_protocol"] || !seen["recovery_protocol"])) {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity is invalid",
		)
	}
	return identity, nil
}
