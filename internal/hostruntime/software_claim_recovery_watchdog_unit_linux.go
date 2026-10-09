//go:build linux

package hostruntime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const softwareClaimRecoveryWatchdogUnitPath = "/etc/systemd/system/autostream-host-self-update-recovery@.service"

var softwareClaimRecoveryWatchdogUnitProperties = []string{
	"Id", "LoadState", "FragmentPath", "DropInPaths", "NeedDaemonReload", "Transient",
	"Type", "User", "Group", "DynamicUser", "ExecStart", "ExecCondition", "ExecStartPre",
	"ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "RuntimeDirectory",
	"RuntimeDirectoryMode", "RuntimeDirectoryPreserve", "UMask", "RootDirectory", "RootImage",
	"BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "MountImages", "ExtensionImages",
	"ActiveState", "MainPID", "ControlPID", "ControlGroup", "InvocationID",
}

type softwareClaimRecoveryWatchdogUnit struct {
	slot, state                string
	mainPID, controlPID        int
	controlGroup, invocationID string
	staticIdentity             string
}

type softwareClaimRecoveryUnitSnapshot struct {
	file  secureManualHostUpgradeFile
	units []softwareClaimRecoveryWatchdogUnit
}

func inspectSoftwareClaimRecoveryWatchdogUnit(ctx context.Context, rt manualHostUpgradeRuntime) (softwareClaimRecoveryUnitSnapshot, error) {
	file, err := readSoftwareClaimRecoveryWatchdogUnitFile(ctx, rt)
	if err != nil {
		return softwareClaimRecoveryUnitSnapshot{}, err
	}
	units, err := readSoftwareClaimRecoveryWatchdogUnits(ctx, rt)
	if err != nil {
		return softwareClaimRecoveryUnitSnapshot{}, err
	}
	final, err := readSoftwareClaimRecoveryWatchdogUnitFile(ctx, rt)
	if err != nil || !sameSoftwareClaimRecoveryWatchdogUnitFile(file, final) {
		return softwareClaimRecoveryUnitSnapshot{}, softwareClaimWatchdogRefusal("unit_snapshot")
	}
	return softwareClaimRecoveryUnitSnapshot{file: file, units: units}, nil
}

func (snapshot softwareClaimRecoveryUnitSnapshot) Verify(ctx context.Context, rt manualHostUpgradeRuntime) error {
	if snapshot.file.info == nil || len(snapshot.units) != 2 {
		return softwareClaimWatchdogRefusal("unit_snapshot")
	}
	current, err := inspectSoftwareClaimRecoveryWatchdogUnit(ctx, rt)
	if err != nil {
		return err
	}
	if !sameSoftwareClaimRecoveryWatchdogUnitFile(snapshot.file, current.file) {
		return softwareClaimWatchdogRefusal("unit_snapshot")
	}
	for index, original := range snapshot.units {
		if original.slot != current.units[index].slot || original.staticIdentity == "" ||
			original.staticIdentity != current.units[index].staticIdentity {
			return softwareClaimWatchdogRefusal("unit_snapshot")
		}
	}
	return nil
}

func readSoftwareClaimRecoveryWatchdogUnitFile(ctx context.Context, rt manualHostUpgradeRuntime) (secureManualHostUpgradeFile, error) {
	path := rt.paths.installedRecoveryService
	if ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		(!rt.allowTestPaths && (path != softwareClaimRecoveryWatchdogUnitPath || validateSecureRootPath(path, false) != nil)) {
		return secureManualHostUpgradeFile{}, softwareClaimWatchdogRefusal("unit_file")
	}
	info, err := os.Lstat(path)
	if err != nil || !softwareClaimRecoveryWatchdogUnitFileSafe(info, rt.allowTestPaths) || info.Size() <= 0 || info.Size() > 16<<10 {
		return secureManualHostUpgradeFile{}, softwareClaimWatchdogRefusal("unit_file")
	}
	file, opened, err := openVerifiedConfig(path, info)
	if err != nil {
		return secureManualHostUpgradeFile{}, softwareClaimWatchdogRefusal("unit_file")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 16<<10+1))
	named, statErr := os.Lstat(path)
	final, fdErr := file.Stat()
	if ctx.Err() != nil || err != nil || statErr != nil || fdErr != nil || len(body) != int(info.Size()) ||
		!softwareClaimRecoveryWatchdogUnitFileSafe(opened, rt.allowTestPaths) ||
		!softwareClaimRecoveryWatchdogUnitFileSafe(named, rt.allowTestPaths) ||
		!softwareClaimRecoveryWatchdogUnitFileSafe(final, rt.allowTestPaths) ||
		!sameSoftwareClaimRecoveryWatchdogUnitInfo(opened, named) || !sameSoftwareClaimRecoveryWatchdogUnitInfo(opened, final) {
		return secureManualHostUpgradeFile{}, softwareClaimWatchdogRefusal("unit_file")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if !manualHostRecoveryUnitDigestIsCorrected(digest) {
		return secureManualHostUpgradeFile{}, softwareClaimWatchdogRefusal("unit_file")
	}
	_, dropIns, err := snapshotManualHostRecoveryUnitDropIns(manualHostRecoveryUnitMigrationConfig{InstalledPath: path, AllowTestPaths: rt.allowTestPaths})
	if err != nil || len(dropIns) != 0 || ctx.Err() != nil {
		return secureManualHostUpgradeFile{}, softwareClaimWatchdogRefusal("unit_file")
	}
	return secureManualHostUpgradeFile{path: path, info: final, digest: digest}, nil
}

func softwareClaimRecoveryWatchdogUnitFileSafe(info os.FileInfo, testPaths bool) bool {
	return info != nil && info.Mode() == 0o644 && manualHostRecoveryUnitLinkCount(info) == 1 &&
		((testPaths && managedSnapshotOwnedByCurrentUser(info)) || (!testPaths && manualHostRecoveryUnitRootOwned(info)))
}

func sameSoftwareClaimRecoveryWatchdogUnitInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() &&
		left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func sameSoftwareClaimRecoveryWatchdogUnitFile(left, right secureManualHostUpgradeFile) bool {
	return left.path == right.path && left.digest == right.digest && sameSoftwareClaimRecoveryWatchdogUnitInfo(left.info, right.info)
}

func readSoftwareClaimRecoveryWatchdogUnits(ctx context.Context, rt manualHostUpgradeRuntime) ([]softwareClaimRecoveryWatchdogUnit, error) {
	if rt.runner == nil || ctx.Err() != nil {
		return nil, softwareClaimWatchdogRefusal("unit_read")
	}
	units := make([]softwareClaimRecoveryWatchdogUnit, 0, 2)
	for _, slot := range []string{"a", "b"} {
		if ctx.Err() != nil {
			return nil, softwareClaimWatchdogRefusal("unit_read")
		}
		args := []string{"show", "--all"}
		for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
			args = append(args, "--property="+key)
		}
		args = append(args, "autostream-host-self-update-recovery@"+slot+".service")
		output, err := rt.runner.Run(ctx, "/", nil, "/usr/bin/systemctl", args...)
		if err != nil || ctx.Err() != nil {
			return nil, softwareClaimWatchdogRefusal("unit_read")
		}
		unit, err := parseSoftwareClaimRecoveryWatchdogUnit(output, slot, rt.paths.installedRecoveryService)
		if err != nil {
			return nil, err
		}
		units = append(units, unit)
	}
	return units, nil
}

func parseSoftwareClaimRecoveryWatchdogUnit(output, slot, fragment string) (softwareClaimRecoveryWatchdogUnit, error) {
	var empty softwareClaimRecoveryWatchdogUnit
	if (slot != "a" && slot != "b") || len(output) == 0 || len(output) > 16<<10 || !filepath.IsAbs(fragment) || filepath.Clean(fragment) != fragment {
		return empty, softwareClaimWatchdogRefusal("unit_output")
	}
	known := make(map[string]bool, len(softwareClaimRecoveryWatchdogUnitProperties))
	for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
		known[key] = true
	}
	values := make(map[string]string, len(known))
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || !known[key] {
			return empty, softwareClaimWatchdogRefusal("unit_output")
		}
		if _, duplicate := values[key]; duplicate {
			return empty, softwareClaimWatchdogRefusal("unit_output")
		}
		if !softwareClaimRecoveryWatchdogText(value, 4096) {
			return empty, softwareClaimWatchdogRefusal("unit_property_" + key)
		}
		values[key] = value
	}
	for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
		if _, found := values[key]; !found {
			// systemd's structured Exec printer emits no line for an empty
			// command array, even with --all. Only these fixed no-hook arrays
			// may be absent; any emitted command still fails the empty guard.
			if softwareClaimRecoveryWatchdogEmptyExecProperty(key) {
				values[key] = ""
				continue
			}
			return empty, softwareClaimWatchdogRefusal("unit_property_" + key)
		}
	}
	expected := map[string]string{
		"Id": "autostream-host-self-update-recovery@" + slot + ".service", "LoadState": "loaded",
		"FragmentPath": fragment, "DropInPaths": "", "NeedDaemonReload": "no", "Transient": "no",
		"Type": "oneshot", "User": "root", "Group": "root", "DynamicUser": "no", "ExecCondition": "",
		"ExecStartPre": "", "ExecStartPost": "", "ExecReload": "", "ExecStop": "", "ExecStopPost": "",
		"RuntimeDirectory": "autostream-updater", "RuntimeDirectoryMode": "0700", "RuntimeDirectoryPreserve": "yes", "UMask": "0077",
		"RootDirectory": "", "RootImage": "", "BindPaths": "", "BindReadOnlyPaths": "", "TemporaryFileSystem": "",
		"MountImages": "", "ExtensionImages": "",
	}
	for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
		if want, static := expected[key]; static && values[key] != want {
			return empty, softwareClaimWatchdogRefusal("unit_property_" + key)
		}
	}
	execution, valid := parseSoftwareClaimRecoveryWatchdogExecStart(values["ExecStart"], slot)
	if !valid {
		return empty, softwareClaimWatchdogRefusal("unit_exec_start")
	}
	state := values["ActiveState"]
	switch state {
	case "inactive", "failed", "active", "activating", "deactivating", "reloading", "maintenance":
	default:
		return empty, softwareClaimWatchdogRefusal("unit_property_ActiveState")
	}
	main, mainOK := softwareClaimRecoveryWatchdogPID(values["MainPID"])
	control, controlOK := softwareClaimRecoveryWatchdogPID(values["ControlPID"])
	if !mainOK {
		return empty, softwareClaimWatchdogRefusal("unit_property_MainPID")
	}
	if !controlOK {
		return empty, softwareClaimWatchdogRefusal("unit_property_ControlPID")
	}
	cgroup, invocation := values["ControlGroup"], values["InvocationID"]
	if (cgroup != "" && (!validLocalExecutorCgroup(cgroup) || strings.ContainsAny(cgroup, " \t"))) || ((main != 0 || control != 0) && cgroup == "") {
		return empty, softwareClaimWatchdogRefusal("unit_property_ControlGroup")
	}
	if invocation != "" && (len(invocation) != 32 || strings.IndexFunc(invocation, func(c rune) bool { return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') }) != -1) {
		return empty, softwareClaimWatchdogRefusal("unit_property_InvocationID")
	}
	identity := []string{}
	for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
		if _, static := expected[key]; static {
			identity = append(identity, key+"="+values[key])
		}
	}
	identity = append(identity, "ExecStart="+execution)
	return softwareClaimRecoveryWatchdogUnit{slot: slot, state: state, mainPID: main, controlPID: control,
		controlGroup: cgroup, invocationID: invocation, staticIdentity: fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(identity, "\n"))))}, nil
}

// Exec metadata is observed serialization, never a state or exclusion proof.
func parseSoftwareClaimRecoveryWatchdogExecStart(output, slot string) (string, bool) {
	text := strings.TrimSpace(output)
	if (slot != "a" && slot != "b") || len(text) < 2 || len(text) > 4096 || text[0] != '{' || text[len(text)-1] != '}' {
		return "", false
	}
	body := text[1 : len(text)-1]
	if strings.ContainsAny(body, "{}\\\"'") {
		return "", false
	}
	parts := strings.Split(body, ";")
	if len(parts) < 3 || len(parts) > 8 {
		return "", false
	}
	values := map[string]string{}
	for _, part := range parts {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		value = strings.TrimSpace(value)
		if !found || value == "" || !softwareClaimRecoveryWatchdogText(value, 1024) {
			return "", false
		}
		switch key {
		case "path", "argv[]", "ignore_errors", "start_time", "stop_time", "pid", "code", "status":
		default:
			return "", false
		}
		if _, duplicate := values[key]; duplicate {
			return "", false
		}
		values[key] = value
	}
	path := "/opt/autostream/host-agent/slots/" + slot + "/bin/autostream-local-executor"
	argv := path + " recover-self-update --recovery-slot " + slot
	if values["path"] != path || values["argv[]"] != argv || values["ignore_errors"] != "no" {
		return "", false
	}
	if value, present := values["pid"]; present {
		if _, valid := softwareClaimRecoveryWatchdogPID(value); !valid {
			return "", false
		}
	}
	if value, present := values["status"]; present && !softwareClaimRecoveryWatchdogExecStatus(value) {
		return "", false
	}
	return argv + " ignore_errors=no", true
}

func softwareClaimRecoveryWatchdogEmptyExecProperty(key string) bool {
	switch key {
	case "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost":
		return true
	}
	return false
}

// systemctl show prints a decimal exit status, or number/signal for a
// non-exited Exec record (including the never-run status=0/0). It is bounded
// observation metadata, not lock or process authority.
func softwareClaimRecoveryWatchdogExecStatus(value string) bool {
	number, label, slash := strings.Cut(value, "/")
	status, valid := softwareClaimRecoveryWatchdogPID(number)
	if !valid || status > 255 {
		return false
	}
	if !slash {
		return true
	}
	if label == number {
		return true
	}
	signals := []string{"", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS"}
	if status < len(signals) && signals[status] == label && label != "" {
		return true
	}
	if status >= 34 && status <= 64 && label == "RTMIN+"+strconv.Itoa(status-34) {
		return true
	}
	return false
}

func softwareClaimRecoveryWatchdogText(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, c := range value {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func softwareClaimRecoveryWatchdogPID(value string) (int, bool) {
	if len(value) == 0 || len(value) > 10 {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 31)
	return int(parsed), err == nil && strconv.FormatUint(parsed, 10) == value
}
