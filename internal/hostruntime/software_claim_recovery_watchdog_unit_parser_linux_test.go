//go:build linux

package hostruntime

import (
	"context"
	"strings"
	"testing"
)

// This follows the systemd v255 source printer, not captured host output.
// The actual installed-unit full-chain matrix must independently prove it.
func softwareClaimRecoveryWatchdogUnitTestOutput(slot, fragment string) string {
	output := `Id=autostream-host-self-update-recovery@$SLOT.service
LoadState=loaded
FragmentPath=$FRAGMENT
DropInPaths=
NeedDaemonReload=no
Transient=no
Type=oneshot
User=root
Group=root
DynamicUser=no
ExecStart={ path=/opt/autostream/host-agent/slots/$SLOT/bin/autostream-local-executor ; argv[]=/opt/autostream/host-agent/slots/$SLOT/bin/autostream-local-executor recover-self-update --recovery-slot $SLOT ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
RuntimeDirectory=autostream-updater
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
UMask=0077
RootDirectory=
RootImage=
BindPaths=
BindReadOnlyPaths=
TemporaryFileSystem=
MountImages=
ExtensionImages=
ActiveState=inactive
MainPID=0
ControlPID=0
ControlGroup=
InvocationID=
`
	return strings.ReplaceAll(strings.ReplaceAll(output, "$SLOT", slot), "$FRAGMENT", fragment)
}

func softwareClaimRecoveryWatchdogUnitTestProperty(output, key, value string) string {
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	found := false
	for index, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			lines[index] = key + "=" + value
			found = true
		}
	}
	if !found {
		lines = append(lines, key+"="+value)
	}
	return strings.Join(lines, "\n") + "\n"
}

// Parent wires this helper into the existing mandatory Linux root parent.
func softwareClaimRecoveryWatchdogUnitChecks(t *testing.T) {
	const fragment = "/fixture/autostream-host-self-update-recovery@.service"
	base := softwareClaimRecoveryWatchdogUnitTestOutput("a", fragment)
	for _, slot := range []string{"a", "b"} {
		t.Run("watchdog_unit_valid_"+slot, func(t *testing.T) {
			unit, err := parseSoftwareClaimRecoveryWatchdogUnit(softwareClaimRecoveryWatchdogUnitTestOutput(slot, fragment), slot, fragment)
			if err != nil || unit.slot != slot || unit.state != "inactive" || unit.mainPID != 0 || unit.controlPID != 0 ||
				unit.controlGroup != "" || unit.invocationID != "" || !isCanonicalBareSHA256(unit.staticIdentity) {
				t.Fatal("closed corrected watchdog contract was rejected")
			}
		})
	}
	t.Run("watchdog_unit_metadata_normalized", func(t *testing.T) {
		original, err := parseSoftwareClaimRecoveryWatchdogUnit(base, "a", fragment)
		if err != nil {
			t.Fatal("valid initial watchdog contract was rejected")
		}
		changed := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(base, "start_time=[n/a]", "start_time=[Fri 2026-10-09 00:00:00 UTC]"), "pid=0 ; code=(null)", "pid=123 ; code=exited"), "status=0/0 }", "status=1 }")
		current, err := parseSoftwareClaimRecoveryWatchdogUnit(changed, "a", fragment)
		if err != nil || original.staticIdentity != current.staticIdentity {
			t.Fatal("dynamic Exec metadata changed the authenticated static identity")
		}
	})
	for _, state := range []string{"inactive", "failed", "active", "activating", "deactivating", "reloading", "maintenance"} {
		t.Run("watchdog_unit_observation_"+state, func(t *testing.T) {
			original, err := parseSoftwareClaimRecoveryWatchdogUnit(base, "a", fragment)
			if err != nil {
				t.Fatal("valid initial watchdog contract was rejected")
			}
			changed := softwareClaimRecoveryWatchdogUnitTestProperty(base, "ActiveState", state)
			changed = softwareClaimRecoveryWatchdogUnitTestProperty(changed, "MainPID", "123")
			changed = softwareClaimRecoveryWatchdogUnitTestProperty(changed, "ControlPID", "124")
			changed = softwareClaimRecoveryWatchdogUnitTestProperty(changed, "ControlGroup", "/system.slice/known-watchdog.service")
			changed = softwareClaimRecoveryWatchdogUnitTestProperty(changed, "InvocationID", strings.Repeat("a", 32))
			current, err := parseSoftwareClaimRecoveryWatchdogUnit(changed, "a", fragment)
			if err != nil || current.state != state || current.mainPID != 123 || current.controlPID != 124 || current.staticIdentity != original.staticIdentity {
				t.Fatal("bounded dynamic observations changed the static contract")
			}
		})
	}
	for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
		t.Run("watchdog_unit_missing_"+key, func(t *testing.T) {
			lines := strings.Split(strings.TrimSuffix(base, "\n"), "\n")
			kept := []string{}
			for _, line := range lines {
				if !strings.HasPrefix(line, key+"=") {
					kept = append(kept, line)
				}
			}
			_, err := parseSoftwareClaimRecoveryWatchdogUnit(strings.Join(kept, "\n")+"\n", "a", fragment)
			if softwareClaimRecoveryWatchdogEmptyExecProperty(key) {
				if err != nil {
					t.Fatal("source-defined omitted empty Exec array was rejected")
				}
			} else if err == nil {
				t.Fatal("missing mandatory watchdog property was accepted")
			}
		})
		t.Run("watchdog_unit_invalid_"+key, func(t *testing.T) {
			if _, err := parseSoftwareClaimRecoveryWatchdogUnit(softwareClaimRecoveryWatchdogUnitTestProperty(base, key, "private-invalid"), "a", fragment); err == nil {
				t.Fatal("invalid watchdog property was accepted")
			}
		})
	}
	for _, variant := range []string{"unknown", "duplicate", "malformed", "oversized", "live_empty_group", "negative_pid", "overflow_pid", "noncanonical_pid", "unsafe_cgroup", "escaped_line"} {
		t.Run("watchdog_unit_output_"+variant, func(t *testing.T) {
			output := base
			switch variant {
			case "unknown":
				output += "Unknown=private-value\n"
			case "duplicate":
				output += "MainPID=0\n"
			case "malformed":
				output = strings.Replace(base, "User=root", "User:root", 1)
			case "oversized":
				output = strings.Repeat("x", 16<<10+1)
			case "live_empty_group":
				output = softwareClaimRecoveryWatchdogUnitTestProperty(base, "ControlPID", "123")
			case "negative_pid":
				output = softwareClaimRecoveryWatchdogUnitTestProperty(base, "MainPID", "-1")
			case "overflow_pid":
				output = softwareClaimRecoveryWatchdogUnitTestProperty(base, "MainPID", "2147483648")
			case "noncanonical_pid":
				output = softwareClaimRecoveryWatchdogUnitTestProperty(base, "MainPID", "00")
			case "unsafe_cgroup":
				output = softwareClaimRecoveryWatchdogUnitTestProperty(base, "ControlGroup", "/system.slice/../private")
			case "escaped_line":
				output = strings.Replace(base, "LoadState=loaded", "LoadState=loaded\r", 1)
			}
			if _, err := parseSoftwareClaimRecoveryWatchdogUnit(output, "a", fragment); err == nil {
				t.Fatal("unknown, ambiguous or malformed watchdog output was accepted")
			}
		})
	}
	path := "/opt/autostream/host-agent/slots/a/bin/autostream-local-executor"
	core := "path=" + path + " ; argv[]=" + path + " recover-self-update --recovery-slot a ; ignore_errors=no"
	for _, status := range []string{"0/0", "1", "15/TERM", "34/RTMIN+0", "255/255"} {
		t.Run("watchdog_unit_exec_status_valid_"+status, func(t *testing.T) {
			if _, valid := parseSoftwareClaimRecoveryWatchdogExecStart("{ "+core+" ; status="+status+" }", "a"); !valid {
				t.Fatal("source-defined bounded status metadata was rejected")
			}
		})
	}
	for _, status := range []string{"0/SUCCESS", "0/", "15/SEGV", "34/RTMIN+1", "0/0/0", "00/0", "256/256"} {
		t.Run("watchdog_unit_exec_status_invalid_"+strings.ReplaceAll(status, "/", "_"), func(t *testing.T) {
			if _, valid := parseSoftwareClaimRecoveryWatchdogExecStart("{ "+core+" ; status="+status+" }", "a"); valid {
				t.Fatal("ambiguous status metadata was accepted")
			}
		})
	}
	for _, variant := range []string{"missing_path", "missing_argv", "missing_ignore", "duplicate", "unknown", "second_record", "wrong_slot", "shell", "extra_argv", "quoted", "escaped", "ignored_error", "bad_metadata_pid", "bad_metadata_status", "empty_metadata"} {
		t.Run("watchdog_unit_exec_"+variant, func(t *testing.T) {
			body := core
			switch variant {
			case "missing_path":
				body = strings.Replace(core, "path="+path+" ; ", "", 1)
			case "missing_argv":
				body = "path=" + path + " ; ignore_errors=no"
			case "missing_ignore":
				body = strings.TrimSuffix(core, " ; ignore_errors=no")
			case "duplicate":
				body += " ; path=" + path
			case "unknown":
				body += " ; executable=private"
			case "second_record":
				body += " } { " + core
			case "wrong_slot":
				body = strings.ReplaceAll(core, "/slots/a/", "/slots/b/")
			case "shell":
				body = strings.Replace(core, "path="+path, "path=/bin/sh", 1)
			case "extra_argv":
				body = strings.Replace(core, "--recovery-slot a", "--recovery-slot a --extra", 1)
			case "quoted":
				body = strings.Replace(core, "argv[]=", "argv[]=\"", 1)
			case "escaped":
				body += " ; code=\\private"
			case "ignored_error":
				body = strings.Replace(core, "ignore_errors=no", "ignore_errors=yes", 1)
			case "bad_metadata_pid":
				body += " ; pid=-1"
			case "bad_metadata_status":
				body += " ; status=256"
			case "empty_metadata":
				body += " ; code="
			}
			if _, valid := parseSoftwareClaimRecoveryWatchdogExecStart("{ "+body+" }", "a"); valid {
				t.Fatal("ambiguous or untrusted watchdog command was accepted")
			}
		})
	}
	t.Run("watchdog_unit_empty_snapshot", func(t *testing.T) {
		if (softwareClaimRecoveryUnitSnapshot{}).Verify(context.Background(), manualHostUpgradeRuntime{}) == nil {
			t.Fatal("empty unit snapshot was accepted")
		}
	})
	t.Run("watchdog_unit_two_fixed_reads", func(t *testing.T) {
		calls := 0
		runner := softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
			if dir != "/" || len(env) != 0 || name != "/usr/bin/systemctl" || len(args) != len(softwareClaimRecoveryWatchdogUnitProperties)+3 || args[0] != "show" || args[1] != "--all" || calls > 1 {
				t.Fatal("unit reader broadened its fixed read-only command")
			}
			for index, key := range softwareClaimRecoveryWatchdogUnitProperties {
				if args[index+2] != "--property="+key {
					t.Fatal("unit reader changed the closed property query")
				}
			}
			slot := []string{"a", "b"}[calls]
			if args[len(args)-1] != "autostream-host-self-update-recovery@"+slot+".service" {
				t.Fatal("unit reader selected a foreign instance")
			}
			calls++
			return softwareClaimRecoveryWatchdogUnitTestOutput(slot, fragment), nil
		})
		units, err := readSoftwareClaimRecoveryWatchdogUnits(context.Background(), manualHostUpgradeRuntime{runner: runner, paths: manualHostUpgradePaths{installedRecoveryService: fragment}})
		if err != nil || calls != 2 || len(units) != 2 || units[0].slot != "a" || units[1].slot != "b" {
			t.Fatal("two bounded corrected unit observations were not returned")
		}
	})
	t.Run("watchdog_unit_canceled_read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		runner := softwareClaimRecoveryDiagnosticTestRunner(func(context.Context, string, []string, string, ...string) (string, error) {
			calls++
			return base, nil
		})
		if _, err := readSoftwareClaimRecoveryWatchdogUnits(ctx, manualHostUpgradeRuntime{runner: runner, paths: manualHostUpgradePaths{installedRecoveryService: fragment}}); err == nil || calls != 0 {
			t.Fatal("canceled unit read was accepted or launched a command")
		}
	})
}
