#!/bin/bash
set -Eeuo pipefail

# This is a fixture-only installer oracle. It never fetches or publishes a
# release and refuses to run outside the disposable Actions systemd container.
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
readonly SOFTWARE_INSTALLER_STATUS=/evidence/artifacts/normal-installer-status.json
software_installer_phase=entry
software_installer_status_enabled=false
software_installer_getfacl_present=false
software_installer_setfacl_present=false
software_installer_other_dependencies_present=false
software_installer_source_inventory_matched=false
software_installer_source_inventory_count=0
software_installer_checkpoint=entry
software_installer_failure_line=null
software_installer_failure_status=null
software_installer_baseline_exit=null
software_installer_candidate_exit=null
software_installer_after_injection=false
software_installer_race_result=false
software_installer_timers=false

software_installer_record_status() {
  [[ ${software_installer_status_enabled} == true ]] || return 0
  local exited=false exit_code=null
  if [[ $# -eq 1 ]]; then exited=true; exit_code=$1; fi
  printf '{"schema_version":1,"phase":"%s","exited":%s,"exit_code":%s,"getfacl_present":%s,"setfacl_present":%s,"other_dependencies_present":%s,"source_inventory_matched":%s,"source_inventory_count":%d}\n' \
    "${software_installer_phase}" "${exited}" "${exit_code}" "${software_installer_getfacl_present}" \
    "${software_installer_setfacl_present}" "${software_installer_other_dependencies_present}" \
    "${software_installer_source_inventory_matched}" "${software_installer_source_inventory_count}" \
    > "${SOFTWARE_INSTALLER_STATUS}" || return 0
}
software_installer_enter_phase() {
  software_installer_phase=$1
  software_installer_checkpoint=$1
  software_installer_record_status
}
software_installer_record_boundary() {
  [[ ${software_installer_status_enabled} == true ]] || return 0
  # Private input for the post-fixture projection; never dump command/error text.
  printf '{"checkpoint":"%s","failure_source_line":%s,"shell_command_exit":%s,"baseline_installer_exit":%s,"candidate_installer_exit":%s,"hook_exit":%d,"after_injection_confirmed":%s,"race_result_completed":%s,"timers_verified":%s}\n' \
    "${software_installer_checkpoint}" "${software_installer_failure_line}" "${software_installer_failure_status}" \
    "${software_installer_baseline_exit}" "${software_installer_candidate_exit}" "$1" \
    "${software_installer_after_injection}" "${software_installer_race_result}" "${software_installer_timers}" \
    > /evidence/installer/ui183-command-boundary.json
}
software_installer_on_error() {
  local status=$?
  software_installer_failure_line=$1
  software_installer_failure_status=${status}
  if [[ ${software_installer_checkpoint} == candidate_installer_command ]]; then
    software_installer_candidate_exit=${status}
  fi
  software_installer_record_status "${status}"
  printf 'software installer ordering failed at phase %s (status %s)\n' "${software_installer_phase}" "${status}" >&2
  exit "${status}"
}
software_installer_on_exit() {
  local status=$?
  trap - EXIT ERR
  software_installer_record_status "${status}"
  software_installer_record_boundary "${status}" 2>/dev/null || true
  exit "${status}"
}
trap 'software_installer_on_error "$LINENO"' ERR
trap software_installer_on_exit EXIT
[[ ${GITHUB_ACTIONS:-} == true && $(id -u) == 0 && -f /.dockerenv &&
  $(cat /proc/1/comm) == systemd && $# == 6 ]] || {
  printf '%s\n' 'software installer ordering requires the isolated CI container and six inputs' >&2
  exit 1
}
[[ -d /evidence/artifacts && ! -e ${SOFTWARE_INSTALLER_STATUS} && ! -L ${SOFTWARE_INSTALLER_STATUS} ]] || {
  printf '%s\n' 'software installer diagnostic output must be fresh in the isolated fixture' >&2
  exit 1
}
software_installer_status_enabled=true
software_installer_enter_phase input_validation
if command -v getfacl >/dev/null 2>&1; then software_installer_getfacl_present=true; fi
if command -v setfacl >/dev/null 2>&1; then software_installer_setfacl_present=true; fi
software_installer_record_status
readonly REPOSITORY_ROOT=$1
readonly BEFORE_BINARIES=$2
readonly BEFORE_COMMIT=$3
readonly CANDIDATE_BINARIES=$4
readonly CANDIDATE_COMMIT=$5
readonly EVIDENCE_DIRECTORY=$6
readonly BEFORE_VERSION=v2.0.0
readonly CANDIDATE_VERSION=v2.0.1
readonly BASELINE_COMMIT=f72d1bddb712eeb64bab2b852b648c2c6b0f4641
readonly BASELINE_BINARIES=/opt/software-input/baseline-production
readonly IDENTITY=/etc/autostream/updater/agent.yaml
readonly POLICY=/etc/autostream/updater/executor-policy.json
readonly HOST_ROOT=/opt/autostream/host-agent
readonly STATE_ROOT=/var/lib/autostream-local-executor
[[ ${BEFORE_COMMIT} =~ ^[0-9a-f]{40}$ && ${CANDIDATE_COMMIT} =~ ^[0-9a-f]{40}$ &&
  ${BEFORE_COMMIT} != "${CANDIDATE_COMMIT}" &&
  -d ${REPOSITORY_ROOT} && -d ${BEFORE_BINARIES} && -d ${CANDIDATE_BINARIES} &&
  ! -e ${HOST_ROOT} && ! -e ${EVIDENCE_DIRECTORY}/result.json ]] || {
  printf '%s\n' 'software installer inputs or fresh managed runtime namespace are invalid' >&2
  exit 1
}
case "$(uname -m)" in
  x86_64) readonly ARCH=amd64 ;;
  aarch64|arm64) readonly ARCH=arm64 ;;
  *) exit 1 ;;
esac
software_installer_enter_phase protected_inputs
[[ $(stat -c '%U:%G:%a' /etc/autostream/updater) == root:autostream-host-agent:750 &&
  $(stat -c '%U:%G:%a:%h' "${IDENTITY}") == root:autostream-host-agent:640:1 &&
  $(stat -c '%U:%G:%a:%h' "${POLICY}") == root:root:600:1 &&
  ! -L ${IDENTITY} && ! -L ${POLICY} ]] || {
  printf '%s\n' 'software fixture identity or policy is not canonical' >&2
  exit 1
}
install -d -o root -g root -m 0700 "${EVIDENCE_DIRECTORY}"
readonly IDENTITY_SHA256="$(sha256sum "${IDENTITY}" | awk '{print $1}')"
readonly IDENTITY_METADATA="$(stat -c '%d:%i:%u:%g:%a:%h' "${IDENTITY}")"
readonly POLICY_SHA256="$(sha256sum "${POLICY}" | awk '{print $1}')"
readonly POLICY_METADATA="$(stat -c '%d:%i:%u:%g:%a:%h' "${POLICY}")"

# Read only the generated installer's closed ordinary dependency inventory.
# Captured names contain ASCII letters/digits/spaces; no source is evaluated.
software_installer_enter_phase ordinary_dependencies
software_installer_dependency_inventory() {
  local line matches=0 getfacl_seen=false setfacl_seen=false unique=true program
  local -a commands=()
  local -A seen=()
  [[ -f ${REPOSITORY_ROOT}/install/install-autostream-updater-agent &&
    ! -L ${REPOSITORY_ROOT}/install/install-autostream-updater-agent ]] || return 0
  while IFS= read -r line || [[ -n ${line} ]]; do
    line=${line%$'\r'}
    if [[ ${line} =~ ^for\ command\ in\ ([a-z0-9\ ]+)\;\ do$ ]]; then
      matches=$((matches + 1))
      read -r -a commands <<< "${BASH_REMATCH[1]}"
    fi
  done < "${REPOSITORY_ROOT}/install/install-autostream-updater-agent"
  if [[ ${#commands[@]} -le 64 ]]; then software_installer_source_inventory_count=${#commands[@]}; fi
  [[ ${matches} -eq 1 && ${#commands[@]} -eq 37 ]] || return 0
  for program in "${commands[@]}"; do
    if [[ -n ${seen[${program}]+present} ]]; then unique=false; fi
    seen[${program}]=present
    case "${program}" in
      getfacl) getfacl_seen=true ;;
      setfacl) setfacl_seen=true ;;
    esac
  done
  [[ ${unique} == true && ${getfacl_seen} == true && ${setfacl_seen} == true ]] || return 0
  software_installer_source_inventory_matched=true
  software_installer_other_dependencies_present=true
  for program in "${commands[@]}"; do
    case "${program}" in getfacl|setfacl) continue ;; esac
    if ! command -v "${program}" >/dev/null 2>&1; then software_installer_other_dependencies_present=false; fi
  done
}
software_installer_dependency_inventory
software_installer_record_status

assert_binary_pair() {
  local directory=$1 version=$2 commit=$3 agent executor build_date
  agent="$("${directory}/autostream-host-agent" --version)"
  executor="$("${directory}/autostream-local-executor" --version)"
  [[ $(printf '%s\n' "${agent}" | wc -l) == 3 &&
    $(printf '%s\n' "${executor}" | wc -l) == 5 &&
    $(printf '%s\n' "${agent}" | sed -n '1p') == "autostream-host-agent ${version}" &&
    $(printf '%s\n' "${executor}" | sed -n '1p') == "autostream-local-executor ${version}" &&
    $(printf '%s\n' "${agent}" | sed -n '2p') == "commit: ${commit}" &&
    $(printf '%s\n' "${executor}" | sed -n '2p') == "commit: ${commit}" &&
    $(printf '%s\n' "${executor}" | sed -n '4p') == 'mutation_protocol: 2' &&
    $(printf '%s\n' "${executor}" | sed -n '5p') == 'recovery_protocol: 2' ]]
  build_date="$(printf '%s\n' "${agent}" | sed -n '3p')"
  [[ ${build_date} =~ ^build_date:\ [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ &&
    $(printf '%s\n' "${executor}" | sed -n '3p') == "${build_date}" ]]
}

assert_live_unit() {
  local unit=$1 expected=$2 pid
  [[ $(systemctl is-active "${unit}") == active &&
    $(systemctl is-enabled "${unit}") == enabled &&
    $(systemctl show "${unit}" --property=FragmentPath --value) == "/etc/systemd/system/${unit}" &&
    $(systemctl show "${unit}" --property=NeedDaemonReload --value) == no &&
    -z $(systemctl show "${unit}" --property=DropInPaths --value) ]]
  pid="$(systemctl show "${unit}" --property=MainPID --value)"
  [[ ${pid} =~ ^[1-9][0-9]*$ && $(readlink -f "/proc/${pid}/exe") == "${expected}" ]]
}

software_installer_enter_phase binary_pair
assert_binary_pair "${BEFORE_BINARIES}" "${BEFORE_VERSION}" "${BEFORE_COMMIT}"
assert_binary_pair "${CANDIDATE_BINARIES}" "${CANDIDATE_VERSION}" "${CANDIDATE_COMMIT}"
assert_binary_pair "${BASELINE_BINARIES}" "${CANDIDATE_VERSION}" "${BASELINE_COMMIT}"
software_installer_enter_phase compatibility_floor
MINIMUM_PANEL_VERSION="$(python3 "${REPOSITORY_ROOT}/scripts/ci/host_runtime_compatibility.py" \
  --root "${REPOSITORY_ROOT}" --source-version "${CANDIDATE_VERSION}")"
readonly MINIMUM_PANEL_VERSION
[[ ${MINIMUM_PANEL_VERSION} == v2.0.0 ]]

software_installer_enter_phase fixture_archive
readonly ARTIFACT_ID="autostream-host-agent_${CANDIDATE_VERSION}_linux_${ARCH}"
readonly FIXTURE_STAGE=/root/autostream-software-installer-candidate
readonly PACKAGE_ROOT="${FIXTURE_STAGE}/${ARTIFACT_ID}"
readonly ARCHIVE="${FIXTURE_STAGE}/${ARTIFACT_ID}.tar.gz"
[[ ! -e ${FIXTURE_STAGE} ]]
install -d -o root -g root -m 0700 "${FIXTURE_STAGE}"
install -d -o root -g root -m 0755 "${PACKAGE_ROOT}" \
  "${PACKAGE_ROOT}/bin" "${PACKAGE_ROOT}/install" "${PACKAGE_ROOT}/systemd"
for binary in autostream-host-agent autostream-local-executor; do
  install -o root -g root -m 0755 "${CANDIDATE_BINARIES}/${binary}" "${PACKAGE_ROOT}/bin/${binary}"
done
for installer in install-autostream-updater-agent uninstall-autostream-updater-agent \
  install-autostream-local-executor uninstall-autostream-local-executor; do
  destination=${installer/updater-agent/host-agent}
  install -o root -g root -m 0755 "${REPOSITORY_ROOT}/install/${installer}" \
    "${PACKAGE_ROOT}/install/${destination}"
done
for unit in autostream-local-executor.service autostream-local-executor.socket \
  autostream-local-executor.tmpfiles autostream-host-self-update-recovery@.service \
  autostream-host-self-update-recovery@.timer; do
  install -o root -g root -m 0644 "${REPOSITORY_ROOT}/systemd/${unit}.example" \
    "${PACKAGE_ROOT}/systemd/${unit}"
done
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-updater-agent.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-host-agent.service"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/install/autostream-local-executor-policy.json.example" \
  "${PACKAGE_ROOT}/autostream-local-executor-policy.json.example"
BUILD_DATE="$("${CANDIDATE_BINARIES}/autostream-host-agent" --version | sed -n 's/^build_date: //p')"
readonly BUILD_DATE
jq -n --arg version "${CANDIDATE_VERSION}" --arg commit "${CANDIDATE_COMMIT}" \
  --arg build_date "${BUILD_DATE}" --arg arch "${ARCH}" --arg root "${ARTIFACT_ID}" \
  --arg floor "${MINIMUM_PANEL_VERSION}" '{
    schema_version: 1, component: "host-agent", source_version: $version,
    commit: $commit, build_date: $build_date, platform: {os: "linux", arch: $arch},
    archive: {name: ($root + ".tar.gz"), root: $root},
    compatibility: {minimum_agent_version: null, minimum_panel_version: $floor,
      rollback_compatible: true, database_schema: "none"}
  }' > "${PACKAGE_ROOT}/artifact-manifest.json"
(
  cd "${PACKAGE_ROOT}"
  find . -type f ! -name checksums.txt -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > checksums.txt
)
tar --owner=0 --group=0 --numeric-owner -C "${FIXTURE_STAGE}" -czf "${ARCHIVE}" "${ARTIFACT_ID}"
(
  cd "${FIXTURE_STAGE}"
  sha256sum "${ARTIFACT_ID}.tar.gz" > "${ARTIFACT_ID}.tar.gz.sha256"
)

# A fresh synthetic baseline bundle, never a modified published archive.
readonly BASELINE_STAGE=/root/autostream-software-installer-baseline
readonly BASELINE_ROOT="${BASELINE_STAGE}/${ARTIFACT_ID}"
[[ ! -e ${BASELINE_STAGE} ]]
install -d -o root -g root -m 0700 "${BASELINE_STAGE}"
cp -a -- "${PACKAGE_ROOT}" "${BASELINE_ROOT}"
for binary in autostream-host-agent autostream-local-executor; do
  install -o root -g root -m 0755 "${BASELINE_BINARIES}/${binary}" "${BASELINE_ROOT}/bin/${binary}"
done
jq --arg commit "${BASELINE_COMMIT}" '.commit = $commit' "${PACKAGE_ROOT}/artifact-manifest.json" \
  > "${BASELINE_ROOT}/artifact-manifest.json"
(
  cd "${BASELINE_ROOT}"
  find . -type f ! -name checksums.txt -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > checksums.txt
)
tar --owner=0 --group=0 --numeric-owner -C "${BASELINE_STAGE}" -czf "${BASELINE_STAGE}/${ARTIFACT_ID}.tar.gz" "${ARTIFACT_ID}"
(
  cd "${BASELINE_STAGE}"
  sha256sum "${ARTIFACT_ID}.tar.gz" > "${ARTIFACT_ID}.tar.gz.sha256"
)

# Establish a legitimate already-configured managed pair from the reported
# old source, while retaining the real CP-generated identity, policy and state.
software_installer_enter_phase legacy_pair_install
install -d -o root -g root -m 0755 "${HOST_ROOT}" "${HOST_ROOT}/slots" "${HOST_ROOT}/slots/a" \
  "${HOST_ROOT}/slots/a/bin" "${HOST_ROOT}/slots/b" "${HOST_ROOT}/slots/b/bin" /usr/local/libexec
for binary in autostream-host-agent autostream-local-executor; do
  install -o root -g root -m 0755 "${BEFORE_BINARIES}/${binary}" "${HOST_ROOT}/slots/a/bin/${binary}"
  install -o root -g root -m 0755 "${BEFORE_BINARIES}/${binary}" "${HOST_ROOT}/slots/b/bin/${binary}"
done
ln -s slots/a "${HOST_ROOT}/current"
[[ ! -e /usr/local/bin/autostream-host-agent && ! -e /usr/local/libexec/autostream-local-executor ]]
ln -s "${HOST_ROOT}/current/bin/autostream-host-agent" /usr/local/bin/autostream-host-agent
ln -s "${HOST_ROOT}/current/bin/autostream-local-executor" /usr/local/libexec/autostream-local-executor
install -d -o root -g root -m 0700 "${STATE_ROOT}" /etc/autostream-local-executor \
  /etc/autostream-local-executor/docker /opt/autostream/local-executor /opt/autostream/local-executor/ports
install -d -o root -g root -m 0700 "${STATE_ROOT}/host-self-update"
jq -n '{schema_version: 2, recovery_protocol_version: 2, phase: "stable", active_slot: "a",
  healthy_slot: "a", active_agent_version: "v2.0.0", active_executor_version: "v2.0.0"}' \
  > "${STATE_ROOT}/host-self-update/state.json"
chmod 0600 "${STATE_ROOT}/host-self-update/state.json"
for unit in autostream-host-agent.service autostream-local-executor.service \
  autostream-local-executor.socket autostream-host-self-update-recovery@.service \
  autostream-host-self-update-recovery@.timer; do
  [[ ! -e /etc/systemd/system/${unit} ]]
  install -o root -g root -m 0644 "${PACKAGE_ROOT}/systemd/${unit}" "/etc/systemd/system/${unit}"
done
install -o root -g root -m 0644 "${PACKAGE_ROOT}/systemd/autostream-local-executor.tmpfiles" \
  /etc/tmpfiles.d/autostream-local-executor.conf
software_installer_enter_phase legacy_pair_start
systemd-tmpfiles --create /etc/tmpfiles.d/autostream-local-executor.conf
systemctl daemon-reload
systemctl enable --now autostream-host-self-update-recovery@a.timer autostream-host-self-update-recovery@b.timer \
  autostream-local-executor.socket autostream-local-executor.service autostream-host-agent.service
software_installer_enter_phase legacy_pair_probe
assert_live_unit autostream-host-agent.service "${HOST_ROOT}/slots/a/bin/autostream-host-agent"
assert_live_unit autostream-local-executor.service "${HOST_ROOT}/slots/a/bin/autostream-local-executor"
[[ $(/usr/local/libexec/autostream-local-executor inspect-host-update-recovery) == inactive ]]

# A small, fixture-only systemctl interposer injects starts at the first recovery
# query made by the real installer lock owner. It delegates every command to the
# real systemctl and leaves both actual periodic timers enabled and running.
# The query is read first, then both old fixed services start before it returns:
# this controls the old state/PID gap and the candidate property observation.
[[ ! -e /usr/bin/systemctl-ui183-real ]]
cp -- /usr/bin/systemctl /usr/bin/systemctl-ui183-real
cat > /usr/bin/systemctl <<'RACE_SYSTEMCTL'
#!/bin/bash
set -u
real=/usr/bin/systemctl-ui183-real
phase=$(cat /evidence/installer/ui183-phase 2>/dev/null || true)
unit=${!#}
if [[ ( ${phase} == before || ${phase} == after ) &&
  ( $1 == is-active || ( $1 == show && ${2:-} == --property=ActiveState ) ) &&
  ( ${unit} == autostream-host-self-update-recovery@a.service ||
    ${unit} == autostream-host-self-update-recovery@b.service ) &&
  ! -d /evidence/installer/ui183-${phase}.injected ]]; then
  output=$(${real} "$@")
  status=$?
  if python3 - "${PPID}" "${phase}" <<'OWNER'
import json, os, sys
from pathlib import Path
pid, phase = int(sys.argv[1]), sys.argv[2]
paths = ['/run/autostream-updater/.autostream-runtime-host-setup.lock',
         '/run/autostream-updater/.autostream-host-lifecycle.lock']
locks = []
for path in paths:
    stat = os.stat(path)
    records = [line.split() for line in Path('/proc/locks').read_text().splitlines()]
    wanted = f'{os.major(stat.st_dev):02x}:{os.minor(stat.st_dev):02x}:{stat.st_ino}'
    matches = [r for r in records if len(r) == 8 and r[1:4] == ['FLOCK','ADVISORY','WRITE']
               and r[4] == str(pid) and tuple(int(v, 16 if i < 2 else 10)
                   for i, v in enumerate(r[5].split(':'))) == (os.major(stat.st_dev), os.minor(stat.st_dev), stat.st_ino)]
    if len(matches) != 1: sys.exit(1)
    locks.append({'path': path, 'inode': stat.st_ino, 'owner_pid': pid})
with open(f'/evidence/installer/ui183-{phase}-locks.json', 'x') as out:
    json.dump({'locks': locks, 'actual_installer_owner': True}, out)
OWNER
  then
    mkdir "/evidence/installer/ui183-${phase}.injected" || exit 1
    for slot in a b; do
      ${real} start "autostream-host-self-update-recovery@${slot}.service" >/dev/null 2>&1
      started=$?
      [[ ${started} == 1 ]] || exit 1
      ${real} show "autostream-host-self-update-recovery@${slot}.service" \
        --property=ActiveState --property=SubState --property=MainPID --property=ControlPID \
        --property=Result --property=ExecMainStatus \
        > "/evidence/installer/ui183-${phase}-${slot}.properties" || exit 1
      invocation=$(${real} show "autostream-host-self-update-recovery@${slot}.service" --property=InvocationID --value)
      [[ ${invocation} =~ ^[0-9a-f]{32}$ ]] || exit 1
      lock_failure=0
      for _ in {1..10}; do
        lock_failure=$(journalctl --no-pager --output=cat "_SYSTEMD_INVOCATION_ID=${invocation}" \
          | grep -cF 'acquire host lifecycle recovery lock' || true)
        [[ ${lock_failure} == 1 ]] && break
        sleep 0.1
      done
      [[ ${lock_failure} == 1 ]] || exit 1
      printf '%s\n' "${lock_failure}" > "/evidence/installer/ui183-${phase}-${slot}.lock-failure"
    done
  fi
  printf '%s\n' "${output}"
  exit "${status}"
fi
exec "${real}" "$@"
RACE_SYSTEMCTL
chmod 0755 /usr/bin/systemctl

wait_legacy_recovery_quiescent() {
  local deadline=$((SECONDS + 30)) a b
  while (( SECONDS < deadline )); do
    a=$(systemctl show autostream-host-self-update-recovery@a.service --property=ActiveState --value)
    b=$(systemctl show autostream-host-self-update-recovery@b.service --property=ActiveState --value)
    if [[ ${a} == inactive && ${b} == inactive ]]; then return 0; fi
    sleep 0.1
  done
  return 1
}
software_installer_enter_phase baseline_overlap_refusal
wait_legacy_recovery_quiescent
readonly LEGACY_STATE_SHA256="$(sha256sum "${STATE_ROOT}/host-self-update/state.json" | awk '{print $1}')"
printf '%s\n' before > "${EVIDENCE_DIRECTORY}/ui183-phase"
baseline_status=0
software_installer_checkpoint=baseline_installer_command
"${BASELINE_ROOT}/install/install-autostream-host-agent" --upgrade \
  > "${EVIDENCE_DIRECTORY}/baseline-upgrade.log" 2>&1 || baseline_status=$?
software_installer_baseline_exit=${baseline_status}
software_installer_checkpoint=baseline_refusal_assertions
[[ ${baseline_status} == 1 && -d ${EVIDENCE_DIRECTORY}/ui183-before.injected ]]
grep -F 'autostream-host-self-update-recovery@a.service must be inactive and have no MainPID' \
  "${EVIDENCE_DIRECTORY}/baseline-upgrade.log" >/dev/null
[[ $(readlink "${HOST_ROOT}/current") == slots/a &&
  $(sha256sum "${STATE_ROOT}/host-self-update/state.json" | awk '{print $1}') == "${LEGACY_STATE_SHA256}" ]]
assert_live_unit autostream-host-agent.service "${HOST_ROOT}/slots/a/bin/autostream-host-agent"
assert_live_unit autostream-local-executor.service "${HOST_ROOT}/slots/a/bin/autostream-local-executor"
for slot in a b; do
  for binary in autostream-host-agent autostream-local-executor; do
    cmp "${BEFORE_BINARIES}/${binary}" "${HOST_ROOT}/slots/${slot}/bin/${binary}"
  done
done
wait_legacy_recovery_quiescent
printf '%s\n' after > "${EVIDENCE_DIRECTORY}/ui183-phase"

# No active-job bridge flag is permitted: the actual candidate root helper
# must accept all ordinary local journal/ledger/checkpoint/lifecycle guards.
software_installer_enter_phase normal_upgrade
software_installer_checkpoint=candidate_installer_command
"${PACKAGE_ROOT}/install/install-autostream-host-agent" --upgrade \
  > "${EVIDENCE_DIRECTORY}/normal-upgrade.log" 2>&1
software_installer_candidate_exit=$?
software_installer_checkpoint=candidate_command_returned
software_installer_checkpoint=after_injection_confirmation
[[ -d ${EVIDENCE_DIRECTORY}/ui183-after.injected ]]
software_installer_after_injection=true
software_installer_checkpoint=after_injection_phase_record
printf '%s\n' complete > "${EVIDENCE_DIRECTORY}/ui183-phase"
software_installer_checkpoint=race_result_assertions_output
python3 - "${EVIDENCE_DIRECTORY}" <<'RACE_RESULT'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
observations = {}
for phase in ('before', 'after'):
    owner = json.loads((root / f'ui183-{phase}-locks.json').read_text())
    units = {}
    for slot in ('a', 'b'):
        props = dict(line.split('=', 1) for line in (root / f'ui183-{phase}-{slot}.properties').read_text().splitlines())
        assert props == {'ActiveState':'failed', 'SubState':'failed', 'MainPID':'0',
                         'ControlPID':'0', 'Result':'exit-code', 'ExecMainStatus':'1'}, props
        assert (root / f'ui183-{phase}-{slot}.lock-failure').read_text().strip() == '1'
        units[slot] = {'properties': props, 'actual_lifecycle_lock_failure_events': 1}
    observations[phase] = {'lock_owner': owner, 'old_watchdogs': units,
                           'installer_exit': 1 if phase == 'before' else 0}
assert observations['before']['lock_owner']['locks'][1]['inode'] == observations['after']['lock_owner']['locks'][1]['inode']
with open('/evidence/artifacts/ui183-installer-watchdog.json', 'x') as out:
    json.dump({'schema_version':1, 'frozen_before_sha':'f72d1bddb712eeb64bab2b852b648c2c6b0f4641',
               'installed_pair_sha':'b1c94afe2ee2fe8854abb12e2c85565a1bd448dc', 'actual_systemd':True,
               'timer_stop_disable_mask':False, 'test_only_fixed_unit_start':True,
               'overlap':'installer_lock_owner_recovery_query', 'observations':observations}, out)
RACE_RESULT
software_installer_race_result=true
software_installer_checkpoint=recovery_timers_verification
for slot in a b; do
  [[ $(systemctl is-active "autostream-host-self-update-recovery@${slot}.timer") == active &&
    $(systemctl is-enabled "autostream-host-self-update-recovery@${slot}.timer") == enabled ]]
done
software_installer_timers=true
software_installer_enter_phase candidate_pair_verify
[[ $(readlink "${HOST_ROOT}/current") == slots/b ]]
assert_binary_pair "${HOST_ROOT}/slots/b/bin" "${CANDIDATE_VERSION}" "${CANDIDATE_COMMIT}"
assert_live_unit autostream-host-agent.service "${HOST_ROOT}/slots/b/bin/autostream-host-agent"
assert_live_unit autostream-local-executor.service "${HOST_ROOT}/slots/b/bin/autostream-local-executor"
cmp "${BEFORE_BINARIES}/autostream-host-agent" "${HOST_ROOT}/slots/a/bin/autostream-host-agent"
cmp "${BEFORE_BINARIES}/autostream-local-executor" "${HOST_ROOT}/slots/a/bin/autostream-local-executor"
software_installer_enter_phase identity_policy_preservation
[[ $(sha256sum "${IDENTITY}" | awk '{print $1}') == "${IDENTITY_SHA256}" &&
  $(stat -c '%d:%i:%u:%g:%a:%h' "${IDENTITY}") == "${IDENTITY_METADATA}" &&
  $(sha256sum "${POLICY}" | awk '{print $1}') == "${POLICY_SHA256}" &&
  $(stat -c '%d:%i:%u:%g:%a:%h' "${POLICY}") == "${POLICY_METADATA}" ]]
software_installer_enter_phase terminal_state_verify
jq -e --arg version "${CANDIDATE_VERSION}" '.phase == "stable" and
  .active_slot == "b" and .healthy_slot == "b" and .rollback_slot == "a" and
  .active_agent_version == $version and .active_executor_version == $version and
  .rollback_agent_version == "v2.0.0" and .rollback_executor_version == "v2.0.0" and
  (.pending_slot // "") == ""' "${STATE_ROOT}/host-self-update/state.json" >/dev/null
software_installer_enter_phase agent_stop
systemctl stop autostream-host-agent.service
[[ $(systemctl show autostream-host-agent.service --property=MainPID --value) == 0 &&
  $(systemctl show autostream-host-agent.service --property=ActiveState --value) == inactive &&
  $(systemctl is-active autostream-local-executor.socket) == active ]]
assert_live_unit autostream-local-executor.service "${HOST_ROOT}/slots/b/bin/autostream-local-executor"
software_installer_enter_phase result_record
jq -n --arg before "${BEFORE_COMMIT}" --arg candidate "${CANDIDATE_COMMIT}" \
  --arg identity "${IDENTITY_SHA256}" --arg policy "${POLICY_SHA256}" '{
    fixture: "software_update_normal_installer_order", before_version: "v2.0.0",
    candidate_fixture_version: "v2.0.1", before_commit: $before, candidate_commit: $candidate,
    published_release: false, minimum_panel_version: "v2.0.0", installer_mode: "--upgrade",
    actual_paired_binaries: true, actual_systemd: true, stable_active_slot: "b", rollback_slot: "a",
    identity_sha256: $identity, policy_sha256: $policy, identity_policy_preserved: true,
    local_guards_preserved: true, old_pair_preserved: true, agent_stopped_for_exact_recovery: true,
    local_executor_active: true, result: "PASS"
  }' > "${EVIDENCE_DIRECTORY}/result.json"
software_installer_enter_phase complete
printf '%s\n' 'software installer ordering: actual normal paired upgrade verified'
