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
  software_installer_record_status
}
software_installer_on_error() {
  local status=$?
  software_installer_record_status "${status}"
  printf 'software installer ordering failed at phase %s (status %s)\n' "${software_installer_phase}" "${status}" >&2
  exit "${status}"
}
software_installer_on_exit() {
  local status=$?
  trap - EXIT ERR
  software_installer_record_status "${status}"
  exit "${status}"
}
trap software_installer_on_error ERR
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

# Establish a legitimate already-configured managed pair from the reported
# old source, while retaining the real CP-generated identity, policy and state.
software_installer_enter_phase legacy_pair_install
install -d -o root -g root -m 0755 "${HOST_ROOT}" "${HOST_ROOT}/slots" "${HOST_ROOT}/slots/a" \
  "${HOST_ROOT}/slots/a/bin" /usr/local/libexec
for binary in autostream-host-agent autostream-local-executor; do
  install -o root -g root -m 0755 "${BEFORE_BINARIES}/${binary}" "${HOST_ROOT}/slots/a/bin/${binary}"
done
ln -s slots/a "${HOST_ROOT}/current"
[[ ! -e /usr/local/bin/autostream-host-agent && ! -e /usr/local/libexec/autostream-local-executor ]]
ln -s "${HOST_ROOT}/current/bin/autostream-host-agent" /usr/local/bin/autostream-host-agent
ln -s "${HOST_ROOT}/current/bin/autostream-local-executor" /usr/local/libexec/autostream-local-executor
install -d -o root -g root -m 0700 "${STATE_ROOT}" /etc/autostream-local-executor \
  /etc/autostream-local-executor/docker /opt/autostream/local-executor /opt/autostream/local-executor/ports
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

# No active-job bridge flag is permitted: the actual candidate root helper
# must accept all ordinary local journal/ledger/checkpoint/lifecycle guards.
software_installer_enter_phase normal_upgrade
"${PACKAGE_ROOT}/install/install-autostream-host-agent" --upgrade \
  > "${EVIDENCE_DIRECTORY}/normal-upgrade.log" 2>&1
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
