#!/bin/bash
set -euo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

readonly AGENT_USER="autostream-host-agent"
readonly AGENT_GROUP="autostream-host-agent"
readonly AGENT_USER_ROLLBACK_LOGIN="autostream-ha-install-rollback"
readonly CONFIG_DIR="/etc/autostream/updater"
readonly CONFIG_DEST="${CONFIG_DIR}/agent.yaml"
readonly BINARY_DEST="/usr/local/bin/autostream-host-agent"
readonly UNIT_DEST="/etc/systemd/system/autostream-host-agent.service"
readonly STATE_DIR="/var/lib/autostream-host-agent"
readonly UNIT_NAME="autostream-host-agent.service"
readonly LOCAL_EXECUTOR_POLICY_DEST="${CONFIG_DIR}/executor-policy.json"
readonly LOCAL_EXECUTOR_DATA_DIR="/opt/autostream/local-executor"
readonly LOCAL_EXECUTOR_PORT_CONFIG_DIR="${LOCAL_EXECUTOR_DATA_DIR}/ports"
readonly LOCAL_EXECUTOR_BINARY_DEST="/usr/local/libexec/autostream-local-executor"
readonly LOCAL_EXECUTOR_SERVICE_DEST="/etc/systemd/system/autostream-local-executor.service"
readonly LOCAL_EXECUTOR_SOCKET_DEST="/etc/systemd/system/autostream-local-executor.socket"
readonly LOCAL_EXECUTOR_TMPFILES_DEST="/etc/tmpfiles.d/autostream-local-executor.conf"
readonly SELF_UPDATE_RECOVERY_SERVICE_DEST="/etc/systemd/system/autostream-host-self-update-recovery@.service"
readonly SELF_UPDATE_RECOVERY_TIMER_DEST="/etc/systemd/system/autostream-host-self-update-recovery@.timer"
readonly LOCAL_EXECUTOR_SERVICE_NAME="autostream-local-executor.service"
readonly LOCAL_EXECUTOR_SOCKET_NAME="autostream-local-executor.socket"
readonly SELF_UPDATE_RECOVERY_TIMER_A="autostream-host-self-update-recovery@a.timer"
readonly SELF_UPDATE_RECOVERY_TIMER_B="autostream-host-self-update-recovery@b.timer"
readonly SELF_UPDATE_RECOVERY_SERVICE_A="autostream-host-self-update-recovery@a.service"
readonly SELF_UPDATE_RECOVERY_SERVICE_B="autostream-host-self-update-recovery@b.service"
readonly SYSTEMCTL_PATH="/usr/bin/systemctl"
readonly SYSTEMD_RUN_PATH="/usr/bin/systemd-run"
readonly RUNUSER_PATH="/usr/sbin/runuser"
readonly ENV_PATH="/usr/bin/env"
readonly TEST_PATH="/usr/bin/test"
readonly ACTIVE_JOB_RECOVERY_GUARD_BASE="autostream-host-agent-upgrade-recovery-guard"
readonly ACTIVE_JOB_RECOVERY_GUARD_SERVICE="${ACTIVE_JOB_RECOVERY_GUARD_BASE}.service"
readonly ACTIVE_JOB_RECOVERY_GUARD_TIMER="${ACTIVE_JOB_RECOVERY_GUARD_BASE}.timer"
readonly ACTIVE_JOB_RECOVERY_GUARD_SERVICE_PATH="/run/systemd/transient/${ACTIVE_JOB_RECOVERY_GUARD_SERVICE}"
readonly ACTIVE_JOB_RECOVERY_GUARD_TIMER_PATH="/run/systemd/transient/${ACTIVE_JOB_RECOVERY_GUARD_TIMER}"
readonly ACTIVE_JOB_RECOVERY_CLEAR_MARKER="/var/lib/autostream-host-agent/journal.clear-active.pending.json"
readonly ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR="${UNIT_DEST}.d"
readonly ACTIVE_JOB_RECOVERY_CLEAR_FENCE="${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}/90-autostream-upgrade-recovery-guard.conf"
readonly ACTIVE_JOB_RECOVERY_GUARD_CANDIDATE_PREFIX="/run/autostream-host-agent-upgrade-guard."
# The one-shot recovery is capped at two minutes and the paired activation and
# rollback windows total at most seven more. Keep ample room for pre-fence
# validation and fsync work while still recovering an abruptly killed wrapper.
readonly ACTIVE_JOB_RECOVERY_GUARD_DELAY="25m"
readonly HOST_RUNTIME_ROOT="/opt/autostream/host-agent"
readonly HOST_RUNTIME_SLOTS="${HOST_RUNTIME_ROOT}/slots"
readonly HOST_RUNTIME_INITIAL_SLOT="${HOST_RUNTIME_SLOTS}/a"
readonly HOST_RUNTIME_CURRENT="${HOST_RUNTIME_ROOT}/current"
readonly HOST_RUNTIME_AGENT="${HOST_RUNTIME_INITIAL_SLOT}/bin/autostream-host-agent"
readonly HOST_RUNTIME_EXECUTOR="${HOST_RUNTIME_INITIAL_SLOT}/bin/autostream-local-executor"
readonly SHARED_HOST_SETUP_LOCK_DIR="/run/autostream-updater"
readonly SHARED_HOST_SETUP_LOCK="${SHARED_HOST_SETUP_LOCK_DIR}/.autostream-runtime-host-setup.lock"
readonly HOST_LIFECYCLE_LOCK="${SHARED_HOST_SETUP_LOCK_DIR}/.autostream-host-lifecycle.lock"
readonly ARTIFACT_MANIFEST_NAME="artifact-manifest.json"
readonly MAX_ARCHIVE_SIZE=268435456

usage() {
  cat >&2 <<'EOF'
Usage:
  install-autostream-host-agent --prepare
  install-autostream-host-agent --upgrade
  install-autostream-host-agent --upgrade --recover-active-job

--prepare installs the service account, Host Agent, and the same-release local
executor binary and units. It also prepares the root:root 0700 policy and port
configuration directories, but does not create either identity/policy, enable
the runtime units, or start either runtime service. It enables only the
root-owned A/B recovery timers. Complete the generated Control Panel configure
command before explicitly enabling the Host Agent and executor socket.

--upgrade verifies the adjacent Host Agent archive, then atomically upgrades
an existing healthy managed A/B Host Agent and Local Executor runtime together.
It preserves the installed identity and Local Executor policy.

--recover-active-job is accepted only with --upgrade. It uses the verified
candidate Host Agent once as the service account to reconcile the exact active
Host update journal before continuing the paired managed runtime upgrade.
EOF
}

die() {
  printf 'install-autostream-host-agent: %s\n' "$*" >&2
  exit 1
}

pending_cleanup_signal=""

defer_cleanup_signals() {
  trap 'pending_cleanup_signal=INT' INT
  trap 'pending_cleanup_signal=TERM' TERM
}

resume_cleanup_signals() {
  trap 'exit 130' INT
  trap 'exit 143' TERM
  local deferred_signal=${pending_cleanup_signal}
  pending_cleanup_signal=""
  case "${deferred_signal}" in
    "") return 0 ;;
    INT) return 130 ;;
    TERM) return 143 ;;
    *) return 1 ;;
  esac
}

arm_cleanup_handler() {
  local handler=$1
  trap "${handler}" EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

[[ ${EUID} -eq 0 ]] || die "must run as root"

install_mode=""
recover_active_job=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prepare)
      [[ -z ${install_mode} ]] || die "--prepare and --upgrade are mutually exclusive"
      install_mode="prepare"
      shift
      ;;
    --upgrade)
      [[ -z ${install_mode} ]] || die "--prepare and --upgrade are mutually exclusive"
      install_mode="upgrade"
      shift
      ;;
    --recover-active-job)
      [[ ${recover_active_job} == false ]] || die "--recover-active-job may be specified only once"
      recover_active_job=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown argument: $1"
      ;;
  esac
done
[[ -n ${install_mode} ]] || {
  usage
  die "--prepare or --upgrade is required"
}
[[ ${recover_active_job} == false || ${install_mode} == "upgrade" ]] || \
  die "--recover-active-job requires --upgrade"
for command in awk basename chmod chown dd dirname find flock getent getfacl groupadd groupdel id install jq ln mkdir mktemp mv readlink rm rmdir runuser setfacl sha256sum sort stat sync systemctl tar test tr uname uniq useradd userdel usermod; do
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
done
if [[ ${recover_active_job} == true ]]; then
  for command in sleep systemd-run; do
    command -v "${command}" >/dev/null 2>&1 || \
      die "required command is unavailable: ${command}"
  done
fi

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly RELEASE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
ARTIFACT_ID="$(basename -- "${RELEASE_ROOT}")" || die "could not resolve the Host Agent release directory name"
readonly ARTIFACT_ID
if [[ ! ${ARTIFACT_ID} =~ ^autostream-host-agent_(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?)_linux_(amd64|arm64)$ ]]; then
  die "the extracted Host Agent directory name is invalid: ${ARTIFACT_ID}"
fi
readonly VERSION="${BASH_REMATCH[1]}"
readonly ARCH="${BASH_REMATCH[4]}"
case "$(uname -m)" in
  x86_64) readonly HOST_ARCH="amd64" ;;
  aarch64|arm64) readonly HOST_ARCH="arm64" ;;
  *) die "unsupported host architecture: $(uname -m)" ;;
esac
[[ ${ARCH} == "${HOST_ARCH}" ]] || \
  die "artifact architecture ${ARCH} does not match host ${HOST_ARCH}"

ARTIFACT_PARENT="$(dirname -- "${RELEASE_ROOT}")" || die "could not resolve the release parent directory"
readonly ARTIFACT_PARENT
readonly ARCHIVE_NAME="${ARTIFACT_ID}.tar.gz"
readonly ARCHIVE_SOURCE="${ARTIFACT_PARENT}/${ARCHIVE_NAME}"
readonly RUNNING_INSTALLER_SOURCE="${SCRIPT_DIR}/install-autostream-host-agent"
readonly RUNNING_BINARY_SOURCE="${RELEASE_ROOT}/bin/autostream-host-agent"
readonly RUNNING_UNIT_SOURCE="${RELEASE_ROOT}/systemd/autostream-host-agent.service"
readonly RUNNING_LOCAL_EXECUTOR_POLICY_TEMPLATE="${RELEASE_ROOT}/autostream-local-executor-policy.json.example"
readonly RUNNING_LOCAL_EXECUTOR_BINARY_SOURCE="${RELEASE_ROOT}/bin/autostream-local-executor"
readonly RUNNING_LOCAL_EXECUTOR_SERVICE_SOURCE="${RELEASE_ROOT}/systemd/autostream-local-executor.service"
readonly RUNNING_LOCAL_EXECUTOR_SOCKET_SOURCE="${RELEASE_ROOT}/systemd/autostream-local-executor.socket"
readonly RUNNING_LOCAL_EXECUTOR_TMPFILES_SOURCE="${RELEASE_ROOT}/systemd/autostream-local-executor.tmpfiles"
readonly RUNNING_SELF_UPDATE_RECOVERY_SERVICE_SOURCE="${RELEASE_ROOT}/systemd/autostream-host-self-update-recovery@.service"
readonly RUNNING_SELF_UPDATE_RECOVERY_TIMER_SOURCE="${RELEASE_ROOT}/systemd/autostream-host-self-update-recovery@.timer"
