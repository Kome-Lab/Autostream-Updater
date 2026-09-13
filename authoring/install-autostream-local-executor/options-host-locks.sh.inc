#!/bin/bash
set -euo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

readonly AGENT_USER="autostream-host-agent"
readonly AGENT_GROUP="autostream-host-agent"
readonly CONFIG_DIR="/etc/autostream/updater"
readonly POLICY_DEST="${CONFIG_DIR}/executor-policy.json"
readonly EXECUTOR_CONFIG_DIR="/etc/autostream-local-executor"
readonly BINARY_DEST="/usr/local/libexec/autostream-local-executor"
readonly SERVICE_DEST="/etc/systemd/system/autostream-local-executor.service"
readonly SOCKET_DEST="/etc/systemd/system/autostream-local-executor.socket"
readonly TMPFILES_DEST="/etc/tmpfiles.d/autostream-local-executor.conf"
readonly SERVICE_NAME="autostream-local-executor.service"
readonly SOCKET_NAME="autostream-local-executor.socket"
readonly HOST_AGENT_SERVICE_NAME="autostream-host-agent.service"
readonly SOCKET_DIR="/run/autostream-local-executor"
readonly UPDATER_RUNTIME_DIR="/run/autostream-updater"
readonly SHARED_HOST_SETUP_LOCK="${UPDATER_RUNTIME_DIR}/.autostream-runtime-host-setup.lock"
readonly HOST_LIFECYCLE_LOCK="${UPDATER_RUNTIME_DIR}/.autostream-host-lifecycle.lock"
readonly STATE_DIR="/var/lib/autostream-local-executor"
readonly DOCKER_CONFIG_DIR="${EXECUTOR_CONFIG_DIR}/docker"
readonly DOCKER_CONFIG_FILE="${DOCKER_CONFIG_DIR}/config.json"
readonly EXECUTOR_DATA_DIR="/opt/autostream/local-executor"
readonly PORT_CONFIG_DIR="${EXECUTOR_DATA_DIR}/ports"
readonly DOCKER_VERSION_DIR="${EXECUTOR_DATA_DIR}/docker"
readonly DOCKER_PORT_CONFIG_DIR="${DOCKER_VERSION_DIR}/ports"
readonly HOST_RUNTIME_ROOT="/opt/autostream/host-agent"
readonly HOST_RUNTIME_CURRENT="${HOST_RUNTIME_ROOT}/current"
readonly ARTIFACT_MANIFEST_NAME="artifact-manifest.json"
readonly MAX_ARCHIVE_SIZE=268435456

usage() {
  printf '%s\n' "Usage: install-autostream-local-executor --policy PATH"
}

die() {
  printf 'install-autostream-local-executor: %s\n' "$*" >&2
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

validate_root_parent_chain() {
  local label=${2:-policy source}
  local current
  local parent
  local mode
  current=$(dirname -- "$1")
  while true; do
    [[ -d ${current} && ! -L ${current} ]] || die "${label} parents must be non-symlink directories"
    [[ $(stat -c '%U:%G' -- "${current}") == "root:root" ]] || \
      die "${label} parents must be owned by root:root"
    mode=$(stat -c '%a' -- "${current}")
    (( (8#${mode} & 0022) == 0 )) || \
      die "${label} parents must not be writable by group or other"
    parent=$(dirname -- "${current}")
    [[ ${parent} == "${current}" ]] && break
    current=${parent}
  done
}

acquire_shared_host_setup_lock() {
  local directory_identity
  local fd_identity
  local lock_created=false

  # The published lock path is permanent coordination state. Never unlink it:
  # doing so while another process holds the old inode would split the lock.
  validate_root_parent_chain "${UPDATER_RUNTIME_DIR}" "shared host-setup lock"
  if [[ -e ${UPDATER_RUNTIME_DIR} || -L ${UPDATER_RUNTIME_DIR} ]]; then
    [[ -d ${UPDATER_RUNTIME_DIR} &&
      ! -L ${UPDATER_RUNTIME_DIR} &&
      $(readlink -f -- "${UPDATER_RUNTIME_DIR}") == "${UPDATER_RUNTIME_DIR}" &&
      $(stat -c '%U:%G:%a' -- "${UPDATER_RUNTIME_DIR}") == "root:root:700" ]] || \
      die "shared host-setup lock directory is unsafe"
  else
    install -d -o root -g root -m 0700 "${UPDATER_RUNTIME_DIR}" || \
      die "could not create the shared host-setup lock directory"
    [[ -d ${UPDATER_RUNTIME_DIR} &&
      ! -L ${UPDATER_RUNTIME_DIR} &&
      $(readlink -f -- "${UPDATER_RUNTIME_DIR}") == "${UPDATER_RUNTIME_DIR}" &&
      $(stat -c '%U:%G:%a' -- "${UPDATER_RUNTIME_DIR}") == "root:root:700" ]] || \
      die "could not create a safe shared host-setup lock directory"
    sync -f /run
  fi
  validate_root_parent_chain "${SHARED_HOST_SETUP_LOCK}" "shared host-setup lock"
  directory_identity="$(stat -c '%d:%i' -- "${UPDATER_RUNTIME_DIR}")" || \
    die "could not record the shared host-setup lock directory identity"

  if [[ -e ${SHARED_HOST_SETUP_LOCK} || -L ${SHARED_HOST_SETUP_LOCK} ]]; then
    [[ -f ${SHARED_HOST_SETUP_LOCK} &&
      ! -L ${SHARED_HOST_SETUP_LOCK} &&
      $(readlink -f -- "${SHARED_HOST_SETUP_LOCK}") == "${SHARED_HOST_SETUP_LOCK}" &&
      $(stat -c '%U:%G:%a:%h' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600:1" ]] || \
      die "shared host-setup lock path is unsafe"
  else
    lock_created=true
  fi
  exec 8<>"${SHARED_HOST_SETUP_LOCK}" || die "could not open the shared host-setup lock"
  fd_identity="$(stat -Lc '%d:%i' -- /proc/self/fd/8)" || \
    die "could not record the shared host-setup lock identity"
  [[ $(stat -c '%d:%i' -- "${UPDATER_RUNTIME_DIR}") == "${directory_identity}" &&
    -f ${SHARED_HOST_SETUP_LOCK} &&
    ! -L ${SHARED_HOST_SETUP_LOCK} &&
    -f /proc/self/fd/8 &&
    $(stat -c '%U:%G:%a:%h' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/8) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}")" ]] || \
    die "shared host-setup lock identity changed while being opened"
  if [[ ${lock_created} == true ]]; then
    sync -f "${UPDATER_RUNTIME_DIR}"
  fi
  flock -n 8 || die "another AutoStream installer is provisioning shared host state"
  [[ $(stat -c '%d:%i' -- "${UPDATER_RUNTIME_DIR}") == "${directory_identity}" &&
    -f ${SHARED_HOST_SETUP_LOCK} &&
    ! -L ${SHARED_HOST_SETUP_LOCK} &&
    -f /proc/self/fd/8 &&
    $(stat -c '%U:%G:%a:%h' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/8) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}")" ]] || \
    die "shared host-setup lock identity changed after acquisition"
}

acquire_host_lifecycle_lock() {
  local directory_identity
  local fd_identity
  local lock_created=false

  validate_root_parent_chain "${HOST_LIFECYCLE_LOCK}" "Host lifecycle lock"
  [[ -d ${UPDATER_RUNTIME_DIR} &&
    ! -L ${UPDATER_RUNTIME_DIR} &&
    $(readlink -f -- "${UPDATER_RUNTIME_DIR}") == "${UPDATER_RUNTIME_DIR}" &&
    $(stat -c '%U:%G:%a' -- "${UPDATER_RUNTIME_DIR}") == "root:root:700" ]] || \
    die "Host lifecycle lock directory is unsafe"
  directory_identity="$(stat -c '%d:%i' -- "${UPDATER_RUNTIME_DIR}")" || \
    die "could not record the Host lifecycle lock directory identity"

  if [[ -e ${HOST_LIFECYCLE_LOCK} || -L ${HOST_LIFECYCLE_LOCK} ]]; then
    [[ -f ${HOST_LIFECYCLE_LOCK} &&
      ! -L ${HOST_LIFECYCLE_LOCK} &&
      $(readlink -f -- "${HOST_LIFECYCLE_LOCK}") == "${HOST_LIFECYCLE_LOCK}" &&
      $(stat -c '%U:%G:%a:%h' -- "${HOST_LIFECYCLE_LOCK}") == "root:root:600:1" ]] || \
      die "Host lifecycle lock path is unsafe"
  else
    lock_created=true
  fi
  exec 9<>"${HOST_LIFECYCLE_LOCK}" || die "could not open the Host lifecycle lock"
  fd_identity="$(stat -Lc '%d:%i' -- /proc/self/fd/9)" || \
    die "could not record the Host lifecycle lock identity"
  [[ $(stat -c '%d:%i' -- "${UPDATER_RUNTIME_DIR}") == "${directory_identity}" &&
    -f ${HOST_LIFECYCLE_LOCK} &&
    ! -L ${HOST_LIFECYCLE_LOCK} &&
    -f /proc/self/fd/9 &&
    $(stat -c '%U:%G:%a:%h' -- "${HOST_LIFECYCLE_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/9) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${HOST_LIFECYCLE_LOCK}")" ]] || \
    die "Host lifecycle lock identity changed while being opened"
  if [[ ${lock_created} == true ]]; then
    sync -f "${UPDATER_RUNTIME_DIR}"
  fi
  flock -n 9 || die "another privileged Host lifecycle operation is active"
  [[ $(stat -c '%d:%i' -- "${UPDATER_RUNTIME_DIR}") == "${directory_identity}" &&
    -f ${HOST_LIFECYCLE_LOCK} &&
    ! -L ${HOST_LIFECYCLE_LOCK} &&
    -f /proc/self/fd/9 &&
    $(stat -c '%U:%G:%a:%h' -- "${HOST_LIFECYCLE_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/9) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${HOST_LIFECYCLE_LOCK}")" ]] || \
    die "Host lifecycle lock identity changed after acquisition"
}

policy_source=
case "${1:-}" in
  --policy)
    [[ $# -eq 2 ]] || {
      usage >&2
      exit 1
    }
    policy_source=$2
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac

for command in awk basename chmod chown dirname find flock getent getfacl id install jq mkdir mktemp mv pwd readlink rm rmdir runuser setfacl sha256sum sort stat sync systemctl systemd-tmpfiles tar uname uniq; do
  command -v "${command}" >/dev/null 2>&1 || die "required command ${command} is unavailable"
done

[[ ${EUID} -eq 0 ]] || die "must run as root"
[[ ${policy_source} == /* ]] || die "--policy must be an absolute path"
[[ -f ${policy_source} && ! -L ${policy_source} ]] || die "policy source must be a regular non-symlink file"
validate_root_parent_chain "${policy_source}"
[[ $(stat -c '%U:%G:%a' -- "${policy_source}") == "root:root:600" ]] || \
  die "policy source must be root:root 0600"

readonly RELEASE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
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
readonly RUNNING_INSTALLER_SOURCE="${RELEASE_ROOT}/install/install-autostream-local-executor"
readonly RUNNING_HOST_BINARY_SOURCE="${RELEASE_ROOT}/bin/autostream-host-agent"
readonly RUNNING_BINARY_SOURCE="${RELEASE_ROOT}/bin/autostream-local-executor"
readonly RUNNING_SERVICE_SOURCE="${RELEASE_ROOT}/systemd/autostream-local-executor.service"
readonly RUNNING_SOCKET_SOURCE="${RELEASE_ROOT}/systemd/autostream-local-executor.socket"
readonly RUNNING_TMPFILES_SOURCE="${RELEASE_ROOT}/systemd/autostream-local-executor.tmpfiles"
