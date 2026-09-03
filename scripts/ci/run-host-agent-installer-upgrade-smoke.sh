#!/bin/bash
set -Eeuo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
trap 'smoke_status=$?; printf "Host Agent upgrade smoke failed at line %s (status %s)\n" "${LINENO}" "${smoke_status}" >&2; exit "${smoke_status}"' ERR

[[ $(id -u) -eq 0 ]] || {
  printf '%s\n' 'host agent installer upgrade smoke requires root' >&2
  exit 1
}
[[ $# -eq 2 ]] || {
  printf '%s\n' \
    'usage: run-host-agent-installer-upgrade-smoke.sh REPOSITORY_ROOT RUNTIME_PROCESS_FIXTURE' >&2
  exit 1
}

readonly REPOSITORY_ROOT=$1
readonly RUNTIME_PROCESS_FIXTURE=$2
[[ -f ${RUNTIME_PROCESS_FIXTURE} && ! -L ${RUNTIME_PROCESS_FIXTURE} &&
  -x ${RUNTIME_PROCESS_FIXTURE} ]] || {
  printf '%s\n' 'managed runtime process fixture is missing or unsafe' >&2
  exit 1
}
readonly RUNTIME_PROCESS_FIXTURE_COPY=/root/autostream-host-runtime-process-fixture
readonly COMMAND_FIXTURE_DIR=/opt/autostream/host-agent-smoke-fixtures
readonly HOST_COMMAND_FIXTURE=/opt/autostream/host-agent-smoke-fixtures/autostream-host-agent-command
readonly EXECUTOR_COMMAND_FIXTURE=/opt/autostream/host-agent-smoke-fixtures/autostream-local-executor-command
export AUTOSTREAM_RUNTIME_FIXTURE_VERSION=v1.9.9
unset \
  AUTOSTREAM_RUNTIME_FIXTURE_AGENT_VERSION \
  AUTOSTREAM_RUNTIME_FIXTURE_EXECUTOR_VERSION \
  AUTOSTREAM_RUNTIME_FIXTURE_RECOVERY_PROTOCOL
readonly VERSION=v1.9.11
readonly BUILD_COMMIT=0123456789abcdef0123456789abcdef01234567
readonly BUILD_DATE=2026-07-31T00:00:00Z
case "$(uname -m)" in
  x86_64) readonly ARCH=amd64 ;;
  aarch64|arm64) readonly ARCH=arm64 ;;
  *)
    printf 'unsupported smoke architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac
readonly ARTIFACT_ID="autostream-host-agent_${VERSION}_linux_${ARCH}"
readonly PACKAGE_ROOT="/root/${ARTIFACT_ID}"
readonly ARCHIVE="/root/${ARTIFACT_ID}.tar.gz"
readonly INSTALLER="${PACKAGE_ROOT}/install/install-autostream-host-agent"
readonly HELPER_LOG=/root/autostream-host-agent-upgrade-helper.log
readonly HELPER_FAIL_MARKER=/root/autostream-host-agent-upgrade-helper.fail
readonly HELPER_FAIL_WITH_LOCK_MARKER=/root/autostream-host-agent-upgrade-helper.fail-with-lock
readonly HELPER_PARTIAL_SWITCH_MARKER=/root/autostream-host-agent-upgrade-helper.partial-switch
readonly HELPER_SIGNAL_MODE=/root/autostream-host-agent-upgrade-helper.signal-mode
readonly HELPER_SIGNAL_READY=/root/autostream-host-agent-upgrade-helper.signal-ready
readonly HELPER_SIGNAL_RECEIVED=/root/autostream-host-agent-upgrade-helper.signal-received
readonly HELPER_SIGNAL_FINISHED=/root/autostream-host-agent-upgrade-helper.signal-finished
readonly SIGNAL_OUTPUT=/root/autostream-host-agent-upgrade-signal-output.log
readonly SYSTEMCTL_LOG=/root/autostream-host-agent-upgrade-systemctl.log
readonly SYSTEMD_RUN_LOG=/root/autostream-host-agent-upgrade-systemd-run.log
readonly RECOVERY_STATE=/var/lib/autostream-host-agent/installer-recovery-state
readonly RECOVERY_LOG=/var/lib/autostream-host-agent/installer-recovery.log
readonly RECOVERY_ENV_LOG=/var/lib/autostream-host-agent/installer-recovery.env
readonly RECOVERY_FAIL_MARKER=/var/lib/autostream-host-agent/installer-recovery.fail
readonly RECOVERY_BLOCK_MARKER=/var/lib/autostream-host-agent/installer-recovery.block
readonly RECOVERY_BLOCK_READY=/var/lib/autostream-host-agent/installer-recovery.block-ready
readonly RECOVERY_SEQUENCE_LOG=/var/lib/autostream-host-agent/installer-recovery-sequence.log
readonly RECOVERY_EXECUTOR_TRIGGER=/var/lib/autostream-host-agent/installer-executor-trigger
readonly RECOVERY_EXECUTOR_RESPONSE=/var/lib/autostream-host-agent/installer-executor-response
readonly RECOVERY_EXECUTOR_RESPONSE_STAGE="${RECOVERY_EXECUTOR_RESPONSE}.new"
readonly RECOVERY_FAIL_WITH_LIFECYCLE_LOCK_MARKER=/var/lib/autostream-host-agent/installer-recovery.fail-with-lifecycle-lock
readonly RECOVERY_LIFECYCLE_HOLD_TRIGGER=/var/lib/autostream-host-agent/installer-lifecycle-hold-trigger
readonly RECOVERY_LIFECYCLE_HOLD_READY=/var/lib/autostream-host-agent/installer-lifecycle-hold-ready
readonly RECOVERY_LIFECYCLE_HOLD_RELEASE=/var/lib/autostream-host-agent/installer-lifecycle-hold-release
readonly RECOVERY_FULL_HOLD_TRIGGER=/var/lib/autostream-host-agent/installer-full-hold-trigger
readonly RECOVERY_FULL_HOLD_READY=/var/lib/autostream-host-agent/installer-full-hold-ready
readonly RECOVERY_FULL_HOLD_RELEASE=/var/lib/autostream-host-agent/installer-full-hold-release
readonly SERVICE_PID_FILE=/root/autostream-host-agent-upgrade-service.pid
readonly EXECUTOR_PID_FILE=/root/autostream-local-executor-upgrade-service.pid
readonly GUARD_LOADED_MARKER=/root/autostream-host-agent-upgrade-guard.loaded
readonly GUARD_TIMER_ACTIVE_MARKER=/root/autostream-host-agent-upgrade-guard.timer-active
readonly GUARD_FIRE_TRIGGER=/root/autostream-host-agent-upgrade-guard.fire
readonly GUARD_FIRE_STATUS=/root/autostream-host-agent-upgrade-guard.fire-status
readonly GUARD_WORKER_PID_FILE=/root/autostream-host-agent-upgrade-guard.worker-pid
readonly GUARD_SELF_FIRE_OUTPUT=/root/autostream-host-agent-upgrade-guard-self-fire.log
readonly SYSTEMCTL_BACKUP=/root/autostream-host-agent-upgrade-systemctl.original
readonly SYSTEMD_RUN_BACKUP=/root/autostream-host-agent-upgrade-systemd-run.original
readonly MANAGED_RUNTIME_ROOT=/opt/autostream/host-agent
readonly MANAGED_RUNTIME_AGENT=/opt/autostream/host-agent/slots/a/bin/autostream-host-agent
readonly MANAGED_RUNTIME_EXECUTOR=/opt/autostream/host-agent/slots/a/bin/autostream-local-executor
readonly MANAGED_RUNTIME_CURRENT=/opt/autostream/host-agent/current
readonly PUBLIC_AGENT=/usr/local/bin/autostream-host-agent
readonly PUBLIC_EXECUTOR=/usr/local/libexec/autostream-local-executor
readonly RECOVERY_GUARD_SERVICE_PATH=/run/systemd/transient/autostream-host-agent-upgrade-recovery-guard.service
readonly RECOVERY_GUARD_TIMER_PATH=/run/systemd/transient/autostream-host-agent-upgrade-recovery-guard.timer
readonly RECOVERY_CLEAR_MARKER=/var/lib/autostream-host-agent/journal.clear-active.pending.json
readonly RECOVERY_CLEAR_FENCE_DIR=/etc/systemd/system/autostream-host-agent.service.d
readonly RECOVERY_CLEAR_FENCE=/etc/systemd/system/autostream-host-agent.service.d/90-autostream-upgrade-recovery-guard.conf
readonly RECOVERY_LIFECYCLE_LOCK=/run/autostream-updater/.autostream-host-lifecycle.lock
readonly RECOVERY_SETUP_LOCK=/run/autostream-updater/.autostream-runtime-host-setup.lock
readonly ARCHIVE_BACKUP="/root/.${ARTIFACT_ID}.valid.tar.gz"
readonly HOST_BINARY_BACKUP=/root/.autostream-host-agent-upgrade-smoke.valid
readonly IDENTITY_PATH=/etc/autostream/updater/agent.yaml
readonly POLICY_PATH=/etc/autostream/updater/executor-policy.json
readonly COMPLETION='Managed Host Agent and Local Executor runtime upgrade complete.'

for path in \
  "${PACKAGE_ROOT}" \
  "${ARCHIVE}" \
  "${ARCHIVE_BACKUP}" \
  "${HOST_BINARY_BACKUP}" \
  "${RUNTIME_PROCESS_FIXTURE_COPY}" \
  "${COMMAND_FIXTURE_DIR}" \
  "${HELPER_LOG}" \
  "${HELPER_FAIL_MARKER}" \
  "${HELPER_FAIL_WITH_LOCK_MARKER}" \
  "${HELPER_PARTIAL_SWITCH_MARKER}" \
  "${HELPER_SIGNAL_MODE}" \
  "${HELPER_SIGNAL_READY}" \
  "${HELPER_SIGNAL_RECEIVED}" \
  "${HELPER_SIGNAL_FINISHED}" \
  "${SIGNAL_OUTPUT}" \
  "${SYSTEMCTL_LOG}" \
  "${SYSTEMD_RUN_LOG}" \
  "${RECOVERY_EXECUTOR_RESPONSE_STAGE}" \
  "${SERVICE_PID_FILE}" \
  "${EXECUTOR_PID_FILE}" \
  "${GUARD_LOADED_MARKER}" \
  "${GUARD_TIMER_ACTIVE_MARKER}" \
  "${GUARD_FIRE_TRIGGER}" \
  "${GUARD_FIRE_STATUS}" \
  "${GUARD_WORKER_PID_FILE}" \
  "${GUARD_SELF_FIRE_OUTPUT}" \
  "${SYSTEMCTL_BACKUP}" \
  "${SYSTEMD_RUN_BACKUP}" \
  "${MANAGED_RUNTIME_ROOT}" \
  "${PUBLIC_AGENT}" \
  "${PUBLIC_EXECUTOR}" \
  "${RECOVERY_GUARD_SERVICE_PATH}" \
  "${RECOVERY_GUARD_TIMER_PATH}" \
  "${RECOVERY_CLEAR_FENCE_DIR}" \
  /etc/autostream/updater \
  /etc/autostream-local-executor \
  /var/lib/autostream-host-agent; do
  [[ ! -e ${path} && ! -L ${path} ]] || {
    printf 'upgrade smoke requires an isolated container; path already exists: %s\n' \
      "${path}" >&2
    exit 1
  }
done

install -d -o root -g root -m 0755 \
  "${PACKAGE_ROOT}/bin" \
  "${PACKAGE_ROOT}/install" \
  "${PACKAGE_ROOT}/systemd" \
  "${COMMAND_FIXTURE_DIR}"
install -o root -g root -m 0755 \
  "${REPOSITORY_ROOT}/release/install-autostream-host-agent" \
  "${INSTALLER}"
install -o root -g root -m 0755 \
  "${REPOSITORY_ROOT}/release/uninstall-autostream-host-agent" \
  "${PACKAGE_ROOT}/install/uninstall-autostream-host-agent"
install -o root -g root -m 0755 \
  "${REPOSITORY_ROOT}/release/install-autostream-local-executor" \
  "${PACKAGE_ROOT}/install/install-autostream-local-executor"
install -o root -g root -m 0755 \
  "${REPOSITORY_ROOT}/release/uninstall-autostream-local-executor" \
  "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/release/autostream-local-executor-policy.json.example" \
  "${PACKAGE_ROOT}/autostream-local-executor-policy.json.example"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-host-agent.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-host-agent.service"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.service"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.socket.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.socket"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.tmpfiles.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.tmpfiles"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-host-self-update-recovery@.service"
install -o root -g root -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.timer.example" \
  "${PACKAGE_ROOT}/systemd/autostream-host-self-update-recovery@.timer"

fake_host_agent=$(mktemp)
cat > "${fake_host_agent}" <<'EOF'
#!/bin/bash
set -euo pipefail
readonly RECOVERY_STATE=/var/lib/autostream-host-agent/installer-recovery-state
readonly RECOVERY_LOG=/var/lib/autostream-host-agent/installer-recovery.log
readonly RECOVERY_ENV_LOG=/var/lib/autostream-host-agent/installer-recovery.env
readonly RECOVERY_FAIL_MARKER=/var/lib/autostream-host-agent/installer-recovery.fail
readonly RECOVERY_BLOCK_MARKER=/var/lib/autostream-host-agent/installer-recovery.block
readonly RECOVERY_BLOCK_READY=/var/lib/autostream-host-agent/installer-recovery.block-ready
readonly RECOVERY_SEQUENCE_LOG=/var/lib/autostream-host-agent/installer-recovery-sequence.log
readonly RECOVERY_EXECUTOR_TRIGGER=/var/lib/autostream-host-agent/installer-executor-trigger
readonly RECOVERY_EXECUTOR_RESPONSE=/var/lib/autostream-host-agent/installer-executor-response
readonly RECOVERY_EXECUTOR_RESPONSE_STAGE="${RECOVERY_EXECUTOR_RESPONSE}.new"
readonly RECOVERY_FAIL_WITH_LIFECYCLE_LOCK_MARKER=/var/lib/autostream-host-agent/installer-recovery.fail-with-lifecycle-lock
readonly RECOVERY_LIFECYCLE_HOLD_TRIGGER=/var/lib/autostream-host-agent/installer-lifecycle-hold-trigger
readonly RECOVERY_LIFECYCLE_HOLD_READY=/var/lib/autostream-host-agent/installer-lifecycle-hold-ready
fixture_executable=${AUTOSTREAM_FIXTURE_EXECUTABLE:-$0}
unset AUTOSTREAM_FIXTURE_EXECUTABLE
case "${1:-}" in
  --version)
    [[ $# -eq 1 ]] || exit 90
    printf '%s\n' \
      'autostream-host-agent v1.9.11' \
      'commit: 0123456789abcdef0123456789abcdef01234567' \
      'build_date: 2026-07-31T00:00:00Z'
    ;;
  recover-update)
    [[ $# -eq 3 &&
      ${2:-} == --config &&
      ${3:-} == /etc/autostream/updater/agent.yaml &&
      $(id -u) -ne 0 &&
      $(id -un) == autostream-host-agent &&
      $(<"${RECOVERY_STATE}") == active ]] || exit 91
    [[ ${HOME:-} == /nonexistent &&
      ${PATH:-} == /usr/sbin:/usr/bin:/sbin:/bin &&
      ${LC_ALL:-} == C ]] || exit 93
    for forbidden_variable in \
      HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
      http_proxy https_proxy all_proxy no_proxy \
      SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE REQUESTS_CA_BUNDLE \
      AUTOSTREAM_RUNTIME_TOKEN AUTOSTREAM_CONFIGURE_TOKEN \
      AUTOSTREAM_RUNTIME_FIXTURE_VERSION \
      AUTOSTREAM_RUNTIME_FIXTURE_AGENT_VERSION \
      AUTOSTREAM_RUNTIME_FIXTURE_EXECUTOR_VERSION \
      AUTOSTREAM_RUNTIME_FIXTURE_RECOVERY_PROTOCOL; do
      [[ -z ${!forbidden_variable+x} ]] || exit 94
    done
    /usr/bin/env | LC_ALL=C sort > "${RECOVERY_ENV_LOG}"
    chmod 0600 "${RECOVERY_ENV_LOG}"
    {
      printf 'uid=%s\n' "$(id -u)"
      printf 'argv=%s\n' "$*"
      printf 'executable=%s\n' "${fixture_executable}"
    } > "${RECOVERY_LOG}"
    chmod 0600 "${RECOVERY_LOG}"
    printf '%s\n' 'recover-agent' >> "${RECOVERY_SEQUENCE_LOG}"
    if [[ -f ${RECOVERY_BLOCK_MARKER} && ! -L ${RECOVERY_BLOCK_MARKER} ]]; then
      printf '%s\n' "$$" > "${RECOVERY_BLOCK_READY}"
      chmod 0600 "${RECOVERY_BLOCK_READY}"
      trap 'exit 74' INT TERM
      while [[ -f ${RECOVERY_BLOCK_MARKER} && ! -L ${RECOVERY_BLOCK_MARKER} ]]; do
        sleep 0.05
      done
      exit 74
    fi
    if [[ -f ${RECOVERY_FAIL_WITH_LIFECYCLE_LOCK_MARKER} &&
      ! -L ${RECOVERY_FAIL_WITH_LIFECYCLE_LOCK_MARKER} ]]; then
      : > "${RECOVERY_LIFECYCLE_HOLD_TRIGGER}"
      chmod 0600 "${RECOVERY_LIFECYCLE_HOLD_TRIGGER}"
      for ((attempt = 0; attempt < 200; attempt++)); do
        [[ -f ${RECOVERY_LIFECYCLE_HOLD_READY} &&
          ! -L ${RECOVERY_LIFECYCLE_HOLD_READY} ]] && exit 74
        sleep 0.01
      done
      exit 79
    fi
    [[ ! -e ${RECOVERY_FAIL_MARKER} ]] || exit 74
    rm -f -- "${RECOVERY_EXECUTOR_RESPONSE}"
    : > "${RECOVERY_EXECUTOR_TRIGGER}"
    chmod 0600 "${RECOVERY_EXECUTOR_TRIGGER}"
    for ((attempt = 0; attempt < 200; attempt++)); do
      if [[ -f ${RECOVERY_EXECUTOR_RESPONSE} &&
        ! -L ${RECOVERY_EXECUTOR_RESPONSE} ]]; then
        response="$(<"${RECOVERY_EXECUTOR_RESPONSE}")"
        case "${response}" in
          acquired) break ;;
          target_busy) exit 76 ;;
          *) exit 77 ;;
        esac
      fi
      sleep 0.01
    done
    [[ -f ${RECOVERY_EXECUTOR_RESPONSE} &&
      ! -L ${RECOVERY_EXECUTOR_RESPONSE} &&
      $(<"${RECOVERY_EXECUTOR_RESPONSE}") == acquired &&
      $(<"${RECOVERY_STATE}") == inactive ]] || exit 78
    ;;
  *)
    printf 'unexpected Host Agent invocation: %s\n' "$*" >&2
    exit 92
    ;;
esac
EOF
install -o root -g root -m 0755 \
  "${fake_host_agent}" \
  "${PACKAGE_ROOT}/bin/autostream-host-agent"
install -o root -g root -m 0755 \
  "${fake_host_agent}" "${HOST_COMMAND_FIXTURE}"
rm -f -- "${fake_host_agent}"

fake_local_executor=$(mktemp)
cat > "${fake_local_executor}" <<'EOF'
#!/bin/bash
set -euo pipefail
readonly RUNTIME_PROCESS_FIXTURE_COPY=/root/autostream-host-runtime-process-fixture
readonly HELPER_LOG=/root/autostream-host-agent-upgrade-helper.log
readonly HELPER_FAIL_MARKER=/root/autostream-host-agent-upgrade-helper.fail
readonly HELPER_FAIL_WITH_LOCK_MARKER=/root/autostream-host-agent-upgrade-helper.fail-with-lock
readonly HELPER_PARTIAL_SWITCH_MARKER=/root/autostream-host-agent-upgrade-helper.partial-switch
readonly HELPER_SIGNAL_MODE=/root/autostream-host-agent-upgrade-helper.signal-mode
readonly HELPER_SIGNAL_READY=/root/autostream-host-agent-upgrade-helper.signal-ready
readonly HELPER_SIGNAL_RECEIVED=/root/autostream-host-agent-upgrade-helper.signal-received
readonly HELPER_SIGNAL_FINISHED=/root/autostream-host-agent-upgrade-helper.signal-finished
readonly RECOVERY_STATE=/var/lib/autostream-host-agent/installer-recovery-state
readonly RECOVERY_SEQUENCE_LOG=/var/lib/autostream-host-agent/installer-recovery-sequence.log
readonly RECOVERY_FULL_HOLD_TRIGGER=/var/lib/autostream-host-agent/installer-full-hold-trigger
readonly RECOVERY_FULL_HOLD_READY=/var/lib/autostream-host-agent/installer-full-hold-ready
readonly RECOVERY_CLEAR_MARKER=/var/lib/autostream-host-agent/journal.clear-active.pending.json
readonly RECOVERY_CLEAR_FENCE_DIR=/etc/systemd/system/autostream-host-agent.service.d
readonly RECOVERY_CLEAR_FENCE=/etc/systemd/system/autostream-host-agent.service.d/90-autostream-upgrade-recovery-guard.conf
readonly MANAGED_RUNTIME_CURRENT=/opt/autostream/host-agent/current
readonly PUBLIC_AGENT=/usr/local/bin/autostream-host-agent
readonly PUBLIC_EXECUTOR=/usr/local/libexec/autostream-local-executor
fixture_executable=${AUTOSTREAM_FIXTURE_EXECUTABLE:-$0}
unset AUTOSTREAM_FIXTURE_EXECUTABLE
case "${1:-}" in
  --version)
    printf '%s\n' \
      'autostream-local-executor v1.9.11' \
      'commit: 0123456789abcdef0123456789abcdef01234567' \
      'build_date: 2026-07-31T00:00:00Z' \
      'mutation_protocol: 2' \
      'recovery_protocol: 2'
    ;;
  manual-upgrade-host-runtime)
    [[ ($# -eq 7 || $# -eq 8) &&
      ${2:-} == --artifact-root && -n ${3:-} &&
      ${4:-} == --archive-sha256 && -n ${5:-} &&
      ${6:-} == --archive-size && ${7:-} =~ ^[1-9][0-9]*$ &&
      ($# -eq 7 || ${8:-} == --agent-stopped-for-recovery) ]] || {
      printf 'unexpected manual upgrade invocation: %s\n' "$*" >&2
      exit 92
    }
    [[ $(stat -c '%U:%G:%a:%h' -- \
      "${3}/systemd/autostream-host-self-update-recovery@.service") == \
      root:root:644:1 ]] || {
      printf '%s\n' \
        'candidate Host recovery service was not normalized to root:root 0644 nlink 1' >&2
      exit 95
    }
    {
      printf 'artifact-root=%s\n' "$3"
      printf 'archive-sha256=%s\n' "$5"
      printf 'archive-size=%s\n' "$7"
      if [[ ${8:-} == --agent-stopped-for-recovery ]]; then
        printf '%s\n' 'agent-stopped-for-recovery=true'
        printf '%s\n' 'manual-upgrade' >> "${RECOVERY_SEQUENCE_LOG}"
      fi
    } > "${HELPER_LOG}"
    chmod 0600 "${HELPER_LOG}"
    if [[ -f ${HELPER_PARTIAL_SWITCH_MARKER} &&
      ! -L ${HELPER_PARTIAL_SWITCH_MARKER} ]]; then
      install -d -o root -g root -m 0755 \
        /opt/autostream/host-agent/slots/b/bin
      ln -sfnT slots/b /opt/autostream/host-agent/current
      exit 73
    fi
    if [[ -f ${HELPER_FAIL_WITH_LOCK_MARKER} &&
      ! -L ${HELPER_FAIL_WITH_LOCK_MARKER} ]]; then
      : > "${RECOVERY_FULL_HOLD_TRIGGER}"
      chmod 0600 "${RECOVERY_FULL_HOLD_TRIGGER}"
      for ((attempt = 0; attempt < 200; attempt++)); do
        [[ -f ${RECOVERY_FULL_HOLD_READY} &&
          ! -L ${RECOVERY_FULL_HOLD_READY} ]] && exit 73
        sleep 0.01
      done
      exit 79
    fi
    [[ ! -e ${HELPER_FAIL_MARKER} ]] || exit 73
    if [[ -f ${HELPER_SIGNAL_MODE} && ! -L ${HELPER_SIGNAL_MODE} ]]; then
      signal_mode="$(<"${HELPER_SIGNAL_MODE}")"
      [[ ${signal_mode} == success || ${signal_mode} == failure ]] || exit 94
      finish_after_forwarded_signal() {
        local signal=$1
        printf '%s\n' "${signal}" > "${HELPER_SIGNAL_RECEIVED}"
        chmod 0600 "${HELPER_SIGNAL_RECEIVED}"
        sleep 1
        printf '%s\n' "${signal}" > "${HELPER_SIGNAL_FINISHED}"
        chmod 0600 "${HELPER_SIGNAL_FINISHED}"
        if [[ ${signal_mode} == success ]]; then
          exit 0
        fi
        exit 75
      }
      trap 'finish_after_forwarded_signal INT' INT
      trap 'finish_after_forwarded_signal TERM' TERM
      printf '%s\n' "$$" > "${HELPER_SIGNAL_READY}"
      chmod 0600 "${HELPER_SIGNAL_READY}"
      while true; do
        sleep 1
      done
    fi
    if [[ ${8:-} == --agent-stopped-for-recovery ]]; then
      [[ $(<"${RECOVERY_STATE}") == inactive ]] || exit 96
      install -d -o root -g root -m 0755 \
        /opt/autostream/host-agent/slots/b/bin
      install -o root -g root -m 0755 \
        "${RUNTIME_PROCESS_FIXTURE_COPY}" \
        /opt/autostream/host-agent/slots/b/bin/autostream-host-agent
      install -o root -g root -m 0755 \
        "${RUNTIME_PROCESS_FIXTURE_COPY}" \
        /opt/autostream/host-agent/slots/b/bin/autostream-local-executor
      ln -sfnT slots/b /opt/autostream/host-agent/current
      /usr/bin/systemctl restart autostream-local-executor.service
      /usr/bin/systemctl start autostream-host-agent.service
    fi
    ;;
  inspect-host-update-recovery)
    [[ $# -eq 1 && -f ${RECOVERY_STATE} && ! -L ${RECOVERY_STATE} ]] || exit 97
    state="$(<"${RECOVERY_STATE}")"
    [[ ${state} == active || ${state} == inactive ]] || exit 98
    printf '%s\n' "${state}"
    ;;
  guard-restart-host-agent)
    [[ $# -eq 7 &&
      ${2:-} == --expected-slot && (${3:-} == a || ${3:-} == b) &&
      ${4:-} == --agent-sha256 && ${5:-} =~ ^[0-9a-f]{64}$ &&
      ${6:-} == --executor-sha256 && ${7:-} =~ ^[0-9a-f]{64}$ ]] || {
      printf 'unexpected Host recovery guard invocation: %s\n' "$*" >&2
      exit 99
    }
    selected_root="/opt/autostream/host-agent/slots/${3}/bin"
    selected_agent="${selected_root}/autostream-host-agent"
    selected_executor="${selected_root}/autostream-local-executor"
    expected_fence="$(printf '%s\n' \
      '[Unit]' \
      "ConditionPathExists=!${RECOVERY_CLEAR_MARKER}" \
      "ConditionFileIsExecutable=${fixture_executable}")"
    [[ ${fixture_executable} == /run/autostream-host-agent-upgrade-guard.*/autostream-local-executor &&
      -f ${fixture_executable} && ! -L ${fixture_executable} &&
      $(stat -c '%U:%G:%a:%h' -- "${fixture_executable}") == root:root:700:1 &&
      $(readlink -- "${MANAGED_RUNTIME_CURRENT}") == "slots/${3}" &&
      $(stat -c '%U:%G:%a:%h' -- "${selected_agent}") == root:root:755:1 &&
      $(stat -c '%U:%G:%a:%h' -- "${selected_executor}") == root:root:755:1 &&
      $(sha256sum -- "${selected_agent}" | awk 'NR == 1 { print $1 }') == "${5}" &&
      $(sha256sum -- "${selected_executor}" | awk 'NR == 1 { print $1 }') == "${7}" &&
      $(readlink -f -- "${PUBLIC_AGENT}") == "${selected_agent}" &&
      $(readlink -f -- "${PUBLIC_EXECUTOR}") == "${selected_executor}" &&
      -f ${RECOVERY_STATE} && ! -L ${RECOVERY_STATE} &&
      $(<"${RECOVERY_STATE}") == active &&
      ! -e ${RECOVERY_CLEAR_MARKER} && ! -L ${RECOVERY_CLEAR_MARKER} &&
      -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
      $(stat -c '%U:%G:%a:%h' -- "${RECOVERY_CLEAR_FENCE}") == root:root:644:1 &&
      $(<"${RECOVERY_CLEAR_FENCE}") == "${expected_fence}" &&
      $(/usr/bin/systemctl show autostream-host-agent.service \
        --property=ActiveState --value) == inactive &&
      $(/usr/bin/systemctl show autostream-host-agent.service \
        --property=MainPID --value) == 0 &&
      $(/usr/bin/systemctl is-active autostream-local-executor.service) == active ]] || {
      printf '%s\n' 'Host recovery guard fixture rejected unsafe runtime state' >&2
      exit 100
    }
    executor_pid="$(/usr/bin/systemctl show autostream-local-executor.service \
      --property=MainPID --value)"
    [[ ${executor_pid} =~ ^[1-9][0-9]*$ &&
      $(readlink -f -- "/proc/${executor_pid}/exe") == "${selected_executor}" ]] || exit 101
    printf '%s\n' guard-helper >> "${RECOVERY_SEQUENCE_LOG}"
    /usr/bin/systemctl start autostream-host-agent.service
    [[ $(/usr/bin/systemctl is-active autostream-host-agent.service) == active ]] || exit 102
    rm -f -- "${RECOVERY_CLEAR_FENCE}"
    sync -f "${RECOVERY_CLEAR_FENCE_DIR}"
    /usr/bin/systemctl daemon-reload
    [[ $(/usr/bin/systemctl show autostream-host-agent.service \
      --property=NeedDaemonReload --value) == no &&
      -z $(/usr/bin/systemctl show autostream-host-agent.service \
        --property=DropInPaths --value) ]] || exit 103
    ;;
  *)
    printf 'unexpected Local Executor invocation: %s\n' "$*" >&2
    exit 93
    ;;
esac
EOF
install -o root -g root -m 0755 \
  "${fake_local_executor}" \
  "${PACKAGE_ROOT}/bin/autostream-local-executor"
install -o root -g root -m 0755 \
  "${fake_local_executor}" "${EXECUTOR_COMMAND_FIXTURE}"
rm -f -- "${fake_local_executor}"

install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" \
  "${PACKAGE_ROOT}/bin/autostream-host-agent"
install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" \
  "${PACKAGE_ROOT}/bin/autostream-local-executor"

cat > "${PACKAGE_ROOT}/artifact-manifest.json" <<EOF
{
  "schema_version": 1,
  "component": "host-agent",
  "source_version": "${VERSION}",
  "commit": "${BUILD_COMMIT}",
  "build_date": "${BUILD_DATE}",
  "platform": {
    "os": "linux",
    "arch": "${ARCH}"
  },
  "archive": {
    "name": "${ARTIFACT_ID}.tar.gz",
    "root": "${ARTIFACT_ID}"
  },
  "compatibility": {
    "minimum_agent_version": null,
    "minimum_panel_version": "${VERSION}",
    "rollback_compatible": true,
    "database_schema": "none"
  }
}
EOF

rebuild_bundle_archive() {
  rm -f -- "${PACKAGE_ROOT}/checksums.txt" "${ARCHIVE}"
  (
    cd -- "${PACKAGE_ROOT}"
    find . -type f ! -path './checksums.txt' -print0 |
      sort -z |
      xargs -0 sha256sum > checksums.txt
  )
  tar -C /root -czf "${ARCHIVE}" "${ARTIFACT_ID}"
}

private_stage_listing() {
  find /var/tmp -mindepth 1 -maxdepth 1 -type d \
    -name 'autostream-host-agent-install.*' -printf '%f\n' |
    LC_ALL=C sort
}

readonly PRIVATE_STAGE_BEFORE="$(private_stage_listing)"
assert_private_stage_cleaned() {
  local allow_systemctl=${1:-false}
  local after
  after="$(private_stage_listing)"
  [[ ${after} == "${PRIVATE_STAGE_BEFORE}" ]] || {
    printf '%s\n%s\n' \
      'Host Agent upgrade installer left a private bundle stage behind:' \
      "${after}" >&2
    exit 1
  }
  [[ ${allow_systemctl} == true ||
    (! -e ${SYSTEMCTL_LOG} && ! -L ${SYSTEMCTL_LOG}) ]] || {
    printf '%s\n' 'delegating Host Agent upgrade unexpectedly invoked systemctl' >&2
    exit 1
  }
}

assert_no_completion() {
  local output=$1
  if grep -Fq -- "${COMPLETION}" <<<"${output}"; then
    printf '%s\n%s\n' \
      'failed Host Agent upgrade printed its completion marker:' \
      "${output}" >&2
    exit 1
  fi
}

assert_helper_not_called() {
  [[ ! -e ${HELPER_LOG} && ! -L ${HELPER_LOG} ]] || {
    printf '%s\n' 'Host Agent upgrade invoked the candidate helper before validation completed' >&2
    exit 1
  }
}

assert_helper_arguments() {
  local expect_recovery=${1:-false}
  local artifact_root
  [[ -f ${HELPER_LOG} && ! -L ${HELPER_LOG} ]] || {
    printf '%s\n' 'candidate Local Executor did not record the manual upgrade request' >&2
    exit 1
  }
  [[ $(stat -c '%U:%G:%a' -- "${HELPER_LOG}") == root:root:600 ]] || {
    printf '%s\n' 'candidate Local Executor request log is not root:root 0600' >&2
    exit 1
  }
  artifact_root=$(awk -F= '$1 == "artifact-root" { sub(/^artifact-root=/, ""); print }' \
    "${HELPER_LOG}")
  case "${artifact_root}" in
    /var/tmp/autostream-host-agent-install.*/unpack/"${ARTIFACT_ID}") ;;
    *)
      printf 'candidate Local Executor received an unexpected artifact root: %s\n' \
        "${artifact_root}" >&2
      exit 1
      ;;
  esac
  grep -Fx -- "archive-sha256=${EXPECTED_ARCHIVE_SHA256}" \
    "${HELPER_LOG}" >/dev/null
  grep -Fx -- "archive-size=${EXPECTED_ARCHIVE_SIZE}" \
    "${HELPER_LOG}" >/dev/null
  if [[ ${expect_recovery} == true ]]; then
    grep -Fx -- 'agent-stopped-for-recovery=true' \
      "${HELPER_LOG}" >/dev/null
  elif grep -Fq -- 'agent-stopped-for-recovery=' "${HELPER_LOG}"; then
    printf '%s\n' \
      'normal Host Agent upgrade unexpectedly used the internal stopped-Agent flag' >&2
    exit 1
  fi
}

getent group autostream-host-agent >/dev/null 2>&1 || \
  groupadd --system autostream-host-agent
getent passwd autostream-host-agent >/dev/null 2>&1 || \
  useradd \
    --system \
    --gid autostream-host-agent \
    --home-dir /nonexistent \
    --shell /usr/sbin/nologin \
    autostream-host-agent
install -d -o root -g autostream-host-agent -m 0750 \
  /etc/autostream/updater
install -d -o root -g root -m 0700 \
  /etc/autostream-local-executor
install -d -o autostream-host-agent -g autostream-host-agent -m 0700 \
  /var/lib/autostream-host-agent
printf '%s\n' \
  'panel_url: https://panel.example.com' \
  'node_id: host-smoke' \
  'runtime_token: sentinel-token' \
  'service_name: Host smoke' \
  > "${IDENTITY_PATH}"
chown root:autostream-host-agent "${IDENTITY_PATH}"
chmod 0640 "${IDENTITY_PATH}"
printf '%s\n' '{"sentinel":"local-executor-policy"}' > "${POLICY_PATH}"
chown root:root "${POLICY_PATH}"
chmod 0600 "${POLICY_PATH}"

readonly IDENTITY_STAT_BEFORE="$(stat -c '%d:%i:%u:%g:%a' -- "${IDENTITY_PATH}")"
readonly IDENTITY_SHA_BEFORE="$(sha256sum -- "${IDENTITY_PATH}" | awk 'NR == 1 { print $1 }')"
readonly POLICY_STAT_BEFORE="$(stat -c '%d:%i:%u:%g:%a' -- "${POLICY_PATH}")"
readonly POLICY_SHA_BEFORE="$(sha256sum -- "${POLICY_PATH}" | awk 'NR == 1 { print $1 }')"

assert_sentinels_unchanged() {
  [[ $(stat -c '%d:%i:%u:%g:%a' -- "${IDENTITY_PATH}") == \
      "${IDENTITY_STAT_BEFORE}" &&
    $(sha256sum -- "${IDENTITY_PATH}" | awk 'NR == 1 { print $1 }') == \
      "${IDENTITY_SHA_BEFORE}" ]] || {
    printf '%s\n' 'Host Agent upgrade changed the installed identity sentinel' >&2
    exit 1
  }
  [[ $(stat -c '%d:%i:%u:%g:%a' -- "${POLICY_PATH}") == \
      "${POLICY_STAT_BEFORE}" &&
    $(sha256sum -- "${POLICY_PATH}" | awk 'NR == 1 { print $1 }') == \
      "${POLICY_SHA_BEFORE}" ]] || {
    printf '%s\n' 'Host Agent upgrade changed the Local Executor policy sentinel' >&2
    exit 1
  }
}

rebuild_bundle_archive
expected_manifest_sha="$(sha256sum -- "${PACKAGE_ROOT}/artifact-manifest.json" |
  awk 'NR == 1 { print $1 }')"
if ! command -v jq >/dev/null 2>&1; then
  jq_shim=$(mktemp)
  cat > "${jq_shim}" <<EOF
#!/bin/bash
set -euo pipefail
manifest="\${!#}"
actual_sha="\$(sha256sum -- "\${manifest}" | awk 'NR == 1 { print \$1 }')"
[[ \${actual_sha} == "${expected_manifest_sha}" ]] || exit 1
case " \$* " in
  *" .commit "*)
    printf '%s\n' '${BUILD_COMMIT}'
    ;;
  *" .build_date "*)
    printf '%s\n' '${BUILD_DATE}'
    ;;
  *)
    exit 0
    ;;
esac
EOF
  install -o root -g root -m 0755 "${jq_shim}" /usr/bin/jq
  rm -f -- "${jq_shim}"
fi
if ! command -v systemctl >/dev/null 2>&1; then
  systemctl_shim=$(mktemp)
  cat > "${systemctl_shim}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" > /root/autostream-host-agent-upgrade-systemctl.log
exit 98
EOF
  install -o root -g root -m 0755 "${systemctl_shim}" /usr/bin/systemctl
  rm -f -- "${systemctl_shim}"
fi

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --upgrade --prepare 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted --upgrade with --prepare' >&2
  exit 1
fi
grep -Fq -- '--prepare, --config, and --upgrade are mutually exclusive' \
  <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --upgrade --config "${IDENTITY_PATH}" 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted --upgrade with --config' >&2
  exit 1
fi
grep -Fq -- '--prepare, --config, and --upgrade are mutually exclusive' \
  <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --prepare --recover-active-job 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted recovery without upgrade mode' >&2
  exit 1
fi
grep -Fq -- '--recover-active-job requires --upgrade' <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --upgrade --recover-active-job --recover-active-job 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted a duplicate recovery flag' >&2
  exit 1
fi
grep -Fq -- '--recover-active-job may be specified only once' <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

mv -- "${ARCHIVE}" "${ARCHIVE_BACKUP}"
rm -f -- "${HELPER_LOG}"
if missing_output="$("${INSTALLER}" --upgrade 2>&1)"; then
  printf '%s\n' 'Host Agent upgrade accepted a missing adjacent archive' >&2
  exit 1
fi
mv -- "${ARCHIVE_BACKUP}" "${ARCHIVE}"
assert_no_completion "${missing_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

install -o root -g root -m 0600 "${ARCHIVE}" "${ARCHIVE_BACKUP}"
install -o root -g root -m 0755 \
  "${PACKAGE_ROOT}/bin/autostream-host-agent" "${HOST_BINARY_BACKUP}"
printf '%s\n' '# adjacent archive checksum tamper' >> \
  "${PACKAGE_ROOT}/bin/autostream-host-agent"
rm -f -- "${ARCHIVE}"
tar -C /root -czf "${ARCHIVE}" "${ARTIFACT_ID}"
rm -f -- "${HELPER_LOG}"
if tampered_output="$("${INSTALLER}" --upgrade 2>&1)"; then
  printf '%s\n' 'Host Agent upgrade accepted a modified adjacent archive' >&2
  exit 1
fi
install -o root -g root -m 0755 \
  "${HOST_BINARY_BACKUP}" "${PACKAGE_ROOT}/bin/autostream-host-agent"
install -o root -g root -m 0600 "${ARCHIVE_BACKUP}" "${ARCHIVE}"
rm -f -- "${HOST_BINARY_BACKUP}" "${ARCHIVE_BACKUP}"
assert_no_completion "${tampered_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

readonly EXPECTED_ARCHIVE_SHA256="$(sha256sum -- "${ARCHIVE}" |
  awk 'NR == 1 { print $1 }')"
readonly EXPECTED_ARCHIVE_SIZE="$(stat -c %s -- "${ARCHIVE}")"

run_wrapper_signal_case() {
  local signal_mode=$1
  local expect_success=$2
  local expected_status=$3
  local wrapper_pid
  local wrapper_status
  local candidate_pid
  local attempts=0

  printf '%s\n' "${signal_mode}" > "${HELPER_SIGNAL_MODE}"
  chmod 0600 "${HELPER_SIGNAL_MODE}"
  rm -f -- \
    "${HELPER_LOG}" \
    "${HELPER_SIGNAL_READY}" \
    "${HELPER_SIGNAL_RECEIVED}" \
    "${HELPER_SIGNAL_FINISHED}" \
    "${SIGNAL_OUTPUT}"

  "${INSTALLER}" --upgrade > "${SIGNAL_OUTPUT}" 2>&1 &
  wrapper_pid=$!
  while [[ ! -f ${HELPER_SIGNAL_READY} ]]; do
    if ! kill -0 "${wrapper_pid}" 2>/dev/null; then
      if wait "${wrapper_pid}"; then
        wrapper_status=0
      else
        wrapper_status=$?
      fi
      printf 'Host Agent upgrade wrapper exited with status %s before its candidate was ready:\n' \
        "${wrapper_status}" >&2
      sed -n '1,160p' "${SIGNAL_OUTPUT}" >&2
      exit 1
    fi
    attempts=$((attempts + 1))
    if [[ ${attempts} -ge 200 ]]; then
      kill -TERM "${wrapper_pid}" 2>/dev/null || true
      wait "${wrapper_pid}" 2>/dev/null || true
      printf '%s\n' 'timed out waiting for the candidate Local Executor signal fixture' >&2
      exit 1
    fi
    sleep 0.05
  done

  candidate_pid="$(<"${HELPER_SIGNAL_READY}")"
  [[ ${candidate_pid} =~ ^[1-9][0-9]*$ ]] || {
    printf 'candidate signal fixture recorded an invalid PID: %s\n' "${candidate_pid}" >&2
    exit 1
  }
  kill -TERM "${wrapper_pid}"
  if wait "${wrapper_pid}"; then
    wrapper_status=0
  else
    wrapper_status=$?
  fi

  [[ ${wrapper_status} -eq ${expected_status} ]] || {
    printf 'Host Agent upgrade wrapper status=%s, expected candidate status=%s:\n' \
      "${wrapper_status}" "${expected_status}" >&2
    sed -n '1,160p' "${SIGNAL_OUTPUT}" >&2
    exit 1
  }

  [[ -f ${HELPER_SIGNAL_RECEIVED} && ! -L ${HELPER_SIGNAL_RECEIVED} &&
    $(<"${HELPER_SIGNAL_RECEIVED}") == TERM ]] || {
    printf '%s\n' 'wrapper-only SIGTERM was not forwarded to the candidate Local Executor' >&2
    exit 1
  }
  [[ -f ${HELPER_SIGNAL_FINISHED} && ! -L ${HELPER_SIGNAL_FINISHED} &&
    $(<"${HELPER_SIGNAL_FINISHED}") == TERM ]] || {
    kill -TERM "${candidate_pid}" 2>/dev/null || true
    printf '%s\n' 'Host Agent upgrade wrapper did not wait for the signaled candidate to finish' >&2
    exit 1
  }
  if kill -0 "${candidate_pid}" 2>/dev/null; then
    kill -TERM "${candidate_pid}" 2>/dev/null || true
    printf '%s\n' 'candidate Local Executor remained alive after its wrapper returned' >&2
    exit 1
  fi

  if [[ ${expect_success} == true ]]; then
    grep -Fq -- "${COMPLETION}" "${SIGNAL_OUTPUT}"
  else
    [[ ${wrapper_status} -ne 0 ]] || {
      printf '%s\n' 'Host Agent upgrade converted candidate cancellation failure to success' >&2
      exit 1
    }
    assert_no_completion "$(<"${SIGNAL_OUTPUT}")"
    grep -Fq -- 'managed Host runtime upgrade failed' "${SIGNAL_OUTPUT}"
  fi

  rm -f -- \
    "${HELPER_SIGNAL_MODE}" \
    "${HELPER_SIGNAL_READY}" \
    "${HELPER_SIGNAL_RECEIVED}" \
    "${HELPER_SIGNAL_FINISHED}" \
    "${SIGNAL_OUTPUT}"
  assert_helper_arguments
  assert_private_stage_cleaned
  assert_sentinels_unchanged
}

install -o root -g root -m 0600 /dev/null "${HELPER_FAIL_MARKER}"
rm -f -- "${HELPER_LOG}"
helper_failure_status=0
helper_failure_output="$("${INSTALLER}" --upgrade 2>&1)" || helper_failure_status=$?
if [[ ${helper_failure_status} -ne 73 ]]; then
  printf '%s\n' 'Host Agent upgrade survived a candidate Local Executor failure' >&2
  printf 'status=%s, expected=73\n' "${helper_failure_status}" >&2
  exit 1
fi
rm -f -- "${HELPER_FAIL_MARKER}"
assert_no_completion "${helper_failure_output}"
assert_helper_arguments
assert_private_stage_cleaned
assert_sentinels_unchanged

[[ ! -d /run/systemd/system && "$(< /proc/1/comm)" != systemd ]] || {
  printf '%s\n' \
    'active-job recovery smoke may replace systemd clients only in an isolated non-systemd container' >&2
  exit 1
}
export HTTP_PROXY=http://poison.invalid:65535
export HTTPS_PROXY=http://poison.invalid:65535
export ALL_PROXY=socks5://poison.invalid:65535
export NO_PROXY=poison.invalid
export http_proxy=http://lower-poison.invalid:65535
export https_proxy=http://lower-poison.invalid:65535
export all_proxy=socks5://lower-poison.invalid:65535
export no_proxy=lower-poison.invalid
export SSL_CERT_FILE=/root/poison-cert.pem
export SSL_CERT_DIR=/root/poison-certs
export CURL_CA_BUNDLE=/root/poison-curl.pem
export REQUESTS_CA_BUNDLE=/root/poison-requests.pem
export AUTOSTREAM_RUNTIME_TOKEN=sentinel-runtime-token
export AUTOSTREAM_CONFIGURE_TOKEN=sentinel-configure-token
for fixture_command in /usr/bin/sleep; do
  [[ -f ${fixture_command} && ! -L ${fixture_command} && -x ${fixture_command} ]] || {
    printf 'active-job recovery smoke fixture command is unavailable: %s\n' \
      "${fixture_command}" >&2
    exit 1
  }
done

install -d -o root -g root -m 0755 \
  "${MANAGED_RUNTIME_ROOT}/slots/a/bin"
install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" "${RUNTIME_PROCESS_FIXTURE_COPY}"
install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" "${MANAGED_RUNTIME_AGENT}"
install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" "${MANAGED_RUNTIME_EXECUTOR}"
ln -s slots/a "${MANAGED_RUNTIME_CURRENT}"
ln -s \
  "${MANAGED_RUNTIME_CURRENT}/bin/autostream-host-agent" \
  "${PUBLIC_AGENT}"
install -d -o root -g root -m 0755 /usr/local/libexec
ln -s \
  "${MANAGED_RUNTIME_CURRENT}/bin/autostream-local-executor" \
  "${PUBLIC_EXECUTOR}"
readonly ORIGINAL_RUNTIME_AGENT_SHA256="$(sha256sum -- \
  "${MANAGED_RUNTIME_AGENT}" | awk 'NR == 1 { print $1 }')"
readonly ORIGINAL_RUNTIME_EXECUTOR_SHA256="$(sha256sum -- \
  "${MANAGED_RUNTIME_EXECUTOR}" | awk 'NR == 1 { print $1 }')"

install -d -o root -g root -m 0700 /run/autostream-updater
install -o root -g root -m 0600 /dev/null "${RECOVERY_LIFECYCLE_LOCK}"

local_executor_lock_daemon() {
  local response
  while true; do
    if [[ -f ${RECOVERY_LIFECYCLE_HOLD_TRIGGER} &&
      ! -L ${RECOVERY_LIFECYCLE_HOLD_TRIGGER} ]]; then
      exec 6<>"${RECOVERY_LIFECYCLE_LOCK}"
      if flock -n 6; then
        printf '%s\n' lifecycle-lock-held >> "${RECOVERY_SEQUENCE_LOG}"
        printf '%s\n' ready > "${RECOVERY_LIFECYCLE_HOLD_READY}"
        chown autostream-host-agent:autostream-host-agent \
          "${RECOVERY_LIFECYCLE_HOLD_READY}"
        chmod 0600 "${RECOVERY_LIFECYCLE_HOLD_READY}"
        while [[ ! -f ${RECOVERY_LIFECYCLE_HOLD_RELEASE} ||
          -L ${RECOVERY_LIFECYCLE_HOLD_RELEASE} ]]; do
          sleep 0.01
        done
        rm -f -- \
          "${RECOVERY_LIFECYCLE_HOLD_TRIGGER}" \
          "${RECOVERY_LIFECYCLE_HOLD_READY}" \
          "${RECOVERY_LIFECYCLE_HOLD_RELEASE}"
        flock -u 6
      fi
      exec 6>&-
    fi
    if [[ -f ${RECOVERY_FULL_HOLD_TRIGGER} &&
      ! -L ${RECOVERY_FULL_HOLD_TRIGGER} ]]; then
      exec 7<>"${RECOVERY_SETUP_LOCK}"
      if flock -n 7; then
        exec 6<>"${RECOVERY_LIFECYCLE_LOCK}"
        if flock -n 6; then
          printf '%s\n' full-locks-held >> "${RECOVERY_SEQUENCE_LOG}"
          printf '%s\n' ready > "${RECOVERY_FULL_HOLD_READY}"
          chown autostream-host-agent:autostream-host-agent \
            "${RECOVERY_FULL_HOLD_READY}"
          chmod 0600 "${RECOVERY_FULL_HOLD_READY}"
          while [[ ! -f ${RECOVERY_FULL_HOLD_RELEASE} ||
            -L ${RECOVERY_FULL_HOLD_RELEASE} ]]; do
            sleep 0.01
          done
          rm -f -- \
            "${RECOVERY_FULL_HOLD_TRIGGER}" \
            "${RECOVERY_FULL_HOLD_READY}" \
            "${RECOVERY_FULL_HOLD_RELEASE}"
          flock -u 6
        fi
        exec 6>&-
        flock -u 7
      fi
      exec 7>&-
    fi
    if [[ -f ${RECOVERY_EXECUTOR_TRIGGER} &&
      ! -L ${RECOVERY_EXECUTOR_TRIGGER} ]]; then
      response=target_busy
      exec 6<>"${RECOVERY_LIFECYCLE_LOCK}"
      if flock -n 6; then
        response=acquired
        printf '%s\n' inactive > "${RECOVERY_STATE}"
        chown autostream-host-agent:autostream-host-agent "${RECOVERY_STATE}"
        chmod 0600 "${RECOVERY_STATE}"
        printf '%s\n' executor-lock-acquired >> "${RECOVERY_SEQUENCE_LOG}"
        flock -u 6
      else
        printf '%s\n' executor-lock-busy >> "${RECOVERY_SEQUENCE_LOG}"
      fi
      exec 6>&-
      rm -f -- "${RECOVERY_EXECUTOR_TRIGGER}"
      # Publish only after ownership and mode are ready; the fake Host Agent
      # runs unprivileged and must never observe a root-owned response inode.
      rm -f -- "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      printf '%s\n' "${response}" > "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      chown autostream-host-agent:autostream-host-agent \
        "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      chmod 0600 "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      mv -T -- \
        "${RECOVERY_EXECUTOR_RESPONSE_STAGE}" \
        "${RECOVERY_EXECUTOR_RESPONSE}"
    fi
    sleep 0.01
  done
}

local_executor_lock_daemon &
readonly LOCAL_EXECUTOR_LOCK_DAEMON_PID=$!

start_managed_agent_fixture() {
  local pid
  if [[ -f ${SERVICE_PID_FILE} && ! -L ${SERVICE_PID_FILE} ]]; then
    pid="$(<"${SERVICE_PID_FILE}")"
    if [[ ${pid} =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
  fi
  "${MANAGED_RUNTIME_AGENT}" 3600 \
    </dev/null >/dev/null 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" > "${SERVICE_PID_FILE}"
  chmod 0600 "${SERVICE_PID_FILE}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -d /proc/${pid} &&
      $(readlink -f -- "/proc/${pid}/exe") == "${MANAGED_RUNTIME_AGENT}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  printf '%s\n' 'could not start the managed Host Agent process fixture' >&2
  exit 1
}

start_managed_agent_fixture

start_managed_executor_fixture() {
  local pid
  if [[ -f ${EXECUTOR_PID_FILE} && ! -L ${EXECUTOR_PID_FILE} ]]; then
    pid="$(<"${EXECUTOR_PID_FILE}")"
    if [[ ${pid} =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
  fi
  "${MANAGED_RUNTIME_EXECUTOR}" run \
    </dev/null >/dev/null 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" > "${EXECUTOR_PID_FILE}"
  chmod 0600 "${EXECUTOR_PID_FILE}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -d /proc/${pid} &&
      $(readlink -f -- "/proc/${pid}/exe") == "${MANAGED_RUNTIME_EXECUTOR}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  printf '%s\n' 'could not start the managed Local Executor process fixture' >&2
  exit 1
}

start_managed_executor_fixture

if [[ -f /usr/bin/systemctl && ! -L /usr/bin/systemctl ]]; then
  install -o root -g root -m 0755 /usr/bin/systemctl "${SYSTEMCTL_BACKUP}"
fi
if [[ -f /usr/bin/systemd-run && ! -L /usr/bin/systemd-run ]]; then
  install -o root -g root -m 0755 /usr/bin/systemd-run "${SYSTEMD_RUN_BACKUP}"
fi

systemctl_shim=$(mktemp)
cat > "${systemctl_shim}" <<'EOF'
#!/bin/bash
set -euo pipefail
readonly UNIT_NAME=autostream-host-agent.service
readonly EXECUTOR_UNIT=autostream-local-executor.service
readonly EXECUTOR_SOCKET=autostream-local-executor.socket
readonly PID_FILE=/root/autostream-host-agent-upgrade-service.pid
readonly EXECUTOR_PID_FILE=/root/autostream-local-executor-upgrade-service.pid
readonly LOG=/root/autostream-host-agent-upgrade-systemctl.log
readonly SEQUENCE=/var/lib/autostream-host-agent/installer-recovery-sequence.log
readonly GUARD_SERVICE=autostream-host-agent-upgrade-recovery-guard.service
readonly GUARD_TIMER=autostream-host-agent-upgrade-recovery-guard.timer
readonly GUARD_LOADED=/root/autostream-host-agent-upgrade-guard.loaded
readonly GUARD_TIMER_ACTIVE=/root/autostream-host-agent-upgrade-guard.timer-active
readonly GUARD_SERVICE_PATH=/run/systemd/transient/autostream-host-agent-upgrade-recovery-guard.service
readonly GUARD_TIMER_PATH=/run/systemd/transient/autostream-host-agent-upgrade-recovery-guard.timer
readonly RECOVERY_CLEAR_MARKER=/var/lib/autostream-host-agent/journal.clear-active.pending.json
readonly RECOVERY_CLEAR_FENCE=/etc/systemd/system/autostream-host-agent.service.d/90-autostream-upgrade-recovery-guard.conf
readonly MANAGED_CURRENT=/opt/autostream/host-agent/current

printf 'systemctl %s\n' "$*" >> "${LOG}"
chmod 0600 "${LOG}"

service_pid() {
  [[ -f ${PID_FILE} && ! -L ${PID_FILE} ]] || return 1
  local pid
  pid="$(<"${PID_FILE}")"
  [[ ${pid} =~ ^[1-9][0-9]*$ && -d /proc/${pid} ]] || return 1
  printf '%s\n' "${pid}"
}

managed_agent() {
  readlink -f -- "${MANAGED_CURRENT}/bin/autostream-host-agent"
}

managed_executor() {
  readlink -f -- "${MANAGED_CURRENT}/bin/autostream-local-executor"
}

executor_pid() {
  local expected
  [[ -f ${EXECUTOR_PID_FILE} && ! -L ${EXECUTOR_PID_FILE} ]] || return 1
  local pid
  pid="$(<"${EXECUTOR_PID_FILE}")"
  [[ ${pid} =~ ^[1-9][0-9]*$ && -d /proc/${pid} ]] || return 1
  expected="$(managed_executor)" || return 1
  [[ $(readlink -f -- "/proc/${pid}/exe") == "${expected}" ]] || return 1
  printf '%s\n' "${pid}"
}

start_agent() {
  local executable
  local guard_executable
  local pid
  if pid="$(service_pid)" && kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi
  if [[ -e ${RECOVERY_CLEAR_FENCE} || -L ${RECOVERY_CLEAR_FENCE} ]]; then
    [[ -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
      ! -e ${RECOVERY_CLEAR_MARKER} && ! -L ${RECOVERY_CLEAR_MARKER} ]] || return 1
    guard_executable="$(awk -F= \
      '$1 == "ConditionFileIsExecutable" { print $2 }' \
      "${RECOVERY_CLEAR_FENCE}")"
    [[ ${guard_executable} == /run/autostream-host-agent-upgrade-guard.*/autostream-local-executor &&
      -f ${guard_executable} && ! -L ${guard_executable} &&
      -x ${guard_executable} ]] || return 1
  fi
  executable="$(managed_agent)" || return 1
  "${executable}" 3600 \
    </dev/null >/dev/null 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" > "${PID_FILE}"
  chmod 0600 "${PID_FILE}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ -d /proc/${pid} &&
      $(readlink -f -- "/proc/${pid}/exe") == "${executable}" ]] && return 0
    sleep 0.05
  done
  return 1
}

start_executor() {
  local executable
  local pid
  executable="$(managed_executor)" || return 1
  "${executable}" run \
    </dev/null >/dev/null 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" > "${EXECUTOR_PID_FILE}"
  chmod 0600 "${EXECUTOR_PID_FILE}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ -d /proc/${pid} &&
      $(readlink -f -- "/proc/${pid}/exe") == "${executable}" ]] && return 0
    sleep 0.05
  done
  return 1
}

case "${1:-}" in
  is-enabled)
    [[ $# -eq 2 ]] || exit 81
    case "${2:-}" in
      "${UNIT_NAME}"|"${EXECUTOR_SOCKET}") printf '%s\n' enabled ;;
      "${EXECUTOR_UNIT}")
        printf '%s\n' disabled
        exit 1
        ;;
      *) exit 81 ;;
    esac
    ;;
  is-active)
    [[ $# -eq 2 ]] || exit 82
    case "${2}" in
      "${UNIT_NAME}")
        if service_pid >/dev/null; then
          printf '%s\n' active
        else
          printf '%s\n' inactive
          exit 3
        fi
        ;;
      "${EXECUTOR_UNIT}")
        if executor_pid >/dev/null; then
          printf '%s\n' active
        else
          printf '%s\n' inactive
          exit 3
        fi
        ;;
      "${EXECUTOR_SOCKET}")
        printf '%s\n' active
        ;;
      "${GUARD_TIMER}")
        [[ -f ${GUARD_TIMER_ACTIVE} && ! -L ${GUARD_TIMER_ACTIVE} ]] || {
          printf '%s\n' inactive
          exit 3
        }
        printf '%s\n' active
        ;;
      *) exit 83 ;;
    esac
    ;;
  show)
    [[ $# -eq 4 && ${4:-} == --value ]] || exit 84
    unit=$2
    property=${3#--property=}
    case "${unit}:${property}" in
      "${UNIT_NAME}:MainPID")
        service_pid 2>/dev/null || printf '%s\n' 0
        ;;
      "${UNIT_NAME}:ActiveState")
        if service_pid >/dev/null; then
          printf '%s\n' active
        else
          printf '%s\n' inactive
        fi
        ;;
      "${UNIT_NAME}:User")
        printf '%s\n' autostream-host-agent
        ;;
      "${UNIT_NAME}:Group")
        printf '%s\n' autostream-host-agent
        ;;
      "${UNIT_NAME}:NeedDaemonReload")
        printf '%s\n' no
        ;;
      "${UNIT_NAME}:DropInPaths")
        if [[ -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} ]]; then
          printf '%s\n' "${RECOVERY_CLEAR_FENCE}"
        fi
        ;;
      "${EXECUTOR_UNIT}:MainPID")
        executor_pid 2>/dev/null || printf '%s\n' 0
        ;;
      "${EXECUTOR_UNIT}:User"|"${EXECUTOR_UNIT}:Group")
        printf '%s\n' root
        ;;
      "${GUARD_SERVICE}:LoadState"|"${GUARD_TIMER}:LoadState")
        if [[ -f ${GUARD_LOADED} && ! -L ${GUARD_LOADED} ]]; then
          printf '%s\n' loaded
        else
          printf '%s\n' not-found
        fi
        ;;
      "${GUARD_SERVICE}:FragmentPath")
        printf '%s\n' "${GUARD_SERVICE_PATH}"
        ;;
      "${GUARD_TIMER}:FragmentPath")
        printf '%s\n' "${GUARD_TIMER_PATH}"
        ;;
      "${GUARD_TIMER}:ActiveState")
        if [[ -f ${GUARD_TIMER_ACTIVE} && ! -L ${GUARD_TIMER_ACTIVE} ]]; then
          printf '%s\n' active
        else
          printf '%s\n' inactive
        fi
        ;;
      *) exit 85 ;;
    esac
    ;;
  daemon-reload)
    [[ $# -eq 1 ]] || exit 91
    ;;
  stop)
    [[ $# -eq 2 ]] || exit 86
    case "${2}" in
      "${UNIT_NAME}")
        printf '%s\n' stop-agent >> "${SEQUENCE}"
        if pid="$(service_pid)"; then
          kill -TERM "${pid}" 2>/dev/null || true
        fi
        rm -f -- "${PID_FILE}"
        ;;
      "${GUARD_TIMER}")
        printf '%s\n' stop-guard-timer >> "${SEQUENCE}"
        rm -f -- "${GUARD_TIMER_ACTIVE}" "${GUARD_TIMER_PATH}"
        ;;
      "${GUARD_SERVICE}")
        printf '%s\n' stop-guard-service >> "${SEQUENCE}"
        rm -f -- "${GUARD_LOADED}" "${GUARD_SERVICE_PATH}"
        ;;
      *) exit 87 ;;
    esac
    ;;
  start)
    [[ $# -eq 2 && ${2:-} == "${UNIT_NAME}" ]] || exit 88
    printf '%s\n' start-agent >> "${SEQUENCE}"
    start_agent
    ;;
  restart)
    [[ $# -eq 2 && ${2:-} == "${EXECUTOR_UNIT}" ]] || exit 90
    printf '%s\n' restart-executor >> "${SEQUENCE}"
    pid="$(<"${EXECUTOR_PID_FILE}")"
    if [[ ${pid} =~ ^[1-9][0-9]*$ && -d /proc/${pid} ]]; then
      kill -TERM "${pid}" 2>/dev/null || true
    fi
    rm -f -- "${EXECUTOR_PID_FILE}"
    start_executor
    ;;
  *)
    printf 'unexpected systemctl invocation: %s\n' "$*" >&2
    exit 89
    ;;
esac
EOF
install -o root -g root -m 0755 "${systemctl_shim}" /usr/bin/systemctl
rm -f -- "${systemctl_shim}"

systemd_run_shim=$(mktemp)
cat > "${systemd_run_shim}" <<'EOF'
#!/bin/bash
set -euo pipefail
readonly LOG=/root/autostream-host-agent-upgrade-systemd-run.log
readonly SEQUENCE=/var/lib/autostream-host-agent/installer-recovery-sequence.log
readonly GUARD_LOADED=/root/autostream-host-agent-upgrade-guard.loaded
readonly GUARD_TIMER_ACTIVE=/root/autostream-host-agent-upgrade-guard.timer-active
readonly GUARD_FIRE_TRIGGER=/root/autostream-host-agent-upgrade-guard.fire
readonly GUARD_FIRE_STATUS=/root/autostream-host-agent-upgrade-guard.fire-status
readonly GUARD_WORKER_PID_FILE=/root/autostream-host-agent-upgrade-guard.worker-pid
readonly GUARD_SERVICE_PATH=/run/systemd/transient/autostream-host-agent-upgrade-recovery-guard.service
readonly GUARD_TIMER_PATH=/run/systemd/transient/autostream-host-agent-upgrade-recovery-guard.timer
readonly RECOVERY_CLEAR_MARKER=/var/lib/autostream-host-agent/journal.clear-active.pending.json
readonly RECOVERY_CLEAR_FENCE=/etc/systemd/system/autostream-host-agent.service.d/90-autostream-upgrade-recovery-guard.conf
readonly MANAGED_RUNTIME_CURRENT=/opt/autostream/host-agent/current
[[ $# -eq 13 &&
  ${1:-} == --quiet &&
  ${2:-} == --collect &&
  ${3:-} == --unit=autostream-host-agent-upgrade-recovery-guard &&
  ${4:-} == --on-active=25m &&
  ${5:-} == --timer-property=AccuracySec=1s &&
  ${6:-} == /run/autostream-host-agent-upgrade-guard.*/autostream-local-executor &&
  ${7:-} == guard-restart-host-agent &&
  ${8:-} == --expected-slot && (${9:-} == a || ${9:-} == b) &&
  ${10:-} == --agent-sha256 && ${11:-} =~ ^[0-9a-f]{64}$ &&
  ${12:-} == --executor-sha256 && ${13:-} =~ ^[0-9a-f]{64}$ ]] || {
  printf 'unexpected systemd-run invocation: %s\n' "$*" >&2
  exit 90
}
guard_directory="$(dirname -- "${6}")"
selected_root="/opt/autostream/host-agent/slots/${9}/bin"
expected_fence="$(printf '%s\n' \
  '[Unit]' \
  "ConditionPathExists=!${RECOVERY_CLEAR_MARKER}" \
  "ConditionFileIsExecutable=${6}")"
[[ -d ${guard_directory} && ! -L ${guard_directory} &&
  $(readlink -f -- "${guard_directory}") == "${guard_directory}" &&
  $(stat -c '%U:%G:%a' -- "${guard_directory}") == root:root:700 &&
  -f ${6} && ! -L ${6} &&
  $(stat -c '%U:%G:%a:%h' -- "${6}") == root:root:700:1 &&
  $(readlink -- "${MANAGED_RUNTIME_CURRENT}") == "slots/${9}" &&
  $(stat -c '%U:%G:%a:%h' -- \
    "${selected_root}/autostream-host-agent") == root:root:755:1 &&
  $(stat -c '%U:%G:%a:%h' -- \
    "${selected_root}/autostream-local-executor") == root:root:755:1 &&
  $(sha256sum -- "${selected_root}/autostream-host-agent" | \
    awk 'NR == 1 { print $1 }') == "${11}" &&
  $(sha256sum -- "${selected_root}/autostream-local-executor" | \
    awk 'NR == 1 { print $1 }') == "${13}" &&
  ! -e ${RECOVERY_CLEAR_MARKER} && ! -L ${RECOVERY_CLEAR_MARKER} &&
  -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
  $(stat -c '%U:%G:%a:%h' -- "${RECOVERY_CLEAR_FENCE}") == root:root:644:1 &&
  $(<"${RECOVERY_CLEAR_FENCE}") == "${expected_fence}" ]] || {
  printf '%s\n' 'systemd-run fixture rejected an unsafe Host recovery guard' >&2
  exit 91
}
printf 'systemd-run %s\n' "$*" > "${LOG}"
chmod 0600 "${LOG}"
printf '%s\n' guard-arm >> "${SEQUENCE}"
install -d -o root -g root -m 0755 /run/systemd/transient
printf '%s\n' '[Service]' > "${GUARD_SERVICE_PATH}"
printf '%s\n' '[Timer]' > "${GUARD_TIMER_PATH}"
chown root:root "${GUARD_SERVICE_PATH}" "${GUARD_TIMER_PATH}"
chmod 0644 "${GUARD_SERVICE_PATH}" "${GUARD_TIMER_PATH}"
install -o root -g root -m 0600 /dev/null "${GUARD_LOADED}"
printf '%s\n' "$$" > "${GUARD_TIMER_ACTIVE}"
chown root:root "${GUARD_TIMER_ACTIVE}"
chmod 0600 "${GUARD_TIMER_ACTIVE}"
guard_token="$$"
(
  exec 6>&- 7>&- 8>&- 9>&-
  while [[ -f ${GUARD_TIMER_ACTIVE} && ! -L ${GUARD_TIMER_ACTIVE} &&
    $(<"${GUARD_TIMER_ACTIVE}") == "${guard_token}" ]]; do
    if [[ -f ${GUARD_FIRE_TRIGGER} && ! -L ${GUARD_FIRE_TRIGGER} ]]; then
      guard_status=0
      "${6}" "${@:7}" || guard_status=$?
      printf '%s\n' "${guard_status}" > "${GUARD_FIRE_STATUS}"
      chown root:root "${GUARD_FIRE_STATUS}"
      chmod 0600 "${GUARD_FIRE_STATUS}"
      exit 0
    fi
    sleep 0.01
  done
) </dev/null >/dev/null 2>&1 &
printf '%s\n' "$!" > "${GUARD_WORKER_PID_FILE}"
chown root:root "${GUARD_WORKER_PID_FILE}"
chmod 0600 "${GUARD_WORKER_PID_FILE}"
EOF
install -o root -g root -m 0755 "${systemd_run_shim}" /usr/bin/systemd-run
rm -f -- "${systemd_run_shim}"

reset_recovery_fixture() {
  [[ ! -e ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
    -z $(find /run -mindepth 1 -maxdepth 1 \
      -name 'autostream-host-agent-upgrade-guard.*' -print -quit) &&
    ! -e ${GUARD_WORKER_PID_FILE} && ! -L ${GUARD_WORKER_PID_FILE} ]] || {
    printf '%s\n' 'previous Host recovery guard fixture was not cleaned safely' >&2
    exit 1
  }
  /usr/bin/systemctl start autostream-host-agent.service >/dev/null
  printf '%s\n' active > "${RECOVERY_STATE}"
  chown autostream-host-agent:autostream-host-agent "${RECOVERY_STATE}"
  chmod 0600 "${RECOVERY_STATE}"
  rm -f -- \
    "${RECOVERY_LOG}" \
    "${RECOVERY_ENV_LOG}" \
    "${RECOVERY_FAIL_MARKER}" \
    "${RECOVERY_BLOCK_MARKER}" \
    "${RECOVERY_BLOCK_READY}" \
    "${RECOVERY_FAIL_WITH_LIFECYCLE_LOCK_MARKER}" \
    "${RECOVERY_EXECUTOR_TRIGGER}" \
    "${RECOVERY_EXECUTOR_RESPONSE}" \
    "${RECOVERY_EXECUTOR_RESPONSE_STAGE}" \
    "${RECOVERY_LIFECYCLE_HOLD_TRIGGER}" \
    "${RECOVERY_LIFECYCLE_HOLD_READY}" \
    "${RECOVERY_LIFECYCLE_HOLD_RELEASE}" \
    "${RECOVERY_FULL_HOLD_TRIGGER}" \
    "${RECOVERY_FULL_HOLD_READY}" \
    "${RECOVERY_FULL_HOLD_RELEASE}" \
    "${RECOVERY_SEQUENCE_LOG}" \
    "${HELPER_LOG}" \
    "${HELPER_FAIL_MARKER}" \
    "${HELPER_FAIL_WITH_LOCK_MARKER}" \
    "${HELPER_PARTIAL_SWITCH_MARKER}" \
    "${SYSTEMCTL_LOG}" \
    "${SYSTEMD_RUN_LOG}" \
    "${GUARD_LOADED_MARKER}" \
    "${GUARD_TIMER_ACTIVE_MARKER}" \
    "${GUARD_FIRE_TRIGGER}" \
    "${GUARD_FIRE_STATUS}" \
    "${GUARD_SELF_FIRE_OUTPUT}" \
    "${RECOVERY_GUARD_SERVICE_PATH}" \
    "${RECOVERY_GUARD_TIMER_PATH}"
  install -o autostream-host-agent -g autostream-host-agent -m 0600 \
    /dev/null "${RECOVERY_SEQUENCE_LOG}"
}

assert_recovery_candidate_directory_cleaned() {
  [[ -z $(find /run -mindepth 1 -maxdepth 1 \
    -name 'autostream-host-agent-recovery.*' -print -quit) ]] || {
    printf '%s\n' 'active-job recovery left its private candidate directory behind' >&2
    exit 1
  }
}

assert_guard_candidate_directory_cleaned() {
  [[ -z $(find /run -mindepth 1 -maxdepth 1 \
    -name 'autostream-host-agent-upgrade-guard.*' -print -quit) ]] || {
    printf '%s\n' 'active-job recovery left its private guard candidate directory behind' >&2
    exit 1
  }
}

wait_for_guard_worker_exit() {
  local pid
  local state
  if [[ ! -e ${GUARD_WORKER_PID_FILE} && ! -L ${GUARD_WORKER_PID_FILE} ]]; then
    return 0
  fi
  [[ -f ${GUARD_WORKER_PID_FILE} && ! -L ${GUARD_WORKER_PID_FILE} &&
    $(stat -c '%U:%G:%a' -- "${GUARD_WORKER_PID_FILE}") == root:root:600 ]] || {
    printf '%s\n' 'Host recovery guard worker PID record is missing or unsafe' >&2
    exit 1
  }
  pid="$(<"${GUARD_WORKER_PID_FILE}")"
  [[ ${pid} =~ ^[1-9][0-9]*$ ]] || {
    printf '%s\n' 'Host recovery guard worker PID is invalid' >&2
    exit 1
  }
  for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ ! -d /proc/${pid} ]]; then
      rm -f -- "${GUARD_WORKER_PID_FILE}"
      return 0
    fi
    state="$(awk '{ print $3 }' "/proc/${pid}/stat" 2>/dev/null || true)"
    if [[ ${state} == Z ]]; then
      rm -f -- "${GUARD_WORKER_PID_FILE}"
      return 0
    fi
    sleep 0.01
  done
  printf '%s\n' 'Host recovery guard worker did not stop after timer disarm' >&2
  exit 1
}

assert_recovery_candidate_cleaned() {
  wait_for_guard_worker_exit
  assert_recovery_candidate_directory_cleaned
  assert_guard_candidate_directory_cleaned
  [[ ! -e ${RECOVERY_GUARD_SERVICE_PATH} && ! -L ${RECOVERY_GUARD_SERVICE_PATH} &&
    ! -e ${RECOVERY_GUARD_TIMER_PATH} && ! -L ${RECOVERY_GUARD_TIMER_PATH} &&
    ! -e ${GUARD_LOADED_MARKER} && ! -L ${GUARD_LOADED_MARKER} &&
    ! -e ${GUARD_TIMER_ACTIVE_MARKER} && ! -L ${GUARD_TIMER_ACTIVE_MARKER} &&
    ! -e ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} ]] || {
    printf '%s\n' 'active-job recovery left its systemd guard armed' >&2
    exit 1
  }
  [[ $(/usr/bin/systemctl is-enabled autostream-host-agent.service) == enabled &&
    $(/usr/bin/systemctl is-active autostream-host-agent.service) == active ]] || {
    printf '%s\n' 'active-job recovery did not leave the Host Agent enabled and active' >&2
    exit 1
  }
  assert_private_stage_cleaned true
  assert_sentinels_unchanged
}

release_recovery_lock_holder() {
  local release_path=$1
  local ready_path=$2
  install -o root -g root -m 0600 /dev/null "${release_path}"
  for ((attempt = 0; attempt < 200; attempt++)); do
    [[ ! -e ${ready_path} && ! -L ${ready_path} ]] && return 0
    sleep 0.01
  done
  printf 'recovery lock holder did not release: %s\n' "${ready_path}" >&2
  exit 1
}

assert_fail_closed_recovery_guard() {
  local guard_candidate
  local guard_directory
  local expected_fence
  local worker_pid
  local worker_state
  [[ $(/usr/bin/systemctl is-active autostream-host-agent.service 2>/dev/null || true) == \
    inactive ]] || {
    printf '%s\n' 'lock-contended recovery restarted the Host Agent without its lifecycle fence' >&2
    exit 1
  }
  [[ -f ${RECOVERY_GUARD_SERVICE_PATH} && ! -L ${RECOVERY_GUARD_SERVICE_PATH} &&
    -f ${RECOVERY_GUARD_TIMER_PATH} && ! -L ${RECOVERY_GUARD_TIMER_PATH} &&
    -f ${GUARD_LOADED_MARKER} && ! -L ${GUARD_LOADED_MARKER} &&
    -f ${GUARD_TIMER_ACTIVE_MARKER} && ! -L ${GUARD_TIMER_ACTIVE_MARKER} ]] || {
    printf '%s\n' 'lock-contended recovery did not leave its systemd guard armed' >&2
    exit 1
  }
  mapfile -t guard_candidates < <(find /run -mindepth 1 -maxdepth 1 \
    -type d -name 'autostream-host-agent-upgrade-guard.*' -print)
  [[ ${#guard_candidates[@]} -eq 1 ]] || {
    printf '%s\n' 'fail-closed recovery did not retain exactly one guard candidate' >&2
    exit 1
  }
  guard_directory=${guard_candidates[0]}
  guard_candidate="${guard_directory}/autostream-local-executor"
  expected_fence="$(printf '%s\n' \
    '[Unit]' \
    "ConditionPathExists=!${RECOVERY_CLEAR_MARKER}" \
    "ConditionFileIsExecutable=${guard_candidate}")"
  [[ $(readlink -f -- "${guard_directory}") == "${guard_directory}" &&
    $(stat -c '%U:%G:%a' -- "${guard_directory}") == root:root:700 &&
    -f ${guard_candidate} && ! -L ${guard_candidate} &&
    $(stat -c '%U:%G:%a:%h' -- "${guard_candidate}") == root:root:700:1 &&
    $(sha256sum -- "${guard_candidate}" | awk 'NR == 1 { print $1 }') == \
      "$(sha256sum -- "${PACKAGE_ROOT}/bin/autostream-local-executor" | awk 'NR == 1 { print $1 }')" &&
    -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
    $(stat -c '%U:%G:%a:%h' -- "${RECOVERY_CLEAR_FENCE}") == root:root:644:1 &&
    $(<"${RECOVERY_CLEAR_FENCE}") == "${expected_fence}" &&
    ! -e ${RECOVERY_CLEAR_MARKER} && ! -L ${RECOVERY_CLEAR_MARKER} &&
    -f ${GUARD_WORKER_PID_FILE} && ! -L ${GUARD_WORKER_PID_FILE} ]] || {
    printf '%s\n' 'fail-closed recovery retained an unsafe durable guard or fence' >&2
    exit 1
  }
  worker_pid="$(<"${GUARD_WORKER_PID_FILE}")"
  worker_state="$(awk '{ print $3 }' "/proc/${worker_pid}/stat" 2>/dev/null || true)"
  [[ ${worker_pid} =~ ^[1-9][0-9]*$ && -n ${worker_state} && ${worker_state} != Z ]] || {
    printf '%s\n' 'fail-closed recovery guard worker is not independently live' >&2
    exit 1
  }
  assert_recovery_candidate_directory_cleaned
  assert_private_stage_cleaned true
  assert_sentinels_unchanged
}

disarm_recovery_guard_fixture() {
  local guard_candidate
  local guard_directory
  local expected_fence
  /usr/bin/systemctl start autostream-host-agent.service >/dev/null
  assert_original_runtime_pair_active
  mapfile -t guard_candidates < <(find /run -mindepth 1 -maxdepth 1 \
    -type d -name 'autostream-host-agent-upgrade-guard.*' -print)
  [[ ${#guard_candidates[@]} -eq 1 ]] || {
    printf '%s\n' 'fixture disarm requires exactly one retained guard candidate' >&2
    exit 1
  }
  guard_directory=${guard_candidates[0]}
  guard_candidate="${guard_directory}/autostream-local-executor"
  expected_fence="$(printf '%s\n' \
    '[Unit]' \
    "ConditionPathExists=!${RECOVERY_CLEAR_MARKER}" \
    "ConditionFileIsExecutable=${guard_candidate}")"
  [[ -f ${guard_candidate} && ! -L ${guard_candidate} &&
    $(stat -c '%U:%G:%a:%h' -- "${guard_candidate}") == root:root:700:1 &&
    -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
    $(stat -c '%U:%G:%a:%h' -- "${RECOVERY_CLEAR_FENCE}") == root:root:644:1 &&
    $(<"${RECOVERY_CLEAR_FENCE}") == "${expected_fence}" ]] || {
    printf '%s\n' 'fixture refused to disarm an unsafe Host recovery fence' >&2
    exit 1
  }
  rm -f -- "${RECOVERY_CLEAR_FENCE}"
  sync -f "${RECOVERY_CLEAR_FENCE_DIR}"
  /usr/bin/systemctl daemon-reload >/dev/null
  [[ $(/usr/bin/systemctl show autostream-host-agent.service \
    --property=NeedDaemonReload --value) == no &&
    -z $(/usr/bin/systemctl show autostream-host-agent.service \
      --property=DropInPaths --value) ]] || {
    printf '%s\n' 'fixture systemd reload retained the Host recovery fence' >&2
    exit 1
  }
  /usr/bin/systemctl stop \
    autostream-host-agent-upgrade-recovery-guard.timer >/dev/null
  /usr/bin/systemctl stop \
    autostream-host-agent-upgrade-recovery-guard.service >/dev/null
  wait_for_guard_worker_exit
  [[ $(readlink -f -- "${guard_directory}") == "${guard_directory}" &&
    $(stat -c '%U:%G:%a' -- "${guard_directory}") == root:root:700 &&
    -f ${guard_candidate} && ! -L ${guard_candidate} &&
    $(stat -c '%U:%G:%a:%h' -- "${guard_candidate}") == root:root:700:1 ]] || {
    printf '%s\n' 'fixture refused to remove a changed Host recovery guard candidate' >&2
    exit 1
  }
  rm -f -- "${guard_candidate}"
  rmdir -- "${guard_directory}"
  assert_guard_candidate_directory_cleaned
}

cleanup_fired_guard_candidate_fixture() {
  local guard_candidate
  local guard_directory
  mapfile -t guard_candidates < <(find /run -mindepth 1 -maxdepth 1 \
    -type d -name 'autostream-host-agent-upgrade-guard.*' -print)
  [[ ${#guard_candidates[@]} -eq 1 ]] || {
    printf '%s\n' 'self-fire cleanup requires exactly one guard candidate' >&2
    exit 1
  }
  guard_directory=${guard_candidates[0]}
  guard_candidate="${guard_directory}/autostream-local-executor"
  [[ $(readlink -f -- "${guard_directory}") == "${guard_directory}" &&
    $(stat -c '%U:%G:%a' -- "${guard_directory}") == root:root:700 &&
    -f ${guard_candidate} && ! -L ${guard_candidate} &&
    $(stat -c '%U:%G:%a:%h' -- "${guard_candidate}") == root:root:700:1 &&
    $(sha256sum -- "${guard_candidate}" | awk 'NR == 1 { print $1 }') == \
      "$(sha256sum -- "${PACKAGE_ROOT}/bin/autostream-local-executor" | awk 'NR == 1 { print $1 }')" ]] || {
    printf '%s\n' 'self-fire cleanup refused a changed guard candidate' >&2
    exit 1
  }
  rm -f -- "${guard_candidate}"
  rmdir -- "${guard_directory}"
}

cleanup_abandoned_recovery_candidate_fixture() {
  local candidate
  local directory
  mapfile -t recovery_candidates < <(find /run -mindepth 1 -maxdepth 1 \
    -type d -name 'autostream-host-agent-recovery.*' -print)
  [[ ${#recovery_candidates[@]} -eq 1 ]] || {
    printf '%s\n' 'wrapper SIGKILL did not leave exactly one recovery candidate' >&2
    exit 1
  }
  directory=${recovery_candidates[0]}
  candidate="${directory}/autostream-host-agent"
  [[ $(readlink -f -- "${directory}") == "${directory}" &&
    $(stat -c '%U:%G:%a' -- "${directory}") == root:autostream-host-agent:750 &&
    -f ${candidate} && ! -L ${candidate} &&
    $(stat -c '%U:%G:%a:%h' -- "${candidate}") == root:autostream-host-agent:750:1 &&
    $(sha256sum -- "${candidate}" | awk 'NR == 1 { print $1 }') == \
      "$(sha256sum -- "${PACKAGE_ROOT}/bin/autostream-host-agent" | awk 'NR == 1 { print $1 }')" ]] || {
    printf '%s\n' 'wrapper SIGKILL left an unsafe recovery candidate' >&2
    exit 1
  }
  rm -f -- "${candidate}"
  rmdir -- "${directory}"
}

cleanup_abandoned_private_stage_fixture() {
  local stage
  mapfile -t abandoned_stages < <(find /var/tmp -mindepth 1 -maxdepth 1 \
    -type d -name 'autostream-host-agent-install.*' -print)
  [[ ${#abandoned_stages[@]} -eq 1 ]] || {
    printf '%s\n' 'wrapper SIGKILL did not leave exactly one private bundle stage' >&2
    exit 1
  }
  stage=${abandoned_stages[0]}
  [[ ${stage} == /var/tmp/autostream-host-agent-install.* &&
    $(readlink -f -- "${stage}") == "${stage}" &&
    $(stat -c '%U:%G:%a' -- "${stage}") == root:root:700 ]] || {
    printf '%s\n' 'wrapper SIGKILL left an unsafe private bundle stage' >&2
    exit 1
  }
  rm -rf -- "${stage}"
  [[ ! -e ${stage} && ! -L ${stage} ]] || {
    printf '%s\n' 'could not remove the exact abandoned private bundle stage' >&2
    exit 1
  }
}

assert_recovery_invocation() {
  local agent_uid
  agent_uid="$(id -u autostream-host-agent)"
  [[ -f ${RECOVERY_LOG} && ! -L ${RECOVERY_LOG} &&
    $(stat -c '%U:%G:%a' -- "${RECOVERY_LOG}") == \
      autostream-host-agent:autostream-host-agent:600 ]] || {
    printf '%s\n' 'recovery candidate did not create a safe invocation record' >&2
    exit 1
  }
  grep -Fx -- "uid=${agent_uid}" "${RECOVERY_LOG}" >/dev/null
  grep -Fx -- \
    'argv=recover-update --config /etc/autostream/updater/agent.yaml' \
    "${RECOVERY_LOG}" >/dev/null
  grep -E -- \
    '^executable=/run/autostream-host-agent-recovery\.[A-Za-z0-9]+/autostream-host-agent$' \
    "${RECOVERY_LOG}" >/dev/null
  [[ -f ${RECOVERY_ENV_LOG} && ! -L ${RECOVERY_ENV_LOG} &&
    $(stat -c '%U:%G:%a' -- "${RECOVERY_ENV_LOG}") == \
      autostream-host-agent:autostream-host-agent:600 ]] || {
    printf '%s\n' 'recovery candidate did not record its sanitized environment safely' >&2
    exit 1
  }
  grep -Fx -- 'HOME=/nonexistent' "${RECOVERY_ENV_LOG}" >/dev/null
  grep -Fx -- 'LC_ALL=C' "${RECOVERY_ENV_LOG}" >/dev/null
  grep -Fx -- 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' "${RECOVERY_ENV_LOG}" >/dev/null
  if grep -Eqi -- \
    'proxy=|ssl_cert|ca_bundle|runtime[_-]?token|configure[_-]?token|runtime_fixture' \
    "${RECOVERY_ENV_LOG}"; then
    printf '%s\n' 'recovery candidate inherited a proxy, TLS, secret, or fixture variable' >&2
    exit 1
  fi
  for recovery_output_path in \
    "${RECOVERY_LOG}" "${RECOVERY_ENV_LOG}" "${HELPER_LOG}" "${SYSTEMD_RUN_LOG}"; do
    if [[ -f ${recovery_output_path} && ! -L ${recovery_output_path} ]] &&
      grep -Eqi -- 'runtime[_-]?token|configure.token|--job|sentinel-token' \
        "${recovery_output_path}"; then
      printf '%s\n' 'recovery path exposed a token or accepted a job argument' >&2
      exit 1
    fi
  done
}

assert_recovery_sequence() {
  local expected=$1
  local actual
  actual="$(tr '\n' ' ' < "${RECOVERY_SEQUENCE_LOG}")"
  actual=${actual% }
  [[ ${actual} == "${expected}" ]] || {
    printf 'recovery sequence=%q, want=%q\n' "${actual}" "${expected}" >&2
    exit 1
  }
}

assert_original_runtime_pair_active() {
  local agent_pid
  local executor_pid
  [[ $(readlink -- "${MANAGED_RUNTIME_CURRENT}") == slots/a &&
    $(sha256sum -- "${MANAGED_RUNTIME_AGENT}" | awk 'NR == 1 { print $1 }') == \
      "${ORIGINAL_RUNTIME_AGENT_SHA256}" &&
    $(sha256sum -- "${MANAGED_RUNTIME_EXECUTOR}" | awk 'NR == 1 { print $1 }') == \
      "${ORIGINAL_RUNTIME_EXECUTOR_SHA256}" ]] || {
    printf '%s\n' 'the exact original managed Host runtime pair was not preserved' >&2
    exit 1
  }
  agent_pid="$(/usr/bin/systemctl show \
    autostream-host-agent.service --property=MainPID --value)"
  executor_pid="$(/usr/bin/systemctl show \
    autostream-local-executor.service --property=MainPID --value)"
  [[ ${agent_pid} =~ ^[1-9][0-9]*$ &&
    ${executor_pid} =~ ^[1-9][0-9]*$ &&
    $(readlink -f -- "/proc/${agent_pid}/exe") == "${MANAGED_RUNTIME_AGENT}" &&
    $(readlink -f -- "/proc/${executor_pid}/exe") == "${MANAGED_RUNTIME_EXECUTOR}" ]] || {
    printf '%s\n' 'the running Host services do not use the exact original pair' >&2
    exit 1
  }
}

assert_committed_runtime_pair_active() {
  local agent=/opt/autostream/host-agent/slots/b/bin/autostream-host-agent
  local executor=/opt/autostream/host-agent/slots/b/bin/autostream-local-executor
  local agent_pid
  local executor_pid
  [[ $(readlink -- "${MANAGED_RUNTIME_CURRENT}") == slots/b &&
    $(stat -c '%U:%G:%a:%h' -- "${agent}") == root:root:755:1 &&
    $(stat -c '%U:%G:%a:%h' -- "${executor}") == root:root:755:1 &&
    $(sha256sum -- "${agent}" | awk 'NR == 1 { print $1 }') == \
      "$(sha256sum -- "${PACKAGE_ROOT}/bin/autostream-host-agent" | awk 'NR == 1 { print $1 }')" &&
    $(sha256sum -- "${executor}" | awk 'NR == 1 { print $1 }') == \
      "$(sha256sum -- "${PACKAGE_ROOT}/bin/autostream-local-executor" | awk 'NR == 1 { print $1 }')" ]] || {
    printf '%s\n' 'the committed Host runtime pair is not the exact verified candidate bytes' >&2
    exit 1
  }
  [[ $("${agent}" --version) == $'autostream-host-agent v1.9.11\ncommit: 0123456789abcdef0123456789abcdef01234567\nbuild_date: 2026-07-31T00:00:00Z' &&
    $("${executor}" --version) == $'autostream-local-executor v1.9.11\ncommit: 0123456789abcdef0123456789abcdef01234567\nbuild_date: 2026-07-31T00:00:00Z\nmutation_protocol: 2\nrecovery_protocol: 2' ]] || {
    printf '%s\n' 'the committed Host runtime pair identity is not v1.9.11' >&2
    exit 1
  }
  agent_pid="$(/usr/bin/systemctl show \
    autostream-host-agent.service --property=MainPID --value)"
  executor_pid="$(/usr/bin/systemctl show \
    autostream-local-executor.service --property=MainPID --value)"
  [[ ${agent_pid} =~ ^[1-9][0-9]*$ &&
    ${executor_pid} =~ ^[1-9][0-9]*$ &&
    $(readlink -f -- "/proc/${agent_pid}/exe") == "${agent}" &&
    $(readlink -f -- "/proc/${executor_pid}/exe") == "${executor}" ]] || {
    printf '%s\n' 'the running Host services do not use the committed candidate bytes' >&2
    exit 1
  }
}

assert_recovery_preflight_rejected_without_stop() {
  local label=$1
  local output
  local status=0
  output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || status=$?
  [[ ${status} -ne 0 ]] || {
    printf 'recovery accepted unsafe live pair: %s\n' "${label}" >&2
    exit 1
  }
  assert_no_completion "${output}"
  grep -Fq -- \
    '--recover-active-job requires an exact permitted live Host Agent and Local Executor A/B pair' \
    <<<"${output}" || {
    printf 'unexpected recovery preflight rejection: %s\n' "${label}" >&2
    awk '/^install-autostream-host-agent:/ { last = $0 } END { if (last != "") print last }' \
      <<<"${output}" >&2
    exit 1
  }
  [[ ! -s ${RECOVERY_SEQUENCE_LOG} ]] || {
    printf 'unsafe live pair reached stop or guard operation: %s\n' "${label}" >&2
    exit 1
  }
  assert_helper_not_called
  assert_recovery_candidate_cleaned
}

reset_recovery_fixture
[[ $(/usr/bin/systemctl is-active autostream-local-executor.service) == active ]]
executor_enabled_status=0
executor_enabled_output="$(/usr/bin/systemctl is-enabled \
  autostream-local-executor.service 2>&1)" || executor_enabled_status=$?
[[ ${executor_enabled_status} -ne 0 && ${executor_enabled_output} == disabled ]]
[[ $(/usr/bin/systemctl is-enabled autostream-local-executor.socket) == enabled &&
  $(/usr/bin/systemctl is-active autostream-local-executor.socket) == active ]]
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0700 "${MANAGED_RUNTIME_ROOT}/slots/a/bin"
assert_recovery_preflight_rejected_without_stop 'selected slot bin mode 0700'
chmod 0755 "${MANAGED_RUNTIME_ROOT}/slots/a/bin"
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0700 "${MANAGED_RUNTIME_ROOT}/slots/a"
assert_recovery_preflight_rejected_without_stop 'selected slot mode 0700'
chmod 0755 "${MANAGED_RUNTIME_ROOT}/slots/a"
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0744 "${MANAGED_RUNTIME_AGENT}"
assert_recovery_preflight_rejected_without_stop 'Host Agent binary mode 0744'
chmod 0755 "${MANAGED_RUNTIME_AGENT}"
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0744 "${MANAGED_RUNTIME_EXECUTOR}"
assert_recovery_preflight_rejected_without_stop 'Local Executor binary mode 0744'
chmod 0755 "${MANAGED_RUNTIME_EXECUTOR}"
assert_original_runtime_pair_active

reset_recovery_fixture
chown root:autostream-host-agent "${MANAGED_RUNTIME_EXECUTOR}"
assert_recovery_preflight_rejected_without_stop 'Local Executor binary owner drift'
chown root:root "${MANAGED_RUNTIME_EXECUTOR}"
assert_original_runtime_pair_active

reset_recovery_fixture
ln -sfnT /usr/bin/true "${PUBLIC_EXECUTOR}"
assert_recovery_preflight_rejected_without_stop 'public Local Executor symlink drift'
ln -sfnT \
  "${MANAGED_RUNTIME_CURRENT}/bin/autostream-local-executor" \
  "${PUBLIC_EXECUTOR}"
assert_original_runtime_pair_active

reset_recovery_fixture
export AUTOSTREAM_RUNTIME_FIXTURE_AGENT_VERSION=v1.9.9
export AUTOSTREAM_RUNTIME_FIXTURE_EXECUTOR_VERSION=v1.9.10
assert_recovery_preflight_rejected_without_stop 'mixed v1.9.9/v1.9.10 identity'
unset \
  AUTOSTREAM_RUNTIME_FIXTURE_AGENT_VERSION \
  AUTOSTREAM_RUNTIME_FIXTURE_EXECUTOR_VERSION
assert_original_runtime_pair_active

reset_recovery_fixture
export AUTOSTREAM_RUNTIME_FIXTURE_RECOVERY_PROTOCOL=1
assert_recovery_preflight_rejected_without_stop 'Local Executor recovery protocol 1'
unset AUTOSTREAM_RUNTIME_FIXTURE_RECOVERY_PROTOCOL
assert_original_runtime_pair_active

reset_recovery_fixture
original_executor_pid="$(<"${EXECUTOR_PID_FILE}")"
managed_agent_pid="$(<"${SERVICE_PID_FILE}")"
printf '%s\n' "${managed_agent_pid}" > "${EXECUTOR_PID_FILE}"
assert_recovery_preflight_rejected_without_stop 'Local Executor MainPID executable mismatch'
printf '%s\n' "${original_executor_pid}" > "${EXECUTOR_PID_FILE}"
assert_original_runtime_pair_active

reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_FAIL_MARKER}"
recovery_failure_status=0
recovery_failure_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  recovery_failure_status=$?
[[ ${recovery_failure_status} -eq 74 ]] || {
  printf 'recovery candidate failure status=%s, want=74\n' \
    "${recovery_failure_status}" >&2
  printf '%s\n' "${recovery_failure_output}" >&2
  exit 1
}
assert_no_completion "${recovery_failure_output}"
grep -Fq -- 'exact active Host update recovery failed' \
  <<<"${recovery_failure_output}"
[[ $(<"${RECOVERY_STATE}") == active ]]
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active

export AUTOSTREAM_RUNTIME_FIXTURE_VERSION=v1.9.10
reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_FAIL_MARKER}"
v1910_failure_status=0
v1910_failure_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  v1910_failure_status=$?
[[ ${v1910_failure_status} -eq 74 ]] || {
  printf 'v1.9.10 recovery candidate failure status=%s, want=74\n' \
    "${v1910_failure_status}" >&2
  printf '%s\n' "${v1910_failure_output}" >&2
  exit 1
}
assert_no_completion "${v1910_failure_output}"
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active
export AUTOSTREAM_RUNTIME_FIXTURE_VERSION=v1.9.9

reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_FAIL_WITH_LIFECYCLE_LOCK_MARKER}"
lifecycle_contention_status=0
lifecycle_contention_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  lifecycle_contention_status=$?
[[ ${lifecycle_contention_status} -ne 0 ]] || {
  printf '%s\n' 'recovery cleanup ignored lifecycle lock contention' >&2
  exit 1
}
assert_no_completion "${lifecycle_contention_output}"
grep -Fq -- \
  'could not reacquire the canonical Host setup and lifecycle locks' \
  <<<"${lifecycle_contention_output}"
grep -Fq -- \
  'the durable recovery fence and systemd guard were retained' \
  <<<"${lifecycle_contention_output}"
[[ $(<"${RECOVERY_STATE}") == active ]]
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent lifecycle-lock-held'
assert_fail_closed_recovery_guard
release_recovery_lock_holder \
  "${RECOVERY_LIFECYCLE_HOLD_RELEASE}" \
  "${RECOVERY_LIFECYCLE_HOLD_READY}"
disarm_recovery_guard_fixture

reset_recovery_fixture
install -o root -g root -m 0600 /dev/null "${HELPER_FAIL_MARKER}"
manual_failure_status=0
manual_failure_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  manual_failure_status=$?
[[ ${manual_failure_status} -eq 73 ]] || {
  printf 'post-recovery manual upgrade failure status=%s, want=73\n' \
    "${manual_failure_status}" >&2
  printf '%s\n' "${manual_failure_output}" >&2
  exit 1
}
assert_no_completion "${manual_failure_output}"
grep -Fq -- 'managed Host runtime upgrade failed' <<<"${manual_failure_output}"
[[ $(<"${RECOVERY_STATE}") == inactive ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active

reset_recovery_fixture
install -o root -g root -m 0600 /dev/null "${HELPER_PARTIAL_SWITCH_MARKER}"
partial_switch_status=0
partial_switch_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  partial_switch_status=$?
[[ ${partial_switch_status} -ne 0 ]] || {
  printf '%s\n' 'partial A/B switch unexpectedly completed recovery upgrade' >&2
  exit 1
}
assert_no_completion "${partial_switch_output}"
grep -Fq -- 'managed Host runtime upgrade failed' <<<"${partial_switch_output}"
grep -Fq -- \
  'the pre-stop Host runtime pair was not restored; the durable recovery fence and systemd guard were retained' \
  <<<"${partial_switch_output}"
[[ $(<"${RECOVERY_STATE}") == inactive &&
  $(readlink -- "${MANAGED_RUNTIME_CURRENT}") == slots/b ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade'
assert_fail_closed_recovery_guard
ln -sfnT slots/a "${MANAGED_RUNTIME_CURRENT}"
rm -f -- "${HELPER_PARTIAL_SWITCH_MARKER}"
disarm_recovery_guard_fixture
assert_original_runtime_pair_active

reset_recovery_fixture
install -o root -g root -m 0600 /dev/null "${HELPER_FAIL_WITH_LOCK_MARKER}"
full_contention_status=0
full_contention_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  full_contention_status=$?
[[ ${full_contention_status} -ne 0 ]] || {
  printf '%s\n' 'post-recovery cleanup ignored setup/lifecycle lock contention' >&2
  exit 1
}
assert_no_completion "${full_contention_output}"
grep -Fq -- \
  'could not reacquire the canonical Host setup and lifecycle locks' \
  <<<"${full_contention_output}"
grep -Fq -- \
  'the durable recovery fence and systemd guard were retained' \
  <<<"${full_contention_output}"
[[ $(<"${RECOVERY_STATE}") == inactive ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade full-locks-held'
assert_fail_closed_recovery_guard
release_recovery_lock_holder \
  "${RECOVERY_FULL_HOLD_RELEASE}" \
  "${RECOVERY_FULL_HOLD_READY}"
disarm_recovery_guard_fixture

reset_recovery_fixture
exec 7<>/run/autostream-updater/.autostream-runtime-host-setup.lock
flock -n 7
lock_conflict_status=0
lock_conflict_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  lock_conflict_status=$?
[[ ${lock_conflict_status} -ne 0 ]] || {
  printf '%s\n' 'recovery ignored a concurrent Host runtime setup lock' >&2
  exit 1
}
grep -Fq -- 'another AutoStream installer is provisioning shared host state' \
  <<<"${lock_conflict_output}"
[[ ! -s ${RECOVERY_SEQUENCE_LOG} ]]
assert_helper_not_called
flock -u 7
exec 7>&-
assert_recovery_candidate_cleaned

reset_recovery_fixture
install -d -o root -g root -m 0755 /run/systemd/transient
printf '%s\n' conflicting > "${RECOVERY_GUARD_TIMER_PATH}"
chown root:root "${RECOVERY_GUARD_TIMER_PATH}"
chmod 0644 "${RECOVERY_GUARD_TIMER_PATH}"
conflict_status=0
conflict_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  conflict_status=$?
[[ ${conflict_status} -ne 0 ]] || {
  printf '%s\n' 'recovery accepted a conflicting transient guard path' >&2
  exit 1
}
grep -Fq -- 'recovery guard timer already exists or is unsafe' \
  <<<"${conflict_output}"
[[ ! -s ${RECOVERY_SEQUENCE_LOG} ]]
assert_helper_not_called
rm -f -- "${RECOVERY_GUARD_TIMER_PATH}"
assert_recovery_candidate_cleaned

# Prove that the transient recovery guard is an independent recovery path: the
# installer wrapper is killed while its service-owned recovery process is
# blocked, then only the delayed guard is allowed to restart the exact old pair.
reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_BLOCK_MARKER}"
"${INSTALLER}" --upgrade --recover-active-job \
  >"${GUARD_SELF_FIRE_OUTPUT}" 2>&1 &
guard_self_fire_wrapper_pid=$!
for ((attempt = 0; attempt < 400; attempt++)); do
  if [[ -f ${RECOVERY_BLOCK_READY} && ! -L ${RECOVERY_BLOCK_READY} &&
    -f ${GUARD_TIMER_ACTIVE_MARKER} && ! -L ${GUARD_TIMER_ACTIVE_MARKER} &&
    -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
    $(/usr/bin/systemctl is-active autostream-host-agent.service 2>/dev/null || true) == \
      inactive ]]; then
    break
  fi
  if ! kill -0 "${guard_self_fire_wrapper_pid}" 2>/dev/null; then
    printf '%s\n' 'installer exited before the recovery guard self-fire fixture was ready' >&2
    sed -n '1,160p' "${GUARD_SELF_FIRE_OUTPUT}" >&2
    exit 1
  fi
  sleep 0.025
done
[[ -f ${RECOVERY_BLOCK_READY} && ! -L ${RECOVERY_BLOCK_READY} &&
  -f ${GUARD_TIMER_ACTIVE_MARKER} && ! -L ${GUARD_TIMER_ACTIVE_MARKER} &&
  -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} ]] || {
  printf '%s\n' 'timed out waiting for the recovery guard self-fire fixture' >&2
  exit 1
}
guard_self_fire_candidate_pid="$(<"${RECOVERY_BLOCK_READY}")"
[[ ${guard_self_fire_candidate_pid} =~ ^[1-9][0-9]*$ &&
  -d /proc/${guard_self_fire_candidate_pid} ]] || {
  printf '%s\n' 'recovery guard self-fire fixture recorded an invalid candidate PID' >&2
  exit 1
}
kill -KILL "${guard_self_fire_wrapper_pid}"
guard_self_fire_wrapper_status=0
wait "${guard_self_fire_wrapper_pid}" || guard_self_fire_wrapper_status=$?
[[ ${guard_self_fire_wrapper_status} -eq 137 ]] || {
  printf 'SIGKILLed installer status=%s, want=137\n' \
    "${guard_self_fire_wrapper_status}" >&2
  exit 1
}
kill -TERM "${guard_self_fire_candidate_pid}"
rm -f -- "${RECOVERY_BLOCK_MARKER}"
for ((attempt = 0; attempt < 400; attempt++)); do
  if [[ ! -d /proc/${guard_self_fire_candidate_pid} ]] ||
    [[ $(awk '{ print $3 }' "/proc/${guard_self_fire_candidate_pid}/stat" \
      2>/dev/null || true) == Z ]]; then
    break
  fi
  sleep 0.025
done
if [[ -d /proc/${guard_self_fire_candidate_pid} &&
  $(awk '{ print $3 }' "/proc/${guard_self_fire_candidate_pid}/stat" \
    2>/dev/null || true) != Z ]]; then
  printf '%s\n' 'service-owned recovery candidate survived wrapper SIGKILL cleanup' >&2
  exit 1
fi
guard_self_fire_locks_ready=false
for ((attempt = 0; attempt < 400; attempt++)); do
  exec 10<>"${RECOVERY_SETUP_LOCK}"
  if flock -n 10; then
    exec 11<>"${RECOVERY_LIFECYCLE_LOCK}"
    if flock -n 11; then
      flock -u 11
      exec 11>&-
      flock -u 10
      exec 10>&-
      guard_self_fire_locks_ready=true
      break
    fi
    exec 11>&-
    flock -u 10
  fi
  exec 10>&-
  sleep 0.025
done
[[ ${guard_self_fire_locks_ready} == true ]] || {
  printf '%s\n' 'wrapper SIGKILL left a Host setup or lifecycle lock held' >&2
  exit 1
}
install -o root -g root -m 0600 /dev/null "${GUARD_FIRE_TRIGGER}"
for ((attempt = 0; attempt < 400; attempt++)); do
  [[ -f ${GUARD_FIRE_STATUS} && ! -L ${GUARD_FIRE_STATUS} ]] && break
  sleep 0.025
done
[[ -f ${GUARD_FIRE_STATUS} && ! -L ${GUARD_FIRE_STATUS} &&
  $(stat -c '%U:%G:%a' -- "${GUARD_FIRE_STATUS}") == root:root:600 &&
  $(<"${GUARD_FIRE_STATUS}") == 0 &&
  $(<"${RECOVERY_STATE}") == active &&
  ! -e ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} ]] || {
  printf '%s\n' 'independent recovery guard did not restart the exact old runtime' >&2
  exit 1
}
assert_no_completion "$(<"${GUARD_SELF_FIRE_OUTPUT}")"
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent guard-helper start-agent'
assert_original_runtime_pair_active
/usr/bin/systemctl stop \
  autostream-host-agent-upgrade-recovery-guard.timer >/dev/null
/usr/bin/systemctl stop \
  autostream-host-agent-upgrade-recovery-guard.service >/dev/null
wait_for_guard_worker_exit
cleanup_fired_guard_candidate_fixture
cleanup_abandoned_recovery_candidate_fixture
cleanup_abandoned_private_stage_fixture
rm -f -- \
  "${RECOVERY_BLOCK_READY}" \
  "${GUARD_FIRE_TRIGGER}" \
  "${GUARD_FIRE_STATUS}" \
  "${GUARD_SELF_FIRE_OUTPUT}"
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active

reset_recovery_fixture
recovery_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)"
grep -Fq -- "${COMPLETION}" <<<"${recovery_output}"
grep -Fq -- "Verified Host Agent bundle archive SHA-256: ${EXPECTED_ARCHIVE_SHA256}" \
  <<<"${recovery_output}"
[[ $(<"${RECOVERY_STATE}") == inactive ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade restart-executor start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_committed_runtime_pair_active

if fixture_pid="$(<"${SERVICE_PID_FILE}")" && \
  [[ ${fixture_pid} =~ ^[1-9][0-9]*$ ]]; then
  kill -TERM "${fixture_pid}" 2>/dev/null || true
fi
if executor_fixture_pid="$(<"${EXECUTOR_PID_FILE}")" &&
  [[ ${executor_fixture_pid} =~ ^[1-9][0-9]*$ ]]; then
  kill -TERM "${executor_fixture_pid}" 2>/dev/null || true
fi
kill -TERM "${LOCAL_EXECUTOR_LOCK_DAEMON_PID}" 2>/dev/null || true
wait "${LOCAL_EXECUTOR_LOCK_DAEMON_PID}" 2>/dev/null || true
if [[ -f ${SYSTEMCTL_BACKUP} && ! -L ${SYSTEMCTL_BACKUP} ]]; then
  install -o root -g root -m 0755 "${SYSTEMCTL_BACKUP}" /usr/bin/systemctl
fi
if [[ -f ${SYSTEMD_RUN_BACKUP} && ! -L ${SYSTEMD_RUN_BACKUP} ]]; then
  install -o root -g root -m 0755 "${SYSTEMD_RUN_BACKUP}" /usr/bin/systemd-run
fi
rm -f -- "${SYSTEMCTL_LOG}" "${SYSTEMD_RUN_LOG}"

run_wrapper_signal_case failure false 75
run_wrapper_signal_case success true 0

rm -f -- "${HELPER_LOG}"
upgrade_output="$("${INSTALLER}" --upgrade 2>&1)"
grep -Fq -- "${COMPLETION}" <<<"${upgrade_output}"
grep -Fq -- "Verified Host Agent bundle archive SHA-256: ${EXPECTED_ARCHIVE_SHA256}" \
  <<<"${upgrade_output}"
assert_helper_arguments
assert_private_stage_cleaned
assert_sentinels_unchanged
