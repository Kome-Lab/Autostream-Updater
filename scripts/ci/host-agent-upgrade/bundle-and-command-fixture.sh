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
