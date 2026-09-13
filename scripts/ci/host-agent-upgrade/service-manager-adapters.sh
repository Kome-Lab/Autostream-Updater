
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
