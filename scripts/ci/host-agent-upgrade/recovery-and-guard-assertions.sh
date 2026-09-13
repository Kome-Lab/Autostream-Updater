
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
