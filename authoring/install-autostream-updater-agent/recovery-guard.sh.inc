
active_job_recovery_service_is_inactive() {
  local active_state
  local main_pid
  active_state="$(${SYSTEMCTL_PATH} show "${UNIT_NAME}" --property=ActiveState --value 2>/dev/null)" || return 1
  main_pid="$(${SYSTEMCTL_PATH} show "${UNIT_NAME}" --property=MainPID --value 2>/dev/null)" || return 1
  [[ ${active_state} == "inactive" && ${main_pid} == "0" ]]
}

active_job_recovery_guard_candidate_is_intact() {
  [[ -n ${active_job_recovery_guard_candidate_dir} &&
    ${active_job_recovery_guard_candidate_dir} == \
      "${ACTIVE_JOB_RECOVERY_GUARD_CANDIDATE_PREFIX}"* &&
    -d ${active_job_recovery_guard_candidate_dir} &&
    ! -L ${active_job_recovery_guard_candidate_dir} &&
    $(readlink -f -- "${active_job_recovery_guard_candidate_dir}") == \
      "${active_job_recovery_guard_candidate_dir}" &&
    $(stat -c '%U:%G:%a' -- "${active_job_recovery_guard_candidate_dir}") == \
      "root:root:700" &&
    $(stat -c '%d:%i' -- "${active_job_recovery_guard_candidate_dir}") == \
      "${active_job_recovery_guard_candidate_dir_identity}" &&
    ${active_job_recovery_guard_candidate_path} == \
      "${active_job_recovery_guard_candidate_dir}/autostream-local-executor" &&
    -f ${active_job_recovery_guard_candidate_path} &&
    ! -L ${active_job_recovery_guard_candidate_path} &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
      "${active_job_recovery_guard_candidate_path}") == \
      "${active_job_recovery_guard_candidate_identity}" &&
    $(stat -c '%U:%G:%a:%h' -- \
      "${active_job_recovery_guard_candidate_path}") == "root:root:700:1" &&
    $(sha256sum -- "${active_job_recovery_guard_candidate_path}" |
      awk 'NR == 1 { print $1 }') == \
      "${active_job_recovery_guard_candidate_sha256}" ]]
}

prepare_active_job_recovery_guard_candidate() {
  local source_identity
  local source_sha256
  validate_root_parent_chain "/run/autostream-host-agent-upgrade-guard.placeholder" \
    "Host Agent delayed recovery guard"
  source_identity="$(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
    "${LOCAL_EXECUTOR_BINARY_SOURCE}")" || \
    die "could not record the delayed recovery Executor source identity"
  source_sha256="$(sha256sum -- "${LOCAL_EXECUTOR_BINARY_SOURCE}" |
    awk 'NR == 1 { print $1 }')" || \
    die "could not hash the delayed recovery Executor source"
  [[ ${source_sha256} == "${VERIFIED_EXECUTOR_SOURCE_SHA256}" ]] || \
    die "delayed recovery Executor source differs from the verified bundle"

  defer_cleanup_signals
  active_job_recovery_guard_candidate_dir="$(
    mktemp -d "${ACTIVE_JOB_RECOVERY_GUARD_CANDIDATE_PREFIX}XXXXXXXX"
  )" || die "could not create the delayed recovery guard directory"
  resume_cleanup_signals || \
    die "installation was interrupted while creating the delayed recovery guard"
  active_job_recovery_guard_candidate_path="${active_job_recovery_guard_candidate_dir}/autostream-local-executor"
  install -o root -g root -m 0700 \
    "${LOCAL_EXECUTOR_BINARY_SOURCE}" \
    "${active_job_recovery_guard_candidate_path}"
  sync -f "${active_job_recovery_guard_candidate_path}"
  sync -f "${active_job_recovery_guard_candidate_dir}"
  [[ -f ${LOCAL_EXECUTOR_BINARY_SOURCE} &&
    ! -L ${LOCAL_EXECUTOR_BINARY_SOURCE} &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
      "${LOCAL_EXECUTOR_BINARY_SOURCE}") == "${source_identity}" &&
    $(sha256sum -- "${LOCAL_EXECUTOR_BINARY_SOURCE}" |
      awk 'NR == 1 { print $1 }') == "${source_sha256}" ]] || \
    die "verified delayed recovery Executor source changed while copying"
  active_job_recovery_guard_candidate_dir_identity="$(stat -c '%d:%i' -- \
    "${active_job_recovery_guard_candidate_dir}")" || \
    die "could not record the delayed recovery guard directory identity"
  active_job_recovery_guard_candidate_identity="$(
    stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
      "${active_job_recovery_guard_candidate_path}"
  )" || die "could not record the delayed recovery guard identity"
  active_job_recovery_guard_candidate_sha256=${source_sha256}
  active_job_recovery_guard_candidate_is_intact || \
    die "delayed recovery guard candidate is unsafe"
}

active_job_recovery_clear_fence_is_intact() {
  local expected_content
  expected_content="$(printf '%s\n' \
    '[Unit]' \
    "ConditionPathExists=!${ACTIVE_JOB_RECOVERY_CLEAR_MARKER}" \
    "ConditionFileIsExecutable=${active_job_recovery_guard_candidate_path}")"
  [[ ${active_job_recovery_clear_fence_installed} == true &&
    -f ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE} &&
    ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE} &&
    $(readlink -f -- "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}") == \
      "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}" &&
    $(stat -c '%U:%G:%a:%h' -- "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}") == \
      "root:root:644:1" &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
      "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}") == \
      "${active_job_recovery_clear_fence_identity}" &&
    $(sha256sum -- "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}" |
      awk 'NR == 1 { print $1 }') == \
      "${active_job_recovery_clear_fence_sha256}" &&
    $(<"${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}") == "${expected_content}" ]]
}

active_job_recovery_clear_fence_is_loaded() {
  local drop_in
  local drop_ins
  drop_ins="$(${SYSTEMCTL_PATH} show "${UNIT_NAME}" \
    --property=DropInPaths --value 2>/dev/null)" || return 1
  for drop_in in ${drop_ins}; do
    [[ ${drop_in} == "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}" ]] && return 0
  done
  return 1
}

install_active_job_recovery_clear_fence() {
  local temporary_fence
  [[ ! -e ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} &&
    ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} ]] || \
    die "Host Agent journal clear fence already blocks legacy Agent restart"
  active_job_recovery_guard_candidate_is_intact || \
    die "delayed recovery guard candidate changed before fence installation"
  validate_root_parent_chain "${UNIT_DEST}" "Host Agent recovery drop-in"
  if [[ -e ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR} ||
    -L ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR} ]]; then
    [[ -d ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR} &&
      ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR} &&
      $(readlink -f -- "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}") == \
        "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}" &&
      $(stat -c '%U:%G:%a' -- "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}") == \
        "root:root:755" ]] || \
      die "Host Agent recovery drop-in directory is unsafe"
  else
    install -d -o root -g root -m 0755 \
      "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}"
    sync -f "$(dirname -- "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}")"
  fi
  [[ ! -e ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE} &&
    ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE} ]] || \
    die "Host Agent delayed recovery fence already exists"
  temporary_fence="$(mktemp \
    "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}/.90-autostream-upgrade-recovery-guard.XXXXXXXX")" || \
    die "could not create the Host Agent delayed recovery fence"
  printf '%s\n' \
    '[Unit]' \
    "ConditionPathExists=!${ACTIVE_JOB_RECOVERY_CLEAR_MARKER}" \
    "ConditionFileIsExecutable=${active_job_recovery_guard_candidate_path}" \
    >"${temporary_fence}"
  chown root:root "${temporary_fence}"
  chmod 0644 "${temporary_fence}"
  sync -f "${temporary_fence}"
  mv -- "${temporary_fence}" "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}"
  active_job_recovery_clear_fence_installed=true
  active_job_recovery_clear_fence_identity="$(
    stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
      "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}"
  )" || die "could not record the Host Agent delayed recovery fence identity"
  active_job_recovery_clear_fence_sha256="$(sha256sum -- \
    "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}" | awk 'NR == 1 { print $1 }')" || \
    die "could not hash the Host Agent delayed recovery fence"
  sync -f "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}"
  active_job_recovery_clear_fence_is_intact || \
    die "Host Agent delayed recovery fence is unsafe"
  ${SYSTEMCTL_PATH} daemon-reload
  [[ $(${SYSTEMCTL_PATH} show "${UNIT_NAME}" \
    --property=NeedDaemonReload --value 2>/dev/null) == "no" ]] || \
    die "systemd did not load the Host Agent delayed recovery fence"
  active_job_recovery_clear_fence_is_loaded || \
    die "systemd did not report the Host Agent delayed recovery fence"
  [[ ! -e ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} &&
    ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} ]] || \
    die "Host Agent journal clear fence appeared before service stop"
}

active_job_recovery_guard_unit_load_state() {
  local unit=$1
  ${SYSTEMCTL_PATH} show "${unit}" --property=LoadState --value 2>/dev/null
}

active_job_recovery_guard_unit_is_absent() {
  local unit=$1
  local path=$2
  local load_state
  load_state="$(active_job_recovery_guard_unit_load_state "${unit}")" || return 1
  [[ ${load_state} == "not-found" && ! -e ${path} && ! -L ${path} ]]
}

validate_active_job_recovery_guard_fragment() {
  local unit=$1
  local path=$2
  local fragment_path
  local mode
  [[ -f ${path} && ! -L ${path} &&
    $(readlink -f -- "${path}") == "${path}" &&
    $(stat -c '%U:%G:%h' -- "${path}") == "root:root:1" ]] || \
    return 1
  mode=$(stat -c '%a' -- "${path}") || return 1
  (( (8#${mode} & 0022) == 0 )) || return 1
  fragment_path="$(${SYSTEMCTL_PATH} show "${unit}" --property=FragmentPath --value 2>/dev/null)" || \
    return 1
  [[ ${fragment_path} == "${path}" ]]
}

arm_active_job_recovery_guard() {
  local expected_slot
  local timer_state
  [[ ${active_job_recovery_original_current_target} == "slots/a" ||
    ${active_job_recovery_original_current_target} == "slots/b" ]] || \
    die "pre-stop Host runtime slot is unavailable for the recovery guard"
  expected_slot=${active_job_recovery_original_current_target#slots/}
  active_job_recovery_guard_candidate_is_intact || \
    die "delayed recovery guard candidate changed before timer activation"
  active_job_recovery_clear_fence_is_intact || \
    die "Host Agent delayed recovery fence changed before timer activation"
  active_job_recovery_clear_fence_is_loaded || \
    die "Host Agent delayed recovery fence is not loaded"
  [[ ! -e ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} &&
    ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} ]] || \
    die "Host Agent journal clear fence blocks recovery guard activation"
  active_job_recovery_guard_unit_is_absent \
    "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE}" \
    "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE_PATH}" || \
    die "Host Agent recovery guard service already exists or is unsafe"
  active_job_recovery_guard_unit_is_absent \
    "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}" \
    "${ACTIVE_JOB_RECOVERY_GUARD_TIMER_PATH}" || \
    die "Host Agent recovery guard timer already exists or is unsafe"

  if ! ${SYSTEMD_RUN_PATH} \
    --quiet \
    --collect \
    --unit="${ACTIVE_JOB_RECOVERY_GUARD_BASE}" \
    --on-active="${ACTIVE_JOB_RECOVERY_GUARD_DELAY}" \
    --timer-property=AccuracySec=1s \
    "${active_job_recovery_guard_candidate_path}" \
      guard-restart-host-agent \
      --expected-slot "${expected_slot}" \
      --agent-sha256 "${active_job_recovery_original_agent_sha256}" \
      --executor-sha256 "${active_job_recovery_original_executor_sha256}"; then
    if ! active_job_recovery_guard_unit_is_absent \
      "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE}" \
      "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE_PATH}" || \
      ! active_job_recovery_guard_unit_is_absent \
        "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}" \
        "${ACTIVE_JOB_RECOVERY_GUARD_TIMER_PATH}"; then
      active_job_recovery_guard_armed=true
    fi
    die "could not arm the Host Agent recovery guard"
  fi
  active_job_recovery_guard_armed=true
  validate_active_job_recovery_guard_fragment \
    "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE}" \
    "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE_PATH}" || \
    die "Host Agent recovery guard service identity is unsafe"
  validate_active_job_recovery_guard_fragment \
    "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}" \
    "${ACTIVE_JOB_RECOVERY_GUARD_TIMER_PATH}" || \
    die "Host Agent recovery guard timer identity is unsafe"
  timer_state="$(${SYSTEMCTL_PATH} is-active "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}" 2>/dev/null)" || \
    die "Host Agent recovery guard timer did not become active"
  [[ ${timer_state} == "active" ]] || \
    die "Host Agent recovery guard timer did not become active"
}

disarm_active_job_recovery_guard() {
  local attempt
  local load_state
  local active_state
  [[ ${active_job_recovery_guard_armed} == true ]] || return 0
  active_job_recovery_service_is_managed || {
    printf '%s\n' \
      'install-autostream-host-agent: refusing to disarm the recovery guard before the Host Agent is active' >&2
    return 1
  }
  load_state="$(active_job_recovery_guard_unit_load_state \
    "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}")" || return 1
  if [[ ${load_state} != "not-found" ]]; then
    ${SYSTEMCTL_PATH} stop "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}" >/dev/null || return 1
  fi
  load_state="$(active_job_recovery_guard_unit_load_state \
    "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE}")" || return 1
  if [[ ${load_state} != "not-found" ]]; then
    ${SYSTEMCTL_PATH} stop "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE}" >/dev/null || return 1
  fi
  active_state="$(${SYSTEMCTL_PATH} show \
    "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}" --property=ActiveState --value 2>/dev/null)" || \
    return 1
  [[ ${active_state} == "inactive" ]] || return 1
  for attempt in {1..40}; do
    if active_job_recovery_guard_unit_is_absent \
      "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE}" \
      "${ACTIVE_JOB_RECOVERY_GUARD_SERVICE_PATH}" && \
      active_job_recovery_guard_unit_is_absent \
        "${ACTIVE_JOB_RECOVERY_GUARD_TIMER}" \
        "${ACTIVE_JOB_RECOVERY_GUARD_TIMER_PATH}"; then
      active_job_recovery_guard_armed=false
      return 0
    fi
    sleep 0.05
  done
  printf '%s\n' \
    'install-autostream-host-agent: systemd did not collect the recovery guard units' >&2
  return 1
}

remove_active_job_recovery_clear_fence() {
  [[ ${active_job_recovery_clear_fence_installed} == true ]] || return 0
  active_job_recovery_service_is_managed || return 1
  [[ ! -e ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} &&
    ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_MARKER} ]] || return 1
  active_job_recovery_guard_candidate_is_intact || return 1
  active_job_recovery_clear_fence_is_intact || return 1
  active_job_recovery_clear_fence_is_loaded || return 1
  rm -f -- "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE}" || return 1
  sync -f "${ACTIVE_JOB_RECOVERY_CLEAR_FENCE_DIR}" || return 1
  ${SYSTEMCTL_PATH} daemon-reload || return 1
  [[ $(${SYSTEMCTL_PATH} show "${UNIT_NAME}" \
    --property=NeedDaemonReload --value 2>/dev/null) == "no" ]] || return 1
  if active_job_recovery_clear_fence_is_loaded; then
    return 1
  fi
  [[ ! -e ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE} &&
    ! -L ${ACTIVE_JOB_RECOVERY_CLEAR_FENCE} ]] || return 1
  active_job_recovery_clear_fence_installed=false
  active_job_recovery_clear_fence_identity=""
  active_job_recovery_clear_fence_sha256=""
}
