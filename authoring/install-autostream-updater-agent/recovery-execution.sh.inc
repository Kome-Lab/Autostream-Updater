
prepare_active_job_recovery_candidate() {
  local agent_gid
  local agent_uid
  local source_identity
  local source_sha256
  agent_uid="$(id -u "${AGENT_USER}")" || \
    die "Host Agent service account is unavailable"
  agent_gid="$(getent group "${AGENT_GROUP}" | awk -F: 'NR == 1 { print $3 }')" || \
    die "Host Agent service group is unavailable"
  [[ ${agent_uid} =~ ^[1-9][0-9]*$ &&
    ${agent_gid} =~ ^[1-9][0-9]*$ ]] || \
    die "Host Agent service account identity is unsafe"
  validate_root_parent_chain "/run/autostream-host-agent-recovery.placeholder" \
    "Host Agent recovery candidate"
  [[ -d ${CONFIG_DIR} && ! -L ${CONFIG_DIR} &&
    $(readlink -f -- "${CONFIG_DIR}") == "${CONFIG_DIR}" &&
    $(stat -c '%U:%G:%a' -- "${CONFIG_DIR}") == \
      "root:${AGENT_GROUP}:750" ]] || \
    die "canonical Host Agent identity directory is unsafe"
  [[ -f ${CONFIG_DEST} && ! -L ${CONFIG_DEST} &&
    $(readlink -f -- "${CONFIG_DEST}") == "${CONFIG_DEST}" &&
    $(stat -c '%U:%G:%a:%h' -- "${CONFIG_DEST}") == \
      "root:${AGENT_GROUP}:640:1" ]] || \
    die "canonical Host Agent identity is unsafe"
  ${RUNUSER_PATH} --user "${AGENT_USER}" -- test -r "${CONFIG_DEST}" || \
    die "Host Agent service account cannot read the canonical identity"

  defer_cleanup_signals
  active_job_recovery_candidate_dir="$(
    mktemp -d /run/autostream-host-agent-recovery.XXXXXXXX
  )" || die "could not create the Host Agent recovery candidate directory"
  resume_cleanup_signals || \
    die "installation was interrupted while creating the recovery candidate directory"
  [[ -n ${active_job_recovery_candidate_dir} &&
    ${active_job_recovery_candidate_dir} == \
      /run/autostream-host-agent-recovery.* &&
    -d ${active_job_recovery_candidate_dir} &&
    ! -L ${active_job_recovery_candidate_dir} &&
    $(readlink -f -- "${active_job_recovery_candidate_dir}") == \
      "${active_job_recovery_candidate_dir}" &&
    $(stat -c '%U:%G:%a' -- "${active_job_recovery_candidate_dir}") == \
      "root:root:700" ]] || \
    die "Host Agent recovery candidate directory is unsafe"
  chown "root:${AGENT_GROUP}" "${active_job_recovery_candidate_dir}"
  chmod 0750 "${active_job_recovery_candidate_dir}"
  [[ $(stat -c '%U:%G:%a' -- "${active_job_recovery_candidate_dir}") == \
    "root:${AGENT_GROUP}:750" ]] || \
    die "Host Agent recovery candidate directory metadata is unsafe"
  active_job_recovery_candidate_dir_identity="$(
    stat -c '%d:%i' -- "${active_job_recovery_candidate_dir}"
  )" || die "could not record the recovery candidate directory identity"
  active_job_recovery_candidate_path="${active_job_recovery_candidate_dir}/autostream-host-agent"
  source_identity="$(stat -c '%d:%i:%s:%Y:%f' -- "${BINARY_SOURCE}")"
  source_sha256="$(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }')"
  install -o root -g "${AGENT_GROUP}" -m 0750 \
    "${BINARY_SOURCE}" "${active_job_recovery_candidate_path}"
  [[ -f ${BINARY_SOURCE} && ! -L ${BINARY_SOURCE} &&
    $(stat -c '%d:%i:%s:%Y:%f' -- "${BINARY_SOURCE}") == \
      "${source_identity}" &&
    $(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }') == \
      "${source_sha256}" &&
    -f ${active_job_recovery_candidate_path} &&
    ! -L ${active_job_recovery_candidate_path} &&
    $(sha256sum -- "${active_job_recovery_candidate_path}" | awk 'NR == 1 { print $1 }') == \
      "${source_sha256}" &&
    $(stat -c '%U:%G:%a:%h' -- "${active_job_recovery_candidate_path}") == \
      "root:${AGENT_GROUP}:750:1" ]] || \
    die "Host Agent recovery candidate copy is unsafe"
  active_job_recovery_candidate_identity="$(
    stat -c '%d:%i:%s:%u:%g:%a:%h' -- "${active_job_recovery_candidate_path}"
  )" || die "could not record the recovery candidate identity"
  active_job_recovery_candidate_sha256="${source_sha256}"
}

manual_upgrade_candidate_pid=""
manual_upgrade_wait_signal=""
manual_upgrade_pending_signal=""

manual_upgrade_candidate_is_child_job() {
  local job_pid
  while IFS= read -r job_pid; do
    [[ ${job_pid} == "${manual_upgrade_candidate_pid}" ]] && return 0
  done < <(jobs -p)
  return 1
}

record_manual_upgrade_signal() {
  local signal=$1
  manual_upgrade_wait_signal=${signal}
  manual_upgrade_pending_signal=${signal}
}

forward_manual_upgrade_signal() {
  local signal=$1
  manual_upgrade_wait_signal=${signal}
  if [[ -n ${manual_upgrade_candidate_pid} ]] &&
    manual_upgrade_candidate_is_child_job; then
    manual_upgrade_pending_signal=""
    kill -s "${signal}" -- "${manual_upgrade_candidate_pid}" 2>/dev/null || true
  else
    manual_upgrade_pending_signal=${signal}
  fi
}

run_guarded_upgrade_candidate() {
  local ignore_signals_after=$1
  shift
  local candidate_status=1
  local interrupted_status=0
  local pending_signal=""

  manual_upgrade_candidate_pid=""
  manual_upgrade_wait_signal=""
  manual_upgrade_pending_signal=""
  # Before $! is available, record signals without guessing a PID. Switch to
  # guarded forwarding only after Bash has registered the candidate child job.
  trap 'record_manual_upgrade_signal INT' INT
  trap 'record_manual_upgrade_signal TERM' TERM

  "$@" &
  manual_upgrade_candidate_pid=$!
  trap 'forward_manual_upgrade_signal INT' INT
  trap 'forward_manual_upgrade_signal TERM' TERM
  if [[ -n ${manual_upgrade_pending_signal} ]]; then
    pending_signal=${manual_upgrade_pending_signal}
    forward_manual_upgrade_signal "${pending_signal}"
  fi

  while true; do
    manual_upgrade_wait_signal=""
    if wait "${manual_upgrade_candidate_pid}"; then
      candidate_status=0
    else
      candidate_status=$?
    fi
    case "${manual_upgrade_wait_signal}" in
      INT) interrupted_status=130 ;;
      TERM) interrupted_status=143 ;;
      "") interrupted_status=0 ;;
      *) interrupted_status=1 ;;
    esac
    if [[ ${interrupted_status} -ne 0 &&
      ${candidate_status} -eq ${interrupted_status} ]]; then
      continue
    fi
    break
  done

  manual_upgrade_candidate_pid=""
  manual_upgrade_pending_signal=""
  manual_upgrade_wait_signal=""
  if [[ ${ignore_signals_after} == true ]]; then
    # The manual upgrade candidate's durable final status is authoritative.
    # Once it has been reaped, later wrapper-only signals must not turn a
    # committed success into 130/143 while the wrapper reports the result.
    trap '' INT TERM
  else
    trap 'exit 130' INT
    trap 'exit 143' TERM
  fi
  return "${candidate_status}"
}

run_active_job_recovery_candidate() {
  run_guarded_upgrade_candidate false \
    "${RUNUSER_PATH}" --user "${AGENT_USER}" -- \
    "${ENV_PATH}" -i \
    HOME=/nonexistent \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LC_ALL=C \
    "${active_job_recovery_candidate_path}" \
    recover-update --config "${CONFIG_DEST}"
}

run_manual_upgrade_candidate() {
  local -a candidate_command=(
    "${LOCAL_EXECUTOR_BINARY_SOURCE}" manual-upgrade-host-runtime
    --artifact-root "${EXTRACTED_ROOT}"
    --archive-sha256 "${ARTIFACT_SHA256}"
    --archive-size "${ARTIFACT_SIZE}"
  )
  if [[ ${recover_active_job} == true ]]; then
    candidate_command+=(--agent-stopped-for-recovery)
  fi
  run_guarded_upgrade_candidate true "${candidate_command[@]}"
}

inspect_active_job_recovery_state() {
  local state
  state="$(${LOCAL_EXECUTOR_BINARY_SOURCE} inspect-host-update-recovery)" || \
    die "candidate Local Executor could not inspect Host update recovery"
  [[ ${state} == "active" || ${state} == "inactive" ]] || \
    die "candidate Local Executor returned an invalid Host update recovery state"
  printf '%s\n' "${state}"
}

if [[ ${install_mode} == "upgrade" ]]; then
  # The private bundle is extracted under umask 077 with
  # --no-same-permissions, so archive files declared as 0644 arrive as 0600.
  # The candidate Executor deliberately requires both migration templates to
  # be root:root 0644 with one link before it can inspect or migrate the
  # installed units. Normalize only these verified, non-executable templates
  # inside the root-only staging directory; keep every other staged file under
  # the restrictive extraction mask.
  chmod 0644 -- \
    "${LOCAL_EXECUTOR_SERVICE_SOURCE}" \
    "${SELF_UPDATE_RECOVERY_SERVICE_SOURCE}" || \
    die "could not normalize the verified systemd unit candidates"
  for verified_unit_candidate in \
    "${LOCAL_EXECUTOR_SERVICE_SOURCE}" \
    "${SELF_UPDATE_RECOVERY_SERVICE_SOURCE}"; do
    [[ -f ${verified_unit_candidate} &&
      ! -L ${verified_unit_candidate} &&
      $(stat -c '%U:%G:%a:%h' -- "${verified_unit_candidate}") == \
        root:root:644:1 ]] || \
      die "verified systemd unit candidate metadata is unsafe: ${verified_unit_candidate}"
  done

  if [[ ${recover_active_job} == true ]]; then
    validate_active_job_recovery_executable \
      "${SYSTEMCTL_PATH}" "systemctl"
    validate_active_job_recovery_executable \
      "${SYSTEMD_RUN_PATH}" "systemd-run"
    validate_active_job_recovery_executable \
      "${RUNUSER_PATH}" "runuser"
    validate_active_job_recovery_executable \
      "${ENV_PATH}" "env"
    validate_active_job_recovery_executable \
      "${TEST_PATH}" "test"
    [[ $(inspect_active_job_recovery_state) == "active" ]] || \
      die "--recover-active-job requires an exact active Host update journal"
    acquire_active_job_recovery_locks
    [[ $(inspect_active_job_recovery_state) == "active" ]] || \
      die "exact active Host update journal settled before recovery could start"
    active_job_recovery_service_is_managed || \
      die "--recover-active-job requires an enabled, active Host Agent with a live MainPID"
    active_job_recovery_live_pair_is_managed || \
      die "--recover-active-job requires an exact permitted live Host Agent and Local Executor A/B pair"
    active_job_recovery_original_pair_is_intact || \
      die "--recover-active-job could not pin the exact pre-stop Host runtime pair"
    prepare_active_job_recovery_guard_candidate
    install_active_job_recovery_clear_fence
    arm_active_job_recovery_guard
    active_job_recovery_stop_attempted=true
    ${SYSTEMCTL_PATH} stop "${UNIT_NAME}" || \
      die "could not stop the Host Agent for active job recovery"
    active_job_recovery_service_is_inactive || \
      die "Host Agent did not become safely inactive for active job recovery"
    prepare_active_job_recovery_candidate
    # Local Executor Reconcile takes this same lock for every root mutation.
    # Keep the setup lock to exclude configure/install/manual-upgrade, but
    # release lifecycle so the bounded candidate can reconcile the exact job.
    release_active_job_recovery_lifecycle_lock || \
      die "could not release the lifecycle lock for exact active job recovery"
    active_job_recovery_status=0
    run_active_job_recovery_candidate || active_job_recovery_status=$?
    if [[ ${active_job_recovery_status} -ne 0 ]]; then
      printf '%s\n' \
        'install-autostream-host-agent: exact active Host update recovery failed' >&2
      exit "${active_job_recovery_status}"
    fi
    reacquire_active_job_recovery_lifecycle_lock
    [[ $(inspect_active_job_recovery_state) == "inactive" ]] || \
      die "candidate Host Agent did not settle the exact active Host update journal"
    release_active_job_recovery_locks || \
      die "could not release active-job recovery locks before the managed runtime upgrade"
  fi

  manual_upgrade_status=0
  run_manual_upgrade_candidate || manual_upgrade_status=$?
  if [[ ${manual_upgrade_status} -ne 0 ]]; then
    printf '%s\n' \
      'install-autostream-host-agent: managed Host runtime upgrade failed' >&2
    exit "${manual_upgrade_status}"
  fi
  if [[ ${recover_active_job} == true ]]; then
    active_job_recovery_upgrade_committed=true
    cleanup_active_job_recovery || \
      die "managed Host runtime upgrade completed but recovery cleanup failed"
  fi
  printf '%s\n' "Verified Host Agent bundle archive SHA-256: ${ARTIFACT_SHA256}"
  printf '%s\n' "Managed Host Agent and Local Executor runtime upgrade complete."
  exit 0
fi

acquire_shared_host_setup_lock
acquire_host_lifecycle_lock
