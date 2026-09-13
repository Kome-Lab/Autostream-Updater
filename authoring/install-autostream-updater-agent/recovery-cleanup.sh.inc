
cleanup_active_job_recovery_guard_candidate() {
  [[ -n ${active_job_recovery_guard_candidate_dir} ]] || return 0
  if [[ ${active_job_recovery_guard_armed} == true ||
    ${active_job_recovery_clear_fence_installed} == true ]]; then
    return 0
  fi
  active_job_recovery_guard_candidate_is_intact || {
    printf '%s\n' \
      'install-autostream-host-agent: refusing to remove a changed delayed recovery guard path' >&2
    return 1
  }
  rm -f -- "${active_job_recovery_guard_candidate_path}" || return 1
  rmdir -- "${active_job_recovery_guard_candidate_dir}" || return 1
  active_job_recovery_guard_candidate_path=""
  active_job_recovery_guard_candidate_identity=""
  active_job_recovery_guard_candidate_sha256=""
  active_job_recovery_guard_candidate_dir=""
  active_job_recovery_guard_candidate_dir_identity=""
}

cleanup_active_job_recovery_candidate() {
  [[ -n ${active_job_recovery_candidate_dir} ]] || return 0
  [[ ${active_job_recovery_candidate_dir} == \
      /run/autostream-host-agent-recovery.* &&
    -d ${active_job_recovery_candidate_dir} &&
    ! -L ${active_job_recovery_candidate_dir} &&
    $(stat -c '%d:%i' -- "${active_job_recovery_candidate_dir}") == \
      "${active_job_recovery_candidate_dir_identity}" &&
    ${active_job_recovery_candidate_path} == \
      "${active_job_recovery_candidate_dir}/autostream-host-agent" &&
    -f ${active_job_recovery_candidate_path} &&
    ! -L ${active_job_recovery_candidate_path} &&
    $(stat -c '%d:%i:%s:%u:%g:%a:%h' -- \
      "${active_job_recovery_candidate_path}") == \
      "${active_job_recovery_candidate_identity}" &&
    $(sha256sum -- "${active_job_recovery_candidate_path}" | awk 'NR == 1 { print $1 }') == \
      "${active_job_recovery_candidate_sha256}" &&
    $(stat -c '%U:%G:%a' -- "${active_job_recovery_candidate_dir}") == \
      "root:${AGENT_GROUP}:750" ]] || {
    printf '%s\n' \
      'install-autostream-host-agent: refusing to remove a changed Host Agent recovery candidate path' >&2
    return 1
  }
  rm -f -- "${active_job_recovery_candidate_path}" || return 1
  rmdir -- "${active_job_recovery_candidate_dir}" || return 1
  active_job_recovery_candidate_path=""
  active_job_recovery_candidate_identity=""
  active_job_recovery_candidate_sha256=""
  active_job_recovery_candidate_dir=""
  active_job_recovery_candidate_dir_identity=""
}

cleanup_active_job_recovery() {
  local cleanup_failed=false
  if [[ ${active_job_recovery_stop_attempted} == true ||
    ${active_job_recovery_clear_fence_installed} == true ||
    ${active_job_recovery_guard_armed} == true ]]; then
    if ! reacquire_active_job_recovery_cleanup_locks; then
      printf '%s\n' \
        'install-autostream-host-agent: could not reacquire the canonical Host setup and lifecycle locks; the durable recovery fence and systemd guard were retained' >&2
      cleanup_failed=true
    elif [[ ${active_job_recovery_stop_attempted} == true &&
      ${active_job_recovery_upgrade_committed} == false ]] &&
      ! active_job_recovery_original_pair_is_intact; then
      printf '%s\n' \
        'install-autostream-host-agent: the pre-stop Host runtime pair was not restored; the durable recovery fence and systemd guard were retained' >&2
      cleanup_failed=true
    elif [[ ${active_job_recovery_stop_attempted} == true &&
      ${active_job_recovery_upgrade_committed} == true ]] &&
      ! active_job_recovery_live_pair_is_managed verified-candidate; then
      printf '%s\n' \
        'install-autostream-host-agent: the committed Host runtime pair is not safely managed; the durable recovery fence and systemd guard were retained' >&2
      cleanup_failed=true
    else
      if ! active_job_recovery_service_is_managed; then
        if ! ${SYSTEMCTL_PATH} start "${UNIT_NAME}" >/dev/null 2>&1 ||
          ! active_job_recovery_service_is_managed; then
          printf '%s\n' \
            'install-autostream-host-agent: Host Agent recovery failed and the exact runtime could not be restarted; the durable recovery fence and systemd guard were retained' >&2
          cleanup_failed=true
        fi
      fi
      if [[ ${cleanup_failed} == false &&
        ${active_job_recovery_upgrade_committed} == false ]] &&
        ! active_job_recovery_original_pair_is_intact; then
        printf '%s\n' \
          'install-autostream-host-agent: the restarted Host Agent no longer matches the pre-stop runtime pair; the durable recovery fence and systemd guard were retained' >&2
        cleanup_failed=true
      fi
      if [[ ${cleanup_failed} == false &&
        ${active_job_recovery_upgrade_committed} == true ]] &&
        ! active_job_recovery_live_pair_is_managed verified-candidate; then
        printf '%s\n' \
          'install-autostream-host-agent: the active Host Agent no longer matches the committed runtime pair; the durable recovery fence and systemd guard were retained' >&2
        cleanup_failed=true
      fi
    fi
    if [[ ${active_job_recovery_clear_fence_installed} == true &&
      ${cleanup_failed} == false ]] &&
      ! remove_active_job_recovery_clear_fence; then
      printf '%s\n' \
        'install-autostream-host-agent: Host Agent is active but the durable recovery fence could not be removed' >&2
      cleanup_failed=true
    fi
    if [[ ${active_job_recovery_guard_armed} == true &&
      ${cleanup_failed} == false ]] &&
      ! disarm_active_job_recovery_guard; then
      printf '%s\n' \
        'install-autostream-host-agent: Host Agent is active but the recovery guard could not be disarmed' >&2
      cleanup_failed=true
    fi
    if [[ ${cleanup_failed} == false &&
      ${active_job_recovery_clear_fence_installed} == false &&
      ${active_job_recovery_guard_armed} == false ]]; then
      active_job_recovery_stop_attempted=false
    fi
  fi
  if ! cleanup_active_job_recovery_candidate; then
    cleanup_failed=true
  fi
  if ! cleanup_active_job_recovery_guard_candidate; then
    cleanup_failed=true
  fi
  if ! release_active_job_recovery_locks; then
    cleanup_failed=true
  fi
  [[ ${cleanup_failed} == false ]]
}
