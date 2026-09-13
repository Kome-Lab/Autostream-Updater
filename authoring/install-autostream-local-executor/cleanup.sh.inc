
cleanup() {
  local status=$?
  local rollback_failed=false
  local runtime_quiesced=true
  local state_rollback_ready=true
  local observed_service_state=""
  local observed_socket_state=""
  local observed_socket_enabled=""
  trap '' INT TERM
  trap - EXIT
  rm -f -- "${policy_stage}" "${binary_stage}" "${service_stage}" "${socket_stage}" "${tmpfiles_stage}"
  if [[ ${installation_complete} == true ]]; then
    rm -f -- "${policy_backup}" "${binary_backup}" "${service_backup}" "${socket_backup}" "${tmpfiles_backup}"
    rm -rf -- "${BUNDLE_STAGE}"
    exit "${status}"
  fi
  if [[ ${commit_started} == true ]]; then
    socket_quiesce_attempted=true
    if ! systemctl disable --now "${SOCKET_NAME}" >/dev/null 2>&1; then
      printf '%s\n' 'install-autostream-local-executor: rollback disable command failed; checking the resulting state' >&2
    fi
    observed_socket_state=$(unit_active_state "${SOCKET_NAME}" 2>/dev/null || true)
    observed_socket_enabled=$(unit_enabled_state "${SOCKET_NAME}" 2>/dev/null || true)
    if [[ ${observed_socket_state} != "inactive" ||
      ${observed_socket_enabled} != "disabled" ]]; then
      runtime_quiesced=false
    fi
    service_quiesce_attempted=true
    if ! systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1; then
      printf '%s\n' 'install-autostream-local-executor: rollback stop command failed; checking the resulting state' >&2
    fi
    observed_service_state=$(unit_active_state "${SERVICE_NAME}" 2>/dev/null || true)
    observed_socket_state=$(unit_active_state "${SOCKET_NAME}" 2>/dev/null || true)
    observed_socket_enabled=$(unit_enabled_state "${SOCKET_NAME}" 2>/dev/null || true)
    if [[ ${observed_service_state} != "inactive" ||
      ${observed_socket_state} != "inactive" ||
      ${observed_socket_enabled} != "disabled" ]]; then
      runtime_quiesced=false
    fi
    if [[ ${runtime_quiesced} == false &&
      ( ${managed_file_change_started} == true ||
        ${socket_activation_attempted} == true ||
        ${service_activation_attempted} == true ) ]]; then
      printf '%s\n' 'install-autostream-local-executor: rollback refused to mutate managed files or state before the socket and executor converged to disabled and inactive' >&2
      rollback_failed=true
    fi
    if [[ ${managed_file_change_started} == false &&
      ${socket_activation_attempted} == false &&
      ${service_activation_attempted} == false ]]; then
      if ! restore_initial_runtime_state; then
        printf '%s\n' 'install-autostream-local-executor: early rollback could not restore the original socket and service states' >&2
        rollback_failed=true
      fi
    fi
    if [[ ${runtime_quiesced} == true ]]; then
      if [[ ${socket_activation_attempted} == true ||
        ${service_activation_attempted} == true ]]; then
        if [[ ${state_dir_existed} == false &&
          ( -e ${STATE_DIR} || -L ${STATE_DIR} ) ]]; then
          if [[ ! -d ${STATE_DIR} ||
            -L ${STATE_DIR} ||
            $(stat -c '%U:%G:%a' -- "${STATE_DIR}" 2>/dev/null || true) != "root:root:700" ]]; then
            printf '%s\n' 'install-autostream-local-executor: rollback refused an unsafe fresh state root' >&2
            state_rollback_ready=false
            rollback_failed=true
          else
            capture_fresh_runtime_directory \
              "${STATE_DIR}" "${state_dir_existed}" state_dir_identity
          fi
        fi
        if [[ ${state_rollback_ready} == true ]] &&
          ! restore_executor_state; then
          rollback_failed=true
        fi
      fi
      restore_file \
        "${policy_backup}" "${POLICY_DEST}" "${policy_existed}" "${policy_replacement_started}" ||
        rollback_failed=true
      if [[ ${binary_managed_link} == false ]]; then
        restore_file \
          "${binary_backup}" "${BINARY_DEST}" "${binary_existed}" "${binary_replacement_started}" ||
          rollback_failed=true
      fi
      restore_file \
        "${service_backup}" "${SERVICE_DEST}" "${service_existed}" "${service_replacement_started}" ||
        rollback_failed=true
      restore_file \
        "${socket_backup}" "${SOCKET_DEST}" "${socket_existed}" "${socket_replacement_started}" ||
        rollback_failed=true
      restore_file \
        "${tmpfiles_backup}" "${TMPFILES_DEST}" "${tmpfiles_existed}" "${tmpfiles_replacement_started}" ||
        rollback_failed=true
      systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=true
      if [[ ${tmpfiles_creation_attempted} == true ]]; then
        capture_fresh_runtime_directory \
          "${SOCKET_DIR}" "${socket_dir_existed}" socket_dir_identity
        capture_fresh_runtime_directory \
          "${UPDATER_RUNTIME_DIR}" "${updater_runtime_dir_existed}" updater_runtime_dir_identity
      fi
      if [[ ${socket_dir_existed} == false && -n ${socket_dir_identity} ]] &&
        ! rollback_created_directory \
          "${SOCKET_DIR}" "${socket_dir_identity}" "Local Executor socket directory"; then
        rollback_failed=true
      fi
      if [[ ${updater_runtime_dir_existed} == false && -n ${updater_runtime_dir_identity} ]] &&
        ! rollback_created_directory \
          "${UPDATER_RUNTIME_DIR}" "${updater_runtime_dir_identity}" "updater runtime directory"; then
        rollback_failed=true
      fi
      if ! restore_initial_runtime_state; then
        printf '%s\n' 'install-autostream-local-executor: rollback could not restore the original socket and service states' >&2
        rollback_failed=true
      fi
    fi
  fi
  if ! rollback_prerequisite_directories; then
    rollback_failed=true
  fi
  if
    remove_fresh_empty_directory /opt/autostream "${release_root_existed}" "root:root:755"
  then
    :
  else
    rollback_failed=true
  fi
  if [[ ${runtime_quiesced} == true ]]; then
    rm -f -- "${policy_backup}" "${binary_backup}" "${service_backup}" "${socket_backup}" "${tmpfiles_backup}"
  fi
  rm -rf -- "${BUNDLE_STAGE}"
  if [[ ${rollback_failed} == true ]]; then
    exit 1
  fi
  exit "${status}"
}
