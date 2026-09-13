
rollback_prepared_private_directory() {
  local path=$1
  local expected_identity=$2
  local label=$3
  if [[ ! -d ${path} || -L ${path} ||
    $(stat -c '%d:%i' -- "${path}" 2>/dev/null || true) != "${expected_identity}" ]]; then
    printf '%s\n' "install-autostream-host-agent: rollback refused changed ${label}; inspect ${path}" >&2
    return 1
  fi
  if ! rmdir -- "${path}"; then
    printf '%s\n' "install-autostream-host-agent: rollback could not remove new ${label}; inspect ${path}" >&2
    return 1
  fi
}

rollback_created_host_runtime() {
  local entry
  local entry_mode
  local runtime_device
  [[ ${host_runtime_root_created} == true ]] || return
  if [[ ! -d ${HOST_RUNTIME_ROOT} ||
    -L ${HOST_RUNTIME_ROOT} ||
    $(stat -c '%d:%i' -- "${HOST_RUNTIME_ROOT}" 2>/dev/null || true) != "${host_runtime_root_identity}" ||
    $(stat -c '%U:%G:%a' -- "${HOST_RUNTIME_ROOT}" 2>/dev/null || true) != "root:root:755" ||
    ! -d ${HOST_RUNTIME_SLOTS} ||
    -L ${HOST_RUNTIME_SLOTS} ||
    $(stat -c '%d:%i' -- "${HOST_RUNTIME_SLOTS}" 2>/dev/null || true) != "${host_runtime_slots_identity}" ||
    ! -d ${HOST_RUNTIME_INITIAL_SLOT} ||
    -L ${HOST_RUNTIME_INITIAL_SLOT} ||
    $(stat -c '%d:%i' -- "${HOST_RUNTIME_INITIAL_SLOT}" 2>/dev/null || true) != "${host_runtime_initial_slot_identity}" ||
    ! -d ${HOST_RUNTIME_INITIAL_SLOT}/bin ||
    -L ${HOST_RUNTIME_INITIAL_SLOT}/bin ||
    $(stat -c '%d:%i' -- "${HOST_RUNTIME_INITIAL_SLOT}/bin" 2>/dev/null || true) != "${host_runtime_bin_identity}" ]]; then
    printf '%s\n' 'install-autostream-host-agent: rollback refused a changed Host Agent runtime directory tree' >&2
    return 1
  fi
  if [[ ${host_runtime_agent_created} == true ]] &&
    [[ ! -f ${HOST_RUNTIME_AGENT} ||
      -L ${HOST_RUNTIME_AGENT} ||
      $(stat -c '%d:%i' -- "${HOST_RUNTIME_AGENT}" 2>/dev/null || true) != "${host_runtime_agent_identity}" ||
      $(stat -c '%U:%G:%a' -- "${HOST_RUNTIME_AGENT}" 2>/dev/null || true) != "root:root:755" ||
      $(sha256sum -- "${HOST_RUNTIME_AGENT}" 2>/dev/null | awk 'NR == 1 { print $1 }') != \
        "$(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }')" ]]; then
    printf '%s\n' 'install-autostream-host-agent: rollback refused a changed Host Agent runtime binary' >&2
    return 1
  fi
  if [[ ${host_runtime_executor_created} == true ]] &&
    [[ ! -f ${HOST_RUNTIME_EXECUTOR} ||
      -L ${HOST_RUNTIME_EXECUTOR} ||
      $(stat -c '%d:%i' -- "${HOST_RUNTIME_EXECUTOR}" 2>/dev/null || true) != "${host_runtime_executor_identity}" ||
      $(stat -c '%U:%G:%a' -- "${HOST_RUNTIME_EXECUTOR}" 2>/dev/null || true) != "root:root:755" ||
      $(sha256sum -- "${HOST_RUNTIME_EXECUTOR}" 2>/dev/null | awk 'NR == 1 { print $1 }') != \
        "$(sha256sum -- "${LOCAL_EXECUTOR_BINARY_SOURCE}" | awk 'NR == 1 { print $1 }')" ]]; then
    printf '%s\n' 'install-autostream-host-agent: rollback refused a changed local executor runtime binary' >&2
    return 1
  fi
  if [[ ${host_runtime_current_created} == true ]] &&
    [[ ! -L ${HOST_RUNTIME_CURRENT} ||
      $(stat -c '%d:%i' -- "${HOST_RUNTIME_CURRENT}" 2>/dev/null || true) != "${host_runtime_current_identity}" ||
      $(stat -c '%U:%G' -- "${HOST_RUNTIME_CURRENT}" 2>/dev/null || true) != "root:root" ||
      $(readlink -- "${HOST_RUNTIME_CURRENT}" 2>/dev/null || true) != "slots/a" ]]; then
    printf '%s\n' 'install-autostream-host-agent: rollback refused a changed Host Agent current link' >&2
    return 1
  fi
  if [[ ${binary_installed} == true ]] &&
    [[ ! -L ${BINARY_DEST} ||
      $(stat -c '%d:%i' -- "${BINARY_DEST}" 2>/dev/null || true) != "${host_binary_link_identity}" ||
      $(readlink -- "${BINARY_DEST}" 2>/dev/null || true) != \
        "${HOST_RUNTIME_CURRENT}/bin/autostream-host-agent" ]]; then
    printf '%s\n' 'install-autostream-host-agent: rollback refused a changed Host Agent public link' >&2
    return 1
  fi
  if [[ ${local_executor_binary_installed} == true ]] &&
    [[ ! -L ${LOCAL_EXECUTOR_BINARY_DEST} ||
      $(stat -c '%d:%i' -- "${LOCAL_EXECUTOR_BINARY_DEST}" 2>/dev/null || true) != \
        "${local_executor_binary_link_identity}" ||
      $(readlink -- "${LOCAL_EXECUTOR_BINARY_DEST}" 2>/dev/null || true) != \
        "${HOST_RUNTIME_CURRENT}/bin/autostream-local-executor" ]]; then
    printf '%s\n' 'install-autostream-host-agent: rollback refused a changed local executor public link' >&2
    return 1
  fi
  runtime_device=$(stat -c '%d' -- "${HOST_RUNTIME_ROOT}") || return 1
  while IFS= read -r -d '' entry; do
    if [[ -L ${entry} ]]; then
      if [[ ${entry} != "${HOST_RUNTIME_CURRENT}" ||
        ${host_runtime_current_created} != true ||
        $(stat -c '%d:%i' -- "${entry}" 2>/dev/null || true) != "${host_runtime_current_identity}" ||
        $(readlink -- "${entry}" 2>/dev/null || true) != "slots/a" ]]; then
        printf '%s\n' "install-autostream-host-agent: rollback refused unsafe runtime link ${entry}" >&2
        return 1
      fi
      continue
    fi
    if [[ ! -d ${entry} && ! -f ${entry} ]] ||
      [[ $(stat -c '%d:%u' -- "${entry}" 2>/dev/null || true) != "${runtime_device}:0" ]]; then
      printf '%s\n' "install-autostream-host-agent: rollback refused unsafe runtime entry ${entry}" >&2
      return 1
    fi
    entry_mode=$(stat -c '%a' -- "${entry}") || return 1
    if (( (8#${entry_mode} & 0022) != 0 )); then
      printf '%s\n' "install-autostream-host-agent: rollback refused writable runtime entry ${entry}" >&2
      return 1
    fi
  done < <(find "${HOST_RUNTIME_ROOT}" -xdev -mindepth 1 -print0)

  if [[ ${binary_installed} == true ]]; then
    rm -f -- "${BINARY_DEST}" || return 1
    binary_installed=false
  fi
  if [[ ${local_executor_binary_installed} == true ]]; then
    rm -f -- "${LOCAL_EXECUTOR_BINARY_DEST}" || return 1
    local_executor_binary_installed=false
  fi
  find "${HOST_RUNTIME_ROOT}" -xdev -mindepth 1 -delete || return 1
  host_runtime_current_created=false
  host_runtime_agent_created=false
  host_runtime_executor_created=false
  host_runtime_bin_created=false
  host_runtime_initial_slot_created=false
  host_runtime_slots_created=false
  rollback_created_directory \
    "${HOST_RUNTIME_ROOT}" "${host_runtime_root_identity}" \
    "Host Agent runtime root" || return 1
  host_runtime_root_created=false
}

cleanup() {
  local status=$?
  local rollback_failed=false
  local recovery_quiesce_failed=false
  local observed_state=""
  trap '' INT TERM
  trap - EXIT
  if [[ ${installation_complete} == true ]]; then
    rm -f -- "${binary_stage}" "${unit_stage}"
    [[ -z ${local_executor_binary_stage} ]] || rm -f -- "${local_executor_binary_stage}"
    [[ -z ${local_executor_service_stage} ]] || rm -f -- "${local_executor_service_stage}"
    [[ -z ${local_executor_socket_stage} ]] || rm -f -- "${local_executor_socket_stage}"
    [[ -z ${local_executor_tmpfiles_stage} ]] || rm -f -- "${local_executor_tmpfiles_stage}"
    [[ -z ${self_update_recovery_service_stage} ]] || rm -f -- "${self_update_recovery_service_stage}"
    [[ -z ${self_update_recovery_timer_stage} ]] || rm -f -- "${self_update_recovery_timer_stage}"
    [[ -z ${binary_backup} ]] || rm -f -- "${binary_backup}"
    [[ -z ${unit_backup} ]] || rm -f -- "${unit_backup}"
    [[ -z ${local_executor_binary_backup} ]] || rm -f -- "${local_executor_binary_backup}"
    [[ -z ${local_executor_service_backup} ]] || rm -f -- "${local_executor_service_backup}"
    [[ -z ${local_executor_socket_backup} ]] || rm -f -- "${local_executor_socket_backup}"
    [[ -z ${local_executor_tmpfiles_backup} ]] || rm -f -- "${local_executor_tmpfiles_backup}"
    [[ -z ${self_update_recovery_service_backup} ]] || rm -f -- "${self_update_recovery_service_backup}"
    [[ -z ${self_update_recovery_timer_backup} ]] || rm -f -- "${self_update_recovery_timer_backup}"
    rm -rf -- "${BUNDLE_STAGE}"
    exit "${status}"
  fi

  rm -f -- "${binary_stage}" "${unit_stage}"
  [[ -z ${local_executor_binary_stage} ]] || rm -f -- "${local_executor_binary_stage}"
  [[ -z ${local_executor_service_stage} ]] || rm -f -- "${local_executor_service_stage}"
  [[ -z ${local_executor_socket_stage} ]] || rm -f -- "${local_executor_socket_stage}"
  [[ -z ${local_executor_tmpfiles_stage} ]] || rm -f -- "${local_executor_tmpfiles_stage}"
  [[ -z ${self_update_recovery_service_stage} ]] || rm -f -- "${self_update_recovery_service_stage}"
  [[ -z ${self_update_recovery_timer_stage} ]] || rm -f -- "${self_update_recovery_timer_stage}"
  if [[ ${commit_started} == true ]]; then
    if ! systemctl stop "${UNIT_NAME}" >/dev/null 2>&1; then
      observed_state=$(unit_active_state "${UNIT_NAME}" 2>/dev/null || true)
      if [[ ${observed_state} != "inactive" ]]; then
        printf '%s\n' 'install-autostream-host-agent: rollback could not stop the Host Agent; installed state was left for console recovery' >&2
        if ! rollback_bootstrap_prerequisites false; then
          :
        fi
        rm -rf -- "${BUNDLE_STAGE}"
        exit 1
      fi
    fi
    observed_state=$(unit_active_state "${UNIT_NAME}" 2>/dev/null || true)
    if [[ ${observed_state} != "inactive" ]]; then
      printf '%s\n' 'install-autostream-host-agent: rollback refused to mutate files while the Host Agent remained active' >&2
      if ! rollback_bootstrap_prerequisites false; then
        :
      fi
      rm -rf -- "${BUNDLE_STAGE}"
      exit 1
    fi
    if [[ ${self_update_recovery_timer_a_enable_attempted} == true ||
      ${self_update_recovery_timer_b_enable_attempted} == true ]]; then
      if [[ ${self_update_recovery_timer_a_enable_attempted} == true ]] &&
        ! systemctl disable --now "${SELF_UPDATE_RECOVERY_TIMER_A}" >/dev/null 2>&1; then
        printf '%s\n' 'install-autostream-host-agent: rollback timer A disable command failed; checking the resulting state' >&2
      fi
      if [[ ${self_update_recovery_timer_b_enable_attempted} == true ]] &&
        ! systemctl disable --now "${SELF_UPDATE_RECOVERY_TIMER_B}" >/dev/null 2>&1; then
        printf '%s\n' 'install-autostream-host-agent: rollback timer B disable command failed; checking the resulting state' >&2
      fi
      if ! systemctl stop "${SELF_UPDATE_RECOVERY_SERVICE_A}" >/dev/null 2>&1; then
        printf '%s\n' 'install-autostream-host-agent: rollback recovery service A stop command failed; checking the resulting state' >&2
      fi
      if ! systemctl stop "${SELF_UPDATE_RECOVERY_SERVICE_B}" >/dev/null 2>&1; then
        printf '%s\n' 'install-autostream-host-agent: rollback recovery service B stop command failed; checking the resulting state' >&2
      fi
      observed_state=$(unit_active_state "${SELF_UPDATE_RECOVERY_SERVICE_A}" 2>/dev/null || true)
      [[ ${observed_state} == "inactive" ]] || recovery_quiesce_failed=true
      observed_state=$(unit_active_state "${SELF_UPDATE_RECOVERY_SERVICE_B}" 2>/dev/null || true)
      [[ ${observed_state} == "inactive" ]] || recovery_quiesce_failed=true
      if [[ ${self_update_recovery_timer_a_enable_attempted} == true ]]; then
        observed_state=$(unit_active_state "${SELF_UPDATE_RECOVERY_TIMER_A}" 2>/dev/null || true)
        [[ ${observed_state} == "inactive" ]] || recovery_quiesce_failed=true
        observed_state=$(unit_enabled_state "${SELF_UPDATE_RECOVERY_TIMER_A}" 2>/dev/null || true)
        [[ ${observed_state} == "disabled" ]] || recovery_quiesce_failed=true
      fi
      if [[ ${self_update_recovery_timer_b_enable_attempted} == true ]]; then
        observed_state=$(unit_active_state "${SELF_UPDATE_RECOVERY_TIMER_B}" 2>/dev/null || true)
        [[ ${observed_state} == "inactive" ]] || recovery_quiesce_failed=true
        observed_state=$(unit_enabled_state "${SELF_UPDATE_RECOVERY_TIMER_B}" 2>/dev/null || true)
        [[ ${observed_state} == "disabled" ]] || recovery_quiesce_failed=true
      fi
      if [[ ${recovery_quiesce_failed} == true ]]; then
        printf '%s\n' 'install-autostream-host-agent: rollback could not quiesce the self-update timers and recovery services; installed runtime was left for console recovery' >&2
        if ! rollback_bootstrap_prerequisites false; then
          :
        fi
        rm -rf -- "${BUNDLE_STAGE}"
        exit 1
      fi
    fi
    if [[ ${managed_runtime_snapshot_ready} == true ]] &&
      ! verify_managed_runtime_snapshot; then
      printf '%s\n' 'install-autostream-host-agent: rollback refused a changed pre-existing managed runtime; installed state was left for console recovery' >&2
      if ! rollback_bootstrap_prerequisites false; then
        :
      fi
      rm -rf -- "${BUNDLE_STAGE}"
      exit 1
    fi
    if [[ ${host_runtime_root_created} == true ]] &&
      ! rollback_created_host_runtime; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not safely remove the newly created Host Agent runtime' >&2
      if ! rollback_bootstrap_prerequisites false; then
        :
      fi
      rm -rf -- "${BUNDLE_STAGE}"
      exit 1
    fi
    if [[ ${was_enabled} == false && ( ${unit_installed} == true || ${unit_existed} == true ) ]]; then
      if ! systemctl disable "${UNIT_NAME}" >/dev/null 2>&1; then
        printf '%s\n' 'install-autostream-host-agent: rollback could not restore the previous disabled state' >&2
        rollback_failed=true
      fi
    fi
    if [[ ${binary_installed} == true ]]; then
      if ! rm -f -- "${BINARY_DEST}"; then
        printf '%s\n' 'install-autostream-host-agent: rollback could not remove the staged binary' >&2
        rollback_failed=true
      fi
    fi
    if [[ ${binary_backed_up} == true && -e ${binary_backup} ]]; then
      if ! mv -f -- "${binary_backup}" "${BINARY_DEST}"; then
        printf '%s\n' "install-autostream-host-agent: rollback could not restore ${binary_backup}; preserve it for console recovery" >&2
        rollback_failed=true
      fi
    fi
    if [[ ${unit_installed} == true ]]; then
      if ! rm -f -- "${UNIT_DEST}"; then
        printf '%s\n' 'install-autostream-host-agent: rollback could not remove the staged systemd unit' >&2
        rollback_failed=true
      fi
    fi
    if [[ ${unit_backed_up} == true && -e ${unit_backup} ]]; then
      if ! mv -f -- "${unit_backup}" "${UNIT_DEST}"; then
        printf '%s\n' "install-autostream-host-agent: rollback could not restore ${unit_backup}; preserve it for console recovery" >&2
        rollback_failed=true
      fi
    fi
    if [[ ${local_executor_binary_installed} == true ]] &&
      ! rm -f -- "${LOCAL_EXECUTOR_BINARY_DEST}"; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not remove the prepared local executor binary' >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_binary_backed_up} == true && -e ${local_executor_binary_backup} ]] &&
      ! mv -f -- "${local_executor_binary_backup}" "${LOCAL_EXECUTOR_BINARY_DEST}"; then
      printf '%s\n' "install-autostream-host-agent: rollback could not restore ${local_executor_binary_backup}; preserve it for console recovery" >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_service_installed} == true ]] &&
      ! rm -f -- "${LOCAL_EXECUTOR_SERVICE_DEST}"; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not remove the prepared local executor service' >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_service_backed_up} == true && -e ${local_executor_service_backup} ]] &&
      ! mv -f -- "${local_executor_service_backup}" "${LOCAL_EXECUTOR_SERVICE_DEST}"; then
      printf '%s\n' "install-autostream-host-agent: rollback could not restore ${local_executor_service_backup}; preserve it for console recovery" >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_socket_installed} == true ]] &&
      ! rm -f -- "${LOCAL_EXECUTOR_SOCKET_DEST}"; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not remove the prepared local executor socket' >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_socket_backed_up} == true && -e ${local_executor_socket_backup} ]] &&
      ! mv -f -- "${local_executor_socket_backup}" "${LOCAL_EXECUTOR_SOCKET_DEST}"; then
      printf '%s\n' "install-autostream-host-agent: rollback could not restore ${local_executor_socket_backup}; preserve it for console recovery" >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_tmpfiles_installed} == true ]] &&
      ! rm -f -- "${LOCAL_EXECUTOR_TMPFILES_DEST}"; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not remove the prepared local executor tmpfiles policy' >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_tmpfiles_backed_up} == true && -e ${local_executor_tmpfiles_backup} ]] &&
      ! mv -f -- "${local_executor_tmpfiles_backup}" "${LOCAL_EXECUTOR_TMPFILES_DEST}"; then
      printf '%s\n' "install-autostream-host-agent: rollback could not restore ${local_executor_tmpfiles_backup}; preserve it for console recovery" >&2
      rollback_failed=true
    fi
    if [[ ${self_update_recovery_service_installed} == true ]] &&
      ! rm -f -- "${SELF_UPDATE_RECOVERY_SERVICE_DEST}"; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not remove the self-update recovery service template' >&2
      rollback_failed=true
    fi
    if [[ ${self_update_recovery_service_backed_up} == true && -e ${self_update_recovery_service_backup} ]] &&
      ! mv -f -- "${self_update_recovery_service_backup}" "${SELF_UPDATE_RECOVERY_SERVICE_DEST}"; then
      printf '%s\n' "install-autostream-host-agent: rollback could not restore ${self_update_recovery_service_backup}; preserve it for console recovery" >&2
      rollback_failed=true
    fi
    if [[ ${self_update_recovery_timer_installed} == true ]] &&
      ! rm -f -- "${SELF_UPDATE_RECOVERY_TIMER_DEST}"; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not remove the self-update recovery timer template' >&2
      rollback_failed=true
    fi
    if [[ ${self_update_recovery_timer_backed_up} == true && -e ${self_update_recovery_timer_backup} ]] &&
      ! mv -f -- "${self_update_recovery_timer_backup}" "${SELF_UPDATE_RECOVERY_TIMER_DEST}"; then
      printf '%s\n' "install-autostream-host-agent: rollback could not restore ${self_update_recovery_timer_backup}; preserve it for console recovery" >&2
      rollback_failed=true
    fi
    if [[ ${local_executor_port_config_dir_created} == true ]] &&
      ! rollback_prepared_private_directory \
        "${LOCAL_EXECUTOR_PORT_CONFIG_DIR}" \
        "${local_executor_port_config_dir_identity}" \
        "local executor port directory"; then
      rollback_failed=true
    fi
    if [[ ${local_executor_data_dir_created} == true ]] &&
      ! rollback_prepared_private_directory \
        "${LOCAL_EXECUTOR_DATA_DIR}" \
        "${local_executor_data_dir_identity}" \
        "local executor data directory"; then
      rollback_failed=true
    fi
    if ! systemctl daemon-reload >/dev/null 2>&1; then
      printf '%s\n' 'install-autostream-host-agent: rollback could not reload systemd state' >&2
      rollback_failed=true
    fi
    if [[ ${was_enabled} == true ]]; then
      if ! systemctl enable "${UNIT_NAME}" >/dev/null 2>&1; then
        printf '%s\n' 'install-autostream-host-agent: rollback could not re-enable the previous service; inspect it locally' >&2
        rollback_failed=true
      fi
    fi
  fi
  if [[ ${service_quiesce_attempted} == true && ${was_active} == true ]]; then
    systemctl start "${UNIT_NAME}" >/dev/null 2>&1 || \
      {
        printf '%s\n' 'install-autostream-host-agent: rollback could not restart the previous service; inspect it locally' >&2
        rollback_failed=true
      }
  fi
  if ! rollback_bootstrap_prerequisites; then
    rollback_failed=true
  fi
  rm -rf -- "${BUNDLE_STAGE}"
  if [[ ${rollback_failed} == true ]]; then
    exit 1
  fi
  exit "${status}"
}
arm_cleanup_handler cleanup

copy_verified_release_file "${BINARY_SOURCE}" "${binary_stage}" root root 0755 "Host Agent binary"
copy_verified_release_file "${UNIT_SOURCE}" "${unit_stage}" root root 0644 "Host Agent systemd unit"
if [[ ${install_mode} == "prepare" ]]; then
  copy_verified_release_file \
    "${LOCAL_EXECUTOR_BINARY_SOURCE}" "${local_executor_binary_stage}" root root 0755 "local executor binary"
  copy_verified_release_file \
    "${LOCAL_EXECUTOR_SERVICE_SOURCE}" "${local_executor_service_stage}" root root 0644 "local executor service"
  copy_verified_release_file \
    "${LOCAL_EXECUTOR_SOCKET_SOURCE}" "${local_executor_socket_stage}" root root 0644 "local executor socket"
  copy_verified_release_file \
    "${LOCAL_EXECUTOR_TMPFILES_SOURCE}" "${local_executor_tmpfiles_stage}" root root 0644 "local executor tmpfiles policy"
  copy_verified_release_file \
    "${SELF_UPDATE_RECOVERY_SERVICE_SOURCE}" "${self_update_recovery_service_stage}" root root 0644 "self-update recovery service template"
  copy_verified_release_file \
    "${SELF_UPDATE_RECOVERY_TIMER_SOURCE}" "${self_update_recovery_timer_stage}" root root 0644 "self-update recovery timer template"
fi

"${binary_stage}" --version >/dev/null
if [[ ${install_mode} == "prepare" ]]; then
  "${local_executor_binary_stage}" --version >/dev/null
fi
