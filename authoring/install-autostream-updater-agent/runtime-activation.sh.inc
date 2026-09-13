
validate_existing() {
  local path=$1
  local owner=$2
  local group=$3
  local mode=$4
  local label=$5
  [[ ! -e ${path} && ! -L ${path} ]] && return 1
  [[ -f ${path} && ! -L ${path} ]] || die "existing ${label} must be a regular non-symlink file"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "${owner}:${group}:${mode}" ]] || \
    die "existing ${label} must be ${owner}:${group} ${mode}"
  return 0
}

snapshot_managed_runtime_path() {
  local path=$1
  if [[ -L ${path} ]]; then
    printf 'symlink:%s:%s\n' \
      "$(stat -c '%d:%i:%u:%g:%a' -- "${path}")" \
      "$(readlink -- "${path}")"
    return
  fi
  if [[ -f ${path} ]]; then
    printf 'file:%s:%s\n' \
      "$(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a' -- "${path}")" \
      "$(sha256sum -- "${path}" | awk 'NR == 1 { print $1 }')"
    return
  fi
  if [[ -e ${path} ]]; then
    die "managed runtime path has an unsupported type: ${path}"
  fi
  printf '%s\n' absent
}

capture_managed_runtime_snapshot() {
  managed_binary_dest_snapshot=$(snapshot_managed_runtime_path "${BINARY_DEST}")
  managed_runtime_current_snapshot=$(snapshot_managed_runtime_path "${HOST_RUNTIME_CURRENT}")
  managed_runtime_agent_snapshot=$(snapshot_managed_runtime_path "${HOST_RUNTIME_AGENT}")
  managed_local_executor_dest_snapshot=$(snapshot_managed_runtime_path "${LOCAL_EXECUTOR_BINARY_DEST}")
  managed_runtime_executor_snapshot=$(snapshot_managed_runtime_path "${HOST_RUNTIME_EXECUTOR}")
  managed_runtime_snapshot_ready=true
}

verify_managed_runtime_snapshot() {
  [[ $(snapshot_managed_runtime_path "${BINARY_DEST}") == "${managed_binary_dest_snapshot}" &&
    $(snapshot_managed_runtime_path "${HOST_RUNTIME_CURRENT}") == "${managed_runtime_current_snapshot}" &&
    $(snapshot_managed_runtime_path "${HOST_RUNTIME_AGENT}") == "${managed_runtime_agent_snapshot}" &&
    $(snapshot_managed_runtime_path "${LOCAL_EXECUTOR_BINARY_DEST}") == \
      "${managed_local_executor_dest_snapshot}" &&
    $(snapshot_managed_runtime_path "${HOST_RUNTIME_EXECUTOR}") == \
      "${managed_runtime_executor_snapshot}" ]]
}

validate_managed_agent_link() {
  [[ -L ${BINARY_DEST} ]] || return 1
  validate_root_parent_chain "${BINARY_DEST}" "managed Host Agent binary destination"
  [[ $(stat -c '%U:%G' -- "${BINARY_DEST}") == "root:root" ]] || \
    die "managed Host Agent binary link must be owned by root:root"
  [[ -L ${HOST_RUNTIME_CURRENT} ]] || \
    die "managed Host Agent binary is missing the atomic current link"
  local current_target
  current_target=$(readlink -- "${HOST_RUNTIME_CURRENT}")
  [[ ${current_target} == "slots/a" || ${current_target} == "slots/b" ]] || \
    die "managed Host Agent current link points outside its fixed A/B slots"
  [[ $(readlink -- "${BINARY_DEST}") == "${HOST_RUNTIME_CURRENT}/bin/autostream-host-agent" ]] || \
    die "managed Host Agent binary link points outside the atomic current runtime"
  local resolved
  resolved=$(readlink -f -- "${BINARY_DEST}")
  [[ ${resolved} == "${HOST_RUNTIME_SLOTS}/a/bin/autostream-host-agent" ||
    ${resolved} == "${HOST_RUNTIME_SLOTS}/b/bin/autostream-host-agent" ]] || \
    die "managed Host Agent binary resolves outside its fixed A/B slots"
  [[ -f ${resolved} && ! -L ${resolved} ]] || \
    die "managed Host Agent active binary is missing or unsafe"
  [[ $(stat -c '%U:%G:%a' -- "${resolved}") == "root:root:755" ]] || \
    die "managed Host Agent active binary must be root:root 0755"
  validate_root_parent_chain "${resolved}" "managed Host Agent active binary"
  [[ $(sha256sum -- "${resolved}" | awk 'NR == 1 { print $1 }') == \
    "$(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }')" ]] || \
    die "managed Host Agent active binary does not match this verified release"
  return 0
}

if [[ -L ${BINARY_DEST} ]]; then
  if validate_managed_agent_link; then
    binary_managed_link=true
    capture_managed_runtime_snapshot
  fi
elif validate_existing "${BINARY_DEST}" root root 755 "binary"; then
  binary_existed=true
fi
if validate_existing "${UNIT_DEST}" root root 644 "systemd unit"; then
  unit_existed=true
fi
if [[ ${install_mode} == "prepare" ]]; then
  if validate_existing "${LOCAL_EXECUTOR_BINARY_DEST}" root root 755 "local executor binary"; then
    local_executor_binary_existed=true
  fi
  if validate_existing "${LOCAL_EXECUTOR_SERVICE_DEST}" root root 644 "local executor service"; then
    local_executor_service_existed=true
  fi
  if validate_existing "${LOCAL_EXECUTOR_SOCKET_DEST}" root root 644 "local executor socket"; then
    local_executor_socket_existed=true
  fi
  if validate_existing "${LOCAL_EXECUTOR_TMPFILES_DEST}" root root 644 "local executor tmpfiles policy"; then
    local_executor_tmpfiles_existed=true
  fi
  if validate_existing "${SELF_UPDATE_RECOVERY_SERVICE_DEST}" root root 644 "self-update recovery service template"; then
    self_update_recovery_service_existed=true
  fi
  if validate_existing "${SELF_UPDATE_RECOVERY_TIMER_DEST}" root root 644 "self-update recovery timer template"; then
    self_update_recovery_timer_existed=true
  fi
fi
initial_unit_active_state=$(unit_active_state "${UNIT_NAME}")
if [[ ${initial_unit_active_state} == "active" ]]; then
  was_active=true
fi
initial_unit_enabled_state=$(unit_enabled_state "${UNIT_NAME}")
if [[ ${initial_unit_enabled_state} == "enabled" ]]; then
  was_enabled=true
fi
if [[ ${install_mode} == "prepare" ]]; then
  [[ ${was_active} == false ]] || die "--prepare requires the Host Agent service to remain inactive"
  [[ ${was_enabled} == false ]] || die "--prepare requires the Host Agent service to remain disabled"
  [[ ! -e ${CONFIG_DEST} && ! -L ${CONFIG_DEST} ]] || \
    die "an identity appeared during --prepare; refusing to install or start the service"
  [[ ! -e ${LOCAL_EXECUTOR_POLICY_DEST} && ! -L ${LOCAL_EXECUTOR_POLICY_DEST} ]] || \
    die "a local executor policy appeared during --prepare; refusing to replace its runtime"
  for runtime_unit in \
    "${LOCAL_EXECUTOR_SERVICE_NAME}" \
    "${LOCAL_EXECUTOR_SOCKET_NAME}" \
    "${SELF_UPDATE_RECOVERY_SERVICE_A}" \
    "${SELF_UPDATE_RECOVERY_SERVICE_B}" \
    "${SELF_UPDATE_RECOVERY_TIMER_A}" \
    "${SELF_UPDATE_RECOVERY_TIMER_B}"; do
    [[ $(unit_active_state "${runtime_unit}") == "inactive" ]] || \
      die "--prepare requires the local executor and self-update recovery timers to remain disabled and inactive"
  done
  for runtime_unit in \
    "${LOCAL_EXECUTOR_SERVICE_NAME}" \
    "${LOCAL_EXECUTOR_SOCKET_NAME}" \
    "${SELF_UPDATE_RECOVERY_TIMER_A}" \
    "${SELF_UPDATE_RECOVERY_TIMER_B}"; do
    [[ $(unit_enabled_state "${runtime_unit}") == "disabled" ]] || \
      die "--prepare requires the local executor and self-update recovery timers to remain disabled and inactive"
  done
fi

commit_started=true
if [[ ${install_mode} == "prepare" ]]; then
  if [[ ${local_executor_data_dir_existed} == true ]]; then
    recheck_private_root_directory \
      "${LOCAL_EXECUTOR_DATA_DIR}" \
      "${local_executor_data_dir_identity}"
  else
    create_private_root_directory \
      "${LOCAL_EXECUTOR_DATA_DIR}" \
      local_executor_data_dir_created \
      local_executor_data_dir_identity
  fi
  if [[ ${local_executor_port_config_dir_existed} == true ]]; then
    recheck_private_root_directory \
      "${LOCAL_EXECUTOR_PORT_CONFIG_DIR}" \
      "${local_executor_port_config_dir_identity}"
  else
    create_private_root_directory \
      "${LOCAL_EXECUTOR_PORT_CONFIG_DIR}" \
      local_executor_port_config_dir_created \
      local_executor_port_config_dir_identity
  fi
fi
if [[ ${binary_existed} == true ]]; then
  create_temp_file binary_backup /usr/local/bin/.autostream-host-agent.backup.XXXXXX
  rm -f -- "${binary_backup}"
  move_with_journal "${BINARY_DEST}" "${binary_backup}" binary_backed_up
fi
if [[ ${unit_existed} == true ]]; then
  create_temp_file unit_backup /etc/systemd/system/.autostream-host-agent.service.backup.XXXXXX
  rm -f -- "${unit_backup}"
  move_with_journal "${UNIT_DEST}" "${unit_backup}" unit_backed_up
fi
if [[ ${local_executor_binary_existed} == true ]]; then
  create_temp_file \
    local_executor_binary_backup /usr/local/libexec/.autostream-local-executor.backup.XXXXXX
  rm -f -- "${local_executor_binary_backup}"
  move_with_journal \
    "${LOCAL_EXECUTOR_BINARY_DEST}" "${local_executor_binary_backup}" \
    local_executor_binary_backed_up
fi
if [[ ${local_executor_service_existed} == true ]]; then
  create_temp_file \
    local_executor_service_backup /etc/systemd/system/.autostream-local-executor.service.backup.XXXXXX
  rm -f -- "${local_executor_service_backup}"
  move_with_journal \
    "${LOCAL_EXECUTOR_SERVICE_DEST}" "${local_executor_service_backup}" \
    local_executor_service_backed_up
fi
if [[ ${local_executor_socket_existed} == true ]]; then
  create_temp_file \
    local_executor_socket_backup /etc/systemd/system/.autostream-local-executor.socket.backup.XXXXXX
  rm -f -- "${local_executor_socket_backup}"
  move_with_journal \
    "${LOCAL_EXECUTOR_SOCKET_DEST}" "${local_executor_socket_backup}" \
    local_executor_socket_backed_up
fi
if [[ ${local_executor_tmpfiles_existed} == true ]]; then
  create_temp_file \
    local_executor_tmpfiles_backup /etc/tmpfiles.d/.autostream-local-executor.conf.backup.XXXXXX
  rm -f -- "${local_executor_tmpfiles_backup}"
  move_with_journal \
    "${LOCAL_EXECUTOR_TMPFILES_DEST}" "${local_executor_tmpfiles_backup}" \
    local_executor_tmpfiles_backed_up
fi
if [[ ${self_update_recovery_service_existed} == true ]]; then
  create_temp_file \
    self_update_recovery_service_backup /etc/systemd/system/.autostream-host-self-update-recovery.service.backup.XXXXXX
  rm -f -- "${self_update_recovery_service_backup}"
  move_with_journal \
    "${SELF_UPDATE_RECOVERY_SERVICE_DEST}" "${self_update_recovery_service_backup}" \
    self_update_recovery_service_backed_up
fi
if [[ ${self_update_recovery_timer_existed} == true ]]; then
  create_temp_file \
    self_update_recovery_timer_backup /etc/systemd/system/.autostream-host-self-update-recovery.timer.backup.XXXXXX
  rm -f -- "${self_update_recovery_timer_backup}"
  move_with_journal \
    "${SELF_UPDATE_RECOVERY_TIMER_DEST}" "${self_update_recovery_timer_backup}" \
    self_update_recovery_timer_backed_up
fi

if [[ ${install_mode} == "prepare" ]]; then
  create_managed_directory \
    "${HOST_RUNTIME_ROOT}" root root 0755 \
    host_runtime_root_created host_runtime_root_identity
  create_managed_directory \
    "${HOST_RUNTIME_SLOTS}" root root 0755 \
    host_runtime_slots_created host_runtime_slots_identity
  create_managed_directory \
    "${HOST_RUNTIME_INITIAL_SLOT}" root root 0755 \
    host_runtime_initial_slot_created host_runtime_initial_slot_identity
  create_managed_directory \
    "${HOST_RUNTIME_INITIAL_SLOT}/bin" root root 0755 \
    host_runtime_bin_created host_runtime_bin_identity
  move_with_identity_journal \
    "${binary_stage}" "${HOST_RUNTIME_AGENT}" \
    host_runtime_agent_created host_runtime_agent_identity
  move_with_identity_journal \
    "${local_executor_binary_stage}" "${HOST_RUNTIME_EXECUTOR}" \
    host_runtime_executor_created host_runtime_executor_identity
  create_symlink_with_journal \
    "slots/a" "${HOST_RUNTIME_CURRENT}" \
    host_runtime_current_created host_runtime_current_identity
  create_symlink_with_journal \
    "${HOST_RUNTIME_CURRENT}/bin/autostream-host-agent" "${BINARY_DEST}" \
    binary_installed host_binary_link_identity
  create_symlink_with_journal \
    "${HOST_RUNTIME_CURRENT}/bin/autostream-local-executor" \
    "${LOCAL_EXECUTOR_BINARY_DEST}" \
    local_executor_binary_installed local_executor_binary_link_identity
elif [[ ${binary_managed_link} == true ]]; then
  rm -f -- "${binary_stage}"
else
  move_with_journal "${binary_stage}" "${BINARY_DEST}" binary_installed
fi
move_with_journal "${unit_stage}" "${UNIT_DEST}" unit_installed
if [[ ${install_mode} == "prepare" ]]; then
  move_with_journal \
    "${local_executor_service_stage}" "${LOCAL_EXECUTOR_SERVICE_DEST}" \
    local_executor_service_installed
  move_with_journal \
    "${local_executor_socket_stage}" "${LOCAL_EXECUTOR_SOCKET_DEST}" \
    local_executor_socket_installed
  move_with_journal \
    "${local_executor_tmpfiles_stage}" "${LOCAL_EXECUTOR_TMPFILES_DEST}" \
    local_executor_tmpfiles_installed
  move_with_journal \
    "${self_update_recovery_service_stage}" "${SELF_UPDATE_RECOVERY_SERVICE_DEST}" \
    self_update_recovery_service_installed
  move_with_journal \
    "${self_update_recovery_timer_stage}" "${SELF_UPDATE_RECOVERY_TIMER_DEST}" \
    self_update_recovery_timer_installed
fi

validate_identity_directory "${CONFIG_DIR}"
[[ $(stat -c '%d:%i' -- "${CONFIG_DIR}") == "${identity_config_dir_identity}" ]] || \
  die "Host Agent identity directory changed during installation"
if [[ ${install_mode} == "prepare" || ${binary_managed_link} == true ]]; then
  validate_managed_agent_link || die "installed managed Host Agent binary failed verification"
else
  [[ $(stat -c '%U:%G:%a' -- "${BINARY_DEST}") == "root:root:755" ]] || \
    die "installed binary failed verification"
fi
[[ $(stat -c '%U:%G:%a' -- "${UNIT_DEST}") == "root:root:644" ]] || die "installed systemd unit failed verification"
if [[ ${install_mode} == "prepare" ]]; then
  recheck_private_root_directory \
    "${LOCAL_EXECUTOR_DATA_DIR}" \
    "${local_executor_data_dir_identity}"
  recheck_private_root_directory \
    "${LOCAL_EXECUTOR_PORT_CONFIG_DIR}" \
    "${local_executor_port_config_dir_identity}"
  [[ -L ${LOCAL_EXECUTOR_BINARY_DEST} ]] || \
    die "prepared local executor binary is not linked to the atomic current runtime"
  [[ $(readlink -- "${LOCAL_EXECUTOR_BINARY_DEST}") == "${HOST_RUNTIME_CURRENT}/bin/autostream-local-executor" ]] || \
    die "prepared local executor binary link escaped the atomic current runtime"
  [[ $(readlink -f -- "${LOCAL_EXECUTOR_BINARY_DEST}") == "${HOST_RUNTIME_EXECUTOR}" ]] || \
    die "prepared local executor binary resolves outside the initial A/B slot"
  [[ $(stat -c '%U:%G:%a' -- "${HOST_RUNTIME_EXECUTOR}") == "root:root:755" ]] || \
    die "prepared local executor binary failed verification"
  [[ $(stat -c '%U:%G:%a' -- "${LOCAL_EXECUTOR_SERVICE_DEST}") == "root:root:644" ]] || \
    die "prepared local executor service failed verification"
  [[ $(stat -c '%U:%G:%a' -- "${LOCAL_EXECUTOR_SOCKET_DEST}") == "root:root:644" ]] || \
    die "prepared local executor socket failed verification"
  [[ $(stat -c '%U:%G:%a' -- "${LOCAL_EXECUTOR_TMPFILES_DEST}") == "root:root:644" ]] || \
    die "prepared local executor tmpfiles policy failed verification"
  [[ $(stat -c '%U:%G:%a' -- "${SELF_UPDATE_RECOVERY_SERVICE_DEST}") == "root:root:644" ]] || \
    die "prepared self-update recovery service template failed verification"
  [[ $(stat -c '%U:%G:%a' -- "${SELF_UPDATE_RECOVERY_TIMER_DEST}") == "root:root:644" ]] || \
    die "prepared self-update recovery timer template failed verification"
fi
systemctl daemon-reload
[[ $(unit_active_state "${UNIT_NAME}") == "inactive" &&
  $(unit_enabled_state "${UNIT_NAME}") == "disabled" &&
  $(unit_active_state "${LOCAL_EXECUTOR_SERVICE_NAME}") == "inactive" &&
  $(unit_active_state "${LOCAL_EXECUTOR_SOCKET_NAME}") == "inactive" &&
  $(unit_enabled_state "${LOCAL_EXECUTOR_SERVICE_NAME}") == "disabled" &&
  $(unit_enabled_state "${LOCAL_EXECUTOR_SOCKET_NAME}") == "disabled" ]] || \
  die "--prepare must leave the Host Agent and local executor disabled and inactive"
self_update_recovery_timer_a_enable_attempted=true
systemctl enable --now "${SELF_UPDATE_RECOVERY_TIMER_A}"
self_update_recovery_timer_a_enabled=true
self_update_recovery_timer_b_enable_attempted=true
systemctl enable --now "${SELF_UPDATE_RECOVERY_TIMER_B}"
self_update_recovery_timer_b_enabled=true
[[ $(unit_enabled_state "${SELF_UPDATE_RECOVERY_TIMER_A}") == "enabled" ]] || \
  die "slot A self-update recovery timer was not enabled"
[[ $(unit_enabled_state "${SELF_UPDATE_RECOVERY_TIMER_B}") == "enabled" ]] || \
  die "slot B self-update recovery timer was not enabled"
[[ $(unit_active_state "${SELF_UPDATE_RECOVERY_TIMER_A}") == "active" ]] || \
  die "slot A self-update recovery timer did not become active"
[[ $(unit_active_state "${SELF_UPDATE_RECOVERY_TIMER_B}") == "active" ]] || \
  die "slot B self-update recovery timer did not become active"
[[ ! -e ${CONFIG_DEST} && ! -L ${CONFIG_DEST} ]] || \
  die "--prepare must not create an identity configuration"
[[ ! -e ${LOCAL_EXECUTOR_POLICY_DEST} && ! -L ${LOCAL_EXECUTOR_POLICY_DEST} ]] || \
  die "--prepare must not create a local executor policy"

installation_complete=true
printf '%s\n' "Verified Host Agent bundle archive SHA-256: ${ARTIFACT_SHA256}"
printf '%s\n' "AutoStream Host Agent and local executor runtime prepared but disabled; root A/B recovery timers are active. Run the Control Panel configure command before enabling either runtime unit."
