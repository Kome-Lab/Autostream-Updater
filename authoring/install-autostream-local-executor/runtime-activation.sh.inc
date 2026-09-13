
restore_file() {
  local backup=$1
  local destination=$2
  local existed=$3
  local replacement_started=$4
  [[ ${replacement_started} == true ]] || return 0
  if [[ -n ${backup} && -e ${backup} ]]; then
    rm -f -- "${destination}" || return 1
    mv -fT -- "${backup}" "${destination}" || return 1
  elif [[ ${existed} == true ]]; then
    [[ -e ${destination} || -L ${destination} ]] || return 1
  else
    rm -f -- "${destination}" || return 1
  fi
}

backup_file() {
  local source=$1
  local directory=$2
  local template=$3
  local existed=$4
  local expected_identity=$5
  local backup_variable=$6
  local replacement_variable=$7
  local backup=""
  if [[ ${existed} == false ]]; then
    return 0
  fi
  [[ -f ${source} && ! -L ${source} &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g' -- "${source}") == "${expected_identity}" ]] || \
    die "managed destination changed before backup: ${source}"
  create_temp_file backup "${directory}/${template}.XXXXXX"
  rm -f -- "${backup}"
  printf -v "${backup_variable}" '%s' "${backup}"
  move_with_journal "${source}" "${backup}" "${replacement_variable}"
}

arm_cleanup_handler cleanup

policy_source_identity=$(stat -c '%d:%i:%s:%Y:%f' -- "${policy_source}")
policy_source_sha256=$(sha256sum -- "${policy_source}" | awk 'NR == 1 { print $1 }')
install -o root -g root -m 0600 "${policy_source}" "${policy_stage}"
[[ $(stat -c '%d:%i:%s:%Y:%f' -- "${policy_source}") == "${policy_source_identity}" ]] || \
  die "policy source changed while it was copied"
[[ $(sha256sum -- "${policy_source}" | awk 'NR == 1 { print $1 }') == "${policy_source_sha256}" ]] || \
  die "policy source content changed while it was copied"
[[ $(sha256sum -- "${policy_stage}" | awk 'NR == 1 { print $1 }') == "${policy_source_sha256}" ]] || \
  die "staged policy does not match the verified source"
copy_verified_release_file "${BINARY_SOURCE}" "${binary_stage}" root root 0755 "binary"
copy_verified_release_file "${SERVICE_SOURCE}" "${service_stage}" root root 0644 "service unit"
copy_verified_release_file "${SOCKET_SOURCE}" "${socket_stage}" root root 0644 "socket unit"
copy_verified_release_file "${TMPFILES_SOURCE}" "${tmpfiles_stage}" root root 0644 "tmpfiles policy"

"${binary_stage}" --version >/dev/null
policy_validation=$("${binary_stage}" validate-policy --policy "${policy_stage}")
policy_uid=$(awk -F': ' '$1 == "agent_uid" { print $2 }' <<<"${policy_validation}")
policy_gid=$(awk -F': ' '$1 == "agent_gid" { print $2 }' <<<"${policy_validation}")
[[ ${policy_uid} == "${agent_uid}" ]] || die "policy agent_uid does not match ${AGENT_USER}"
[[ ${policy_gid} == "${agent_gid}" ]] || die "policy agent_gid does not match ${AGENT_GROUP}"
if [[ ${binary_managed_link} == true ]]; then
  validate_managed_runtime_binary
fi

socket_enabled_state=$(unit_enabled_state "${SOCKET_NAME}")
socket_active_state=$(unit_active_state "${SOCKET_NAME}")
service_active_state=$(unit_active_state "${SERVICE_NAME}")
[[ ${socket_enabled_state} == "enabled" ]] && was_socket_enabled=true
[[ ${socket_active_state} == "active" ]] && was_socket_active=true
[[ ${service_active_state} == "active" ]] && was_service_active=true
verify_unit_inactive "${HOST_AGENT_SERVICE_NAME}"
verify_unit_disabled "${HOST_AGENT_SERVICE_NAME}"

commit_started=true
socket_quiesce_attempted=true
systemctl disable --now "${SOCKET_NAME}" >/dev/null 2>&1 || \
  die "could not disable the Local Executor socket"
verify_unit_inactive "${SOCKET_NAME}"
verify_unit_disabled "${SOCKET_NAME}"
service_quiesce_attempted=true
systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || \
  die "could not stop the Local Executor service"
verify_unit_inactive "${SERVICE_NAME}"
verify_unit_inactive "${SOCKET_NAME}"
verify_unit_disabled "${SOCKET_NAME}"
verify_unit_inactive "${SERVICE_NAME}"
snapshot_executor_state
verify_unit_inactive "${HOST_AGENT_SERVICE_NAME}"
verify_unit_disabled "${HOST_AGENT_SERVICE_NAME}"

managed_file_change_started=true
backup_file \
  "${POLICY_DEST}" "${CONFIG_DIR}" .executor-policy.json.backup \
  "${policy_existed}" "${policy_identity}" policy_backup policy_replacement_started
if [[ ${binary_managed_link} == false ]]; then
  backup_file \
    "${BINARY_DEST}" /usr/local/libexec .autostream-local-executor.backup \
    "${binary_existed}" "${binary_identity}" binary_backup binary_replacement_started
fi
backup_file \
  "${SERVICE_DEST}" /etc/systemd/system .autostream-local-executor.service.backup \
  "${service_existed}" "${service_identity}" service_backup service_replacement_started
backup_file \
  "${SOCKET_DEST}" /etc/systemd/system .autostream-local-executor.socket.backup \
  "${socket_existed}" "${socket_identity}" socket_backup socket_replacement_started
backup_file \
  "${TMPFILES_DEST}" /etc/tmpfiles.d .autostream-local-executor.conf.backup \
  "${tmpfiles_existed}" "${tmpfiles_identity}" tmpfiles_backup tmpfiles_replacement_started

move_with_journal "${policy_stage}" "${POLICY_DEST}" policy_replacement_started
if [[ ${binary_managed_link} == false ]]; then
  move_with_journal "${binary_stage}" "${BINARY_DEST}" binary_replacement_started
else
  rm -f -- "${binary_stage}"
fi
move_with_journal "${service_stage}" "${SERVICE_DEST}" service_replacement_started
move_with_journal "${socket_stage}" "${SOCKET_DEST}" socket_replacement_started
move_with_journal "${tmpfiles_stage}" "${TMPFILES_DEST}" tmpfiles_replacement_started

[[ -f ${POLICY_DEST} && ! -L ${POLICY_DEST} &&
  $(stat -c '%U:%G:%a' -- "${POLICY_DEST}") == "root:root:600" &&
  $(sha256sum -- "${POLICY_DEST}" | awk 'NR == 1 { print $1 }') == "${policy_source_sha256}" ]] || \
  die "installed policy failed verification"
[[ -f ${SERVICE_DEST} && ! -L ${SERVICE_DEST} &&
  $(stat -c '%U:%G:%a' -- "${SERVICE_DEST}") == "root:root:644" ]] || \
  die "installed service unit failed verification"
[[ -f ${SOCKET_DEST} && ! -L ${SOCKET_DEST} &&
  $(stat -c '%U:%G:%a' -- "${SOCKET_DEST}") == "root:root:644" ]] || \
  die "installed socket unit failed verification"
[[ -f ${TMPFILES_DEST} && ! -L ${TMPFILES_DEST} &&
  $(stat -c '%U:%G:%a' -- "${TMPFILES_DEST}") == "root:root:644" ]] || \
  die "installed tmpfiles policy failed verification"
if [[ ${binary_managed_link} == true ]]; then
  validate_managed_runtime_binary
else
  [[ -f ${BINARY_DEST} && ! -L ${BINARY_DEST} &&
    $(stat -c '%U:%G:%a' -- "${BINARY_DEST}") == "root:root:755" &&
    $(sha256sum -- "${BINARY_DEST}" | awk 'NR == 1 { print $1 }') == \
      "$(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }')" ]] || \
    die "installed binary destination failed verification"
fi
systemctl daemon-reload
tmpfiles_creation_attempted=true
if ! systemd-tmpfiles --create "${TMPFILES_DEST}"; then
  capture_fresh_runtime_directory \
    "${SOCKET_DIR}" "${socket_dir_existed}" socket_dir_identity
  capture_fresh_runtime_directory \
    "${UPDATER_RUNTIME_DIR}" "${updater_runtime_dir_existed}" updater_runtime_dir_identity
  die "systemd-tmpfiles failed after applying the Local Executor policy"
fi
capture_fresh_runtime_directory \
  "${SOCKET_DIR}" "${socket_dir_existed}" socket_dir_identity
capture_fresh_runtime_directory \
  "${UPDATER_RUNTIME_DIR}" "${updater_runtime_dir_existed}" updater_runtime_dir_identity
[[ -d ${SOCKET_DIR} && ! -L ${SOCKET_DIR} ]] || die "tmpfiles did not create the socket directory"
[[ $(stat -c '%U:%G:%a' -- "${SOCKET_DIR}") == "root:${AGENT_GROUP}:750" ]] || \
  die "socket directory owner or mode is invalid"
[[ -d ${UPDATER_RUNTIME_DIR} && ! -L ${UPDATER_RUNTIME_DIR} &&
  $(stat -c '%U:%G:%a' -- "${UPDATER_RUNTIME_DIR}") == "root:root:700" ]] || \
  die "updater runtime directory owner or mode is invalid"
verify_unit_inactive "${HOST_AGENT_SERVICE_NAME}"
verify_unit_disabled "${HOST_AGENT_SERVICE_NAME}"
socket_activation_attempted=true
systemctl enable --now autostream-local-executor.socket
verify_unit_inactive "${HOST_AGENT_SERVICE_NAME}"
verify_unit_disabled "${HOST_AGENT_SERVICE_NAME}"
service_activation_attempted=true
if ! systemctl start "${SERVICE_NAME}"; then
  capture_fresh_runtime_directory "${STATE_DIR}" "${state_dir_existed}" state_dir_identity
  die "Local Executor service failed to start"
fi
capture_fresh_runtime_directory "${STATE_DIR}" "${state_dir_existed}" state_dir_identity
verify_unit_inactive "${HOST_AGENT_SERVICE_NAME}"
verify_unit_disabled "${HOST_AGENT_SERVICE_NAME}"
[[ $(unit_active_state "${SOCKET_NAME}") == "active" ]] || \
  die "Local Executor socket did not become active"
[[ $(unit_active_state "${SERVICE_NAME}") == "active" ]] || \
  die "Local Executor service did not become active"
[[ -d ${STATE_DIR} && ! -L ${STATE_DIR} ]] || die "systemd did not create the executor state directory"
[[ $(stat -c '%U:%G:%a' -- "${STATE_DIR}") == "root:root:700" ]] || \
  die "executor state directory owner or mode is invalid"
if [[ ${binary_managed_link} == true ]]; then
  validate_managed_runtime_binary
else
  [[ $(sha256sum -- "${BINARY_DEST}" | awk 'NR == 1 { print $1 }') == \
    "$(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }')" ]] || \
    die "installed binary destination changed during activation"
fi

installation_complete=true
printf '%s\n' "Verified Host Agent bundle archive SHA-256: ${ARTIFACT_SHA256}"
printf '%s\n' "AutoStream local executor installed with protocol v1 probe compatibility and protocol v2 bounded mutation."
printf '%s\n' "${policy_validation}"
