
copy_verified_release_file() {
  local source=$1
  local destination=$2
  local owner=$3
  local group=$4
  local mode=$5
  local label=$6
  local source_identity
  local source_sha256
  [[ -f ${source} && ! -L ${source} ]] || die "${label} release source is missing or unsafe"
  source_identity=$(stat -c '%d:%i:%s:%Y:%f' -- "${source}")
  source_sha256=$(sha256sum -- "${source}" | awk 'NR == 1 { print $1 }')
  install -o "${owner}" -g "${group}" -m "${mode}" "${source}" "${destination}"
  [[ -f ${source} && ! -L ${source} ]] || die "${label} release source changed while it was copied"
  [[ $(stat -c '%d:%i:%s:%Y:%f' -- "${source}") == "${source_identity}" ]] || \
    die "${label} release source identity changed while it was copied"
  [[ $(sha256sum -- "${source}" | awk 'NR == 1 { print $1 }') == "${source_sha256}" ]] || \
    die "${label} release source content changed while it was copied"
  [[ $(sha256sum -- "${destination}" | awk 'NR == 1 { print $1 }') == "${source_sha256}" ]] || \
    die "staged ${label} does not match the verified release source"
}

agent_group_created=false
agent_group_identity=""
agent_group_creation_attempted=false
preexisting_agent_group_identity=""
agent_user_created=false
agent_user_identity=""
agent_user_creation_attempted=false
agent_user_uid=""
agent_user_gid=""
agent_user_rollback_login_ready=false
etc_autostream_dir_created=false
etc_autostream_dir_identity=""
identity_parent_acl_changed=false
identity_parent_acl_path_identity=""
identity_parent_acl_before=""
identity_parent_acl_after=""
usr_local_bin_dir_created=false
usr_local_bin_dir_identity=""
systemd_system_dir_created=false
systemd_system_dir_identity=""
usr_local_libexec_dir_created=false
usr_local_libexec_dir_identity=""
etc_tmpfiles_dir_created=false
etc_tmpfiles_dir_identity=""
opt_autostream_dir_created=false
opt_autostream_dir_identity=""
identity_config_dir_created=false
identity_config_dir_identity=""
state_dir_created=false
state_dir_existed=false
state_dir_identity=""
state_root_snapshot=""
state_snapshot=""
state_snapshot_ready=false
host_runtime_root_created=false
host_runtime_root_identity=""
host_runtime_slots_created=false
host_runtime_slots_identity=""
host_runtime_initial_slot_created=false
host_runtime_initial_slot_identity=""
host_runtime_bin_created=false
host_runtime_bin_identity=""
host_runtime_agent_created=false
host_runtime_agent_identity=""
host_runtime_executor_created=false
host_runtime_executor_identity=""
host_runtime_current_created=false
host_runtime_current_identity=""
host_binary_link_identity=""
local_executor_binary_link_identity=""
managed_runtime_snapshot_ready=false
managed_binary_dest_snapshot=""
managed_runtime_current_snapshot=""
managed_runtime_agent_snapshot=""
managed_local_executor_dest_snapshot=""
managed_runtime_executor_snapshot=""
binary_stage=""
unit_stage=""
local_executor_binary_stage=""
local_executor_service_stage=""
local_executor_socket_stage=""
local_executor_tmpfiles_stage=""
self_update_recovery_service_stage=""
self_update_recovery_timer_stage=""

create_temp_file() {
  local variable=$1
  local template=$2
  local temp_path=""
  defer_cleanup_signals
  temp_path=$(mktemp "${template}") || die "could not create temporary file from ${template}"
  printf -v "${variable}" '%s' "${temp_path}"
  resume_cleanup_signals || die "installation was interrupted while journaling a temporary file"
}

move_with_journal() {
  local source=$1
  local destination=$2
  local journal_variable=$3
  defer_cleanup_signals
  printf -v "${journal_variable}" '%s' true
  mv -fT -- "${source}" "${destination}"
  resume_cleanup_signals || die "installation was interrupted while journaling ${destination}"
}

move_with_identity_journal() {
  local source=$1
  local destination=$2
  local journal_variable=$3
  local identity_variable=$4
  defer_cleanup_signals
  printf -v "${journal_variable}" '%s' true
  mv -fT -- "${source}" "${destination}"
  printf -v "${identity_variable}" '%s' "$(stat -c '%d:%i' -- "${destination}")"
  resume_cleanup_signals || die "installation was interrupted while journaling ${destination}"
}

create_symlink_with_journal() {
  local target=$1
  local destination=$2
  local journal_variable=$3
  local identity_variable=$4
  defer_cleanup_signals
  printf -v "${journal_variable}" '%s' true
  ln -s -- "${target}" "${destination}"
  printf -v "${identity_variable}" '%s' "$(stat -c '%d:%i' -- "${destination}")"
  resume_cleanup_signals || die "installation was interrupted while journaling ${destination}"
}

rollback_created_directory() {
  local path=$1
  local expected_identity=$2
  local label=$3
  if [[ -z ${expected_identity} ||
    ! -d ${path} ||
    -L ${path} ||
    $(stat -c '%d:%i' -- "${path}" 2>/dev/null || true) != "${expected_identity}" ]]; then
    printf '%s\n' "install-autostream-host-agent: rollback refused changed ${label}; inspect ${path}" >&2
    return 1
  fi
  if ! rmdir -- "${path}"; then
    printf '%s\n' "install-autostream-host-agent: rollback could not remove new ${label}; inspect ${path}" >&2
    return 1
  fi
}
