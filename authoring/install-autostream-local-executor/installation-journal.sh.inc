
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

config_dir_existed=false
config_dir_identity=""
etc_autostream_dir_existed=false
etc_autostream_dir_identity=""
identity_parent_acl_changed=false
identity_parent_acl_path_identity=""
identity_parent_acl_before=""
identity_parent_acl_after=""
executor_config_dir_existed=false
executor_config_dir_identity=""
usr_local_libexec_dir_existed=false
usr_local_libexec_dir_identity=""
systemd_system_dir_existed=false
systemd_system_dir_identity=""
etc_tmpfiles_dir_existed=false
etc_tmpfiles_dir_identity=""
release_root_existed=false
release_root_identity=""
executor_data_dir_existed=false
executor_data_dir_identity=""
port_config_dir_existed=false
port_config_dir_identity=""
docker_version_dir_existed=false
docker_version_dir_identity=""
docker_port_config_dir_existed=false
docker_port_config_dir_identity=""
docker_config_dir_existed=false
docker_config_dir_identity=""
socket_dir_existed=false
socket_dir_identity=""
updater_runtime_dir_existed=false
updater_runtime_dir_identity=""
state_dir_existed=false
state_dir_identity=""
state_root_snapshot=""
state_snapshot=""
state_snapshot_ready=false
policy_existed=false
policy_identity=""
binary_existed=false
binary_identity=""
service_existed=false
service_identity=""
socket_existed=false
socket_identity=""
tmpfiles_existed=false
tmpfiles_identity=""
policy_stage=""
binary_stage=""
service_stage=""
socket_stage=""
tmpfiles_stage=""
policy_backup=""
binary_backup=""
service_backup=""
socket_backup=""
tmpfiles_backup=""
policy_replacement_started=false
binary_replacement_started=false
service_replacement_started=false
socket_replacement_started=false
tmpfiles_replacement_started=false
commit_started=false
managed_file_change_started=false
installation_complete=false
was_socket_enabled=false
was_socket_active=false
was_service_active=false
service_quiesce_attempted=false
socket_quiesce_attempted=false
socket_activation_attempted=false
service_activation_attempted=false
tmpfiles_creation_attempted=false

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

create_managed_directory() {
  local path=$1
  local owner=$2
  local group=$3
  local mode=$4
  local existed_variable=$5
  local identity_variable=$6
  local identity
  [[ ! -e ${path} && ! -L ${path} ]] || die "${path} appeared after preflight"
  defer_cleanup_signals
  mkdir -- "${path}" || die "could not create ${path}"
  printf -v "${existed_variable}" '%s' false
  identity=$(stat -c '%d:%i' -- "${path}") || die "could not record the identity of ${path}"
  printf -v "${identity_variable}" '%s' "${identity}"
  chown "${owner}:${group}" -- "${path}" || die "could not set the owner of ${path}"
  chmod "${mode}" -- "${path}" || die "could not set the mode of ${path}"
  resume_cleanup_signals || die "installation was interrupted while journaling ${path}"
}

rollback_created_directory() {
  local path=$1
  local expected_identity=$2
  local label=${3:-directory}
  if [[ -z ${expected_identity} ||
    ! -d ${path} ||
    -L ${path} ||
    $(stat -c '%d:%i' -- "${path}" 2>/dev/null || true) != "${expected_identity}" ]]; then
    printf '%s\n' "install-autostream-local-executor: rollback refused changed ${label}; inspect ${path}" >&2
    return 1
  fi
  if ! rmdir -- "${path}"; then
    printf '%s\n' "install-autostream-local-executor: rollback could not remove new ${label}; inspect ${path}" >&2
    return 1
  fi
}

remove_fresh_empty_directory() {
  local path=$1
  local existed=$2
  local expected_metadata=$3
  local expected_identity=${4:-${release_root_identity}}
  if [[ ${existed} == true ]]; then
    return
  fi
  if [[ ! -d ${path} ||
    -L ${path} ||
    $(stat -c '%U:%G:%a' -- "${path}" 2>/dev/null || true) != "${expected_metadata}" ]]; then
    printf '%s\n' "install-autostream-local-executor: rollback refused changed directory; inspect ${path}" >&2
    return 1
  fi
  rollback_created_directory "${path}" "${expected_identity}" "${path} directory"
}
