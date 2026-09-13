
create_managed_directory() {
  local path=$1
  local owner=$2
  local group=$3
  local mode=$4
  local created_variable=$5
  local identity_variable=$6
  local identity
  [[ ! -e ${path} && ! -L ${path} ]] || die "${path} appeared after preflight"
  defer_cleanup_signals
  mkdir -- "${path}" || die "could not create ${path}"
  printf -v "${created_variable}" '%s' true
  identity=$(stat -c '%d:%i' -- "${path}") || die "could not record the identity of ${path}"
  printf -v "${identity_variable}" '%s' "${identity}"
  chown "${owner}:${group}" -- "${path}" || die "could not set the owner of ${path}"
  chmod "${mode}" -- "${path}" || die "could not set the mode of ${path}"
  resume_cleanup_signals || die "installation was interrupted while journaling ${path}"
}

ensure_root_directory() {
  local path=$1
  local create_mode=$2
  local created_variable=$3
  local identity_variable=$4
  local mode
  if [[ -e ${path} || -L ${path} ]]; then
    [[ -d ${path} && ! -L ${path} ]] || die "${path} must be a non-symlink directory"
    [[ $(stat -c '%U:%G' -- "${path}") == "root:root" ]] || die "${path} must be owned by root:root"
    mode=$(stat -c '%a' -- "${path}")
    (( (8#${mode} & 0022) == 0 )) || die "${path} must not be writable by group or other"
    return
  fi
  create_managed_directory \
    "${path}" root root "${create_mode}" "${created_variable}" "${identity_variable}"
}

validate_private_root_directory() {
  local path=$1
  [[ -d ${path} && ! -L ${path} ]] || die "${path} must be a non-symlink directory"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:root:700" ]] || \
    die "${path} must be root:root 0700"
}

recheck_private_root_directory() {
  local path=$1
  local expected_identity=$2
  validate_private_root_directory "${path}"
  [[ $(stat -c '%d:%i' -- "${path}") == "${expected_identity}" ]] || \
    die "${path} changed after preflight"
}

create_private_root_directory() {
  local path=$1
  local created_variable=$2
  local identity_variable=$3
  create_managed_directory \
    "${path}" root root 0700 "${created_variable}" "${identity_variable}"
  validate_private_root_directory "${path}"
}

validate_identity_directory() {
  local path=$1
  [[ -d ${path} && ! -L ${path} ]] || \
    die "${path} must be a non-symlink directory"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "root:${AGENT_GROUP}:750" ]] || \
    die "${path} must be root:${AGENT_GROUP} 0750"
  [[ $(getfacl --omit-header --numeric -- "${path}") == $'user::rwx\ngroup::r-x\nother::---' ]] || \
    die "Host Agent identity directory must not grant named or inherited ACL access"
}

ensure_root_directory \
  /etc/autostream 0750 etc_autostream_dir_created etc_autostream_dir_identity
prepare_identity_parent_traversal
ensure_root_directory \
  /usr/local/bin 0755 usr_local_bin_dir_created usr_local_bin_dir_identity
ensure_root_directory \
  /etc/systemd/system 0755 systemd_system_dir_created systemd_system_dir_identity
if [[ -e ${CONFIG_DIR} || -L ${CONFIG_DIR} ]]; then
  validate_identity_directory "${CONFIG_DIR}"
  identity_config_dir_identity=$(stat -c '%d:%i' -- "${CONFIG_DIR}")
else
  create_managed_directory \
    "${CONFIG_DIR}" root "${AGENT_GROUP}" 0750 \
    identity_config_dir_created identity_config_dir_identity
  setfacl --remove-all --remove-default -- "${CONFIG_DIR}" || \
    die "could not remove inherited ACLs from the new identity directory"
  validate_identity_directory "${CONFIG_DIR}"
fi
local_executor_data_dir_existed=false
local_executor_port_config_dir_existed=false
local_executor_data_dir_identity=""
local_executor_port_config_dir_identity=""
if [[ ${install_mode} == "prepare" ]]; then
  ensure_root_directory \
    /usr/local/libexec 0755 usr_local_libexec_dir_created usr_local_libexec_dir_identity
  ensure_root_directory \
    /etc/tmpfiles.d 0755 etc_tmpfiles_dir_created etc_tmpfiles_dir_identity
  ensure_root_directory \
    /opt/autostream 0755 opt_autostream_dir_created opt_autostream_dir_identity
  if [[ -e ${LOCAL_EXECUTOR_DATA_DIR} || -L ${LOCAL_EXECUTOR_DATA_DIR} ]]; then
    validate_private_root_directory "${LOCAL_EXECUTOR_DATA_DIR}"
    local_executor_data_dir_existed=true
    local_executor_data_dir_identity=$(stat -c '%d:%i' -- "${LOCAL_EXECUTOR_DATA_DIR}")
  fi
  if [[ -e ${LOCAL_EXECUTOR_PORT_CONFIG_DIR} || -L ${LOCAL_EXECUTOR_PORT_CONFIG_DIR} ]]; then
    validate_private_root_directory "${LOCAL_EXECUTOR_PORT_CONFIG_DIR}"
    local_executor_port_config_dir_existed=true
    local_executor_port_config_dir_identity=$(stat -c '%d:%i' -- "${LOCAL_EXECUTOR_PORT_CONFIG_DIR}")
  fi
fi
if [[ -e ${STATE_DIR} || -L ${STATE_DIR} ]]; then
  [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} ]] || die "${STATE_DIR} must be a non-symlink directory"
  [[ $(stat -c '%U:%G:%a' -- "${STATE_DIR}") == "${AGENT_USER}:${AGENT_GROUP}:700" ]] || \
    die "${STATE_DIR} must be ${AGENT_USER}:${AGENT_GROUP} 0700"
  state_dir_existed=true
  state_dir_identity=$(stat -c '%d:%i' -- "${STATE_DIR}")
  state_root_snapshot=$(stat -c '%d:%i:%u:%g:%a' -- "${STATE_DIR}")
else
  create_managed_directory \
    "${STATE_DIR}" "${AGENT_USER}" "${AGENT_GROUP}" 0700 \
    state_dir_created state_dir_identity
fi

create_temp_file binary_stage /usr/local/bin/.autostream-host-agent.new.XXXXXX
create_temp_file unit_stage /etc/systemd/system/.autostream-host-agent.service.new.XXXXXX
if [[ ${install_mode} == "prepare" ]]; then
  create_temp_file \
    local_executor_binary_stage /usr/local/libexec/.autostream-local-executor.new.XXXXXX
  create_temp_file \
    local_executor_service_stage /etc/systemd/system/.autostream-local-executor.service.new.XXXXXX
  create_temp_file \
    local_executor_socket_stage /etc/systemd/system/.autostream-local-executor.socket.new.XXXXXX
  create_temp_file \
    local_executor_tmpfiles_stage /etc/tmpfiles.d/.autostream-local-executor.conf.new.XXXXXX
  create_temp_file \
    self_update_recovery_service_stage /etc/systemd/system/.autostream-host-self-update-recovery.service.new.XXXXXX
  create_temp_file \
    self_update_recovery_timer_stage /etc/systemd/system/.autostream-host-self-update-recovery.timer.new.XXXXXX
fi
binary_backup=""
unit_backup=""
local_executor_binary_backup=""
local_executor_service_backup=""
local_executor_socket_backup=""
local_executor_tmpfiles_backup=""
self_update_recovery_service_backup=""
self_update_recovery_timer_backup=""
commit_started=false
installation_complete=false
was_active=false
was_enabled=false
service_quiesce_attempted=false
binary_existed=false
unit_existed=false
local_executor_binary_existed=false
local_executor_service_existed=false
local_executor_socket_existed=false
local_executor_tmpfiles_existed=false
self_update_recovery_service_existed=false
self_update_recovery_timer_existed=false
binary_backed_up=false
unit_backed_up=false
local_executor_binary_backed_up=false
local_executor_service_backed_up=false
local_executor_socket_backed_up=false
local_executor_tmpfiles_backed_up=false
self_update_recovery_service_backed_up=false
self_update_recovery_timer_backed_up=false
binary_installed=false
unit_installed=false
local_executor_binary_installed=false
local_executor_service_installed=false
local_executor_socket_installed=false
local_executor_tmpfiles_installed=false
self_update_recovery_service_installed=false
self_update_recovery_timer_installed=false
self_update_recovery_timer_a_enabled=false
self_update_recovery_timer_b_enabled=false
self_update_recovery_timer_a_enable_attempted=false
self_update_recovery_timer_b_enable_attempted=false
binary_managed_link=false
local_executor_data_dir_created=false
local_executor_port_config_dir_created=false
