
cleanup_prerequisites() {
  local status=$?
  local rollback_failed=false
  local release_root_path=${EXECUTOR_DATA_DIR%/*}
  trap '' INT TERM
  trap - EXIT
  [[ -z ${policy_stage:-} ]] || rm -f -- "${policy_stage}"
  [[ -z ${binary_stage:-} ]] || rm -f -- "${binary_stage}"
  [[ -z ${service_stage:-} ]] || rm -f -- "${service_stage}"
  [[ -z ${socket_stage:-} ]] || rm -f -- "${socket_stage}"
  [[ -z ${tmpfiles_stage:-} ]] || rm -f -- "${tmpfiles_stage}"
  rollback_prerequisite_directories || rollback_failed=true
  if ! remove_fresh_empty_directory \
    "${release_root_path}" "${release_root_existed}" "root:root:755"; then
    rollback_failed=true
  fi
  if [[ -n ${BUNDLE_STAGE:-} &&
    ${BUNDLE_STAGE} == /var/tmp/autostream-local-executor-install.* &&
    -d ${BUNDLE_STAGE} &&
    ! -L ${BUNDLE_STAGE} ]]; then
    rm -rf -- "${BUNDLE_STAGE}"
  fi
  if [[ ${rollback_failed} == true ]]; then
    exit 1
  fi
  exit "${status}"
}

verify_existing() {
  local path=$1
  local expected=$2
  local label=$3
  local existed_variable=$4
  local identity_variable=$5
  if [[ ! -e ${path} && ! -L ${path} ]]; then
    printf -v "${existed_variable}" '%s' false
    return 0
  fi
  [[ -f ${path} && ! -L ${path} ]] || die "${label} destination is not a regular non-symlink file"
  [[ $(stat -c '%U:%G:%a' -- "${path}") == "${expected}" ]] || \
    die "${label} destination owner or mode drifted"
  printf -v "${existed_variable}" '%s' true
  printf -v "${identity_variable}" '%s' "$(stat -c '%d:%i:%s:%Y:%f:%u:%g' -- "${path}")"
}

validate_managed_runtime_binary() {
  local current_target
  local resolved
  local expected_resolved
  local release_sha256
  local active_sha256
  [[ -L ${BINARY_DEST} ]] || return 1
  validate_root_parent_chain "${BINARY_DEST}" "binary destination"
  [[ $(stat -c '%U:%G' -- "${BINARY_DEST}") == "root:root" ]] || \
    die "managed A/B binary link must be owned by root:root"
  [[ $(readlink -- "${BINARY_DEST}") == "${HOST_RUNTIME_CURRENT}/bin/autostream-local-executor" ]] || \
    die "binary destination symlink is outside the fixed Host Agent A/B runtime"
  [[ -L ${HOST_RUNTIME_CURRENT} ]] || \
    die "managed A/B binary is missing the fixed current symlink"
  [[ $(stat -c '%U:%G' -- "${HOST_RUNTIME_CURRENT}") == "root:root" ]] || \
    die "managed A/B current symlink must be owned by root:root"
  current_target=$(readlink -- "${HOST_RUNTIME_CURRENT}")
  [[ ${current_target} == "slots/a" || ${current_target} == "slots/b" ]] || \
    die "managed A/B current symlink points outside the fixed slots"
  expected_resolved="${HOST_RUNTIME_ROOT}/${current_target}/bin/autostream-local-executor"
  resolved=$(readlink -f -- "${BINARY_DEST}") || \
    die "managed A/B binary link could not be resolved"
  [[ ${resolved} == "${expected_resolved}" ]] || \
    die "managed A/B binary resolved outside the active fixed slot"
  [[ -f ${resolved} && ! -L ${resolved} ]] || \
    die "managed A/B binary must resolve to a regular non-symlink file"
  [[ $(stat -c '%U:%G:%a' -- "${resolved}") == "root:root:755" ]] || \
    die "managed A/B binary owner or mode drifted"
  validate_root_parent_chain "${resolved}" "managed A/B binary"
  release_sha256=$(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }')
  active_sha256=$(sha256sum -- "${resolved}" | awk 'NR == 1 { print $1 }')
  [[ ${active_sha256} == "${release_sha256}" ]] || \
    die "managed A/B binary does not match this verified Host Agent release"
}

binary_managed_link=false
verify_existing \
  "${POLICY_DEST}" "root:root:600" "policy" policy_existed policy_identity
if [[ -L ${BINARY_DEST} ]]; then
  validate_managed_runtime_binary
  binary_managed_link=true
else
  verify_existing \
    "${BINARY_DEST}" "root:root:755" "binary" binary_existed binary_identity
fi
verify_existing \
  "${SERVICE_DEST}" "root:root:644" "service unit" service_existed service_identity
verify_existing \
  "${SOCKET_DEST}" "root:root:644" "socket unit" socket_existed socket_identity
verify_existing \
  "${TMPFILES_DEST}" "root:root:644" "tmpfiles policy" tmpfiles_existed tmpfiles_identity

verify_unit_inactive "${HOST_AGENT_SERVICE_NAME}"
verify_unit_disabled "${HOST_AGENT_SERVICE_NAME}"
arm_cleanup_handler cleanup_prerequisites

ensure_root_directory() {
  local path=$1
  local create_mode=$2
  local existed_variable=${3:-release_root_existed}
  local identity_variable=${4:-release_root_identity}
  local mode
  if [[ -e ${path} || -L ${path} ]]; then
    [[ -d ${path} && ! -L ${path} ]] || die "${path} must be a non-symlink directory"
    [[ $(stat -c '%U:%G' -- "${path}") == "root:root" ]] || die "${path} must be owned by root:root"
    mode=$(stat -c '%a' -- "${path}")
    (( (8#${mode} & 0022) == 0 )) || die "${path} must not be writable by group or other"
    printf -v "${existed_variable}" '%s' true
    printf -v "${identity_variable}" '%s' "$(stat -c '%d:%i' -- "${path}")"
    return
  fi
  create_managed_directory \
    "${path}" root root "${create_mode}" "${existed_variable}" "${identity_variable}"
}

ensure_root_directory /etc/autostream 0750 \
  etc_autostream_dir_existed etc_autostream_dir_identity
prepare_identity_parent_traversal
if [[ -e ${CONFIG_DIR} || -L ${CONFIG_DIR} ]]; then
  [[ -d ${CONFIG_DIR} && ! -L ${CONFIG_DIR} &&
    $(stat -c '%U:%G:%a' -- "${CONFIG_DIR}") == "root:${AGENT_GROUP}:750" ]] || \
    die "${CONFIG_DIR} must be root:${AGENT_GROUP} 0750"
  [[ $(getfacl --omit-header --numeric -- "${CONFIG_DIR}") == $'user::rwx\ngroup::r-x\nother::---' ]] || \
    die "Updater identity directory must not grant named or inherited ACL access"
  config_dir_existed=true
  config_dir_identity=$(stat -c '%d:%i' -- "${CONFIG_DIR}")
else
  create_managed_directory \
    "${CONFIG_DIR}" root "${AGENT_GROUP}" 0750 config_dir_existed config_dir_identity
  setfacl --remove-all --remove-default -- "${CONFIG_DIR}" || \
    die "could not remove inherited ACLs from the new identity directory"
fi
ensure_root_directory \
  "${EXECUTOR_CONFIG_DIR}" 0700 executor_config_dir_existed executor_config_dir_identity
[[ $(stat -c '%U:%G:%a' -- "${EXECUTOR_CONFIG_DIR}") == "root:root:700" ]] || \
  die "${EXECUTOR_CONFIG_DIR} must be root:root 0700"
ensure_root_directory /usr/local/libexec 0755 \
  usr_local_libexec_dir_existed usr_local_libexec_dir_identity
ensure_root_directory \
  /etc/systemd/system 0755 systemd_system_dir_existed systemd_system_dir_identity
ensure_root_directory /etc/tmpfiles.d 0755 \
  etc_tmpfiles_dir_existed etc_tmpfiles_dir_identity
if [[ -e /opt/autostream || -L /opt/autostream ]]; then
  release_root_existed=true
fi
ensure_root_directory /opt/autostream 0755
ensure_root_directory \
  "${EXECUTOR_DATA_DIR}" 0700 executor_data_dir_existed executor_data_dir_identity
ensure_root_directory \
  "${PORT_CONFIG_DIR}" 0700 port_config_dir_existed port_config_dir_identity
ensure_root_directory \
  "${DOCKER_VERSION_DIR}" 0700 docker_version_dir_existed docker_version_dir_identity
ensure_root_directory \
  "${DOCKER_PORT_CONFIG_DIR}" 0700 \
  docker_port_config_dir_existed docker_port_config_dir_identity
ensure_root_directory \
  "${DOCKER_CONFIG_DIR}" 0700 docker_config_dir_existed docker_config_dir_identity
for private_dir in "${EXECUTOR_DATA_DIR}" "${PORT_CONFIG_DIR}" "${DOCKER_VERSION_DIR}" "${DOCKER_PORT_CONFIG_DIR}" "${DOCKER_CONFIG_DIR}"; do
  [[ $(stat -c '%U:%G:%a' -- "${private_dir}") == "root:root:700" ]] || \
    die "${private_dir} must be root:root 0700"
done
unexpected_docker_config=$(find "${DOCKER_CONFIG_DIR}" -mindepth 1 -maxdepth 1 ! -name config.json -print -quit)
[[ -z ${unexpected_docker_config} ]] || \
  die "${DOCKER_CONFIG_DIR} must contain only config.json"
if [[ -e ${DOCKER_CONFIG_FILE} || -L ${DOCKER_CONFIG_FILE} ]]; then
  [[ -f ${DOCKER_CONFIG_FILE} && ! -L ${DOCKER_CONFIG_FILE} ]] || \
    die "${DOCKER_CONFIG_FILE} must be a regular non-symlink file"
  [[ $(stat -c '%U:%G:%a' -- "${DOCKER_CONFIG_FILE}") == "root:root:600" ]] || \
    die "${DOCKER_CONFIG_FILE} must be root:root 0600"
fi

if [[ -e ${SOCKET_DIR} || -L ${SOCKET_DIR} ]]; then
  [[ -d ${SOCKET_DIR} && ! -L ${SOCKET_DIR} ]] || die "socket path must be a non-symlink directory"
  [[ $(stat -c '%U:%G:%a' -- "${SOCKET_DIR}") == "root:${AGENT_GROUP}:750" ]] || \
    die "socket directory must be root:${AGENT_GROUP} 0750"
  socket_dir_existed=true
  socket_dir_identity=$(stat -c '%d:%i' -- "${SOCKET_DIR}")
fi
if [[ -e ${UPDATER_RUNTIME_DIR} || -L ${UPDATER_RUNTIME_DIR} ]]; then
  [[ -d ${UPDATER_RUNTIME_DIR} && ! -L ${UPDATER_RUNTIME_DIR} ]] || \
    die "updater runtime path must be a non-symlink directory"
  [[ $(stat -c '%U:%G:%a' -- "${UPDATER_RUNTIME_DIR}") == "root:root:700" ]] || \
    die "updater runtime directory must be root:root 0700"
  updater_runtime_dir_existed=true
  updater_runtime_dir_identity=$(stat -c '%d:%i' -- "${UPDATER_RUNTIME_DIR}")
fi
if [[ -e ${STATE_DIR} || -L ${STATE_DIR} ]]; then
  [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} ]] || die "state path must be a non-symlink directory"
  [[ $(stat -c '%U:%G:%a' -- "${STATE_DIR}") == "root:root:700" ]] || \
    die "state directory must be root:root 0700"
  state_dir_existed=true
  state_dir_identity=$(stat -c '%d:%i' -- "${STATE_DIR}")
  state_root_snapshot=$(stat -c '%d:%i:%u:%g:%a' -- "${STATE_DIR}")
fi

create_temp_file policy_stage "${CONFIG_DIR}/.executor-policy.json.new.XXXXXX"
create_temp_file binary_stage /usr/local/libexec/.autostream-local-executor.new.XXXXXX
create_temp_file service_stage /etc/systemd/system/.autostream-local-executor.service.new.XXXXXX
create_temp_file socket_stage /etc/systemd/system/.autostream-local-executor.socket.new.XXXXXX
create_temp_file tmpfiles_stage /etc/tmpfiles.d/.autostream-local-executor.conf.new.XXXXXX
