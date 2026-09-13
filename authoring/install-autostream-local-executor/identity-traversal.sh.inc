
prepare_identity_parent_traversal() {
  local acl_entry
  local traversal_agent_gid
  local traversal_agent_uid
  local managed_acl_entry=""
  traversal_agent_uid=$(id -u "${AGENT_USER}")
  traversal_agent_gid=$(id -g "${AGENT_USER}")
  identity_parent_acl_before=$(getfacl --absolute-names --numeric -- /etc/autostream) || \
    die "could not snapshot the identity parent ACL"
  while IFS= read -r acl_entry; do
    case "${acl_entry}" in
      "user:${traversal_agent_uid}:"*)
        [[ -z ${managed_acl_entry} ]] || \
          die "the identity parent contains duplicate Agent ACL entries"
        managed_acl_entry=${acl_entry}
        ;;
      "group:${traversal_agent_gid}:"*)
        die "the identity parent must not grant access through the dedicated Agent group"
        ;;
    esac
  done <<<"${identity_parent_acl_before}"
  if [[ -n ${managed_acl_entry} && ${managed_acl_entry} != "user:${traversal_agent_uid}:--x" ]]; then
    die "the dedicated Agent has a customized identity parent ACL"
  fi
  # Preserve the shared directory mode and all sibling permissions. The
  # dedicated Agent receives search permission only, not listing or writes.
  if runuser --user "${AGENT_USER}" -- test -x /etc/autostream; then
    if runuser --user "${AGENT_USER}" -- test -r /etc/autostream ||
      runuser --user "${AGENT_USER}" -- test -w /etc/autostream; then
      die "the dedicated Agent has excessive identity parent access"
    fi
    [[ ${managed_acl_entry} == "user:${traversal_agent_uid}:--x" ]] && return
  fi
  identity_parent_acl_path_identity=$(stat -c '%d:%i:%u:%g:%a' -- /etc/autostream) || \
    die "could not record the identity parent directory"
  defer_cleanup_signals
  identity_parent_acl_changed=true
  if ! setfacl --no-mask -m "u:${traversal_agent_uid}:--x" -- /etc/autostream; then
    identity_parent_acl_after=$(getfacl --absolute-names --numeric -- /etc/autostream) || true
    die "could not grant the dedicated Agent identity traversal"
  fi
  identity_parent_acl_after=$(getfacl --absolute-names --numeric -- /etc/autostream) || \
    die "could not verify the identity parent ACL"
  [[ $(stat -c '%d:%i:%u:%g:%a' -- /etc/autostream) == "${identity_parent_acl_path_identity}" ]] || \
    die "identity traversal changed the shared directory ownership or mode"
  sync -f /etc/autostream
  resume_cleanup_signals || die "installation was interrupted while journaling identity traversal"
  runuser --user "${AGENT_USER}" -- test -x /etc/autostream || \
    die "the existing identity parent ACL mask does not allow dedicated traversal"
  if runuser --user "${AGENT_USER}" -- test -r /etc/autostream ||
    runuser --user "${AGENT_USER}" -- test -w /etc/autostream; then
    die "identity traversal granted listing or write access to the shared directory"
  fi
}

restore_identity_parent_traversal() {
  [[ ${identity_parent_acl_changed} == true ]] || return 0
  if [[ -L /etc/autostream || ! -d /etc/autostream ||
    -z ${identity_parent_acl_after} ||
    $(stat -c '%d:%i:%u:%g:%a' -- /etc/autostream) != "${identity_parent_acl_path_identity}" ||
    $(getfacl --absolute-names --numeric -- /etc/autostream) != "${identity_parent_acl_after}" ]]; then
    printf '%s\n' 'AutoStream installer: rollback refused a changed identity parent ACL' >&2
    return 1
  fi
  printf '%s\n' "${identity_parent_acl_before}" | setfacl --restore=- || return 1
  [[ $(getfacl --absolute-names --numeric -- /etc/autostream) == "${identity_parent_acl_before}" ]] || return 1
  sync -f /etc/autostream || return 1
  identity_parent_acl_changed=false
}

rollback_prerequisite_directories() {
  local failed=false
  if [[ ${docker_config_dir_existed} == false && -n ${docker_config_dir_identity} ]] &&
    ! rollback_created_directory \
      "${DOCKER_CONFIG_DIR}" "${docker_config_dir_identity}" "Docker config directory"; then
    failed=true
  fi
  if [[ ${executor_config_dir_existed} == false && -n ${executor_config_dir_identity} ]] &&
    ! rollback_created_directory \
      "${EXECUTOR_CONFIG_DIR}" "${executor_config_dir_identity}" "Local Executor private config directory"; then
    failed=true
  fi
  if [[ ${config_dir_existed} == false && -n ${config_dir_identity} ]] &&
    ! rollback_created_directory "${CONFIG_DIR}" "${config_dir_identity}" \
      "Updater configuration directory"; then
    failed=true
  fi
  if [[ ${docker_port_config_dir_existed} == false && -n ${docker_port_config_dir_identity} ]] &&
    ! rollback_created_directory \
      "${DOCKER_PORT_CONFIG_DIR}" "${docker_port_config_dir_identity}" "Docker port directory"; then
    failed=true
  fi
  if [[ ${docker_version_dir_existed} == false && -n ${docker_version_dir_identity} ]] &&
    ! rollback_created_directory \
      "${DOCKER_VERSION_DIR}" "${docker_version_dir_identity}" "Docker data directory"; then
    failed=true
  fi
  if [[ ${port_config_dir_existed} == false && -n ${port_config_dir_identity} ]] &&
    ! rollback_created_directory \
      "${PORT_CONFIG_DIR}" "${port_config_dir_identity}" "port data directory"; then
    failed=true
  fi
  if [[ ${executor_data_dir_existed} == false && -n ${executor_data_dir_identity} ]] &&
    ! rollback_created_directory \
      "${EXECUTOR_DATA_DIR}" "${executor_data_dir_identity}" "Local Executor data directory"; then
    failed=true
  fi
  if [[ ${etc_tmpfiles_dir_existed} == false && -n ${etc_tmpfiles_dir_identity} ]] &&
    ! rollback_created_directory \
      /etc/tmpfiles.d "${etc_tmpfiles_dir_identity}" "/etc/tmpfiles.d directory"; then
    failed=true
  fi
  if [[ ${systemd_system_dir_existed} == false && -n ${systemd_system_dir_identity} ]] &&
    ! rollback_created_directory \
      /etc/systemd/system "${systemd_system_dir_identity}" "/etc/systemd/system directory"; then
    failed=true
  fi
  if [[ ${usr_local_libexec_dir_existed} == false && -n ${usr_local_libexec_dir_identity} ]] &&
    ! rollback_created_directory \
      /usr/local/libexec "${usr_local_libexec_dir_identity}" "/usr/local/libexec directory"; then
    failed=true
  fi
  if ! restore_identity_parent_traversal; then
    failed=true
  fi
  if [[ ${etc_autostream_dir_existed} == false && -n ${etc_autostream_dir_identity} ]] &&
    ! rollback_created_directory \
      /etc/autostream "${etc_autostream_dir_identity}" "identity parent directory"; then
    failed=true
  fi
  [[ ${failed} == false ]]
}
