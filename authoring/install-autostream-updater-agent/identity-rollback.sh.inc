
validate_state_tree() {
  local root=$1
  local root_device
  local entry
  root_device=$(stat -c '%d' -- "${root}") || die "could not read the Host Agent state filesystem"
  while IFS= read -r -d '' entry; do
    if [[ -L ${entry} || ( ! -d ${entry} && ! -f ${entry} ) ]]; then
      printf '%s\n' "install-autostream-host-agent: Host Agent state contains a symlink or special file: ${entry}" >&2
      return 1
    fi
    if [[ $(stat -c '%d' -- "${entry}") != "${root_device}" ]]; then
      printf '%s\n' "install-autostream-host-agent: Host Agent state contains a nested mount: ${entry}" >&2
      return 1
    fi
  done < <(find "${root}" -xdev -mindepth 1 -print0)
}

restore_host_agent_state() {
  local root_device
  local entry
  local snapshot_device
  local snapshot_inode
  local snapshot_uid
  local snapshot_gid
  local snapshot_mode
  if [[ ${state_dir_existed} == true && ${state_snapshot_ready} == true ]]; then
    IFS=: read -r snapshot_device snapshot_inode snapshot_uid snapshot_gid snapshot_mode \
      <<<"${state_root_snapshot}"
    [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} &&
      $(stat -c '%d:%i' -- "${STATE_DIR}") == "${snapshot_device}:${snapshot_inode}" ]] || {
      printf '%s\n' 'install-autostream-host-agent: rollback refused a replaced Host Agent state root' >&2
      return 1
    }
    validate_state_tree "${STATE_DIR}" || return 1
    find "${STATE_DIR}" -xdev -mindepth 1 -delete || return 1
    tar --numeric-owner --same-owner --same-permissions -xpf "${state_snapshot}" \
      -C "${STATE_DIR}" || return 1
    chown "${snapshot_uid}:${snapshot_gid}" -- "${STATE_DIR}" || return 1
    chmod "${snapshot_mode}" -- "${STATE_DIR}" || return 1
    [[ $(stat -c '%d:%i:%u:%g:%a' -- "${STATE_DIR}") == "${state_root_snapshot}" ]] || \
      return 1
    return
  fi
  if [[ ${state_dir_created} == true ]]; then
    [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} &&
      $(stat -c '%d:%i' -- "${STATE_DIR}" 2>/dev/null || true) == "${state_dir_identity}" ]] || {
      printf '%s\n' 'install-autostream-host-agent: rollback refused a replaced fresh Host Agent state root' >&2
      return 1
    }
    root_device=$(stat -c '%d' -- "${STATE_DIR}") || return 1
    while IFS= read -r -d '' entry; do
      [[ ! -L ${entry} && ( -d ${entry} || -f ${entry} ) &&
        $(stat -c '%d' -- "${entry}") == "${root_device}" ]] || {
        printf '%s\n' "install-autostream-host-agent: rollback refused unsafe fresh state entry ${entry}" >&2
        return 1
      }
    done < <(find "${STATE_DIR}" -xdev -mindepth 1 -print0)
    find "${STATE_DIR}" -xdev -mindepth 1 -delete || return 1
    rollback_created_directory "${STATE_DIR}" "${state_dir_identity}" "Host Agent state directory" ||
      return 1
    state_dir_created=false
  fi
}

prepare_identity_parent_traversal() {
  local acl_entry
  local agent_gid
  local agent_uid
  local managed_acl_entry=""
  agent_uid=$(id -u "${AGENT_USER}")
  agent_gid=$(id -g "${AGENT_USER}")
  identity_parent_acl_before=$(getfacl --absolute-names --numeric -- /etc/autostream) || \
    die "could not snapshot the identity parent ACL"
  while IFS= read -r acl_entry; do
    case "${acl_entry}" in
      "user:${agent_uid}:"*)
        [[ -z ${managed_acl_entry} ]] || \
          die "the identity parent contains duplicate Agent ACL entries"
        managed_acl_entry=${acl_entry}
        ;;
      "group:${agent_gid}:"*)
        die "the identity parent must not grant access through the dedicated Agent group"
        ;;
    esac
  done <<<"${identity_parent_acl_before}"
  if [[ -n ${managed_acl_entry} && ${managed_acl_entry} != "user:${agent_uid}:--x" ]]; then
    die "the dedicated Agent has a customized identity parent ACL"
  fi
  # Preserve the shared directory mode and all sibling permissions. The
  # dedicated Agent receives search permission only, not listing or writes.
  if runuser --user "${AGENT_USER}" -- test -x /etc/autostream; then
    if runuser --user "${AGENT_USER}" -- test -r /etc/autostream ||
      runuser --user "${AGENT_USER}" -- test -w /etc/autostream; then
      die "the dedicated Agent has excessive identity parent access"
    fi
    [[ ${managed_acl_entry} == "user:${agent_uid}:--x" ]] && return
  fi
  identity_parent_acl_path_identity=$(stat -c '%d:%i:%u:%g:%a' -- /etc/autostream) || \
    die "could not record the identity parent directory"
  defer_cleanup_signals
  identity_parent_acl_changed=true
  if ! setfacl --no-mask -m "u:${agent_uid}:--x" -- /etc/autostream; then
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

rollback_bootstrap_prerequisites() {
  local failed=false
  local rollback_accounts=${1:-true}
  if [[ ${state_dir_created} == true ]] &&
    ! rollback_created_directory \
      "${STATE_DIR}" "${state_dir_identity}" "Host Agent state directory"; then
    failed=true
  fi
  if [[ ${identity_config_dir_created} == true ]] &&
    ! rollback_created_directory \
      "${CONFIG_DIR}" "${identity_config_dir_identity}" "Host Agent identity directory"; then
    failed=true
  fi
  if [[ ${opt_autostream_dir_created} == true ]] &&
    ! rollback_created_directory \
      /opt/autostream "${opt_autostream_dir_identity}" "/opt/autostream directory"; then
    failed=true
  fi
  if [[ ${etc_tmpfiles_dir_created} == true ]] &&
    ! rollback_created_directory \
      /etc/tmpfiles.d "${etc_tmpfiles_dir_identity}" "/etc/tmpfiles.d directory"; then
    failed=true
  fi
  if [[ ${usr_local_libexec_dir_created} == true ]] &&
    ! rollback_created_directory \
      /usr/local/libexec "${usr_local_libexec_dir_identity}" "/usr/local/libexec directory"; then
    failed=true
  fi
  if [[ ${systemd_system_dir_created} == true ]] &&
    ! rollback_created_directory \
      /etc/systemd/system "${systemd_system_dir_identity}" "/etc/systemd/system directory"; then
    failed=true
  fi
  if [[ ${usr_local_bin_dir_created} == true ]] &&
    ! rollback_created_directory \
      /usr/local/bin "${usr_local_bin_dir_identity}" "/usr/local/bin directory"; then
    failed=true
  fi
  if ! restore_identity_parent_traversal; then
    failed=true
  fi
  if [[ ${etc_autostream_dir_created} == true ]] &&
    ! rollback_created_directory \
      /etc/autostream "${etc_autostream_dir_identity}" "/etc/autostream directory"; then
    failed=true
  fi
  if [[ ${rollback_accounts} == true ]] &&
    ! rollback_created_account; then
    failed=true
  fi
  [[ ${failed} == false ]]
}
