
unit_active_state() {
  local unit=$1
  local state=""
  local status=0
  if state=$(systemctl is-active "${unit}" 2>/dev/null); then
    status=0
  else
    status=$?
  fi
  case "${status}:${state}" in
    0:active) printf '%s\n' active ;;
    3:inactive|4:inactive|4:unknown) printf '%s\n' inactive ;;
    *) die "could not establish a stable active state for ${unit}" ;;
  esac
}

unit_enabled_state() {
  local unit=$1
  local state=""
  local status=0
  if state=$(systemctl is-enabled "${unit}" 2>/dev/null); then
    status=0
  else
    status=$?
  fi
  case "${status}:${state}" in
    0:enabled) printf '%s\n' enabled ;;
    1:disabled|1:not-found|4:not-found) printf '%s\n' disabled ;;
    *) die "could not establish a stable enablement state for ${unit}" ;;
  esac
}

verify_unit_inactive() {
  local unit=$1
  [[ $(unit_active_state "${unit}") == "inactive" ]] || die "${unit} must be inactive"
}

verify_unit_disabled() {
  local unit=$1
  [[ $(unit_enabled_state "${unit}") == "disabled" ]] || die "${unit} must be disabled"
}

verify_initial_runtime_state() {
  local expected_socket_enabled=disabled
  local expected_socket_active=inactive
  local expected_service_active=inactive
  [[ ${was_socket_enabled} == true ]] && expected_socket_enabled=enabled
  [[ ${was_socket_active} == true ]] && expected_socket_active=active
  [[ ${was_service_active} == true ]] && expected_service_active=active
  [[ $(unit_enabled_state "${SOCKET_NAME}") == "${expected_socket_enabled}" &&
    $(unit_active_state "${SOCKET_NAME}") == "${expected_socket_active}" &&
    $(unit_active_state "${SERVICE_NAME}") == "${expected_service_active}" ]]
}

restore_initial_runtime_state() {
  local failed=false
  if [[ ${was_socket_enabled} == true ]]; then
    systemctl enable "${SOCKET_NAME}" >/dev/null 2>&1 || true
  else
    systemctl disable "${SOCKET_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ ${was_service_active} == true ]]; then
    systemctl start "${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ ${was_socket_active} == true ]]; then
    systemctl start "${SOCKET_NAME}" >/dev/null 2>&1 || true
  fi
  if ! verify_initial_runtime_state; then
    failed=true
  fi
  [[ ${failed} == false ]]
}

validate_executor_state_tree() {
  local root=$1
  local root_device
  local entry
  root_device=$(stat -c '%d' -- "${root}") || die "could not read the Local Executor state filesystem"
  while IFS= read -r -d '' entry; do
    if [[ -L ${entry} || ( ! -d ${entry} && ! -f ${entry} ) ]]; then
      printf '%s\n' "install-autostream-local-executor: Local Executor state contains a symlink or special file: ${entry}" >&2
      return 1
    fi
    if [[ $(stat -c '%d' -- "${entry}") != "${root_device}" ]]; then
      printf '%s\n' "install-autostream-local-executor: Local Executor state contains a nested mount: ${entry}" >&2
      return 1
    fi
  done < <(find "${root}" -xdev -mindepth 1 -print0)
}

snapshot_executor_state() {
  [[ ${state_dir_existed} == true ]] || return 0
  [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} &&
    $(stat -c '%d:%i' -- "${STATE_DIR}") == "${state_dir_identity}" ]] || \
    die "Local Executor state directory changed before snapshot"
  validate_executor_state_tree "${STATE_DIR}" || \
    die "existing Local Executor state is unsafe to snapshot"
  state_snapshot="${BUNDLE_STAGE}/local-executor-state.before.tar"
  tar --numeric-owner --one-file-system -cpf "${state_snapshot}" -C "${STATE_DIR}" . || \
    die "could not snapshot existing Local Executor state"
  [[ -f ${state_snapshot} && ! -L ${state_snapshot} ]] || \
    die "Local Executor state snapshot is missing or unsafe"
  state_snapshot_ready=true
}

capture_fresh_runtime_directory() {
  local path=$1
  local existed=$2
  local identity_variable=$3
  if [[ ${existed} == false && -d ${path} && ! -L ${path} ]]; then
    printf -v "${identity_variable}" '%s' "$(stat -c '%d:%i' -- "${path}")"
  fi
}

restore_executor_state() {
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
      printf '%s\n' 'install-autostream-local-executor: rollback refused a replaced state root' >&2
      return 1
    }
    validate_executor_state_tree "${STATE_DIR}" || return 1
    find "${STATE_DIR}" -xdev -mindepth 1 -delete || return 1
    tar --numeric-owner --same-owner --same-permissions -xpf "${state_snapshot}" \
      -C "${STATE_DIR}" || return 1
    chown "${snapshot_uid}:${snapshot_gid}" -- "${STATE_DIR}" || return 1
    chmod "${snapshot_mode}" -- "${STATE_DIR}" || return 1
    [[ $(stat -c '%d:%i:%u:%g:%a' -- "${STATE_DIR}") == "${state_root_snapshot}" ]] || \
      return 1
    return
  fi
  if [[ ${state_dir_existed} == false && -n ${state_dir_identity} ]]; then
    [[ -d ${STATE_DIR} && ! -L ${STATE_DIR} &&
      $(stat -c '%d:%i' -- "${STATE_DIR}" 2>/dev/null || true) == "${state_dir_identity}" ]] || \
      return 1
    root_device=$(stat -c '%d' -- "${STATE_DIR}") || return 1
    while IFS= read -r -d '' entry; do
      [[ ! -L ${entry} && ( -d ${entry} || -f ${entry} ) &&
        $(stat -c '%d' -- "${entry}") == "${root_device}" ]] || return 1
    done < <(find "${STATE_DIR}" -xdev -mindepth 1 -print0)
    find "${STATE_DIR}" -xdev -mindepth 1 -delete || return 1
    rollback_created_directory "${STATE_DIR}" "${state_dir_identity}" "Local Executor state directory" ||
      return 1
    state_dir_identity=""
  fi
}
