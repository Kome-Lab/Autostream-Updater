
acquire_active_job_recovery_locks() {
  acquire_shared_host_setup_lock
  active_job_recovery_setup_lock_held=true
  active_job_recovery_lock_dir_identity="$(
    stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK_DIR}"
  )" || die "could not record the active-job recovery lock directory identity"
  acquire_host_lifecycle_lock
  active_job_recovery_lifecycle_lock_held=true
}

active_job_recovery_root_parent_chain_is_safe() {
  local path=$1
  local current
  local mode
  local owner
  local parent
  current="$(dirname -- "${path}")" || return 1
  while true; do
    [[ -d ${current} && ! -L ${current} ]] || return 1
    owner="$(stat -c '%U:%G' -- "${current}")" || return 1
    [[ ${owner} == "root:root" ]] || return 1
    mode="$(stat -c '%a' -- "${current}")" || return 1
    [[ ${mode} =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#${mode} & 0022) == 0 )) || return 1
    parent="$(dirname -- "${current}")" || return 1
    [[ ${parent} == "${current}" ]] && break
    current=${parent}
  done
}

active_job_recovery_lock_directory_is_stable() {
  local directory_identity
  [[ -n ${active_job_recovery_lock_dir_identity} ]] || return 1
  active_job_recovery_root_parent_chain_is_safe \
    "${HOST_LIFECYCLE_LOCK}" || return 1
  [[ -d ${SHARED_HOST_SETUP_LOCK_DIR} &&
    ! -L ${SHARED_HOST_SETUP_LOCK_DIR} ]] || return 1
  [[ $(readlink -f -- "${SHARED_HOST_SETUP_LOCK_DIR}") == \
    "${SHARED_HOST_SETUP_LOCK_DIR}" ]] || return 1
  [[ $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == \
    "root:root:700" ]] || return 1
  directory_identity="$(stat -c '%d:%i' -- \
    "${SHARED_HOST_SETUP_LOCK_DIR}")" || return 1
  [[ ${directory_identity} == "${active_job_recovery_lock_dir_identity}" ]]
}

active_job_recovery_lock_path_is_safe() {
  local path=$1
  [[ -f ${path} && ! -L ${path} ]] || return 1
  [[ $(readlink -f -- "${path}") == "${path}" ]] || return 1
  [[ $(stat -c '%U:%G:%a:%h' -- "${path}") == \
    "root:root:600:1" ]]
}

active_job_recovery_lock_fd_matches_path() {
  local descriptor=$1
  local path=$2
  local fd_path="/proc/self/fd/${descriptor}"
  local fd_identity
  local path_identity
  [[ -f ${fd_path} ]] || return 1
  [[ $(stat -Lc '%U:%G:%a:%h' -- "${fd_path}") == \
    "root:root:600:1" ]] || return 1
  fd_identity="$(stat -Lc '%d:%i' -- "${fd_path}")" || return 1
  path_identity="$(stat -c '%d:%i' -- "${path}")" || return 1
  [[ ${fd_identity} == "${path_identity}" ]]
}

try_reacquire_active_job_recovery_setup_lock() {
  if [[ ${active_job_recovery_setup_lock_held} == true ]]; then
    return 0
  fi
  [[ ${active_job_recovery_lifecycle_lock_held} == false ]] || return 1
  active_job_recovery_lock_directory_is_stable || return 1
  active_job_recovery_lock_path_is_safe "${SHARED_HOST_SETUP_LOCK}" || return 1
  # Read-only open avoids creating or truncating permanent coordination state
  # during best-effort cleanup. flock(2) does not require a writable descriptor.
  exec 8<"${SHARED_HOST_SETUP_LOCK}" || return 1
  if ! active_job_recovery_lock_directory_is_stable ||
    ! active_job_recovery_lock_path_is_safe "${SHARED_HOST_SETUP_LOCK}" ||
    ! active_job_recovery_lock_fd_matches_path 8 "${SHARED_HOST_SETUP_LOCK}"; then
    exec 8>&-
    return 1
  fi
  if ! flock -n 8; then
    exec 8>&-
    return 1
  fi
  if ! active_job_recovery_lock_directory_is_stable ||
    ! active_job_recovery_lock_path_is_safe "${SHARED_HOST_SETUP_LOCK}" ||
    ! active_job_recovery_lock_fd_matches_path 8 "${SHARED_HOST_SETUP_LOCK}"; then
    flock -u 8 >/dev/null 2>&1 || true
    exec 8>&-
    return 1
  fi
  active_job_recovery_setup_lock_held=true
}

try_reacquire_active_job_recovery_lifecycle_lock() {
  if [[ ${active_job_recovery_lifecycle_lock_held} == true ]]; then
    [[ ${active_job_recovery_setup_lock_held} == true ]] || return 1
    return 0
  fi
  [[ ${active_job_recovery_setup_lock_held} == true ]] || return 1
  active_job_recovery_lock_directory_is_stable || return 1
  active_job_recovery_lock_path_is_safe "${HOST_LIFECYCLE_LOCK}" || return 1
  exec 9<"${HOST_LIFECYCLE_LOCK}" || return 1
  if ! active_job_recovery_lock_directory_is_stable ||
    ! active_job_recovery_lock_path_is_safe "${HOST_LIFECYCLE_LOCK}" ||
    ! active_job_recovery_lock_fd_matches_path 9 "${HOST_LIFECYCLE_LOCK}"; then
    exec 9>&-
    return 1
  fi
  if ! flock -n 9; then
    exec 9>&-
    return 1
  fi
  if ! active_job_recovery_lock_directory_is_stable ||
    ! active_job_recovery_lock_path_is_safe "${HOST_LIFECYCLE_LOCK}" ||
    ! active_job_recovery_lock_fd_matches_path 9 "${HOST_LIFECYCLE_LOCK}"; then
    flock -u 9 >/dev/null 2>&1 || true
    exec 9>&-
    return 1
  fi
  active_job_recovery_lifecycle_lock_held=true
}

reacquire_active_job_recovery_cleanup_locks() {
  try_reacquire_active_job_recovery_setup_lock || return 1
  try_reacquire_active_job_recovery_lifecycle_lock
}

release_active_job_recovery_lifecycle_lock() {
  local release_failed=false
  [[ ${active_job_recovery_lifecycle_lock_held} == true ]] || return 0
  flock -u 9 || release_failed=true
  exec 9>&-
  # Closing the descriptor releases its lock even if the explicit unlock
  # command reported an error. Never retry against a recycled descriptor.
  active_job_recovery_lifecycle_lock_held=false
  if [[ ${release_failed} == true ]]; then
    printf '%s\n' \
      'install-autostream-host-agent: could not release the active-job lifecycle lock' >&2
    return 1
  fi
}

reacquire_active_job_recovery_lifecycle_lock() {
  [[ ${active_job_recovery_setup_lock_held} == true &&
    ${active_job_recovery_lifecycle_lock_held} == false ]] || \
    die "active-job recovery lock state is invalid"
  try_reacquire_active_job_recovery_lifecycle_lock || \
    die "another privileged Host lifecycle operation is active after exact active job recovery"
}

release_active_job_recovery_setup_lock() {
  local release_failed=false
  [[ ${active_job_recovery_setup_lock_held} == true ]] || return 0
  flock -u 8 || release_failed=true
  exec 8>&-
  active_job_recovery_setup_lock_held=false
  if [[ ${release_failed} == true ]]; then
    printf '%s\n' \
      'install-autostream-host-agent: could not release the active-job setup lock' >&2
    return 1
  fi
}

release_active_job_recovery_locks() {
  local release_failed=false
  release_active_job_recovery_lifecycle_lock || release_failed=true
  release_active_job_recovery_setup_lock || release_failed=true
  [[ ${release_failed} == false ]]
}
