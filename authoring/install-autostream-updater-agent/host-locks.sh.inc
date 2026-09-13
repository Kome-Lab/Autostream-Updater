
validate_root_parent_chain() {
  local path=$1
  local label=$2
  local current
  local parent
  local mode
  current=$(dirname -- "${path}")
  while true; do
    [[ -d ${current} && ! -L ${current} ]] || die "${label} parents must be non-symlink directories"
    [[ $(stat -c '%U:%G' -- "${current}") == "root:root" ]] || \
      die "${label} parents must be owned by root:root"
    mode=$(stat -c '%a' -- "${current}")
    (( (8#${mode} & 0022) == 0 )) || \
      die "${label} parents must not be writable by group or other"
    parent=$(dirname -- "${current}")
    [[ ${parent} == "${current}" ]] && break
    current=${parent}
  done
}

acquire_shared_host_setup_lock() {
  local directory_identity
  local fd_identity
  local lock_created=false

  # The published lock path is permanent coordination state. Never unlink it:
  # doing so while another process holds the old inode would split the lock.
  validate_root_parent_chain "${SHARED_HOST_SETUP_LOCK_DIR}" "shared host-setup lock"
  if [[ -e ${SHARED_HOST_SETUP_LOCK_DIR} || -L ${SHARED_HOST_SETUP_LOCK_DIR} ]]; then
    [[ -d ${SHARED_HOST_SETUP_LOCK_DIR} &&
      ! -L ${SHARED_HOST_SETUP_LOCK_DIR} &&
      $(readlink -f -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "${SHARED_HOST_SETUP_LOCK_DIR}" &&
      $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "root:root:700" ]] || \
      die "shared host-setup lock directory is unsafe"
  else
    install -d -o root -g root -m 0700 "${SHARED_HOST_SETUP_LOCK_DIR}" || \
      die "could not create the shared host-setup lock directory"
    [[ -d ${SHARED_HOST_SETUP_LOCK_DIR} &&
      ! -L ${SHARED_HOST_SETUP_LOCK_DIR} &&
      $(readlink -f -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "${SHARED_HOST_SETUP_LOCK_DIR}" &&
      $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "root:root:700" ]] || \
      die "could not create a safe shared host-setup lock directory"
    sync -f /run
  fi
  validate_root_parent_chain "${SHARED_HOST_SETUP_LOCK}" "shared host-setup lock"
  directory_identity="$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK_DIR}")" || \
    die "could not record the shared host-setup lock directory identity"

  if [[ -e ${SHARED_HOST_SETUP_LOCK} || -L ${SHARED_HOST_SETUP_LOCK} ]]; then
    [[ -f ${SHARED_HOST_SETUP_LOCK} &&
      ! -L ${SHARED_HOST_SETUP_LOCK} &&
      $(readlink -f -- "${SHARED_HOST_SETUP_LOCK}") == "${SHARED_HOST_SETUP_LOCK}" &&
      $(stat -c '%U:%G:%a:%h' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600:1" ]] || \
      die "shared host-setup lock path is unsafe"
  else
    lock_created=true
  fi
  exec 8<>"${SHARED_HOST_SETUP_LOCK}" || die "could not open the shared host-setup lock"
  fd_identity="$(stat -Lc '%d:%i' -- /proc/self/fd/8)" || \
    die "could not record the shared host-setup lock identity"
  [[ $(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "${directory_identity}" &&
    -f ${SHARED_HOST_SETUP_LOCK} &&
    ! -L ${SHARED_HOST_SETUP_LOCK} &&
    -f /proc/self/fd/8 &&
    $(stat -c '%U:%G:%a:%h' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/8) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}")" ]] || \
    die "shared host-setup lock identity changed while being opened"
  if [[ ${lock_created} == true ]]; then
    sync -f "${SHARED_HOST_SETUP_LOCK_DIR}"
  fi
  flock -n 8 || die "another AutoStream installer is provisioning shared host state"
  [[ $(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "${directory_identity}" &&
    -f ${SHARED_HOST_SETUP_LOCK} &&
    ! -L ${SHARED_HOST_SETUP_LOCK} &&
    -f /proc/self/fd/8 &&
    $(stat -c '%U:%G:%a:%h' -- "${SHARED_HOST_SETUP_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/8) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK}")" ]] || \
    die "shared host-setup lock identity changed after acquisition"
}

acquire_host_lifecycle_lock() {
  local directory_identity
  local fd_identity
  local lock_created=false

  validate_root_parent_chain "${HOST_LIFECYCLE_LOCK}" "Host lifecycle lock"
  [[ -d ${SHARED_HOST_SETUP_LOCK_DIR} &&
    ! -L ${SHARED_HOST_SETUP_LOCK_DIR} &&
    $(readlink -f -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "${SHARED_HOST_SETUP_LOCK_DIR}" &&
    $(stat -c '%U:%G:%a' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "root:root:700" ]] || \
    die "Host lifecycle lock directory is unsafe"
  directory_identity="$(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK_DIR}")" || \
    die "could not record the Host lifecycle lock directory identity"

  if [[ -e ${HOST_LIFECYCLE_LOCK} || -L ${HOST_LIFECYCLE_LOCK} ]]; then
    [[ -f ${HOST_LIFECYCLE_LOCK} &&
      ! -L ${HOST_LIFECYCLE_LOCK} &&
      $(readlink -f -- "${HOST_LIFECYCLE_LOCK}") == "${HOST_LIFECYCLE_LOCK}" &&
      $(stat -c '%U:%G:%a:%h' -- "${HOST_LIFECYCLE_LOCK}") == "root:root:600:1" ]] || \
      die "Host lifecycle lock path is unsafe"
  else
    lock_created=true
  fi
  exec 9<>"${HOST_LIFECYCLE_LOCK}" || die "could not open the Host lifecycle lock"
  fd_identity="$(stat -Lc '%d:%i' -- /proc/self/fd/9)" || \
    die "could not record the Host lifecycle lock identity"
  [[ $(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "${directory_identity}" &&
    -f ${HOST_LIFECYCLE_LOCK} &&
    ! -L ${HOST_LIFECYCLE_LOCK} &&
    -f /proc/self/fd/9 &&
    $(stat -c '%U:%G:%a:%h' -- "${HOST_LIFECYCLE_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/9) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${HOST_LIFECYCLE_LOCK}")" ]] || \
    die "Host lifecycle lock identity changed while being opened"
  if [[ ${lock_created} == true ]]; then
    sync -f "${SHARED_HOST_SETUP_LOCK_DIR}"
  fi
  flock -n 9 || die "another privileged Host lifecycle operation is active"
  [[ $(stat -c '%d:%i' -- "${SHARED_HOST_SETUP_LOCK_DIR}") == "${directory_identity}" &&
    -f ${HOST_LIFECYCLE_LOCK} &&
    ! -L ${HOST_LIFECYCLE_LOCK} &&
    -f /proc/self/fd/9 &&
    $(stat -c '%U:%G:%a:%h' -- "${HOST_LIFECYCLE_LOCK}") == "root:root:600:1" &&
    $(stat -Lc '%U:%G:%a:%h' -- /proc/self/fd/9) == "root:root:600:1" &&
    ${fd_identity} == "$(stat -c '%d:%i' -- "${HOST_LIFECYCLE_LOCK}")" ]] || \
    die "Host lifecycle lock identity changed after acquisition"
}
