
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
  [[ $(unit_active_state "${unit}") == "inactive" ]] || \
    die "${unit} did not reach the inactive state"
}

verify_unit_active() {
  local unit=$1
  [[ $(unit_active_state "${unit}") == "active" ]] || \
    die "${unit} did not reach the active state"
}

verify_unit_disabled() {
  local unit=$1
  [[ $(unit_enabled_state "${unit}") == "disabled" ]] || \
    die "${unit} did not reach the disabled state"
}

cleanup_bootstrap() {
  local status=$?
  local rollback_failed=false
  trap '' INT TERM
  trap - EXIT
  [[ -z ${binary_stage:-} ]] || rm -f -- "${binary_stage}"
  [[ -z ${unit_stage:-} ]] || rm -f -- "${unit_stage}"
  [[ -z ${local_executor_binary_stage:-} ]] || rm -f -- "${local_executor_binary_stage}"
  [[ -z ${local_executor_service_stage:-} ]] || rm -f -- "${local_executor_service_stage}"
  [[ -z ${local_executor_socket_stage:-} ]] || rm -f -- "${local_executor_socket_stage}"
  [[ -z ${local_executor_tmpfiles_stage:-} ]] || rm -f -- "${local_executor_tmpfiles_stage}"
  [[ -z ${self_update_recovery_service_stage:-} ]] || rm -f -- "${self_update_recovery_service_stage}"
  [[ -z ${self_update_recovery_timer_stage:-} ]] || rm -f -- "${self_update_recovery_timer_stage}"
  rollback_bootstrap_prerequisites || rollback_failed=true
  if [[ -n ${BUNDLE_STAGE:-} &&
    ${BUNDLE_STAGE} == /var/tmp/autostream-host-agent-install.* &&
    -d ${BUNDLE_STAGE} &&
    ! -L ${BUNDLE_STAGE} ]]; then
    rm -rf -- "${BUNDLE_STAGE}"
  fi
  if [[ ${rollback_failed} == true ]]; then
    exit 1
  fi
  exit "${status}"
}
arm_cleanup_handler cleanup_bootstrap

if [[ ${install_mode} == "prepare" ]]; then
  [[ ! -e ${CONFIG_DEST} && ! -L ${CONFIG_DEST} ]] || \
    die "--prepare refuses an existing identity; use the Control Panel configure lifecycle"
  [[ ! -e ${LOCAL_EXECUTOR_POLICY_DEST} && ! -L ${LOCAL_EXECUTOR_POLICY_DEST} ]] || \
    die "--prepare refuses an existing local executor policy; use the local executor installer for upgrades"
  [[ $(unit_active_state "${UNIT_NAME}") == "inactive" ]] || \
    die "--prepare requires the Host Agent service to be inactive"
  [[ $(unit_enabled_state "${UNIT_NAME}") == "disabled" ]] || \
    die "--prepare requires the Host Agent service to be disabled"
  for runtime_unit in \
    "${LOCAL_EXECUTOR_SERVICE_NAME}" \
    "${LOCAL_EXECUTOR_SOCKET_NAME}" \
    "${SELF_UPDATE_RECOVERY_SERVICE_A}" \
    "${SELF_UPDATE_RECOVERY_SERVICE_B}" \
    "${SELF_UPDATE_RECOVERY_TIMER_A}" \
    "${SELF_UPDATE_RECOVERY_TIMER_B}"; do
    [[ $(unit_active_state "${runtime_unit}") == "inactive" ]] || \
      die "--prepare requires the local executor and self-update recovery timers to be inactive"
  done
  for runtime_unit in \
    "${LOCAL_EXECUTOR_SERVICE_NAME}" \
    "${LOCAL_EXECUTOR_SOCKET_NAME}" \
    "${SELF_UPDATE_RECOVERY_TIMER_A}" \
    "${SELF_UPDATE_RECOVERY_TIMER_B}"; do
    [[ $(unit_enabled_state "${runtime_unit}") == "disabled" ]] || \
      die "--prepare requires the local executor and self-update recovery timers to be disabled"
  done
  [[ ! -e ${HOST_RUNTIME_ROOT} && ! -L ${HOST_RUNTIME_ROOT} ]] || \
    die "--prepare refuses an existing Host Agent A/B runtime root"
fi

prepare_agent_user_rollback_login || \
  die "could not reserve a safe Host Agent account rollback login"
if ! getent group "${AGENT_GROUP}" >/dev/null; then
  agent_group_creation_attempted=true
  defer_cleanup_signals
  groupadd --system "${AGENT_GROUP}"
  agent_group_created=true
  agent_group_identity=$(getent group "${AGENT_GROUP}") || \
    die "could not record the newly created Host Agent group"
  resume_cleanup_signals || die "installation was interrupted while journaling the Host Agent group"
else
  preexisting_agent_group_identity="$(getent group "${AGENT_GROUP}" 2>/dev/null || true)"
  [[ -n ${preexisting_agent_group_identity} ]] || \
    die "could not record the pre-existing Host Agent group"
fi
IFS=: read -r _ _ agent_gid _ < <(getent group "${AGENT_GROUP}")
[[ ${agent_gid} =~ ^[0-9]+$ && ${agent_gid} -ne 0 ]] || \
  die "agent group must use a non-root numeric gid"
if [[ ${agent_group_created} == true ]]; then
  [[ $(getent group "${AGENT_GROUP}" 2>/dev/null || true) == "${agent_group_identity}" ]] || \
    die "newly created Host Agent group changed before user provisioning"
else
  [[ $(getent group "${AGENT_GROUP}" 2>/dev/null || true) == "${preexisting_agent_group_identity}" ]] || \
    die "pre-existing Host Agent group changed before user provisioning"
fi
if ! id "${AGENT_USER}" >/dev/null 2>&1; then
  [[ ${agent_user_rollback_login_ready} == true &&
    -z $(getent passwd "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    -z $(getent group "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    die "Host Agent account rollback login reservation changed before user provisioning"
  agent_account_member_fields_are_clear || \
    die "Host Agent account membership changed before user provisioning"
  agent_user_creation_attempted=true
  defer_cleanup_signals
  useradd \
    --system \
    --gid "${AGENT_GROUP}" \
    --home-dir "${STATE_DIR}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
  agent_user_created=true
  agent_user_identity=$(getent passwd "${AGENT_USER}") || \
    die "could not record the newly created Host Agent account"
  agent_user_uid="$(id -u "${AGENT_USER}" 2>/dev/null || true)"
  agent_user_gid="$(id -g "${AGENT_USER}" 2>/dev/null || true)"
  [[ ${agent_user_uid} =~ ^[1-9][0-9]*$ &&
    ${agent_user_gid} == "${agent_gid}" ]] || \
    die "could not record the newly created Host Agent account identity"
  resume_cleanup_signals || die "installation was interrupted while journaling the Host Agent account"
fi
[[ $(id -u "${AGENT_USER}") -ne 0 ]] || die "agent user must not be root"
[[ $(id -gn "${AGENT_USER}") == "${AGENT_GROUP}" ]] || die "agent user must use the dedicated primary group"
mapfile -t supplementary_groups < <(id -Gn "${AGENT_USER}" | tr ' ' '\n' | LC_ALL=C sort -u)
[[ ${#supplementary_groups[@]} -eq 1 && ${supplementary_groups[0]} == "${AGENT_GROUP}" ]] || \
  die "agent user must not belong to supplementary groups"
IFS=: read -r _ _ agent_gid agent_group_members < <(getent group "${AGENT_GROUP}")
[[ ${agent_gid} =~ ^[0-9]+$ && ${agent_gid} -ne 0 ]] || \
  die "agent group has an invalid or root gid"
if [[ -n ${agent_group_members} ]]; then
  IFS=, read -r -a explicit_group_members <<<"${agent_group_members}"
  for member in "${explicit_group_members[@]}"; do
    [[ ${member} == "${AGENT_USER}" ]] || die "agent group must not grant identity access to another user"
  done
fi
while IFS=: read -r account_name _ _ account_gid _ _ _; do
  if [[ ${account_gid} == "${agent_gid}" && ${account_name} != "${AGENT_USER}" ]]; then
    die "agent group must not be the primary group of another user"
  fi
done < <(getent passwd)
IFS=: read -r _ _ _ _ _ agent_home agent_shell < <(getent passwd "${AGENT_USER}")
[[ ${agent_home} == "${STATE_DIR}" ]] || die "agent user must use ${STATE_DIR} as its home"
[[ ${agent_shell} == "/usr/sbin/nologin" ]] || die "agent user must use /usr/sbin/nologin"
