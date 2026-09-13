
prepare_agent_user_rollback_login() {
  if id "${AGENT_USER}" >/dev/null 2>&1; then
    return 0
  fi
  [[ -z $(getent passwd "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    -z $(getent group "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  agent_account_member_fields_are_clear || return 1
  agent_user_rollback_login_ready=true
}

agent_account_member_fields_are_clear() {
  [[ -f /etc/group && ! -L /etc/group &&
    -f /etc/gshadow && ! -L /etc/gshadow ]] || return 1
  awk -F: \
    -v agent_login="${AGENT_USER}" \
    -v rollback_login="${AGENT_USER_ROLLBACK_LOGIN}" \
    '{
      count = split($4, members, ",")
      for (member_index = 1; member_index <= count; member_index++) {
        if (members[member_index] == agent_login || members[member_index] == rollback_login) {
          exit 1
        }
      }
    }' /etc/group || return 1
  awk -F: \
    -v agent_login="${AGENT_USER}" \
    -v rollback_login="${AGENT_USER_ROLLBACK_LOGIN}" \
    '{
      admin_count = split($3, admins, ",")
      for (admin_index = 1; admin_index <= admin_count; admin_index++) {
        if (admins[admin_index] == agent_login || admins[admin_index] == rollback_login) {
          exit 1
        }
      }
      member_count = split($4, members, ",")
      for (member_index = 1; member_index <= member_count; member_index++) {
        if (members[member_index] == agent_login || members[member_index] == rollback_login) {
          exit 1
        }
      }
    }' /etc/gshadow
}

agent_account_databases_match_digests() {
  local expected_group_digest=$1
  local expected_gshadow_digest=$2
  local group_digest
  local gshadow_digest

  group_digest="$(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }')" || return 1
  gshadow_digest="$(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }')" || return 1
  [[ ${group_digest} =~ ^[[:xdigit:]]{64}$ &&
    ${gshadow_digest} =~ ^[[:xdigit:]]{64}$ &&
    ${group_digest} == "${expected_group_digest}" &&
    ${gshadow_digest} == "${expected_gshadow_digest}" ]]
}

restore_created_agent_user_login() {
  local expected_group_record=$1
  local renamed_user_record=$2
  local expected_group_digest=$3
  local expected_gshadow_digest=$4

  [[ -z $(getent passwd "${AGENT_USER}" 2>/dev/null || true) &&
    $(getent passwd "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) == \
      "${renamed_user_record}" &&
    -z $(getent group "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  usermod --login "${AGENT_USER}" "${AGENT_USER_ROLLBACK_LOGIN}" || return 1
  [[ $(getent passwd "${AGENT_USER}" 2>/dev/null || true) == \
      "${agent_user_identity}" &&
    -z $(getent passwd "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    -z $(getent group "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  agent_account_databases_match_digests \
    "${expected_group_digest}" "${expected_gshadow_digest}" || return 1
  [[ $(getent group "${AGENT_GROUP}" 2>/dev/null || true) == "${expected_group_record}" ]]
}

remove_created_agent_user_preserving_group() {
  local delete_status=0
  local expected_group_gid
  local expected_group_record
  local group_database_digest_before
  local gshadow_database_digest_before
  local rename_status=0
  local renamed_user_record
  local record_gid
  local record_home
  local record_login
  local record_shell
  local record_uid
  local user_record_suffix

  IFS=: read -r record_login _ record_uid record_gid _ record_home record_shell <<<"${agent_user_identity}"
  [[ ${agent_user_created} == true &&
    ${agent_user_rollback_login_ready} == true &&
    ${record_login} == "${AGENT_USER}" &&
    ${record_uid} =~ ^[1-9][0-9]*$ &&
    ${record_uid} == "${agent_user_uid}" &&
    ${record_gid} =~ ^[1-9][0-9]*$ &&
    ${record_gid} == "${agent_user_gid}" &&
    ${record_home} == "${STATE_DIR}" &&
    ${record_shell} == "/usr/sbin/nologin" &&
    $(getent passwd "${AGENT_USER}" 2>/dev/null || true) == "${agent_user_identity}" &&
    $(id -u "${AGENT_USER}" 2>/dev/null || true) == "${agent_user_uid}" &&
    $(id -g "${AGENT_USER}" 2>/dev/null || true) == "${agent_user_gid}" ]] || \
    return 1

  if [[ ${agent_group_created} == true ]]; then
    expected_group_record="${agent_group_identity}"
  else
    expected_group_record="${preexisting_agent_group_identity}"
  fi
  [[ -n ${expected_group_record} &&
    $(getent group "${AGENT_GROUP}" 2>/dev/null || true) == "${expected_group_record}" ]] || \
    return 1
  expected_group_gid="$(printf '%s\n' "${expected_group_record}" | awk -F: -v group_name="${AGENT_GROUP}" 'NR == 1 && $1 == group_name { print $3 }')"
  [[ ${expected_group_gid} =~ ^[1-9][0-9]*$ &&
    ${agent_user_gid} == "${expected_group_gid}" &&
    -z $(getent passwd "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    -z $(getent group "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1

  group_database_digest_before="$(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }')" || return 1
  gshadow_database_digest_before="$(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }')" || return 1
  [[ ${group_database_digest_before} =~ ^[[:xdigit:]]{64}$ &&
    ${gshadow_database_digest_before} =~ ^[[:xdigit:]]{64}$ ]] || return 1
  agent_account_member_fields_are_clear || return 1
  agent_account_databases_match_digests \
    "${group_database_digest_before}" "${gshadow_database_digest_before}" || return 1

  # Ubuntu may automatically delete an empty user-private group whose name
  # matches the login. Rename only this invocation's user before userdel so the
  # protected Host Agent group cannot match the deleted login.
  user_record_suffix="${agent_user_identity#"${AGENT_USER}"}"
  renamed_user_record="${AGENT_USER_ROLLBACK_LOGIN}${user_record_suffix}"
  if usermod --login "${AGENT_USER_ROLLBACK_LOGIN}" "${AGENT_USER}"; then
    :
  else
    rename_status=$?
  fi
  if [[ ${rename_status} -ne 0 ||
    -n $(getent passwd "${AGENT_USER}" 2>/dev/null || true) ||
    $(getent passwd "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) != \
      "${renamed_user_record}" ||
    $(getent group "${AGENT_GROUP}" 2>/dev/null || true) != "${expected_group_record}" ||
    -n $(getent group "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]]; then
    restore_created_agent_user_login \
      "${expected_group_record}" "${renamed_user_record}" \
      "${group_database_digest_before}" "${gshadow_database_digest_before}" || true
    return 1
  fi
  if ! agent_account_databases_match_digests \
    "${group_database_digest_before}" "${gshadow_database_digest_before}"; then
    restore_created_agent_user_login \
      "${expected_group_record}" "${renamed_user_record}" \
      "${group_database_digest_before}" "${gshadow_database_digest_before}" || true
    return 1
  fi

  if userdel "${AGENT_USER_ROLLBACK_LOGIN}"; then
    delete_status=0
  else
    delete_status=$?
  fi
  if [[ ${delete_status} -ne 0 ]]; then
    restore_created_agent_user_login \
      "${expected_group_record}" "${renamed_user_record}" \
      "${group_database_digest_before}" "${gshadow_database_digest_before}" || true
    return 1
  fi
  [[ -z $(getent passwd "${AGENT_USER}" 2>/dev/null || true) &&
    -z $(getent passwd "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) &&
    $(getent group "${AGENT_GROUP}" 2>/dev/null || true) == "${expected_group_record}" &&
    -z $(getent group "${AGENT_USER_ROLLBACK_LOGIN}" 2>/dev/null || true) ]] || \
    return 1
  agent_account_databases_match_digests \
    "${group_database_digest_before}" "${gshadow_database_digest_before}" || return 1
  agent_user_created=false
  agent_user_uid=""
  agent_user_gid=""
  agent_user_identity=""
}

rollback_created_account() {
  local failed=false
  local current_identity=""
  if [[ ${agent_user_creation_attempted} == true &&
    ${agent_user_created} == false ]] &&
    current_identity=$(getent passwd "${AGENT_USER}" 2>/dev/null); then
    printf '%s\n' "install-autostream-host-agent: rollback cannot prove ownership of the newly appeared ${AGENT_USER} account" >&2
    failed=true
  fi
  if [[ ${agent_user_created} == true ]] &&
    ! remove_created_agent_user_preserving_group; then
    printf '%s\n' "install-autostream-host-agent: rollback could not safely remove ${AGENT_USER} account" >&2
    failed=true
  fi
  if [[ ${agent_group_creation_attempted} == true &&
    ${agent_group_created} == false ]] &&
    current_identity=$(getent group "${AGENT_GROUP}" 2>/dev/null); then
    printf '%s\n' "install-autostream-host-agent: rollback cannot prove ownership of the newly appeared ${AGENT_GROUP} group" >&2
    failed=true
  fi
  if [[ ${agent_group_created} == true && ${agent_user_created} == true ]]; then
    failed=true
  elif [[ ${agent_group_created} == true ]]; then
    current_identity=$(getent group "${AGENT_GROUP}" 2>/dev/null || true)
    if [[ -z ${agent_group_identity} || ${current_identity} != "${agent_group_identity}" ]]; then
      printf '%s\n' "install-autostream-host-agent: rollback refused changed ${AGENT_GROUP} group" >&2
      failed=true
    elif ! groupdel "${AGENT_GROUP}"; then
      printf '%s\n' "install-autostream-host-agent: rollback could not remove ${AGENT_GROUP} group" >&2
      failed=true
    elif getent group "${AGENT_GROUP}" >/dev/null 2>&1; then
      printf '%s\n' "install-autostream-host-agent: rollback could not prove removal of ${AGENT_GROUP} group" >&2
      failed=true
    else
      agent_group_created=false
      agent_group_identity=""
    fi
  fi
  [[ ${failed} == false ]]
}
