
validate_active_job_recovery_executable() {
  local path=$1
  local label=$2
  active_job_recovery_executable_is_safe "${path}" || \
    die "${label} executable is missing or unsafe"
}

active_job_recovery_executable_is_safe() {
  local path=$1
  [[ -f ${path} && ! -L ${path} && -x ${path} &&
    $(readlink -f -- "${path}") == "${path}" ]] || return 1
  [[ $(stat -c '%U:%G:%a:%h' -- "${path}") == "root:root:755:1" ]] || \
    return 1
  active_job_recovery_root_parent_chain_is_safe "${path}"
}

active_job_recovery_verified_candidate_sources_are_intact() {
  [[ -f ${BINARY_SOURCE} && ! -L ${BINARY_SOURCE} &&
    $(readlink -f -- "${BINARY_SOURCE}") == "${BINARY_SOURCE}" &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- "${BINARY_SOURCE}") == \
      "${VERIFIED_AGENT_SOURCE_STAT}" &&
    $(sha256sum -- "${BINARY_SOURCE}" | awk 'NR == 1 { print $1 }') == \
      "${VERIFIED_AGENT_SOURCE_SHA256}" &&
    -f ${LOCAL_EXECUTOR_BINARY_SOURCE} &&
    ! -L ${LOCAL_EXECUTOR_BINARY_SOURCE} &&
    $(readlink -f -- "${LOCAL_EXECUTOR_BINARY_SOURCE}") == \
      "${LOCAL_EXECUTOR_BINARY_SOURCE}" &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
      "${LOCAL_EXECUTOR_BINARY_SOURCE}") == "${VERIFIED_EXECUTOR_SOURCE_STAT}" &&
    $(sha256sum -- "${LOCAL_EXECUTOR_BINARY_SOURCE}" | \
      awk 'NR == 1 { print $1 }') == "${VERIFIED_EXECUTOR_SOURCE_SHA256}" ]]
}

active_job_recovery_service_is_enabled_active() {
  local enabled_state
  local active_state
  local main_pid
  enabled_state="$(${SYSTEMCTL_PATH} is-enabled "${UNIT_NAME}" 2>/dev/null)" || return 1
  active_state="$(${SYSTEMCTL_PATH} is-active "${UNIT_NAME}" 2>/dev/null)" || return 1
  main_pid="$(${SYSTEMCTL_PATH} show "${UNIT_NAME}" --property=MainPID --value 2>/dev/null)" || return 1
  [[ ${enabled_state} == "enabled" &&
    ${active_state} == "active" &&
    ${main_pid} =~ ^[1-9][0-9]*$ ]]
}

active_job_recovery_service_is_managed() {
  local expected_executable
  local first_executable
  local first_pid
  local second_executable
  local second_pid
  local unit_group
  local unit_user
  active_job_recovery_service_is_enabled_active || return 1
  unit_user="$(${SYSTEMCTL_PATH} show \
    "${UNIT_NAME}" --property=User --value 2>/dev/null)" || return 1
  unit_group="$(${SYSTEMCTL_PATH} show \
    "${UNIT_NAME}" --property=Group --value 2>/dev/null)" || return 1
  [[ ${unit_user} == "${AGENT_USER}" &&
    ${unit_group} == "${AGENT_GROUP}" ]] || return 1
  first_pid="$(${SYSTEMCTL_PATH} show \
    "${UNIT_NAME}" --property=MainPID --value 2>/dev/null)" || return 1
  [[ ${first_pid} =~ ^[1-9][0-9]*$ &&
    -d /proc/${first_pid} &&
    ! -L /proc/${first_pid} ]] || return 1
  expected_executable="$(readlink -f -- \
    "${HOST_RUNTIME_CURRENT}/bin/autostream-host-agent")" || return 1
  case "${expected_executable}" in
    "${HOST_RUNTIME_SLOTS}"/a/bin/autostream-host-agent|"${HOST_RUNTIME_SLOTS}"/b/bin/autostream-host-agent) ;;
    *) return 1 ;;
  esac
  [[ -f ${expected_executable} && ! -L ${expected_executable} &&
    -x ${expected_executable} &&
    $(readlink -f -- "${BINARY_DEST}") == "${expected_executable}" ]] || return 1
  first_executable="$(readlink -f -- "/proc/${first_pid}/exe")" || return 1
  [[ ${first_executable} == "${expected_executable}" ]] || return 1
  second_pid="$(${SYSTEMCTL_PATH} show \
    "${UNIT_NAME}" --property=MainPID --value 2>/dev/null)" || return 1
  [[ ${second_pid} == "${first_pid}" ]] || return 1
  second_executable="$(readlink -f -- "/proc/${second_pid}/exe")" || return 1
  [[ ${second_executable} == "${expected_executable}" ]]
}

read_active_job_recovery_binary_identity() {
  local binary_path=$1
  local binary_name=$2
  local expected_pair=$3
  local build_date
  local commit
  local version
  local -a lines=()
  mapfile -t lines < <("${binary_path}" --version) || return 1
  case "${binary_name}" in
    autostream-host-agent)
      [[ ${#lines[@]} -eq 3 ]] || return 1
      [[ ${lines[0]} =~ ^autostream-host-agent\ (v[0-9]+[.][0-9]+[.][0-9]+)$ ]] || \
        return 1
      version=${BASH_REMATCH[1]}
      ;;
    autostream-local-executor)
      [[ ${#lines[@]} -eq 5 ]] || return 1
      [[ ${lines[0]} =~ ^autostream-local-executor\ (v[0-9]+[.][0-9]+[.][0-9]+)$ ]] || \
        return 1
      version=${BASH_REMATCH[1]}
      [[ ${lines[3]} == "mutation_protocol: 2" &&
        ${lines[4]} == "recovery_protocol: 2" ]] || return 1
      ;;
    *) return 1 ;;
  esac
  [[ ${lines[1]} =~ ^commit:\ ([0-9a-f]{40})$ ]] || return 1
  commit=${BASH_REMATCH[1]}
  [[ ${lines[2]} =~ ^build_date:\ ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$ ]] || \
    return 1
  build_date=${BASH_REMATCH[1]}
  case "${expected_pair}" in
    rescue-source)
      case "${version}" in
        v1.9.9|v1.9.10) ;;
        *) return 1 ;;
      esac
      ;;
    verified-candidate)
      [[ ${version} == "${VERSION}" &&
        ${commit} == "${MANIFEST_COMMIT}" &&
        ${build_date} == "${MANIFEST_BUILD_DATE}" ]] || return 1
      ;;
    *) return 1 ;;
  esac
  printf '%s\t%s\t%s\n' "${version}" "${commit}" "${build_date}"
}

active_job_recovery_live_pair_is_managed() {
  local expected_pair=${1:-rescue-source}
  local current_agent
  local current_executor
  local current_slot_root
  local current_target
  local directory
  local executor_first_executable
  local executor_first_pid
  local executor_group
  local executor_second_executable
  local executor_second_pid
  local executor_user
  local first_agent_identity
  local first_agent_sha256
  local first_agent_stat
  local first_executor_identity
  local first_executor_sha256
  local first_executor_stat
  local second_agent_identity
  local second_executor_identity

  case "${expected_pair}" in
    rescue-source) ;;
    verified-candidate)
      active_job_recovery_verified_candidate_sources_are_intact || return 1
      ;;
    *) return 1 ;;
  esac

  [[ -L ${HOST_RUNTIME_CURRENT} &&
    $(stat -c '%U:%G:%h' -- "${HOST_RUNTIME_CURRENT}") == "root:root:1" ]] || \
    return 1
  current_target="$(readlink -- "${HOST_RUNTIME_CURRENT}")" || return 1
  case "${current_target}" in
    slots/a|slots/b) ;;
    *) return 1 ;;
  esac
  current_slot_root="${HOST_RUNTIME_SLOTS}/${current_target#slots/}"
  current_agent="$(readlink -f -- \
    "${HOST_RUNTIME_CURRENT}/bin/autostream-host-agent")" || return 1
  current_executor="$(readlink -f -- \
    "${HOST_RUNTIME_CURRENT}/bin/autostream-local-executor")" || return 1
  [[ ${current_agent} == \
      "${current_slot_root}/bin/autostream-host-agent" &&
    ${current_executor} == \
      "${current_slot_root}/bin/autostream-local-executor" ]] || \
    return 1
  for directory in \
    "${HOST_RUNTIME_ROOT}" \
    "${HOST_RUNTIME_SLOTS}" \
    "${current_slot_root}" \
    "${current_slot_root}/bin"; do
    [[ -d ${directory} && ! -L ${directory} &&
      $(readlink -f -- "${directory}") == "${directory}" &&
      $(stat -c '%U:%G:%a' -- "${directory}") == "root:root:755" ]] || \
      return 1
  done
  active_job_recovery_executable_is_safe "${current_agent}" || return 1
  active_job_recovery_executable_is_safe "${current_executor}" || return 1
  ${RUNUSER_PATH} --user "${AGENT_USER}" -- \
    "${ENV_PATH}" -i \
    HOME=/nonexistent \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LC_ALL=C \
    "${TEST_PATH}" -r "${current_agent}" || return 1
  ${RUNUSER_PATH} --user "${AGENT_USER}" -- \
    "${ENV_PATH}" -i \
    HOME=/nonexistent \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LC_ALL=C \
    "${TEST_PATH}" -x "${current_agent}" || return 1
  ${RUNUSER_PATH} --user "${AGENT_USER}" -- \
    "${ENV_PATH}" -i \
    HOME=/nonexistent \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LC_ALL=C \
    "${TEST_PATH}" -r "${current_executor}" || return 1
  ${RUNUSER_PATH} --user "${AGENT_USER}" -- \
    "${ENV_PATH}" -i \
    HOME=/nonexistent \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LC_ALL=C \
    "${TEST_PATH}" -x "${current_executor}" || return 1
  [[ -L ${BINARY_DEST} &&
    $(stat -c '%U:%G:%h' -- "${BINARY_DEST}") == "root:root:1" &&
    $(readlink -- "${BINARY_DEST}") == \
      "${HOST_RUNTIME_CURRENT}/bin/autostream-host-agent" &&
    $(readlink -f -- "${BINARY_DEST}") == "${current_agent}" ]] || return 1
  [[ -L ${LOCAL_EXECUTOR_BINARY_DEST} &&
    $(stat -c '%U:%G:%h' -- "${LOCAL_EXECUTOR_BINARY_DEST}") == "root:root:1" &&
    $(readlink -- "${LOCAL_EXECUTOR_BINARY_DEST}") == \
      "${HOST_RUNTIME_CURRENT}/bin/autostream-local-executor" &&
    $(readlink -f -- "${LOCAL_EXECUTOR_BINARY_DEST}") == "${current_executor}" ]] || \
    return 1

  first_agent_stat="$(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
    "${current_agent}")" || return 1
  first_executor_stat="$(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- \
    "${current_executor}")" || return 1
  if [[ ${expected_pair} == verified-candidate ]]; then
    first_agent_sha256="$(sha256sum -- "${current_agent}" | \
      awk 'NR == 1 { print $1 }')" || return 1
    first_executor_sha256="$(sha256sum -- "${current_executor}" | \
      awk 'NR == 1 { print $1 }')" || return 1
    [[ ${first_agent_sha256} == "${VERIFIED_AGENT_SOURCE_SHA256}" &&
      ${first_executor_sha256} == "${VERIFIED_EXECUTOR_SOURCE_SHA256}" ]] || \
      return 1
  fi
  first_agent_identity="$(read_active_job_recovery_binary_identity \
    "${current_agent}" autostream-host-agent "${expected_pair}")" || return 1
  first_executor_identity="$(read_active_job_recovery_binary_identity \
    "${current_executor}" autostream-local-executor "${expected_pair}")" || return 1
  [[ ${first_agent_identity} == "${first_executor_identity}" ]] || return 1

  [[ $(${SYSTEMCTL_PATH} is-active \
      "${LOCAL_EXECUTOR_SERVICE_NAME}" 2>/dev/null) == "active" &&
    $(${SYSTEMCTL_PATH} is-enabled \
      "${LOCAL_EXECUTOR_SOCKET_NAME}" 2>/dev/null) == "enabled" &&
    $(${SYSTEMCTL_PATH} is-active \
      "${LOCAL_EXECUTOR_SOCKET_NAME}" 2>/dev/null) == "active" ]] || return 1
  executor_user="$(${SYSTEMCTL_PATH} show "${LOCAL_EXECUTOR_SERVICE_NAME}" \
    --property=User --value 2>/dev/null)" || return 1
  executor_group="$(${SYSTEMCTL_PATH} show "${LOCAL_EXECUTOR_SERVICE_NAME}" \
    --property=Group --value 2>/dev/null)" || return 1
  [[ ${executor_user} == "root" && ${executor_group} == "root" ]] || return 1
  executor_first_pid="$(${SYSTEMCTL_PATH} show \
    "${LOCAL_EXECUTOR_SERVICE_NAME}" --property=MainPID --value 2>/dev/null)" || \
    return 1
  [[ ${executor_first_pid} =~ ^[1-9][0-9]*$ &&
    -d /proc/${executor_first_pid} &&
    ! -L /proc/${executor_first_pid} ]] || return 1
  executor_first_executable="$(readlink -f -- \
    "/proc/${executor_first_pid}/exe")" || return 1
  [[ ${executor_first_executable} == "${current_executor}" ]] || return 1

  active_job_recovery_executable_is_safe "${current_agent}" || return 1
  active_job_recovery_executable_is_safe "${current_executor}" || return 1
  [[ $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- "${current_agent}") == \
      "${first_agent_stat}" &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- "${current_executor}") == \
      "${first_executor_stat}" ]] || return 1
  second_agent_identity="$(read_active_job_recovery_binary_identity \
    "${current_agent}" autostream-host-agent "${expected_pair}")" || return 1
  second_executor_identity="$(read_active_job_recovery_binary_identity \
    "${current_executor}" autostream-local-executor "${expected_pair}")" || return 1
  [[ ${second_agent_identity} == "${first_agent_identity}" &&
    ${second_executor_identity} == "${first_executor_identity}" &&
    ${second_agent_identity} == "${second_executor_identity}" ]] || return 1
  if [[ ${expected_pair} == verified-candidate ]]; then
    active_job_recovery_verified_candidate_sources_are_intact || return 1
    [[ $(sha256sum -- "${current_agent}" | awk 'NR == 1 { print $1 }') == \
        "${first_agent_sha256}" &&
      $(sha256sum -- "${current_executor}" | awk 'NR == 1 { print $1 }') == \
        "${first_executor_sha256}" ]] || return 1
  fi
  executor_second_pid="$(${SYSTEMCTL_PATH} show \
    "${LOCAL_EXECUTOR_SERVICE_NAME}" --property=MainPID --value 2>/dev/null)" || \
    return 1
  [[ ${executor_second_pid} == "${executor_first_pid}" ]] || return 1
  executor_second_executable="$(readlink -f -- \
    "/proc/${executor_second_pid}/exe")" || return 1
  [[ ${executor_second_executable} == "${current_executor}" ]] || return 1

  if [[ -z ${active_job_recovery_original_current_target} ]]; then
    active_job_recovery_original_current_target=${current_target}
    active_job_recovery_original_agent_identity=${second_agent_identity}
    active_job_recovery_original_agent_stat=${first_agent_stat}
    active_job_recovery_original_agent_sha256="$(sha256sum -- \
      "${current_agent}" | awk 'NR == 1 { print $1 }')" || return 1
    active_job_recovery_original_executor_identity=${second_executor_identity}
    active_job_recovery_original_executor_stat=${first_executor_stat}
    active_job_recovery_original_executor_sha256="$(sha256sum -- \
      "${current_executor}" | awk 'NR == 1 { print $1 }')" || return 1
  fi
}

active_job_recovery_original_pair_is_intact() {
  local current_agent
  local current_executor
  local current_target
  local agent_identity
  local executor_identity
  [[ -n ${active_job_recovery_original_current_target} &&
    -n ${active_job_recovery_original_agent_identity} &&
    -n ${active_job_recovery_original_agent_stat} &&
    ${active_job_recovery_original_agent_sha256} =~ ^[0-9a-f]{64}$ &&
    -n ${active_job_recovery_original_executor_identity} &&
    -n ${active_job_recovery_original_executor_stat} &&
    ${active_job_recovery_original_executor_sha256} =~ ^[0-9a-f]{64}$ ]] || return 1
  active_job_recovery_live_pair_is_managed || return 1
  current_target="$(readlink -- "${HOST_RUNTIME_CURRENT}")" || return 1
  [[ ${current_target} == "${active_job_recovery_original_current_target}" ]] || return 1
  current_agent="$(readlink -f -- \
    "${HOST_RUNTIME_CURRENT}/bin/autostream-host-agent")" || return 1
  current_executor="$(readlink -f -- \
    "${HOST_RUNTIME_CURRENT}/bin/autostream-local-executor")" || return 1
  [[ $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- "${current_agent}") == \
      "${active_job_recovery_original_agent_stat}" &&
    $(sha256sum -- "${current_agent}" | awk 'NR == 1 { print $1 }') == \
      "${active_job_recovery_original_agent_sha256}" &&
    $(stat -c '%d:%i:%s:%Y:%f:%u:%g:%a:%h' -- "${current_executor}") == \
      "${active_job_recovery_original_executor_stat}" &&
    $(sha256sum -- "${current_executor}" | awk 'NR == 1 { print $1 }') == \
      "${active_job_recovery_original_executor_sha256}" ]] || return 1
  agent_identity="$(read_active_job_recovery_binary_identity \
    "${current_agent}" autostream-host-agent rescue-source)" || return 1
  executor_identity="$(read_active_job_recovery_binary_identity \
    "${current_executor}" autostream-local-executor rescue-source)" || return 1
  [[ ${agent_identity} == "${active_job_recovery_original_agent_identity}" &&
    ${executor_identity} == "${active_job_recovery_original_executor_identity}" &&
    ${agent_identity} == "${executor_identity}" ]]
}
