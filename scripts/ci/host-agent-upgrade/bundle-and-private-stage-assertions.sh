
rebuild_bundle_archive() {
  rm -f -- "${PACKAGE_ROOT}/checksums.txt" "${ARCHIVE}"
  (
    cd -- "${PACKAGE_ROOT}"
    find . -type f ! -path './checksums.txt' -print0 |
      sort -z |
      xargs -0 sha256sum > checksums.txt
  )
  tar -C /root -czf "${ARCHIVE}" "${ARTIFACT_ID}"
}

private_stage_listing() {
  find /var/tmp -mindepth 1 -maxdepth 1 -type d \
    -name 'autostream-host-agent-install.*' -printf '%f\n' |
    LC_ALL=C sort
}

readonly PRIVATE_STAGE_BEFORE="$(private_stage_listing)"
assert_private_stage_cleaned() {
  local allow_systemctl=${1:-false}
  local after
  after="$(private_stage_listing)"
  [[ ${after} == "${PRIVATE_STAGE_BEFORE}" ]] || {
    printf '%s\n%s\n' \
      'Host Agent upgrade installer left a private bundle stage behind:' \
      "${after}" >&2
    exit 1
  }
  [[ ${allow_systemctl} == true ||
    (! -e ${SYSTEMCTL_LOG} && ! -L ${SYSTEMCTL_LOG}) ]] || {
    printf '%s\n' 'delegating Host Agent upgrade unexpectedly invoked systemctl' >&2
    exit 1
  }
}

assert_no_completion() {
  local output=$1
  if grep -Fq -- "${COMPLETION}" <<<"${output}"; then
    printf '%s\n%s\n' \
      'failed Host Agent upgrade printed its completion marker:' \
      "${output}" >&2
    exit 1
  fi
}

assert_helper_not_called() {
  [[ ! -e ${HELPER_LOG} && ! -L ${HELPER_LOG} ]] || {
    printf '%s\n' 'Host Agent upgrade invoked the candidate helper before validation completed' >&2
    exit 1
  }
}

assert_helper_arguments() {
  local expect_recovery=${1:-false}
  local artifact_root
  [[ -f ${HELPER_LOG} && ! -L ${HELPER_LOG} ]] || {
    printf '%s\n' 'candidate Local Executor did not record the manual upgrade request' >&2
    exit 1
  }
  [[ $(stat -c '%U:%G:%a' -- "${HELPER_LOG}") == root:root:600 ]] || {
    printf '%s\n' 'candidate Local Executor request log is not root:root 0600' >&2
    exit 1
  }
  artifact_root=$(awk -F= '$1 == "artifact-root" { sub(/^artifact-root=/, ""); print }' \
    "${HELPER_LOG}")
  case "${artifact_root}" in
    /var/tmp/autostream-host-agent-install.*/unpack/"${ARTIFACT_ID}") ;;
    *)
      printf 'candidate Local Executor received an unexpected artifact root: %s\n' \
        "${artifact_root}" >&2
      exit 1
      ;;
  esac
  grep -Fx -- "archive-sha256=${EXPECTED_ARCHIVE_SHA256}" \
    "${HELPER_LOG}" >/dev/null
  grep -Fx -- "archive-size=${EXPECTED_ARCHIVE_SIZE}" \
    "${HELPER_LOG}" >/dev/null
  if [[ ${expect_recovery} == true ]]; then
    grep -Fx -- 'agent-stopped-for-recovery=true' \
      "${HELPER_LOG}" >/dev/null
  elif grep -Fq -- 'agent-stopped-for-recovery=' "${HELPER_LOG}"; then
    printf '%s\n' \
      'normal Host Agent upgrade unexpectedly used the internal stopped-Agent flag' >&2
    exit 1
  fi
}

getent group autostream-host-agent >/dev/null 2>&1 || \
  groupadd --system autostream-host-agent
getent passwd autostream-host-agent >/dev/null 2>&1 || \
  useradd \
    --system \
    --gid autostream-host-agent \
    --home-dir /nonexistent \
    --shell /usr/sbin/nologin \
    autostream-host-agent
install -d -o root -g autostream-host-agent -m 0750 \
  /etc/autostream/updater
install -d -o root -g root -m 0700 \
  /etc/autostream-local-executor
install -d -o autostream-host-agent -g autostream-host-agent -m 0700 \
  /var/lib/autostream-host-agent
printf '%s\n' \
  'panel_url: https://panel.example.com' \
  'node_id: host-smoke' \
  'runtime_token: sentinel-token' \
  'service_name: Host smoke' \
  > "${IDENTITY_PATH}"
chown root:autostream-host-agent "${IDENTITY_PATH}"
chmod 0640 "${IDENTITY_PATH}"
printf '%s\n' '{"sentinel":"local-executor-policy"}' > "${POLICY_PATH}"
chown root:root "${POLICY_PATH}"
chmod 0600 "${POLICY_PATH}"

readonly IDENTITY_STAT_BEFORE="$(stat -c '%d:%i:%u:%g:%a' -- "${IDENTITY_PATH}")"
readonly IDENTITY_SHA_BEFORE="$(sha256sum -- "${IDENTITY_PATH}" | awk 'NR == 1 { print $1 }')"
readonly POLICY_STAT_BEFORE="$(stat -c '%d:%i:%u:%g:%a' -- "${POLICY_PATH}")"
readonly POLICY_SHA_BEFORE="$(sha256sum -- "${POLICY_PATH}" | awk 'NR == 1 { print $1 }')"

assert_sentinels_unchanged() {
  [[ $(stat -c '%d:%i:%u:%g:%a' -- "${IDENTITY_PATH}") == \
      "${IDENTITY_STAT_BEFORE}" &&
    $(sha256sum -- "${IDENTITY_PATH}" | awk 'NR == 1 { print $1 }') == \
      "${IDENTITY_SHA_BEFORE}" ]] || {
    printf '%s\n' 'Host Agent upgrade changed the installed identity sentinel' >&2
    exit 1
  }
  [[ $(stat -c '%d:%i:%u:%g:%a' -- "${POLICY_PATH}") == \
      "${POLICY_STAT_BEFORE}" &&
    $(sha256sum -- "${POLICY_PATH}" | awk 'NR == 1 { print $1 }') == \
      "${POLICY_SHA_BEFORE}" ]] || {
    printf '%s\n' 'Host Agent upgrade changed the Local Executor policy sentinel' >&2
    exit 1
  }
}
