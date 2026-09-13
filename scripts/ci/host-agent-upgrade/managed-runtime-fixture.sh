export HTTP_PROXY=http://poison.invalid:65535
export HTTPS_PROXY=http://poison.invalid:65535
export ALL_PROXY=socks5://poison.invalid:65535
export NO_PROXY=poison.invalid
export http_proxy=http://lower-poison.invalid:65535
export https_proxy=http://lower-poison.invalid:65535
export all_proxy=socks5://lower-poison.invalid:65535
export no_proxy=lower-poison.invalid
export SSL_CERT_FILE=/root/poison-cert.pem
export SSL_CERT_DIR=/root/poison-certs
export CURL_CA_BUNDLE=/root/poison-curl.pem
export REQUESTS_CA_BUNDLE=/root/poison-requests.pem
export AUTOSTREAM_RUNTIME_TOKEN=sentinel-runtime-token
export AUTOSTREAM_CONFIGURE_TOKEN=sentinel-configure-token
for fixture_command in /usr/bin/sleep; do
  [[ -f ${fixture_command} && ! -L ${fixture_command} && -x ${fixture_command} ]] || {
    printf 'active-job recovery smoke fixture command is unavailable: %s\n' \
      "${fixture_command}" >&2
    exit 1
  }
done

install -d -o root -g root -m 0755 \
  "${MANAGED_RUNTIME_ROOT}/slots/a/bin"
install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" "${RUNTIME_PROCESS_FIXTURE_COPY}"
install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" "${MANAGED_RUNTIME_AGENT}"
install -o root -g root -m 0755 \
  "${RUNTIME_PROCESS_FIXTURE}" "${MANAGED_RUNTIME_EXECUTOR}"
ln -s slots/a "${MANAGED_RUNTIME_CURRENT}"
ln -s \
  "${MANAGED_RUNTIME_CURRENT}/bin/autostream-host-agent" \
  "${PUBLIC_AGENT}"
install -d -o root -g root -m 0755 /usr/local/libexec
ln -s \
  "${MANAGED_RUNTIME_CURRENT}/bin/autostream-local-executor" \
  "${PUBLIC_EXECUTOR}"
readonly ORIGINAL_RUNTIME_AGENT_SHA256="$(sha256sum -- \
  "${MANAGED_RUNTIME_AGENT}" | awk 'NR == 1 { print $1 }')"
readonly ORIGINAL_RUNTIME_EXECUTOR_SHA256="$(sha256sum -- \
  "${MANAGED_RUNTIME_EXECUTOR}" | awk 'NR == 1 { print $1 }')"

install -d -o root -g root -m 0700 /run/autostream-updater
install -o root -g root -m 0600 /dev/null "${RECOVERY_LIFECYCLE_LOCK}"

local_executor_lock_daemon() {
  local response
  while true; do
    if [[ -f ${RECOVERY_LIFECYCLE_HOLD_TRIGGER} &&
      ! -L ${RECOVERY_LIFECYCLE_HOLD_TRIGGER} ]]; then
      exec 6<>"${RECOVERY_LIFECYCLE_LOCK}"
      if flock -n 6; then
        printf '%s\n' lifecycle-lock-held >> "${RECOVERY_SEQUENCE_LOG}"
        printf '%s\n' ready > "${RECOVERY_LIFECYCLE_HOLD_READY}"
        chown autostream-host-agent:autostream-host-agent \
          "${RECOVERY_LIFECYCLE_HOLD_READY}"
        chmod 0600 "${RECOVERY_LIFECYCLE_HOLD_READY}"
        while [[ ! -f ${RECOVERY_LIFECYCLE_HOLD_RELEASE} ||
          -L ${RECOVERY_LIFECYCLE_HOLD_RELEASE} ]]; do
          sleep 0.01
        done
        rm -f -- \
          "${RECOVERY_LIFECYCLE_HOLD_TRIGGER}" \
          "${RECOVERY_LIFECYCLE_HOLD_READY}" \
          "${RECOVERY_LIFECYCLE_HOLD_RELEASE}"
        flock -u 6
      fi
      exec 6>&-
    fi
    if [[ -f ${RECOVERY_FULL_HOLD_TRIGGER} &&
      ! -L ${RECOVERY_FULL_HOLD_TRIGGER} ]]; then
      exec 7<>"${RECOVERY_SETUP_LOCK}"
      if flock -n 7; then
        exec 6<>"${RECOVERY_LIFECYCLE_LOCK}"
        if flock -n 6; then
          printf '%s\n' full-locks-held >> "${RECOVERY_SEQUENCE_LOG}"
          printf '%s\n' ready > "${RECOVERY_FULL_HOLD_READY}"
          chown autostream-host-agent:autostream-host-agent \
            "${RECOVERY_FULL_HOLD_READY}"
          chmod 0600 "${RECOVERY_FULL_HOLD_READY}"
          while [[ ! -f ${RECOVERY_FULL_HOLD_RELEASE} ||
            -L ${RECOVERY_FULL_HOLD_RELEASE} ]]; do
            sleep 0.01
          done
          rm -f -- \
            "${RECOVERY_FULL_HOLD_TRIGGER}" \
            "${RECOVERY_FULL_HOLD_READY}" \
            "${RECOVERY_FULL_HOLD_RELEASE}"
          flock -u 6
        fi
        exec 6>&-
        flock -u 7
      fi
      exec 7>&-
    fi
    if [[ -f ${RECOVERY_EXECUTOR_TRIGGER} &&
      ! -L ${RECOVERY_EXECUTOR_TRIGGER} ]]; then
      response=target_busy
      exec 6<>"${RECOVERY_LIFECYCLE_LOCK}"
      if flock -n 6; then
        response=acquired
        printf '%s\n' inactive > "${RECOVERY_STATE}"
        chown autostream-host-agent:autostream-host-agent "${RECOVERY_STATE}"
        chmod 0600 "${RECOVERY_STATE}"
        printf '%s\n' executor-lock-acquired >> "${RECOVERY_SEQUENCE_LOG}"
        flock -u 6
      else
        printf '%s\n' executor-lock-busy >> "${RECOVERY_SEQUENCE_LOG}"
      fi
      exec 6>&-
      rm -f -- "${RECOVERY_EXECUTOR_TRIGGER}"
      # Publish only after ownership and mode are ready; the fake Host Agent
      # runs unprivileged and must never observe a root-owned response inode.
      rm -f -- "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      printf '%s\n' "${response}" > "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      chown autostream-host-agent:autostream-host-agent \
        "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      chmod 0600 "${RECOVERY_EXECUTOR_RESPONSE_STAGE}"
      mv -T -- \
        "${RECOVERY_EXECUTOR_RESPONSE_STAGE}" \
        "${RECOVERY_EXECUTOR_RESPONSE}"
    fi
    sleep 0.01
  done
}

local_executor_lock_daemon &
readonly LOCAL_EXECUTOR_LOCK_DAEMON_PID=$!

start_managed_agent_fixture() {
  local pid
  if [[ -f ${SERVICE_PID_FILE} && ! -L ${SERVICE_PID_FILE} ]]; then
    pid="$(<"${SERVICE_PID_FILE}")"
    if [[ ${pid} =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
  fi
  "${MANAGED_RUNTIME_AGENT}" 3600 \
    </dev/null >/dev/null 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" > "${SERVICE_PID_FILE}"
  chmod 0600 "${SERVICE_PID_FILE}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -d /proc/${pid} &&
      $(readlink -f -- "/proc/${pid}/exe") == "${MANAGED_RUNTIME_AGENT}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  printf '%s\n' 'could not start the managed Host Agent process fixture' >&2
  exit 1
}

start_managed_agent_fixture

start_managed_executor_fixture() {
  local pid
  if [[ -f ${EXECUTOR_PID_FILE} && ! -L ${EXECUTOR_PID_FILE} ]]; then
    pid="$(<"${EXECUTOR_PID_FILE}")"
    if [[ ${pid} =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
  fi
  "${MANAGED_RUNTIME_EXECUTOR}" run \
    </dev/null >/dev/null 2>&1 &
  pid=$!
  printf '%s\n' "${pid}" > "${EXECUTOR_PID_FILE}"
  chmod 0600 "${EXECUTOR_PID_FILE}"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -d /proc/${pid} &&
      $(readlink -f -- "/proc/${pid}/exe") == "${MANAGED_RUNTIME_EXECUTOR}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  printf '%s\n' 'could not start the managed Local Executor process fixture' >&2
  exit 1
}

start_managed_executor_fixture

if [[ -f /usr/bin/systemctl && ! -L /usr/bin/systemctl ]]; then
  install -o root -g root -m 0755 /usr/bin/systemctl "${SYSTEMCTL_BACKUP}"
fi
if [[ -f /usr/bin/systemd-run && ! -L /usr/bin/systemd-run ]]; then
  install -o root -g root -m 0755 /usr/bin/systemd-run "${SYSTEMD_RUN_BACKUP}"
fi
