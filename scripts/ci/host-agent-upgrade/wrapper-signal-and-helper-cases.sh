
run_wrapper_signal_case() {
  local signal_mode=$1
  local expect_success=$2
  local expected_status=$3
  local wrapper_pid
  local wrapper_status
  local candidate_pid
  local attempts=0

  printf '%s\n' "${signal_mode}" > "${HELPER_SIGNAL_MODE}"
  chmod 0600 "${HELPER_SIGNAL_MODE}"
  rm -f -- \
    "${HELPER_LOG}" \
    "${HELPER_SIGNAL_READY}" \
    "${HELPER_SIGNAL_RECEIVED}" \
    "${HELPER_SIGNAL_FINISHED}" \
    "${SIGNAL_OUTPUT}"

  "${INSTALLER}" --upgrade > "${SIGNAL_OUTPUT}" 2>&1 &
  wrapper_pid=$!
  while [[ ! -f ${HELPER_SIGNAL_READY} ]]; do
    if ! kill -0 "${wrapper_pid}" 2>/dev/null; then
      if wait "${wrapper_pid}"; then
        wrapper_status=0
      else
        wrapper_status=$?
      fi
      printf 'Host Agent upgrade wrapper exited with status %s before its candidate was ready:\n' \
        "${wrapper_status}" >&2
      sed -n '1,160p' "${SIGNAL_OUTPUT}" >&2
      exit 1
    fi
    attempts=$((attempts + 1))
    if [[ ${attempts} -ge 200 ]]; then
      kill -TERM "${wrapper_pid}" 2>/dev/null || true
      wait "${wrapper_pid}" 2>/dev/null || true
      printf '%s\n' 'timed out waiting for the candidate Local Executor signal fixture' >&2
      exit 1
    fi
    sleep 0.05
  done

  candidate_pid="$(<"${HELPER_SIGNAL_READY}")"
  [[ ${candidate_pid} =~ ^[1-9][0-9]*$ ]] || {
    printf 'candidate signal fixture recorded an invalid PID: %s\n' "${candidate_pid}" >&2
    exit 1
  }
  kill -TERM "${wrapper_pid}"
  if wait "${wrapper_pid}"; then
    wrapper_status=0
  else
    wrapper_status=$?
  fi

  [[ ${wrapper_status} -eq ${expected_status} ]] || {
    printf 'Host Agent upgrade wrapper status=%s, expected candidate status=%s:\n' \
      "${wrapper_status}" "${expected_status}" >&2
    sed -n '1,160p' "${SIGNAL_OUTPUT}" >&2
    exit 1
  }

  [[ -f ${HELPER_SIGNAL_RECEIVED} && ! -L ${HELPER_SIGNAL_RECEIVED} &&
    $(<"${HELPER_SIGNAL_RECEIVED}") == TERM ]] || {
    printf '%s\n' 'wrapper-only SIGTERM was not forwarded to the candidate Local Executor' >&2
    exit 1
  }
  [[ -f ${HELPER_SIGNAL_FINISHED} && ! -L ${HELPER_SIGNAL_FINISHED} &&
    $(<"${HELPER_SIGNAL_FINISHED}") == TERM ]] || {
    kill -TERM "${candidate_pid}" 2>/dev/null || true
    printf '%s\n' 'Host Agent upgrade wrapper did not wait for the signaled candidate to finish' >&2
    exit 1
  }
  if kill -0 "${candidate_pid}" 2>/dev/null; then
    kill -TERM "${candidate_pid}" 2>/dev/null || true
    printf '%s\n' 'candidate Local Executor remained alive after its wrapper returned' >&2
    exit 1
  fi

  if [[ ${expect_success} == true ]]; then
    grep -Fq -- "${COMPLETION}" "${SIGNAL_OUTPUT}"
  else
    [[ ${wrapper_status} -ne 0 ]] || {
      printf '%s\n' 'Host Agent upgrade converted candidate cancellation failure to success' >&2
      exit 1
    }
    assert_no_completion "$(<"${SIGNAL_OUTPUT}")"
    grep -Fq -- 'managed Host runtime upgrade failed' "${SIGNAL_OUTPUT}"
  fi

  rm -f -- \
    "${HELPER_SIGNAL_MODE}" \
    "${HELPER_SIGNAL_READY}" \
    "${HELPER_SIGNAL_RECEIVED}" \
    "${HELPER_SIGNAL_FINISHED}" \
    "${SIGNAL_OUTPUT}"
  assert_helper_arguments
  assert_private_stage_cleaned
  assert_sentinels_unchanged
}

install -o root -g root -m 0600 /dev/null "${HELPER_FAIL_MARKER}"
rm -f -- "${HELPER_LOG}"
helper_failure_status=0
helper_failure_output="$("${INSTALLER}" --upgrade 2>&1)" || helper_failure_status=$?
if [[ ${helper_failure_status} -ne 73 ]]; then
  printf '%s\n' 'Host Agent upgrade survived a candidate Local Executor failure' >&2
  printf 'status=%s, expected=73\n' "${helper_failure_status}" >&2
  exit 1
fi
rm -f -- "${HELPER_FAIL_MARKER}"
assert_no_completion "${helper_failure_output}"
assert_helper_arguments
assert_private_stage_cleaned
assert_sentinels_unchanged

[[ ! -d /run/systemd/system && "$(< /proc/1/comm)" != systemd ]] || {
  printf '%s\n' \
    'active-job recovery smoke may replace systemd clients only in an isolated non-systemd container' >&2
  exit 1
}
