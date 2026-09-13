
# Prove that the transient recovery guard is an independent recovery path: the
# installer wrapper is killed while its service-owned recovery process is
# blocked, then only the delayed guard is allowed to restart the exact old pair.
reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_BLOCK_MARKER}"
"${INSTALLER}" --upgrade --recover-active-job \
  >"${GUARD_SELF_FIRE_OUTPUT}" 2>&1 &
guard_self_fire_wrapper_pid=$!
for ((attempt = 0; attempt < 400; attempt++)); do
  if [[ -f ${RECOVERY_BLOCK_READY} && ! -L ${RECOVERY_BLOCK_READY} &&
    -f ${GUARD_TIMER_ACTIVE_MARKER} && ! -L ${GUARD_TIMER_ACTIVE_MARKER} &&
    -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} &&
    $(/usr/bin/systemctl is-active autostream-host-agent.service 2>/dev/null || true) == \
      inactive ]]; then
    break
  fi
  if ! kill -0 "${guard_self_fire_wrapper_pid}" 2>/dev/null; then
    printf '%s\n' 'installer exited before the recovery guard self-fire fixture was ready' >&2
    sed -n '1,160p' "${GUARD_SELF_FIRE_OUTPUT}" >&2
    exit 1
  fi
  sleep 0.025
done
[[ -f ${RECOVERY_BLOCK_READY} && ! -L ${RECOVERY_BLOCK_READY} &&
  -f ${GUARD_TIMER_ACTIVE_MARKER} && ! -L ${GUARD_TIMER_ACTIVE_MARKER} &&
  -f ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} ]] || {
  printf '%s\n' 'timed out waiting for the recovery guard self-fire fixture' >&2
  exit 1
}
guard_self_fire_candidate_pid="$(<"${RECOVERY_BLOCK_READY}")"
[[ ${guard_self_fire_candidate_pid} =~ ^[1-9][0-9]*$ &&
  -d /proc/${guard_self_fire_candidate_pid} ]] || {
  printf '%s\n' 'recovery guard self-fire fixture recorded an invalid candidate PID' >&2
  exit 1
}
kill -KILL "${guard_self_fire_wrapper_pid}"
guard_self_fire_wrapper_status=0
wait "${guard_self_fire_wrapper_pid}" || guard_self_fire_wrapper_status=$?
[[ ${guard_self_fire_wrapper_status} -eq 137 ]] || {
  printf 'SIGKILLed installer status=%s, want=137\n' \
    "${guard_self_fire_wrapper_status}" >&2
  exit 1
}
kill -TERM "${guard_self_fire_candidate_pid}"
rm -f -- "${RECOVERY_BLOCK_MARKER}"
for ((attempt = 0; attempt < 400; attempt++)); do
  if [[ ! -d /proc/${guard_self_fire_candidate_pid} ]] ||
    [[ $(awk '{ print $3 }' "/proc/${guard_self_fire_candidate_pid}/stat" \
      2>/dev/null || true) == Z ]]; then
    break
  fi
  sleep 0.025
done
if [[ -d /proc/${guard_self_fire_candidate_pid} &&
  $(awk '{ print $3 }' "/proc/${guard_self_fire_candidate_pid}/stat" \
    2>/dev/null || true) != Z ]]; then
  printf '%s\n' 'service-owned recovery candidate survived wrapper SIGKILL cleanup' >&2
  exit 1
fi
guard_self_fire_locks_ready=false
for ((attempt = 0; attempt < 400; attempt++)); do
  exec 10<>"${RECOVERY_SETUP_LOCK}"
  if flock -n 10; then
    exec 11<>"${RECOVERY_LIFECYCLE_LOCK}"
    if flock -n 11; then
      flock -u 11
      exec 11>&-
      flock -u 10
      exec 10>&-
      guard_self_fire_locks_ready=true
      break
    fi
    exec 11>&-
    flock -u 10
  fi
  exec 10>&-
  sleep 0.025
done
[[ ${guard_self_fire_locks_ready} == true ]] || {
  printf '%s\n' 'wrapper SIGKILL left a Host setup or lifecycle lock held' >&2
  exit 1
}
install -o root -g root -m 0600 /dev/null "${GUARD_FIRE_TRIGGER}"
for ((attempt = 0; attempt < 400; attempt++)); do
  [[ -f ${GUARD_FIRE_STATUS} && ! -L ${GUARD_FIRE_STATUS} ]] && break
  sleep 0.025
done
[[ -f ${GUARD_FIRE_STATUS} && ! -L ${GUARD_FIRE_STATUS} &&
  $(stat -c '%U:%G:%a' -- "${GUARD_FIRE_STATUS}") == root:root:600 &&
  $(<"${GUARD_FIRE_STATUS}") == 0 &&
  $(<"${RECOVERY_STATE}") == active &&
  ! -e ${RECOVERY_CLEAR_FENCE} && ! -L ${RECOVERY_CLEAR_FENCE} ]] || {
  printf '%s\n' 'independent recovery guard did not restart the exact old runtime' >&2
  exit 1
}
assert_no_completion "$(<"${GUARD_SELF_FIRE_OUTPUT}")"
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent guard-helper start-agent'
assert_original_runtime_pair_active
/usr/bin/systemctl stop \
  autostream-host-agent-upgrade-recovery-guard.timer >/dev/null
/usr/bin/systemctl stop \
  autostream-host-agent-upgrade-recovery-guard.service >/dev/null
wait_for_guard_worker_exit
cleanup_fired_guard_candidate_fixture
cleanup_abandoned_recovery_candidate_fixture
cleanup_abandoned_private_stage_fixture
rm -f -- \
  "${RECOVERY_BLOCK_READY}" \
  "${GUARD_FIRE_TRIGGER}" \
  "${GUARD_FIRE_STATUS}" \
  "${GUARD_SELF_FIRE_OUTPUT}"
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active

reset_recovery_fixture
recovery_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)"
grep -Fq -- "${COMPLETION}" <<<"${recovery_output}"
grep -Fq -- "Verified Host Agent bundle archive SHA-256: ${EXPECTED_ARCHIVE_SHA256}" \
  <<<"${recovery_output}"
[[ $(<"${RECOVERY_STATE}") == inactive ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade restart-executor start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_committed_runtime_pair_active

if fixture_pid="$(<"${SERVICE_PID_FILE}")" && \
  [[ ${fixture_pid} =~ ^[1-9][0-9]*$ ]]; then
  kill -TERM "${fixture_pid}" 2>/dev/null || true
fi
if executor_fixture_pid="$(<"${EXECUTOR_PID_FILE}")" &&
  [[ ${executor_fixture_pid} =~ ^[1-9][0-9]*$ ]]; then
  kill -TERM "${executor_fixture_pid}" 2>/dev/null || true
fi
kill -TERM "${LOCAL_EXECUTOR_LOCK_DAEMON_PID}" 2>/dev/null || true
wait "${LOCAL_EXECUTOR_LOCK_DAEMON_PID}" 2>/dev/null || true
if [[ -f ${SYSTEMCTL_BACKUP} && ! -L ${SYSTEMCTL_BACKUP} ]]; then
  install -o root -g root -m 0755 "${SYSTEMCTL_BACKUP}" /usr/bin/systemctl
fi
if [[ -f ${SYSTEMD_RUN_BACKUP} && ! -L ${SYSTEMD_RUN_BACKUP} ]]; then
  install -o root -g root -m 0755 "${SYSTEMD_RUN_BACKUP}" /usr/bin/systemd-run
fi
rm -f -- "${SYSTEMCTL_LOG}" "${SYSTEMD_RUN_LOG}"

run_wrapper_signal_case failure false 75
run_wrapper_signal_case success true 0

rm -f -- "${HELPER_LOG}"
upgrade_output="$("${INSTALLER}" --upgrade 2>&1)"
grep -Fq -- "${COMPLETION}" <<<"${upgrade_output}"
grep -Fq -- "Verified Host Agent bundle archive SHA-256: ${EXPECTED_ARCHIVE_SHA256}" \
  <<<"${upgrade_output}"
assert_helper_arguments
assert_private_stage_cleaned
assert_sentinels_unchanged
