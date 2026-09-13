
reset_recovery_fixture
[[ $(/usr/bin/systemctl is-active autostream-local-executor.service) == active ]]
executor_enabled_status=0
executor_enabled_output="$(/usr/bin/systemctl is-enabled \
  autostream-local-executor.service 2>&1)" || executor_enabled_status=$?
[[ ${executor_enabled_status} -ne 0 && ${executor_enabled_output} == disabled ]]
[[ $(/usr/bin/systemctl is-enabled autostream-local-executor.socket) == enabled &&
  $(/usr/bin/systemctl is-active autostream-local-executor.socket) == active ]]
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0700 "${MANAGED_RUNTIME_ROOT}/slots/a/bin"
assert_recovery_preflight_rejected_without_stop 'selected slot bin mode 0700'
chmod 0755 "${MANAGED_RUNTIME_ROOT}/slots/a/bin"
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0700 "${MANAGED_RUNTIME_ROOT}/slots/a"
assert_recovery_preflight_rejected_without_stop 'selected slot mode 0700'
chmod 0755 "${MANAGED_RUNTIME_ROOT}/slots/a"
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0744 "${MANAGED_RUNTIME_AGENT}"
assert_recovery_preflight_rejected_without_stop 'Host Agent binary mode 0744'
chmod 0755 "${MANAGED_RUNTIME_AGENT}"
assert_original_runtime_pair_active

reset_recovery_fixture
chmod 0744 "${MANAGED_RUNTIME_EXECUTOR}"
assert_recovery_preflight_rejected_without_stop 'Local Executor binary mode 0744'
chmod 0755 "${MANAGED_RUNTIME_EXECUTOR}"
assert_original_runtime_pair_active

reset_recovery_fixture
chown root:autostream-host-agent "${MANAGED_RUNTIME_EXECUTOR}"
assert_recovery_preflight_rejected_without_stop 'Local Executor binary owner drift'
chown root:root "${MANAGED_RUNTIME_EXECUTOR}"
assert_original_runtime_pair_active

reset_recovery_fixture
ln -sfnT /usr/bin/true "${PUBLIC_EXECUTOR}"
assert_recovery_preflight_rejected_without_stop 'public Local Executor symlink drift'
ln -sfnT \
  "${MANAGED_RUNTIME_CURRENT}/bin/autostream-local-executor" \
  "${PUBLIC_EXECUTOR}"
assert_original_runtime_pair_active

reset_recovery_fixture
export AUTOSTREAM_RUNTIME_FIXTURE_AGENT_VERSION=v1.9.9
export AUTOSTREAM_RUNTIME_FIXTURE_EXECUTOR_VERSION=v1.9.10
assert_recovery_preflight_rejected_without_stop 'mixed v1.9.9/v1.9.10 identity'
unset \
  AUTOSTREAM_RUNTIME_FIXTURE_AGENT_VERSION \
  AUTOSTREAM_RUNTIME_FIXTURE_EXECUTOR_VERSION
assert_original_runtime_pair_active

reset_recovery_fixture
export AUTOSTREAM_RUNTIME_FIXTURE_RECOVERY_PROTOCOL=1
assert_recovery_preflight_rejected_without_stop 'Local Executor recovery protocol 1'
unset AUTOSTREAM_RUNTIME_FIXTURE_RECOVERY_PROTOCOL
assert_original_runtime_pair_active

reset_recovery_fixture
original_executor_pid="$(<"${EXECUTOR_PID_FILE}")"
managed_agent_pid="$(<"${SERVICE_PID_FILE}")"
printf '%s\n' "${managed_agent_pid}" > "${EXECUTOR_PID_FILE}"
assert_recovery_preflight_rejected_without_stop 'Local Executor MainPID executable mismatch'
printf '%s\n' "${original_executor_pid}" > "${EXECUTOR_PID_FILE}"
assert_original_runtime_pair_active

reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_FAIL_MARKER}"
recovery_failure_status=0
recovery_failure_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  recovery_failure_status=$?
[[ ${recovery_failure_status} -eq 74 ]] || {
  printf 'recovery candidate failure status=%s, want=74\n' \
    "${recovery_failure_status}" >&2
  printf '%s\n' "${recovery_failure_output}" >&2
  exit 1
}
assert_no_completion "${recovery_failure_output}"
grep -Fq -- 'exact active Host update recovery failed' \
  <<<"${recovery_failure_output}"
[[ $(<"${RECOVERY_STATE}") == active ]]
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active

export AUTOSTREAM_RUNTIME_FIXTURE_VERSION=v1.9.10
reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_FAIL_MARKER}"
v1910_failure_status=0
v1910_failure_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  v1910_failure_status=$?
[[ ${v1910_failure_status} -eq 74 ]] || {
  printf 'v1.9.10 recovery candidate failure status=%s, want=74\n' \
    "${v1910_failure_status}" >&2
  printf '%s\n' "${v1910_failure_output}" >&2
  exit 1
}
assert_no_completion "${v1910_failure_output}"
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active
export AUTOSTREAM_RUNTIME_FIXTURE_VERSION=v1.9.9

reset_recovery_fixture
install -o autostream-host-agent -g autostream-host-agent -m 0600 \
  /dev/null "${RECOVERY_FAIL_WITH_LIFECYCLE_LOCK_MARKER}"
lifecycle_contention_status=0
lifecycle_contention_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  lifecycle_contention_status=$?
[[ ${lifecycle_contention_status} -ne 0 ]] || {
  printf '%s\n' 'recovery cleanup ignored lifecycle lock contention' >&2
  exit 1
}
assert_no_completion "${lifecycle_contention_output}"
grep -Fq -- \
  'could not reacquire the canonical Host setup and lifecycle locks' \
  <<<"${lifecycle_contention_output}"
grep -Fq -- \
  'the durable recovery fence and systemd guard were retained' \
  <<<"${lifecycle_contention_output}"
[[ $(<"${RECOVERY_STATE}") == active ]]
assert_recovery_invocation
assert_helper_not_called
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent lifecycle-lock-held'
assert_fail_closed_recovery_guard
release_recovery_lock_holder \
  "${RECOVERY_LIFECYCLE_HOLD_RELEASE}" \
  "${RECOVERY_LIFECYCLE_HOLD_READY}"
disarm_recovery_guard_fixture

reset_recovery_fixture
install -o root -g root -m 0600 /dev/null "${HELPER_FAIL_MARKER}"
manual_failure_status=0
manual_failure_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  manual_failure_status=$?
[[ ${manual_failure_status} -eq 73 ]] || {
  printf 'post-recovery manual upgrade failure status=%s, want=73\n' \
    "${manual_failure_status}" >&2
  printf '%s\n' "${manual_failure_output}" >&2
  exit 1
}
assert_no_completion "${manual_failure_output}"
grep -Fq -- 'managed Host runtime upgrade failed' <<<"${manual_failure_output}"
[[ $(<"${RECOVERY_STATE}") == inactive ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade start-agent stop-guard-timer stop-guard-service'
assert_recovery_candidate_cleaned
assert_original_runtime_pair_active

reset_recovery_fixture
install -o root -g root -m 0600 /dev/null "${HELPER_PARTIAL_SWITCH_MARKER}"
partial_switch_status=0
partial_switch_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  partial_switch_status=$?
[[ ${partial_switch_status} -ne 0 ]] || {
  printf '%s\n' 'partial A/B switch unexpectedly completed recovery upgrade' >&2
  exit 1
}
assert_no_completion "${partial_switch_output}"
grep -Fq -- 'managed Host runtime upgrade failed' <<<"${partial_switch_output}"
grep -Fq -- \
  'the pre-stop Host runtime pair was not restored; the durable recovery fence and systemd guard were retained' \
  <<<"${partial_switch_output}"
[[ $(<"${RECOVERY_STATE}") == inactive &&
  $(readlink -- "${MANAGED_RUNTIME_CURRENT}") == slots/b ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade'
assert_fail_closed_recovery_guard
ln -sfnT slots/a "${MANAGED_RUNTIME_CURRENT}"
rm -f -- "${HELPER_PARTIAL_SWITCH_MARKER}"
disarm_recovery_guard_fixture
assert_original_runtime_pair_active

reset_recovery_fixture
install -o root -g root -m 0600 /dev/null "${HELPER_FAIL_WITH_LOCK_MARKER}"
full_contention_status=0
full_contention_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  full_contention_status=$?
[[ ${full_contention_status} -ne 0 ]] || {
  printf '%s\n' 'post-recovery cleanup ignored setup/lifecycle lock contention' >&2
  exit 1
}
assert_no_completion "${full_contention_output}"
grep -Fq -- \
  'could not reacquire the canonical Host setup and lifecycle locks' \
  <<<"${full_contention_output}"
grep -Fq -- \
  'the durable recovery fence and systemd guard were retained' \
  <<<"${full_contention_output}"
[[ $(<"${RECOVERY_STATE}") == inactive ]]
assert_recovery_invocation
assert_helper_arguments true
assert_recovery_sequence \
  'guard-arm stop-agent recover-agent executor-lock-acquired manual-upgrade full-locks-held'
assert_fail_closed_recovery_guard
release_recovery_lock_holder \
  "${RECOVERY_FULL_HOLD_RELEASE}" \
  "${RECOVERY_FULL_HOLD_READY}"
disarm_recovery_guard_fixture

reset_recovery_fixture
exec 7<>/run/autostream-updater/.autostream-runtime-host-setup.lock
flock -n 7
lock_conflict_status=0
lock_conflict_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  lock_conflict_status=$?
[[ ${lock_conflict_status} -ne 0 ]] || {
  printf '%s\n' 'recovery ignored a concurrent Host runtime setup lock' >&2
  exit 1
}
grep -Fq -- 'another AutoStream installer is provisioning shared host state' \
  <<<"${lock_conflict_output}"
[[ ! -s ${RECOVERY_SEQUENCE_LOG} ]]
assert_helper_not_called
flock -u 7
exec 7>&-
assert_recovery_candidate_cleaned

reset_recovery_fixture
install -d -o root -g root -m 0755 /run/systemd/transient
printf '%s\n' conflicting > "${RECOVERY_GUARD_TIMER_PATH}"
chown root:root "${RECOVERY_GUARD_TIMER_PATH}"
chmod 0644 "${RECOVERY_GUARD_TIMER_PATH}"
conflict_status=0
conflict_output="$(${INSTALLER} --upgrade --recover-active-job 2>&1)" || \
  conflict_status=$?
[[ ${conflict_status} -ne 0 ]] || {
  printf '%s\n' 'recovery accepted a conflicting transient guard path' >&2
  exit 1
}
grep -Fq -- 'recovery guard timer already exists or is unsafe' \
  <<<"${conflict_output}"
[[ ! -s ${RECOVERY_SEQUENCE_LOG} ]]
assert_helper_not_called
rm -f -- "${RECOVERY_GUARD_TIMER_PATH}"
assert_recovery_candidate_cleaned
