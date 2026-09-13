
install -d -o root -g root -m 0700 /run/autostream-updater
exec 8<>/run/autostream-updater/.autostream-runtime-host-setup.lock
flock -n 8
set +e
host_setup_lock_output="$(${PACKAGE_ROOT}/install/install-autostream-host-agent --prepare 2>&1)"
host_setup_lock_status=$?
set -e
exec 8>&-
if [[ ${host_setup_lock_status} -eq 0 ||
  ${host_setup_lock_output} != *'another AutoStream installer is provisioning shared host state'* ]]; then
  printf '%s\n' 'prepare mode did not fail closed on shared host-setup lock contention' >&2
  printf '%s\n' "${host_setup_lock_output}" >&2
  exit 1
fi
test "$(stat -c '%U:%G:%a' /run/autostream-updater)" = "root:root:700"
test "$(stat -c '%U:%G:%a:%h' \
  /run/autostream-updater/.autostream-runtime-host-setup.lock)" = "root:root:600:1"

exec 9<>/run/autostream-updater/.autostream-host-lifecycle.lock
flock -n 9
set +e
host_lifecycle_lock_output="$(${PACKAGE_ROOT}/install/install-autostream-host-agent --prepare 2>&1)"
host_lifecycle_lock_status=$?
set -e
exec 9>&-
if [[ ${host_lifecycle_lock_status} -eq 0 ||
  ${host_lifecycle_lock_output} != *'another privileged Host lifecycle operation is active'* ]]; then
  printf '%s\n' 'prepare mode did not fail closed on Host lifecycle lock contention' >&2
  printf '%s\n' "${host_lifecycle_lock_output}" >&2
  exit 1
fi
test "$(stat -c '%U:%G:%a:%h' \
  /run/autostream-updater/.autostream-host-lifecycle.lock)" = "root:root:600:1"

"${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare

test "$(stat -c '%U:%G:%a' /etc/autostream)" = "root:root:750"
runuser -u autostream-host-agent -- test -x /etc/autostream
if runuser -u autostream-host-agent -- test -r /etc/autostream ||
  runuser -u autostream-host-agent -- test -w /etc/autostream; then
  printf '%s\n' 'prepare widened the Agent shared directory access beyond traversal' >&2
  exit 1
fi
test "$(stat -c '%U:%G:%a' /etc/autostream/updater)" = "root:autostream-host-agent:750"
test ! -e /etc/autostream/updater/agent.yaml
test ! -e /etc/autostream/updater/executor-policy.json
test ! -e /etc/autostream-local-executor
test "$(stat -c '%U:%G:%a' /opt/autostream/local-executor)" = "root:root:700"
test "$(stat -c '%U:%G:%a' /opt/autostream/local-executor/ports)" = "root:root:700"
test -L /usr/local/bin/autostream-host-agent
test "$(readlink /usr/local/bin/autostream-host-agent)" = \
  "/opt/autostream/host-agent/current/bin/autostream-host-agent"
test "$(readlink /opt/autostream/host-agent/current)" = "slots/a"
test "$(stat -c '%U:%G:%a' /opt/autostream/host-agent/slots/a/bin/autostream-host-agent)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /etc/systemd/system/autostream-host-agent.service)" = "root:root:644"
test -L /usr/local/libexec/autostream-local-executor
test "$(readlink /usr/local/libexec/autostream-local-executor)" = \
  "/opt/autostream/host-agent/current/bin/autostream-local-executor"
test "$(stat -c '%U:%G:%a' /opt/autostream/host-agent/slots/a/bin/autostream-local-executor)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /etc/systemd/system/autostream-local-executor.service)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /etc/systemd/system/autostream-local-executor.socket)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /etc/tmpfiles.d/autostream-local-executor.conf)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /etc/systemd/system/autostream-host-self-update-recovery@.service)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /etc/systemd/system/autostream-host-self-update-recovery@.timer)" = "root:root:644"
test -e /tmp/autostream-host-self-update-recovery@a.timer.enabled
test -e /tmp/autostream-host-self-update-recovery@a.timer.active
test -e /tmp/autostream-host-self-update-recovery@b.timer.enabled
test -e /tmp/autostream-host-self-update-recovery@b.timer.active
test ! -e /run/autostream-local-executor
test ! -e /var/lib/autostream-local-executor
grep -qx -- 'ConditionPathExists=/etc/autostream/updater/agent.yaml' \
  /etc/systemd/system/autostream-host-agent.service
test "$(stat -c '%U:%G:%a' /var/lib/autostream-host-agent)" = "autostream-host-agent:autostream-host-agent:700"
test "$(id -u autostream-host-agent)" -ne 0
test "$(id -gn autostream-host-agent)" = "autostream-host-agent"
test "$(id -Gn autostream-host-agent)" = "autostream-host-agent"
grep -qx -- '--version' "${BINARY_LOG}"
grep -qx -- '--version' "${LOCAL_EXECUTOR_BINARY_LOG}"
grep -qx -- 'daemon-reload' "${SYSTEMCTL_LOG}"
if grep -Eq '^(enable|start)( |$).*(autostream-host-agent\.service|autostream-local-executor\.(service|socket))' "${SYSTEMCTL_LOG}"; then
  printf '%s\n' 'prepare mode enabled or started a runtime unit' >&2
  exit 1
fi
grep -qx -- 'enable --now autostream-host-self-update-recovery@a.timer' "${SYSTEMCTL_LOG}"
grep -qx -- 'enable --now autostream-host-self-update-recovery@b.timer' "${SYSTEMCTL_LOG}"

install -o root -g root -m 0600 \
  "${REPOSITORY_ROOT}/release/autostream-local-executor-policy.json.example" \
  /root/autostream-local-executor-policy.json
prepared_executor_sha=$(sha256sum \
  /opt/autostream/host-agent/slots/a/bin/autostream-local-executor |
  awk '{print $1}')
exec 8<>/run/autostream-updater/.autostream-runtime-host-setup.lock
flock -n 8
set +e
local_setup_lock_output="$(
  "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
    --policy /root/autostream-local-executor-policy.json 2>&1
)"
local_setup_lock_status=$?
set -e
exec 8>&-
if [[ ${local_setup_lock_status} -eq 0 ||
  ${local_setup_lock_output} != *'another AutoStream installer is provisioning shared host state'* ]]; then
  printf '%s\n' 'local executor installer did not fail closed on shared host-setup lock contention' >&2
  printf '%s\n' "${local_setup_lock_output}" >&2
  exit 1
fi
test ! -e /etc/autostream/updater/executor-policy.json
exec 9<>/run/autostream-updater/.autostream-host-lifecycle.lock
flock -n 9
set +e
local_lifecycle_lock_output="$(
  "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
    --policy /root/autostream-local-executor-policy.json 2>&1
)"
local_lifecycle_lock_status=$?
set -e
exec 9>&-
if [[ ${local_lifecycle_lock_status} -eq 0 ||
  ${local_lifecycle_lock_output} != *'another privileged Host lifecycle operation is active'* ]]; then
  printf '%s\n' 'local executor installer did not fail closed on Host lifecycle lock contention' >&2
  printf '%s\n' "${local_lifecycle_lock_output}" >&2
  exit 1
fi
test ! -e /etc/autostream/updater/executor-policy.json
touch /tmp/autostream-host-agent-fail-daemon-reload
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'composed local installer survived an injected daemon-reload failure' >&2
  exit 1
fi
rm -f -- /tmp/autostream-host-agent-fail-daemon-reload
test -L /usr/local/libexec/autostream-local-executor
test "$(readlink /usr/local/libexec/autostream-local-executor)" = \
  "/opt/autostream/host-agent/current/bin/autostream-local-executor"
test "$(sha256sum /opt/autostream/host-agent/slots/a/bin/autostream-local-executor |
  awk '{print $1}')" = "${prepared_executor_sha}"
test ! -e /etc/autostream/updater/executor-policy.json
"${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json
