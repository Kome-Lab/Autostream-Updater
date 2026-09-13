for uninstaller in \
  "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor" \
  "${PACKAGE_ROOT}/install/uninstall-autostream-host-agent"; do
  exec 8<>/run/autostream-updater/.autostream-runtime-host-setup.lock
  flock -n 8
  set +e
  uninstall_setup_lock_output="$(${uninstaller} 2>&1)"
  uninstall_setup_lock_status=$?
  set -e
  exec 8>&-
  if [[ ${uninstall_setup_lock_status} -eq 0 ||
    ${uninstall_setup_lock_output} != *'another AutoStream installer is provisioning shared host state'* ]]; then
    printf 'uninstaller %s did not fail closed on setup lock contention\n' "${uninstaller}" >&2
    printf '%s\n' "${uninstall_setup_lock_output}" >&2
    exit 1
  fi

  exec 9<>/run/autostream-updater/.autostream-host-lifecycle.lock
  flock -n 9
  lifecycle_lock_metadata="$(stat -c '%U:%G:%a:%h' \
    /run/autostream-updater/.autostream-host-lifecycle.lock)"
  lifecycle_lock_canonical="$(readlink -f \
    /run/autostream-updater/.autostream-host-lifecycle.lock)"
  if [[ ${lifecycle_lock_metadata} != "root:root:600:1" ||
    ${lifecycle_lock_canonical} != "/run/autostream-updater/.autostream-host-lifecycle.lock" ]]; then
    printf 'fixture lifecycle lock metadata=%s canonical=%s\n' \
      "${lifecycle_lock_metadata}" "${lifecycle_lock_canonical}" >&2
    exit 1
  fi
  set +e
  uninstall_lifecycle_lock_output="$(${uninstaller} 2>&1)"
  uninstall_lifecycle_lock_status=$?
  set -e
  exec 9>&-
  if [[ ${uninstall_lifecycle_lock_status} -eq 0 ||
    ${uninstall_lifecycle_lock_output} != *'another privileged Host lifecycle operation is active'* ]]; then
    printf 'uninstaller %s did not fail closed on lifecycle lock contention\n' "${uninstaller}" >&2
    printf '%s\n' "${uninstall_lifecycle_lock_output}" >&2
    exit 1
  fi
done
test -e /usr/local/bin/autostream-host-agent
test -e /usr/local/libexec/autostream-local-executor
test -L /usr/local/libexec/autostream-local-executor
test "$(readlink /usr/local/libexec/autostream-local-executor)" = \
  "/opt/autostream/host-agent/current/bin/autostream-local-executor"
test "$(sha256sum /opt/autostream/host-agent/slots/a/bin/autostream-local-executor |
  awk '{print $1}')" = "${prepared_executor_sha}"
test "$(stat -c '%U:%G:%a' /etc/autostream/updater/executor-policy.json)" = \
  "root:root:600"
test -e /tmp/autostream-local-executor.socket.enabled
test -e /tmp/autostream-local-executor.socket.active
test -e /tmp/autostream-local-executor.service.active
: > "${SYSTEMCTL_LOG}"

binary_sha=$(sha256sum /usr/local/bin/autostream-host-agent | awk '{print $1}')
install -o root -g autostream-host-agent -m 0640 \
  "${REPOSITORY_ROOT}/release/agent.yaml.example" \
  /etc/autostream/updater/agent.yaml
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted an existing canonical identity' >&2
  exit 1
fi
test "$(sha256sum /usr/local/bin/autostream-host-agent | awk '{print $1}')" = "${binary_sha}"
test "$(stat -c '%U:%G:%a' /etc/autostream/updater/agent.yaml)" = \
  "root:autostream-host-agent:640"
test "$(stat -c '%U:%G:%a' /etc/autostream/updater/executor-policy.json)" = \
  "root:root:600"

# An unrelated named traversal grant is operator-owned and must survive both
# normal uninstall and the later explicit purge of the dedicated Agent.
setfacl --no-mask -m "u:$(id -u nobody):--x" -- /etc/autostream
retained_parent_acl=$(getfacl --absolute-names --numeric -- /etc/autostream)
purged_agent_uid=$(id -u autostream-host-agent)
printf '%s\n' "${retained_parent_acl}" | grep -Fx -- "user:${purged_agent_uid}:--x" >/dev/null
"${PACKAGE_ROOT}/install/uninstall-autostream-host-agent"
test "$(getfacl --absolute-names --numeric -- /etc/autostream)" = "${retained_parent_acl}"
test ! -e /usr/local/bin/autostream-host-agent
test ! -e /etc/systemd/system/autostream-host-agent.service
test -e /etc/autostream/updater/agent.yaml
test -d /var/lib/autostream-host-agent
test -e /usr/local/libexec/autostream-local-executor
test -e /etc/systemd/system/autostream-local-executor.service
test -e /etc/systemd/system/autostream-local-executor.socket
test -e /etc/tmpfiles.d/autostream-local-executor.conf

"${PACKAGE_ROOT}/install/uninstall-autostream-local-executor" --purge
test ! -e /usr/local/libexec/autostream-local-executor
test ! -e /etc/systemd/system/autostream-local-executor.service
test ! -e /etc/systemd/system/autostream-local-executor.socket
test ! -e /etc/tmpfiles.d/autostream-local-executor.conf
test ! -e /etc/autostream/updater/executor-policy.json
test "$(getfacl --absolute-names --numeric -- /etc/autostream)" = "${retained_parent_acl}"

setfacl --no-mask -m "u:${purged_agent_uid}:r-x" -- /etc/autostream
if "${PACKAGE_ROOT}/install/uninstall-autostream-host-agent" --purge; then
  printf '%s\n' 'Host Agent purge accepted a customized parent ACL' >&2
  exit 1
fi
test -e /etc/autostream/updater/agent.yaml
id autostream-host-agent >/dev/null
setfacl --no-mask -m "u:${purged_agent_uid}:--x" -- /etc/autostream
test "$(getfacl --absolute-names --numeric -- /etc/autostream)" = "${retained_parent_acl}"

install -o root -g autostream-host-agent -m 0640 \
  /etc/autostream/updater/agent.yaml \
  /etc/autostream/updater/.agent.staged.wipe
"${PACKAGE_ROOT}/install/uninstall-autostream-host-agent" --purge
expected_purged_acl=$(printf '%s\n' "${retained_parent_acl}" | grep -vFx -- "user:${purged_agent_uid}:--x")
test "$(getfacl --absolute-names --numeric -- /etc/autostream)" = "${expected_purged_acl}"
test ! -e /etc/autostream/updater/.agent.staged.wipe
test ! -e /etc/autostream/updater
test ! -e /var/lib/autostream-host-agent
if id autostream-host-agent >/dev/null 2>&1 || getent group autostream-host-agent >/dev/null; then
  printf '%s\n' 'Host Agent purge preserved its dedicated account or group' >&2
  exit 1
fi
