
ln -s /root /etc/systemd/system/autostream-local-executor.service
if fresh_late_failure_output="$(
  "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare 2>&1
)"; then
  printf '%s\n' 'prepare mode survived a late destination preflight failure' >&2
  exit 1
fi
rm -f -- /etc/systemd/system/autostream-local-executor.service
if [[ ${fresh_late_failure_output} != \
    *'existing local executor service must be a regular non-symlink file'* ]]; then
  printf '%s\n%s\n' \
    'late destination preflight did not fail at the local executor service boundary; captured output:' \
    "${fresh_late_failure_output}" >&2
  exit 1
fi
if [[ ${fresh_late_failure_output} == *'rollback refused'* ||
  ${fresh_late_failure_output} == *'rollback could not'* ]]; then
  printf '%s\n%s\n' \
    'late destination preflight reported an account rollback failure; captured output:' \
    "${fresh_late_failure_output}" >&2
  exit 1
fi
if id autostream-host-agent >/dev/null 2>&1 ||
  getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'late destination preflight failure left a fresh Host Agent account or group' >&2
  exit 1
fi
if [[ -e /etc/autostream/updater ||
  -e /var/lib/autostream-host-agent ||
  -e /etc/autostream-local-executor ||
  -e /opt/autostream/host-agent ||
  -e /opt/autostream/local-executor ]]; then
  printf '%s\n' 'late destination preflight failure left fresh Host Agent directories' >&2
  exit 1
fi

groupadd --system autostream-host-agent
preexisting_group_record_before="$(getent group autostream-host-agent)"
preexisting_group_database_before="$(
  sha256sum -- /etc/group | awk 'NR == 1 { print $1 }'
)"
preexisting_gshadow_database_before="$(
  sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }'
)"
if [[ -z ${preexisting_group_record_before} ||
  ! ${preexisting_group_database_before} =~ ^[0-9a-f]{64}$ ||
  ! ${preexisting_gshadow_database_before} =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' 'could not snapshot the pre-existing Host Agent group fixture' >&2
  exit 1
fi
if id autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'pre-existing Host Agent group fixture unexpectedly has a user' >&2
  exit 1
fi
ln -s /root /etc/systemd/system/autostream-local-executor.service
if preexisting_group_failure_output="$(
  "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare 2>&1
)"; then
  printf '%s\n' 'prepare mode survived failure with only a pre-existing Host Agent group' >&2
  exit 1
fi
rm -f -- /etc/systemd/system/autostream-local-executor.service
if [[ ${preexisting_group_failure_output} != \
    *'existing local executor service must be a regular non-symlink file'* ]]; then
  printf '%s\n%s\n' \
    'pre-existing Host Agent group probe did not fail at the local executor service boundary; captured output:' \
    "${preexisting_group_failure_output}" >&2
  exit 1
fi
if [[ ${preexisting_group_failure_output} == *'rollback refused'* ||
  ${preexisting_group_failure_output} == *'rollback could not'* ]]; then
  printf '%s\n%s\n' \
    'pre-existing Host Agent group probe reported an account rollback failure; captured output:' \
    "${preexisting_group_failure_output}" >&2
  exit 1
fi
if id autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'pre-existing Host Agent group rollback left its temporary user behind' >&2
  exit 1
fi
if [[ $(getent group autostream-host-agent) != "${preexisting_group_record_before}" ||
  $(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }') != \
    "${preexisting_group_database_before}" ||
  $(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }') != \
    "${preexisting_gshadow_database_before}" ]]; then
  printf '%s\n' 'pre-existing Host Agent group changed during rollback' >&2
  exit 1
fi
groupdel autostream-host-agent
if getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'pre-existing Host Agent group fixture cleanup left the group behind' >&2
  exit 1
fi

groupadd --system autostream-host-agent
useradd --system --gid autostream-host-agent \
  --home-dir /var/lib/autostream-host-agent --shell /usr/sbin/nologin \
  autostream-host-agent
install -d -o root -g root -m 0750 /etc/autostream
install -d -o root -g autostream-host-agent -m 0750 /etc/autostream/updater
install -d -o autostream-host-agent -g autostream-host-agent -m 0700 \
  /var/lib/autostream-host-agent
printf '%s\n' preserved > /var/lib/autostream-host-agent/sentinel
chown autostream-host-agent:autostream-host-agent \
  /var/lib/autostream-host-agent/sentinel
chmod 0600 /var/lib/autostream-host-agent/sentinel
existing_state_identity=$(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-host-agent)
existing_state_sha=$(sha256sum /var/lib/autostream-host-agent/sentinel | awk 'NR == 1 { print $1 }')
existing_parent_acl=$(getfacl --absolute-names --numeric /etc/autostream)
install -o root -g root -m 0640 /dev/null /etc/autostream/private-service.env
existing_service_metadata=$(stat -c '%d:%i:%u:%g:%a' /etc/autostream/private-service.env)
setfacl -m u:nobody:r-x /etc/autostream/updater
if unsafe_acl_output="$("${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare 2>&1)"; then
  printf '%s\n' 'prepare accepted an identity directory ACL for another account' >&2
  exit 1
fi
[[ ${unsafe_acl_output} == *'must not grant named or inherited ACL access'* ]]
[[ $(getfacl --absolute-names --numeric /etc/autostream) == "${existing_parent_acl}" ]]
setfacl --remove-all /etc/autostream/updater
setfacl --no-mask -m "u:$(id -u autostream-host-agent):r-x" /etc/autostream
excessive_parent_acl=$(getfacl --absolute-names --numeric /etc/autostream)
if excessive_parent_output="$("${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare 2>&1)"; then
  printf '%s\n' 'prepare accepted identity-parent listing access' >&2
  exit 1
fi
[[ ${excessive_parent_output} == *'the dedicated Agent has a customized identity parent ACL'* ]]
[[ $(getfacl --absolute-names --numeric /etc/autostream) == "${excessive_parent_acl}" ]]
printf '%s\n' "${existing_parent_acl}" | setfacl --restore=-
ln -s /root /etc/systemd/system/autostream-local-executor.service
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode survived failure with existing Host Agent state' >&2
  exit 1
fi
rm -f -- /etc/systemd/system/autostream-local-executor.service
if [[ $(getfacl --absolute-names --numeric /etc/autostream) != "${existing_parent_acl}" ||
  $(stat -c '%d:%i:%u:%g:%a' /etc/autostream/private-service.env) != "${existing_service_metadata}" ]]; then
  printf '%s\n' 'failed prepare changed the shared parent ACL or a sibling service secret' >&2
  exit 1
fi
rm -f -- /etc/autostream/private-service.env
if [[ $(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-host-agent) != \
    "${existing_state_identity}" ||
  $(sha256sum /var/lib/autostream-host-agent/sentinel | awk 'NR == 1 { print $1 }') != \
    "${existing_state_sha}" ]]; then
  printf '%s\n' 'failed prepare changed the existing Host Agent state directory' >&2
  exit 1
fi
rm -f -- /var/lib/autostream-host-agent/sentinel
rmdir -- /var/lib/autostream-host-agent /etc/autostream/updater /etc/autostream
userdel autostream-host-agent
if getent group autostream-host-agent >/dev/null 2>&1; then
  groupdel autostream-host-agent
fi
if id autostream-host-agent >/dev/null 2>&1 ||
  getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'existing Host Agent account fixture cleanup left the account or group behind' >&2
  exit 1
fi

hostile_gid_group_database_before="$(
  sha256sum -- /etc/group | awk 'NR == 1 { print $1 }'
)"
hostile_gid_gshadow_database_before="$(
  sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }'
)"
if [[ ! ${hostile_gid_group_database_before} =~ ^[0-9a-f]{64}$ ||
  ! ${hostile_gid_gshadow_database_before} =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' 'could not snapshot local group databases before the hostile GID 0 fixture' >&2
  exit 1
fi
groupadd --system --non-unique --gid 0 autostream-host-agent
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a Host Agent group using gid 0' >&2
  exit 1
fi
if id autostream-host-agent >/dev/null 2>&1 ||
  [[ -e /etc/autostream/updater || -e /var/lib/autostream-host-agent ]]; then
  printf '%s\n' 'gid 0 rejection mutated the Host Agent account or paths' >&2
  exit 1
fi
groupdel --force autostream-host-agent
if getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'hostile GID 0 fixture cleanup left the Host Agent group behind' >&2
  exit 1
fi
if [[ $(sha256sum -- /etc/group | awk 'NR == 1 { print $1 }') != \
    "${hostile_gid_group_database_before}" ||
  $(sha256sum -- /etc/gshadow | awk 'NR == 1 { print $1 }') != \
    "${hostile_gid_gshadow_database_before}" ]]; then
  printf '%s\n' 'hostile GID 0 fixture cleanup changed the local group databases' >&2
  exit 1
fi

touch \
  /tmp/autostream-host-agent-fail-timer-enable-after-side-effect \
  /tmp/autostream-host-agent-reactivate-recovery-after-timer-disable
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode survived a timer enable failure after side effects' >&2
  exit 1
fi
rm -f -- \
  /tmp/autostream-host-agent-fail-timer-enable-after-side-effect \
  /tmp/autostream-host-agent-reactivate-recovery-after-timer-disable
for recovery_unit in \
  autostream-host-self-update-recovery@a.timer \
  autostream-host-self-update-recovery@b.timer \
  autostream-host-self-update-recovery@a.service \
  autostream-host-self-update-recovery@b.service; do
  if [[ -e /tmp/"${recovery_unit}".enabled ||
    -e /tmp/"${recovery_unit}".active ]]; then
    printf '%s\n' 'timer enable failure left a recovery timer enabled or active' >&2
    exit 1
  fi
done
if [[ -e /opt/autostream/host-agent ]]; then
  printf '%s\n' 'timer recovery side effects left a partial Host Agent runtime' >&2
  exit 1
fi
if id autostream-host-agent >/dev/null 2>&1 ||
  getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'timer enable failure left a fresh Host Agent account or group' >&2
  exit 1
fi

touch /tmp/autostream-host-agent-fail-daemon-reload
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode survived an injected post-commit daemon-reload failure' >&2
  exit 1
fi
test ! -e /etc/autostream/updater
test ! -e /var/lib/autostream-host-agent
test ! -e /etc/autostream/updater/executor-policy.json
test ! -e /etc/autostream-local-executor
test ! -e /opt/autostream/local-executor
test ! -e /usr/local/bin/autostream-host-agent
test ! -e /etc/systemd/system/autostream-host-agent.service
test ! -e /usr/local/libexec/autostream-local-executor
test ! -e /etc/systemd/system/autostream-local-executor.service
test ! -e /etc/systemd/system/autostream-local-executor.socket
test ! -e /etc/tmpfiles.d/autostream-local-executor.conf
test ! -e /etc/systemd/system/autostream-host-self-update-recovery@.service
test ! -e /etc/systemd/system/autostream-host-self-update-recovery@.timer
test ! -e /opt/autostream/host-agent
if id autostream-host-agent >/dev/null 2>&1 ||
  getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'post-commit prepare failure left a fresh Host Agent account or group' >&2
  exit 1
fi

install -d -o root -g root -m 0750 /etc/autostream
ln -s /root /etc/autostream/updater
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a symlink policy directory' >&2
  exit 1
fi
rm -f -- /etc/autostream/updater

install -o root -g root -m 0600 /dev/null /etc/autostream/updater
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a non-directory policy path' >&2
  exit 1
fi
rm -f -- /etc/autostream/updater

install -d -o root -g root -m 0755 /etc/autostream/updater
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted an over-permissive policy directory' >&2
  exit 1
fi
rmdir -- /etc/autostream/updater

install -d -o root -g root -m 0750 /etc/autostream/updater
chown 1:1 /etc/autostream/updater
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a non-root-owned policy directory' >&2
  exit 1
fi
chown root:root /etc/autostream/updater
rmdir -- /etc/autostream/updater

install -d -o root -g root -m 0700 /opt/autostream/local-executor
ln -s /root /opt/autostream/local-executor/ports
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a symlink port directory' >&2
  exit 1
fi
rm -f -- /opt/autostream/local-executor/ports
install -d -o root -g root -m 0755 /opt/autostream/local-executor/ports
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted an over-permissive port directory' >&2
  exit 1
fi
rmdir -- /opt/autostream/local-executor/ports
rmdir -- /opt/autostream/local-executor

install -d -o root -g root -m 0700 \
  /opt/autostream/local-executor \
  /opt/autostream/local-executor/ports
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode survived failure with existing private directories' >&2
  exit 1
fi
for private_dir in \
  /opt/autostream/local-executor \
  /opt/autostream/local-executor/ports; do
  test "$(stat -c '%U:%G:%a' "${private_dir}")" = "root:root:700"
done
rm -f -- /tmp/autostream-host-agent-fail-daemon-reload
rmdir -- /opt/autostream/local-executor/ports
rmdir -- /opt/autostream/local-executor
