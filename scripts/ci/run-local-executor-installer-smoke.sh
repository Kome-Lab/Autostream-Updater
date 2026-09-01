#!/bin/bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

[[ $(id -u) -eq 0 ]] || {
  printf '%s\n' 'local executor installer smoke requires root' >&2
  exit 1
}
[[ $# -eq 1 ]] || {
  printf '%s\n' 'usage: run-local-executor-installer-smoke.sh REPOSITORY_ROOT' >&2
  exit 1
}

readonly REPOSITORY_ROOT=$1
readonly VERSION=v9.9.9
readonly BUILD_COMMIT=0123456789abcdef0123456789abcdef01234567
readonly BUILD_DATE=2026-07-31T00:00:00Z
readonly ARTIFACT_ID="autostream-host-agent_${VERSION}_linux_amd64"
readonly PACKAGE_ROOT="/root/${ARTIFACT_ID}"
readonly ARCHIVE="/root/${ARTIFACT_ID}.tar.gz"
readonly SYSTEMCTL_LOG=/tmp/autostream-local-executor-systemctl.log
readonly BINARY_LOG=/tmp/autostream-local-executor-binary.log

getent group autostream-host-agent >/dev/null 2>&1 || groupadd --system autostream-host-agent
id autostream-host-agent >/dev/null 2>&1 || \
  useradd --system --gid autostream-host-agent --home-dir /var/lib/autostream-host-agent \
    --shell /usr/sbin/nologin autostream-host-agent
readonly AGENT_UID=$(id -u autostream-host-agent)
readonly AGENT_GID=$(id -g autostream-host-agent)

rm -rf -- "${PACKAGE_ROOT}"
rm -f -- "${ARCHIVE}"
mkdir -p "${PACKAGE_ROOT}/bin" "${PACKAGE_ROOT}/install" "${PACKAGE_ROOT}/systemd"
install -m 0755 \
  "${REPOSITORY_ROOT}/release/install-autostream-local-executor" \
  "${PACKAGE_ROOT}/install/install-autostream-local-executor"
install -m 0755 \
  "${REPOSITORY_ROOT}/release/uninstall-autostream-local-executor" \
  "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor"
install -m 0755 \
  "${REPOSITORY_ROOT}/release/install-autostream-host-agent" \
  "${PACKAGE_ROOT}/install/install-autostream-host-agent"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.service"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.socket.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.socket"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.tmpfiles.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.tmpfiles"

fake_binary=$(mktemp)
cat > "${fake_binary}" <<EOF
#!/bin/bash
set -euo pipefail
printf '%s\n' "\$*" >> "${BINARY_LOG}"
case "\${1:-}" in
  --version)
    printf '%s\n' \
      'autostream-local-executor v9.9.9' \
      'commit: 0123456789abcdef0123456789abcdef01234567' \
      'build_date: 2026-07-31T00:00:00Z' \
      'mutation_protocol: 2' \
      'recovery_protocol: 2'
    ;;
  validate-policy)
    test -f "\${3:-}"
    agent_uid=${AGENT_UID}
    if [[ -e /tmp/autostream-local-executor-wrong-id ]]; then
      agent_uid=1
    fi
    printf '%s\n' \
      'local executor policy valid' \
      'host_id: host-smoke' \
      "agent_uid: \${agent_uid}" \
      'agent_gid: ${AGENT_GID}' \
      'policy_revision: 1' \
      'policy_sha256: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ;;
  *)
    printf 'unexpected local executor invocation: %s\n' "\$*" >&2
    exit 91
    ;;
esac
EOF
install -m 0755 "${fake_binary}" "${PACKAGE_ROOT}/bin/autostream-local-executor"
rm -f -- "${fake_binary}"

fake_host_binary=$(mktemp)
cat > "${fake_host_binary}" <<'EOF'
#!/bin/bash
set -euo pipefail
[[ ${1:-} == "--version" ]] || exit 92
printf '%s\n' \
  'autostream-host-agent v9.9.9' \
  'commit: 0123456789abcdef0123456789abcdef01234567' \
  'build_date: 2026-07-31T00:00:00Z'
EOF
install -m 0755 "${fake_host_binary}" "${PACKAGE_ROOT}/bin/autostream-host-agent"
rm -f -- "${fake_host_binary}"

cat > "${PACKAGE_ROOT}/artifact-manifest.json" <<EOF
{
  "schema_version": 1,
  "component": "host-agent",
  "source_version": "${VERSION}",
  "commit": "${BUILD_COMMIT}",
  "build_date": "${BUILD_DATE}",
  "platform": {
    "os": "linux",
    "arch": "amd64"
  },
  "archive": {
    "name": "${ARTIFACT_ID}.tar.gz",
    "root": "${ARTIFACT_ID}"
  },
  "compatibility": {
    "minimum_agent_version": null,
    "minimum_panel_version": "${VERSION}",
    "rollback_compatible": true,
    "database_schema": "none"
  }
}
EOF
install -o root -g root -m 0600 "${PACKAGE_ROOT}/artifact-manifest.json" \
  /root/autostream-local-executor-artifact-manifest.valid.json

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

rebuild_bundle_archive
expected_manifest_sha="$(sha256sum "${PACKAGE_ROOT}/artifact-manifest.json" | awk 'NR == 1 { print $1 }')"
if ! command -v jq >/dev/null 2>&1; then
  jq_shim=$(mktemp)
  cat > "${jq_shim}" <<EOF
#!/bin/bash
set -euo pipefail
manifest="\${!#}"
actual_sha="\$(sha256sum -- "\${manifest}" | awk 'NR == 1 { print \$1 }')"
[[ \${actual_sha} == "${expected_manifest_sha}" ]] || exit 1
case " \$* " in
  *" .commit "*)
    printf '%s\n' '${BUILD_COMMIT}'
    ;;
  *" .build_date "*)
    printf '%s\n' '${BUILD_DATE}'
    ;;
  *)
    exit 0
    ;;
esac
EOF
  install -o root -g root -m 0755 "${jq_shim}" /usr/bin/jq
  rm -f -- "${jq_shim}"
fi

install -d -o root -g root -m 0700 /root
install -o root -g root -m 0600 \
  "${REPOSITORY_ROOT}/release/autostream-local-executor-policy.json.example" \
  /root/autostream-local-executor-policy.json

sed 's/"component": "host-agent"/"component": "worker"/' \
  /root/autostream-local-executor-artifact-manifest.valid.json \
  > "${PACKAGE_ROOT}/artifact-manifest.json"
rebuild_bundle_archive
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted a self-consistent bundle with invalid artifact metadata' >&2
  exit 1
fi
test ! -e /etc/autostream-local-executor
test ! -e /opt/autostream/local-executor
test ! -e /usr/local/libexec/autostream-local-executor
install -o root -g root -m 0644 \
  /root/autostream-local-executor-artifact-manifest.valid.json \
  "${PACKAGE_ROOT}/artifact-manifest.json"
rebuild_bundle_archive

printf '%s\n' 'canonical archive alias probe' \
  > /root/local-executor-canonical-alias-file
tar -C /root -czf "${ARCHIVE}" \
  "${ARTIFACT_ID}" \
  --transform="s#^local-executor-canonical-alias-file\$#${ARTIFACT_ID}#" \
  local-executor-canonical-alias-file
rm -f -- /root/local-executor-canonical-alias-file
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted an archive with a duplicate canonical path' >&2
  exit 1
fi
test ! -e /etc/autostream-local-executor
test ! -e /opt/autostream/local-executor
test ! -e /usr/local/libexec/autostream-local-executor
rebuild_bundle_archive

chmod 0777 "${PACKAGE_ROOT}"
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted a group/other-writable release root' >&2
  exit 1
fi
chmod 0755 "${PACKAGE_ROOT}"
test ! -e /usr/local/libexec/autostream-local-executor

systemctl_path=/usr/bin/systemctl
if [[ -e ${systemctl_path} ]]; then
  mv -- "${systemctl_path}" "${systemctl_path}.real"
fi
fake_systemctl=$(mktemp)
cat > "${fake_systemctl}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> /tmp/autostream-local-executor-systemctl.log
unit="${*: -1}"
case "${1:-}" in
  daemon-reload)
    if [[ -e /tmp/autostream-local-executor-fail-daemon-reload ]]; then
      exit 94
    fi
    ;;
  is-active)
    if [[ ${unit} == "autostream-local-executor.service" &&
      -e /tmp/autostream-local-executor-final-active-check-fails ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' inactive
      exit 3
    fi
    if [[ -e /tmp/autostream-local-executor-fail-producer-state-query &&
      ${unit} == "autostream-host-agent.service" ]]; then
      exit 97
    fi
    if [[ -e "/tmp/${unit}.active" ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' active
      exit 0
    fi
    [[ " $* " == *" --quiet "* ]] || printf '%s\n' inactive
    exit 3
    ;;
  is-enabled)
    if [[ -e "/tmp/${unit}.enabled" ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' enabled
      exit 0
    fi
    [[ " $* " == *" --quiet "* ]] || printf '%s\n' disabled
    exit 1
    ;;
  enable)
    touch "/tmp/${unit}.enabled"
    [[ " $* " != *" --now "* ]] || touch "/tmp/${unit}.active"
    ;;
  start)
    if [[ ${unit} == "autostream-local-executor.service" ]]; then
      install -d -o root -g root -m 0700 /var/lib/autostream-local-executor
      if [[ -e /tmp/autostream-local-executor-create-ledger-state ||
        -e /tmp/autostream-local-executor-fail-service-start ||
        -e /tmp/autostream-local-executor-fail-final-active-check ]]; then
        install -d -o root -g root -m 0700 \
          /var/lib/autostream-local-executor/port-ledger/jobs/active \
          /var/lib/autostream-local-executor/port-ledger/jobs/applied \
          /var/lib/autostream-local-executor/docker-port/jobs/active
        printf '%s\n' runtime-mutation \
          > /var/lib/autostream-local-executor/port-ledger/jobs/active/job.json
      fi
      if [[ -e /tmp/autostream-local-executor-fail-service-start ]]; then
        exit 93
      fi
      if [[ -e /tmp/autostream-local-executor-fail-final-active-check ]]; then
        touch /tmp/autostream-local-executor-final-active-check-fails
      fi
    fi
    touch "/tmp/${unit}.active"
    ;;
  stop)
    if [[ ${unit} == "autostream-local-executor.service" &&
      -e /tmp/autostream-local-executor-stop-keeps-active ]]; then
      exit 0
    fi
    rm -f -- "/tmp/${unit}.active"
    rm -f -- /tmp/autostream-local-executor-final-active-check-fails
    if [[ ${unit} == "autostream-local-executor.service" &&
      -e /tmp/autostream-local-executor-stop-fails-after-side-effect ]]; then
      exit 98
    fi
    ;;
  disable)
    if [[ ${unit} == "autostream-host-agent.service" &&
      -e /tmp/autostream-local-executor-fail-producer-freeze ]]; then
      exit 96
    fi
    if [[ ${unit} == "autostream-local-executor.socket" &&
      -e /tmp/autostream-local-executor-disable-keeps-active ]]; then
      exit 0
    fi
    rm -f -- "/tmp/${unit}.enabled"
    [[ " $* " != *" --now "* ]] || rm -f -- "/tmp/${unit}.active"
    if [[ ${unit} == "autostream-local-executor.socket" &&
      -e /tmp/autostream-local-executor-disable-fails-after-side-effect ]]; then
      exit 99
    fi
    ;;
  *)
    exit 0
    ;;
esac
EOF
install -m 0755 "${fake_systemctl}" "${systemctl_path}"
rm -f -- "${fake_systemctl}"

tmpfiles_path=/usr/bin/systemd-tmpfiles
if [[ -e ${tmpfiles_path} ]]; then
  mv -- "${tmpfiles_path}" "${tmpfiles_path}.real"
fi
fake_tmpfiles=$(mktemp)
cat > "${fake_tmpfiles}" <<'EOF'
#!/bin/bash
set -euo pipefail
case "${1:-}" in
  --create)
    test -f "${2:-}"
    install -d -o root -g autostream-host-agent -m 0750 /run/autostream-local-executor
    install -d -o root -g root -m 0700 /run/autostream-updater
    ;;
  *)
    printf 'unexpected systemd-tmpfiles invocation: %s\n' "$*" >&2
    exit 92
    ;;
esac
EOF
install -m 0755 "${fake_tmpfiles}" "${tmpfiles_path}"
rm -f -- "${fake_tmpfiles}"

find_path=/usr/bin/find
if [[ -e ${find_path} ]]; then
  mv -- "${find_path}" "${find_path}.real"
fi
fake_find=$(mktemp)
cat > "${fake_find}" <<'EOF'
#!/bin/bash
set -euo pipefail
if [[ -e /tmp/autostream-local-executor-fail-state-delete && " $* " == *" -delete "* ]]; then
  exit 95
fi
exec /usr/bin/find.real "$@"
EOF
install -m 0755 "${fake_find}" "${find_path}"
rm -f -- "${fake_find}"

touch /tmp/autostream-host-agent.service.active
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted an active Host Agent before Local Executor activation' >&2
  exit 1
fi
rm -f -- /tmp/autostream-host-agent.service.active
test ! -e /etc/autostream-local-executor
test ! -e /opt/autostream/local-executor
test ! -e /usr/local/libexec/autostream-local-executor

install -d -o root -g root -m 0755 /var/lib
ln -s /root /var/lib/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted an unsafe late state path' >&2
  exit 1
fi
rm -f -- /var/lib/autostream-local-executor
if [[ -e /etc/autostream-local-executor ||
  -e /opt/autostream/local-executor ||
  -e /usr/local/libexec/autostream-local-executor ]]; then
  printf '%s\n' 'unsafe late state path left fresh Local Executor directories' >&2
  exit 1
fi

install -d -o root -g root -m 0755 /usr/local/libexec
ln -s /bin/true /usr/local/libexec/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted an arbitrary executor binary symlink' >&2
  exit 1
fi
rm -f -- /usr/local/libexec/autostream-local-executor

install -d -o root -g root -m 0755 \
  /opt/autostream/host-agent/slots/a/bin
install -o root -g root -m 0755 /bin/true \
  /opt/autostream/host-agent/slots/a/bin/autostream-local-executor
ln -s slots/a /opt/autostream/host-agent/current
ln -s /opt/autostream/host-agent/current/bin/autostream-local-executor \
  /usr/local/libexec/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted a cross-release managed A/B executor binary' >&2
  exit 1
fi
rm -f -- \
  /usr/local/libexec/autostream-local-executor \
  /opt/autostream/host-agent/current \
  /opt/autostream/host-agent/slots/a/bin/autostream-local-executor

install -o root -g root -m 0755 \
  "${PACKAGE_ROOT}/bin/autostream-local-executor" \
  /opt/autostream/host-agent/slots/a/bin/autostream-local-executor
chmod 0777 /opt/autostream/host-agent/slots/a/bin
ln -s slots/a /opt/autostream/host-agent/current
ln -s /opt/autostream/host-agent/current/bin/autostream-local-executor \
  /usr/local/libexec/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted a writable managed A/B parent directory' >&2
  exit 1
fi
rm -f -- \
  /usr/local/libexec/autostream-local-executor \
  /opt/autostream/host-agent/current \
  /opt/autostream/host-agent/slots/a/bin/autostream-local-executor
chmod 0755 /opt/autostream/host-agent/slots/a/bin
rmdir -- \
  /opt/autostream/host-agent/slots/a/bin \
  /opt/autostream/host-agent/slots/a \
  /opt/autostream/host-agent/slots \
  /opt/autostream/host-agent

touch /tmp/autostream-local-executor-wrong-id
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer accepted a mismatched Host Agent UID' >&2
  exit 1
fi
rm -f -- /tmp/autostream-local-executor-wrong-id
test ! -e /etc/autostream-local-executor/policy.json
test ! -e /usr/local/libexec/autostream-local-executor
test ! -e /etc/systemd/system/autostream-local-executor.service
test ! -e /etc/systemd/system/autostream-local-executor.socket

touch /tmp/autostream-local-executor-fail-service-start
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer survived an injected post-commit service start failure' >&2
  exit 1
fi
rm -f -- /tmp/autostream-local-executor-fail-service-start
test ! -e /etc/autostream-local-executor/policy.json
test ! -e /usr/local/libexec/autostream-local-executor
test ! -e /etc/systemd/system/autostream-local-executor.service
test ! -e /etc/systemd/system/autostream-local-executor.socket
test ! -e /etc/tmpfiles.d/autostream-local-executor.conf
test ! -e /run/autostream-local-executor
test "$(stat -c '%U:%G:%a' /run/autostream-updater)" = "root:root:700"
test "$(stat -c '%U:%G:%a:%h' \
  /run/autostream-updater/.autostream-runtime-host-setup.lock)" = "root:root:600:1"
if [[ -e /var/lib/autostream-local-executor ]]; then
  printf '%s\n' 'post-start failure left fresh Local Executor state' >&2
  exit 1
fi
test ! -e /etc/autostream-local-executor
test ! -e /opt/autostream/local-executor

install -d -o root -g root -m 0700 /var/lib/autostream-local-executor
printf '%s\n' preserved > /var/lib/autostream-local-executor/sentinel
chmod 0600 /var/lib/autostream-local-executor/sentinel
existing_executor_state_identity=$(stat -c '%d:%i:%u:%g:%a' \
  /var/lib/autostream-local-executor)
existing_executor_state_sha=$(sha256sum \
  /var/lib/autostream-local-executor/sentinel | awk 'NR == 1 { print $1 }')
touch /tmp/autostream-local-executor-fail-final-active-check
if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json; then
  printf '%s\n' 'installer survived a post-start active-state failure' >&2
  exit 1
fi
rm -f -- /tmp/autostream-local-executor-fail-final-active-check
test ! -e /var/lib/autostream-local-executor/port-ledger
if [[ $(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-local-executor) != \
    "${existing_executor_state_identity}" ||
  $(sha256sum /var/lib/autostream-local-executor/sentinel | awk 'NR == 1 { print $1 }') != \
    "${existing_executor_state_sha}" ]]; then
  printf '%s\n' 'post-start failure changed existing Local Executor state' >&2
  exit 1
fi
rm -f -- /var/lib/autostream-local-executor/sentinel
rmdir -- /var/lib/autostream-local-executor

"${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json

test "$(stat -c '%U:%G:%a' /etc/autostream-local-executor/policy.json)" = "root:root:600"
test "$(stat -c '%U:%G:%a' /usr/local/libexec/autostream-local-executor)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /etc/systemd/system/autostream-local-executor.service)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /etc/systemd/system/autostream-local-executor.socket)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /etc/tmpfiles.d/autostream-local-executor.conf)" = "root:root:644"
test "$(stat -c '%U:%G:%a' /run/autostream-local-executor)" = "root:autostream-host-agent:750"
test "$(stat -c '%U:%G:%a' /var/lib/autostream-local-executor)" = "root:root:700"
for private_dir in \
  /opt/autostream/local-executor \
  /opt/autostream/local-executor/ports \
  /opt/autostream/local-executor/docker \
  /opt/autostream/local-executor/docker/ports; do
  test "$(stat -c '%U:%G:%a' "${private_dir}")" = "root:root:700"
done
test -e /tmp/autostream-local-executor.socket.enabled
test -e /tmp/autostream-local-executor.socket.active
test -e /tmp/autostream-local-executor.service.active
grep -Eq '^validate-policy --policy /etc/autostream-local-executor/\.policy\.json\.new\.' "${BINARY_LOG}"
grep -qx -- 'enable --now autostream-local-executor.socket' "${SYSTEMCTL_LOG}"
grep -qx -- 'start autostream-local-executor.service' "${SYSTEMCTL_LOG}"

managed_install_sha=$(
  sha256sum \
    /etc/autostream-local-executor/policy.json \
    /usr/local/libexec/autostream-local-executor \
    /etc/systemd/system/autostream-local-executor.service \
    /etc/systemd/system/autostream-local-executor.socket \
    /etc/tmpfiles.d/autostream-local-executor.conf
)
for quiesce_failure_marker in \
  autostream-local-executor-stop-keeps-active \
  autostream-local-executor-stop-fails-after-side-effect \
  autostream-local-executor-disable-keeps-active \
  autostream-local-executor-disable-fails-after-side-effect; do
  touch "/tmp/${quiesce_failure_marker}"
  if "${PACKAGE_ROOT}/install/install-autostream-local-executor" \
    --policy /root/autostream-local-executor-policy.json; then
    printf 'installer survived injected quiesce failure %s\n' \
      "${quiesce_failure_marker}" >&2
    exit 1
  fi
  rm -f -- "/tmp/${quiesce_failure_marker}"
  if [[ $(
      sha256sum \
        /etc/autostream-local-executor/policy.json \
        /usr/local/libexec/autostream-local-executor \
        /etc/systemd/system/autostream-local-executor.service \
        /etc/systemd/system/autostream-local-executor.socket \
        /etc/tmpfiles.d/autostream-local-executor.conf
    ) != "${managed_install_sha}" ]]; then
    printf '%s\n' 'quiesce failure replaced Local Executor managed files' >&2
    exit 1
  fi
  test -e /tmp/autostream-local-executor.socket.enabled
  test -e /tmp/autostream-local-executor.socket.active
  test -e /tmp/autostream-local-executor.service.active
done

touch /tmp/autostream-local-executor-fail-daemon-reload
if "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor"; then
  printf '%s\n' 'uninstaller survived an injected post-quarantine daemon-reload failure' >&2
  exit 1
fi
rm -f -- /tmp/autostream-local-executor-fail-daemon-reload
test -e /etc/autostream-local-executor/policy.json
test -e /usr/local/libexec/autostream-local-executor
test -e /etc/systemd/system/autostream-local-executor.service
test -e /etc/systemd/system/autostream-local-executor.socket
test -e /etc/tmpfiles.d/autostream-local-executor.conf
test -d /run/autostream-local-executor
test -d /var/lib/autostream-local-executor
test -e /tmp/autostream-local-executor.socket.enabled
test -e /tmp/autostream-local-executor.socket.active
test -e /tmp/autostream-local-executor.service.active

"${PACKAGE_ROOT}/install/uninstall-autostream-local-executor"
test -e /etc/autostream-local-executor/policy.json
test ! -e /usr/local/libexec/autostream-local-executor
test ! -e /etc/systemd/system/autostream-local-executor.service
test ! -e /etc/systemd/system/autostream-local-executor.socket
test ! -e /etc/tmpfiles.d/autostream-local-executor.conf
test ! -e /run/autostream-local-executor
test -d /var/lib/autostream-local-executor

"${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json
touch /tmp/autostream-local-executor-fail-producer-state-query
if "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor" --purge; then
  printf '%s\n' 'purge treated an unavailable producer state as inactive' >&2
  exit 1
fi
rm -f -- /tmp/autostream-local-executor-fail-producer-state-query
test -d /var/lib/autostream-local-executor
test -e /etc/autostream-local-executor/policy.json
test -e /usr/local/libexec/autostream-local-executor

touch \
  /tmp/autostream-host-agent.service.enabled \
  /tmp/autostream-host-agent.service.active \
  /tmp/autostream-host-self-update-recovery@a.timer.enabled \
  /tmp/autostream-host-self-update-recovery@a.timer.active \
  /tmp/autostream-host-self-update-recovery@b.timer.enabled \
  /tmp/autostream-host-self-update-recovery@b.timer.active \
  /tmp/autostream-host-self-update-recovery@a.service.enabled \
  /tmp/autostream-host-self-update-recovery@a.service.active \
  /tmp/autostream-host-self-update-recovery@b.service.enabled \
  /tmp/autostream-host-self-update-recovery@b.service.active
touch /tmp/autostream-local-executor-fail-producer-freeze
if "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor" --purge; then
  printf '%s\n' 'purge continued while the Host Agent producer remained active' >&2
  exit 1
fi
rm -f -- /tmp/autostream-local-executor-fail-producer-freeze
test -d /var/lib/autostream-local-executor
test -e /etc/autostream-local-executor/policy.json
test -e /usr/local/libexec/autostream-local-executor
test -e /tmp/autostream-host-agent.service.active

touch /tmp/autostream-local-executor-fail-state-delete
if "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor" --purge; then
  printf '%s\n' 'purge survived an injected quarantined-state deletion failure' >&2
  exit 1
fi
rm -f -- /tmp/autostream-local-executor-fail-state-delete
test -e /etc/autostream-local-executor/policy.json
test -e /usr/local/libexec/autostream-local-executor
test -e /etc/systemd/system/autostream-local-executor.service
test -e /etc/systemd/system/autostream-local-executor.socket
test -e /etc/tmpfiles.d/autostream-local-executor.conf
test ! -e /run/autostream-local-executor
test ! -e /var/lib/autostream-local-executor
test ! -e /tmp/autostream-local-executor.socket.enabled
test ! -e /tmp/autostream-local-executor.socket.active
test ! -e /tmp/autostream-local-executor.service.active
for producer in \
  autostream-host-agent.service \
  autostream-host-self-update-recovery@a.timer \
  autostream-host-self-update-recovery@b.timer \
  autostream-host-self-update-recovery@a.service \
  autostream-host-self-update-recovery@b.service; do
  test ! -e "/tmp/${producer}.active"
done
for producer in \
  autostream-host-agent.service \
  autostream-host-self-update-recovery@a.timer \
  autostream-host-self-update-recovery@b.timer \
  autostream-host-self-update-recovery@a.service \
  autostream-host-self-update-recovery@b.service; do
  test ! -e "/tmp/${producer}.enabled"
done
for timer in \
  autostream-host-self-update-recovery@a.timer \
  autostream-host-self-update-recovery@b.timer; do
  if [[ -e /tmp/"${timer}".active ]]; then
    install -d -o root -g root -m 0700 /var/lib/autostream-local-executor
  fi
done
test ! -e /var/lib/autostream-local-executor
state_quarantine=$(/usr/bin/find.real /var/lib -maxdepth 1 -type d \
  -name '.autostream-local-executor.uninstall.*' -print -quit)
test -n "${state_quarantine}"
mv -T -- "${state_quarantine}" /var/lib/autostream-local-executor

"${PACKAGE_ROOT}/install/uninstall-autostream-local-executor" --purge
test ! -e /etc/autostream-local-executor/policy.json
test ! -e /var/lib/autostream-local-executor
test -d /opt/autostream/local-executor/docker/ports
test "$(id -u autostream-host-agent)" = "${AGENT_UID}"



