readonly VERSION=v9.9.9
readonly BUILD_COMMIT=0123456789abcdef0123456789abcdef01234567
readonly BUILD_DATE=2026-07-31T00:00:00Z
readonly ARTIFACT_ID="autostream-host-agent_${VERSION}_linux_amd64"
readonly PACKAGE_ROOT="/root/${ARTIFACT_ID}"
readonly ARCHIVE="/root/${ARTIFACT_ID}.tar.gz"
readonly SYSTEMCTL_LOG=/tmp/autostream-host-agent-systemctl.log
readonly BINARY_LOG=/tmp/autostream-host-agent-binary.log
readonly LOCAL_EXECUTOR_BINARY_LOG=/tmp/autostream-local-executor-prepare-binary.log

[[ -f ${AUTOSTREAM_REAL_HOST_AGENT_BINARY} &&
  ! -L ${AUTOSTREAM_REAL_HOST_AGENT_BINARY} ]] || {
  printf '%s\n' 'real Host Agent smoke binary must be a regular non-symlink file' >&2
  exit 1
}

rm -rf -- "${PACKAGE_ROOT}"
rm -f -- "${ARCHIVE}"
mkdir -p "${PACKAGE_ROOT}/bin" "${PACKAGE_ROOT}/install" "${PACKAGE_ROOT}/systemd"
install -m 0755 \
  "${REPOSITORY_ROOT}/release/install-autostream-host-agent" \
  "${PACKAGE_ROOT}/install/install-autostream-host-agent"
install -m 0755 \
  "${REPOSITORY_ROOT}/release/uninstall-autostream-host-agent" \
  "${PACKAGE_ROOT}/install/uninstall-autostream-host-agent"
install -m 0755 \
  "${REPOSITORY_ROOT}/release/install-autostream-local-executor" \
  "${PACKAGE_ROOT}/install/install-autostream-local-executor"
install -m 0755 \
  "${REPOSITORY_ROOT}/release/uninstall-autostream-local-executor" \
  "${PACKAGE_ROOT}/install/uninstall-autostream-local-executor"
install -m 0644 \
  "${REPOSITORY_ROOT}/release/autostream-local-executor-policy.json.example" \
  "${PACKAGE_ROOT}/autostream-local-executor-policy.json.example"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-host-agent.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-host-agent.service"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.service"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.socket.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.socket"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-local-executor.tmpfiles.example" \
  "${PACKAGE_ROOT}/systemd/autostream-local-executor.tmpfiles"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.service.example" \
  "${PACKAGE_ROOT}/systemd/autostream-host-self-update-recovery@.service"
install -m 0644 \
  "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.timer.example" \
  "${PACKAGE_ROOT}/systemd/autostream-host-self-update-recovery@.timer"

fake_binary=$(mktemp)
cat > "${fake_binary}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> /tmp/autostream-host-agent-binary.log
case "${1:-}" in
  --version)
    printf '%s\n' \
      'autostream-host-agent v9.9.9' \
      'commit: 0123456789abcdef0123456789abcdef01234567' \
      'build_date: 2026-07-31T00:00:00Z'
    ;;
  validate-config)
    "${AUTOSTREAM_REAL_HOST_AGENT_BINARY:?}" "$@"
    ;;
  *)
    printf 'unexpected Host Agent invocation: %s\n' "$*" >&2
    exit 91
    ;;
esac
EOF
install -m 0755 "${fake_binary}" "${PACKAGE_ROOT}/bin/autostream-host-agent"
rm -f -- "${fake_binary}"

fake_local_executor=$(mktemp)
cat > "${fake_local_executor}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> /tmp/autostream-local-executor-prepare-binary.log
case "${1:-}" in
  --version)
    printf '%s\n' \
      'autostream-local-executor v9.9.9' \
      'commit: 0123456789abcdef0123456789abcdef01234567' \
      'build_date: 2026-07-31T00:00:00Z' \
      'mutation_protocol: 2' \
      'recovery_protocol: 2'
    ;;
  validate-policy)
    test -f "${3:-}"
    printf '%s\n' \
      'local executor policy valid' \
      'host_id: host-smoke' \
      "agent_uid: $(id -u autostream-host-agent)" \
      "agent_gid: $(getent group autostream-host-agent | awk -F: 'NR == 1 { print $3 }')" \
      'policy_revision: 1' \
      'policy_sha256: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ;;
  *)
    printf 'unexpected local executor invocation: %s\n' "$*" >&2
    exit 93
    ;;
esac
EOF
install -m 0755 "${fake_local_executor}" "${PACKAGE_ROOT}/bin/autostream-local-executor"
rm -f -- "${fake_local_executor}"

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
  /root/autostream-host-agent-artifact-manifest.valid.json

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

managed_runtime_fingerprint() {
  {
    for link_path in \
      /usr/local/bin/autostream-host-agent \
      /usr/local/libexec/autostream-local-executor \
      /opt/autostream/host-agent/current; do
      stat -c '%F:%d:%i:%u:%g:%a' -- "${link_path}"
      readlink -- "${link_path}"
    done
    for binary_path in \
      /opt/autostream/host-agent/slots/a/bin/autostream-host-agent \
      /opt/autostream/host-agent/slots/a/bin/autostream-local-executor; do
      stat -c '%F:%d:%i:%s:%Y:%f:%u:%g:%a' -- "${binary_path}"
      sha256sum -- "${binary_path}"
    done
  } | sha256sum | awk 'NR == 1 { print $1 }'
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

systemctl_path=/usr/bin/systemctl
if [[ -e ${systemctl_path} || -L ${systemctl_path} ]]; then
  if [[ -e ${systemctl_path}.real || -L ${systemctl_path}.real ]]; then
    printf '%s\n' 'could not preserve the pre-existing systemctl command for the smoke fixture' >&2
    exit 1
  fi
  mv -- "${systemctl_path}" "${systemctl_path}.real"
fi
early_systemctl=$(mktemp)
cat > "${early_systemctl}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf 'unexpected early systemctl invocation: %s\n' "$*" >&2
exit 98
EOF
install -m 0755 "${early_systemctl}" "${systemctl_path}"
rm -f -- "${early_systemctl}"

sed 's/"component": "host-agent"/"component": "worker"/' \
  /root/autostream-host-agent-artifact-manifest.valid.json \
  > "${PACKAGE_ROOT}/artifact-manifest.json"
rebuild_bundle_archive
if invalid_manifest_output="$(
  "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare 2>&1
)"; then
  printf '%s\n' 'prepare mode accepted a self-consistent bundle with invalid artifact metadata' >&2
  exit 1
fi
if [[ ${invalid_manifest_output} != \
    *'artifact-manifest.json does not authorize this exact Host Agent bundle'* ]]; then
  printf '%s\n%s\n' \
    'invalid artifact metadata did not fail at its authorization boundary; captured output:' \
    "${invalid_manifest_output}" >&2
  exit 1
fi
if [[ ${invalid_manifest_output} == *'required command is unavailable'* ]]; then
  printf '%s\n%s\n' \
    'invalid artifact metadata failed because a required command was unavailable; captured output:' \
    "${invalid_manifest_output}" >&2
  exit 1
fi
test ! -e /etc/autostream/updater
test ! -e /var/lib/autostream-host-agent
test ! -e /opt/autostream/host-agent
test ! -e /usr/local/bin/autostream-host-agent
if id autostream-host-agent >/dev/null 2>&1 ||
  getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'invalid artifact metadata mutated the Host Agent account' >&2
  exit 1
fi
install -o root -g root -m 0644 \
  /root/autostream-host-agent-artifact-manifest.valid.json \
  "${PACKAGE_ROOT}/artifact-manifest.json"
rebuild_bundle_archive

printf '%s\n' 'canonical archive alias probe' \
  > /root/host-agent-canonical-alias-file
tar -C /root -czf "${ARCHIVE}" \
  "${ARTIFACT_ID}" \
  --transform="s#^host-agent-canonical-alias-file\$#${ARTIFACT_ID}#" \
  host-agent-canonical-alias-file
rm -f -- /root/host-agent-canonical-alias-file
if duplicate_path_output="$(
  "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare 2>&1
)"; then
  printf '%s\n' 'prepare mode accepted an archive with a duplicate canonical path' >&2
  exit 1
fi
if [[ ${duplicate_path_output} != *'bundle archive contains duplicate paths'* ]]; then
  printf '%s\n%s\n' \
    'duplicate canonical path did not fail at its archive boundary; captured output:' \
    "${duplicate_path_output}" >&2
  exit 1
fi
if [[ ${duplicate_path_output} == *'required command is unavailable'* ]]; then
  printf '%s\n%s\n' \
    'duplicate canonical path failed because a required command was unavailable; captured output:' \
    "${duplicate_path_output}" >&2
  exit 1
fi
test ! -e /etc/autostream/updater
test ! -e /var/lib/autostream-host-agent
test ! -e /opt/autostream/host-agent
test ! -e /usr/local/bin/autostream-host-agent
if id autostream-host-agent >/dev/null 2>&1 ||
  getent group autostream-host-agent >/dev/null 2>&1; then
  printf '%s\n' 'duplicate archive path mutated the Host Agent account' >&2
  exit 1
fi
rebuild_bundle_archive

chmod 0777 "${PACKAGE_ROOT}"
if writable_release_output="$(
  "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare 2>&1
)"; then
  printf '%s\n' 'prepare mode accepted a group/other-writable release root' >&2
  exit 1
fi
if [[ ${writable_release_output} != \
    *'release source parents must not be writable by group or other'* ]]; then
  printf '%s\n%s\n' \
    'writable release root did not fail at its parent-chain boundary; captured output:' \
    "${writable_release_output}" >&2
  exit 1
fi
if [[ ${writable_release_output} == *'required command is unavailable'* ]]; then
  printf '%s\n%s\n' \
    'writable release root failed because a required command was unavailable; captured output:' \
    "${writable_release_output}" >&2
  exit 1
fi
chmod 0755 "${PACKAGE_ROOT}"
test ! -e /usr/local/bin/autostream-host-agent
test ! -e /usr/local/libexec/autostream-local-executor
