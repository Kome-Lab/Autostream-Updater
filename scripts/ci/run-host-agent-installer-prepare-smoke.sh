#!/bin/bash
set -euo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

[[ $(id -u) -eq 0 ]] || {
  printf '%s\n' 'host agent installer prepare smoke requires root' >&2
  exit 1
}
[[ $# -eq 2 ]] || {
  printf '%s\n' \
    'usage: run-host-agent-installer-prepare-smoke.sh REPOSITORY_ROOT REAL_HOST_AGENT_BINARY' >&2
  exit 1
}

readonly REPOSITORY_ROOT=$1
export AUTOSTREAM_REAL_HOST_AGENT_BINARY=$2
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
test ! -e /etc/autostream-host-agent
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
test ! -e /etc/autostream-host-agent
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

rm -f -- "${systemctl_path}"
fake_systemctl=$(mktemp)
cat > "${fake_systemctl}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> /tmp/autostream-host-agent-systemctl.log
unit=${!#}
case "${1:-}" in
  daemon-reload)
    if [[ -e /tmp/autostream-host-agent-fail-daemon-reload ]]; then
      exit 94
    fi
    ;;
  is-active)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      marker=/tmp/"${unit}".active
    elif [[ ${unit} == autostream-host-agent.service ]]; then
      marker=/tmp/autostream-host-agent-active
    else
      marker=/tmp/"${unit}".active
    fi
    if [[ ${unit} == autostream-host-agent.service &&
      -e /tmp/autostream-host-agent-is-active-query-error ]]; then
      exit 99
    fi
    if [[ ${unit} == autostream-host-agent.service &&
      -e /tmp/autostream-host-agent-final-active-check-fails ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' inactive
      exit 3
    fi
    if [[ -e ${marker} ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' active
      exit 0
    fi
    # A real systemd host can report an unloaded unit as stdout "inactive"
    # with exit status 4. Keep that exact pair in the root smoke fixture.
    [[ " $* " == *" --quiet "* ]] || printf '%s\n' inactive
    exit 4
    ;;
  is-enabled)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      marker=/tmp/"${unit}".enabled
    elif [[ ${unit} == autostream-host-agent.service ]]; then
      marker=/tmp/autostream-host-agent-enabled
    else
      marker=/tmp/"${unit}".enabled
    fi
    if [[ -e ${marker} ]]; then
      [[ " $* " == *" --quiet "* ]] || printf '%s\n' enabled
      exit 0
    fi
    [[ " $* " == *" --quiet "* ]] || printf '%s\n' disabled
    exit 1
    ;;
  enable)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      touch /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || touch /tmp/"${unit}".active
      if [[ -e /tmp/autostream-host-agent-fail-timer-enable-after-side-effect ]]; then
        recovery_service=${unit/.timer/.service}
        touch /tmp/"${recovery_service}".active
        install -d -o root -g root -m 0755 \
          /opt/autostream/host-agent/slots/b/recovery-extra
        printf '%s\n' recovery-side-effect \
          > /opt/autostream/host-agent/slots/b/recovery-extra/ledger
        if [[ ${unit} == autostream-host-self-update-recovery@b.timer ]]; then
          exit 96
        fi
      fi
      exit 0
    fi
    if [[ ${unit} == autostream-host-agent.service ]]; then
      [[ -e /tmp/autostream-host-agent-allow-enable ]] || {
        printf 'prepare mode attempted forbidden service mutation: %s\n' "$*" >&2
        exit 92
      }
      touch /tmp/autostream-host-agent-enabled
      [[ " $* " != *" --now "* ]] || touch /tmp/autostream-host-agent-active
      if [[ -e /tmp/autostream-host-agent-fail-final-active-check ]]; then
        install -d -o autostream-host-agent -g autostream-host-agent -m 0700 \
          /var/lib/autostream-host-agent/runtime-created
        printf '%s\n' mutated \
          > /var/lib/autostream-host-agent/runtime-created/ledger
        touch /tmp/autostream-host-agent-final-active-check-fails
      fi
    else
      touch /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || touch /tmp/"${unit}".active
    fi
    ;;
  start)
    if [[ ${unit} == autostream-host-agent.service ]]; then
      [[ -e /tmp/autostream-host-agent-allow-enable ]] || {
        printf 'prepare mode attempted forbidden service mutation: %s\n' "$*" >&2
        exit 92
      }
      touch /tmp/autostream-host-agent-active
    else
      if [[ ${unit} == autostream-local-executor.service ]]; then
        install -d -o root -g root -m 0700 /var/lib/autostream-local-executor
      fi
      touch /tmp/"${unit}".active
    fi
    ;;
  stop)
    if [[ ${unit} == autostream-host-agent.service ]]; then
      if [[ ! -e /tmp/autostream-host-agent-stop-keeps-active ]]; then
        rm -f -- /tmp/autostream-host-agent-active
      fi
      rm -f -- /tmp/autostream-host-agent-final-active-check-fails
    else
      rm -f -- /tmp/"${unit}".active
    fi
    ;;
  disable)
    if [[ ${unit} == autostream-host-self-update-recovery@?.timer ]]; then
      rm -f -- /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || rm -f -- /tmp/"${unit}".active
      if [[ -e /tmp/autostream-host-agent-reactivate-recovery-after-timer-disable ]]; then
        recovery_service=${unit/.timer/.service}
        touch /tmp/"${recovery_service}".active
      fi
    elif [[ ${unit} == autostream-host-agent.service ]]; then
      rm -f -- /tmp/autostream-host-agent-enabled
      [[ " $* " != *" --now "* ]] || rm -f -- /tmp/autostream-host-agent-active
    else
      rm -f -- /tmp/"${unit}".enabled
      [[ " $* " != *" --now "* ]] || rm -f -- /tmp/"${unit}".active
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
[[ ${1:-} == "--create" ]] || {
  printf 'unexpected systemd-tmpfiles invocation: %s\n' "$*" >&2
  exit 95
}
if [[ ${2:-} == "/etc/tmpfiles.d/autostream-local-executor.conf" ]]; then
  install -d -o root -g autostream-host-agent -m 0750 /run/autostream-local-executor
  install -d -o root -g root -m 0700 /run/autostream-updater
fi
EOF
install -m 0755 "${fake_tmpfiles}" "${tmpfiles_path}"
rm -f -- "${fake_tmpfiles}"

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
if [[ -e /etc/autostream-host-agent ||
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
install -d -o root -g autostream-host-agent -m 0750 /etc/autostream-host-agent
install -d -o autostream-host-agent -g autostream-host-agent -m 0700 \
  /var/lib/autostream-host-agent
printf '%s\n' preserved > /var/lib/autostream-host-agent/sentinel
chown autostream-host-agent:autostream-host-agent \
  /var/lib/autostream-host-agent/sentinel
chmod 0600 /var/lib/autostream-host-agent/sentinel
existing_state_identity=$(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-host-agent)
existing_state_sha=$(sha256sum /var/lib/autostream-host-agent/sentinel | awk 'NR == 1 { print $1 }')
ln -s /root /etc/systemd/system/autostream-local-executor.service
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode survived failure with existing Host Agent state' >&2
  exit 1
fi
rm -f -- /etc/systemd/system/autostream-local-executor.service
if [[ $(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-host-agent) != \
    "${existing_state_identity}" ||
  $(sha256sum /var/lib/autostream-host-agent/sentinel | awk 'NR == 1 { print $1 }') != \
    "${existing_state_sha}" ]]; then
  printf '%s\n' 'failed prepare changed the existing Host Agent state directory' >&2
  exit 1
fi
rm -f -- /var/lib/autostream-host-agent/sentinel
rmdir -- /var/lib/autostream-host-agent /etc/autostream-host-agent
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
  [[ -e /etc/autostream-host-agent || -e /var/lib/autostream-host-agent ]]; then
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
test ! -e /etc/autostream-host-agent
test ! -e /var/lib/autostream-host-agent
test ! -e /etc/autostream/host-agent.json
test ! -e /etc/autostream-local-executor/policy.json
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

ln -s /root /etc/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a symlink policy directory' >&2
  exit 1
fi
rm -f -- /etc/autostream-local-executor

install -o root -g root -m 0600 /dev/null /etc/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a non-directory policy path' >&2
  exit 1
fi
rm -f -- /etc/autostream-local-executor

install -d -o root -g root -m 0755 /etc/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted an over-permissive policy directory' >&2
  exit 1
fi
rmdir -- /etc/autostream-local-executor

install -d -o root -g root -m 0700 /etc/autostream-local-executor
chown 1:1 /etc/autostream-local-executor
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted a non-root-owned policy directory' >&2
  exit 1
fi
chown root:root /etc/autostream-local-executor
rmdir -- /etc/autostream-local-executor

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
  /etc/autostream-local-executor \
  /opt/autostream/local-executor \
  /opt/autostream/local-executor/ports
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode survived failure with existing private directories' >&2
  exit 1
fi
for private_dir in \
  /etc/autostream-local-executor \
  /opt/autostream/local-executor \
  /opt/autostream/local-executor/ports; do
  test "$(stat -c '%U:%G:%a' "${private_dir}")" = "root:root:700"
done
rm -f -- /tmp/autostream-host-agent-fail-daemon-reload
rmdir -- /opt/autostream/local-executor/ports
rmdir -- /opt/autostream/local-executor
rmdir -- /etc/autostream-local-executor

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

test "$(stat -c '%U:%G:%a' /etc/autostream-host-agent)" = "root:autostream-host-agent:750"
test ! -e /etc/autostream-host-agent/identity.json
test ! -e /etc/autostream/host-agent.json
test ! -e /etc/autostream-local-executor/policy.json
test "$(stat -c '%U:%G:%a' /etc/autostream-local-executor)" = "root:root:700"
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
grep -qx -- 'ConditionPathExists=|/etc/autostream-host-agent/identity.json' \
  /etc/systemd/system/autostream-host-agent.service
grep -qx -- 'ConditionPathExists=|/etc/autostream/host-agent.json' \
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
test ! -e /etc/autostream-local-executor/policy.json
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
test ! -e /etc/autostream-local-executor/policy.json
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
test ! -e /etc/autostream-local-executor/policy.json
"${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json
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
test "$(stat -c '%U:%G:%a' /etc/autostream-local-executor/policy.json)" = \
  "root:root:600"
test -e /tmp/autostream-local-executor.socket.enabled
test -e /tmp/autostream-local-executor.socket.active
test -e /tmp/autostream-local-executor.service.active
: > "${SYSTEMCTL_LOG}"

binary_sha=$(sha256sum /usr/local/bin/autostream-host-agent | awk '{print $1}')
install -o root -g autostream-host-agent -m 0640 \
  "${REPOSITORY_ROOT}/release/autostream-host-agent.json.example" \
  /etc/autostream-host-agent/identity.json
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted an existing current identity' >&2
  exit 1
fi
test "$(sha256sum /usr/local/bin/autostream-host-agent | awk '{print $1}')" = "${binary_sha}"
rm -f -- /etc/autostream-host-agent/identity.json

touch /tmp/autostream-host-agent-enabled
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare; then
  printf '%s\n' 'prepare mode accepted an enabled Host Agent service' >&2
  exit 1
fi
rm -f -- /tmp/autostream-host-agent-enabled
test ! -e /etc/autostream-host-agent/identity.json

if grep -Eq '^(enable|start)( |$).*(autostream-host-agent\.service|autostream-local-executor\.(service|socket))' "${SYSTEMCTL_LOG}"; then
  printf '%s\n' 'a failed prepare path enabled or started a runtime unit' >&2
  exit 1
fi

touch /tmp/autostream-host-agent-allow-enable
install -o root -g root -m 0600 \
  "${REPOSITORY_ROOT}/release/autostream-host-agent.json.example" \
  /root/autostream-host-agent.json

managed_runtime_before=$(managed_runtime_fingerprint)
touch \
  /tmp/autostream-host-agent-active \
  /tmp/autostream-host-agent-is-active-query-error
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" \
  --config /root/autostream-host-agent.json; then
  printf '%s\n' 'configured install accepted an indeterminate Host Agent active state' >&2
  exit 1
fi
rm -f -- \
  /tmp/autostream-host-agent-is-active-query-error \
  /tmp/autostream-host-agent-active
test ! -e /etc/autostream-host-agent/identity.json
if [[ $(managed_runtime_fingerprint) != "${managed_runtime_before}" ]]; then
  printf '%s\n' 'failed configured install changed the pre-existing managed A/B runtime' >&2
  exit 1
fi

chmod 0777 /opt/autostream/host-agent/slots/a/bin
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" \
  --config /root/autostream-host-agent.json; then
  printf '%s\n' 'configured install accepted a writable managed A/B parent directory' >&2
  exit 1
fi
chmod 0755 /opt/autostream/host-agent/slots/a/bin
test ! -e /etc/autostream-host-agent/identity.json

printf '%s\n' durable > /var/lib/autostream-host-agent/sentinel
chown autostream-host-agent:autostream-host-agent \
  /var/lib/autostream-host-agent/sentinel
chmod 0600 /var/lib/autostream-host-agent/sentinel
host_state_identity=$(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-host-agent)
host_state_sha=$(sha256sum /var/lib/autostream-host-agent/sentinel | awk 'NR == 1 { print $1 }')
touch \
  /tmp/autostream-host-agent-active \
  /tmp/autostream-host-agent-stop-keeps-active
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" \
  --config /root/autostream-host-agent.json; then
  printf '%s\n' 'configured install accepted a stop command that left the Host Agent active' >&2
  exit 1
fi
rm -f -- \
  /tmp/autostream-host-agent-stop-keeps-active \
  /tmp/autostream-host-agent-active
test ! -e /etc/autostream-host-agent/identity.json
if [[ $(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-host-agent) != \
    "${host_state_identity}" ||
  $(sha256sum /var/lib/autostream-host-agent/sentinel | awk 'NR == 1 { print $1 }') != \
    "${host_state_sha}" ]]; then
  printf '%s\n' 'failed Host Agent quiesce changed existing state' >&2
  exit 1
fi

touch /tmp/autostream-host-agent-fail-final-active-check
if "${PACKAGE_ROOT}/install/install-autostream-host-agent" \
  --config /root/autostream-host-agent.json; then
  printf '%s\n' 'configured install survived a post-start active-state failure' >&2
  exit 1
fi
rm -f -- /tmp/autostream-host-agent-fail-final-active-check
test ! -e /etc/autostream-host-agent/identity.json
test ! -e /var/lib/autostream-host-agent/runtime-created
test ! -e /tmp/autostream-host-agent-active
test ! -e /tmp/autostream-host-agent-enabled
if [[ $(stat -c '%d:%i:%u:%g:%a' /var/lib/autostream-host-agent) != \
    "${host_state_identity}" ||
  $(sha256sum /var/lib/autostream-host-agent/sentinel | awk 'NR == 1 { print $1 }') != \
    "${host_state_sha}" ]]; then
  printf '%s\n' 'post-start failure changed existing Host Agent state' >&2
  exit 1
fi

dd if=/dev/zero of=/etc/autostream/host-agent.json \
  bs=65537 count=1 status=none
chown root:autostream-host-agent /etc/autostream/host-agent.json
chmod 0640 /etc/autostream/host-agent.json
unsafe_legacy_identity=$(stat -c '%d:%i:%s:%Y:%f:%u:%g' \
  /etc/autostream/host-agent.json)
unsafe_legacy_sha=$(sha256sum /etc/autostream/host-agent.json |
  awk 'NR == 1 { print $1 }')
set +e
unsafe_legacy_output="$(${PACKAGE_ROOT}/install/install-autostream-host-agent \
  --config /root/autostream-host-agent.json 2>&1)"
unsafe_legacy_status=$?
set -e
if [[ ${unsafe_legacy_status} -eq 0 ||
  ${unsafe_legacy_output} != *'legacy Host Agent identity has an unsafe size'* ]]; then
  printf '%s\n' 'configured install did not reject an oversized legacy identity before retirement' >&2
  printf '%s\n' "${unsafe_legacy_output}" >&2
  exit 1
fi
test ! -e /etc/autostream-host-agent/identity.json
test -e /etc/autostream/host-agent.json
if [[ $(stat -c '%d:%i:%s:%Y:%f:%u:%g' /etc/autostream/host-agent.json) != \
    "${unsafe_legacy_identity}" ||
  $(sha256sum /etc/autostream/host-agent.json | awk 'NR == 1 { print $1 }') != \
    "${unsafe_legacy_sha}" ||
  $(managed_runtime_fingerprint) != "${managed_runtime_before}" ||
  -e /tmp/autostream-host-agent-active ||
  -e /tmp/autostream-host-agent-enabled ]]; then
  printf '%s\n' 'pre-retirement legacy validation failure was not rolled back exactly' >&2
  exit 1
fi
rm -f -- /etc/autostream/host-agent.json

install -o root -g autostream-host-agent -m 0640 \
  "${REPOSITORY_ROOT}/release/autostream-host-agent.json.example" \
  /etc/autostream/host-agent.json
"${PACKAGE_ROOT}/install/install-autostream-host-agent" \
  --config /root/autostream-host-agent.json
test "$(stat -c '%U:%G:%a' /etc/autostream-host-agent)" = "root:autostream-host-agent:750"
test "$(stat -c '%U:%G:%a' /etc/autostream-host-agent/identity.json)" = "root:autostream-host-agent:640"
test ! -e /etc/autostream/host-agent.json
test -e /tmp/autostream-host-agent-enabled
test -e /tmp/autostream-host-agent-active
grep -Eq '^validate-config --config /etc/autostream-host-agent/\.identity\.json\.new\.' "${BINARY_LOG}"
grep -qx -- 'validate-config --config /etc/autostream-host-agent/identity.json' "${BINARY_LOG}"
grep -Eq '^enable --now autostream-host-agent\.service$' "${SYSTEMCTL_LOG}"

"${PACKAGE_ROOT}/install/uninstall-autostream-host-agent"
test ! -e /usr/local/bin/autostream-host-agent
test ! -e /etc/systemd/system/autostream-host-agent.service
test -e /etc/autostream-host-agent/identity.json
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

install -o root -g autostream-host-agent -m 0640 \
  /etc/autostream-host-agent/identity.json \
  /etc/autostream-host-agent/.identity.staged.wipe
"${PACKAGE_ROOT}/install/uninstall-autostream-host-agent" --purge
test ! -e /etc/autostream-host-agent/.identity.staged.wipe
test ! -e /etc/autostream-host-agent
test ! -e /etc/autostream/host-agent.json
test ! -e /var/lib/autostream-host-agent
if id autostream-host-agent >/dev/null 2>&1 || getent group autostream-host-agent >/dev/null; then
  printf '%s\n' 'Host Agent purge preserved its dedicated account or group' >&2
  exit 1
fi

"${PACKAGE_ROOT}/install/install-autostream-host-agent" --prepare
"${PACKAGE_ROOT}/install/install-autostream-host-agent" \
  --config /root/autostream-host-agent.json
systemctl disable --now autostream-host-agent.service
test ! -e /tmp/autostream-host-agent-active
test ! -e /tmp/autostream-host-agent-enabled
"${PACKAGE_ROOT}/install/install-autostream-local-executor" \
  --policy /root/autostream-local-executor-policy.json
"${PACKAGE_ROOT}/install/uninstall-autostream-local-executor" --purge
install -o root -g autostream-host-agent -m 0640 /dev/null \
  /etc/autostream-host-agent/.identity.staged.wipe
test "$(stat -c '%s:%U:%G:%a' \
  /etc/autostream-host-agent/.identity.staged.wipe)" = \
  "0:root:autostream-host-agent:640"
"${PACKAGE_ROOT}/install/uninstall-autostream-host-agent" --purge
test ! -e /etc/autostream-host-agent/.identity.staged.wipe
test ! -e /etc/autostream-host-agent
test ! -e /var/lib/autostream-host-agent
if id autostream-host-agent >/dev/null 2>&1 || getent group autostream-host-agent >/dev/null; then
  printf '%s\n' 'second Host Agent purge preserved its dedicated account or group' >&2
  exit 1
fi


