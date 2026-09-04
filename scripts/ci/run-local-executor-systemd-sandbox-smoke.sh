#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "local-executor-systemd-sandbox-smoke: $*" >&2
  exit 1
}

[[ $(id -u) -eq 0 ]] || die "must run as root"
command -v systemd-run >/dev/null 2>&1 || die "systemd-run is required"
command -v runuser >/dev/null 2>&1 || die "runuser is required"
getent passwd nobody >/dev/null 2>&1 || die "the nobody account is required"

# User= and Group= are deliberately absent.  On systemd 255, explicitly
# setting User=root can remove CAP_SETUID from the effective set of this
# sandboxed root unit.  The source template is separately checked to retain
# the same inheritance contract.
readonly smoke_command="$(cat <<'EOF'
set -euo pipefail
/usr/bin/grep -E '^(CapEff|CapPrm|CapBnd|NoNewPrivs):' /proc/self/status >&2 || true
# This is the actual capability test: runuser must complete its setgid/setuid
# transition under the same root sandbox used by the Local Executor.
exec /usr/sbin/runuser -u nobody -- /usr/bin/true
EOF
)"

/usr/bin/bash -n -c "${smoke_command}"

readonly -a sandbox_properties=(
  --property=UMask=0077
  --property=NoNewPrivileges=true
  --property=PrivateTmp=true
  --property=PrivateDevices=true
  --property=ProtectSystem=strict
  --property=ProtectHome=true
  --property=ProtectHostname=true
  --property=ProtectClock=true
  --property=ProtectKernelLogs=true
  --property=ProtectKernelTunables=true
  --property=ProtectKernelModules=true
  --property=ProtectControlGroups=true
  --property=RestrictSUIDSGID=true
  --property=RestrictRealtime=true
  --property=RestrictNamespaces=true
  --property=LockPersonality=true
  --property=MemoryDenyWriteExecute=true
  --property=SystemCallArchitectures=native
  --property=AmbientCapabilities=
  --property='RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'
  --property=SocketBindDeny=any
)
readonly root_capabilities='CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SETUID CAP_SETGID'

systemd-run --quiet --wait --pipe --collect --expand-environment=no \
  --unit="autostream-local-executor-capability-smoke-$$" \
  "${sandbox_properties[@]}" --property="${root_capabilities}" \
  /usr/bin/bash -c "${smoke_command}"

# Exercise the same nested tmpfs/bind layout against an isolated fixture root.
# No installed /etc/autostream file, service account, or unit is mutated.
readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly executor_unit="${repository_root}/systemd/autostream-local-executor.service.example"
readonly agent_unit="${repository_root}/systemd/autostream-updater-agent.service.example"
for unit in "${executor_unit}" "${agent_unit}"; do
  grep -Fxq -- 'TemporaryFileSystem=/etc/autostream:ro,mode=0755' "${unit}" || \
    die "unit does not mask the shared application-secret parent"
  if grep -Fxq -- 'InaccessiblePaths=/etc/autostream' "${unit}"; then
    die "unit blocks the canonical Updater child directory"
  fi
done
grep -Fxq -- 'BindPaths=/etc/autostream/updater' "${executor_unit}"
grep -Fxq -- 'ReadWritePaths=/etc/autostream/updater' "${executor_unit}"
grep -Fxq -- 'ReadOnlyPaths=/etc/autostream-local-executor' "${executor_unit}"
grep -Fxq -- 'BindReadOnlyPaths=/etc/autostream/updater' "${agent_unit}"
grep -Fxq -- 'InaccessiblePaths=-/etc/autostream-local-executor' "${agent_unit}"

readonly namespace_root="$(mktemp -d /run/autostream-identity-namespace.XXXXXXXX)"
readonly identity_dir="${namespace_root}/shared/updater"
readonly docker_dir="${namespace_root}/docker"
cleanup_namespace_fixture() {
  local status=$?
  trap - EXIT
  [[ ${namespace_root} == /run/autostream-identity-namespace.* &&
    -d ${namespace_root} && ! -L ${namespace_root} &&
    $(readlink -f -- "${namespace_root}") == "${namespace_root}" ]] || \
    die "namespace fixture cleanup target is unsafe"
  rm -f -- "${identity_dir}/agent.yaml" "${identity_dir}/executor-policy.json" \
    "${identity_dir}/agent.staged.yaml" "${identity_dir}/unexpected" \
    "${namespace_root}/shared/service-secret.env" "${docker_dir}/config.json"
  rmdir -- "${identity_dir}" "${namespace_root}/shared" "${docker_dir}" "${namespace_root}"
  return "${status}"
}
trap cleanup_namespace_fixture EXIT
chmod 0755 "${namespace_root}"
install -d -o root -g root -m 0750 "${namespace_root}/shared"
install -d -o root -g "$(id -gn nobody)" -m 0750 "${identity_dir}"
install -d -o root -g root -m 0700 "${docker_dir}"
install -o root -g "$(id -gn nobody)" -m 0640 /dev/null "${identity_dir}/agent.yaml"
install -o root -g root -m 0600 /dev/null "${identity_dir}/executor-policy.json"
install -o root -g root -m 0640 /dev/null "${namespace_root}/shared/service-secret.env"
install -o root -g root -m 0600 /dev/null "${docker_dir}/config.json"

readonly agent_namespace_command="$(cat <<'EOF'
set -euo pipefail
identity_dir=$1
shared_dir=$2
docker_dir=$3
cat "${identity_dir}/agent.yaml" >/dev/null
test ! -e "${shared_dir}/service-secret.env"
if cat "${identity_dir}/executor-policy.json" >/dev/null 2>&1 ||
  cat "${docker_dir}/config.json" >/dev/null 2>&1 ||
  { printf 'unexpected\n' > "${identity_dir}/unexpected"; } 2>/dev/null; then
  exit 1
fi
EOF
)"
systemd-run --quiet --wait --pipe --collect --expand-environment=no \
  --unit="autostream-agent-identity-namespace-smoke-$$" \
  "${sandbox_properties[@]}" --property=CapabilityBoundingSet= \
  --property=User=nobody --property="Group=$(id -gn nobody)" \
  --property=ProtectProc=invisible --property=ProcSubset=pid \
  --property="TemporaryFileSystem=${namespace_root}/shared:ro,mode=0755" \
  --property="BindReadOnlyPaths=${identity_dir}" \
  --property="InaccessiblePaths=${docker_dir}" \
  /usr/bin/bash -c "${agent_namespace_command}" -- \
    "${identity_dir}" "${namespace_root}/shared" "${docker_dir}"

readonly executor_namespace_command="$(cat <<'EOF'
set -euo pipefail
identity_dir=$1
shared_dir=$2
docker_dir=$3
cat "${identity_dir}/agent.yaml" "${identity_dir}/executor-policy.json" >/dev/null
cat "${docker_dir}/config.json" >/dev/null
test ! -e "${shared_dir}/service-secret.env"
printf '# staged identity fixture\n' > "${identity_dir}/agent.staged.yaml"
test -s "${identity_dir}/agent.staged.yaml"
if { printf 'unexpected\n' >> "${docker_dir}/config.json"; } 2>/dev/null; then
  exit 1
fi
/usr/sbin/runuser -u nobody -- test -r "${identity_dir}/agent.yaml"
EOF
)"
systemd-run --quiet --wait --pipe --collect --expand-environment=no \
  --unit="autostream-executor-identity-namespace-smoke-$$" \
  "${sandbox_properties[@]}" --property="${root_capabilities}" \
  --property="TemporaryFileSystem=${namespace_root}/shared:ro,mode=0755" \
  --property="BindPaths=${identity_dir}" \
  --property="ReadWritePaths=${identity_dir}" \
  --property="ReadOnlyPaths=${docker_dir}" \
  /usr/bin/bash -c "${executor_namespace_command}" -- \
    "${identity_dir}" "${namespace_root}/shared" "${docker_dir}"


