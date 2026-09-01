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
/usr/bin/grep -E '^(CapEff|CapPrm|CapBnd|NoNewPrivs):' "/proc/$$/status" >&2 || true
# This is the actual capability test: runuser must complete its setgid/setuid
# transition under the same root sandbox used by the Local Executor.
exec /usr/sbin/runuser -u nobody -- /usr/bin/true
EOF
)"

/usr/bin/bash -n -c "${smoke_command}"

systemd-run \
  --quiet \
  --wait \
  --pipe \
  --collect \
  --unit="autostream-local-executor-capability-smoke-$$" \
  --property=UMask=0077 \
  --property=NoNewPrivileges=true \
  --property=PrivateTmp=true \
  --property=PrivateDevices=true \
  --property=ProtectSystem=strict \
  --property=ProtectHome=true \
  --property=ProtectHostname=true \
  --property=ProtectClock=true \
  --property=ProtectKernelLogs=true \
  --property=ProtectKernelTunables=true \
  --property=ProtectKernelModules=true \
  --property=ProtectControlGroups=true \
  --property=RestrictSUIDSGID=true \
  --property=RestrictRealtime=true \
  --property=RestrictNamespaces=true \
  --property=LockPersonality=true \
  --property=MemoryDenyWriteExecute=true \
  --property=SystemCallArchitectures=native \
  --property='CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SETUID CAP_SETGID' \
  --property=AmbientCapabilities= \
  --property='RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX' \
  --property=SocketBindDeny=any \
  /usr/bin/bash -c "${smoke_command}"



