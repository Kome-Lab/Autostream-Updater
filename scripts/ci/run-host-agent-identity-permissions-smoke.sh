#!/bin/bash
set -euo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

[[ $(id -u) -eq 0 ]] || {
  printf '%s\n' 'Host Agent identity permission smoke requires root' >&2
  exit 1
}
[[ $# -eq 1 ]] || {
  printf '%s\n' 'usage: run-host-agent-identity-permissions-smoke.sh HOST_AGENT_BINARY' >&2
  exit 1
}

readonly HOST_AGENT_BINARY=$1
readonly AGENT_USER=autostream-host-agent
readonly AGENT_GROUP=autostream-host-agent
readonly CANONICAL_IDENTITY=/etc/autostream-host-agent/identity.json
readonly LEGACY_IDENTITY=/etc/autostream/host-agent.json
readonly BASE_ENV=/etc/autostream/encoder-recorder.env
readonly INSTALLED_BINARY=/usr/local/bin/autostream-host-agent
readonly PERMISSION_ERROR=/tmp/autostream-host-agent-legacy-stat.err
readonly CONFIGURE_STDOUT=/tmp/autostream-host-agent-configure.out
readonly CONFIGURE_STDERR=/tmp/autostream-host-agent-configure.err

[[ -f ${HOST_AGENT_BINARY} && ! -L ${HOST_AGENT_BINARY} ]] || {
  printf '%s\n' 'Host Agent smoke binary must be a regular non-symlink file' >&2
  exit 1
}

groupadd --system "${AGENT_GROUP}"
useradd \
  --system \
  --gid "${AGENT_GROUP}" \
  --home-dir /var/lib/autostream-host-agent \
  --shell /usr/sbin/nologin \
  "${AGENT_USER}"

install -o root -g root -m 0755 "${HOST_AGENT_BINARY}" "${INSTALLED_BINARY}"
install -d -o root -g root -m 0750 /etc/autostream
install -d -o root -g "${AGENT_GROUP}" -m 0750 /etc/autostream-host-agent

printf '%s\n' \
  '{' \
  '  "panel_url": "https://control.example.com",' \
  '  "node_id": "host-agent-permission-smoke",' \
  '  "runtime_token": "runtime-token-smoke",' \
  '  "service_name": "AutoStream Host Agent"' \
  '}' |
  install -o root -g "${AGENT_GROUP}" -m 0640 /dev/stdin "${CANONICAL_IDENTITY}"

printf '%s\n' 'AUTOSTREAM_BIND_ADDR=127.0.0.1:51378' |
  install -o root -g root -m 0640 /dev/stdin "${BASE_ENV}"

[[ $(stat -c '%U:%G:%a' /etc/autostream) == 'root:root:750' ]]
[[ $(stat -c '%U:%G:%a' /etc/autostream-host-agent) == 'root:autostream-host-agent:750' ]]
[[ $(stat -c '%U:%G:%a' "${CANONICAL_IDENTITY}") == 'root:autostream-host-agent:640' ]]
[[ ! -e ${LEGACY_IDENTITY} && ! -L ${LEGACY_IDENTITY} ]]

if runuser -u "${AGENT_USER}" -- stat -- "${LEGACY_IDENTITY}" \
  >/dev/null 2>"${PERMISSION_ERROR}"; then
  printf '%s\n' 'legacy path unexpectedly became visible to the Host Agent user' >&2
  exit 1
fi
grep -q 'Permission denied' "${PERMISSION_ERROR}"

runuser -u "${AGENT_USER}" -- \
  "${INSTALLED_BINARY}" \
  validate-config \
  --config "${CANONICAL_IDENTITY}" |
  grep -qx 'host agent identity configuration valid'

if runuser -u "${AGENT_USER}" -- test -r /etc/autostream; then
  printf '%s\n' '/etc/autostream unexpectedly became readable by the Host Agent user' >&2
  exit 1
fi
if runuser -u "${AGENT_USER}" -- test -r "${BASE_ENV}"; then
  printf '%s\n' 'application environment unexpectedly became readable by the Host Agent user' >&2
  exit 1
fi

readonly CANONICAL_SHA256=$(sha256sum "${CANONICAL_IDENTITY}" | awk 'NR == 1 { print $1 }')
printf '%s\n' \
  '{' \
  '  "panel_url": "https://legacy.example.com",' \
  '  "node_id": "legacy-host-agent",' \
  '  "runtime_token": "legacy-runtime-token",' \
  '  "service_name": "Legacy Host Agent"' \
  '}' |
  install -o root -g root -m 0640 /dev/stdin "${LEGACY_IDENTITY}"

if "${INSTALLED_BINARY}" \
  configure \
  --panel-url https://control.example.com \
  --node host-agent-permission-smoke \
  --config "${CANONICAL_IDENTITY}" \
  </dev/null >"${CONFIGURE_STDOUT}" 2>"${CONFIGURE_STDERR}"; then
  printf '%s\n' 'configure accepted simultaneous canonical and legacy identities' >&2
  exit 1
fi
grep -q 'legacy Host Agent identity already exists' "${CONFIGURE_STDERR}"
if grep -q 'Configure Token' "${CONFIGURE_STDOUT}" "${CONFIGURE_STDERR}"; then
  printf '%s\n' 'configure consumed or requested a token before rejecting the legacy identity' >&2
  exit 1
fi
[[ $(sha256sum "${CANONICAL_IDENTITY}" | awk 'NR == 1 { print $1 }') == "${CANONICAL_SHA256}" ]]
[[ ! -e /etc/autostream-host-agent/identity.staged.json &&
  ! -L /etc/autostream-host-agent/identity.staged.json ]]
[[ ! -e /etc/autostream-local-executor/policy.json &&
  ! -L /etc/autostream-local-executor/policy.json ]]

printf '%s\n' 'Host Agent canonical identity permission boundary smoke passed'



