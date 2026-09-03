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
readonly CANONICAL_IDENTITY=/etc/autostream/updater/agent.yaml
readonly BASE_ENV=/etc/autostream/encoder-recorder.env
readonly INSTALLED_BINARY=/usr/local/bin/autostream-host-agent

for command in getfacl setfacl; do
  command -v "${command}" >/dev/null || {
    printf '%s\n' "identity permission smoke requires ${command}" >&2
    exit 1
  }
done

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
install -d -o root -g "${AGENT_GROUP}" -m 0750 /etc/autostream/updater
if runuser -u "${AGENT_USER}" -- test -x /etc/autostream; then
  printf '%s\n' 'private parent unexpectedly allowed traversal before the dedicated ACL' >&2
  exit 1
fi
setfacl --no-mask -m "u:$(id -u "${AGENT_USER}"):--x" /etc/autostream
runuser -u "${AGENT_USER}" -- test -x /etc/autostream
if runuser -u "${AGENT_USER}" -- test -r /etc/autostream ||
  runuser -u "${AGENT_USER}" -- test -w /etc/autostream; then
  printf '%s\n' 'identity traversal granted shared directory listing or write access' >&2
  exit 1
fi

printf '%s\n' \
  'panel_url: https://control.example.com' \
  'node_id: host-agent-permission-smoke' \
  'runtime_token: runtime-token-smoke' \
  'service_name: AutoStream Host Agent' |
  install -o root -g "${AGENT_GROUP}" -m 0640 /dev/stdin "${CANONICAL_IDENTITY}"

printf '%s\n' 'SERVICE_SECRET=isolated-permission-fixture' |
  install -o root -g root -m 0640 /dev/stdin "${BASE_ENV}"

[[ $(stat -c '%U:%G:%a' /etc/autostream) == 'root:root:750' ]]
[[ $(stat -c '%U:%G:%a' /etc/autostream/updater) == 'root:autostream-host-agent:750' ]]
[[ $(stat -c '%U:%G:%a' "${CANONICAL_IDENTITY}") == 'root:autostream-host-agent:640' ]]

runuser -u "${AGENT_USER}" -- \
  "${INSTALLED_BINARY}" \
  validate-config \
  --config "${CANONICAL_IDENTITY}" |
  grep -qx 'host agent identity configuration valid'

if runuser -u "${AGENT_USER}" -- test -r "${BASE_ENV}"; then
  printf '%s\n' 'application environment unexpectedly became readable by the Host Agent user' >&2
  exit 1
fi
if runuser -u "${AGENT_USER}" -- test -w "${CANONICAL_IDENTITY}" ||
  runuser -u nobody -- test -r "${CANONICAL_IDENTITY}"; then
  printf '%s\n' 'identity was writable by the Agent or readable outside its dedicated group' >&2
  exit 1
fi
[[ ! -e /etc/autostream/updater/agent.staged.yaml &&
  ! -L /etc/autostream/updater/agent.staged.yaml ]]
[[ ! -e /etc/autostream/updater/executor-policy.json &&
  ! -L /etc/autostream/updater/executor-policy.json ]]

printf '%s\n' 'Host Agent v2 identity permission boundary smoke passed'
