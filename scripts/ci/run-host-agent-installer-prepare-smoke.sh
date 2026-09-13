#!/bin/bash
set -Eeuo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
trap 'smoke_status=$?; if [[ $- == *e* ]]; then printf "%s:%s: exit %s\n" "${BASH_SOURCE[0]##*/}" "${LINENO}" "${smoke_status}" >&2; fi' ERR

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

# Modules share this shell and preserve the original scenario order.
readonly SMOKE_MODULE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/host-agent-prepare"
source "${SMOKE_MODULE_ROOT}/bundle-fixture-and-input-rejections.sh"
source "${SMOKE_MODULE_ROOT}/service-manager-adapters.sh"
source "${SMOKE_MODULE_ROOT}/account-and-transaction-rollback-cases.sh"
source "${SMOKE_MODULE_ROOT}/prepare-and-lock-cases.sh"
source "${SMOKE_MODULE_ROOT}/uninstall-and-purge-cases.sh"
