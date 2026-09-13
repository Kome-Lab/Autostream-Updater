#!/bin/bash
set -Eeuo pipefail

umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
trap 'smoke_status=$?; printf "Host Agent upgrade smoke failed at line %s (status %s)\n" "${LINENO}" "${smoke_status}" >&2; exit "${smoke_status}"' ERR

[[ $(id -u) -eq 0 ]] || {
  printf '%s\n' 'host agent installer upgrade smoke requires root' >&2
  exit 1
}
[[ $# -eq 2 ]] || {
  printf '%s\n' \
    'usage: run-host-agent-installer-upgrade-smoke.sh REPOSITORY_ROOT RUNTIME_PROCESS_FIXTURE' >&2
  exit 1
}

readonly REPOSITORY_ROOT=$1
readonly RUNTIME_PROCESS_FIXTURE=$2
[[ -f ${RUNTIME_PROCESS_FIXTURE} && ! -L ${RUNTIME_PROCESS_FIXTURE} &&
  -x ${RUNTIME_PROCESS_FIXTURE} ]] || {
  printf '%s\n' 'managed runtime process fixture is missing or unsafe' >&2
  exit 1
}

# Modules share this shell and preserve the original scenario order.
readonly SMOKE_MODULE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/host-agent-upgrade"
source "${SMOKE_MODULE_ROOT}/bundle-and-command-fixture.sh"
source "${SMOKE_MODULE_ROOT}/bundle-and-private-stage-assertions.sh"
source "${SMOKE_MODULE_ROOT}/archive-rejection-cases.sh"
source "${SMOKE_MODULE_ROOT}/wrapper-signal-and-helper-cases.sh"
source "${SMOKE_MODULE_ROOT}/managed-runtime-fixture.sh"
source "${SMOKE_MODULE_ROOT}/service-manager-adapters.sh"
source "${SMOKE_MODULE_ROOT}/recovery-and-guard-assertions.sh"
source "${SMOKE_MODULE_ROOT}/recovery-rejection-and-rollback-cases.sh"
source "${SMOKE_MODULE_ROOT}/independent-guard-and-commit-cases.sh"
