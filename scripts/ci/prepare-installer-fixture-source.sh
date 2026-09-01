#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf '%s\n' 'usage: prepare-installer-fixture-source.sh REPOSITORY_ROOT OUTPUT_DIRECTORY' >&2
  exit 2
fi
readonly REPOSITORY_ROOT=$1
readonly OUTPUT_DIRECTORY=$2
[[ -d ${REPOSITORY_ROOT}/install && -d ${REPOSITORY_ROOT}/systemd ]] || {
  printf '%s\n' 'updater release source is incomplete' >&2
  exit 1
}
[[ ! -e ${OUTPUT_DIRECTORY} ]] || {
  printf 'fixture output already exists: %s\n' "${OUTPUT_DIRECTORY}" >&2
  exit 1
}
mkdir -p -- "${OUTPUT_DIRECTORY}/release" "${OUTPUT_DIRECTORY}/systemd"
install -m 0755 "${REPOSITORY_ROOT}/install/install-autostream-updater-agent" \
  "${OUTPUT_DIRECTORY}/release/install-autostream-host-agent"
install -m 0755 "${REPOSITORY_ROOT}/install/uninstall-autostream-updater-agent" \
  "${OUTPUT_DIRECTORY}/release/uninstall-autostream-host-agent"
install -m 0755 "${REPOSITORY_ROOT}/install/install-autostream-local-executor" \
  "${OUTPUT_DIRECTORY}/release/install-autostream-local-executor"
install -m 0755 "${REPOSITORY_ROOT}/install/uninstall-autostream-local-executor" \
  "${OUTPUT_DIRECTORY}/release/uninstall-autostream-local-executor"
install -m 0644 "${REPOSITORY_ROOT}/install/autostream-updater-agent.json.example" \
  "${OUTPUT_DIRECTORY}/release/autostream-host-agent.json.example"
install -m 0644 "${REPOSITORY_ROOT}/install/autostream-local-executor-policy.json.example" \
  "${OUTPUT_DIRECTORY}/release/autostream-local-executor-policy.json.example"
install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-updater-agent.service.example" \
  "${OUTPUT_DIRECTORY}/systemd/autostream-host-agent.service.example"
install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-local-executor.service.example" \
  "${OUTPUT_DIRECTORY}/systemd/autostream-local-executor.service.example"
install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-local-executor.socket.example" \
  "${OUTPUT_DIRECTORY}/systemd/autostream-local-executor.socket.example"
install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-local-executor.tmpfiles.example" \
  "${OUTPUT_DIRECTORY}/systemd/autostream-local-executor.tmpfiles.example"
install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.service.example" \
  "${OUTPUT_DIRECTORY}/systemd/autostream-host-self-update-recovery@.service.example"
install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.timer.example" \
  "${OUTPUT_DIRECTORY}/systemd/autostream-host-self-update-recovery@.timer.example"
