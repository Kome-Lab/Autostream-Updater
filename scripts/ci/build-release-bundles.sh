#!/bin/bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  printf '%s\n' 'usage: build-release-bundles.sh VERSION COMMIT BUILD_DATE OUTPUT_DIRECTORY' >&2
  exit 2
fi

readonly VERSION=$1
readonly COMMIT=$2
readonly BUILD_DATE=$3
readonly OUTPUT_DIRECTORY=$4
readonly REPOSITORY_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

[[ ${VERSION} =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'release version must be a stable vX.Y.Z tag: %s\n' "${VERSION}" >&2
  exit 1
}
[[ ${COMMIT} =~ ^[0-9a-f]{40}$ ]] || {
  printf 'release commit must be a full lowercase SHA-1: %s\n' "${COMMIT}" >&2
  exit 1
}
[[ ${BUILD_DATE} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
  printf 'build date must be canonical UTC RFC3339: %s\n' "${BUILD_DATE}" >&2
  exit 1
}
[[ ! -e ${OUTPUT_DIRECTORY} ]] || {
  printf 'release output already exists: %s\n' "${OUTPUT_DIRECTORY}" >&2
  exit 1
}

staging=$(mktemp -d)
trap 'rm -rf -- "${staging}"' EXIT
mkdir -p -- "${OUTPUT_DIRECTORY}"
readonly LDFLAGS="-s -w -X github.com/Kome-Lab/Autostream-Updater/internal/version.Version=${VERSION} -X github.com/Kome-Lab/Autostream-Updater/internal/version.Commit=${COMMIT} -X github.com/Kome-Lab/Autostream-Updater/internal/version.BuildDate=${BUILD_DATE}"

for arch in amd64 arm64; do
  artifact="autostream-host-agent_${VERSION}_linux_${arch}"
  root="${staging}/${artifact}"
  mkdir -p -- "${root}/bin" "${root}/install" "${root}/systemd"

  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go -C "${REPOSITORY_ROOT}" build -p 1 -trimpath -ldflags="${LDFLAGS}" \
      -o "${root}/bin/autostream-host-agent" \
      ./cmd/autostream-updater-agent
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go -C "${REPOSITORY_ROOT}" build -p 1 -trimpath -ldflags="${LDFLAGS}" \
      -o "${root}/bin/autostream-local-executor" \
      ./cmd/autostream-local-executor

  install -m 0755 "${REPOSITORY_ROOT}/install/install-autostream-updater-agent" \
    "${root}/install/install-autostream-host-agent"
  install -m 0755 "${REPOSITORY_ROOT}/install/uninstall-autostream-updater-agent" \
    "${root}/install/uninstall-autostream-host-agent"
  install -m 0755 "${REPOSITORY_ROOT}/install/install-autostream-local-executor" \
    "${root}/install/install-autostream-local-executor"
  install -m 0755 "${REPOSITORY_ROOT}/install/uninstall-autostream-local-executor" \
    "${root}/install/uninstall-autostream-local-executor"
  install -m 0644 "${REPOSITORY_ROOT}/install/agent.yaml.example" \
    "${root}/agent.yaml.example"
  install -m 0644 "${REPOSITORY_ROOT}/install/autostream-local-executor-policy.json.example" \
    "${root}/autostream-local-executor-policy.json.example"
  install -m 0644 "${REPOSITORY_ROOT}/docs/runtime.md" "${root}/README.md"
  install -m 0644 "${REPOSITORY_ROOT}/docs/local-executor.md" "${root}/README.local-executor.md"
  install -m 0644 "${REPOSITORY_ROOT}/docs/contracts-boundary.md" "${root}/CONTRACTS-BOUNDARY.md"
  install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-updater-agent.service.example" \
    "${root}/systemd/autostream-host-agent.service"
  install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-local-executor.service.example" \
    "${root}/systemd/autostream-local-executor.service"
  install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-local-executor.socket.example" \
    "${root}/systemd/autostream-local-executor.socket"
  install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-local-executor.tmpfiles.example" \
    "${root}/systemd/autostream-local-executor.tmpfiles"
  install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.service.example" \
    "${root}/systemd/autostream-host-self-update-recovery@.service"
  install -m 0644 "${REPOSITORY_ROOT}/systemd/autostream-host-self-update-recovery@.timer.example" \
    "${root}/systemd/autostream-host-self-update-recovery@.timer"

  jq -n \
    --arg version "${VERSION}" \
    --arg commit "${COMMIT}" \
    --arg build_date "${BUILD_DATE}" \
    --arg arch "${arch}" \
    --arg archive_name "${artifact}.tar.gz" \
    --arg artifact_root "${artifact}" \
    '{
      schema_version: 1,
      component: "host-agent",
      source_version: $version,
      commit: $commit,
      build_date: $build_date,
      platform: {os: "linux", arch: $arch},
      archive: {name: $archive_name, root: $artifact_root},
      compatibility: {
        minimum_agent_version: null,
        minimum_panel_version: $version,
        rollback_compatible: true,
        database_schema: "none"
      }
    }' > "${root}/artifact-manifest.json"
  (
    cd -- "${root}"
    find . -type f ! -name checksums.txt -print0 |
      LC_ALL=C sort -z |
      xargs -0 sha256sum > checksums.txt
  )
  tar \
    --sort=name \
    --mtime="${BUILD_DATE}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "${staging}" \
    -czf "${OUTPUT_DIRECTORY}/${artifact}.tar.gz" \
    "${artifact}"
  (
    cd -- "${OUTPUT_DIRECTORY}"
    sha256sum "${artifact}.tar.gz" > "${artifact}.tar.gz.sha256"
  )
done

amd64_archive="autostream-host-agent_${VERSION}_linux_amd64.tar.gz"
arm64_archive="autostream-host-agent_${VERSION}_linux_arm64.tar.gz"
amd64_sha=$(awk 'NR == 1 {print $1}' "${OUTPUT_DIRECTORY}/${amd64_archive}.sha256")
arm64_sha=$(awk 'NR == 1 {print $1}' "${OUTPUT_DIRECTORY}/${arm64_archive}.sha256")
amd64_size=$(stat -c %s "${OUTPUT_DIRECTORY}/${amd64_archive}")
arm64_size=$(stat -c %s "${OUTPUT_DIRECTORY}/${arm64_archive}")
jq -n \
  --arg version "${VERSION}" \
  --arg commit "${COMMIT}" \
  --arg published_at "${BUILD_DATE}" \
  --arg amd64_name "${amd64_archive}" \
  --arg amd64_sha "${amd64_sha}" \
  --argjson amd64_size "${amd64_size}" \
  --arg arm64_name "${arm64_archive}" \
  --arg arm64_sha "${arm64_sha}" \
  --argjson arm64_size "${arm64_size}" \
  '{
    schema_version: 1,
    release_id: $version,
    channel: "host-agent",
    published_at: $published_at,
    commit: $commit,
    agent_version: $version,
    protocol_version: 2,
    observe_only: false,
    local_executor_protocol_version: 2,
    local_executor_probe_only: false,
    local_executor_protocol_min_version: 1,
    local_executor_protocol_max_version: 2,
    local_executor_probe_compatible: true,
    local_executor_mutation_protocol_version: 2,
    local_executor_mutation_enabled: true,
    local_executor_mutation_requires_root_policy: true,
    recovery_protocol_version: 2,
    minimum_panel_version: $version,
    artifacts: [
      {os: "linux", arch: "amd64", name: $amd64_name, size: $amd64_size, sha256: $amd64_sha},
      {os: "linux", arch: "arm64", name: $arm64_name, size: $arm64_size, sha256: $arm64_sha}
    ]
  }' > "${OUTPUT_DIRECTORY}/host-agent-manifest.json"
(
  cd -- "${OUTPUT_DIRECTORY}"
  sha256sum host-agent-manifest.json > host-agent-manifest.json.sha256
  sha256sum -- \
    "${amd64_archive}" "${amd64_archive}.sha256" \
    "${arm64_archive}" "${arm64_archive}.sha256" \
    host-agent-manifest.json host-agent-manifest.json.sha256 \
    > SHA256SUMS
)
