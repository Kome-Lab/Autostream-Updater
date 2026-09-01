#!/bin/bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf '%s\n' 'usage: verify-release-bundles.sh ARTIFACT_DIRECTORY VERSION COMMIT' >&2
  exit 2
fi
readonly ARTIFACT_DIRECTORY=$1
readonly VERSION=$2
readonly COMMIT=$3
[[ ${VERSION} =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && ${COMMIT} =~ ^[0-9a-f]{40}$ ]] || {
  printf '%s\n' 'invalid release verification identity' >&2
  exit 1
}
[[ -d ${ARTIFACT_DIRECTORY} ]] || {
  printf 'artifact directory is missing: %s\n' "${ARTIFACT_DIRECTORY}" >&2
  exit 1
}

work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT
for arch in amd64 arm64; do
  printf '%s\n' "autostream-host-agent_${VERSION}_linux_${arch}.tar.gz"
  printf '%s\n' "autostream-host-agent_${VERSION}_linux_${arch}.tar.gz.sha256"
done > "${work}/expected-files"
printf '%s\n' host-agent-manifest.json host-agent-manifest.json.sha256 SHA256SUMS \
  >> "${work}/expected-files"
LC_ALL=C sort -o "${work}/expected-files" "${work}/expected-files"
find "${ARTIFACT_DIRECTORY}" -mindepth 1 -maxdepth 1 -printf '%f\n' |
  LC_ALL=C sort > "${work}/actual-files"
diff -u "${work}/expected-files" "${work}/actual-files"

printf '%s\n' \
  "autostream-host-agent_${VERSION}_linux_amd64.tar.gz" \
  "autostream-host-agent_${VERSION}_linux_amd64.tar.gz.sha256" \
  "autostream-host-agent_${VERSION}_linux_arm64.tar.gz" \
  "autostream-host-agent_${VERSION}_linux_arm64.tar.gz.sha256" \
  host-agent-manifest.json \
  host-agent-manifest.json.sha256 \
  | LC_ALL=C sort > "${work}/expected-sum-subjects"
sed -E 's/^[0-9a-f]{64}  //' "${ARTIFACT_DIRECTORY}/SHA256SUMS" |
  LC_ALL=C sort > "${work}/actual-sum-subjects"
diff -u "${work}/expected-sum-subjects" "${work}/actual-sum-subjects"
[[ $(wc -l < "${ARTIFACT_DIRECTORY}/host-agent-manifest.json.sha256") -eq 1 ]]
grep -Eq \
  '^[0-9a-f]{64}  host-agent-manifest\.json$' \
  "${ARTIFACT_DIRECTORY}/host-agent-manifest.json.sha256"
for arch in amd64 arm64; do
  checksum="${ARTIFACT_DIRECTORY}/autostream-host-agent_${VERSION}_linux_${arch}.tar.gz.sha256"
  [[ $(wc -l < "${checksum}") -eq 1 ]]
  grep -Eq \
    "^[0-9a-f]{64}  autostream-host-agent_${VERSION}_linux_${arch}\\.tar\\.gz$" \
    "${checksum}"
done

(
  cd -- "${ARTIFACT_DIRECTORY}"
  sha256sum -c SHA256SUMS
  sha256sum -c host-agent-manifest.json.sha256
  for arch in amd64 arm64; do
    sha256sum -c "autostream-host-agent_${VERSION}_linux_${arch}.tar.gz.sha256"
  done
)

jq -e --arg version "${VERSION}" --arg commit "${COMMIT}" '
  .schema_version == 1 and
  .release_id == $version and
  .channel == "host-agent" and
  .commit == $commit and
  .agent_version == $version and
  .protocol_version == 2 and
  .observe_only == false and
  .local_executor_protocol_version == 2 and
  .local_executor_mutation_protocol_version == 2 and
  .local_executor_mutation_enabled == true and
  .local_executor_mutation_requires_root_policy == true and
  .recovery_protocol_version == 2 and
  .minimum_panel_version == $version and
  (.artifacts | length) == 2 and
  ([.artifacts[].arch] | sort) == ["amd64", "arm64"] and
  all(.artifacts[];
    .os == "linux" and
    (.name == ("autostream-host-agent_" + $version + "_linux_" + .arch + ".tar.gz")) and
    (.size | type == "number" and . > 0) and
    (.sha256 | test("^[0-9a-f]{64}$"))
  )
' "${ARTIFACT_DIRECTORY}/host-agent-manifest.json" >/dev/null

for arch in amd64 arm64; do
  artifact="autostream-host-agent_${VERSION}_linux_${arch}"
  archive="${artifact}.tar.gz"
  extract="${work}/extract-${arch}"
  mkdir -p -- "${extract}"
  tar -tzf "${ARTIFACT_DIRECTORY}/${archive}" > "${work}/tar-list-${arch}"
  [[ -s ${work}/tar-list-${arch} ]] || {
    printf 'archive is empty: %s\n' "${archive}" >&2
    exit 1
  }
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "${work}/tar-list-${arch}"; then
    printf 'archive contains an unsafe path: %s\n' "${archive}" >&2
    exit 1
  fi
  tar --extract --gzip --file "${ARTIFACT_DIRECTORY}/${archive}" \
    --directory "${extract}" --no-same-owner
  [[ -d ${extract}/${artifact} ]] || {
    printf 'archive root is missing: %s\n' "${artifact}" >&2
    exit 1
  }
  if find "${extract}" -type l -print -quit | grep -q .; then
    printf 'archive contains a symbolic link: %s\n' "${archive}" >&2
    exit 1
  fi
  find "${extract}" -mindepth 1 -maxdepth 1 -printf '%f\n' > "${work}/top-${arch}"
  [[ $(wc -l < "${work}/top-${arch}") -eq 1 ]] &&
    grep -Fxq "${artifact}" "${work}/top-${arch}"

  root="${extract}/${artifact}"
  (
    cd -- "${root}"
    sha256sum -c checksums.txt
  )
  sed -E 's/^[0-9a-f]{64}  //' "${root}/checksums.txt" |
    LC_ALL=C sort > "${work}/listed-inner-${arch}"
  (
    cd -- "${root}"
    find . -type f ! -name checksums.txt -print | LC_ALL=C sort
  ) > "${work}/actual-inner-${arch}"
  diff -u "${work}/listed-inner-${arch}" "${work}/actual-inner-${arch}"

  jq -e \
    --arg version "${VERSION}" \
    --arg commit "${COMMIT}" \
    --arg arch "${arch}" \
    --arg archive "${archive}" \
    --arg root "${artifact}" '
      .schema_version == 1 and
      .component == "host-agent" and
      .source_version == $version and
      .commit == $commit and
      .platform == {os: "linux", arch: $arch} and
      .archive == {name: $archive, root: $root} and
      .compatibility.minimum_panel_version == $version and
      .compatibility.rollback_compatible == true and
      .compatibility.database_schema == "none"
    ' "${root}/artifact-manifest.json" >/dev/null
  archive_sha=$(sha256sum "${ARTIFACT_DIRECTORY}/${archive}" | awk '{print $1}')
  archive_size=$(stat -c %s "${ARTIFACT_DIRECTORY}/${archive}")
  jq -e \
    --arg arch "${arch}" \
    --arg name "${archive}" \
    --arg sha "${archive_sha}" \
    --argjson size "${archive_size}" '
      any(.artifacts[];
        .os == "linux" and .arch == $arch and .name == $name and
        .sha256 == $sha and .size == $size
      )
    ' "${ARTIFACT_DIRECTORY}/host-agent-manifest.json" >/dev/null
  [[ $(stat -c %a "${root}/bin/autostream-host-agent") == 755 ]]
  [[ $(stat -c %a "${root}/bin/autostream-local-executor") == 755 ]]
  [[ $(stat -c %a "${root}/install/install-autostream-host-agent") == 755 ]]
  [[ $(stat -c %a "${root}/install/uninstall-autostream-host-agent") == 755 ]]
  [[ $(stat -c %a "${root}/install/install-autostream-local-executor") == 755 ]]
  [[ $(stat -c %a "${root}/install/uninstall-autostream-local-executor") == 755 ]]
done
