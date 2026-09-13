
validate_root_owned_release_source() {
  local source=$1
  local source_mode
  [[ -f ${source} && ! -L ${source} ]] || die "release asset ${source} is missing or unsafe"
  [[ $(stat -c '%U:%G' -- "${source}") == "root:root" ]] || \
    die "release asset ${source} must be owned by root:root"
  source_mode=$(stat -c '%a' -- "${source}")
  (( (8#${source_mode} & 0022) == 0 )) || \
    die "release asset ${source} must not be writable by group or other"
  validate_root_parent_chain "${source}" "release source"
}

for source in \
  "${RUNNING_INSTALLER_SOURCE}" \
  "${RUNNING_HOST_BINARY_SOURCE}" \
  "${RUNNING_BINARY_SOURCE}" \
  "${RUNNING_SERVICE_SOURCE}" \
  "${RUNNING_SOCKET_SOURCE}" \
  "${RUNNING_TMPFILES_SOURCE}" \
  "${ARCHIVE_SOURCE}"; do
  validate_root_owned_release_source "${source}"
done

ARTIFACT_SOURCE_SIZE="$(stat -c %s -- "${ARCHIVE_SOURCE}")" || \
  die "could not determine the source archive size"
[[ ${ARTIFACT_SOURCE_SIZE} =~ ^[1-9][0-9]*$ ]] || die "source archive size is invalid"
[[ ${ARTIFACT_SOURCE_SIZE} -le ${MAX_ARCHIVE_SIZE} ]] || \
  die "source archive exceeds the ${MAX_ARCHIVE_SIZE}-byte limit"
readonly ARTIFACT_SOURCE_SIZE

BUNDLE_STAGE=""
cleanup_bundle_stage() {
  local status=$?
  trap '' INT TERM
  trap - EXIT
  if [[ -n ${BUNDLE_STAGE:-} &&
    ${BUNDLE_STAGE} == /var/tmp/autostream-local-executor-install.* &&
    -d ${BUNDLE_STAGE} &&
    ! -L ${BUNDLE_STAGE} ]]; then
    rm -rf -- "${BUNDLE_STAGE}"
  fi
  exit "${status}"
}
arm_cleanup_handler cleanup_bundle_stage

defer_cleanup_signals
BUNDLE_STAGE="$(mktemp -d /var/tmp/autostream-local-executor-install.XXXXXXXX)" || \
  die "could not create the private bundle staging directory"
resume_cleanup_signals || die "installation was interrupted while creating the private bundle stage"
[[ -n ${BUNDLE_STAGE} &&
  ${BUNDLE_STAGE} == /var/tmp/autostream-local-executor-install.* &&
  -d ${BUNDLE_STAGE} &&
  ! -L ${BUNDLE_STAGE} ]] || die "private bundle staging directory is invalid"
[[ $(readlink -f -- "${BUNDLE_STAGE}") == "${BUNDLE_STAGE}" &&
  $(stat -c '%U:%G:%a' -- "${BUNDLE_STAGE}") == "root:root:700" ]] || \
  die "private bundle staging directory ownership, mode, or canonical path is invalid"
readonly BUNDLE_STAGE
readonly UNPACK_DIR="${BUNDLE_STAGE}/unpack"

install -d -o root -g root -m 0700 "${UNPACK_DIR}"

copy_stable_bundle_archive() {
  local source_identity
  local source_sha256
  source_identity="$(stat -c '%d:%i:%s:%Y:%f:%u:%g' -- "${ARCHIVE_SOURCE}")"
  source_sha256="$(sha256sum -- "${ARCHIVE_SOURCE}" | awk 'NR == 1 { print $1 }')"
  install -o root -g root -m 0600 "${ARCHIVE_SOURCE}" "${BUNDLE_STAGE}/${ARCHIVE_NAME}"
  validate_root_owned_release_source "${ARCHIVE_SOURCE}"
  [[ $(stat -c '%d:%i:%s:%Y:%f:%u:%g' -- "${ARCHIVE_SOURCE}") == "${source_identity}" ]] || \
    die "bundle archive identity changed while it was copied"
  [[ $(sha256sum -- "${ARCHIVE_SOURCE}" | awk 'NR == 1 { print $1 }') == "${source_sha256}" ]] || \
    die "bundle archive content changed while it was copied"
  [[ $(sha256sum -- "${BUNDLE_STAGE}/${ARCHIVE_NAME}" | awk 'NR == 1 { print $1 }') == "${source_sha256}" ]] || \
    die "staged bundle archive differs from its source"
}

copy_stable_bundle_archive
ARTIFACT_SHA256="$(
  sha256sum -- "${BUNDLE_STAGE}/${ARCHIVE_NAME}" | awk 'NR == 1 { print $1 }'
)" || die "could not calculate the bundle archive digest"
[[ ${ARTIFACT_SHA256} =~ ^[0-9a-f]{64}$ ]] || die "bundle archive digest is invalid"
readonly ARTIFACT_SHA256
ARTIFACT_SIZE="$(stat -c %s -- "${BUNDLE_STAGE}/${ARCHIVE_NAME}")" || \
  die "could not determine the staged archive size"
[[ ${ARTIFACT_SIZE} =~ ^[1-9][0-9]*$ ]] || die "staged archive size is invalid"
[[ ${ARTIFACT_SIZE} -le ${MAX_ARCHIVE_SIZE} ]] || \
  die "staged archive exceeds the ${MAX_ARCHIVE_SIZE}-byte limit"
[[ ${ARTIFACT_SIZE} == "${ARTIFACT_SOURCE_SIZE}" ]] || \
  die "staged bundle archive size differs from its source"
readonly ARTIFACT_SIZE

tar -tzf "${BUNDLE_STAGE}/${ARCHIVE_NAME}" > "${BUNDLE_STAGE}/archive.list"
[[ -s ${BUNDLE_STAGE}/archive.list ]] || die "bundle archive is empty"
while IFS= read -r entry; do
  [[ ${entry} == "${ARTIFACT_ID}" || ${entry} == "${ARTIFACT_ID}/" ||
    ${entry} == "${ARTIFACT_ID}/"* ]] || \
    die "bundle archive contains a path outside ${ARTIFACT_ID}: ${entry}"
  [[ ${entry} != /* &&
    ${entry} != *\\* &&
    ${entry} != ../* &&
    ${entry} != *"/../"* &&
    ${entry} != *"/.." &&
    ${entry} != *"/./"* &&
    ${entry} != *"/." &&
    ${entry} != *"//"* ]] || \
    die "bundle archive contains an unsafe path: ${entry}"
done < "${BUNDLE_STAGE}/archive.list"
duplicate_paths="$(
  awk '{ sub(/\/$/, ""); print }' "${BUNDLE_STAGE}/archive.list" |
    LC_ALL=C sort |
    uniq -d
)"
[[ -z ${duplicate_paths} ]] || die "bundle archive contains duplicate paths"
while IFS= read -r entry; do
  case "${entry:0:1}" in
    -|d) ;;
    *) die "bundle archive contains a non-regular entry" ;;
  esac
done < <(tar -tvzf "${BUNDLE_STAGE}/${ARCHIVE_NAME}")

tar --no-same-owner --no-same-permissions \
  -xzf "${BUNDLE_STAGE}/${ARCHIVE_NAME}" \
  -C "${UNPACK_DIR}"
readonly EXTRACTED_ROOT="${UNPACK_DIR}/${ARTIFACT_ID}"
[[ -d ${EXTRACTED_ROOT} && ! -L ${EXTRACTED_ROOT} ]] || \
  die "bundle archive root is missing or unsafe"
[[ -z $(find "${UNPACK_DIR}" -mindepth 1 -maxdepth 1 ! -name "${ARTIFACT_ID}" -print -quit) ]] || \
  die "bundle archive contains more than one top-level path"
[[ -z $(find "${EXTRACTED_ROOT}" -type l -print -quit) ]] || \
  die "bundle archive must not contain symlinks"
[[ -f ${EXTRACTED_ROOT}/checksums.txt && ! -L ${EXTRACTED_ROOT}/checksums.txt ]] || \
  die "bundle checksums.txt is missing or unsafe"
[[ -f ${EXTRACTED_ROOT}/${ARTIFACT_MANIFEST_NAME} &&
  ! -L ${EXTRACTED_ROOT}/${ARTIFACT_MANIFEST_NAME} ]] || \
  die "bundle ${ARTIFACT_MANIFEST_NAME} is missing or unsafe"

verify_release_checksum_inventory() {
  local root=$1
  local checksum_entry
  local checked_path
  local release_file
  local relative_path
  local -A listed=()
  while IFS= read -r checksum_entry; do
    [[ ${checksum_entry} =~ ^[0-9a-f]{64}\ \ (.+)$ ]] || \
      die "inner checksum entry has an invalid format"
    checked_path="${BASH_REMATCH[1]}"
    [[ ${checked_path} == ./* ]] || die "inner checksum entry must use a ./ relative path"
    checked_path="${checked_path#./}"
    [[ -n ${checked_path} &&
      ${checked_path} != /* &&
      ${checked_path} != ./* &&
      ${checked_path} != *\\* &&
      ${checked_path} != ../* &&
      ${checked_path} != *"/../"* &&
      ${checked_path} != *"/.." &&
      ${checked_path} != *"/./"* &&
      ${checked_path} != *"/." &&
      ${checked_path} != *"//"* &&
      ${checked_path} != "checksums.txt" ]] || die "inner checksum entry has an unsafe path"
    [[ -z ${listed["${checked_path}"]+present} ]] || \
      die "inner checksum entry is duplicated: ${checked_path}"
    listed["${checked_path}"]=1
    [[ -f ${root}/${checked_path} && ! -L ${root}/${checked_path} ]] || \
      die "inner checksum entry does not name a regular file: ${checked_path}"
  done < "${root}/checksums.txt"
  [[ ${#listed[@]} -gt 0 ]] || die "bundle checksums.txt contains no files"
  while IFS= read -r -d '' release_file; do
    relative_path="${release_file#"${root}/"}"
    [[ ${relative_path} == "checksums.txt" ]] && continue
    [[ -n ${listed["${relative_path}"]+present} ]] || \
      die "release file is not listed in checksums.txt: ${relative_path}"
  done < <(find "${root}" -type f -print0)
  [[ -z $(find "${root}" -mindepth 1 ! -type d ! -type f -print -quit) ]] || \
    die "bundle tree contains a symlink or non-regular file"
}

verify_release_checksum_inventory "${EXTRACTED_ROOT}"
(cd -- "${EXTRACTED_ROOT}" && sha256sum --check --strict checksums.txt)

jq -e \
  --arg version "${VERSION}" \
  --arg arch "${ARCH}" \
  --arg archive_name "${ARCHIVE_NAME}" \
  --arg artifact_id "${ARTIFACT_ID}" \
  '((keys | sort) ==
      ["archive", "build_date", "commit", "compatibility", "component",
       "platform", "schema_version", "source_version"]) and
   (.schema_version == 1) and
   (.component == "host-agent") and
   (.source_version == $version) and
   (.commit | type == "string" and test("^[0-9a-f]{40}$")) and
   (.build_date | type == "string" and
    test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
   (.platform |
     ((keys | sort) == ["arch", "os"]) and
     (.os == "linux") and
     (.arch == $arch)) and
   (.archive |
     ((keys | sort) == ["name", "root"]) and
     (.name == $archive_name) and
     (.root == $artifact_id)) and
   (.compatibility |
     ((keys | sort) ==
       ["database_schema", "minimum_agent_version", "minimum_panel_version",
        "rollback_compatible"]) and
     (.minimum_agent_version == null) and
     (.minimum_panel_version == $version) and
     (.rollback_compatible == true) and
     (.database_schema == "none"))' \
  "${EXTRACTED_ROOT}/${ARTIFACT_MANIFEST_NAME}" >/dev/null || \
  die "${ARTIFACT_MANIFEST_NAME} does not authorize this exact Host Agent bundle"
MANIFEST_COMMIT="$(jq -er '.commit' "${EXTRACTED_ROOT}/${ARTIFACT_MANIFEST_NAME}")" || \
  die "could not read the bundle commit"
readonly MANIFEST_COMMIT
MANIFEST_BUILD_DATE="$(jq -er '.build_date' "${EXTRACTED_ROOT}/${ARTIFACT_MANIFEST_NAME}")" || \
  die "could not read the bundle build date"
readonly MANIFEST_BUILD_DATE

readonly HOST_BINARY_SOURCE="${EXTRACTED_ROOT}/bin/autostream-host-agent"
readonly BINARY_SOURCE="${EXTRACTED_ROOT}/bin/autostream-local-executor"
readonly SERVICE_SOURCE="${EXTRACTED_ROOT}/systemd/autostream-local-executor.service"
readonly SOCKET_SOURCE="${EXTRACTED_ROOT}/systemd/autostream-local-executor.socket"
readonly TMPFILES_SOURCE="${EXTRACTED_ROOT}/systemd/autostream-local-executor.tmpfiles"
readonly VERIFIED_INSTALLER_SOURCE="${EXTRACTED_ROOT}/install/install-autostream-local-executor"

for source in \
  "${HOST_BINARY_SOURCE}" \
  "${BINARY_SOURCE}" \
  "${SERVICE_SOURCE}" \
  "${SOCKET_SOURCE}" \
  "${TMPFILES_SOURCE}" \
  "${VERIFIED_INSTALLER_SOURCE}"; do
  [[ -f ${source} && ! -L ${source} ]] || \
    die "required verified Host Agent bundle file is missing or unsafe: ${source}"
done
[[ -x ${HOST_BINARY_SOURCE} && -x ${BINARY_SOURCE} ]] || \
  die "Host Agent bundle binaries are not executable"
[[ $(sha256sum -- "${RUNNING_INSTALLER_SOURCE}" | awk 'NR == 1 { print $1 }') == \
  "$(sha256sum -- "${VERIFIED_INSTALLER_SOURCE}" | awk 'NR == 1 { print $1 }')" ]] || \
  die "running local executor installer does not match the verified bundle"

verify_binary_identity() {
  local binary_path=$1
  local binary_name=$2
  local binary_version_output
  local expected_identity
  binary_version_output="$("${binary_path}" --version)" || \
    die "${binary_name} binary identity command failed"
  expected_identity="$(
    printf '%s %s\ncommit: %s\nbuild_date: %s' \
      "${binary_name}" "${VERSION}" "${MANIFEST_COMMIT}" "${MANIFEST_BUILD_DATE}"
    if [[ ${binary_name} == "autostream-local-executor" ]]; then
      printf '\nmutation_protocol: 2\nrecovery_protocol: 2'
    fi
  )"
  [[ ${binary_version_output} == "${expected_identity}" ]] || \
    die "${binary_name} binary identity does not match ${ARTIFACT_MANIFEST_NAME}"
}

verify_binary_identity "${HOST_BINARY_SOURCE}" "autostream-host-agent"
verify_binary_identity "${BINARY_SOURCE}" "autostream-local-executor"

acquire_shared_host_setup_lock
acquire_host_lifecycle_lock

getent passwd "${AGENT_USER}" >/dev/null 2>&1 || \
  die "${AGENT_USER} must be installed before the local executor"
getent group "${AGENT_GROUP}" >/dev/null 2>&1 || \
  die "${AGENT_GROUP} must be installed before the local executor"
readonly agent_uid=$(id -u "${AGENT_USER}")
readonly agent_gid=$(getent group "${AGENT_GROUP}" | awk -F: 'NR == 1 { print $3 }')
[[ ${agent_uid} =~ ^[0-9]+$ && ${agent_uid} -ne 0 ]] || die "Host Agent UID is invalid"
[[ ${agent_gid} =~ ^[0-9]+$ && ${agent_gid} -ne 0 ]] || die "Host Agent GID is invalid"
[[ $(id -g "${AGENT_USER}") == "${agent_gid}" ]] || die "Host Agent primary group is invalid"
