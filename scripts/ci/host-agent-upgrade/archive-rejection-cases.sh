
rebuild_bundle_archive
expected_manifest_sha="$(sha256sum -- "${PACKAGE_ROOT}/artifact-manifest.json" |
  awk 'NR == 1 { print $1 }')"
if ! command -v jq >/dev/null 2>&1; then
  jq_shim=$(mktemp)
  cat > "${jq_shim}" <<EOF
#!/bin/bash
set -euo pipefail
manifest="\${!#}"
actual_sha="\$(sha256sum -- "\${manifest}" | awk 'NR == 1 { print \$1 }')"
[[ \${actual_sha} == "${expected_manifest_sha}" ]] || exit 1
case " \$* " in
  *" .commit "*)
    printf '%s\n' '${BUILD_COMMIT}'
    ;;
  *" .build_date "*)
    printf '%s\n' '${BUILD_DATE}'
    ;;
  *)
    exit 0
    ;;
esac
EOF
  install -o root -g root -m 0755 "${jq_shim}" /usr/bin/jq
  rm -f -- "${jq_shim}"
fi
if ! command -v systemctl >/dev/null 2>&1; then
  systemctl_shim=$(mktemp)
  cat > "${systemctl_shim}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" > /root/autostream-host-agent-upgrade-systemctl.log
exit 98
EOF
  install -o root -g root -m 0755 "${systemctl_shim}" /usr/bin/systemctl
  rm -f -- "${systemctl_shim}"
fi

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --upgrade --prepare 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted --upgrade with --prepare' >&2
  exit 1
fi
grep -Fq -- '--prepare and --upgrade are mutually exclusive' \
  <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --upgrade --config "${IDENTITY_PATH}" 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted --upgrade with --config' >&2
  exit 1
fi
grep -Fq -- 'unknown argument: --config' \
  <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --prepare --recover-active-job 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted recovery without upgrade mode' >&2
  exit 1
fi
grep -Fq -- '--recover-active-job requires --upgrade' <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

rm -f -- "${HELPER_LOG}"
if mode_output="$("${INSTALLER}" --upgrade --recover-active-job --recover-active-job 2>&1)"; then
  printf '%s\n' 'Host Agent installer accepted a duplicate recovery flag' >&2
  exit 1
fi
grep -Fq -- '--recover-active-job may be specified only once' <<<"${mode_output}"
assert_no_completion "${mode_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

mv -- "${ARCHIVE}" "${ARCHIVE_BACKUP}"
rm -f -- "${HELPER_LOG}"
if missing_output="$("${INSTALLER}" --upgrade 2>&1)"; then
  printf '%s\n' 'Host Agent upgrade accepted a missing adjacent archive' >&2
  exit 1
fi
mv -- "${ARCHIVE_BACKUP}" "${ARCHIVE}"
assert_no_completion "${missing_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

install -o root -g root -m 0600 "${ARCHIVE}" "${ARCHIVE_BACKUP}"
install -o root -g root -m 0755 \
  "${PACKAGE_ROOT}/bin/autostream-host-agent" "${HOST_BINARY_BACKUP}"
printf '%s\n' '# adjacent archive checksum tamper' >> \
  "${PACKAGE_ROOT}/bin/autostream-host-agent"
rm -f -- "${ARCHIVE}"
tar -C /root -czf "${ARCHIVE}" "${ARTIFACT_ID}"
rm -f -- "${HELPER_LOG}"
if tampered_output="$("${INSTALLER}" --upgrade 2>&1)"; then
  printf '%s\n' 'Host Agent upgrade accepted a modified adjacent archive' >&2
  exit 1
fi
install -o root -g root -m 0755 \
  "${HOST_BINARY_BACKUP}" "${PACKAGE_ROOT}/bin/autostream-host-agent"
install -o root -g root -m 0600 "${ARCHIVE_BACKUP}" "${ARCHIVE}"
rm -f -- "${HOST_BINARY_BACKUP}" "${ARCHIVE_BACKUP}"
assert_no_completion "${tampered_output}"
assert_helper_not_called
assert_private_stage_cleaned
assert_sentinels_unchanged

readonly EXPECTED_ARCHIVE_SHA256="$(sha256sum -- "${ARCHIVE}" |
  awk 'NR == 1 { print $1 }')"
readonly EXPECTED_ARCHIVE_SIZE="$(stat -c %s -- "${ARCHIVE}")"
