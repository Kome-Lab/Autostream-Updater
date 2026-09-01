#!/bin/bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf '%s\n' 'usage: verify-shell-test-evidence.sh EVIDENCE_DIRECTORY REPOSITORY_ROOT EXPECTED_TEST_TSV' >&2
  exit 2
fi
readonly EVIDENCE_DIRECTORY=$1
readonly REPOSITORY_ROOT=$2
readonly EXPECTED_TEST_TSV=$3

[[ -d ${EVIDENCE_DIRECTORY} && -d ${REPOSITORY_ROOT} && -s ${EXPECTED_TEST_TSV} ]] || {
  printf '%s\n' 'shell evidence input is missing' >&2
  exit 1
}
expected_names=$(mktemp)
trap 'rm -f -- "${expected_names}"' EXIT
while IFS=$'\t' read -r test_name script_path extra; do
  [[ -z ${extra:-} && ${test_name} =~ ^[A-Za-z][A-Za-z0-9_]+$ && ${script_path} == scripts/ci/*.sh ]] || {
    printf 'invalid required shell test mapping: %s %s\n' "${test_name}" "${script_path}" >&2
    exit 1
  }
  [[ -f ${REPOSITORY_ROOT}/${script_path} ]] || {
    printf 'required shell fixture is missing: %s\n' "${script_path}" >&2
    exit 1
  }
  printf '%s\n' "${test_name}" >> "${expected_names}"
done < "${EXPECTED_TEST_TSV}"
[[ -s ${expected_names} && -z $(sort "${expected_names}" | uniq -d) ]] || {
  printf '%s\n' 'required shell test names are empty or duplicated' >&2
  exit 1
}
mapfile -t evidence_files < <(find "${EVIDENCE_DIRECTORY}" -maxdepth 1 -type f -name '*.json' -print | sort)
[[ ${#evidence_files[@]} -gt 0 ]] || {
  printf '%s\n' 'no shell test JSON evidence files were produced' >&2
  exit 1
}
jq -s -e --rawfile expected "${expected_names}" '
  ($expected | split("\n") | map(select(length > 0))) as $tests |
  ([.[] | select(.action == "skip" or .action == "fail")] | length) == 0 and
  all($tests[] as $test;
    ([.[] | select(.action == "run" and .test == $test)] | length) == 1 and
    ([.[] | select(.action == "pass" and .test == $test)] | length) == 1
  )
' "${evidence_files[@]}" >/dev/null || {
  printf '%s\n' 'required shell suite did not prove exact run/pass events with skip=0 and fail=0' >&2
  exit 1
}
