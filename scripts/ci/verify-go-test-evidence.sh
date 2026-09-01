#!/bin/bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  printf '%s\n' 'usage: verify-go-test-evidence.sh EVIDENCE_DIRECTORY SOURCE_ROOT EXPECTED_TEST_LIST...' >&2
  exit 2
fi

readonly EVIDENCE_DIRECTORY=$1
readonly SOURCE_ROOT=$2
shift 2
readonly EXPECTED_LISTS=("$@")

[[ -d ${EVIDENCE_DIRECTORY} ]] || {
  printf 'evidence directory is missing: %s\n' "${EVIDENCE_DIRECTORY}" >&2
  exit 1
}
[[ -d ${SOURCE_ROOT} ]] || {
  printf 'source root is missing: %s\n' "${SOURCE_ROOT}" >&2
  exit 1
}

expected_file=$(mktemp)
trap 'rm -f -- "${expected_file}"' EXIT
for list in "${EXPECTED_LISTS[@]}"; do
  [[ -f ${list} ]] || {
    printf 'expected-test list is missing: %s\n' "${list}" >&2
    exit 1
  }
  sed '/^[[:space:]]*$/d' "${list}" >> "${expected_file}"
done
[[ -s ${expected_file} ]] || {
  printf '%s\n' 'expected-test list is empty' >&2
  exit 1
}

if [[ -n $(sort "${expected_file}" | uniq -d) ]]; then
  printf '%s\n' 'expected-test list contains duplicates' >&2
  sort "${expected_file}" | uniq -d >&2
  exit 1
fi

while IFS= read -r test_name; do
  [[ ${test_name} =~ ^Test[A-Za-z0-9_]+$ ]] || {
    printf 'invalid exact Go test name: %s\n' "${test_name}" >&2
    exit 1
  }
  matches=$(grep -R -n -E --include='*_test.go' \
    "^func[[:space:]]+${test_name}[[:space:]]*\\(" "${SOURCE_ROOT}" || true)
  match_count=$(printf '%s\n' "${matches}" | sed '/^$/d' | wc -l)
  if [[ ${match_count} -ne 1 ]]; then
    printf 'required Go test must have exactly one source declaration: %s (found %s)\n' \
      "${test_name}" "${match_count}" >&2
    exit 1
  fi
done < "${expected_file}"

mapfile -t evidence_files < <(find "${EVIDENCE_DIRECTORY}" -maxdepth 1 -type f -name '*.json' -print | sort)
[[ ${#evidence_files[@]} -gt 0 ]] || {
  printf '%s\n' 'no Go test JSON evidence files were produced' >&2
  exit 1
}
for evidence in "${evidence_files[@]}"; do
  jq -e 'select(.Action == "pass" and ((.Test // "") == ""))' "${evidence}" >/dev/null || {
    printf 'package pass event is missing: %s\n' "${evidence}" >&2
    exit 1
  }
done

jq -s -e --rawfile expected "${expected_file}" '
  ($expected | split("\n") | map(select(length > 0))) as $tests |
  ([.[] | select(.Action == "skip")] | length) == 0 and
  ([.[] | select(.Action == "fail")] | length) == 0 and
  ([ $tests[] as $test |
    (([.[] | select(.Action == "run" and .Test == $test)] | length) == 1 and
     ([.[] | select(.Action == "pass" and .Test == $test)] | length) == 1 and
     ([.[] | select(
       .Action == "skip" and
       ((.Test // "") == $test or ((.Test // "") | startswith($test + "/")))
     )] | length) == 0)
  ] | all)
' "${evidence_files[@]}" >/dev/null || {
  printf '%s\n' 'required Go suite did not prove exact run/pass events with skip=0 and fail=0' >&2
  exit 1
}
