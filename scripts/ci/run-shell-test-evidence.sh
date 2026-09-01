#!/bin/bash
set -euo pipefail

if [[ $# -lt 4 || $3 != -- ]]; then
  printf '%s\n' 'usage: run-shell-test-evidence.sh OUTPUT_JSON TEST_NAME -- COMMAND...' >&2
  exit 2
fi

readonly OUTPUT_JSON=$1
readonly TEST_NAME=$2
shift 3
[[ ${TEST_NAME} =~ ^[A-Za-z][A-Za-z0-9_]+$ ]] || {
  printf 'invalid shell test name: %s\n' "${TEST_NAME}" >&2
  exit 2
}
[[ $# -gt 0 ]] || {
  printf '%s\n' 'shell test command is empty' >&2
  exit 2
}
mkdir -p -- "$(dirname -- "${OUTPUT_JSON}")"
: > "${OUTPUT_JSON}"
jq -cn --arg test "${TEST_NAME}" '{test: $test, action: "run"}' >> "${OUTPUT_JSON}"
set +e
"$@"
status=$?
set -e
if [[ ${status} -eq 0 ]]; then
  jq -cn --arg test "${TEST_NAME}" '{test: $test, action: "pass"}' >> "${OUTPUT_JSON}"
else
  jq -cn --arg test "${TEST_NAME}" --argjson status "${status}" \
    '{test: $test, action: "fail", exit_code: $status}' >> "${OUTPUT_JSON}"
fi
exit "${status}"
