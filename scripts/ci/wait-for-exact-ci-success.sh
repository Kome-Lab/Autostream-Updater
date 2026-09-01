#!/bin/bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf '%s\n' 'usage: wait-for-exact-ci-success.sh REPOSITORY COMMIT TIMEOUT_SECONDS' >&2
  exit 2
fi
readonly REPOSITORY=$1
readonly COMMIT=$2
readonly TIMEOUT_SECONDS=$3
[[ ${REPOSITORY} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  printf '%s\n' 'invalid repository name' >&2
  exit 1
}
[[ ${COMMIT} =~ ^[0-9a-f]{40}$ && ${TIMEOUT_SECONDS} =~ ^[1-9][0-9]*$ ]] || {
  printf '%s\n' 'invalid exact-CI wait input' >&2
  exit 1
}

deadline=$((SECONDS + TIMEOUT_SECONDS))
while (( SECONDS < deadline )); do
  runs=$(gh api \
    --header 'Accept: application/vnd.github+json' \
    "repos/${REPOSITORY}/actions/workflows/ci.yml/runs?head_sha=${COMMIT}&event=push&per_page=100")
  if jq -e --arg sha "${COMMIT}" '
    any(.workflow_runs[]?;
      .head_sha == $sha and .event == "push" and
      .status == "completed" and .conclusion == "success"
    )
  ' <<<"${runs}" >/dev/null; then
    exit 0
  fi
  # A tag push and its CI workflow can become visible in the API at different
  # times. A prior failed run for the same commit is not proof that the new tag
  # run cannot succeed, so only an exact success or the bounded timeout closes
  # this gate.
  sleep 15
done
printf 'timed out waiting for exact-SHA CI success: %s\n' "${COMMIT}" >&2
exit 1
