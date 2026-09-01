#!/bin/bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf '%s\n' 'usage: verify-github-release-tag.sh REPOSITORY TAG EXPECTED_COMMIT' >&2
  exit 2
fi
readonly REPOSITORY=$1
readonly TAG=$2
readonly EXPECTED_COMMIT=$3
[[ ${REPOSITORY} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ &&
  ${TAG} =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ &&
  ${EXPECTED_COMMIT} =~ ^[0-9a-f]{40}$ ]] || {
  printf '%s\n' 'invalid GitHub release tag identity' >&2
  exit 1
}

object=$(gh api \
  --header 'Accept: application/vnd.github+json' \
  "repos/${REPOSITORY}/git/ref/tags/${TAG}")
object_type=$(jq -r '.object.type' <<<"${object}")
object_sha=$(jq -r '.object.sha' <<<"${object}")
for _ in 1 2 3 4; do
  [[ ${object_type} == tag ]] || break
  object=$(gh api \
    --header 'Accept: application/vnd.github+json' \
    "repos/${REPOSITORY}/git/tags/${object_sha}")
  object_type=$(jq -r '.object.type' <<<"${object}")
  object_sha=$(jq -r '.object.sha' <<<"${object}")
done
[[ ${object_type} == commit && ${object_sha} == "${EXPECTED_COMMIT}" ]] || {
  printf 'release tag does not resolve to the event commit: type=%s sha=%s expected=%s\n' \
    "${object_type}" "${object_sha}" "${EXPECTED_COMMIT}" >&2
  exit 1
}
