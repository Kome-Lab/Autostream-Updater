#!/usr/bin/env bash
# Validate UNAPPLIED proposals in a disposable source copy. Never publish or
# replace the production Contracts dependency from this candidate directory.
set -euo pipefail

test "$(go env GOVERSION)" = go1.26.5
candidate_mode="${1:-full}"
case "${candidate_mode}" in full|focused) ;; *) exit 2 ;; esac
repository_root="$(git rev-parse --show-toplevel)"
proposal="${repository_root}/testdata/c03-contracts-candidate"
test -f "${proposal}/README.md"
test ! -e "${repository_root}/internal/localexecutor/registry/guard_contracts.go"
if grep -q 'Autostream-Contracts/v3evidence' "${repository_root}/go.mod" "${repository_root}/go.sum"; then
  printf '%s\n' 'Candidate must not become a production dependency.' >&2
  exit 1
fi

candidate_workspace="$(mktemp -d "${RUNNER_TEMP:?}/c03-evidence-candidate.XXXXXX")"
mkdir -p "${candidate_workspace}/updater" "${candidate_workspace}/contracts/v3evidence"
git archive --format=tar HEAD | tar -xf - -C "${candidate_workspace}/updater"
cp -R "${proposal}/contracts/v3evidence/." "${candidate_workspace}/contracts/v3evidence/"
cp "${proposal}/updater/guard_contracts.go" "${candidate_workspace}/updater/internal/localexecutor/registry/guard_contracts.go"
cp "${proposal}/updater/guard_contracts_test.go" "${candidate_workspace}/updater/internal/localexecutor/registry/guard_contracts_test.go"

printf '%s\n' 'CANDIDATE_ONLY: canonical types/codec; no issuer, key, clock or production publication.'
(
  cd "${candidate_workspace}/contracts/v3evidence"
  gofmt -w types.go codec.go codec_test.go
  go test -p 1 -count=1 -v ./...
  go vet -p 1 ./...
  if [[ "${candidate_mode}" == full ]]; then
    CGO_ENABLED=0 go test -p 1 -count=1 ./...
    CGO_ENABLED=1 go test -race -p 1 -count=1 ./...
  fi
)
printf '%s\n' 'CANDIDATE_ONLY: overlay proposed C10 bridge into isolated archive, never source checkout.'
(
  cd "${candidate_workspace}/updater"
  patch --batch --fuzz=0 -p1 < "${proposal}/updater/guard_evidence.patch"
  gofmt -w internal/localexecutor/registry/guard_contracts.go internal/localexecutor/registry/guard_contracts_test.go internal/localexecutor/registry/guard_evidence.go
  export GOFLAGS=-mod=mod
  go mod edit -require=github.com/Kome-Lab/Autostream-Contracts/v3evidence@v0.0.0
  go mod edit "-replace=github.com/Kome-Lab/Autostream-Contracts/v3evidence=${candidate_workspace}/contracts/v3evidence"
  go test -p 1 -count=1 -v -run '^TestSQLiteContracts' ./internal/localexecutor/registry
  go vet -p 1 ./internal/localexecutor/registry
  if [[ "${candidate_mode}" == full ]]; then
    CGO_ENABLED=0 go test -p 1 -count=1 -run '^TestSQLiteContracts' ./internal/localexecutor/registry
    CGO_ENABLED=1 go test -race -p 1 -count=1 -run '^TestSQLiteContracts' ./internal/localexecutor/registry
    for arch in amd64 arm64; do
      CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go test -p 1 -trimpath -c ./internal/localexecutor/registry -o "${candidate_workspace}/candidate-registry-linux-${arch}.test"
      sha256sum "${candidate_workspace}/candidate-registry-linux-${arch}.test"
    done
  fi
)
cd "${repository_root}"
git diff --exit-code -- go.mod go.sum internal/localexecutor/registry
printf '%s\n' 'CANDIDATE_ONLY_SUCCESS: product sources/dependencies unchanged; publication and real Producer remain blocked.'
