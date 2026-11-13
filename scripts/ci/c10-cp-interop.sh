#!/usr/bin/env bash
set -euo pipefail
test "$(git -C .c10-interop-cp rev-parse HEAD)" = d8ff3362ab29780a9fe605eb260b13293d09abe9
test "$(go list -m -f '{{.Version}}' github.com/Kome-Lab/Autostream-Contracts/v3evidence)" = v0.0.0-20261113091349-790be850e98c
export CP_INTEROP_DIR
CP_INTEROP_DIR="$(mktemp -d "${RUNNER_TEMP:?}/c10-cp-interop.XXXXXX")"
cp .c10-interop-cp/scripts/ci/cp_authorization_interop_test.go internal/localexecutor/registry/zz_cp_producer_interop_test.go
go test -p 1 -tags=cp_producer_interop -run '^TestCPProducerExport$' -count=1 -v ./internal/localexecutor/registry
(cd .c10-interop-cp && go test -p 1 -run '^TestCPProducerInterop$' -count=1 -v ./internal/v3authorization)
go test -p 1 -tags=cp_producer_interop -run '^TestCPProducerImport$' -count=1 -v ./internal/localexecutor/registry
git -C .c10-interop-cp diff --exit-code -- go.mod go.sum
git diff --exit-code -- go.mod go.sum
