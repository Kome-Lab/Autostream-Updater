#!/usr/bin/env bash
set -euo pipefail
test "$(git -C .c10-baseline rev-parse HEAD)" = 6f71ee3a0906665f0a639abf69c27749ba211dc7
export C10_BASELINE_DIR
C10_BASELINE_DIR="$(mktemp -d "${RUNNER_TEMP:?}/c10-baseline-records.XXXXXX")"
cp scripts/ci/c10_baseline_fixture_test.go .c10-baseline/internal/localexecutor/registry/zz_c10_baseline_fixture_test.go
cp scripts/ci/c10_baseline_fixture_test.go internal/localexecutor/registry/zz_c10_baseline_fixture_test.go
(cd .c10-baseline && go test -p 1 -tags=c10_baseline_fixture -count=1 -v -run '^TestC10BaselineExport$' ./internal/localexecutor/registry)
go test -p 1 -tags=c10_baseline_fixture -count=1 -v -run '^TestC10BaselineImport$' ./internal/localexecutor/registry
git -C .c10-baseline diff --exit-code -- go.mod go.sum
git diff --exit-code -- go.mod go.sum
