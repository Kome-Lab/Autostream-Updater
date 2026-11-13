#!/usr/bin/env bash
set -euo pipefail
test "$(git -C .c10-baseline rev-parse HEAD)" = 6f71ee3a0906665f0a639abf69c27749ba211dc7
test "$(git -C .c10-diagnostic-before rev-parse HEAD)" = a697b9ffc17fbcd45b636418e0713bd06e301a44
for checkout in .c10-baseline .c10-diagnostic-before; do
  cp internal/localexecutor/registry/canonical_diagnostic_test.go "$checkout/internal/localexecutor/registry/canonical_diagnostic_test.go"
done
export C10_DIAGNOSTIC_SNAPSHOT
for checkout in .c10-baseline .c10-diagnostic-before .; do
  cp scripts/ci/c10_request_diagnostic_snapshot_test.go "$checkout/internal/localexecutor/registry/zz_c10_request_diagnostic_snapshot_test.go"
  case "$checkout" in
    .c10-baseline) label=old ;;
    .c10-diagnostic-before) label=before ;;
    .) label=after ;;
  esac
  C10_DIAGNOSTIC_SNAPSHOT="${RUNNER_TEMP:?}/c10-diagnostic-$label.json"
  (cd "$checkout" && go test -p 1 -tags=c10_request_diagnostic_snapshot -count=1 -v -run '^TestC10RequestDiagnosticSnapshot$' ./internal/localexecutor/registry)
  git -C "$checkout" diff --exit-code -- go.mod go.sum
done
python3 - "${RUNNER_TEMP}" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
def read(label):
    rows=json.loads((root/("c10-diagnostic-"+label+".json")).read_text())
    result={r["Name"]:r for r in rows}
    assert len(rows)==len(result) and len(rows)>1
    return result
old,before,after=(read(x) for x in ("old","before","after"))
assert old.keys()==before.keys()==after.keys()
restored={name+"/"+order+"/only" for name in ("literal-replacement","escaped-replacement","high-surrogate","low-surrogate") for order in ("command-first","binding-first")}
def stable(row):
    return {k:v for k,v in row.items() if k!="Field"}
for name in old:
    assert stable(after[name])==stable(old[name]), "old Code/Status/bytes not restored: "+name
    if name in restored:
        assert old[name]["Code"]=="binding_conflict" and old[name]["Status"]=="CONFLICT"
        assert before[name]["Code"]=="invalid" and before[name]["Status"]=="REJECTED"
        assert old[name]["Field"]==after[name]["Field"]=="request.binding"
    else:
        assert stable(before[name])==stable(old[name]), "unexpected baseline difference: "+name
field_residuals=[name for name in old if old[name]["Field"]!=after[name]["Field"]]
print("C10_DIAGNOSTIC_COMPATIBILITY: observations=%d restored=%d normal-bytes=identical" % (len(old),len(restored)))
print("C10_FIELD_RESIDUALS=%d" % len(field_residuals))
for name in field_residuals:
    print("FIELD_ONLY: "+name+" "+old[name]["Field"]+" -> "+after[name]["Field"])
PY
