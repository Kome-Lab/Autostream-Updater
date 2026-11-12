#!/usr/bin/env bash
# Public source/dependency identity check; this is not runtime Guard authority.
set -euo pipefail
metadata="${RUNNER_TEMP:?}/v3-evidence-download.json"
selected="${RUNNER_TEMP}/v3-evidence-selected.json"
go mod download -json github.com/Kome-Lab/Autostream-Contracts/v3evidence@v0.0.0-20261112114129-c53da46de667 > "${metadata}"
go list -m -json github.com/Kome-Lab/Autostream-Contracts/v3evidence > "${selected}"
python3 - "${metadata}" "${selected}" <<'PY'
import hashlib, json, pathlib, sys
download=json.load(open(sys.argv[1], encoding="utf-8"))
selected=json.load(open(sys.argv[2], encoding="utf-8"))
expected_path="github.com/Kome-Lab/Autostream-Contracts/v3evidence"
expected_version="v0.0.0-20261112114129-c53da46de667"
expected_commit="c53da46de667d0cb0fc3692978870f373b437b06"
assert download["Path"] == expected_path and download["Version"] == expected_version
assert selected["Path"] == expected_path and selected["Version"] == expected_version
assert "Replace" not in selected, "v3 evidence must not use local/candidate replacement"
assert download.get("Sum", "").startswith("h1:") and download.get("GoModSum", "").startswith("h1:")
origin=download.get("Origin", {})
if origin.get("Hash"):
    assert origin["Hash"] == expected_commit
root=pathlib.Path(download["Dir"])
expected={"go.mod":"b6953f0201990cf0d0637a10cec7e72bf0d79414","types.go":"73db63c362cf35b3003fa5f9071af936b9e09c6c","codec.go":"44a6351a2f124ab31dd7c66e65331be4eb23ab7d","codec_test.go":"2a0dcf8914c5512e01a3cdfa1902d6b91bded7ff"}
assert {p.relative_to(root).as_posix() for p in root.rglob("*.go")} == {"types.go", "codec.go", "codec_test.go"}
for name, blob in expected.items():
    payload=(root/name).read_bytes()
    actual=hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload).hexdigest()
    assert actual == blob, "module source differs from reviewed Contracts commit"
print("PINNED_V3_EVIDENCE_SOURCE=" + expected_commit)
print("PINNED_V3_EVIDENCE_VERSION=" + expected_version)
PY
