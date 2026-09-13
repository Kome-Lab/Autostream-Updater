import argparse
from historical_diagnostic_guard import historical_guard_source, load_historical_guard

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile

parser = argparse.ArgumentParser(description="Run the preserved 30 historical diagnostic guard fixtures")
parser.add_argument("--source-root", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--fixture-root", type=Path, required=True)
args = parser.parse_args()
args.source_root = args.source_root.resolve()
args.out = args.out.resolve()
ROOT = args.fixture_root.resolve()
ROOT.mkdir(parents=True, exist_ok=True)
RUN_ROOT = Path(tempfile.mkdtemp(prefix="guard-run-", dir=ROOT))
STORE = RUN_ROOT / "guard-objects.git"
FIXTURES = RUN_ROOT / "guard-fixtures"
FIXTURES.mkdir()
ENV = dict(os.environ, GIT_AUTHOR_NAME="Diagnostic fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
           GIT_COMMITTER_NAME="Diagnostic fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
           GIT_AUTHOR_DATE="2026-09-11T00:00:00+00:00", GIT_COMMITTER_DATE="2026-09-11T00:00:00+00:00",
           GIT_OPTIONAL_LOCKS="0")
def git(cwd, *args, data=None):
    result = subprocess.run(["git", "-c", "safe.directory=" + str(cwd), "-c", "commit.gpgsign=false",
                             "-C", str(cwd), *args], input=data, capture_output=True, env=ENV)
    if result.returncode:
        raise RuntimeError("fixture git failed: " + args[0] + ": " + result.stderr.decode(errors="replace"))
    return result.stdout.strip()
subprocess.run(["git", "init", "--bare", str(STORE)], check=True, capture_output=True, env=ENV)
guard = load_historical_guard(args.source_root)
ALLOWED = {item.decode() for item in guard["ALLOWED"]}
CI = guard["CI"].decode()
SMOKE = "internal/hostruntime/docker_port_daemon_smoke_linux_test.go"
TEST = "internal/hostruntime/docker_port_smoke_diagnostics_linux_test.go"
WORKFLOW = ".github/workflows/docker-restart-diagnostics.yml"
CI1, CI2 = b"fixed historical ci\n", b"fixed current ci\n"
def oid(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
HISTORICAL, CURRENT = oid(CI1), oid(CI2)
blob_cache = {}
def tree(files):
    nested = {}
    for path, (mode, data) in files.items():
        cursor = nested
        parts = path.split("/")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        if mode == "160000":
            blob = data.decode()
        else:
            blob = blob_cache.setdefault(data, None)
            if blob is None:
                blob = git(STORE, "hash-object", "-w", "--stdin", data=data).decode()
                blob_cache[data] = blob
        cursor[parts[-1]] = (mode, blob)
    def build(node):
        entries = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode, kind, sha = "040000", "tree", build(value)
            else:
                mode, sha = value
                kind = "commit" if mode == "160000" else "blob"
            entries.append(f"{mode} {kind} {sha}\t{name}".encode() + b"\0")
        return git(STORE, "mktree", "-z", data=b"".join(entries)).decode()
    return build(nested)
def commit(files, parents=()):
    args = ["commit-tree", tree(files)]
    for parent in parents:
        args += ["-p", parent]
    return git(STORE, *args, data=b"diagnostic guard fixture\n").decode()
def changed(files, edits=None, removed=()):
    result = dict(files)
    for name in removed:
        result.pop(name, None)
    for name, value in (edits or {}).items():
        result[name] = value if isinstance(value, tuple) else ("100644", value)
    return result
u_files = {CI: ("100644", b"original application ci\n"), SMOKE: ("100644", b"original smoke\n"),
           "product.go": ("100644", b"package fixture\n"), ".gitignore": ("100644", b"generated/\n")}
b_files = changed(u_files, {CI: CI1})
p_files = changed(b_files, {name: b"previous diagnostic\n" for name in ALLOWED})
w_files = changed(p_files, {CI: CI2})
n_files = changed(w_files, {name: b"next diagnostic\n" for name in ALLOWED})
u = commit(u_files)
b = commit(b_files, [u])
p = commit(p_files, [b])
w = commit(w_files, [p])
n = commit(n_files, [w])
default = [u, b, p, w, n, n, HISTORICAL, CURRENT]
results = []
def checkout(label, source):
    dest = FIXTURES / label
    subprocess.run(["git", "init", "--initial-branch=fixture", str(dest)], check=True, capture_output=True, env=ENV)
    git(dest, "config", "core.autocrlf", "false")
    git(dest, "config", "core.symlinks", "false")
    git(dest, "config", "core.filemode", "true")
    (dest / ".git/objects/info/alternates").write_bytes((str(STORE / "objects").replace("\\", "/") + "\n").encode())
    git(dest, "update-ref", "refs/heads/fixture", source)
    git(dest, "read-tree", source)
    git(dest, "checkout-index", "--all")
    return dest
def case(label, expected=None, args=None, dirty=None, checkout_sha=None):
    inputs = list(args or default)
    dest = checkout(label, checkout_sha or inputs[4])
    if dirty:
        dirty(dest)
    checks = dict.fromkeys(guard["CHECKS"], "not_run")
    old = Path.cwd()
    failure = None
    try:
        os.chdir(dest)
        guard["verify_source"](*inputs, checks)
    except guard["GuardFailure"] as error:
        failure = str(error)
    finally:
        os.chdir(old)
    assert failure == expected, (label, expected, failure, checks)
    if expected is None:
        assert all(value == "pass" for value in checks.values())
    results.append({"case": label, "expectedFailure": expected, "observedFailure": failure, "checks": checks, "pass": True})
def current_case(label, files, expected, parents=None):
    head = commit(files, parents or [w])
    case(label, expected, [u, b, p, w, head, head, HISTORICAL, CURRENT])
case("valid-chain")
extra_parent = commit(w_files, [w])
current_case("wrong-direct-parent", n_files, "current_parent", [extra_parent])
current_case("merge-parent", n_files, "current_parent", [w, b])
current_case("unrelated-parent", n_files, "current_ancestry", [p])
current_case("product-change", changed(n_files, {"product.go": b"changed product\n"}), "current_delta")
current_case("ci-change", changed(n_files, {CI: b"changed ci\n"}), "current_delta")
current_case("missing-allowed-path", changed(n_files, {TEST: p_files[TEST]}), "current_delta")
current_case("extra-path", changed(n_files, {"extra.go": b"extra\n"}), "current_delta")
current_case("delete", changed(n_files, removed=[TEST]), "current_delta")
current_case("rename", changed(n_files, {"renamed_test.go": b"next diagnostic\n"}, [TEST]), "current_delta")
current_case("executable", changed(n_files, {SMOKE: ("100755", b"next diagnostic\n")}), "current_delta")
current_case("symlink", changed(n_files, {SMOKE: ("120000", b"product.go")}), "current_delta")
current_case("submodule", changed(n_files, {SMOKE: ("160000", u.encode())}), "current_delta")
case("workflow-sha-mismatch", "workflow_sha", [u, b, p, w, n, w, HISTORICAL, CURRENT])
case("checkout-sha-mismatch", "checkout_sha", checkout_sha=w)
case("short-commit", "commit_ids", [u[:7], b, p, w, n, n, HISTORICAL, CURRENT])
case("missing-object", "git_query_failed", [u, b, "f" * 40, w, n, n, HISTORICAL, CURRENT])
case("historical-blob-mismatch", "historical_ci_blob", [u, b, p, w, n, n, "0" * 40, CURRENT])
case("current-blob-mismatch", "current_ci_blob", [u, b, p, w, n, n, HISTORICAL, "0" * 40])
def write_dirty(dest, name, stage=False):
    full = dest / name
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(b"dirty fixture input\n")
    if stage:
        git(dest, "add", name)
case("dirty-tracked", "worktree_clean", dirty=lambda d: write_dirty(d, SMOKE))
case("dirty-staged", "worktree_clean", dirty=lambda d: write_dirty(d, SMOKE, True))
case("dirty-untracked", "worktree_clean", dirty=lambda d: write_dirty(d, "untracked.go"))
case("dirty-ignored", "worktree_clean", dirty=lambda d: write_dirty(d, "generated/input.go"))
# Historical deltas must be exact too, including their modes and ancestry.
bad_b_files = changed(b_files, {"product.go": b"historical product change\n"})
bad_b = commit(bad_b_files, [u])
bad_p_files = changed(bad_b_files, {name: b"previous diagnostic\n" for name in ALLOWED})
bad_p = commit(bad_p_files, [bad_b])
bad_w_files = changed(bad_p_files, {CI: CI2})
bad_w = commit(bad_w_files, [bad_p])
bad_n = commit(changed(bad_w_files, {name: b"next diagnostic\n" for name in ALLOWED}), [bad_w])
case("historical-baseline-extra", "baseline_delta", [u, bad_b, bad_p, bad_w, bad_n, bad_n, HISTORICAL, CURRENT])
bad_p_files = changed(p_files, removed=[TEST])
bad_p = commit(bad_p_files, [b])
bad_w_files = changed(bad_p_files, {CI: CI2})
bad_w = commit(bad_w_files, [bad_p])
bad_n = commit(changed(bad_w_files, {name: b"next diagnostic\n" for name in ALLOWED}), [bad_w])
case("historical-diagnostic-missing", "previous_delta", [u, b, bad_p, bad_w, bad_n, bad_n, HISTORICAL, CURRENT])
bad_w_files = changed(w_files, {"product.go": b"later product change\n"})
bad_w = commit(bad_w_files, [p])
bad_n = commit(changed(bad_w_files, {name: b"next diagnostic\n" for name in ALLOWED}), [bad_w])
case("historical-base-extra", "base_delta", [u, b, p, bad_w, bad_n, bad_n, HISTORICAL, CURRENT])
bad_b_files = changed(b_files, {CI: ("100755", CI1)})
bad_b = commit(bad_b_files, [u])
bad_p_files = changed(bad_b_files, {name: b"previous diagnostic\n" for name in ALLOWED})
bad_p = commit(bad_p_files, [bad_b])
bad_w_files = changed(bad_p_files, {CI: ("100755", CI2)})
bad_w = commit(bad_w_files, [bad_p])
bad_n = commit(changed(bad_w_files, {name: b"next diagnostic\n" for name in ALLOWED}), [bad_w])
case("historical-mode-change", "baseline_delta", [u, bad_b, bad_p, bad_w, bad_n, bad_n, HISTORICAL, CURRENT])
bad_p = commit(p_files, [u])
bad_w = commit(w_files, [bad_p])
bad_n = commit(n_files, [bad_w])
case("historical-ancestry", "previous_ancestry", [u, b, bad_p, bad_w, bad_n, bad_n, HISTORICAL, CURRENT])
# Individual CI deltas cannot hide a cumulative reversion.
alt_u = commit(changed(u_files, {CI: CI2}))
alt_b = commit(b_files, [alt_u])
alt_p = commit(p_files, [alt_b])
alt_w = commit(w_files, [alt_p])
alt_n = commit(n_files, [alt_w])
case("cumulative-missing-ci", "application_delta", [alt_u, alt_b, alt_p, alt_w, alt_n, alt_n, HISTORICAL, CURRENT])
# A non-repository forces the actual Git failure path (no mocked successful exit).
nonrepo = FIXTURES / "git-query-failure"
nonrepo.mkdir()
old = Path.cwd()
os.chdir(nonrepo)
try:
    guard["verify_source"](*default, {})
except guard["GuardFailure"] as error:
    assert str(error) == "git_query_failed"
    results.append({"case": "git-query-failure", "observedFailure": str(error), "pass": True})
else:
    raise AssertionError("Git failure accepted")
finally:
    os.chdir(old)
# Check the actual historical fixed chain read-only, independent of local dirt.
real = args.source_root
old_config = {name: os.environ.get(name) for name in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0")}
os.environ.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory", GIT_CONFIG_VALUE_0=str(real))
os.chdir(real)
real_u, real_b, real_p, real_w = "794d0cd69dd1b3ca130101f7769aaf8ac1274ac8", "b7ea27bb503bf259abeb34652b41cce9351884d2", "b123456f33f0c61974bb3300dfd59b909646404a", "2cc44bcbad857a103aa58cb30e89f97dcda8ffda"
try:
    for left, right, paths in [(real_u, real_b, {guard["CI"]}), (real_b, real_p, guard["ALLOWED"]), (real_p, real_w, {guard["CI"]})]:
        assert guard["ancestor"](left, right)
        assert guard["allowed_delta"](left, right, paths)
    for ref, expected in [(real_b, "7780fa3a21e20ba304d2301f9dde3b7e97ec79d1"), (real_p, "7780fa3a21e20ba304d2301f9dde3b7e97ec79d1"), (real_w, "1236ba11843261deec085cb7396f1276e41f83d2")]:
        assert guard["git"]("rev-parse", ref + ":" + CI).strip().decode() == expected
finally:
    os.chdir(old)
    for key, value in old_config.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
summary = {"fixtureCount": len(results), "pass": len(results), "fail": 0, "results": results,
           "actualFixedHistoricalChain": "PASS", "actualHistoricalAndCurrentCiBlobs": "PASS",
           "productionGuardSha256": hashlib.sha256(historical_guard_source(args.source_root).encode()).hexdigest()}
args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: value for key, value in summary.items() if key != "results"}, indent=2))
