# CI and versioned releases

## Required CI evidence

The ordinary CI job runs module-state, formatting, all-package test, vet,
production build, Linux amd64/arm64 cross-build, installer syntax, and systemd
unit validation gates. Required integration jobs add machine-readable evidence:

- application identity probes cover the exact five-service allowlist, strict
  identity matching, redirect rejection, and mandatory fresh `no-store`
  responses;
- the privileged Linux suite covers root-owned configuration, stable locks,
  socket activation and negative socket/cgroup ownership, the real non-root
  peer credential, Host runtime bootstrap, upgrade, rollback, and A/B recovery;
- installer fixtures exercise prepare and upgrade failure injection, rollback,
  uninstall behavior, state preservation, identity permissions, and the real
  systemd sandbox capability boundary;
- the Docker suite creates a fresh Compose service fixture against the real
  Docker daemon, exercises fixed service-update behavior and sequential
  mutations, and proves both transaction and software-update rollback paths.
- the pre-removal replacement suite pins both repository SHAs, proves the v2
  Control Panel adapter and independent Updater behavior together, requires
  missing or legacy peers to fail closed without fallback, and uploads exact
  machine-readable test evidence;
- the rollback-candidate job builds and fully verifies the amd64 and arm64
  release shape from that same Updater SHA, uploads it only as a short-lived
  artifact, and never tags, publishes, releases, or deploys it.

Required Go test names live in `scripts/ci/required-*.txt`. The evidence
verifier first requires exactly one matching source declaration and then
requires exactly one `run` and one `pass` event, with zero `skip` and zero
`fail` events. Shell fixture names are bound to real scripts by
`scripts/ci/required-shell-tests.tsv` and use the same run/pass/fail-closed
model. A missing, renamed, skipped, or unexecuted required test cannot pass.

## Stable release model

A stable release starts from an externally created `vX.Y.Z` tag. The publish
workflow does not create, move, or overwrite tags. Before building, it resolves
lightweight or annotated tags through the GitHub API, requires a newly created
non-forced tag whose result equals the event SHA, refuses an already-existing
GitHub Release, and waits for the `CI` workflow to complete successfully for
that exact SHA.

One GitHub-hosted build job creates the Linux amd64 and arm64 bundles exactly
once. Each archive contains an `artifact-manifest.json` plus inner
`checksums.txt`; the release set contains the outer `host-agent-manifest.json`,
adjacent checksum files, and `SHA256SUMS`. Verification re-hashes the inner and
outer files, checks manifest version/commit/architecture identity, checks the
archive root and executable modes, and rejects unlisted release files. The
same payload is reverified after artifact download in the publish job.

GitHub artifact attestations are created for every release file before upload.
The outer Host Agent manifest also receives a dedicated single-subject
attestation whose subject name comes from its canonical adjacent checksum; this
matches the runtime provenance verifier's strict workflow and manifest binding.
The publish job checks the tag and Release absence again and then creates one
GitHub Release with `--verify-tag`. If the tag moved or the Release already
exists, the workflow fails instead of replacing anything. It does not perform
a production deployment.

`Release build rehearsal (no publish)` is the explicit manual path. It requires
successful CI for the selected commit and runs the same build and verification
scripts, but only uploads a short-lived workflow artifact.
