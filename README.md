# AutoStream Updater

AutoStream Updater owns bounded host execution for AutoStream. It contains a
non-root outbound Agent and a root Local Executor. The Control Panel remains
the authorization, orchestration, policy, central job-state, and audit
authority; AutoStream Contracts remains the wire authority.

## Runtime boundary

- `cmd/autostream-updater-agent` builds the non-root Agent. During the
  replacement wave it retains the installed `autostream-host-agent` service,
  account, binary, and state names so existing identity and A/B recovery remain
  valid.
- `autostream-local-executor` performs only root-owned, policy-bounded
  mutations through its fixed Unix-domain socket.
- The Agent cannot supply arbitrary commands, argv, environment variables, or
  privileged paths to the Local Executor.
- This repository never connects to the Control Panel database and never
  imports Control Panel internal packages.
- Target `/updater/version` responses are application-owned identity probes;
  Updater health is independent and cannot substitute for them.

The Agent consumes the strict v2 lease, progress, result, and mutation-grant
envelopes from the pinned Contracts authority. Desired operations are a closed
typed union; unknown operations, legacy claim bodies, cacheable responses, and
responses that do not confirm contract major 2 fail closed. See
[`docs/contracts-boundary.md`](docs/contracts-boundary.md).

## Existing-host compatibility

Wave 1 preserves the existing root-owned identity, policy, journal, A/B slot,
socket, and state paths. A normal runtime upgrade must use the version-matched
installer and must not issue a new Configure Token or delete recovery state.

## Local development

```text
GOMAXPROCS=2 go test -p 1 ./internal/probe ./internal/hostruntime ./cmd/autostream-updater-agent ./cmd/autostream-local-executor
GOMAXPROCS=2 go vet -p 1 ./internal/probe ./internal/hostruntime ./cmd/autostream-updater-agent ./cmd/autostream-local-executor
```

Root, systemd, installer, and Docker checks run in required CI fixtures. Their
evidence gates require each exact source-backed test to report one run, one
pass, no failures, and no skips; a missing or renamed test therefore fails CI.

Stable `vX.Y.Z` tags use the versioned release workflow described in
[`docs/release.md`](docs/release.md). The workflow waits for successful CI on
the exact tag commit, builds the Linux amd64 and arm64 bundles once, verifies
the manifests and every checksum layer, creates GitHub artifact attestations,
and publishes a new GitHub Release. It never creates or moves a tag, overwrites
an existing Release, or deploys to production. The separate manual workflow is
a build rehearsal and never publishes.
