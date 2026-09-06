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

Docker Node listener approval remains an inline Compose configuration. At
execution, the Local Executor stores the exact non-secret listener bytes under
`/var/lib/autostream-local-executor/docker-listener-configs/<service>/<sha256>.json`
and derives a file-backed Compose model for the read-only container. Generations
are root-owned (directories `0700`, files `0444`) and survive container/daemon
restarts and rollback. The initial limit is 256 generations per service, each
at most 64 KiB. At capacity new generations fail closed; existing generations
remain reusable. No automatic garbage collection is performed; only an explicit
purge may remove generations after their runtime and rollback uses have ended.

## Port reconfiguration

Port contract version 2 supports a local listener change, or a local change
with an advertised endpoint port change. Advertised-only changes are rejected.
Docker published and container ports remain separate inputs in the existing
fixed Node profile. The mapping environment digest and the derived container
listener configuration keep their existing, distinct byte representations.

The Agent advertises this capability only after an actual root probe confirms
the installed policy on disk and in memory. Each job retains immutable before,
target, and rollback snapshots. The Local Executor consumes the exact grant,
rechecks the baseline, then atomically writes and securely reloads the fixed
root policy before changing the listener. The first write must begin within
30 seconds measured from immediately before grant consumption, also bounded
by authorization expiry. Forward and rollback each have a 120-second budget.

Verified results retain `applied`, `unchanged`, or `rolled_back` and the first
observation time. A no-op requires fresh proof and performs no policy write or
restart. Rollback restores the original functional ports using newly generated
configuration bytes at revision C+2. A failed rollback retains the recovery
hold and failure observation without occupying the accepted-result slot.
After a disconnect or restart, a fresh authorization for the same job may
observe a completed target or recover toward the saved rollback snapshot;
it never repeats an unproven forward operation. Other host mutations remain
blocked until that recovery converges.

The existing port ledger stores the three bounded policy candidates and
recovery latch. No replacement policy, privileged path, service, command, or
runtime credential can be supplied by a port job. Installer policy ownership,
fixed paths, and the existing Docker listener materialization remain in use.

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
