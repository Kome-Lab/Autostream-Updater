# Runtime and migration boundary

AutoStream Updater is split into two local processes:

- the Agent is the existing `autostream-host-agent` service identity, built
  from `cmd/autostream-updater-agent`, and must run as the dedicated non-root
  `autostream-host-agent` account;
- the Local Executor is built from `cmd/autostream-local-executor`, runs as
  root, and accepts only the fixed operations in its versioned Unix-domain
  socket protocol.

The stable installed names and filesystem layout are deliberate migration
compatibility. Moving the runtime to an independent repository must not reset
identity, journal, A/B, or recovery state.

## Stable paths

| Purpose | Path |
| --- | --- |
| Agent identity | `/etc/autostream-host-agent/identity.json` |
| Agent state and journal | `/var/lib/autostream-host-agent` |
| Executor policy | `/etc/autostream-local-executor/policy.json` |
| Executor durable state | `/var/lib/autostream-local-executor` |
| Executor socket | `/run/autostream-local-executor/executor.sock` |
| Shared lifecycle locks | `/run/autostream-updater` |
| Paired A/B runtime | `/opt/autostream/host-agent/{slots,current}` |

The identity remains exactly four fields: `panel_url`, `node_id`,
`runtime_token`, and `service_name`. It is root-owned and readable only by the
Agent group. Runtime tokens are never accepted through argv or environment
variables.

## Installation

Release archives carry both binaries, the four systemd units/templates, the
tmpfiles policy, and the paired installers. The build-only workflow emits the
archive, per-archive checksums, the immutable host manifest, and `SHA256SUMS`;
it never creates a tag or GitHub Release.

For an existing host, use the archive's paired installer in upgrade mode. It
keeps the canonical identity and policy, holds the permanent lifecycle locks,
stages both binaries into the inactive slot, validates exact binary identity,
and switches the fixed `current` link. Do not delete either state directory or
reissue a Configure Token for a normal repository migration.

Initial provisioning is a separate, operator-controlled action. The Agent
configuration exchange reads its one-time token from a protected input stream,
projects the root policy, and activates only after the installed files have
been re-read and validated.

## Recovery

The journal, mutation ledgers, runtime-token rotation state, and host
self-update state are durable and private. An interrupted upgrade is recovered
by the version-matched Local Executor in the A/B slot. A replacement proof must
complete before the embedded Control Panel runtime is removed.

The Updater repository does not own central job records, service inventory,
authorization, or audit history. Those remain Control Panel responsibilities.
The v2 desired-command consumer is fail-closed until Contracts publishes the
typed payload described in `contracts-boundary.md`.

## Verification

Normal developer verification is unprivileged:

```text
GOMAXPROCS=2 go test -p 1 ./...
GOMAXPROCS=2 go vet -p 1 ./...
GOMAXPROCS=2 go build -p 1 ./cmd/autostream-updater-agent ./cmd/autostream-local-executor
```

Root-owned filesystem, systemd, and Docker daemon proofs run only in the
dedicated Linux CI fixtures.
