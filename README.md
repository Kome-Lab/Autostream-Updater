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

The v2 command intake is intentionally not connected yet. The current
Contracts authority does not carry the typed desired mutation payload required
to execute software, port, bootstrap, or self-update operations. See
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

Root, systemd, and Docker checks run only in CI fixtures. Release automation is
build-only in Wave 1 and does not publish GitHub releases or mutate tags.
