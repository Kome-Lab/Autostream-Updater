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
| Agent identity | `/etc/autostream/updater/agent.yaml` |
| Staged Agent identity | `/etc/autostream/updater/agent.staged.yaml` |
| Interrupted staged-identity wipe | `/etc/autostream/updater/.agent.staged.wipe` |
| Agent state and journal | `/var/lib/autostream-host-agent` |
| Executor policy | `/etc/autostream/updater/executor-policy.json` |
| Executor-only Docker credentials | `/etc/autostream-local-executor/docker/config.json` |
| Executor durable state | `/var/lib/autostream-local-executor` |
| Executor socket | `/run/autostream-local-executor/executor.sock` |
| Shared lifecycle locks | `/run/autostream-updater` |
| Paired A/B runtime | `/opt/autostream/host-agent/{slots,current}` |

The identity remains exactly four fields: `panel_url`, `node_id`,
`runtime_token`, and `service_name`. It is root-owned and readable only by the
Agent group. Runtime tokens are never accepted through argv or environment
variables.

identityの永続形式は4項目のYAMLのみです。JSON identity、追加項目、重複項目、
複数documentは拒否し、旧パスへのfallbackは行いません。runtime-token rotationも
同じYAML decoderを使用し、tokenそのものをエラーや診断へ出力しません。

installerは`acl`パッケージの`getfacl`／`setfacl`を必要とします。
`/etc/autostream`の既存所有者・modeや隣接サービスの秘密情報は変更せず、必要な場合のみ
専用Host Agent userへtraverse専用ACLを追加します。失敗時は同一inode・ACLを確認して
追加分を元へ戻します。identity directoryはroot:autostream-host-agent 0750、
identityは0640、Executor policyはroot:root 0600です。identity directoryへの他user用ACLや
default ACLは許可しません。`/etc/autostream-local-executor`はDocker credentials用の
root-only directoryとして独立して残ります。
通常uninstallはidentity、state、traverse ACLを保持します。明示的な`--purge`だけが、
UID再利用前に専用Host Agent userのtraverse ACLをCAS確認付きで除去します。

Agent／Executorのsystemd mount namespaceでは`/etc/autostream`を空のread-only filesystemで
隠し、`updater`だけをbindします。Agentはread-only、Executorはidentity rotation用に
read-writeです。共有parentを`InaccessiblePaths`に指定して子directoryを再公開する構成は
使いません。A/B recovery unitは引き続きidentityと全サービス秘密情報へアクセスしません。

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
by the version-matched Local Executor in the A/B slot. The exact-SHA replacement
proof must complete before the embedded Control Panel runtime is removed.
After removal, ordinary CI pins the exact Control Panel adapter revision,
executes its absence oracle, proves the strict v2 boundary and fail-closed
mixed-fleet behavior, and produces a verified exact-SHA Updater rollback
candidate. The final evidence preserves the successful pre-removal authority;
an embedded fallback remains prohibited.

The Updater repository does not own central job records, service inventory,
authorization, or audit history. Those remain Control Panel responsibilities.
The v2 desired-command consumer uses the pinned typed Contracts payload
described in `contracts-boundary.md`; unknown, legacy, cacheable, or
contract-major-mismatched claims fail closed without an embedded fallback.

## Verification

Normal developer verification is unprivileged:

```text
GOMAXPROCS=2 go test -p 1 ./...
GOMAXPROCS=2 go vet -p 1 ./...
GOMAXPROCS=2 go build -p 1 ./cmd/autostream-updater-agent ./cmd/autostream-local-executor
```

Root-owned filesystem, systemd, and Docker daemon proofs run only in the
dedicated Linux CI fixtures.
