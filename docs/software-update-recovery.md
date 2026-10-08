# Software update claim recovery

The Control Panel owns the central job, authorization and lease generation.
Its ordinary cancel operation accepts queued jobs only. Lease expiry does not
turn an already claimed job back into a queued job. An empty local active
cursor therefore cannot reclaim that job through ordinary polling.

Use a released, verified, version-matched Agent/Local Executor pair that
includes these recovery commands. Release verification and host installation
are separate operator actions. The candidate CI fixture version is not release
authority.

## Introducing the fixed runtime

A central active software job can block the Updater self-update lane. In that
case, use the selected release's normal verified Updater installer with
`--upgrade` only if its local preflight accepts the exact installed pair and
state. It preserves identity, policy, slots, journal and root state. A local
pending mutation or unresolved recovery marker must still block the upgrade.
Do not infer that central progress 0 proves local absence.

The compiled compatibility floor is Control Panel v2.0.0. The normal installer
still requires exact stable artifact identity, matching Agent/Executor,
checksums, protocol compatibility and health/rollback proof. Verify the
published release provenance separately before invoking the installer. It
does not reconfigure the host or replace its ownership. After installation,
verify both binaries report the selected release and commit before recovery.

## Claimed job without a saved software plan

Start with read-only inspection while the matching pair is running. Reread only the exact central
job and its original target, current/target versions, configuration revision,
ownership epoch and current lease generation. Run the following bounded
commands as the installed `autostream-host-agent` service account.

This is a synthetic example; replace each metadata value with that exact
job's authenticated values. The canonical identity path is fixed by the
installed source and must not be replaced with another config.

```sh
sudo -u autostream-host-agent /usr/local/bin/autostream-host-agent inspect-software-claim \
  --job-id example-stopped-job --lease-generation 1 \
  --target-id control-panel --current-version v2.0.0 --target-version v2.0.1 \
  --config-revision 1 --ownership-epoch 3
```

Inspection performs authenticated policy reads and a closed root read-only
operation. It supplies no credential, URL, path or shell to the Executor. It
requires a stable matching installed pair, the original configuration and
ownership, a valid nonexecuting local cursor or no cursor, and no ambiguous
root state. Requested-job root records, even terminal ones, and unrelated
nonterminal state prevent a no-mutation proof. Unrelated verified terminal
history is retained. Inspection does not claim or report the job.

Review the no-mutation proof before stopping the managed non-root Agent so its
lifecycle lock becomes available. Keep the matching Local Executor and socket
active. The recovery command repeats the proof after the Agent stops:

```sh
sudo systemctl stop autostream-host-agent.service
sudo -u autostream-host-agent /usr/local/bin/autostream-host-agent recover-software-claim \
  --job-id example-stopped-job --lease-generation 1 \
  --target-id control-panel --current-version v2.0.0 --target-version v2.0.1 \
  --config-revision 1 --ownership-epoch 3
```

Recovery retains a bounded local intent, repeats root proof and reclaims only
that exact central job with its current generation. A fresh lease for a
nonterminal job permits a failed report without download, Stage, mutation grant
or Apply. The internal reason is `software_claim_orphan_recovered`; the V2
contract records the public code `execution_failed`. The receipt records this
accepted result only when report acceptance was directly observed. An already
terminal clear, including recovery after a lost report acknowledgment, records
no accepted result and sends no additional failed report. Read the actual
terminal status and code from the authenticated CP rather than inferring an
outcome or internal reason from the clear. The original central record remains.
Fresh lease identity, command, configuration and
policy mismatches refuse reporting. A same-job first progress acknowledgment
loss is handled only after the exact pending report and root absence have
been proven; foreign or terminal pending reports are refused.

If a claim response is lost, keep the intent and cursor. Reread this same job's
generation; do not increment it yourself. Repeat `recover-software-claim`
with that exact reread value and `--confirm-current-generation`. This explicit
confirmation also handles a transport failure that did not advance central
generation. Terminal response loss retains state until the exact structured
same-job terminal proof permits settling the cursor and marker. Other host
mutations remain blocked while the marker is unsettled.

Do not remove a previous settled marker to recover another job. The runtime
requires its exact authenticated clear receipt and preserves its raw bytes in
immutable history before replacing the current intent. Root inspection checks
the new, previous and linked jobs for execution records, including terminal
records. A legacy settled marker without a receipt permits only the same-job
historical check. Missing or unsafe history, changed authority, exhausted
history bounds, or uncertain persistence must stop a successor recovery.

Read back the actual terminal outcome, preserved identity, exact clear receipt,
settled marker and local cursor convergence. A directly observed failed report
must agree with the public `failed / execution_failed` result. A clear-only
receipt does not establish that result or its internal reason. After exact
recovery convergence, start the Agent and read the CP's actual current version.
Create a CP-only job through the normal Control Panel flow only if an update
is still needed; do not resubmit an already applied version.

```sh
sudo systemctl start autostream-host-agent.service
```

## Existing original software plan

A saved plan, staged state or uncertain application mutation cannot use the
no-mutation terminal procedure. Ordinary same-job recovery retains its
original plan and uses a fresh lease to reconcile, without restaging or
reapplying. If CP advanced the reclaim generation but that response was lost,
stop the Agent and reread only that exact central job's current generation.

The explicit entry below accepts a generation gap only after validating the
original saved plan, frozen authority and current authenticated policy:

```sh
sudo -u autostream-host-agent /usr/local/bin/autostream-host-agent recover-software-plan \
  --job-id example-stopped-job --lease-generation 2 \
  --target-id control-panel --current-version v2.0.0 --target-version v2.0.1 \
  --config-revision 1 --ownership-epoch 3
```

It atomically adopts the fresh exact lease and invalidates only its old pending
reports, then enters reconcile with the original plan. It performs no download,
Stage or Apply. An uncertain claim preserves the original journal bytes and
requires another exact read. A changed digest, policy, target, owner, version,
plan, unknown state or unsettled terminal marker fails closed.

Accept the original plan's actual root terminal result and authenticated CP
clear, then confirm active plan, cursor and pending reports have converged.
This path does not require a terminal-only marker and must not replace an
applied success with a failed result. Read the CP's actual version before
deciding whether a new update job is needed.

If these supported checks refuse recovery, preserve the evidence and resolve
the specific missing proof. Do not edit the DB, lease, journal, ledger, slots,
policy, ownership or configuration to make the check pass. No command here
authorizes a production operation or a release publication by an automation
agent.
