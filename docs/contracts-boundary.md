# Contracts boundary

Wire authority is `Kome-Lab/Autostream-Contracts`. Updater must consume its
types directly and must not define a consumer-local duplicate.

The pinned v2 `UpdaterCommandEnvelope` identifies the command, issuer,
idempotency key, canonical digest, authorization, target, revision, fence, and
one closed `UpdaterDesiredOperation`. Software update, port reconfiguration,
bootstrap, and host self-update each use their reviewed typed payload; there is
no generic shell, argv, environment, path, URL, or credential field.

The Agent accepts only a strict Contracts-valid lease whose command digest,
target, desired revision, fence, capability, expiry, and one-time authorization
agree. Progress, terminal result, and Local Executor mutation grants remain
bound to that same lease. Legacy claim bodies and unconfirmed or cacheable v2
responses are rejected without fallback.

Software update preserves distinct revision authorities. The wire command is
not rewritten to match an internal policy revision:

| Value | Authority and use |
| --- | --- |
| C | Application configuration; lease `desired_revision`, target `expected_config_revision`, progress and terminal result |
| S | Authenticated source policy revision |
| P | Authenticated projection revision; internal job policy and ownership fence |
| E | Authenticated Local Executor policy revision; executor fence |
| F | Ownership epoch; lease and mutation ownership |
| D | Root policy digest; fixed in the original local software plan |

The Agent binds a fresh software lease to its authenticated target and policy,
then persists that binding. Recovery retains the original command digest,
configuration, versions, ownership and policy authority. A legacy cursor without
this binding may acquire it only from a valid original saved plan whose policy
digest still matches the authenticated policy. A cursor without such a plan can
only use the bounded terminal recovery described in
[`software-update-recovery.md`](software-update-recovery.md).
