# Contracts boundary

Wire authority is `Kome-Lab/Autostream-Contracts`. Updater must consume its
types directly and must not define a consumer-local duplicate.

The current v2 `UpdaterCommandEnvelope` identifies the command, issuer,
idempotency key, canonical digest, authorization, target, revision, and fence.
It does not carry a typed desired operation payload containing the target
version or the bounded data required by software update, port reconfiguration,
bootstrap, or self-update execution.

Consequently Wave 1 keeps authenticated v2 command intake fail-closed and
unconnected. Agent observation, existing-host recovery, Local Executor policy,
application identity probing, and host-side runtime primitives are extracted
without inventing a wire shape. Connection requires a reviewed additive
Contracts correction and matching Control Panel adapter.

