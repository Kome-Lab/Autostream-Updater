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
