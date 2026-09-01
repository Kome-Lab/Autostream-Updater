# Local Executor security contract

The Local Executor is the only root process in AutoStream Updater. Its
authority is intentionally narrower than the Agent's control-plane view.

## Transport and peer identity

- systemd socket activation owns
  `/run/autostream-local-executor/executor.sock`;
- the socket is `root:autostream-host-agent 0660` inside a `0750` directory;
- Linux requests are accepted only after `SO_PEERCRED` identifies the exact
  UID/GID pinned in the root policy;
- frames are bounded, strict JSON, versioned, and reject unknown fields and
  trailing data;
- no operation accepts a shell command, argv vector, environment map,
  arbitrary unit, arbitrary image repository, URL, or privileged path.

## Root policy

The root-owned policy is an installer projection, not a Control Panel command
payload. It selects one of the fixed service profiles and binds:

- service and execution-host identity;
- deployment mode and expected application identity;
- source, projection, endpoint, configuration, and executor revisions;
- fixed systemd or Docker runtime locations;
- canonical policy and artifact digests.

Every mutation re-loads this policy, verifies ownership/mode, and re-checks
revision and digest fences immediately before the irreversible step.

## Supported operations

- application identity probe;
- staged systemd or digest-pinned Docker software update;
- bounded systemd or Docker port reconfiguration;
- paired Agent/Executor A/B self-update and recovery;
- staged Agent runtime-token rotation and emergency recovery.

Operations use durable private ledgers and deterministic rollback. Result and
error surfaces are allow-listed. Bearer values use a redacting type and must
not appear in formatted values, JSON logs, or errors.

## Application Identity Probe

The executor calls exactly `http://<loopback>:<port>/updater/version`. It does
not follow redirects or use configured proxies. The response is bounded and
must be strict JSON containing only:

```json
{
  "version": "v1.2.3",
  "service_id": "worker-a",
  "service_type": "worker",
  "config_revision": 7
}
```

`Cache-Control` must contain `no-store`. Service identity, type, configuration
revision, process/cgroup ownership, and listener binding must all match the
root policy before the observation is returned.

## Ownership boundaries

The Local Executor owns only privileged local execution and its recovery
state. It has no database dependency, no SSH listener/client, no central
coordinator or supervisor, and no Control Panel internal import. Central
authorization, desired state, job history, and audit records remain in the
Control Panel.
