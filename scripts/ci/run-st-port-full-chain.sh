#!/usr/bin/env bash
set -euo pipefail

# Both real runtime suites share this one deadline. Only disposable CI
# namespaces are used, with no host identity, policy, ledger, DB or socket.
die() { printf 'st-port-full-chain: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 3 ]] || die 'expected CP test binary, canonical Worker binary, evidence directory'
[[ ${GITHUB_ACTIONS:-} == true ]] || die 'this privileged workload is restricted to the authorized CI job'
for command in docker go timeout realpath git date; do command -v "${command}" >/dev/null || die "missing ${command}"; done
readonly deadline_epoch="$(( $(date +%s) + 36 * 60 ))"
remaining_seconds() {
  local remaining=$(( deadline_epoch - $(date +%s) ))
  [[ ${remaining} -gt 0 ]] || die 'shared full-chain deadline exhausted'
  printf '%d' "${remaining}"
}
run_bounded() {
  local remaining
  remaining="$(remaining_seconds)" || return 1
  timeout --signal=TERM --kill-after=10s "${remaining}s" "$@"
}
readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly cp_binary="$(realpath -- "$1")"
readonly worker_binary="$(realpath -- "$2")"
mkdir -p -- "$3"
readonly evidence="$(realpath -- "$3")"
[[ -f ${cp_binary} && ! -L ${cp_binary} && -f ${worker_binary} && ! -L ${worker_binary} ]] || die 'immutable executable input is unavailable'
mkdir -p -- "${evidence}/go" "${evidence}/artifacts" "${evidence}/processes" "${evidence}/build"
for component in CONTROL_PANEL UPDATER CONTRACTS WORKER; do
  name="AUTOSTREAM_ST_PORT_${component}_SHA"
  value="${!name:-}"
  [[ ${value} =~ ^[0-9a-f]{40}$ ]] || die "missing immutable ${component} source identity"
done
[[ $(git -C "${repository_root}" rev-parse HEAD) == "${AUTOSTREAM_ST_PORT_UPDATER_SHA}" ]] || die 'Updater source differs from the declared source set'
[[ ${AUTOSTREAM_ST_PORT_WORKER_VERSION:-} =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die 'missing exact Worker fixture version'
readonly work="$(mktemp -d "${RUNNER_TEMP:?}/st-port-full-chain.XXXXXXXX")"
readonly image="autostream-st-port-chain:${AUTOSTREAM_ST_PORT_UPDATER_SHA}"
container_id=''
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n ${container_id} ]]; then timeout 30s docker rm --force -- "${container_id}" >/dev/null 2>&1 || true; fi
  case "${work}" in "${RUNNER_TEMP}"/st-port-full-chain.*) rm -rf -- "${work}" ;; *) die 'unsafe fixture cleanup path' ;; esac
  exit "${status}"
}
trap cleanup EXIT

(
  cd -- "${repository_root}"
  export GOMAXPROCS=2
  run_bounded go test -c -p 1 ./internal/hostruntime -o "${work}/hostruntime.test"
  CGO_ENABLED=0 run_bounded go build -p 1 -trimpath -o "${work}/docker-port-fixture" ./internal/hostruntime/testdata/docker-port-fixture
) > "${evidence}/build/updater-compile.log" 2>&1

# Existing immutable installer base. Inner Docker uses its own daemon and
# normal TLS trust; the host Docker socket is never mounted.
run_bounded docker build --tag "${image}" - > "${evidence}/build/runtime-image.log" 2>&1 <<'DOCKERFILE'
FROM ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    systemd systemd-sysv dbus mariadb-server mariadb-client ca-certificates openssl python3 \
    docker.io docker-compose-v2 docker-registry \
    fonts-noto-cjk libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKERFILE

prepare_registry() {
  # All writes are inside the fresh, network-none namespace. A private CA with
  # SAN ghcr.io is installed in Docker's normal per-registry trust directory.
  run_bounded docker exec --interactive "${container_id}" /bin/bash -eu <<'REGISTRY' || return 1
umask 077
install -d -m 0700 /run/autostream-st-port-full-chain/registry-private
install -d -m 0755 /etc/docker/certs.d/ghcr.io
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=ST-PORT isolated Docker registry' \
  -addext 'subjectAltName=DNS:ghcr.io' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout /run/autostream-st-port-full-chain/registry-private/tls.key \
  -out /run/autostream-st-port-full-chain/registry-private/tls.crt >/dev/null 2>&1
install -m 0644 /run/autostream-st-port-full-chain/registry-private/tls.crt /etc/docker/certs.d/ghcr.io/ca.crt
printf '%s\n' '127.0.0.1 ghcr.io' >> /etc/hosts
cat > /run/autostream-st-port-full-chain/registry-private/config.yml <<'CONFIG'
version: 0.1
log:
  level: error
storage:
  filesystem:
    rootdirectory: /run/autostream-st-port-full-chain/registry-private/data
http:
  addr: 127.0.0.1:443
  tls:
    certificate: /run/autostream-st-port-full-chain/registry-private/tls.crt
    key: /run/autostream-st-port-full-chain/registry-private/tls.key
CONFIG
cat > /run/systemd/system/st-port-registry.service <<'UNIT'
[Unit]
Description=ST-PORT isolated TLS registry fixture
[Service]
Type=simple
ExecStart=/usr/bin/docker-registry serve /run/autostream-st-port-full-chain/registry-private/config.yml
Restart=no
TimeoutStartSec=30
TimeoutStopSec=15
UNIT
systemctl stop docker-registry.service
systemctl daemon-reload
systemctl start st-port-registry.service
systemctl start docker.service
docker info >/dev/null
docker compose version >/dev/null
REGISTRY
}

capture_boot_failure() {
  local runtime=$1
  # PID 1 has not received application inputs or credentials at this point.
  run_bounded docker inspect --format \
    '{"status":{{json .State.Status}},"running":{{json .State.Running}},"oom_killed":{{json .State.OOMKilled}},"exit_code":{{json .State.ExitCode}},"error":{{json (printf "%.1024s" .State.Error)}}}' \
    "${container_id}" > "${evidence}/artifacts/boot-${runtime}-state.json" 2>/dev/null || true
  run_bounded docker logs --tail 80 --timestamps "${container_id}" \
    > "${evidence}/artifacts/boot-${runtime}.log" 2>&1 || true
}

record_runtime_phase() {
  printf '{"schema_version":1,"runtime":"%s","entered_phase":"%s"}\n' \
    "$1" "$2" > "${evidence}/artifacts/runtime-phase-$1.json"
}

run_runtime() {
  local runtime=$1 parent_test=$2 docker_selected=0 test_seconds
  if [[ ${runtime} == docker ]]; then docker_selected=1; fi
  # Keep Docker's cgroup mount scoped to this private namespace. A bind of the
  # host hierarchy would disagree with /proc/1/cgroup and expose sibling groups.
  record_runtime_phase "${runtime}" container_create
  container_id="$(run_bounded docker create --privileged --cgroupns=private --network none \
    --cpus 2 --memory 4g --pids-limit 1024 \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    --mount "type=bind,source=${evidence},target=/evidence" "${image}")" || return 1
  [[ ${container_id} =~ ^[0-9a-f]{64}$ ]] || return 1
  record_runtime_phase "${runtime}" container_start
  if ! run_bounded docker start "${container_id}" >/dev/null; then
    capture_boot_failure "${runtime}"
    return 1
  fi
  record_runtime_phase "${runtime}" systemd_ready
  for _ in $(seq 1 60); do
    if run_bounded docker exec "${container_id}" systemctl show-environment >/dev/null 2>&1; then break; fi
    if [[ $(run_bounded docker inspect --format '{{.State.Running}}' "${container_id}") != true ]]; then
      capture_boot_failure "${runtime}"
      return 1
    fi
    run_bounded sleep 1 || return 1
  done
  if ! run_bounded docker exec "${container_id}" systemctl show-environment >/dev/null 2>&1; then
    capture_boot_failure "${runtime}"
    return 1
  fi
  record_runtime_phase "${runtime}" cgroup_view
  if ! run_bounded docker exec "${container_id}" /bin/sh -ec \
    'cat /proc/1/cgroup; findmnt -n -t cgroup,cgroup2 -o TARGET,FSTYPE,OPTIONS; test -w /sys/fs/cgroup' \
    > "${evidence}/artifacts/cgroup-${runtime}.log" 2>&1; then
    capture_boot_failure "${runtime}"
    return 1
  fi
  record_runtime_phase "${runtime}" input_copy
  run_bounded docker exec "${container_id}" /usr/bin/install -d -m 0755 /opt/st-port-input /run/autostream-st-port-full-chain || return 1
  run_bounded docker cp "${work}/hostruntime.test" "${container_id}:/opt/st-port-input/hostruntime.test" || return 1
  run_bounded docker cp "${work}/docker-port-fixture" "${container_id}:/opt/st-port-input/docker-port-fixture" || return 1
  run_bounded docker cp "${cp_binary}" "${container_id}:/opt/st-port-input/control-panel.test" || return 1
  run_bounded docker cp "${worker_binary}" "${container_id}:/opt/st-port-input/autostream-worker" || return 1
  run_bounded docker exec "${container_id}" chmod 0755 /opt/st-port-input/hostruntime.test /opt/st-port-input/control-panel.test /opt/st-port-input/autostream-worker /opt/st-port-input/docker-port-fixture || return 1
  record_runtime_phase "${runtime}" mariadb_start
  if ! run_bounded docker exec "${container_id}" systemctl start mariadb; then
    run_bounded docker exec "${container_id}" systemctl show mariadb \
      --property=ActiveState,SubState,Result,ExecMainStatus \
      > "${evidence}/artifacts/mariadb-${runtime}-state.log" 2>&1 || true
    return 1
  fi
  record_runtime_phase "${runtime}" mariadb_schema
  run_bounded docker exec "${container_id}" mariadb --protocol=socket --user=root --execute='CREATE DATABASE st_port_chain_full CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;' || return 1
  run_bounded docker exec --interactive "${container_id}" /bin/bash -eu <<'BOOTSTRAP' || return 1
umask 077
printf '%s\n' 'root@unix(/run/mysqld/mysqld.sock)/st_port_chain_full?parseTime=true&loc=UTC&charset=utf8mb4' > /run/autostream-st-port-full-chain/dsn
printf '%s\n' 'ST-PORT disposable integration namespace v1' > /run/autostream-st-port-full-chain/isolated
chmod 0644 /run/autostream-st-port-full-chain/isolated
BOOTSTRAP
  if [[ ${runtime} == docker ]]; then
    record_runtime_phase "${runtime}" docker_daemon_registry
    prepare_registry > "${evidence}/build/docker-registry.log" 2>&1 || return 1
  fi
  test_seconds="$(remaining_seconds)" || return 1
  [[ ${test_seconds} -gt 10 ]] || return 1
  test_seconds=$((test_seconds - 5))
  record_runtime_phase "${runtime}" required_test
  set +e
  run_bounded docker exec \
    --env GOMAXPROCS=2 --env TZ=UTC \
    --env AUTOSTREAM_ST_PORT_FULL_CHAIN=1 \
    --env "AUTOSTREAM_ST_PORT_DOCKER_FULL_CHAIN=${docker_selected}" \
    --env AUTOSTREAM_DOCKER_PORT_FIXTURE_BINARY=/opt/st-port-input/docker-port-fixture \
    --env AUTOSTREAM_ST_PORT_CP_TEST_BINARY=/opt/st-port-input/control-panel.test \
    --env AUTOSTREAM_ST_PORT_WORKER_BINARY=/opt/st-port-input/autostream-worker \
    --env "AUTOSTREAM_ST_PORT_WORKER_VERSION=${AUTOSTREAM_ST_PORT_WORKER_VERSION}" \
    --env AUTOSTREAM_ST_PORT_DSN_FILE=/run/autostream-st-port-full-chain/dsn \
    --env AUTOSTREAM_ST_PORT_EVIDENCE=/evidence \
    --env "AUTOSTREAM_ST_PORT_CONTROL_PANEL_SHA=${AUTOSTREAM_ST_PORT_CONTROL_PANEL_SHA}" \
    --env "AUTOSTREAM_ST_PORT_UPDATER_SHA=${AUTOSTREAM_ST_PORT_UPDATER_SHA}" \
    --env "AUTOSTREAM_ST_PORT_CONTRACTS_SHA=${AUTOSTREAM_ST_PORT_CONTRACTS_SHA}" \
    --env "AUTOSTREAM_ST_PORT_WORKER_SHA=${AUTOSTREAM_ST_PORT_WORKER_SHA}" \
    "${container_id}" /opt/st-port-input/hostruntime.test \
      -test.v=test2json "-test.run=^${parent_test}$" -test.count=1 "-test.timeout=${test_seconds}s" \
    2>&1 | go tool test2json -t -p github.com/Kome-Lab/Autostream-Updater/internal/hostruntime > "${evidence}/go/full-chain-${runtime}.json"
  local statuses=("${PIPESTATUS[@]}")
  set -e
  printf '{"schema_version":1,"runtime":"%s","runtime_exit":%d,"event_conversion_exit":%d,"test_execution":"real_process"}\n' \
    "${runtime}" "${statuses[0]}" "${statuses[1]}" > "${evidence}/artifacts/runtime-status-${runtime}.json" || return 1
  # Only the credential-screened public artifacts become runner-readable.
  # Private process logs and every runtime credential retain their own modes.
  run_bounded docker exec "${container_id}" chmod -R a+rX /evidence/artifacts || return 1
  run_bounded docker rm --force -- "${container_id}" >/dev/null || return 1
  container_id=''
  [[ ${statuses[0]} -eq 0 && ${statuses[1]} -eq 0 ]]
}

# An independent runtime still runs after the first suite fails, provided the
# original shared deadline permits it. Each selected suite runs exactly once.
systemd_status=0
docker_status=0
run_runtime systemd TestSTPortFullChain || systemd_status=$?
if [[ -n ${container_id} ]]; then
  if run_bounded docker rm --force -- "${container_id}" >/dev/null; then
    container_id=''
  else
    docker_status=1
  fi
fi
if [[ -z ${container_id} ]]; then
  run_runtime docker TestSTPortFullChainDocker || docker_status=$?
fi
printf '{"schema_version":1,"systemd_exit":%d,"docker_exit":%d,"shared_budget_seconds":2160}\n' \
  "${systemd_status}" "${docker_status}" > "${evidence}/artifacts/runtime-status.json"
[[ ${systemd_status} -eq 0 && ${docker_status} -eq 0 ]]
