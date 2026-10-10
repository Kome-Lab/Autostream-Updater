#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Extend the existing ST-PORT process/IPC oracle. All identities, systemd,
# sockets, MariaDB and release provider live in fresh network-none namespaces.
die() { printf 'software-update-full-chain: %s\n' "$*" >&2; exit 1; }
[[ $# == 2 && ${GITHUB_ACTIONS:-} == true ]] || die 'requires the authorized CI job, fixed CP SHA and evidence directory'
readonly cp_sha=$1
case "${cp_sha}" in
  0315845e3af01eff6b97c6164db3ddc3109b55af) readonly cp_product_version=v2.0.0 ;;
  9c75188147daf8435d005651a8266ae31ce39653) readonly cp_product_version=v2.0.1 ;;
  *) die 'CP source is outside the closed compatibility matrix' ;;
esac
for command in git go docker timeout realpath python3 date; do
  command -v "${command}" >/dev/null || die "missing ${command}"
done
[[ $(uname -m) == x86_64 ]] || die 'this fixture executes the declared Linux amd64 artifact only'
readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly updater_sha="${GITHUB_SHA:?}"
readonly before_sha=b1c94afe2ee2fe8854abb12e2c85565a1bd448dc
readonly installer_before_sha=f72d1bddb712eeb64bab2b852b648c2c6b0f4641
[[ ${updater_sha} =~ ^[0-9a-f]{40}$ && $(git -C "${repository_root}" rev-parse HEAD) == "${updater_sha}" ]] || die 'current checkout is not the final declared Actions SHA'
[[ -z $(git -C "${repository_root}" status --porcelain --untracked-files=no) ]] || die 'candidate product source is modified before compilation'
[[ ! -e $2 ]] || die 'evidence directory already exists; preserve the earlier attempt'
mkdir -p -- "$2"
readonly evidence="$(realpath -- "$2")"
readonly temporary_root="$(realpath -- "${RUNNER_TEMP:?}")"
readonly work="$(mktemp -d "${temporary_root}/software-update-full-chain.XXXXXXXX")"
readonly image="autostream-software-update-chain:${updater_sha}"
readonly deadline_epoch="$(( $(date +%s) + 36 * 60 ))"
export GOMAXPROCS=2
container_id=''
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
remove_container() {
  if [[ -n ${container_id} ]]; then
    timeout 30s docker rm --force --volumes -- "${container_id}" >/dev/null 2>&1 || return 1
    container_id=''
  fi
}
cleanup() {
  local status=$?
  trap - EXIT
  remove_container || true
  case "${work}" in
    "${temporary_root}"/software-update-full-chain.*) rm -rf -- "${work}" ;;
    *) printf '%s\n' 'unsafe fixture cleanup path' >&2; exit 1 ;;
  esac
  exit "${status}"
}
trap cleanup EXIT
mkdir -p -- "${evidence}/build" "${evidence}/artifacts" "${work}/before-production" "${work}/candidate-production" "${work}/baseline-production" "${work}/repository"

checkout_fixed() {
  local remote=$1 sha=$2 destination=$3
  run_bounded git init --quiet "${destination}"
  run_bounded git -C "${destination}" remote add origin "${remote}"
  run_bounded git -C "${destination}" fetch --quiet --depth 1 origin "${sha}"
  run_bounded git -C "${destination}" checkout --quiet --detach FETCH_HEAD
  [[ $(git -C "${destination}" rev-parse HEAD) == "${sha}" ]]
}
checkout_fixed https://github.com/Kome-Lab/Autostream-Updater.git "${before_sha}" "${work}/before" > "${evidence}/build/before-checkout.log" 2>&1
checkout_fixed https://github.com/Kome-Lab/Autostream-Updater.git "${installer_before_sha}" "${work}/baseline" > "${evidence}/build/baseline-checkout.log" 2>&1
checkout_fixed https://github.com/Kome-Lab/Autostream-ControlPanel.git "${cp_sha}" "${work}/control-panel" > "${evidence}/build/cp-checkout.log" 2>&1
readonly before_tree="$(git -C "${work}/before" rev-parse 'HEAD^{tree}')"
readonly cp_tree="$(git -C "${work}/control-panel" rev-parse 'HEAD^{tree}')"
readonly updater_tree="$(git -C "${repository_root}" rev-parse 'HEAD^{tree}')"

# Only test-only process observation/delivery files are overlaid on b1. Its
# adapter, validator, root and production-command source bytes are unchanged.
for oracle in st_port_full_chain_harness_linux_test.go st_port_full_chain_process_linux_test.go \
  software_update_full_chain_process_linux_test.go software_update_full_chain_before_test.go; do
  cp -- "${repository_root}/internal/hostruntime/${oracle}" "${work}/before/internal/hostruntime/${oracle}"
done
for oracle in "${repository_root}"/testdata/software-update-cp-overlay/*_test.go; do
  [[ -f ${oracle} && ! -L ${oracle} ]]
  cp -- "${oracle}" "${work}/control-panel/internal/httpapi/$(basename -- "${oracle}")"
done
cp -a -- "${repository_root}/install" "${repository_root}/systemd" "${work}/repository/"
for input in internal/version/release_compatibility.go scripts/ci/host_runtime_compatibility.py \
  scripts/ci/run-software-update-installer-order.sh \
  authoring/install-autostream-updater-agent/artifact-verification.sh.inc \
  authoring/install-autostream-local-executor/artifact-verification.sh.inc; do
  mkdir -p -- "${work}/repository/$(dirname -- "${input}")"
  cp -- "${repository_root}/${input}" "${work}/repository/${input}"
done

readonly version_package=github.com/Kome-Lab/Autostream-Updater/internal/version
readonly build_date=2026-10-08T00:00:00Z
readonly before_flags="-X ${version_package}.Version=v2.0.0 -X ${version_package}.Commit=${before_sha} -X ${version_package}.BuildDate=${build_date}"
# v2.0.1 is a declared isolated candidate-fixture version, not a published
# fixed Updater release. Each binary still records the exact feature SHA.
readonly candidate_flags="-X ${version_package}.Version=v2.0.1 -X ${version_package}.Commit=${updater_sha} -X ${version_package}.BuildDate=${build_date}"
(
  cd -- "${work}/baseline"
  for binary in autostream-updater-agent autostream-local-executor; do
    output=${binary/updater-agent/host-agent}
    run_bounded go build -p 1 -trimpath \
      -ldflags "-X ${version_package}.Version=v2.0.1 -X ${version_package}.Commit=${installer_before_sha} -X ${version_package}.BuildDate=${build_date}" \
      -o "${work}/baseline-production/${output}" "./cmd/${binary}"
  done
  test -z "$(git status --porcelain --untracked-files=no)"
) > "${evidence}/build/baseline-compile.log" 2>&1
(
  cd -- "${work}/before"
  run_bounded go test -c -p 1 -ldflags "${before_flags}" -o "${work}/before-hostruntime.test" ./internal/hostruntime
  run_bounded go build -p 1 -trimpath -ldflags "${before_flags}" -o "${work}/before-production/autostream-host-agent" ./cmd/autostream-updater-agent
  run_bounded go build -p 1 -trimpath -ldflags "${before_flags}" -o "${work}/before-production/autostream-local-executor" ./cmd/autostream-local-executor
) > "${evidence}/build/before-compile.log" 2>&1
(
  cd -- "${repository_root}"
  run_bounded go test -c -p 1 -ldflags "${candidate_flags}" -o "${work}/hostruntime.test" ./internal/hostruntime
  run_bounded go build -p 1 -trimpath -ldflags "${candidate_flags}" -o "${work}/candidate-production/autostream-host-agent" ./cmd/autostream-updater-agent
  run_bounded go build -p 1 -trimpath -ldflags "${candidate_flags}" -o "${work}/candidate-production/autostream-local-executor" ./cmd/autostream-local-executor
) > "${evidence}/build/candidate-compile.log" 2>&1
(
  cd -- "${work}/control-panel"
  run_bounded go test -c -p 1 -ldflags "-X github.com/example/autostream-control-panel/internal/version.Version=${cp_product_version} -X github.com/example/autostream-control-panel/internal/version.Commit=${cp_sha}" \
    -o "${work}/control-panel.test" ./internal/httpapi
) > "${evidence}/build/cp-compile.log" 2>&1

python3 - "${repository_root}" "${work}" "${evidence}/artifacts/provenance.json" "${updater_sha}" "${updater_tree}" "${before_sha}" "${before_tree}" "${cp_sha}" "${cp_tree}" "${cp_product_version}" <<'PROVENANCE'
import hashlib, json, sys
from pathlib import Path
root, work, out = map(Path, sys.argv[1:4])
paths = [root / 'internal/hostruntime' / name for name in (
    'st_port_full_chain_harness_linux_test.go', 'st_port_full_chain_process_linux_test.go',
    'software_update_full_chain_process_linux_test.go', 'software_update_full_chain_before_test.go')]
paths += sorted((root / 'testdata/software-update-cp-overlay').glob('*_test.go'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
manifest = {
    'schema_version': 1, 'updater_sha': sys.argv[4], 'updater_product_tree': sys.argv[5],
    'before_updater_sha': sys.argv[6], 'before_product_tree': sys.argv[7],
    'control_panel_sha': sys.argv[8], 'control_panel_product_tree': sys.argv[9],
    'compiled_control_panel_version': sys.argv[10], 'synthetic_target_start_version': 'v2.0.0',
    'candidate_fixture_version': 'v2.0.1', 'before_version': 'v2.0.0', 'published_release': False,
    'target_application': 'synthetic_checked_fixture', 'executed_arch': 'amd64',
    'cp_product_source_modified': False, 'before_product_source_modified': False,
    'installer_refusal_before_sha': 'f72d1bddb712eeb64bab2b852b648c2c6b0f4641',
    'oracle_overlays': {str(p.relative_to(root)): sha(p) for p in paths},
    'binaries': {str(p.relative_to(work)): sha(p) for p in (
        work / 'hostruntime.test', work / 'before-hostruntime.test', work / 'control-panel.test',
        work / 'before-production/autostream-host-agent', work / 'before-production/autostream-local-executor',
        work / 'candidate-production/autostream-host-agent', work / 'candidate-production/autostream-local-executor',
        work / 'baseline-production/autostream-host-agent', work / 'baseline-production/autostream-local-executor')},
}
with out.open('x', encoding='utf-8') as target:
    json.dump(manifest, target, indent=2, sort_keys=True)
    target.write('\n')
PROVENANCE

run_bounded docker build --tag "${image}" - > "${evidence}/build/runtime-image.log" 2>&1 <<'DOCKERFILE'
FROM ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    systemd systemd-sysv dbus mariadb-server mariadb-client ca-certificates openssl python3 jq curl acl \
    fonts-noto-cjk libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
# This tmpfs has a container-owned propagation peer; no host cgroup/socket
# mount or privileged runtime input is inherited from the runner.
CMD ["/bin/sh", "-ec", "test \"$(findmnt -n -o FSTYPE -M /run)\" = tmpfs; mount --make-private /run; mount --make-shared /run; exec /sbin/init"]
DOCKERFILE

record_phase() {
  printf '{"schema_version":1,"tuple":"%s","entered_phase":"%s"}\n' "$1" "$2" \
    > "${evidence}/artifacts/phase-$1.json"
}
capture_boot_failure() {
  local tuple=$1
  run_bounded docker inspect --format \
    '{"status":{{json .State.Status}},"running":{{json .State.Running}},"oom_killed":{{json .State.OOMKilled}},"exit_code":{{json .State.ExitCode}}}' \
    "${container_id}" > "${evidence}/artifacts/boot-${tuple}.json" 2>/dev/null || true
  run_bounded docker logs --tail 60 "${container_id}" > "${evidence}/artifacts/boot-${tuple}.log" 2>&1 || true
}
run_tuple() {
  local tuple=$1 test_seconds
  mkdir -p -- "${evidence}/${tuple}/go" "${evidence}/${tuple}/artifacts"
  record_phase "${tuple}" container_create
  container_id="$(run_bounded docker create --privileged --cgroupns=private --network none \
    --cpus 2 --memory 4g --pids-limit 1024 --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    --mount "type=bind,source=${evidence}/${tuple},target=/evidence" "${image}")" || return 1
  [[ ${container_id} =~ ^[0-9a-f]{64}$ ]] || return 1
  run_bounded docker start "${container_id}" >/dev/null || { capture_boot_failure "${tuple}"; return 1; }
  record_phase "${tuple}" systemd_ready
  for _ in $(seq 1 60); do
    if run_bounded docker exec "${container_id}" systemctl show-environment >/dev/null 2>&1; then break; fi
    if [[ $(run_bounded docker inspect --format '{{.State.Running}}' "${container_id}") != true ]]; then
      capture_boot_failure "${tuple}"; return 1
    fi
    run_bounded sleep 1 || return 1
  done
  run_bounded docker exec "${container_id}" systemctl show-environment >/dev/null 2>&1 || { capture_boot_failure "${tuple}"; return 1; }
  record_phase "${tuple}" input_copy
  run_bounded docker exec "${container_id}" /usr/bin/install -d -m 0755 /opt/software-input /opt/software-input/repository /run/autostream-st-port-full-chain || return 1
  for input in hostruntime.test before-hostruntime.test control-panel.test before-production candidate-production baseline-production repository; do
    run_bounded docker cp "${work}/${input}" "${container_id}:/opt/software-input/" || return 1
  done
  run_bounded docker exec "${container_id}" chmod -R go-w /opt/software-input || return 1
  run_bounded docker exec "${container_id}" /usr/bin/chown -R root:root /opt/software-input || return 1
  run_bounded docker exec "${container_id}" chmod 0755 /opt/software-input/hostruntime.test /opt/software-input/before-hostruntime.test /opt/software-input/control-panel.test \
    /opt/software-input/before-production/autostream-host-agent /opt/software-input/before-production/autostream-local-executor \
    /opt/software-input/candidate-production/autostream-host-agent /opt/software-input/candidate-production/autostream-local-executor || return 1
  run_bounded docker exec "${container_id}" chmod 0755 \
    /opt/software-input/baseline-production/autostream-host-agent /opt/software-input/baseline-production/autostream-local-executor || return 1
  record_phase "${tuple}" mariadb_start
  run_bounded docker exec "${container_id}" systemctl start mariadb || return 1
  run_bounded docker exec "${container_id}" mariadb --protocol=socket --user=root \
    --execute='CREATE DATABASE st_port_chain_full CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;' || return 1
  run_bounded docker exec --interactive "${container_id}" /bin/bash -eu <<'BOOTSTRAP' || return 1
umask 077
printf '%s\n' 'root@unix(/run/mysqld/mysqld.sock)/st_port_chain_full?parseTime=true&loc=UTC&charset=utf8mb4' > /run/autostream-st-port-full-chain/dsn
printf '%s\n' 'ST-PORT disposable integration namespace v1' > /run/autostream-st-port-full-chain/isolated
chmod 0644 /run/autostream-st-port-full-chain/isolated
BOOTSTRAP
  test_seconds="$(remaining_seconds)" || return 1
  [[ ${test_seconds} -gt 10 ]] || return 1
  test_seconds=$((test_seconds - 5))
  record_phase "${tuple}" required_test
  set +e
  run_bounded docker exec --env GITHUB_ACTIONS=true --env GOMAXPROCS=2 --env TZ=UTC \
    --env AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN=1 --env AUTOSTREAM_ST_PORT_FULL_CHAIN=1 \
    --env "AUTOSTREAM_SOFTWARE_UPDATE_REVISION_TUPLE=${tuple}" \
    --env AUTOSTREAM_ST_PORT_CP_TEST_BINARY=/opt/software-input/control-panel.test \
    --env AUTOSTREAM_SOFTWARE_UPDATE_BEFORE_TEST_BINARY=/opt/software-input/before-hostruntime.test \
    --env AUTOSTREAM_SOFTWARE_UPDATE_INSTALLER_HOOK=/opt/software-input/repository/scripts/ci/run-software-update-installer-order.sh \
    --env AUTOSTREAM_ST_PORT_DSN_FILE=/run/autostream-st-port-full-chain/dsn --env AUTOSTREAM_ST_PORT_EVIDENCE=/evidence \
    --env "AUTOSTREAM_ST_PORT_CONTROL_PANEL_SHA=${cp_sha}" --env "AUTOSTREAM_ST_PORT_UPDATER_SHA=${updater_sha}" \
    --env NO_PROXY=localhost,127.0.0.1,api.github.com --env no_proxy=localhost,127.0.0.1,api.github.com \
    --env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY= --env http_proxy= --env https_proxy= --env all_proxy= \
    "${container_id}" /opt/software-input/hostruntime.test -test.v=test2json \
    '-test.run=^TestSoftwareUpdateFullChain$' -test.count=1 "-test.timeout=${test_seconds}s" \
    2>&1 | go tool test2json -t -p github.com/Kome-Lab/Autostream-Updater/internal/hostruntime \
      > "${evidence}/${tuple}/go/full-chain.json"
  local statuses=("${PIPESTATUS[@]}")
  set -e
  printf '{"schema_version":1,"tuple":"%s","runtime_exit":%d,"event_conversion_exit":%d,"test_execution":"actual_cp_and_real_processes"}\n' \
    "${tuple}" "${statuses[0]}" "${statuses[1]}" > "${evidence}/artifacts/status-${tuple}.json"
  # The hook/process stream is closed now. Project only bounded fixed files,
  # before container removal, without changing either original pipeline exit.
  if run_bounded docker exec --interactive "${container_id}" python3 - "${updater_sha}" "${cp_sha}" "${tuple}" <<'BOUNDARY'
import hashlib, json, os, re, stat, sys
from pathlib import Path
root = Path('/evidence')
limit = 1024 * 1024
def read_fixed(relative):
    meta = {'exists': None, 'size': None, 'sha256': None, 'capture': 'NOT_CAPTURED'}
    try:
        path = root / relative
        info = path.lstat()
        meta.update(exists=True, size=info.st_size)
        if not stat.S_ISREG(info.st_mode):
            meta['capture'] = 'NOT_REGULAR'
            return meta, None
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as src:
            opened = os.fstat(src.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                meta['capture'] = 'CHANGED'
                return meta, None
            data = src.read(limit + 1)
        if len(data) > limit:
            meta['capture'] = 'LIMIT_EXCEEDED'
            return meta, None
        if len(data) != info.st_size:
            meta['capture'] = 'CHANGED'
            return meta, None
        meta.update(capture='CAPTURED', sha256=hashlib.sha256(data).hexdigest())
        return meta, data
    except FileNotFoundError:
        meta.update(exists=False, capture='NOT_GENERATED')
    except OSError:
        meta['capture'] = 'READ_FAILED'
    return meta, None
def integer(value, maximum=2**63-1):
    return value if type(value) is int and 0 <= value <= maximum else None
def decode(data):
    try:
        return json.loads(data) if data is not None else None
    except (ValueError, UnicodeError):
        return None
checkpoints = ('entry input_validation protected_inputs ordinary_dependencies binary_pair compatibility_floor '
               'fixture_archive legacy_pair_install legacy_pair_start legacy_pair_probe baseline_overlap_refusal '
               'baseline_installer_command baseline_refusal_assertions normal_upgrade candidate_installer_command '
               'candidate_command_returned after_injection_confirmation after_injection_phase_record '
               'race_result_assertions_output recovery_timers_verification candidate_pair_verify '
               'identity_policy_preservation terminal_state_verify agent_stop result_record complete').split()
boundary_meta, boundary_data = read_fixed('installer/ui183-command-boundary.json')
raw = decode(boundary_data)
boundary = {'capture': 'NOT_CAPTURED', 'checkpoint': None, 'failure_source_line': None,
            'shell_command_exit': None, 'baseline_installer_exit': None,
            'candidate_installer_exit': None, 'hook_exit': None,
            'after_injection_confirmed': None, 'race_result_completed': None, 'timers_verified': None}
if isinstance(raw, dict):
    boundary['capture'] = 'CAPTURED'
    boundary['checkpoint'] = raw.get('checkpoint') if raw.get('checkpoint') in checkpoints else None
    for key in ('failure_source_line', 'shell_command_exit', 'baseline_installer_exit', 'candidate_installer_exit', 'hook_exit'):
        boundary[key] = integer(raw.get(key), 10000 if key == 'failure_source_line' else 255)
    for key in ('after_injection_confirmed', 'race_result_completed', 'timers_verified'):
        boundary[key] = raw.get(key) if type(raw.get(key)) is bool else None
# Exact source literals only; matching never establishes a product checkpoint.
static = {
    'Host recovery preflight attempt limit': ('PREFLIGHT_ATTEMPT_LIMIT', 'preflight_attempt'),
    'context deadline exceeded': ('CONTEXT_DEADLINE', 'deadline'),
    'context canceled': ('CONTEXT_CANCELED', 'cancellation'),
    'Host archive, pair, slot or durable state changed during preflight handoff': ('ARCHIVE_PAIR_STATE_DRIFT', 'pair_state_archive_drift'),
    'Host current link changed during preflight handoff': ('CURRENT_LINK_DRIFT', 'pair_state_drift'),
    'Host slot appeared during preflight handoff': ('SLOT_APPEARED', 'pair_state_drift'),
    'Host slot binary changed during preflight handoff': ('SLOT_BINARY_DRIFT', 'pair_state_drift'),
    'Host preflight lock identity changed during handoff': ('PREFLIGHT_LOCK_DRIFT', 'lock_drift'),
    'privileged Host lifecycle lock identity changed': ('LIFECYCLE_LOCK_DRIFT', 'lock_drift'),
    'privileged Host lifecycle lock changed after acquisition': ('ACQUIRED_LOCK_DRIFT', 'lock_drift'),
    'another privileged Host lifecycle operation is active': ('LIFECYCLE_BUSY', 'lock_busy'),
    'Local Executor policy changed before checkpoint inspection': ('POLICY_DRIFT', 'policy_drift'),
    'Host self-update state changed or is not upgrade-owned': ('STATE_DRIFT', 'state_drift'),
    'installed Host runtime unit changed during upgrade': ('UNIT_DRIFT', 'pair_state_drift'),
    'manual Host runtime checksum verification failed': ('ARCHIVE_CHECKSUM', 'archive_refusal'),
    'manual Host runtime artifact identity is invalid': ('ARTIFACT_IDENTITY', 'archive_refusal'),
    'an active Host Agent job blocks manual runtime upgrade': ('ACTIVE_AGENT_JOB', 'other_static_refusal'),
    'software claim recovery must settle before a manual runtime upgrade': ('CLAIM_RECOVERY_BLOCKER', 'other_static_refusal'),
    'a non-terminal Local Executor mutation blocks upgrade': ('MUTATION_BLOCKER', 'other_static_refusal'),
    'a non-terminal Local Executor update checkpoint blocks upgrade': ('CHECKPOINT_BLOCKER', 'other_static_refusal'),
    'canonical Host Agent identity is unsafe': ('IDENTITY_UNSAFE', 'other_static_refusal'),
    'candidate Local Executor could not inspect Host update recovery': ('RECOVERY_INSPECTION', 'other_static_refusal'),
}
unit = r'autostream-host-self-update-recovery@[ab]\.service'
states = r'(?:inactive|failed|active|activating|deactivating|reloading)'
substates = r'(?:dead|failed|running|start|start-pre|start-post|stop|stop-sigterm|stop-sigkill|auto-restart|exited)'
results = r'(?:success|exit-code|signal|core-dump|timeout|resources|watchdog|start-limit-hit|condition)'
busy = unit + r' must be inactive and have no MainPID(?: \(state=' + states + r' substate=' + substates + r' MainPID=[0-9]{1,10} ControlPID=[0-9]{1,10} result=' + results + r'\))?'
def classify(line, hook):
    origin = 'fixture_hook' if hook else 'UNKNOWN'
    helper = re.fullmatch(r'(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?autostream-local-executor: (.+)', line)
    if helper:
        origin, line = 'product_helper', helper[1]
        line = line.removeprefix('manual Host runtime upgrade rejected: ')
    elif line.startswith('install-autostream-host-agent: '):
        origin, line = 'installer_shell', line.removeprefix('install-autostream-host-agent: ')
    if origin in ('product_helper', 'installer_shell'):
        for prefix, label in [('Host recovery preflight attempt limit: ', 'PREFLIGHT_ATTEMPT_LIMIT'),
                              ('Host recovery preflight did not settle: ', 'PREFLIGHT_WAIT')]:
            if line.startswith(prefix):
                cause = line.removeprefix(prefix)
                if cause in static or re.fullmatch(busy, cause):
                    return origin, label, 'preflight_wait_deadline' if cause == 'context deadline exceeded' else 'preflight_wait_attempt'
        if line in static:
            return origin, *static[line]
        if re.fullmatch(busy, line):
            return origin, 'RECOVERY_SERVICE_BUSY', 'service_busy'
        if re.fullmatch(unit + r' (?:must have no ControlPID|recovery process is unconfirmed|inactive recovery service retains a MainPID)', line):
            return origin, 'RECOVERY_SERVICE_REFUSAL', 'service_refusal'
    if hook and (line == 'Traceback (most recent call last):' or line == 'AssertionError'):
        return 'fixture_python', 'PYTHON_ASSERT_TRACE', 'fixture_assertion'
    if hook and re.fullmatch(r'software installer ordering failed at phase (?:' + '|'.join(checkpoints) + r') \(status [0-9]{1,3}\)', line):
        return 'fixture_hook', 'HOOK_PHASE_FAILURE', 'fixture_failure'
    return origin, 'UNKNOWN', 'UNKNOWN'
logs = {}
for name, relative in [('baseline', 'installer/baseline-upgrade.log'), ('candidate', 'installer/normal-upgrade.log'),
                       ('hook', 'processes/normal-installer-upgrade.log')]:
    meta, data = read_fixed(relative)
    events = []
    lines = data.splitlines() if data is not None else []
    for number, raw_line in enumerate(lines[:128], 1):
        origin, template, category = classify(raw_line.decode('utf-8', errors='replace'), name == 'hook')
        events.append({'line': number, 'line_sha256': hashlib.sha256(raw_line).hexdigest(),
                       'origin': origin, 'template_id': template, 'classification': category})
    logs[name] = {'file': meta, 'lines_examined': len(events), 'lines_truncated': len(lines) > 128, 'events': events}
observations = {}
for phase in ('before', 'after'):
    meta, data = read_fixed(f'installer/ui183-{phase}-locks.json')
    lock_raw = decode(data)
    locks = {}
    for label, path in [('setup', '/run/autostream-updater/.autostream-runtime-host-setup.lock'),
                        ('lifecycle', '/run/autostream-updater/.autostream-host-lifecycle.lock')]:
        matches = [v for v in lock_raw.get('locks', []) if isinstance(v, dict) and v.get('path') == path] if isinstance(lock_raw, dict) and isinstance(lock_raw.get('locks'), list) else []
        locks[label] = {k: integer(matches[0].get(k)) if len(matches) == 1 else None for k in ('inode', 'owner_pid')}
    slots = {}
    allowed = {'ActiveState': states, 'SubState': substates, 'Result': results,
               'MainPID': r'[0-9]{1,10}', 'ControlPID': r'[0-9]{1,10}', 'ExecMainStatus': r'[0-9]{1,3}'}
    for slot in ('a', 'b'):
        prop_meta, prop_data = read_fixed(f'installer/ui183-{phase}-{slot}.properties')
        props = {}
        for key, pattern in allowed.items():
            values = [line[len(key)+1:] for line in prop_data.decode('utf-8', errors='replace').splitlines() if line.startswith(key + '=')] if prop_data is not None else []
            props[key] = values[0] if len(values) == 1 and re.fullmatch(pattern, values[0]) else None
        count_meta, count_data = read_fixed(f'installer/ui183-{phase}-{slot}.lock-failure')
        count = int(count_data.strip()) if count_data is not None and re.fullmatch(rb'[0-9]{1,3}\n?', count_data) else None
        slots[slot] = {'property_file': prop_meta, 'properties': props, 'lock_failure_file': count_meta, 'actual_lifecycle_lock_failure_events': count}
    observations[phase] = {'lock_file': meta, 'locks': locks, 'slots': slots,
                           'lock_acquired_at': 'installer_lock_owner_query_before_injected_starts',
                           'properties_acquired_at': 'after_injected_fixed_start_before_query_return',
                           'not_atomic': True, 'not_failure_instant': True}
assert re.fullmatch(r'[0-9a-f]{40}', sys.argv[1]) and re.fullmatch(r'[0-9a-f]{40}', sys.argv[2])
assert sys.argv[3] in ('equal', 'distinct')
result = {'schema_version': 1, 'evidence_status': 'COLLECTED', 'collection_timing': 'post_fixture_exit',
          'updater_sha': sys.argv[1], 'control_panel_sha': sys.argv[2], 'tuple': sys.argv[3],
          'installed_pair_sha': 'b1c94afe2ee2fe8854abb12e2c85565a1bd448dc',
          'baseline_installer_sha': 'f72d1bddb712eeb64bab2b852b648c2c6b0f4641',
          'invocation_exit_is_not_guard_proof': True, 'static_reason_is_not_internal_checkpoint': True,
          'boundary_file': boundary_meta, 'boundary': boundary, 'logs': logs, 'observations': observations}
with (root / 'artifacts/ui183-installer-boundary.json').open('x', encoding='utf-8') as out:
    json.dump(result, out, sort_keys=True, indent=2)
    out.write('\n')
BOUNDARY
  then
    :
  else
    local collection_status=$?
    printf '{"schema_version":1,"evidence_status":"COLLECTOR_FAILED","collector_exit":%d,"hook_exit":null}\n' \
      "${collection_status}" > "${evidence}/${tuple}/artifacts/ui183-installer-boundary-unavailable.json"
  fi
  # Only fixed, secret-screened observations are uploadable. Process/build,
  # installer logs and runtime credentials remain private and are never uploaded.
  run_bounded docker exec "${container_id}" chmod -R a+rX /evidence/artifacts || return 1
  if run_bounded docker exec "${container_id}" test -f /evidence/installer/result.json; then
    run_bounded docker exec "${container_id}" cp /evidence/installer/result.json /evidence/artifacts/normal-installer.json || return 1
    run_bounded docker exec "${container_id}" chmod 0644 /evidence/artifacts/normal-installer.json || return 1
  fi
  remove_container || return 1
  [[ ${statuses[0]} == 0 && ${statuses[1]} == 0 ]] || return 1
  run_bounded bash "${repository_root}/scripts/ci/verify-go-test-evidence.sh" --exact-subtests \
    "${evidence}/${tuple}/go" "${repository_root}/internal/hostruntime" \
    "${repository_root}/scripts/ci/required-software-update-full-chain-tests.txt" \
    > "${evidence}/artifacts/required-${tuple}.json"
}

# Each independently seeded tuple runs once, including after an earlier
# failure when the original shared deadline still permits the second run.
equal_status=0
distinct_status=0
run_tuple equal || equal_status=$?
remove_container || distinct_status=1
if [[ -z ${container_id} ]]; then run_tuple distinct || distinct_status=$?; fi
printf '{"schema_version":1,"control_panel_sha":"%s","updater_sha":"%s","equal_exit":%d,"distinct_exit":%d,"shared_budget_seconds":2160}\n' \
  "${cp_sha}" "${updater_sha}" "${equal_status}" "${distinct_status}" > "${evidence}/artifacts/status.json"
[[ ${equal_status} == 0 && ${distinct_status} == 0 ]]
