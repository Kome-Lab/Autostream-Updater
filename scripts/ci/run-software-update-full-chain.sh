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
mkdir -p -- "${evidence}/build" "${evidence}/artifacts" "${work}/before-production" "${work}/candidate-production" "${work}/repository"

checkout_fixed() {
  local remote=$1 sha=$2 destination=$3
  run_bounded git init --quiet "${destination}"
  run_bounded git -C "${destination}" remote add origin "${remote}"
  run_bounded git -C "${destination}" fetch --quiet --depth 1 origin "${sha}"
  run_bounded git -C "${destination}" checkout --quiet --detach FETCH_HEAD
  [[ $(git -C "${destination}" rev-parse HEAD) == "${sha}" ]]
}
checkout_fixed https://github.com/Kome-Lab/Autostream-Updater.git "${before_sha}" "${work}/before" > "${evidence}/build/before-checkout.log" 2>&1
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
    'oracle_overlays': {str(p.relative_to(root)): sha(p) for p in paths},
    'binaries': {str(p.relative_to(work)): sha(p) for p in (
        work / 'hostruntime.test', work / 'before-hostruntime.test', work / 'control-panel.test',
        work / 'before-production/autostream-host-agent', work / 'before-production/autostream-local-executor',
        work / 'candidate-production/autostream-host-agent', work / 'candidate-production/autostream-local-executor')},
}
with out.open('x', encoding='utf-8') as target:
    json.dump(manifest, target, indent=2, sort_keys=True)
    target.write('\n')
PROVENANCE

run_bounded docker build --tag "${image}" - > "${evidence}/build/runtime-image.log" 2>&1 <<'DOCKERFILE'
FROM ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    systemd systemd-sysv dbus mariadb-server mariadb-client ca-certificates openssl python3 jq curl \
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
  for input in hostruntime.test before-hostruntime.test control-panel.test before-production candidate-production repository; do
    run_bounded docker cp "${work}/${input}" "${container_id}:/opt/software-input/" || return 1
  done
  run_bounded docker exec "${container_id}" chmod -R go-w /opt/software-input || return 1
  run_bounded docker exec "${container_id}" /usr/bin/chown -R root:root /opt/software-input || return 1
  run_bounded docker exec "${container_id}" chmod 0755 /opt/software-input/hostruntime.test /opt/software-input/before-hostruntime.test /opt/software-input/control-panel.test \
    /opt/software-input/before-production/autostream-host-agent /opt/software-input/before-production/autostream-local-executor \
    /opt/software-input/candidate-production/autostream-host-agent /opt/software-input/candidate-production/autostream-local-executor || return 1
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
