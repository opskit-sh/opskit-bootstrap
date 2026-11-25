#!/usr/bin/env bash
# Acceptance test suite for pre-installed rootful Docker conversion and cgroup v2 delegation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Running acceptance_docker_rootless.sh ==="

IMAGE_NAME="localhost/opskit-test-debian:13"

source "${REPO_ROOT}/tests/setup_test_env.sh"
mkdir -p /tmp/opencode
TEST_ARTIFACTS_DIR="$(mktemp -d /tmp/opencode/docker-rootless-artifacts.XXXXXX)"
setup_test_artifacts "${TEST_ARTIFACTS_DIR}"

ACTIVE_CIDS=()
cleanup() {
    local cid
    for cid in "${ACTIVE_CIDS[@]+"${ACTIVE_CIDS[@]}"}"; do
        podman rm -f "${cid}" >/dev/null 2>&1 || true
    done
    rm -rf "${TEST_ARTIFACTS_DIR}"
}
trap cleanup EXIT

# Test 1: Pre-installed rootful Docker capability detection and plan mutations (--runtime auto and --runtime docker)
test_rootful_docker_plan_detection() {
    echo "--- Test 1: Pre-installed rootful Docker detection and plan generation ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Hide podman so --runtime auto discovers pre-installed rootful docker
mv /usr/bin/podman /usr/libexec/podman-hidden

cat << "EOF" > /usr/bin/docker
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
    echo "Docker version 27.3.1, build ce12230"
    exit 0
fi
if [[ "${1:-}" == "info" ]]; then
    echo "[name=seccomp]"
    exit 0
fi
exit 1
EOF
chmod 0755 /usr/bin/docker

cat << "EOF" > /usr/bin/dockerd
#!/usr/bin/env bash
exit 0
EOF
chmod 0755 /usr/bin/dockerd

python3 -B -c "
import socket, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(\"/var/run/docker.sock\")
s.listen(1)
" &
SOCK_PID=$!
trap "kill ${SOCK_PID} 2>/dev/null || true" EXIT
sleep 0.3

/bootstrap/bin/opskit-bootstrap --runtime auto --profile private --no-probe --plan-json /tmp/plan_auto.json >/dev/null
/bootstrap/bin/opskit-bootstrap --runtime docker --profile private --no-probe --plan-json /tmp/plan_docker.json >/dev/null

python3 -B -c "
import json
for path in [\"/tmp/plan_auto.json\", \"/tmp/plan_docker.json\"]:
    with open(path) as f:
        p = json.load(f)
    assert p[\"runtime\"] == \"docker\", f\"expected runtime docker in {path}, got {p[\"runtime\"]}\"
    caps = p[\"capabilities\"]
    assert caps[\"docker_rootless_usable\"] is False, f\"expected docker_rootless_usable=false in {path}\"
    assert caps[\"docker_daemon_rootful\"] is True, f\"expected docker_daemon_rootful=true in {path}\"
    assert caps[\"cgroup_delegation_enabled\"] is False, f\"expected cgroup_delegation_enabled=false in {path}\"
    mut_ids = [m[\"id\"] for m in p[\"mutations\"]]
    for req in [\"packages\", \"service_user\", \"subuid_allocation\", \"cgroup_delegation\", \"user_linger\", \"rootless_docker\", \"fetch_cli\"]:
        assert req in mut_ids, f\"missing mutation {req} in {path}: {mut_ids}\"
    pkg_mut = [m for m in p[\"mutations\"] if m[\"id\"] == \"packages\"][0]
    assert \"docker-ce-rootless-extras\" in pkg_mut[\"description\"], f\"missing docker-ce-rootless-extras in {pkg_mut}\"
    assert \"cgroup_delegation_active\" in p[\"postconditions\"], f\"missing cgroup_delegation_active in {p[\"postconditions\"]}\"
    assert \"service_user_rootless_functional\" in p[\"postconditions\"]
print(\"Plan schema and mutations verified for --runtime auto and --runtime docker.\")
"
'
    echo "PASS: Pre-installed rootful Docker detection and plan generation verified."
}

# Test 2: Fail-closed when rootless Docker conversion is impossible
test_rootful_docker_fail_closed() {
    echo "--- Test 2: Fail-closed when rootless Docker conversion is impossible ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

mv /usr/bin/podman /usr/libexec/podman-hidden

cat << "EOF" > /usr/bin/docker
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
    echo "Docker version 27.3.1, build ce12230"
    exit 0
fi
exit 1
EOF
chmod 0755 /usr/bin/docker

# Case 2A: rootless setup tools missing and offline apt-get cannot install them
cat << "EOF" > /usr/local/sbin/apt-get
#!/usr/bin/env bash
exit 100
EOF
chmod 0755 /usr/local/sbin/apt-get
export PATH="/usr/local/sbin:${PATH}"

set +e
out_a="$(/bootstrap/bin/opskit-bootstrap --runtime auto --profile private --no-probe --yes 2>&1)"
rc_a=$?
set -e
if [[ ${rc_a} -eq 0 ]]; then
    echo "FAIL: expected non-zero exit when rootless extras cannot be installed" >&2
    exit 1
fi
echo "Case 2A failed closed cleanly (rc=${rc_a})."

# Case 2B: rootless setup tool present but conversion fails
rm -f /usr/local/sbin/apt-get
cat << "EOF" > /usr/bin/rootlesskit
#!/usr/bin/env bash
exit 0
EOF
cat << "EOF" > /usr/bin/dockerd-rootless-setuptool.sh
#!/usr/bin/env bash
echo "simulated rootless conversion failure" >&2
exit 1
EOF
chmod 0755 /usr/bin/rootlesskit /usr/bin/dockerd-rootless-setuptool.sh

set +e
out_b="$(/bootstrap/bin/opskit-bootstrap --runtime auto --profile private --no-probe --yes 2>&1)"
rc_b=$?
set -e
if [[ ${rc_b} -eq 0 ]]; then
    echo "FAIL: expected non-zero exit when dockerd-rootless-setuptool.sh fails" >&2
    exit 1
fi
if ! echo "${out_b}" | grep -q "Rootless Docker provisioning failed"; then
    echo "FAIL: expected clear error message on rootless conversion failure, got: ${out_b}" >&2
    exit 1
fi
if id -Gn opskit 2>/dev/null | grep -qw docker; then
    echo "FAIL: opskit must never be added to docker group" >&2
    exit 1
fi
echo "Case 2B failed closed cleanly (rc=${rc_b})."
'
    echo "PASS: Fail-closed behavior verified when rootless Docker conversion is impossible."
}

# Test 3: End-to-end rootful-to-rootless Docker conversion + real systemd Delegate=yes + memory verification + undo/purge
test_rootful_docker_conversion_systemd_e2e() {
    echo "--- Test 3: End-to-end rootful-to-rootless Docker conversion and systemd cgroup delegation ---"
    local cid
    cid="$(podman run -d --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /sbin/init)"
    ACTIVE_CIDS+=("${cid}")

    # Wait for systemd PID 1 to initialize /run/systemd/system
    local i=0
    while [[ ${i} -lt 20 ]]; do
        if podman exec "${cid}" test -d /run/systemd/system 2>/dev/null; then
            break
        fi
        sleep 0.5
        i=$((i + 1))
    done

    podman exec "${cid}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
export OPSKIT_SUBUID_START="10000"
export OPSKIT_SUBUID_COUNT="50000"

# Hide podman so --runtime auto selects pre-installed rootful docker
mv /usr/bin/podman /usr/libexec/podman-hidden

# Create a rootful /var/run/docker.sock owned by root:root (mode 0660)
python3 -B -c "
import socket, os, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(\"/var/run/docker.sock\")
os.chmod(\"/var/run/docker.sock\", 0o660)
s.listen(5)
while True:
    try:
        conn, _ = s.accept()
        conn.close()
    except Exception:
        break
" >/dev/null 2>&1 &
ROOTFUL_PID=$!

cat << "EOF" > /usr/bin/rootlesskit
#!/usr/bin/env bash
exec "$@"
EOF
chmod 0755 /usr/bin/rootlesskit

# Rootless setup tool shim running as opskit
cat << "EOF" > /usr/bin/dockerd-rootless-setuptool.sh
#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -eq 0 ]]; then
    echo "Refusing to run as root" >&2
    exit 1
fi
uid="$(id -u)"
mkdir -p "${HOME}/.config/systemd/user"
cat << UNIT > "${HOME}/.config/systemd/user/docker.service"
[Unit]
Description=Docker Application Container Engine (Rootless)
[Service]
ExecStart=/usr/bin/dockerd-rootless.sh
[Install]
WantedBy=default.target
UNIT

if [[ "${1:-}" == "install" ]]; then
    if [[ -n "${XDG_RUNTIME_DIR:-}" && -w "${XDG_RUNTIME_DIR}" ]]; then
        rt_dir="${XDG_RUNTIME_DIR}"
    else
        rt_dir="${HOME}/.docker/run"
    fi
    mkdir -p "${rt_dir}"
    chmod 0700 "${rt_dir}"
    if [[ ! -S "${rt_dir}/docker.sock" ]]; then
        nohup python3 -B -c "
import socket, os, sys
sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
os.chmod(sock_path, 0o660)
s.listen(5)
while True:
    conn, _ = s.accept()
    conn.close()
" "${rt_dir}/docker.sock" >/dev/null 2>&1 &
        echo $! > "${rt_dir}/docker.pid"
        sleep 0.2
    fi
elif [[ "${1:-}" == "uninstall" ]]; then
    for rt_dir in "${XDG_RUNTIME_DIR:-/run/user/${uid}}" "${HOME}/.docker/run"; do
        if [[ -f "${rt_dir}/docker.pid" ]]; then
            kill "$(cat "${rt_dir}/docker.pid")" 2>/dev/null || true
            rm -f "${rt_dir}/docker.pid"
        fi
        rm -f "${rt_dir}/docker.sock"
    done
    rm -f "${HOME}/.config/systemd/user/docker.service"
fi
EOF
chmod 0755 /usr/bin/dockerd-rootless-setuptool.sh

# Docker CLI shim reflecting rootless vs rootful socket behavior and verifying memory constraint
cat << "EOF" > /usr/bin/docker
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
    echo "Docker version 27.3.1, build ce12230"
    exit 0
fi
sock="${DOCKER_HOST:-unix:///var/run/docker.sock}"
sock="${sock#unix://}"
if [[ ! -S "${sock}" || ! -r "${sock}" || ! -w "${sock}" ]]; then
    echo "Cannot connect to the Docker daemon at ${DOCKER_HOST:-unix:///var/run/docker.sock}." >&2
    exit 1
fi
if [[ "${sock}" == "/var/run/docker.sock" || "${sock}" == "/run/docker.sock" ]]; then
    if [[ "${1:-}" == "info" ]]; then
        echo "[name=seccomp name=cgroupns]"
        exit 0
    fi
    exit 0
fi
if [[ "${1:-}" == "info" ]]; then
    echo "[name=seccomp name=rootless name=cgroupns]"
    exit 0
fi
if [[ "${1:-}" == "images" ]]; then
    if [[ "${OPSKIT_VERIFY_IMAGE:-}" != "" ]]; then
        echo "${OPSKIT_VERIFY_IMAGE}"
    fi
    exit 0
fi
if [[ "${1:-}" == "run" ]]; then
    mem_val=""
    prev=""
    for arg in "$@"; do
        if [[ "${prev}" == "--memory" ]]; then
            mem_val="${arg}"
            break
        fi
        prev="${arg}"
    done
    # Fail closed if memory limit was not passed or delegation missing
    if [[ -z "${mem_val}" ]]; then
        echo "max"
        exit 0
    fi
    echo "${mem_val}"
    exit 0
fi
exit 0
EOF
chmod 0755 /usr/bin/docker

# Wait for systemd PID 1 to finish basic boot before running bootstrap
sleep 1

# 1. Apply bootstrap under --runtime auto with real memory verification probe enabled
export OPSKIT_VERIFY_IMAGE="localhost/tiny:mem"
/bootstrap/bin/opskit-bootstrap --runtime auto --profile private --no-probe --yes

# 2. Assert cgroup delegation drop-in and active systemd DelegateControllers
test -f /etc/systemd/system/user@.service.d/opskit-delegate.conf
svc_uid="$(id -u opskit)"
del_prop="$(systemctl show "user@${svc_uid}.service" -p Delegate --value)"
del_ctrls="$(systemctl show "user@${svc_uid}.service" -p DelegateControllers --value)"
test "${del_prop}" = "yes"
echo "Active DelegateControllers for user@${svc_uid}.service: ${del_ctrls}"
for ctrl in cpu memory pids; do
    if [[ "${del_ctrls}" != *"${ctrl}"* ]]; then
        echo "FAIL: missing controller ${ctrl} in DelegateControllers=${del_ctrls}" >&2
        exit 1
    fi
done

# 3. Assert rootless Docker provisioned and service user is NOT in docker group
test -f /home/opskit/.config/systemd/user/docker.service
test -f /home/opskit/.config/environment.d/opskit-docker.conf
rootless_sock="$(grep "^DOCKER_HOST=" /home/opskit/.config/environment.d/opskit-docker.conf | cut -d= -f2-)"
rootless_sock="${rootless_sock#unix://}"
test "${rootless_sock}" != "/var/run/docker.sock"
test "${rootless_sock}" != "/run/docker.sock"
test -S "${rootless_sock}"
if id -Gn opskit | grep -qw docker; then
    echo "FAIL: opskit must never be in docker group" >&2
    exit 1
fi

# Confirm opskit can run docker info rootlessly, and CANNOT access /var/run/docker.sock
su -s /bin/sh opskit -c "DOCKER_HOST=\"unix://${rootless_sock}\" docker info --format \"{{.SecurityOptions}}\"" | grep -q "rootless"
if su -s /bin/sh opskit -c "DOCKER_HOST=unix:///var/run/docker.sock docker info" >/dev/null 2>&1; then
    echo "FAIL: opskit unexpectedly accessed rootful /var/run/docker.sock" >&2
    exit 1
fi

# 4. Assert ledger records cgroup_delegation and rootless_docker
grep -q "\"mutation_id\":\"cgroup_delegation\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"mutation_id\":\"rootless_docker\"" /var/lib/opskit-bootstrap/apply.jsonl

# 5. Assert re-run is a true no-op
lines_before="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"
rerun_out="$(/bootstrap/bin/opskit-bootstrap --runtime auto --profile private --no-probe --yes 2>&1)"
lines_after="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"
test "${lines_before}" -eq "${lines_after}"
echo "${rerun_out}" | grep -q "Host already bootstrapped; no changes required"

# 6. Assert --undo --purge removes delegation drop-in and rootless docker cleanly
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -e /etc/systemd/system/user@.service.d/opskit-delegate.conf
test ! -d /etc/systemd/system/user@.service.d
test ! -e /home/opskit/.config/systemd/user/docker.service
test ! -e /home/opskit/.config/environment.d/opskit-docker.conf
! id opskit >/dev/null 2>&1

# 7. Re-bootstrap then assert plain --undo preserves cgroup_delegation and rootless_docker
/bootstrap/bin/opskit-bootstrap --runtime auto --profile private --no-probe --yes >/dev/null
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
test -f /etc/systemd/system/user@.service.d/opskit-delegate.conf
test -f /home/opskit/.config/systemd/user/docker.service
test -f /home/opskit/.config/environment.d/opskit-docker.conf
id opskit >/dev/null 2>&1

kill "${ROOTFUL_PID}" 2>/dev/null || true
echo "End-to-end rootless Docker conversion, delegation, idempotency, and undo verified."
'
    podman rm -f "${cid}" >/dev/null 2>&1 || true
    echo "PASS: End-to-end rootless Docker conversion and systemd delegation verified."
}

# Test 4: Verify fail-closed when memory limit enforcement fails inside container verification
test_memory_limit_enforcement_fail_closed() {
    echo "--- Test 4: Fail-closed when memory limit enforcement check fails ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
export OPSKIT_SUBUID_START="10000"
export OPSKIT_SUBUID_COUNT="50000"
export OPSKIT_VERIFY_IMAGE="localhost/tiny:mem"

mv /usr/bin/podman /usr/libexec/podman-hidden

cat << "EOF" > /usr/bin/rootlesskit
#!/usr/bin/env bash
exec "$@"
EOF
chmod 0755 /usr/bin/rootlesskit

cat << "EOF" > /usr/bin/dockerd-rootless-setuptool.sh
#!/usr/bin/env bash
set -euo pipefail
uid="$(id -u)"
rt_dir="${HOME}/.docker/run"
mkdir -p "${rt_dir}" "${HOME}/.config/systemd/user"
touch "${HOME}/.config/systemd/user/docker.service"
nohup python3 -B -c "
import socket, os, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o660)
s.listen(5)
while True:
    conn, _ = s.accept()
    conn.close()
" "${rt_dir}/docker.sock" >/dev/null 2>&1 &
sleep 0.2
EOF
chmod 0755 /usr/bin/dockerd-rootless-setuptool.sh

cat << "EOF" > /usr/bin/docker
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
    echo "Docker version 27.3.1, build ce12230"
    exit 0
fi
if [[ "${1:-}" == "info" ]]; then
    echo "[name=seccomp name=rootless]"
    exit 0
fi
if [[ "${1:-}" == "run" ]]; then
    # Simulate missing cgroup memory constraint (memory.max=max)
    echo "max"
    exit 0
fi
exit 0
EOF
chmod 0755 /usr/bin/docker

mkdir -p /run/user && chmod 1777 /run/user

set +e
out="$(/bootstrap/bin/opskit-bootstrap --runtime auto --profile private --no-probe --yes 2>&1)"
rc=$?
set -e
if [[ ${rc} -eq 0 ]]; then
    echo "FAIL: expected non-zero exit when container memory limit reports max" >&2
    exit 1
fi
echo "${out}" | grep -q "cgroup memory limit verification failed"
echo "PASS: Memory limit enforcement check failed closed on unenforced limit (rc=${rc})."
'
}

test_rootful_docker_plan_detection
test_rootful_docker_fail_closed
test_rootful_docker_conversion_systemd_e2e
test_memory_limit_enforcement_fail_closed

echo "ALL DOCKER ROOTLESS AND CGROUP DELEGATION ACCEPTANCE TESTS PASSED."
