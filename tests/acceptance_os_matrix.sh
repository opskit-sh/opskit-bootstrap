#!/usr/bin/env bash
# Acceptance test suite for OS-family matrix and capability edge cases.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Running acceptance_os_matrix.sh ==="

source "${REPO_ROOT}/tests/setup_test_env.sh"
TEST_ARTIFACTS_DIR="$(mktemp -d)"
setup_test_artifacts "${TEST_ARTIFACTS_DIR}"

TEST_ARTIFACTS_DIR_V2="$(mktemp -d)"
setup_test_artifacts "${TEST_ARTIFACTS_DIR_V2}"

# Customize V2 artifacts
ARCH="$(uname -m)"
echo "#!/usr/bin/env bash" > "${TEST_ARTIFACTS_DIR_V2}/opskit-linux-${ARCH}"
echo "echo opskit-cli-v2" >> "${TEST_ARTIFACTS_DIR_V2}/opskit-linux-${ARCH}"
chmod 0755 "${TEST_ARTIFACTS_DIR_V2}/opskit-linux-${ARCH}"

V2_SHA="$(sha256sum "${TEST_ARTIFACTS_DIR_V2}/opskit-linux-${ARCH}" | awk '{print $1}')"
V2_SIZE="$(stat -c%s "${TEST_ARTIFACTS_DIR_V2}/opskit-linux-${ARCH}")"

python3 -B -c "
import json
with open('${TEST_ARTIFACTS_DIR_V2}/release-manifest.json') as f:
    d = json.load(f)
d['artifacts']['opskit-linux-${ARCH}']['sha256'] = '${V2_SHA}'
d['artifacts']['opskit-linux-${ARCH}']['size'] = ${V2_SIZE}
with open('${TEST_ARTIFACTS_DIR_V2}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"

TEMP_KEY="$(mktemp)"
openssl genpkey -algorithm ed25519 -out "${TEMP_KEY}" 2>/dev/null
openssl pkey -in "${TEMP_KEY}" -pubout -out "${TEST_ARTIFACTS_DIR_V2}/release.pub" 2>/dev/null
echo "test-release-key-2" > "${TEST_ARTIFACTS_DIR_V2}/release.key_id"

CANON_FILE="${TEST_ARTIFACTS_DIR_V2}/canon.tmp"
python3 -B "${REPO_ROOT}/lib/canonicalize.py" --strip signatures "${TEST_ARTIFACTS_DIR_V2}/release-manifest.json" > "${CANON_FILE}"
SIG="$(openssl pkeyutl -sign -inkey "${TEMP_KEY}" -rawin -in "${CANON_FILE}" 2>/dev/null | python3 -B -c "import sys; print(sys.stdin.buffer.read().hex())")"
rm -f "${CANON_FILE}" "${TEMP_KEY}"

python3 -B -c "
import json
with open('${TEST_ARTIFACTS_DIR_V2}/release-manifest.json') as f:
    d = json.load(f)
d['signatures'] = [{'key_id': 'test-release-key-2', 'algorithm': 'ed25519', 'signature': '${SIG}'}]
with open('${TEST_ARTIFACTS_DIR_V2}/release-manifest.json', 'w') as f:
    json.dump(d, f, indent=2)
"

ACTIVE_CIDS=()
cleanup() {
    local cid
    for cid in "${ACTIVE_CIDS[@]+"${ACTIVE_CIDS[@]}"}"; do
        podman rm -f "${cid}" >/dev/null 2>&1 || true
    done
    rm -rf "${TEST_ARTIFACTS_DIR}" "${TEST_ARTIFACTS_DIR_V2}" "${LIVE_EDGE_ARTIFACTS_DIR:-}"
}
trap cleanup EXIT

# Test 1: OS Matrix per profile (Debian direct, RHEL tunnel, SLES private)
test_os_matrix_profiles() {
    echo "--- Test 1A: Debian 13 (direct profile) ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
id opskit >/dev/null
test -f /etc/systemd/system/opskit-edge-443.socket
test -f /etc/systemd/system/opskit-edge.service
test -f /usr/local/bin/opskit
test -f /var/lib/opskit-bootstrap/apply.jsonl
echo "Debian direct verified."
'

    echo "--- Test 1B: RHEL 9 (tunnel profile) ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-rhel:9 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="5.14.0-427.el9.aarch64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile tunnel --no-probe --yes >/dev/null
id opskit >/dev/null
test ! -f /etc/systemd/system/opskit-edge-443.socket
test -f /home/opskit/.config/systemd/user/cloudflared.service
test -f /usr/local/bin/opskit
test -f /var/lib/opskit-bootstrap/apply.jsonl
echo "RHEL tunnel verified."
'

    echo "--- Test 1C: SLES 15 (private profile) ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-sles:15.6 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="5.14.21-150500.55.52-default"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile private --no-probe --yes >/dev/null
id opskit >/dev/null
test ! -f /etc/systemd/system/opskit-edge-443.socket
test ! -f /home/opskit/.config/systemd/user/cloudflared.service
test -f /usr/local/bin/opskit
test -f /var/lib/opskit-bootstrap/apply.jsonl
echo "SLES private verified."
'

    echo "--- Test 1D: Ubuntu 24.04 (direct profile smoke run: bootstrap + re-run no-op + undo + zero-trace) ---"
    if ! podman image exists localhost/opskit-test-ubuntu:24.04 2>/dev/null; then
        echo "Building localhost/opskit-test-ubuntu:24.04 image..."
        podman build -t localhost/opskit-test-ubuntu:24.04 -f "${REPO_ROOT}/tests/fixtures/containers/Containerfile.ubuntu" "${REPO_ROOT}" >/dev/null
    fi
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-ubuntu:24.04 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.8.0-31-generic"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Bootstrap direct
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
id opskit >/dev/null
test -f /etc/systemd/system/opskit-edge-443.socket
test -f /etc/systemd/system/opskit-edge.service
test -f /usr/local/bin/opskit
test -f /var/lib/opskit-bootstrap/apply.jsonl
lines_first="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"

# 2. Re-run is a true no-op
out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
lines_second="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"
test "${lines_first}" -eq "${lines_second}"
if [[ "${out}" != *"Host already bootstrapped; no changes required"* ]]; then
    echo "FAIL: unexpected output on re-run: ${out}" >&2
    exit 1
fi

# 3. Undo purge
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null

# 4. Zero-trace verification
! id opskit >/dev/null 2>&1
test ! -e /home/opskit
test ! -e /var/lib/opskit-bootstrap
test ! -e /usr/local/bin/opskit
test ! -e /etc/systemd/system/opskit-edge-443.socket
test ! -e /etc/systemd/system/opskit-edge-80.socket
test ! -e /etc/systemd/system/opskit-edge.service
test ! -e /var/lib/systemd/linger/opskit
test "$(grep -c "^opskit:" /etc/subuid 2>/dev/null || true)" -eq 0
test "$(grep -c "^opskit:" /etc/subgid 2>/dev/null || true)" -eq 0
echo "Ubuntu 24.04 direct smoke run verified."
'

    echo "--- Test 1E: Ubuntu 22.04 negative gate refusal ---"
    local mock_os_rel
    mock_os_rel="$(mktemp)"
    cat << 'EOF' > "${mock_os_rel}"
NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
ID_LIKE=debian
VERSION="22.04.4 LTS (Jammy Jellyfish)"
EOF

    set +e
    local gate_out
    gate_out="$(OPSKIT_TEST_MODE="1" OPSKIT_OS_RELEASE_FILE="${mock_os_rel}" "${REPO_ROOT}/bin/opskit-bootstrap" --dry-run 2>&1)"
    local gate_rc=$?
    set -e
    rm -f "${mock_os_rel}"

    if [[ "${gate_rc}" -ne 8 ]]; then
        echo "FAIL: Ubuntu 22.04 gate check expected exit 8, got ${gate_rc}" >&2
        echo "Output: ${gate_out}" >&2
        exit 1
    fi

    if [[ "${gate_out}" != *"Ubuntu 24.04 LTS (noble) or higher required; found Ubuntu 22.04. Upgrade using 'do-release-upgrade'."* ]]; then
        echo "FAIL: Ubuntu 22.04 gate output did not contain expected remedy text" >&2
        echo "Output: ${gate_out}" >&2
        exit 1
    fi
    echo "Ubuntu 22.04 negative gate refusal verified."
}

# Test 2: Pre-existing service user with existing subuid allocation
test_preexisting_user_reuse() {
    echo "--- Test 2: Pre-existing service user and subuid allocation reuse ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Pre-create user and pre-allocate subuid
useradd -u 1500 -m -s /bin/bash opskit
if ! grep -q "^opskit:" /etc/subuid 2>/dev/null; then
    echo "opskit:200000:65536" >> /etc/subuid
    echo "opskit:200000:65536" >> /etc/subgid
fi

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Verify UID preserved
test "$(id -u opskit)" -eq 1500

# Verify subuid was NOT duplicated or clobbered
count="$(grep -c "^opskit:" /etc/subuid)"
test "${count}" -eq 1
echo "Pre-existing user and subuid reuse verified."
'
}

# Test 3: Pre-existing user in banned docker group fails with exit 8
test_banned_docker_group() {
    echo "--- Test 3: Banned docker group rejection ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

groupadd docker
useradd -m -g docker opskit

set +e
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null 2>&1
code=$?
set -e

if [[ ${code} -ne 8 ]]; then
    echo "FAIL: Expected exit code 8 when user is in docker group, got ${code}" >&2
    exit 1
fi
echo "Docker group ban verified (rejected with exit 8)."
'
}

# Test 4: Missing subordinate UID automatically allocated without collision
test_subuid_allocation_collision_free() {
    echo "--- Test 4: Non-overlapping subordinate UID allocation ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

touch /etc/subuid /etc/subgid
echo "otheruser:100000:65536" >> /etc/subuid
echo "otheruser:100000:65536" >> /etc/subgid

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

opskit_range="$(grep "^opskit:" /etc/subuid | cut -d: -f2)"
if [[ "${opskit_range}" -lt 165536 ]]; then
    echo "FAIL: opskit subordinate UID overlaps with otheruser: ${opskit_range}" >&2
    exit 1
fi
echo "Collision-free subordinate UID allocation verified (assigned ${opskit_range})."
'
}

# Test 5: Re-run is a true no-op
test_rerun_is_true_noop() {
    echo "--- Test 5: Re-run is a true no-op (no_changes, zero ledger writes) ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# First run: applies mutations
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
lines_first="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"

# Second run: should be a true no-op
out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
lines_second="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"

if [[ "${lines_first}" -ne "${lines_second}" ]]; then
    echo "FAIL: ledger was modified on re-run (before=${lines_first}, after=${lines_second})" >&2
    exit 1
fi

if [[ "${out}" != *"Host already bootstrapped; no changes required"* ]]; then
    echo "FAIL: unexpected output on re-run: ${out}" >&2
    exit 1
fi

echo "PASS: Re-run is a true no-op (no_changes, zero ledger mutations appended)."
'
}

# Test 6: Repair on a tunnel node reconstructs tunnel without socket units
test_repair_tunnel_profile_preservation() {
    echo "--- Test 6: Repair on tunnel node preserves tunnel profile without socket units ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Initial bootstrap under tunnel profile
/bootstrap/bin/opskit-bootstrap --profile tunnel --no-probe --yes >/dev/null

# Introduce drift: remove cloudflared user unit
rm -f /home/opskit/.config/systemd/user/cloudflared.service

# Run repair without specifying --profile
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null

# Assert cloudflared was restored
test -f /home/opskit/.config/systemd/user/cloudflared.service

# Assert root socket units were NEVER installed on a tunnel node
if [[ -f /etc/systemd/system/opskit-edge-443.socket || -f /etc/systemd/system/opskit-edge.service ]]; then
    echo "FAIL: repair incorrectly installed direct root socket units on a tunnel node" >&2
    exit 1
fi

echo "PASS: Repair reconstructed tunnel profile from ledger without installing socket units."
'
}

# Test 7: Subordinate UID count bound checking
test_subuid_bound_check() {
    echo "--- Test 7: Subordinate UID count bound checking ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Pre-create opskit user with absurd subuid range (> 1,000,000,000 count)
useradd -m -s /bin/bash opskit
echo "opskit:100000:2000000000" > /etc/subuid
echo "opskit:100000:2000000000" > /etc/subgid

set +e
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null 2>&1
code=$?
set -e

if [[ ${code} -ne 8 ]]; then
    echo "FAIL: Expected exit code 8 for out-of-bounds subordinate UID count, got ${code}" >&2
    exit 1
fi

echo "PASS: Out-of-bounds subordinate UID count rejected with exit 8."
'
}

# Test 8: Repair rejects invalid profile with exit 2
test_repair_invalid_profile_rejection() {
    echo "--- Test 8: Repair rejects invalid profile with exit 2 ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Initial bootstrap
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

set +e
/bootstrap/bin/opskit-bootstrap --repair --profile banana --yes >/dev/null 2>&1
code=$?
set -e

if [[ ${code} -ne 2 ]]; then
    echo "FAIL: Expected exit code 2 when passing invalid profile to repair, got ${code}" >&2
    exit 1
fi
echo "PASS: Invalid profile rejected by repair with exit 2."
'
}

# Test 9: Killed mid-apply recovery
test_killed_mid_apply_recovery() {
    echo "--- Test 9: Killed mid-apply recovery ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Run bootstrap under direct profile
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# 2. Simulate killed mid-apply on edge_socket_units:
# Delete the edge_socket_units ledger entry from apply.jsonl, but leave socket units on disk
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/ledger.sh"
    rewrite_chained_ledger "edge_socket_units" ""
)

test -f /etc/systemd/system/opskit-edge-443.socket

# 3. Re-run bootstrap: must plan edge_socket_units and append it to ledger
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

grep -q "\"edge_socket_units\"" /var/lib/opskit-bootstrap/apply.jsonl

# 4. Third run must be a true no-op
out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
if [[ "${out}" != *"Host already bootstrapped; no changes required"* ]]; then
    echo "FAIL: expected no changes on subsequent re-run, got: ${out}" >&2
    exit 1
fi

echo "PASS: Re-run cleanly reconciled unrecorded mutation from simulated mid-apply crash."
'
}

# Test 10: Golden plan deep-equality inside container
test_golden_plan_in_container() {
    echo "--- Test 10: Golden plan deep-equality inside container ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
bash /bootstrap/tests/acceptance_golden_plan.sh
'
    echo "PASS: Golden plan verified inside Debian container."
}

# Test 11: Multi-package ledger entry and undo verification
test_multi_package_ledger_and_undo() {
    echo "--- Test 11: Multi-package ledger entry and undo verification ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
export OPSKIT_TEST_FORCE_PACKAGES="1"

# Run bootstrap with forced multi-package recording
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Assert packages mutation recorded with podman and uidmap
grep -q "\"mutation_id\":\"packages\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"podman\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"uidmap\"" /var/lib/opskit-bootstrap/apply.jsonl

# Assert offline uninstaller validates canonical HMAC and undoes cleanly
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null

echo "PASS: Multi-package ledger entry signed and verified with canonical HMAC across undo."
'
}

# Test 12: Vendored uninstaller repair and re-run
test_vendored_uninstaller_repair() {
    echo "--- Test 12: Vendored uninstaller repair and re-run ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Initial bootstrap
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Simulate drift by removing a socket unit
rm -f /etc/systemd/system/opskit-edge-443.socket

# Execute repair directly from vendored copy
/var/lib/opskit-bootstrap/opskit-bootstrap --repair --yes >/dev/null
test -f /etc/systemd/system/opskit-edge-443.socket

# Re-run repair from vendored copy with zero drift
out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --repair --yes 2>&1)"
echo "${out}" | grep -q "No configuration drift detected"

echo "PASS: Vendored uninstaller repair succeeded with no self-copy crash and clean re-run."
'
}

# Test 13: Crash window service user reconciliation, purge, and warning
test_crash_window_service_user_and_purge() {
    echo "--- Test 13: Crash window service user reconciliation, purge, and warning ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Initial bootstrap
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
id opskit >/dev/null

# 2. Simulate crash window: delete service_user line from ledger
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/ledger.sh"
    rewrite_chained_ledger "service_user" ""
)
if grep -q "\"mutation_id\":\"service_user\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: service_user unexpectedly still present in ledger" >&2
    exit 1
fi

# 3. Re-run bootstrap reconciles missing service_user entry
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep -q "\"mutation_id\":\"service_user\"" /var/lib/opskit-bootstrap/apply.jsonl

# 4. Undo with purge completely cleans up user and sysusers
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
if id opskit >/dev/null 2>&1; then
    echo "FAIL: opskit user still exists after undo --purge" >&2
    exit 1
fi
if [[ -f /etc/sysusers.d/opskit.conf ]]; then
    echo "FAIL: sysusers config still exists after undo --purge" >&2
    exit 1
fi

# 5. Warning when host state exists but ledger is missing
useradd -m opskit
out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --dry-run 2>&1 || true)"
echo "${out}" | grep -q "Host state exists .* but ledger file"

echo "PASS: Crash window service user reconciliation, purge, and missing ledger warning verified."
'
}

# Test 14: Profile transition cleanup
test_profile_transition_cleanup() {
    echo "--- Test 14: Profile transition cleanup ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Initial bootstrap under tunnel profile
/bootstrap/bin/opskit-bootstrap --profile tunnel --no-probe --yes >/dev/null
test -f /home/opskit/.config/systemd/user/cloudflared.service
test ! -f /etc/systemd/system/opskit-edge-443.socket

# 2. Transition tunnel -> direct via repair
/bootstrap/bin/opskit-bootstrap --repair --profile direct --yes >/dev/null
test ! -f /home/opskit/.config/systemd/user/cloudflared.service
test -f /etc/systemd/system/opskit-edge-443.socket
if grep -q "\"mutation_id\":\"cloudflared_unit\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: cloudflared_unit still present in ledger after tunnel -> direct transition" >&2
    exit 1
fi
nft list table inet opskit >/dev/null

# 3. Transition direct -> tunnel via repair
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null
test -f /home/opskit/.config/systemd/user/cloudflared.service
test ! -f /etc/systemd/system/opskit-edge-443.socket
if grep -q "\"mutation_id\":\"edge_socket_units\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: edge_socket_units still present in ledger after direct -> tunnel transition" >&2
    exit 1
fi
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules still present in ledger after direct -> tunnel transition" >&2
    exit 1
fi
if nft list table inet opskit 2>/dev/null; then
    echo "FAIL: nftables table inet opskit still present after direct -> tunnel transition" >&2
    exit 1
fi

# 4. Unledgered cloudflared unit is preserved across transitions
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/ledger.sh"
    rewrite_chained_ledger "cloudflared_unit" ""
)
echo "# custom unledgered unit" > /home/opskit/.config/systemd/user/cloudflared.service

# Transition to direct via repair
/bootstrap/bin/opskit-bootstrap --repair --profile direct --yes >/dev/null

# Assert custom unit was preserved
test -f /home/opskit/.config/systemd/user/cloudflared.service
grep -q "custom unledgered unit" /home/opskit/.config/systemd/user/cloudflared.service

echo "PASS: Profile transition reversed old profile artifacts, removed firewall rules, preserved unledgered unit."
'
}

# Test 15: Compile plan refusal on corrupted ledger
test_corrupted_ledger_refusal() {
    echo "--- Test 15: Compile plan refusal on corrupted ledger ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Bootstrap system
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Corrupt ledger with invalid JSON line
echo "{\"invalid\":true}" >> /var/lib/opskit-bootstrap/apply.jsonl

set +e
out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
code=$?
set -e

if [[ ${code} -ne 8 ]]; then
    echo "FAIL: Expected exit code 8 on corrupted ledger in compile_plan, got ${code}" >&2
    exit 1
fi
echo "${out}" | grep -q "failed integrity verification"

echo "PASS: Corrupted ledger refused before planning with exit code 8."
'
}

# Test 16: Repair restores deleted package binary via reinstall
test_repair_restores_deleted_binary() {
    echo "--- Test 16: Repair restores deleted package binary via reinstall ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
export OPSKIT_TEST_FORCE_PACKAGES="1"

# Initial bootstrap with packages in ledger
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Delete binary of installed package
rm -f /usr/bin/newuidmap
test ! -f /usr/bin/newuidmap

# Repair configuration
out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
echo "${out}" | grep -q "Missing user namespace utilities"
test -x /usr/bin/newuidmap

echo "PASS: Deleted newuidmap binary detected and restored via package reinstall."
'
}

# Test 17: Repair detects and corrects drifted unit file content
test_repair_unit_content_drift() {
    echo "--- Test 17: Repair detects and corrects drifted unit file content ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Initial bootstrap
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Corrupt unit file content
echo "# corrupted content appended" >> /etc/systemd/system/opskit-edge-443.socket

# Run repair
out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
echo "${out}" | grep -q "has drifted from expected template"
if grep -q "corrupted content appended" /etc/systemd/system/opskit-edge-443.socket; then
    echo "FAIL: corrupted content still present in opskit-edge-443.socket after repair" >&2
    exit 1
fi

# Subsequent repair verifies no drift
out_clean="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
echo "${out_clean}" | grep -q "No configuration drift detected"

echo "PASS: Drifting unit content detected, restored, and verified clean."
'
}

# Test 18: fetch_cli reconciliation re-records entry and respects purge
test_fetch_cli_reconciliation_and_purge() {
    echo "--- Test 18: fetch_cli reconciliation and purge ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Bootstrap system
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
test -f /usr/local/bin/opskit

# 2. Simulate missing fetch_cli entry from ledger
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/ledger.sh"
    rewrite_chained_ledger "fetch_cli" ""
)
if grep -q "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: fetch_cli unexpectedly still present before reconciliation test" >&2
    exit 1
fi

# 3. Re-run bootstrap (reconciliation must re-record fetch_cli entry)
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
count="$(grep -c "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl || true)"
test "${count}" -eq 1
grep "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"after_fingerprint\":\"present:digest-verified\""

# 4. Undo with purge removes binary
/bootstrap/bin/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -f /usr/local/bin/opskit

echo "PASS: fetch_cli re-recorded on reconciliation and removed on purge."
'
}

# Test 19: Upgrade and undo preserves pre-existing admin binary
test_upgrade_and_undo_preserves_admin_binary() {
    echo "--- Test 19: Upgrade and undo preserves pre-existing admin binary ---"
    podman run --rm --privileged \
      -v "${REPO_ROOT}:/bootstrap:ro" \
      -v "${TEST_ARTIFACTS_DIR}:/artifacts_v1:ro" \
      -v "${TEST_ARTIFACTS_DIR_V2}:/artifacts_v2:ro" \
      localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"

# 0. Place pre-existing admin binary
mkdir -p /usr/local/bin
echo "ADMIN-V0" > /usr/local/bin/opskit
chmod 0755 /usr/local/bin/opskit

# 1. First bootstrap with v1
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts_v1"
export OPSKIT_RELEASE_PUBKEY="/artifacts_v1/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Assert before_fingerprint recorded present:<admin-sha> rather than absent
grep "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"before_fingerprint\":\"present:"
if grep "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"before_fingerprint\":\"absent\""; then
    echo "FAIL: fetch_cli recorded absent before_fingerprint over pre-existing binary" >&2
    exit 1
fi

test -f /usr/local/bin/opskit.pre-bootstrap
test "$(< /usr/local/bin/opskit.pre-bootstrap)" = "ADMIN-V0"
test "$(< /usr/local/bin/opskit)" != "ADMIN-V0"

# 2. Second bootstrap (upgrade to v2)
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts_v2"
export OPSKIT_RELEASE_PUBKEY="/artifacts_v2/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-2"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Verify V2 actually replaced V1, ledger updated installed_sha256, and before_fingerprint stayed ADMIN-V0
test "$(/usr/local/bin/opskit)" = "opskit-cli-v2"
v2_sha="$(sha256sum /usr/local/bin/opskit | awk "{print \$1}")"
grep "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"installed_sha256\":\"${v2_sha}\""
admin_sha="$(sha256sum /usr/local/bin/opskit.pre-bootstrap | awk "{print \$1}")"
grep "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"before_fingerprint\":\"present:${admin_sha}\""

# Backup must STILL be ADMIN-V0
test -f /usr/local/bin/opskit.pre-bootstrap
test "$(< /usr/local/bin/opskit.pre-bootstrap)" = "ADMIN-V0"

# 3. Undo
/bootstrap/bin/opskit-bootstrap --undo --yes >/dev/null

# 4. Verify admin binary restored and pre-bootstrap backup cleaned up
test -f /usr/local/bin/opskit
test "$(< /usr/local/bin/opskit)" = "ADMIN-V0"
test ! -f /usr/local/bin/opskit.pre-bootstrap

echo "PASS: Multi-upgrade preserves pre-existing admin binary across undo."
'
}

# Test 20: Vendored uninstaller from sibling prefix layout
test_vendored_uninstaller_prefix_layout() {
    echo "--- Test 20: Vendored uninstaller from sibling prefix layout ---"
    podman run --rm --privileged \
      -v "${REPO_ROOT}:/bootstrap:ro" \
      -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" \
      localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Copy repo to /var/lib/opskit-bootstrap-other
mkdir -p /var/lib/opskit-bootstrap-other
cp -a /bootstrap/* /var/lib/opskit-bootstrap-other/

# Run bootstrap from /var/lib/opskit-bootstrap-other
/var/lib/opskit-bootstrap-other/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Verify vendored files exist in /var/lib/opskit-bootstrap
test -d /var/lib/opskit-bootstrap
test -f /var/lib/opskit-bootstrap/opskit-bootstrap
test -d /var/lib/opskit-bootstrap/lib
test -f /var/lib/opskit-bootstrap/apply.jsonl

echo "PASS: Bootstrap from sibling directory vendored cleanly to state dir."
'
}

# Test 21: Firewall drift repair and transition cleanup
test_firewall_drift_repair_transition() {
    echo "--- Test 21: Firewall drift repair and transition cleanup ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Bootstrap direct
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
test -f /etc/systemd/system/opskit-edge-443.socket

# Verify initial rules and single firewall_rules ledger entry
count_443="$(nft -a list chain inet opskit input | grep -c "comment \"opskit-443\"" || true)"
count_80="$(nft -a list chain inet opskit input | grep -c "comment \"opskit-80\"" || true)"
test "${count_443}" -eq 1
test "${count_80}" -eq 1
fw_entries="$(grep -c "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl || true)"
test "${fw_entries}" -eq 1

# 2. Simulate drift: delete rule 443 by hand
handle_443="$(nft -a list chain inet opskit input | grep "comment \"opskit-443\"" | grep -o "handle [0-9]\+" | awk "{print \$2}")"
nft delete rule inet opskit input handle "${handle_443}"
test "$(nft -a list chain inet opskit input | grep -c "comment \"opskit-443\"" || true)" -eq 0

# 3. Run repair: re-adds 443 without duplicating rule 80 (apply idempotence)
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
count_443_repaired="$(nft -a list chain inet opskit input | grep -c "comment \"opskit-443\"" || true)"
count_80_repaired="$(nft -a list chain inet opskit input | grep -c "comment \"opskit-80\"" || true)"
test "${count_443_repaired}" -eq 1
test "${count_80_repaired}" -eq 1 # Assert apply idempotence
fw_entries_repaired="$(grep -c "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl || true)"
test "${fw_entries_repaired}" -eq 1

# 4. Transition direct -> tunnel
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null

# Assert zero OpsKit rules remain and table is deleted
if nft list table inet opskit 2>/dev/null; then
    echo "FAIL: nftables table inet opskit still present after Test 21 transition" >&2
    exit 1
fi
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules still present in ledger after Test 21 transition" >&2
    exit 1
fi

echo "PASS: Firewall drift repair and transition verified cleanly."
'
}

# Test 22: Crash window transition fallback removal
test_firewall_crash_window_transition() {
    echo "--- Test 22: Crash window transition fallback removal ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Bootstrap direct
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
nft list table inet opskit >/dev/null

# 2. Simulate crash window: delete firewall_rules entry from ledger while rules stay live
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/ledger.sh"
    rewrite_chained_ledger "firewall_rules" ""
)
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules unexpectedly present before Test 22 transition" >&2
    exit 1
fi
nft list table inet opskit >/dev/null

# 3. Transition direct -> tunnel via repair
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null

# 4. Assert comment-based fallback removed live rules and table is deleted
if nft list table inet opskit 2>/dev/null; then
    echo "FAIL: nftables table inet opskit still present after Test 22 transition" >&2
    exit 1
fi

echo "PASS: Crash window transition removed live rules via comment fallback."
'
}

# Test 23: Forced removal failure refuses transition and retains ledger
test_firewall_forced_removal_failure_refusal() {
    echo "--- Test 23: Forced removal failure refuses transition and retains ledger ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Bootstrap direct
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
nft list table inet opskit >/dev/null

# 2. Mock nft to fail on delete operations
mkdir -p /tmp/mock_bin
cat << "EOF" > /tmp/mock_bin/nft
#!/usr/bin/env bash
if [[ "$*" == *"delete"* ]]; then
    exit 1
fi
exec /usr/sbin/nft "$@"
EOF
chmod 0755 /tmp/mock_bin/nft
export PATH="/tmp/mock_bin:${PATH}"

# 3. Attempt transition: must fail and refuse transition
set +e
out="$(/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes 2>&1)"
code=$?
set -e

if [[ ${code} -eq 0 ]]; then
    echo "FAIL: Expected transition to be refused, but exited 0" >&2
    exit 1
fi

echo "${out}" | grep -q "Cannot complete profile transition: failed to remove host firewall rules"
echo "${out}" | grep -q "Ledger entries retained"

# 4. Assert ledger entries were retained (not wiped)
grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"mutation_id\":\"edge_socket_units\"" /var/lib/opskit-bootstrap/apply.jsonl

echo "PASS: Forced removal failure cleanly refused transition and retained ledger entries."
'
}

# Test 24: Empty-metadata variant transition
test_firewall_empty_metadata_transition() {
    echo "--- Test 24: Empty-metadata variant transition ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Bootstrap direct
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
nft list table inet opskit >/dev/null

# 2. Modify firewall_rules entry to have empty metadata: {} with valid chained HMAC
python3 -B -c "
import json
with open(\"/var/lib/opskit-bootstrap/apply.jsonl\", \"r\") as f:
    entries = [json.loads(l) for l in f if l.strip()]
for e in entries:
    if e.get(\"mutation_id\") == \"firewall_rules\":
        e[\"metadata\"] = {}
with open(\"/var/lib/opskit-bootstrap/apply.jsonl\", \"w\") as f:
    for e in entries:
        f.write(json.dumps(e, separators=(\",\", \":\")) + \"\n\")
"
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/ledger.sh"
    rewrite_chained_ledger "" ""
)

# 3. Transition direct -> tunnel via repair
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null

# 4. Assert comment-based fallback removed live rules and table is deleted
if nft list table inet opskit 2>/dev/null; then
    echo "FAIL: nftables table inet opskit still present after Test 24 empty-metadata transition" >&2
    exit 1
fi
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules still present in ledger after Test 24 transition" >&2
    exit 1
fi

echo "PASS: Empty metadata transition cleanly removed rules and updated ledger."
'
}

# Test 25: Adversarial firewall collision vs foreign chain preservation
test_firewall_adversarial_collision_and_foreign_chain() {
    echo "--- Test 25: Adversarial firewall collision vs foreign chain preservation ---"
    # Part A: In-chain prefix collision (nftables) -> admin rule survives, transition refuses exit 6, ledger retained
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Plant adversarial in-chain prefix collision rule
nft add rule inet opskit input tcp dport 8443 accept comment \"opskit-notmine\"
nft list chain inet opskit input | grep "comment \"opskit-notmine\"" >/dev/null

# Attempt direct -> tunnel transition: must refuse with exit 6 and leave opskit-notmine + ledger intact
set +e
out="$(/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes 2>&1)"
code=$?
set -e

if [[ ${code} -ne 6 ]]; then
    echo "FAIL: Expected exit 6 on in-chain collision refusal, got ${code}: ${out}" >&2
    exit 1
fi
echo "${out}" | grep "Cannot complete profile transition: failed to remove host firewall rules" >/dev/null

# OpsKit rules 443/80 removed, admin opskit-notmine rule survives, ledger retained
nft list chain inet opskit input | grep "comment \"opskit-notmine\"" >/dev/null
if nft list chain inet opskit input | grep "comment \"opskit-443\"" >/dev/null; then
    echo "FAIL: opskit-443 rule still present after Test 25 Part A removal" >&2
    exit 1
fi
if nft list chain inet opskit input | grep "comment \"opskit-80\"" >/dev/null; then
    echo "FAIL: opskit-80 rule still present after Test 25 Part A removal" >&2
    exit 1
fi
grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"mutation_id\":\"edge_socket_units\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"mutation_id\":\"edge_system_unit\"" /var/lib/opskit-bootstrap/apply.jsonl

# Resolve blocking rule and verify transition is cleanly re-runnable
h_notmine="$(nft -a list chain inet opskit input | grep "comment \"opskit-notmine\"" | grep -o "handle [0-9]\+" | awk "{print \$2}")"
nft delete rule inet opskit input handle "${h_notmine}"
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null
if nft list table inet opskit 2>/dev/null; then
    echo "FAIL: nftables table inet opskit still present after resolving collision and re-running" >&2
    exit 1
fi
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules still present in ledger after resolving collision and re-running" >&2
    exit 1
fi
echo "PASS: nftables in-chain prefix collision preserved admin rule, refused exit 6, and re-ran cleanly."
'

    # Part B: Foreign-chain substring (iptables with nft hidden) -> admin rule survives, transition succeeds exit 0
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Hide nft so iptables stack is selected
nft_bin="$(command -v nft || true)"
if [[ -n "${nft_bin}" ]]; then
    rm -f "${nft_bin}"
fi

# Plant foreign-chain admin rule containing opskit- substring in INPUT
iptables -I INPUT -p tcp --dport 8080 -m comment --comment "my-opskit-notes" -j ACCEPT
iptables -S INPUT | grep -q "my-opskit-notes"

# Bootstrap direct under iptables
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
iptables -S INPUT | grep -q "opskit-443"
iptables -S INPUT | grep -q "opskit-80"
iptables -S INPUT | grep -q "my-opskit-notes"

# Transition direct -> tunnel must succeed (exit 0) and preserve my-opskit-notes
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null
iptables -S INPUT | grep -q "my-opskit-notes"
if iptables -S INPUT | grep -q "opskit-443"; then
    echo "FAIL: opskit-443 rule still present in iptables after Test 25 Part B transition" >&2
    exit 1
fi
if iptables -S INPUT | grep -q "opskit-80"; then
    echo "FAIL: opskit-80 rule still present in iptables after Test 25 Part B transition" >&2
    exit 1
fi
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules still present in ledger after Test 25 Part B transition" >&2
    exit 1
fi
echo "PASS: iptables foreign-chain substring rule survived and transition succeeded cleanly."
'
}

# Test 26: Concurrent repairs serialized by state lock without ledger churn
test_concurrent_repairs_serialized_by_lock() {
    echo "--- Test 26: Concurrent repairs serialized by state lock without ledger churn ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Introduce firewall drift
handle_443="$(nft -a list chain inet opskit input | grep "comment \"opskit-443\"" | grep -o "handle [0-9]\+" | awk "{print \$2}")"
nft delete rule inet opskit input handle "${handle_443}"

# Launch two concurrent repairs
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null 2>&1 &
pid1=$!
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null 2>&1 &
pid2=$!

wait "${pid1}"
wait "${pid2}"

fw_entries="$(grep -c "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl || true)"
count_443="$(nft -a list chain inet opskit input | grep -c "comment \"opskit-443\"" || true)"
count_80="$(nft -a list chain inet opskit input | grep -c "comment \"opskit-80\"" || true)"
test "${fw_entries}" -eq 1
test "${count_443}" -eq 1
test "${count_80}" -eq 1
echo "PASS: Concurrent repairs serialized cleanly with fw_entries=1 and exact firewall state."
'
}

test_os_matrix_profiles
test_preexisting_user_reuse
test_banned_docker_group
test_subuid_allocation_collision_free
test_rerun_is_true_noop
test_repair_tunnel_profile_preservation
test_subuid_bound_check
test_repair_invalid_profile_rejection
test_killed_mid_apply_recovery
test_golden_plan_in_container
test_multi_package_ledger_and_undo
test_vendored_uninstaller_repair
test_crash_window_service_user_and_purge
test_profile_transition_cleanup
test_corrupted_ledger_refusal
test_repair_restores_deleted_binary
test_repair_unit_content_drift
test_fetch_cli_reconciliation_and_purge
test_upgrade_and_undo_preserves_admin_binary
test_vendored_uninstaller_prefix_layout
test_firewall_drift_repair_transition
test_firewall_crash_window_transition
test_firewall_forced_removal_failure_refusal
test_firewall_empty_metadata_transition
# Test 27: Stack-changing repair updates ledger HMAC metadata and undo cleans up
test_stack_changing_repair_and_undo_cleanup() {
    echo "--- Test 27: Stack-changing repair updates ledger and undo removes all rules ---"
    # Part A: Primary ledger update when live stack changes from nftables -> iptables
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"nftables\""

# Migrate host firewall stack to iptables (remove nft table and hide nft binary)
nft delete table inet opskit
rm -f "$(command -v nft)"

# Repair re-applies rules via iptables and updates firewall_rules metadata in-place
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
iptables -S INPUT | grep -q "opskit-443"
iptables -S INPUT | grep -q "opskit-80"
fw_entries="$(grep -c "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl || true)"
test "${fw_entries}" -eq 1
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"iptables\""

# Subsequent repair verifies ledger integrity and zero drift
repair_noop_out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
echo "${repair_noop_out}" | grep -q "No configuration drift detected"

# Undo removes all iptables rules cleanly
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
if iptables -S INPUT | grep -q "opskit-443"; then
    echo "FAIL: opskit-443 survived in iptables after stack-changing repair + undo" >&2
    exit 1
fi
if iptables -S INPUT | grep -q "opskit-80"; then
    echo "FAIL: opskit-80 survived in iptables after stack-changing repair + undo" >&2
    exit 1
fi
echo "PASS: Stack-changing repair updated firewall_rules to iptables and undo left zero rules."
'

    # Part B: Defense-in-depth fallback in undo when ledger metadata claims stale stack
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

rm -f "$(command -v nft)"
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
iptables -S INPUT | grep -q "opskit-443"

# Simulate stale metadata claiming stack=nftables with valid chained HMAC + ledger.head
python3 -B -c "
import hmac, hashlib, json, sys
sys.path.insert(0, \"/bootstrap/lib\")
from canonicalize import canonical_bytes
with open(\"/var/lib/opskit-bootstrap/ledger.key\", \"rb\") as f:
    key = f.read().strip()
with open(\"/var/lib/opskit-bootstrap/apply.jsonl\", \"r\") as f:
    entries = [json.loads(l) for l in f if l.strip()]
prev = \"genesis\"
for idx, e in enumerate(entries, start=1):
    if e.get(\"mutation_id\") == \"firewall_rules\":
        e[\"metadata\"][\"rule443\"][\"stack\"] = \"nftables\"
        e[\"metadata\"][\"rule80\"][\"stack\"] = \"nftables\"
    e[\"seq\"] = idx
    e[\"prev_hmac\"] = prev
    e.pop(\"hmac\", None)
    sig = hmac.new(key, canonical_bytes(e, strip_keys={\"hmac\"}), hashlib.sha256).hexdigest()
    e[\"hmac\"] = sig
    prev = sig
with open(\"/var/lib/opskit-bootstrap/apply.jsonl\", \"w\") as f:
    for e in entries:
        f.write(json.dumps(e, separators=(\",\", \":\")) + \"\n\")
head_obj = {\"count\": len(entries), \"head_hmac\": prev}
head_obj[\"mac\"] = hmac.new(key, canonical_bytes(head_obj), hashlib.sha256).hexdigest()
with open(\"/var/lib/opskit-bootstrap/ledger.head\", \"w\") as hf:
    hf.write(json.dumps(head_obj, separators=(\",\", \":\")) + \"\n\")
"

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
if iptables -S INPUT | grep -q "opskit-443"; then
    echo "FAIL: opskit-443 survived undo despite defense-in-depth fallback" >&2
    exit 1
fi
if iptables -S INPUT | grep -q "opskit-80"; then
    echo "FAIL: opskit-80 survived undo despite defense-in-depth fallback" >&2
    exit 1
fi
echo "PASS: Undo cross-stack defense fallback cleared live iptables rules even with stale nftables metadata."
'
}

# Test 28: Empty nft table deleted on clean path; retained + warned when untagged foreign rule occupies chain
test_nft_table_retained_and_warned_on_untagged_foreign_rule() {
    echo "--- Test 28: Untouched foreign rule in inet opskit retains table with warning ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
nft add rule inet opskit input tcp dport 9999 accept

out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
echo "${out}" | grep "Retaining nftables table .inet opskit." >/dev/null
nft list table inet opskit >/dev/null
nft list chain inet opskit input | grep "dport 9999 accept" >/dev/null
if nft list chain inet opskit input | grep "comment \"opskit-443\"" >/dev/null; then
    echo "FAIL: opskit-443 still present after undo" >&2
    exit 1
fi
if nft list chain inet opskit input | grep "comment \"opskit-80\"" >/dev/null; then
    echo "FAIL: opskit-80 still present after undo" >&2
    exit 1
fi
echo "PASS: Untagged foreign rule in inet opskit survived undo and triggered retaining warning."
'
}

# Test 29: iptables colliding comment on different port survives removal
test_iptables_colliding_comment_different_port_survives() {
    echo "--- Test 29: iptables colliding comment on different port survives removal ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

rm -f "$(command -v nft)"
iptables -I INPUT -p tcp --dport 8443 -m comment --comment "opskit-443" -j ACCEPT
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
iptables -S INPUT | grep -q -- "--dport 8443 -m comment --comment opskit-443"
if iptables -S INPUT | grep -q -- "--dport 443 -m comment --comment opskit-443"; then
    echo "FAIL: OpsKit port 443 rule still present after undo" >&2
    exit 1
fi
echo "PASS: Admin iptables rule on port 8443 with colliding opskit-443 comment survived."
'
}

# Test 30: Stale recorded handle in recreated nft table is skipped with warning
test_stale_handle_recreated_table_skipped_with_warning() {
    echo "--- Test 30: Stale handle in recreated nft table skipped with warning ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Recreate table externally so recorded handle 2 belongs to an untagged foreign rule
nft delete table inet opskit
nft add table inet opskit
nft add chain inet opskit input "{ type filter hook input priority 0; policy accept; }"
nft add rule inet opskit input tcp dport 9999 accept
nft add rule inet opskit input tcp dport 9998 accept

out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
echo "${out}" | grep "Skipping stale recorded nftables handle" >/dev/null
nft list chain inet opskit input | grep "dport 9999 accept" >/dev/null
nft list chain inet opskit input | grep "dport 9998 accept" >/dev/null
echo "PASS: Stale handle in externally recreated table skipped with warning; foreign rules preserved."
'
}

test_firewall_adversarial_collision_and_foreign_chain
test_concurrent_repairs_serialized_by_lock
test_stack_changing_repair_and_undo_cleanup
test_nft_table_retained_and_warned_on_untagged_foreign_rule
test_iptables_colliding_comment_different_port_survives
test_stale_handle_recreated_table_skipped_with_warning

# Test 31: UFW admin rule preservation (mid-life enabled, inactive staged user.rules, pre-existing allow)
test_ufw_admin_and_preexisting_rules_preserved() {
    echo "--- Test 31: UFW admin, staged inactive user.rules, and pre-existing rules survive ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
fi

# Case 2: inactive ufw staged rule in user.rules/user6.rules survives undo after nftables bootstrap
ufw allow 443/tcp >/dev/null
grep -q "dport 443" /etc/ufw/user.rules
grep -q "dport 443" /etc/ufw/user6.rules

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"nftables\""

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
grep -q "dport 443" /etc/ufw/user.rules
grep -q "dport 443" /etc/ufw/user6.rules

# Reset staged 443 rule before mid-life enabled test
ufw --force delete allow 443/tcp >/dev/null

# Case 1: mid-life enabled ufw with admin 80/tcp survives undo after nftables bootstrap
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
ufw --force enable >/dev/null
ufw allow 80/tcp >/dev/null

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
ufw status | grep -qE "^80/tcp[[:space:]]+ALLOW"
ufw status | grep -qE "^80/tcp \(v6\)[[:space:]]+ALLOW"
grep -q "dport 80" /etc/ufw/user.rules
grep -q "dport 80" /etc/ufw/user6.rules

# Clean ufw state for pre-existing allow test
ufw --force reset >/dev/null

# Case 3: pre-existing ufw 443/tcp before bootstrap survives undo; OpsKit-added opskit-80 is removed
ufw --force enable >/dev/null
ufw allow 443/tcp >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"ufw\""
ufw status | grep -qE "^80/tcp[[:space:]]+ALLOW.*# opskit-80"
! ufw status | grep -q "# opskit-443"

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
ufw status | grep -qE "^443/tcp[[:space:]]+ALLOW"
ufw status | grep -qE "^443/tcp \(v6\)[[:space:]]+ALLOW"
if ufw status | grep -qE "^80/tcp"; then
    echo "FAIL: OpsKit-added ufw 80/tcp survived undo" >&2
    exit 1
fi
echo "PASS: UFW mid-life enabled, inactive user.rules, and pre-existing rules all preserved cleanly."
'
}

# Test 32: Admin iptables rules with -s / -i / conntrack survive undo
test_iptables_qualified_admin_rules_survive() {
    echo "--- Test 32: Qualified admin iptables rules survive undo ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

rm -f "$(command -v nft)"
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 443 -m comment --comment "opskit-443" -j ACCEPT
iptables -A INPUT -i lo -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
iptables -S INPUT | grep -q -- "-A INPUT -p tcp -m tcp --dport 443 -m comment --comment opskit-443 -j ACCEPT"
iptables -S INPUT | grep -q -- "-A INPUT -p tcp -m tcp --dport 80 -m comment --comment opskit-80 -j ACCEPT"

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
iptables -S INPUT | grep -q -- "-s 10.0.0.0/8"
iptables -S INPUT | grep -q -- "-i lo"
iptables -S INPUT | grep -q -- "conntrack --ctstate NEW"
if iptables -S INPUT | grep -qE "^-A INPUT -p tcp (-m tcp )?--dport (443|80) -m comment --comment opskit-(443|80) -j ACCEPT$"; then
    echo "FAIL: exact OpsKit iptables rule survived undo" >&2
    exit 1
fi
echo "PASS: Qualified admin iptables rules survived exact removal."
'
}

# Test 33: Tagged survivor during undo preserves BOOTSTRAP_STATE_DIR and exits 6
test_undo_tagged_survivor_keeps_state_and_exits_6() {
    echo "--- Test 33: Undo tagged survivor keeps state dir and exits 6 for retry ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Wrapper blocking nft delete while allowing reads
REAL_NFT="$(command -v nft)"
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/nft <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "delete" ]]; then
    exit 1
fi
exec "${REAL_NFT}" "\$@"
EOF
chmod +x /usr/local/sbin/nft

set +e
err_out="$(PATH="/usr/local/sbin:${PATH}" /var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
rc=$?
set -e
test "${rc}" -eq 6
echo "${err_out}" | grep -q "preserving .*/var/lib/opskit-bootstrap."
test -f /var/lib/opskit-bootstrap/apply.jsonl
test -f /var/lib/opskit-bootstrap/ledger.key
test ! -f /etc/systemd/system/opskit-edge.service
nft list chain inet opskit input | grep "opskit-443" >/dev/null

# Clear block and retry --undo cleanly (and follow-up --purge)
rm -f /usr/local/sbin/nft
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
test -f /var/lib/opskit-bootstrap/apply.jsonl
! grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
if nft list table inet opskit >/dev/null 2>&1; then
    echo "FAIL: inet opskit table survived successful retry undo" >&2
    exit 1
fi
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit-bootstrap
echo "PASS: Undo tagged survivor retained state dir on exit 6 and succeeded on retry."
'
}

# Test 34: Non-rule nft objects and untagged rule retention + single warning per run
test_nft_nonrule_objects_and_untagged_single_warning() {
    echo "--- Test 34: nft non-rule objects & untagged rule retention + single warning ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Part A: set + extra chain inside inet opskit preserve table and emit warning once
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
nft add set inet opskit admin_ips "{ type ipv4_addr; }"
nft add chain inet opskit custom_chain
undo_out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
warn_count="$(echo "${undo_out}" | grep -c "Retaining nftables table .inet opskit." || true)"
test "${warn_count}" -eq 1
nft list set inet opskit admin_ips >/dev/null
nft list chain inet opskit custom_chain >/dev/null
nft delete table inet opskit

# Part B: untagged tcp dport 443 accept inside inet opskit input allows transition with single warning
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
nft add rule inet opskit input tcp dport 443 accept
rep_out="$(/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes 2>&1)"
rep_warn_count="$(echo "${rep_out}" | grep -c "Retaining nftables table .inet opskit." || true)"
test "${rep_warn_count}" -eq 1
! grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
nft list chain inet opskit input | grep "tcp dport 443 accept" >/dev/null
! nft list chain inet opskit input | grep "comment \"opskit-" >/dev/null
echo "PASS: Non-rule nft objects and untagged in-chain rule preserved with single warning and clean transition."
'
}

# Test 35: Repair NOT_FOUND zero-trace and nft-missing nf_tables warning
test_repair_exit3_clean_and_nft_blind_warning() {
    echo "--- Test 35: Repair exit 3 zero-trace & nft-missing nf_tables warning ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Part A: clean --repair on unbootstrapped node exits 3 with zero state dir residue
set +e
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null 2>&1
rc=$?
set -e
test "${rc}" -eq 3
test ! -e /var/lib/opskit-bootstrap

# Even if stale lock-only directory pre-existed, exit 3 leaves it removed
mkdir -p /var/lib/opskit-bootstrap
: > /var/lib/opskit-bootstrap/.state.lock
set +e
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null 2>&1
rc2=$?
set -e
test "${rc2}" -eq 3
test ! -e /var/lib/opskit-bootstrap

# Part B: missing nft with nf_tables loaded emits warning and avoids claiming Removed host firewall rules
if [[ -d /sys/module/nf_tables ]] || grep -qE "^nf_tables\b" /proc/modules 2>/dev/null; then
    /bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
    rm -f "$(command -v nft)"
    blind_out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
    echo "${blind_out}" | grep -q "nft binary not found while kernel nf_tables subsystem is loaded"
    if echo "${blind_out}" | grep -q "Removed host firewall rules\."; then
        echo "FAIL: undo claimed Removed host firewall rules while nft binary missing" >&2
        exit 1
    fi
fi
echo "PASS: Repair exit 3 zero-trace and nft-missing nf_tables warning verified."
'
}

test_ufw_admin_and_preexisting_rules_preserved
test_iptables_qualified_admin_rules_survive
test_undo_tagged_survivor_keeps_state_and_exits_6
test_nft_nonrule_objects_and_untagged_single_warning
test_repair_exit3_clean_and_nft_blind_warning

# Test 36: Inactive ufw undo & repair-transition clear staged opskit tuples without resurrection
test_inactive_ufw_undo_and_repair_no_resurrection() {
    echo "--- Test 36: Inactive ufw undo & repair-transition leave zero staged opskit tuples ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
fi

# Part A: bootstrap direct with ufw active -> ufw disable -> --undo --yes
ufw allow 8080/tcp >/dev/null
ufw --force enable >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"ufw\""
grep -q "comment=6f70736b69742d343433" /etc/ufw/user.rules
grep -q "comment=6f70736b69742d3830" /etc/ufw/user6.rules

ufw disable >/dev/null
undo_out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
echo "${undo_out}" | grep -q "Removed host firewall rules\."
if grep -q "comment=6f70736b69742d" /etc/ufw/user.rules /etc/ufw/user6.rules; then
    echo "FAIL: staged opskit ufw comment survived undo after ufw disable" >&2
    exit 1
fi
ufw --force enable >/dev/null
if ufw status | grep -qE "^(443|80)(/tcp)?[[:space:]]"; then
    echo "FAIL: opskit 443/80 resurrected on re-enable after undo" >&2
    exit 1
fi
ufw status | grep -qE "^8080/tcp[[:space:]]+ALLOW"

# Part B (Repair transition twin): bootstrap direct with ufw active -> ufw disable -> --repair --profile tunnel --yes
ufw --force reset >/dev/null
ufw allow 8080/tcp >/dev/null
ufw --force enable >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep -q "comment=6f70736b69742d343433" /etc/ufw/user.rules

ufw disable >/dev/null
rep_out="$(/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes 2>&1)"
echo "${rep_out}" | grep -q "Removed host firewall rules\."
if grep -q "comment=6f70736b69742d" /etc/ufw/user.rules /etc/ufw/user6.rules; then
    echo "FAIL: staged opskit ufw comment survived repair transition after ufw disable" >&2
    exit 1
fi
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules still present in ledger after tunnel transition" >&2
    exit 1
fi
ufw --force enable >/dev/null
if ufw status | grep -qE "^(443|80)(/tcp)?[[:space:]]"; then
    echo "FAIL: opskit 443/80 resurrected on re-enable after repair transition" >&2
    exit 1
fi
ufw status | grep -qE "^8080/tcp[[:space:]]+ALLOW"
echo "PASS: Inactive ufw undo and repair-transition left zero staged opskit tuples and no resurrection."
'
}

# Test 37: Shared gate catches forced ufw delete failure and permanent firewalld survivor
test_repair_gate_catches_ufw_and_firewalld_permanent_survivors() {
    echo "--- Test 37: Shared gate catches forced ufw delete failure & firewalld --permanent survivor ---"
    # Part A: Forced ufw --force delete failure during direct -> tunnel repair refuses exit 6 with ledger retained
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
fi

ufw --force enable >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

REAL_UFW="$(command -v ufw)"
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/ufw <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
    if [[ "\${a}" == "delete" ]]; then
        exit 1
    fi
done
exec "${REAL_UFW}" "\$@"
EOF
chmod +x /usr/local/sbin/ufw

set +e
gate_out="$(PATH="/usr/local/sbin:${PATH}" /bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes 2>&1)"
rc=$?
set -e
test "${rc}" -eq 6
echo "${gate_out}" | grep -q "ufw:443/tcp"
echo "${gate_out}" | grep -q "Ledger entries retained"
grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"mutation_id\":\"edge_socket_units\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"mutation_id\":\"edge_system_unit\"" /var/lib/opskit-bootstrap/apply.jsonl

# Remove wrapper and verify re-run clears rules and completes transition cleanly
rm -f /usr/local/sbin/ufw
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null
if grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl; then
    echo "FAIL: firewall_rules still in ledger after retrying repair transition" >&2
    exit 1
fi
if grep -q "comment=6f70736b69742d" /etc/ufw/user.rules /etc/ufw/user6.rules; then
    echo "FAIL: staged opskit ufw comment remained after clean retry" >&2
    exit 1
fi
echo "PASS: Forced ufw delete failure refused exit 6 with ledger retained and succeeded on retry."
'

    # Part B: firewalld --permanent survivor caught by shared helper even when runtime query returns false
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-rhel:9 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="5.14.0-427.el9.x86_64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

mkdir -p /usr/local/sbin
# Mock firewall-cmd: runtime --query-port fails (dropped runtime), --permanent --remove-port fails, --permanent --query-port succeeds
cat > /usr/local/sbin/firewall-cmd <<EOF
#!/usr/bin/env bash
has_perm=0
has_query=0
has_remove=0
for a in "\$@"; do
    case "\$a" in
        --permanent) has_perm=1 ;;
        --query-port=*) has_query=1 ;;
        --remove-port=*) has_remove=1 ;;
    esac
done
if [[ \${has_perm} -eq 1 && \${has_query} -eq 1 ]]; then
    exit 0
fi
if [[ \${has_perm} -eq 1 && \${has_remove} -eq 1 ]]; then
    exit 1
fi
exit 1
EOF
chmod +x /usr/local/sbin/firewall-cmd

export PATH="/usr/local/sbin:${PATH}"
LIB_DIR="/bootstrap/lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/family/rhel.sh"
surv="$(collect_tagged_firewall_survivors "{\"rule443\":{\"stack\":\"firewalld\",\"port\":443,\"proto\":\"tcp\",\"pre_existing\":false},\"rule80\":{\"stack\":\"firewalld\",\"port\":80,\"proto\":\"tcp\",\"pre_existing\":false}}")"
echo "${surv}" | grep -q "firewalld:443/tcp"
echo "${surv}" | grep -q "firewalld:80/tcp"

# Verify repair transition gate uses shared helper and refuses exit 6 with ledger retained
REAL_SYSTEMCTL="$(command -v systemctl)"
cat > /usr/local/sbin/firewalld <<EOF
#!/usr/bin/env bash
exit 0
EOF
chmod +x /usr/local/sbin/firewalld

cat > /usr/local/sbin/systemctl <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "is-active" ]]; then
    for a in "\$@"; do
        [[ "\$a" == "firewalld" ]] && exit 0
    done
fi
exec "${REAL_SYSTEMCTL}" "\$@"
EOF
chmod +x /usr/local/sbin/systemctl

# Bootstrap with a mock firewall-cmd that accepts add/reload, then switch to failing remove
cat > /usr/local/sbin/firewall-cmd <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
    case "\$a" in
        --query-port=*) exit 1 ;;
        --permanent) : ;;
        --add-port=*) exit 0 ;;
        --reload) exit 0 ;;
        --list-ports) echo "443/tcp 80/tcp"; exit 0 ;;
    esac
done
exit 0
EOF
chmod +x /usr/local/sbin/firewall-cmd

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"firewalld\""

# Now make --query-port fail (runtime dropped), --permanent --query-port succeed, --permanent --remove-port fail
cat > /usr/local/sbin/firewall-cmd <<EOF
#!/usr/bin/env bash
has_perm=0
has_query=0
has_remove=0
for a in "\$@"; do
    case "\$a" in
        --permanent) has_perm=1 ;;
        --query-port=*) has_query=1 ;;
        --remove-port=*) has_remove=1 ;;
    esac
done
if [[ \${has_perm} -eq 1 && \${has_query} -eq 1 ]]; then
    exit 0
fi
if [[ \${has_perm} -eq 1 && \${has_remove} -eq 1 ]]; then
    exit 1
fi
exit 1
EOF
chmod +x /usr/local/sbin/firewall-cmd

set +e
rhel_gate_out="$(/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes 2>&1)"
rhel_rc=$?
set -e
test "${rhel_rc}" -eq 6
echo "${rhel_gate_out}" | grep -q "firewalld:443/tcp"
echo "${rhel_gate_out}" | grep -q "Ledger entries retained"
grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
echo "PASS: Shared helper and repair gate caught firewalld --permanent survivor cleanly."
'
}

test_inactive_ufw_undo_and_repair_no_resurrection
test_repair_gate_catches_ufw_and_firewalld_permanent_survivors

# Test 38: Package-removed conffile/zone-XML survivor detection and exact hex comment anchoring
test_package_removed_survivors_and_exact_comment_anchor() {
    echo "--- Test 38: Package-removed ufw/firewalld survivors & exact comment anchor ---"
    # Part A (package-removed conffile + prefix-sharing admin comment): remove ufw package keeping conffiles -> undo fails exit 6 with state dir retained;
    # legacy comment opskit-443-legacy does NOT block clean undo once opskit-443/80 removed;
    # reinstall ufw -> retry undo completes exit 0 and enable does not resurrect 443/80.
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
fi

# Admin prefix collision: Admin rule with comment sharing prefix "opskit-443-legacy" must NOT block undo
ufw --force enable >/dev/null
ufw allow 8443/tcp comment "opskit-443-legacy" >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
! grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit-bootstrap
ufw status | grep -qE "^8443/tcp[[:space:]]+ALLOW.*# opskit-443-legacy"

# Clean slate for package-removed test
ufw --force reset >/dev/null
ufw allow 8080/tcp comment "opskit-443-legacy" >/dev/null
ufw --force enable >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"ufw\""
grep -q "comment=6f70736b69742d343433$" /etc/ufw/user.rules
grep -q "comment=6f70736b69742d3830$" /etc/ufw/user6.rules

# Remove ufw binary/package while keeping /etc/ufw/user.rules + user6.rules
DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq ufw >/dev/null
hash -r
if command -v ufw >/dev/null 2>&1; then
    echo "FAIL: ufw binary still present after apt-get remove" >&2
    exit 1
fi

set +e
rem_out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
rem_rc=$?
set -e
test "${rem_rc}" -eq 6
echo "${rem_out}" | grep -q "ufw:443/tcp"
echo "${rem_out}" | grep -q "ufw:80/tcp"
test -f /var/lib/opskit-bootstrap/apply.jsonl
test -f /var/lib/opskit-bootstrap/ledger.key

# Reinstall ufw -> retry undo completes cleanly; legacy-comment admin rule survives; re-enable does not resurrect 443/80
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
hash -r
# In non-systemd container, mirror deb-systemd-invoke starting ufw.service when ENABLED=yes
if grep -q "^ENABLED=yes" /etc/ufw/ufw.conf && [[ -x /usr/lib/ufw/ufw-init ]]; then
    /usr/lib/ufw/ufw-init start quiet
fi
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
! grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
if grep -qE "comment=6f70736b69742d(343433|3830)([[:space:]]|$)" /etc/ufw/user.rules /etc/ufw/user6.rules; then
    echo "FAIL: opskit-443/80 tuples survived reinstall + retry undo" >&2
    exit 1
fi
ufw --force enable >/dev/null
if ufw status | grep -qE "^(443|80)(/tcp)?[[:space:]]"; then
    echo "FAIL: opskit 443/80 resurrected after package-remove -> reinstall -> undo -> enable" >&2
    exit 1
fi
ufw status | grep -qE "^8080/tcp[[:space:]]+ALLOW.*# opskit-443-legacy"
echo "PASS: Package-removed ufw conffile survivors caught (exit 6 + retry clean) and prefix-suffix legacy comment ignored."
'

    # Part B (package-removed firewalld XML): firewalld zone XML survivor detected when firewall-cmd and firewall-offline-cmd are absent
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-rhel:9 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="5.14.0-427.el9.x86_64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

mkdir -p /etc/firewalld/zones
cat > /etc/firewalld/zones/public.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>Public</short>
  <port protocol="tcp" port="443"/>
  <port port="80" protocol="tcp"/>
</zone>
EOF

# Confirm neither firewall-cmd nor firewall-offline-cmd exists on image
! command -v firewall-cmd >/dev/null 2>&1
! command -v firewall-offline-cmd >/dev/null 2>&1

LIB_DIR="/bootstrap/lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/family/rhel.sh"
surv="$(collect_tagged_firewall_survivors "{\"rule443\":{\"stack\":\"firewalld\",\"port\":443,\"proto\":\"tcp\",\"pre_existing\":false},\"rule80\":{\"stack\":\"firewalld\",\"port\":80,\"proto\":\"tcp\",\"pre_existing\":false}}")"
echo "${surv}" | grep -q "firewalld:443/tcp"
echo "${surv}" | grep -q "firewalld:80/tcp"

# Clean zone XML yields zero survivors
cat > /etc/firewalld/zones/public.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>Public</short>
</zone>
EOF
surv_clean="$(collect_tagged_firewall_survivors "{\"rule443\":{\"stack\":\"firewalld\",\"port\":443,\"proto\":\"tcp\",\"pre_existing\":false},\"rule80\":{\"stack\":\"firewalld\",\"port\":80,\"proto\":\"tcp\",\"pre_existing\":false}}")"
test -z "${surv_clean}"
echo "PASS: Binary-free firewalld zone XML survivor detection verified."
'
}

test_package_removed_survivors_and_exact_comment_anchor

# Test 39: Same-profile repair survivor gate, unconditional residue scans, and metadata-edge hardening
test_same_profile_repair_and_unconditional_residue() {
    echo "--- Test 39: Same-profile repair gate, empty-meta binary-removed undo, zone/hex/XML hardening ---"
    # Part A: Debian cases (same-profile repair after apt-get remove ufw, ufw disable + repair,
    #         empty metadata {} + binary-removed ufw, trailing-space hex anchor)
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
fi

# Subcase 1: ufw active -> bootstrap direct -> ufw disable -> same-profile --repair must refuse exit 6 and keep ufw ledger
ufw --force enable >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"ufw\""
ufw disable >/dev/null

set +e
p5_out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
p5_rc=$?
set -e
test "${p5_rc}" -eq 6
echo "${p5_out}" | grep -q "ufw:443/tcp"
echo "${p5_out}" | grep -q "Ledger entries retained"
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"ufw\""
! nft list table inet opskit >/dev/null 2>&1

# Undo from ufw-disabled state still succeeds cleanly and leaves zero resurrection
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
! grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit-bootstrap
ufw --force enable >/dev/null
if ufw status | grep -qE "^(443|80)(/tcp)?[[:space:]]"; then
    echo "FAIL: opskit 443/80 resurrected after ufw-disable undo" >&2
    exit 1
fi

# Subcase 2: ufw active -> bootstrap direct -> apt-get remove ufw -> same-profile --repair must exit 6;
#     --undo must also exit 6 preserving state; reinstall ufw -> undo completes -> enable has zero 443/80
ufw --force reset >/dev/null
ufw --force enable >/dev/null
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq ufw >/dev/null
hash -r

set +e
p8_rep_out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
p8_rep_rc=$?
set -e
test "${p8_rep_rc}" -eq 6
echo "${p8_rep_out}" | grep -q "ufw:443/tcp"
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"ufw\""
! nft list table inet opskit >/dev/null 2>&1

set +e
p8_undo_out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
p8_undo_rc=$?
set -e
test "${p8_undo_rc}" -eq 6
echo "${p8_undo_out}" | grep -q "ufw:443/tcp"
test -f /var/lib/opskit-bootstrap/apply.jsonl

# Subcase 3: overwrite firewall_rules metadata to {} with valid chained HMAC while ufw binary is removed -> undo STILL exits 6
cp /var/lib/opskit-bootstrap/apply.jsonl /tmp/apply.removed.bak
cp /var/lib/opskit-bootstrap/ledger.head /tmp/head.removed.bak
python3 -B -c "
import json
with open(\"/var/lib/opskit-bootstrap/apply.jsonl\", \"r\") as f:
    entries = [json.loads(l) for l in f if l.strip()]
for e in entries:
    if e.get(\"mutation_id\") == \"firewall_rules\":
        e[\"metadata\"] = {}
with open(\"/var/lib/opskit-bootstrap/apply.jsonl\", \"w\") as f:
    for e in entries:
        f.write(json.dumps(e, separators=(\",\", \":\")) + \"\n\")
"
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/ledger.sh"
    rewrite_chained_ledger "" ""
)
set +e
p2_undo_out="$(/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes 2>&1)"
p2_undo_rc=$?
set -e
test "${p2_undo_rc}" -eq 6
echo "${p2_undo_out}" | grep -q "ufw:443/tcp"
echo "${p2_undo_out}" | grep -q "ufw:80/tcp"
test -f /var/lib/opskit-bootstrap/apply.jsonl
mv /tmp/apply.removed.bak /var/lib/opskit-bootstrap/apply.jsonl
mv /tmp/head.removed.bak /var/lib/opskit-bootstrap/ledger.head

# Subcase 4: trailing-space hex comment=...20 + malformed metadata fallback
LIB_DIR="/bootstrap/lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/family/debian.sh"
cp /etc/ufw/user.rules /tmp/user.rules.bak
printf "### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in comment=6f70736b69742d34343320\n" >> /etc/ufw/user.rules
surv_hex="$(collect_tagged_firewall_survivors "{not-valid-json" 2>/tmp/hex_warn.txt)"
grep -q "Failed to parse recorded firewall metadata" /tmp/hex_warn.txt
echo "${surv_hex}" | grep -q "ufw:443/tcp"
mv /tmp/user.rules.bak /etc/ufw/user.rules

# Reinstall ufw + start kernel rules + retry undo completes cleanly -> enable shows zero 443/80
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
hash -r
if grep -q "^ENABLED=yes" /etc/ufw/ufw.conf && [[ -x /usr/lib/ufw/ufw-init ]]; then
    /usr/lib/ufw/ufw-init start quiet
fi
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
! grep -q "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit-bootstrap
ufw --force enable >/dev/null
if ufw status | grep -qE "^(443|80)(/tcp)?[[:space:]]"; then
    echo "FAIL: opskit 443/80 resurrected after package-removed recovery + undo" >&2
    exit 1
fi
echo "PASS: ufw-disable repair, package-removed repair, empty-meta undo, malformed-metadata fallback, and trailing-space hex all verified."
'

    # Part B: RHEL firewalld twins (default-zone scoping, XML comment stripping,
    #         empty-metadata unconditional check, and same-profile repair refusal)
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-rhel:9 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="5.14.0-427.el9.x86_64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

LIB_DIR="/bootstrap/lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/family/rhel.sh"

# Default-zone scoping: admin custom.xml with port 443 is ignored when DefaultZone is public
mkdir -p /etc/firewalld/zones
echo "DefaultZone=public" > /etc/firewalld/firewalld.conf
cat > /etc/firewalld/zones/public.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone><short>Public</short></zone>
EOF
cat > /etc/firewalld/zones/custom.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone><short>Custom</short><port protocol="tcp" port="443"/></zone>
EOF
surv_custom="$(collect_tagged_firewall_survivors "{}")"
test -z "${surv_custom}"

# XML comment stripping: malformed XML containing <!-- <port protocol="tcp" port="443"/> --> yields zero survivors
cat > /etc/firewalld/zones/public.xml <<EOF
<zone><short>Broken
<!-- <port protocol="tcp" port="443"/> -->
EOF
surv_commented="$(collect_tagged_firewall_survivors "{}")"
test -z "${surv_commented}"

# Empty metadata {} catches real port="443" / port="80" in DefaultZone public.xml unconditionally
cat > /etc/firewalld/zones/public.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>Public</short>
  <port protocol="tcp" port="443"/>
  <port protocol="tcp" port="80"/>
</zone>
EOF
surv_empty_meta="$(collect_tagged_firewall_survivors "{}")"
echo "${surv_empty_meta}" | grep -q "firewalld:443/tcp"
echo "${surv_empty_meta}" | grep -q "firewalld:80/tcp"

# Same-profile --repair twin on firewalld: bootstrap with mock firewalld -> remove mock binaries
# leaving ports in public.xml -> --repair --yes (same profile direct) refuses exit 6 and keeps firewalld in ledger
REAL_SYSTEMCTL="$(command -v systemctl)"
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/firewalld <<EOF
#!/usr/bin/env bash
exit 0
EOF
chmod +x /usr/local/sbin/firewalld
cat > /usr/local/sbin/systemctl <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "is-active" ]]; then
    for a in "\$@"; do
        [[ "\$a" == "firewalld" ]] && exit 0
    done
fi
exec "${REAL_SYSTEMCTL}" "\$@"
EOF
chmod +x /usr/local/sbin/systemctl
cat > /usr/local/sbin/firewall-cmd <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
    case "\$a" in
        --get-default-zone) echo "public"; exit 0 ;;
        --query-port=*) exit 1 ;;
        --list-ports) echo "443/tcp 80/tcp"; exit 0 ;;
    esac
done
exit 0
EOF
chmod +x /usr/local/sbin/firewall-cmd

PATH="/usr/local/sbin:${PATH}" /bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"firewalld\""
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"zone\":\"public\""

# Simulate firewalld package removal leaving public.xml behind on disk
rm -f /usr/local/sbin/firewalld /usr/local/sbin/firewall-cmd /usr/local/sbin/systemctl
set +e
fwd_rep_out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
fwd_rep_rc=$?
set -e
test "${fwd_rep_rc}" -eq 6
echo "${fwd_rep_out}" | grep -q "firewalld:443/tcp"
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"firewalld\""
echo "PASS: firewalld custom-zone isolation, XML-comment strip, empty-metadata scan, and same-profile repair refusal verified."
'
}

test_same_profile_repair_and_unconditional_residue

# Test 40: Pre-existing service account, subuid/subgid reuse, linger preservation on purge, and OpsKit-created purge
test_preexisting_user_preserved_on_purge() {
    echo "--- Test 40: Pre-existing user/subuid/linger preserved on purge; missing subgid filled without duplicating subuid ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Pre-create admin UID-1500 opskit account, admin file, pre-existing subuid only, and pre-existing linger
useradd -u 1500 -m -s /bin/bash opskit
echo "keep-me" > /home/opskit/admin_file.txt
echo "opskit:200000:65536" > /etc/subuid
: > /etc/subgid
mkdir -p /var/lib/systemd/linger
touch /var/lib/systemd/linger/opskit

# Run 1: records pre-existing user & linger honestly, fills missing subgid without duplicating subuid
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
test "$(id -u opskit)" -eq 1500
test -f /home/opskit/admin_file.txt
test "$(grep -c "^opskit:" /etc/subuid)" -eq 1
test "$(grep -c "^opskit:" /etc/subgid)" -eq 1
grep -q "^opskit:200000:65536$" /etc/subgid
test ! -f /etc/sysusers.d/opskit.conf
grep "\"mutation_id\":\"service_user\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"created\":false"
grep "\"mutation_id\":\"service_user\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"before_fingerprint\":\"present:uid=1500"
grep "\"mutation_id\":\"subuid_allocation\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"subuid_allocated\":false"
grep "\"mutation_id\":\"subuid_allocation\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"subgid_allocated\":true"
grep "\"mutation_id\":\"user_linger\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"enabled\":false"

# Run 2: must be a true no-op with zero ledger lines added
lines_r1="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"
out_r2="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
lines_r2="$(wc -l < /var/lib/opskit-bootstrap/apply.jsonl)"
test "${lines_r1}" -eq "${lines_r2}"
echo "${out_r2}" | grep -q "Host already bootstrapped; no changes required"

# Verify vendored lib contains zero __pycache__ or pyc files
if find /var/lib/opskit-bootstrap/lib -name "__pycache__" -o -name "*.py[cod]" | grep -q .; then
    echo "FAIL: bytecode cache leaked into vendored bootstrap state dir" >&2
    exit 1
fi

# Purge uninstall: preserves UID-1500 user, /home/opskit/admin_file.txt, pre-existing subuid, and pre-existing linger;
# removes only OpsKit-added subgid entry!
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
id opskit >/dev/null
test "$(id -u opskit)" -eq 1500
test "$(< /home/opskit/admin_file.txt)" = "keep-me"
grep -q "^opskit:200000:65536$" /etc/subuid
! grep -q "^opskit:" /etc/subgid
test -f /var/lib/systemd/linger/opskit
echo "PASS: Pre-existing user, home data, subuid, and linger preserved across Run 1/Run 2 and --undo --purge."
'
}

# Test 41: Scoped firewalld non-stack ignore, active-stack firewall check, minimal RHEL without cmp, SELinux idempotency
test_firewalld_isolation_active_stack_and_minimal_rhel() {
    echo "--- Test 41: Scoped firewalld check, strict active-stack precedence, minimal RHEL (no cmp), and SELinux idempotency ---"
    # Part A (Debian): non-firewalld stack ignores admin firewalld zone XML; mid-life enabled ufw is not masked by nftables
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
fi

# Plant untagged firewalld zone XML while bootstrapping on nftables
mkdir -p /etc/firewalld/zones
echo "DefaultZone=public" > /etc/firewalld/firewalld.conf
cat > /etc/firewalld/zones/public.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone><short>Public</short><port protocol="tcp" port="443"/><port protocol="tcp" port="80"/></zone>
EOF

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"nftables\""

# Same-profile repair, transition, and undo must all ignore firewalld XML when recorded stack is nftables
rep_out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
echo "${rep_out}" | grep -q "No configuration drift detected"

# Enable ufw mid-life without adding 443/80: strict active-stack precedence must report firewall drift on ufw
ufw --force enable >/dev/null
set +e
drift_out="$(/bootstrap/bin/opskit-bootstrap --repair 2>&1)"
drift_rc=$?
set -e
test "${drift_rc}" -eq 5
echo "${drift_out}" | grep -q "firewall_rules:"

# Disable ufw again, verify tunnel transition + undo both ignore admin firewalld XML
ufw disable >/dev/null
/bootstrap/bin/opskit-bootstrap --repair --profile tunnel --yes >/dev/null
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
! grep -q "\"mutation_id\":\"cloudflared_unit\"" /var/lib/opskit-bootstrap/apply.jsonl
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit-bootstrap
echo "PASS: Admin firewalld XML ignored when another stack owns node; strict active-stack check caught mid-life ufw."
'

    # Part B (RHEL minimal without cmp + SELinux enforcing): idempotent Run 2 and zero phantom drift on --repair
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-rhel:9 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="5.14.0-427.el9.x86_64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
export MOCK_SELINUX_STATUS="enforcing"

# Shadow/remove cmp so minimal RHEL without diffutils is exercised
rm -f "$(command -v cmp || true)" 2>/dev/null || true
! command -v cmp >/dev/null 2>&1

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep -q "\"mutation_id\":\"security_labels\"" /var/lib/opskit-bootstrap/apply.jsonl

# Second run must be a true no-op even with enforcing SELinux and without cmp
r2_out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
echo "${r2_out}" | grep -q "Host already bootstrapped; no changes required"

# Repair must report zero phantom drift without cmp
rep_out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
echo "${rep_out}" | grep -q "No configuration drift detected"
echo "PASS: Minimal RHEL without cmp and enforcing SELinux achieved clean Run 2 no-op and zero phantom drift."
'
}

# Test 42: Profile transitions state integrity (tunnel->private, private->direct, non-repair re-run),
#          corrupted CLI binary detection/repair, and approved PLAN_HASH binding
test_profile_state_integrity_cli_digest_drift_and_plan_hash() {
    echo "--- Test 42: Profile transitions, non-repair re-run cleanup, CLI digest drift repair, and plan hash stability ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Start in tunnel profile
/bootstrap/bin/opskit-bootstrap --profile tunnel --no-probe --yes >/dev/null
test -f /home/opskit/.config/systemd/user/cloudflared.service
test -f /home/opskit/.config/systemd/user/opskit-edge.service

# 2. tunnel -> private via --repair: must remove cloudflared AND update all ledger entries to profile=private
/bootstrap/bin/opskit-bootstrap --repair --profile private --yes >/dev/null
test ! -f /home/opskit/.config/systemd/user/cloudflared.service
! grep -q "\"mutation_id\":\"cloudflared_unit\"" /var/lib/opskit-bootstrap/apply.jsonl
! grep -q "\"profile\":\"tunnel\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"profile\":\"private\"" /var/lib/opskit-bootstrap/apply.jsonl

# Subsequent repair must stay private and NOT resurrect cloudflared
priv_rep="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
echo "${priv_rep}" | grep -q "No configuration drift detected"
test ! -f /home/opskit/.config/systemd/user/cloudflared.service

# 3. private -> direct via --repair: removes user-scope opskit-edge.service
/bootstrap/bin/opskit-bootstrap --repair --profile direct --yes >/dev/null
test ! -f /home/opskit/.config/systemd/user/opskit-edge.service
test -f /etc/systemd/system/opskit-edge-443.socket
grep -q "\"profile\":\"direct\"" /var/lib/opskit-bootstrap/apply.jsonl

# 4. Non-repair re-run transitions: direct -> tunnel WITHOUT --repair removes sockets & firewall;
#    tunnel -> direct WITHOUT --repair removes cloudflared & user edge!
/bootstrap/bin/opskit-bootstrap --profile tunnel --no-probe --yes >/dev/null
test ! -f /etc/systemd/system/opskit-edge-443.socket
! nft list table inet opskit >/dev/null 2>&1
test -f /home/opskit/.config/systemd/user/cloudflared.service
test -f /home/opskit/.config/systemd/user/opskit-edge.service

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
test ! -f /home/opskit/.config/systemd/user/cloudflared.service
test ! -f /home/opskit/.config/systemd/user/opskit-edge.service
! grep -q "\"mutation_id\":\"cloudflared_unit\"" /var/lib/opskit-bootstrap/apply.jsonl
test -f /etc/systemd/system/opskit-edge-443.socket
nft list chain inet opskit input | grep "comment \"opskit-443\"" >/dev/null

# 5. CLI corruption & chmod -x caught by repair drift check and restored cleanly
echo "TAMPERED_CLI" > /usr/local/bin/opskit
chmod 0644 /usr/local/bin/opskit
set +e
chmod_out="$(/bootstrap/bin/opskit-bootstrap --repair 2>&1)"
chmod_rc=$?
set -e
test "${chmod_rc}" -eq 5
echo "${chmod_out}" | grep -q "fetch_cli: Binary at .* is not executable"

chmod 0755 /usr/local/bin/opskit
set +e
sha_drift_out="$(/bootstrap/bin/opskit-bootstrap --repair 2>&1)"
sha_drift_rc=$?
set -e
test "${sha_drift_rc}" -eq 5
echo "${sha_drift_out}" | grep -q "fetch_cli: Digest mismatch"

/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
test -x /usr/local/bin/opskit
expected_cli_sha="$(python3 -B -c "import json; d=json.load(open(\"/artifacts/release-manifest.json\")); import os; print(d[\"artifacts\"][f\"opskit-linux-{os.uname().machine}\"][\"sha256\"])")"
test "$(sha256sum /usr/local/bin/opskit | awk "{print \$1}")" = "${expected_cli_sha}"

# 6. Pre-confirmation PLAN_HASH matches the hash recorded in the ledger on non-MOCK apply
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -f /usr/local/bin/opskit
test ! -f /usr/local/bin/opskit.pre-bootstrap
pre_plan="/tmp/approved_plan.json"
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --plan-json "${pre_plan}" >/dev/null
approved_h="$(sha256sum "${pre_plan}" | awk "{print \$1}")"
# Test explicit plan hash stability using reused PLAN_EXPIRES_AT in-process:
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/detect.sh"
    source "${LIB_DIR}/family/debian.sh"
    source "${LIB_DIR}/manifest.sh"
    source "${LIB_DIR}/probe.sh"
    source "${LIB_DIR}/plan.sh"
    detect_capabilities
    CHOSEN_PROFILE="direct"
    PROBE_STATUS="skipped"
    PROBE_REACHABLE_V4=false
    PROBE_REACHABLE_V6=false
    PROBE_DETAILS="test"
    compile_plan
    h1="${PLAN_HASH}"
    sleep 2
    compile_plan
    h2="${PLAN_HASH}"
    test "${h1}" = "${h2}"
)
echo "PASS: Profile transition integrity, non-repair cleanup, CLI digest repair, and PLAN_HASH stability verified."
'
}

# Test 43: Tampered offline repair refusal, superseded firewall repair, partial subid repair flags,
#          half-existing Run 1 preservation, tunnel->private re-run delta, unreadable file, atomic ledger swap
test_repair_refusal_superseded_fw_and_ownership_edges() {
    echo "--- Test 43: Tampered CLI offline repair refusal, superseded firewall repair, half-existing Run 1, tunnel->private delta, atomic swap ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
fi
ufw disable >/dev/null 2>&1 || true

# 1. Tampered binary + offline --repair --yes without artifact source MUST refuse exit 9 and leave ledger untouched
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
orig_cli_sha="$(python3 -B -c "import json; print([json.loads(l)[\"metadata\"][\"installed_sha256\"] for l in open(\"/var/lib/opskit-bootstrap/apply.jsonl\") if \"fetch_cli\" in l][0])")"
printf "#!/bin/sh\necho TAMPERED\n" > /usr/local/bin/opskit
chmod 0755 /usr/local/bin/opskit
set +e
refuse_out="$(env -u OPSKIT_ARTIFACT_SOURCE_DIR /var/lib/opskit-bootstrap/opskit-bootstrap --repair --yes 2>&1)"
refuse_rc=$?
set -e
test "${refuse_rc}" -eq 9
echo "${refuse_out}" | grep -q "Provide --artifact-dir"
after_cli_sha="$(python3 -B -c "import json; print([json.loads(l)[\"metadata\"][\"installed_sha256\"] for l in open(\"/var/lib/opskit-bootstrap/apply.jsonl\") if \"fetch_cli\" in l][0])")"
test "${orig_cli_sha}" = "${after_cli_sha}"

# Repair with valid source restores clean state
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null

# 2. Superseded firewall stack (nftables -> ufw): foreign iptables survivor still aborts exit 6; clean nftables -> ufw completes
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
ufw --force enable >/dev/null
iptables -I INPUT -p tcp --dport 443 -m comment --comment "opskit-443" -j ACCEPT
set +e
foreign_out="$(/bootstrap/bin/opskit-bootstrap --repair --yes 2>&1)"
foreign_rc=$?
set -e
test "${foreign_rc}" -eq 6
iptables -D INPUT -p tcp --dport 443 -m comment --comment "opskit-443" -j ACCEPT

/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
! nft list chain inet opskit input >/dev/null 2>&1 || ! nft list chain inet opskit input 2>/dev/null | grep -q "comment \"opskit-"
grep "\"mutation_id\":\"firewall_rules\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"stack\":\"ufw\""
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
ufw disable >/dev/null

# 3. Partial subgid repair preserves OpsKit subuid_allocated=true on pre-existing user
useradd -u 1500 -m -s /bin/bash opskit
sed -i "/^opskit:/d" /etc/subuid /etc/subgid
warn_out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
# Single pre-existing warning across pre-confirm + lock compile_plan
test "$(echo "${warn_out}" | grep -c "Host state exists" || true)" -eq 1
: > /etc/subgid
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
grep "\"mutation_id\":\"subuid_allocation\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"subuid_allocated\":true"
grep "\"mutation_id\":\"subuid_allocation\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"subgid_allocated\":true"
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test "$(grep -c "^opskit:" /etc/subuid || true)" -eq 0
test "$(grep -c "^opskit:" /etc/subgid || true)" -eq 0
userdel -r opskit 2>/dev/null || true
rm -rf /home/opskit /var/lib/systemd/linger/opskit

# 4. Half-existing Run 1: user absent, subuid + linger present -> allocated:false, enabled:false, preserved on purge
echo "opskit:250000:65536" > /etc/subuid
echo "opskit:250000:65536" > /etc/subgid
mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/opskit
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
grep "\"mutation_id\":\"service_user\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"created\":true"
grep "\"mutation_id\":\"subuid_allocation\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"allocated\":false"
grep "\"mutation_id\":\"user_linger\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"enabled\":false"
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
! id opskit >/dev/null 2>&1
grep -q "^opskit:250000:65536$" /etc/subuid
grep -q "^opskit:250000:65536$" /etc/subgid
test -f /var/lib/systemd/linger/opskit
sed -i "/^opskit:/d" /etc/subuid /etc/subgid
rm -f /var/lib/systemd/linger/opskit

# 5. tunnel -> private non-repair re-run carries service_units delta (no_changes=false) and atomically cleans cloudflared
/bootstrap/bin/opskit-bootstrap --profile tunnel --no-probe --yes >/dev/null
/bootstrap/bin/opskit-bootstrap --profile private --no-probe --plan-json /tmp/t2p_plan.json >/dev/null
python3 -B -c "import json; d=json.load(open(\"/tmp/t2p_plan.json\")); assert d[\"no_changes\"] is False and any(m[\"id\"]==\"service_units\" for m in d[\"mutations\"]), d"
t2p_apply_out="$(/bootstrap/bin/opskit-bootstrap --profile private --no-probe --yes 2>&1)"
if echo "${t2p_apply_out}" | grep -q "Host already bootstrapped; no changes required"; then
    echo "FAIL: tunnel->private re-run falsely logged no changes required" >&2
    exit 1
fi
test ! -f /home/opskit/.config/systemd/user/cloudflared.service
! grep -q "\"mutation_id\":\"cloudflared_unit\"" /var/lib/opskit-bootstrap/apply.jsonl
! grep -q "\"profile\":\"tunnel\"" /var/lib/opskit-bootstrap/apply.jsonl
test "$(find /var/lib/opskit-bootstrap -maxdepth 1 -name ".ledger.*" ! -name ".ledger.lock" | wc -l)" -eq 0
( LIB_DIR="/bootstrap/lib"; source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/ledger.sh"; validate_entire_ledger )

# 6. Unreadable file in file_matches_expected returns 1 cleanly with zero stderr
echo "secret" > /tmp/unreadable_unit
chmod 0000 /tmp/unreadable_unit
unreadable_err="$(su -s /bin/bash opskit -c "source /bootstrap/lib/common.sh; if file_matches_expected /tmp/unreadable_unit echo secret; then exit 2; fi" 2>&1)"
test -z "${unreadable_err}"
rm -f /tmp/unreadable_unit
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
echo "PASS: Offline tampered-CLI refusal, superseded firewall repair, partial subid repair, half-existing Run 1, tunnel->private delta, and unreadable comparison verified."
'
}

test_preexisting_user_preserved_on_purge
test_firewalld_isolation_active_stack_and_minimal_rhel
test_profile_state_integrity_cli_digest_drift_and_plan_hash
test_repair_refusal_superseded_fw_and_ownership_edges

# Test 44: Symlink-following privesc defense in /home/opskit/.config/systemd/user
test_user_home_symlink_privesc_defense() {
    echo "--- Test 44: Symlink-following privilege escalation defense in service user home ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile tunnel --no-probe --yes >/dev/null

# Plant a root-owned canary file and replace user-owned unit with a symlink to it
echo "ROOT_CANARY_INTACT" > /etc/opskit-canary
chmod 0600 /etc/opskit-canary
chown root:root /etc/opskit-canary

rm -f /home/opskit/.config/systemd/user/opskit-edge.service
ln -s /etc/opskit-canary /home/opskit/.config/systemd/user/opskit-edge.service
chown -h opskit:opskit /home/opskit/.config/systemd/user/opskit-edge.service

# Re-run --repair and --undo --yes: neither may overwrite or chown /etc/opskit-canary
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
test "$(< /etc/opskit-canary)" = "ROOT_CANARY_INTACT"
test "$(stat -c "%a:%u:%g" /etc/opskit-canary)" = "600:0:0"

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
test -f /etc/opskit-canary
test "$(< /etc/opskit-canary)" = "ROOT_CANARY_INTACT"
test "$(stat -c "%a:%u:%g" /etc/opskit-canary)" = "600:0:0"

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test -f /etc/opskit-canary
echo "PASS: Root never followed symlink in service user home across repair and undo."
'
}

# Test 45: Port 80 conflict pre-bind refusal, --no-http, unit hardening, socket directives, and versions/current layout
test_port80_conflict_no_http_and_unit_hardening() {
    echo "--- Test 45: Port 80 conflict abort, --no-http, unit hardening, and versions layout ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Start a foreign TCP listener on :80
python3 -B -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((\"0.0.0.0\", 80))
s.listen(5)
time.sleep(30)
" &
PORT80_PID=$!
trap "kill ${PORT80_PID} 2>/dev/null || true" EXIT
sleep 0.3

# Direct without --no-http must fail with exit 4 BEFORE mutating user or state dir
set +e
c_out="$(/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes 2>&1)"
c_rc=$?
set -e
test "${c_rc}" -eq 4
echo "${c_out}" | grep -q "Port 80 is already in use"
echo "${c_out}" | grep -q -- "--no-http"
! id opskit >/dev/null 2>&1
test ! -e /var/lib/opskit-bootstrap

# 2. Direct with --no-http succeeds with :443 only
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --no-http --yes >/dev/null
test -f /etc/systemd/system/opskit-edge-443.socket
test ! -f /etc/systemd/system/opskit-edge-80.socket
test -f /etc/systemd/system/opskit-edge.service
test ! -f /home/opskit/.config/systemd/user/opskit-cloud.service

# Verify socket unit fixes
grep -q "BindIPv6Only=ipv6-only" /etc/systemd/system/opskit-edge-443.socket
grep -q "NonBlocking=true" /etc/systemd/system/opskit-edge-443.socket
! grep -q "PartOf=" /etc/systemd/system/opskit-edge-443.socket
! grep -q "SocketMode=" /etc/systemd/system/opskit-edge-443.socket

# Verify hardened opskit-edge.service directives and state/config paths
svc="/etc/systemd/system/opskit-edge.service"
grep -q "Requires=opskit-edge-443.socket" "${svc}"
! grep -q "opskit-edge-80.socket" "${svc}"
grep -q "Environment=OPSKIT_EDGE_STATE_DIR=/var/lib/opskit/edge" "${svc}"
grep -q "Environment=XDG_STATE_HOME=/var/lib/opskit/state" "${svc}"
grep -q "Environment=XDG_CONFIG_HOME=/var/lib/opskit/config" "${svc}"
grep -q "NoNewPrivileges=yes" "${svc}"
grep -q "ProtectSystem=strict" "${svc}"
grep -q "ReadWritePaths=/var/lib/opskit" "${svc}"
grep -q "ProtectHome=yes" "${svc}"
grep -q "PrivateTmp=yes" "${svc}"
grep -q "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" "${svc}"
grep -q "UMask=0027" "${svc}"
! grep -q "NonBlocking=true" "${svc}"
test -f /var/lib/opskit/config/opskit/config.json
test "$(stat -c "%a:%U:%G" /var/lib/opskit/config/opskit/config.json)" = "600:opskit:opskit"
grep -q "\"node-profile\":\"direct\"" /var/lib/opskit/config/opskit/config.json

# Verify versions/current is an atomic symlink to the active version directory containing opskit-edge
test -d /var/lib/opskit/versions
test -L /var/lib/opskit/versions/current
test -x /var/lib/opskit/versions/current/opskit-edge
test "$(stat -c "%a:%U:%G" /var/lib/opskit/versions/current/opskit-edge)" = "755:opskit:opskit"

# Verify unit SHA-256 fingerprints recorded in apply.jsonl
grep "\"mutation_id\":\"edge_system_unit\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"after_fingerprint\":\"sha256:"
grep "\"mutation_id\":\"edge_socket_units\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"after_fingerprint\":\"sha256:"

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
echo "PASS: Port 80 conflict gate, --no-http, unit hardening, socket directives, and versions layout verified."
'
}

# Test 46: Repair detects unit permission drift and unexpected systemd .d/ drop-ins
test_repair_detects_unit_perms_and_dropins() {
    echo "--- Test 46: Repair detects unit permission drift and .d/ drop-ins ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Drift 1: permission change on opskit-edge.service
chmod 0600 /etc/systemd/system/opskit-edge.service
set +e
perm_out="$(/bootstrap/bin/opskit-bootstrap --repair 2>&1)"
perm_rc=$?
set -e
test "${perm_rc}" -eq 5
echo "${perm_out}" | grep -q "Permissions/ownership"

# Repair fixes permission
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
test "$(stat -c "%a:%u:%g" /etc/systemd/system/opskit-edge.service)" = "644:0:0"

# Drift 2: unexpected drop-in under opskit-edge.service.d
mkdir -p /etc/systemd/system/opskit-edge.service.d
printf "[Service]\nUser=root\n" > /etc/systemd/system/opskit-edge.service.d/override.conf
set +e
drop_out="$(/bootstrap/bin/opskit-bootstrap --repair 2>&1)"
drop_rc=$?
set -e
test "${drop_rc}" -eq 5
echo "${drop_out}" | grep -q "Unexpected systemd drop-in"

rm -rf /etc/systemd/system/opskit-edge.service.d
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
echo "PASS: Repair detected unit permission drift and unexpected systemd .d/ drop-in."
'
}

# Test 47: Inaccessible root-only cwd in run_as_service_user + versioned opskit-edge installation/repair/undo
test_inaccessible_cwd_and_versioned_edge_install() {
    echo "--- Test 47: Inaccessible cwd execution and versioned opskit-edge install ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" localhost/opskit-test-debian:13 /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

mkdir -p /root/opskit-inaccessible-cwd
chmod 0700 /root/opskit-inaccessible-cwd
cd /root/opskit-inaccessible-cwd

# Full direct bootstrap invoked from a root-only 0700 directory
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# 1. Verify run_as_service_user handles inaccessible cwd cleanly across both runuser and python setuid paths
(
    LIB_DIR="/bootstrap/lib"
    source "${LIB_DIR}/common.sh"
    cwd_out="$(run_as_service_user "pwd")"
    test "${cwd_out}" != "/root/opskit-inaccessible-cwd"
    rootless_out="$(run_as_service_user "podman info --format \"{{.Host.Security.Rootless}}\"" 2>&1 || true)"
    ! echo "${rootless_out}" | grep -qi "Permission denied"

    # Exercise python setuid fallback branch with runuser hidden on PATH
    mkdir -p /tmp/no-runuser-bin
    for b in /usr/bin/* /bin/*; do
        bn="$(basename "${b}")"
        [ "${bn}" = "runuser" ] && continue
        ln -sf "${b}" "/tmp/no-runuser-bin/${bn}"
    done
    py_cwd="$(PATH="/tmp/no-runuser-bin" run_as_service_user "pwd")"
    test "${py_cwd}" != "/root/opskit-inaccessible-cwd"
    rm -rf /tmp/no-runuser-bin
)

# 2. Verify /var/lib/opskit/versions/current/opskit-edge layout, ownership, and ledger metadata
test -L /var/lib/opskit/versions/current
test "$(readlink /var/lib/opskit/versions/current)" = "0.1.0"
edge_bin="/var/lib/opskit/versions/current/opskit-edge"
test -x "${edge_bin}"
test "$(stat -c "%a:%U:%G" /var/lib/opskit/versions/0.1.0/opskit-edge)" = "755:opskit:opskit"
test "$("${edge_bin}" --version)" = "opskit-edge 0.1.0 mock test"
arch="$(uname -m)"
expected_edge_sha="$(sha256sum "/artifacts/opskit-edge-linux-${arch}" | awk "{print \$1}")"
actual_edge_sha="$(sha256sum "${edge_bin}" | awk "{print \$1}")"
test "${actual_edge_sha}" = "${expected_edge_sha}"
grep "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"edge_sha256\":\"${expected_edge_sha}\""
grep "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl | grep -q "\"edge_version\":\"0.1.0\""

# 3. Verify --repair detects tampered edge binary and restores it cleanly
printf "#!/bin/sh\necho BAD\n" > /var/lib/opskit/versions/0.1.0/opskit-edge
set +e
repair_check="$(/bootstrap/bin/opskit-bootstrap --repair 2>&1)"
repair_rc=$?
set -e
test "${repair_rc}" -eq 5
echo "${repair_check}" | grep -q "fetch_cli: Digest mismatch at .*versions/current/opskit-edge"
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
test "$(sha256sum "${edge_bin}" | awk "{print \$1}")" = "${expected_edge_sha}"

# 4. Verify plain --undo removes versioned edge symlink and binary, and --purge cleans everything
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --yes >/dev/null
test ! -e /var/lib/opskit/versions/current
test ! -e /var/lib/opskit/versions/0.1.0/opskit-edge
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit
echo "PASS: Inaccessible cwd execution and versioned opskit-edge lifecycle verified."
'
}

# Test 48: Live systemd socket activation under hardened opskit-edge.service serves /health
test_direct_edge_active_and_serves_health_under_hardened_unit() {
    echo "--- Test 48: Hardened opskit-edge.service becomes active and serves /health via socket FDs ---"
    LIVE_EDGE_ARTIFACTS_DIR="$(mktemp -d)"
    local live_art_dir="${LIVE_EDGE_ARTIFACTS_DIR}"
    cp "${TEST_ARTIFACTS_DIR}/release"* "${TEST_ARTIFACTS_DIR}/opskit-"* "${live_art_dir}/"

    local host_arch
    host_arch="$(uname -m)"
    cat << 'EDGEPY' > "${live_art_dir}/opskit-edge-linux-${host_arch}"
#!/usr/bin/env python3
import json
import os
import selectors
import signal
import socket
import sys

if os.geteuid() == 0:
    sys.stderr.write("opskit-edge refuses to run as root.\n")
    sys.exit(5)

def resolve_state_dir():
    for env_key, suffix in (
        ("OPSKIT_EDGE_STATE_DIR", ()),
        ("OPSKIT_HOME", ("edge",)),
        ("XDG_STATE_HOME", ("opskit", "edge")),
        ("HOME", (".local", "state", "opskit", "edge")),
    ):
        v = os.environ.get(env_key, "")
        if v:
            return os.path.join(v, *suffix)
    return "/var/lib/opskit/edge"

def resolve_prefs_path():
    xdg_cfg = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg_cfg:
        return os.path.join(xdg_cfg, "opskit", "config.json")
    return os.path.join(os.environ.get("HOME", ""), ".config", "opskit", "config.json")

state_dir = resolve_state_dir()
prefs_path = resolve_prefs_path()

try:
    with open(prefs_path, "r", encoding="utf-8") as pf:
        prefs = json.load(pf)
except Exception as exc:
    sys.stderr.write(f"opskit-edge: failed to read configuration file {prefs_path}: {exc}\n")
    sys.exit(1)

os.makedirs(state_dir, mode=0o700, exist_ok=True)
os.chmod(state_dir, 0o700)

cfg_path = os.path.join(state_dir, "config.json")
fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as cf:
    json.dump({"node_profile": prefs.get("node-profile", "direct"), "routes": []}, cf)

pid_path = os.path.join(state_dir, "edge.pid")
pfd = os.open(pid_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(pfd, "w", encoding="utf-8") as pf:
    pf.write(f"{os.getpid()}\n")

listen_pid = int(os.environ.get("LISTEN_PID", "0") or "0")
listen_fds = int(os.environ.get("LISTEN_FDS", "0") or "0")
fd_names = [n for n in os.environ.get("LISTEN_FDNAMES", "").split(":") if n]
if listen_pid != os.getpid() or listen_fds < 1:
    sys.stderr.write(f"opskit-edge: expected systemd LISTEN_FDS, got pid={listen_pid} fds={listen_fds}\n")
    sys.exit(1)

sel = selectors.DefaultSelector()
listeners = []
for idx in range(listen_fds):
    sock = socket.socket(fileno=3 + idx)
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ, data="listener")
    listeners.append(sock)

health_sock_path = os.path.join(state_dir, "health.sock")
if os.path.exists(health_sock_path):
    os.unlink(health_sock_path)
hsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
hsock.bind(health_sock_path)
os.chmod(health_sock_path, 0o600)
hsock.listen(16)
hsock.setblocking(False)
sel.register(hsock, selectors.EVENT_READ, data="listener")
listeners.append(hsock)

running = True
def stop_handler(_signum, _frame):
    global running
    running = False

signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)

body_bytes = json.dumps({
    "status": "ok",
    "fds": fd_names,
    "state_dir": state_dir,
    "prefs_path": prefs_path,
}, separators=(",", ":")).encode("utf-8")

while running:
    events = sel.select(timeout=0.5)
    for key, _ in events:
        conn, _ = key.fileobj.accept()
        try:
            conn.settimeout(2.0)
            req = conn.recv(4096)
            first_line = req.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            if first_line.startswith("GET /health "):
                hdr = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                conn.sendall(hdr + body_bytes)
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            conn.close()
EDGEPY
    chmod 0755 "${live_art_dir}/opskit-edge-linux-${host_arch}"

    local tmp_key="${live_art_dir}/tmp.key"
    openssl genpkey -algorithm ed25519 -out "${tmp_key}" 2>/dev/null
    openssl pkey -in "${tmp_key}" -pubout -out "${live_art_dir}/release.pub" 2>/dev/null
    python3 -B -c "
import hashlib, json, os, subprocess
d_dir = '${live_art_dir}'
m_path = os.path.join(d_dir, 'release-manifest.json')
m = json.load(open(m_path, 'r', encoding='utf-8'))
ek = 'opskit-edge-linux-${host_arch}'
data = open(os.path.join(d_dir, ek), 'rb').read()
m['artifacts'][ek]['sha256'] = hashlib.sha256(data).hexdigest()
m['artifacts'][ek]['size'] = len(data)
m.pop('signatures', None)
canon = json.dumps(m, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
cf = os.path.join(d_dir, 'canon.tmp')
open(cf, 'wb').write(canon)
sig = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${tmp_key}', '-rawin', '-in', cf], stdout=subprocess.PIPE, check=True).stdout.hex()
os.remove(cf)
m['signatures'] = [{'key_id': 'test-release-key-1', 'algorithm': 'ed25519', 'signature': sig}]
open(m_path, 'w', encoding='utf-8').write(json.dumps(m, indent=2))
"
    rm -f "${tmp_key}"

    local cid
    cid="$(podman run -d --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${live_art_dir}:/artifacts:ro" localhost/opskit-test-debian:13 /sbin/init)"
    ACTIVE_CIDS+=("${cid}")

    local wait_i=0
    while [[ ${wait_i} -lt 30 ]]; do
        if podman exec "${cid}" systemctl list-units >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
        wait_i=$((wait_i + 1))
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

/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

systemctl is-active --quiet opskit-edge-443.socket
systemctl is-active --quiet opskit-edge-80.socket
# L-24 regression: fresh bootstrap leaves :443 and :80 actively listening with zero manual restart
test "$(systemctl show -p SubState --value opskit-edge-443.socket)" = "listening"
test "$(systemctl show -p SubState --value opskit-edge-80.socket)" = "listening"
ss -Htlpn | awk "\$4 ~ /(^|:|\\])443\$/ { found=1 } END { exit !found }"
ss -Htlpn | awk "\$4 ~ /(^|:|\\])80\$/ { found=1 } END { exit !found }"

# Trigger socket activation via inherited :80 FD under ProtectHome=yes
health_http="$(curl -sf --max-time 5 http://127.0.0.1:80/health)"
echo "${health_http}" | grep -q "\"status\":\"ok\""
echo "${health_http}" | grep -q "\"443\""
echo "${health_http}" | grep -q "\"80\""
echo "${health_http}" | grep -q "\"state_dir\":\"/var/lib/opskit/edge\""
echo "${health_http}" | grep -q "\"prefs_path\":\"/var/lib/opskit/config/opskit/config.json\""

systemctl is-active --quiet opskit-edge.service
main_pid="$(systemctl show -p MainPID --value opskit-edge.service)"
test -n "${main_pid}" && test "${main_pid}" -gt 0
test "$(ps -o user= -p "${main_pid}" | tr -d "[:space:]")" = "opskit"
test "$(systemctl show -p ProtectHome --value opskit-edge.service)" = "yes"
test "$(systemctl show -p ProtectSystem --value opskit-edge.service)" = "strict"

test -f /var/lib/opskit/edge/config.json
test "$(stat -c "%a:%U:%G" /var/lib/opskit/edge/config.json)" = "600:opskit:opskit"
test -S /var/lib/opskit/edge/health.sock
health_unix="$(curl -sf --max-time 5 --unix-socket /var/lib/opskit/edge/health.sock http://localhost/health)"
echo "${health_unix}" | grep -q "\"status\":\"ok\""

# L-25 regression: CLI running as opskit with no manual env finds the same edge health socket & config
test -f /home/opskit/.config/environment.d/opskit.conf
test "$(stat -c "%a:%U:%G" /home/opskit/.config/environment.d/opskit.conf)" = "600:opskit:opskit"
grep -q "^OPSKIT_EDGE_STATE_DIR=/var/lib/opskit/edge$" /home/opskit/.config/environment.d/opskit.conf
grep -q "^XDG_STATE_HOME=/var/lib/opskit/state$" /home/opskit/.config/environment.d/opskit.conf
grep -q "^XDG_CONFIG_HOME=/var/lib/opskit/config$" /home/opskit/.config/environment.d/opskit.conf
test -L /home/opskit/.local/state/opskit/edge
test "$(readlink /home/opskit/.local/state/opskit/edge)" = "/var/lib/opskit/edge"
test -L /home/opskit/.config/opskit
test "$(readlink /home/opskit/.config/opskit)" = "/var/lib/opskit/config/opskit"

cli_health="$(runuser -u opskit -- env -i HOME=/home/opskit USER=opskit PATH=/usr/local/bin:/usr/bin:/bin \
    curl -sf --max-time 5 --unix-socket /home/opskit/.local/state/opskit/edge/health.sock http://localhost/health)"
echo "${cli_health}" | grep -q "\"status\":\"ok\""
cli_prefs="$(runuser -u opskit -- env -i HOME=/home/opskit USER=opskit PATH=/usr/local/bin:/usr/bin:/bin \
    cat /home/opskit/.config/opskit/config.json)"
echo "${cli_prefs}" | grep -q "\"node-profile\":\"direct\""

# L-24 re-run/repair regression: socket unit config change + daemon-reload drops FD, repair restores listening FD
sed -i "s/^NonBlocking=true$/NonBlocking=false/" /etc/systemd/system/opskit-edge-443.socket
systemctl daemon-reload
set +e
s443_drift="$(/bootstrap/bin/opskit-bootstrap --repair 2>&1)"
s443_drift_rc=$?
set -e
test "${s443_drift_rc}" -eq 5
echo "${s443_drift}" | grep -q "edge_socket_units"
/bootstrap/bin/opskit-bootstrap --repair --yes >/dev/null
ss -Htlpn | awk "\$4 ~ /(^|:|\\])443\$/ { found=1 } END { exit !found }"

/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
! systemctl is-active --quiet opskit-edge.service
test ! -d /var/lib/opskit
'
    podman rm -f "${cid}" >/dev/null 2>&1 || true
    echo "PASS: Hardened opskit-edge.service activated, read config, bound inherited FDs, and served /health."
}

test_user_home_symlink_privesc_defense
test_port80_conflict_no_http_and_unit_hardening
test_repair_detects_unit_perms_and_dropins
test_inaccessible_cwd_and_versioned_edge_install
test_direct_edge_active_and_serves_health_under_hardened_unit

echo "ALL OS MATRIX ACCEPTANCE TESTS PASSED."
