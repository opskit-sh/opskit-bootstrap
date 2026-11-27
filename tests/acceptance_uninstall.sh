#!/usr/bin/env bash
# Acceptance test suite for offline uninstaller and zero-trace guarantee.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Running acceptance_uninstall.sh ==="

IMAGE_NAME="localhost/opskit-test-debian:13"

source "${REPO_ROOT}/tests/setup_test_env.sh"
TEST_ARTIFACTS_DIR="$(mktemp -d)"
setup_test_artifacts "${TEST_ARTIFACTS_DIR}"

cleanup() {
    rm -rf "${TEST_ARTIFACTS_DIR}"
}
trap cleanup EXIT

# Test 1: Plain uninstall covenant: workloads, user, subuid, linger survive
test_plain_uninstall_covenant() {
    echo "--- Test 1: Plain uninstall covenant (workloads, user, subuid, linger survive) ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Apply bootstrap under direct profile
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# 2. Plant native Compose workload under service user home
mkdir -p /home/opskit/opskit/deployments/web-service
cat << "EOF" > /home/opskit/opskit/deployments/web-service/compose.yml
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
EOF
chown -R opskit:opskit /home/opskit/opskit

# 3. Perform offline plain uninstallation
/var/lib/opskit-bootstrap/opskit-bootstrap --undo >/dev/null

# 4. Assert OpsKit-owned exposure/CLI infrastructure is removed
test ! -f /etc/systemd/system/opskit-edge-443.socket
test ! -f /etc/systemd/system/opskit-edge-80.socket
test ! -f /etc/systemd/system/opskit-edge.service
test ! -f /usr/local/bin/opskit
if nft list table inet opskit >/dev/null 2>&1; then
    echo "FAIL: nftables table inet opskit still exists after plain undo" >&2
    exit 1
fi

# Plain undo retains pruned ledger & vendored uninstaller so follow-up --purge remains possible
test -d /var/lib/opskit-bootstrap
test -f /var/lib/opskit-bootstrap/apply.jsonl
! grep -q "\"mutation_id\":\"edge_socket_units\"" /var/lib/opskit-bootstrap/apply.jsonl
! grep -q "\"mutation_id\":\"fetch_cli\"" /var/lib/opskit-bootstrap/apply.jsonl
grep -q "\"mutation_id\":\"service_user\"" /var/lib/opskit-bootstrap/apply.jsonl

# 5. Assert service user, subuid, linger, and workloads survive intact
id opskit >/dev/null
grep -q "^opskit:" /etc/subuid
grep -q "^opskit:" /etc/subgid
test -f /var/lib/systemd/linger/opskit
test -f /home/opskit/opskit/deployments/web-service/compose.yml

# 6. Follow-up --undo --purge --yes succeeds from retained pruned ledger
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit-bootstrap
! id opskit >/dev/null 2>&1

echo "PASS: Plain uninstall covenant preserved service identity/workloads and allowed follow-up --purge."
'
}

# Test 2: Purge uninstall covenant: full zero-trace snapshot comparison including /home
test_purge_uninstall_covenant() {
    echo "--- Test 2: Purge uninstall covenant (full zero-trace snapshot including /home) ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Ensure base packages exist
touch /etc/subuid /etc/subgid
mkdir -p /home /etc/sysusers.d

# 1. Capture pre-bootstrap baseline snapshot (including /home and /etc/sysusers.d)
SNAPSHOT_PRE="/tmp/pre_snapshot.txt"
{
    cut -d: -f1 /etc/passwd | sort
    cut -d: -f1 /etc/group | sort
    sort /etc/subuid
    sort /etc/subgid
    ls -1 /etc/systemd/system/ 2>/dev/null | sort
    ls -1 /etc/sysusers.d/ 2>/dev/null | sort
    ls -1 /usr/local/bin/ 2>/dev/null | sort
    ls -1 /var/lib/ 2>/dev/null | sort
    ls -1 /home/ 2>/dev/null | sort
    nft list tables 2>/dev/null | sort
} > "${SNAPSHOT_PRE}"

# 2. Apply bootstrap
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Assert resources created
id opskit >/dev/null
test -f /usr/local/bin/opskit
test -d /var/lib/opskit-bootstrap
test -f /etc/sysusers.d/opskit.conf

# 3. Purge without --yes in non-interactive mode must refuse with exit 5
set +e
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge >/dev/null 2>&1
purge_guard_rc=$?
set -e
test "${purge_guard_rc}" -eq 5
test -d /var/lib/opskit-bootstrap

# 4. Perform destructive purge uninstallation (--undo --purge --yes)
/var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null

# 4. Assert resurrection impossibility via systemd-sysusers
systemd-sysusers 2>/dev/null || true
if id opskit >/dev/null 2>&1; then
    echo "FAIL: opskit user resurrected by systemd-sysusers after purge" >&2
    exit 1
fi

# 5. Capture post-purge snapshot
SNAPSHOT_POST="/tmp/post_snapshot.txt"
{
    cut -d: -f1 /etc/passwd | sort
    cut -d: -f1 /etc/group | sort
    sort /etc/subuid
    sort /etc/subgid
    ls -1 /etc/systemd/system/ 2>/dev/null | sort
    ls -1 /etc/sysusers.d/ 2>/dev/null | sort
    ls -1 /usr/local/bin/ 2>/dev/null | sort
    ls -1 /var/lib/ 2>/dev/null | sort
    ls -1 /home/ 2>/dev/null | sort
    nft list tables 2>/dev/null | sort
} > "${SNAPSHOT_POST}"

if nft list table inet opskit >/dev/null 2>&1; then
    echo "FAIL: nftables table inet opskit still exists after purge undo" >&2
    exit 1
fi

# 6. Assert exact snapshot equality (zero-trace guarantee)
if ! diff -u "${SNAPSHOT_PRE}" "${SNAPSHOT_POST}"; then
    echo "FAIL: Post-purge snapshot does not match pre-bootstrap snapshot" >&2
    exit 1
fi

echo "PASS: Zero-trace purge covenant verified (pre and post snapshots match identically)."
'
}

# Test 3: Corrupt or tampered ledger line refuses undo and preserves state dir intact
test_corrupt_ledger_line_refusal() {
    echo "--- Test 3: Corrupt/tampered ledger line refusal ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Apply bootstrap
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null
cp /var/lib/opskit-bootstrap/apply.jsonl /tmp/apply.bak
cp /var/lib/opskit-bootstrap/ledger.head /tmp/head.bak

# 2. Corrupt a line in apply.jsonl (append corrupt syntax and invalid HMAC)
echo "{\"timestamp\":\"corrupt\",\"mutation_id\":\"service_user\",\"class\":\"H\",\"before_fingerprint\":\"a\",\"after_fingerprint\":\"b\",\"plan_hash\":\"c\",\"metadata\":{},\"hmac\":\"invalid\"}" >> /var/lib/opskit-bootstrap/apply.jsonl

# 3. Run uninstaller: must fail with code 8
set +e
/var/lib/opskit-bootstrap/opskit-bootstrap --undo >/dev/null 2>&1
CODE=$?
set -e

if [[ ${CODE} -ne 8 ]]; then
    echo "FAIL: expected exit code 8 on corrupt ledger line, got ${CODE}" >&2
    exit 1
fi

# 4. Assert that state dir was NOT destroyed
if [[ ! -d /var/lib/opskit-bootstrap || ! -f /var/lib/opskit-bootstrap/apply.jsonl ]]; then
    echo "FAIL: state directory /var/lib/opskit-bootstrap was destroyed despite corrupt ledger" >&2
    exit 1
fi

# 5. Test chained ledger truncation, line deletion, reordering, and missing head anchor
# (Uses clean /tmp/apply.bak and /tmp/head.bak saved prior to corruption above)

# 5A: Truncated 0-byte apply.jsonl
: > /var/lib/opskit-bootstrap/apply.jsonl
set +e
/var/lib/opskit-bootstrap/opskit-bootstrap --undo >/dev/null 2>&1
rc_zero=$?
set -e
test "${rc_zero}" -eq 8

# 5B: Last line deleted (mismatch with ledger.head)
head -n -1 /tmp/apply.bak > /var/lib/opskit-bootstrap/apply.jsonl
set +e
/var/lib/opskit-bootstrap/opskit-bootstrap --undo >/dev/null 2>&1
rc_drop=$?
set -e
test "${rc_drop}" -eq 8

# 5C: Missing ledger.head
cp /tmp/apply.bak /var/lib/opskit-bootstrap/apply.jsonl
rm -f /var/lib/opskit-bootstrap/ledger.head
set +e
/var/lib/opskit-bootstrap/opskit-bootstrap --undo >/dev/null 2>&1
rc_nohead=$?
set -e
test "${rc_nohead}" -eq 8

# 5D: --undo succeeds even when pre-bootstrap disk/clock gates would fail
cp /tmp/head.bak /var/lib/opskit-bootstrap/ledger.head
OPSKIT_SKIP_DISK_CHECK="" MOCK_DISK_FREE_GB="1" MOCK_CLOCK_SKEW="9999" /var/lib/opskit-bootstrap/opskit-bootstrap --undo --purge --yes >/dev/null
test ! -d /var/lib/opskit-bootstrap

echo "PASS: Corrupt/truncated ledger refused with exit 8; --undo works on degraded disk/clock nodes."
'
}

# Test 4: Pre-existing CLI binary is restored upon undo, never deleted
test_preexisting_cli_restoration() {
    echo "--- Test 4: Pre-existing CLI restoration upon undo ---"
    podman run --rm --privileged -v "${REPO_ROOT}:/bootstrap:ro" -v "${TEST_ARTIFACTS_DIR}:/artifacts:ro" "${IMAGE_NAME}" /bin/bash -c '
set -euo pipefail
export OPSKIT_TEST_MODE="1"
export MOCK_KERNEL_RELEASE="6.1.0-28-amd64"
export MOCK_DISK_FREE_GB="50"
export OPSKIT_SKIP_DISK_CHECK="1"
export OPSKIT_ARTIFACT_SOURCE_DIR="/artifacts"
export OPSKIT_RELEASE_PUBKEY="/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# 1. Plant pre-existing CLI binary
mkdir -p /usr/local/bin
cat << "ORIGINAL" > /usr/local/bin/opskit
#!/usr/bin/env bash
echo "admin-custom-opskit-binary-v0"
ORIGINAL
chmod 0755 /usr/local/bin/opskit

# 2. Apply bootstrap (upgrades CLI and backs up original)
/bootstrap/bin/opskit-bootstrap --profile direct --no-probe --yes >/dev/null

# Verify bootstrap installed verified release binary
out="$(/usr/local/bin/opskit || true)"
test "${out}" != "admin-custom-opskit-binary-v0"

# 3. Perform undo
/var/lib/opskit-bootstrap/opskit-bootstrap --undo >/dev/null

# 4. Assert pre-existing binary was RESTORED intact, not deleted
test -f /usr/local/bin/opskit
out="$(/usr/local/bin/opskit)"
if [[ "${out}" != "admin-custom-opskit-binary-v0" ]]; then
    echo "FAIL: pre-existing CLI was not restored; got: ${out}" >&2
    exit 1
fi

echo "PASS: Pre-existing CLI binary restored upon uninstallation."
'
}

test_plain_uninstall_covenant
test_purge_uninstall_covenant
test_corrupt_ledger_line_refusal
test_preexisting_cli_restoration

echo "ALL UNINSTALL ACCEPTANCE TESTS PASSED."
