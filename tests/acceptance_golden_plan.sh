#!/usr/bin/env bash
# Acceptance test suite for trust-contract plan generation across OS families and profiles.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ ! -f /.dockerenv && ! -f /run/.containerenv ]]; then
    if id opskit >/dev/null 2>&1 || [[ -d /var/lib/opskit || -d /var/lib/opskit-bootstrap || -f /var/lib/systemd/linger/opskit || -f /etc/systemd/system/opskit-edge.service || -f /etc/systemd/system/user@.service.d/opskit-delegate.conf ]]; then
        if command -v podman >/dev/null 2>&1 && podman image exists localhost/opskit-test-debian:13; then
            exec podman run --rm -v "${REPO_ROOT}:/bootstrap:ro" localhost/opskit-test-debian:13 /bin/bash /bootstrap/tests/acceptance_golden_plan.sh
        fi
    fi
fi

BOOTSTRAP_BIN="${REPO_ROOT}/bin/opskit-bootstrap"
FIXTURE_DIR="${REPO_ROOT}/tests/fixtures/golden"
TEST_TEMP_DIR="$(mktemp -d)"

source "${REPO_ROOT}/tests/setup_test_env.sh"
setup_test_artifacts "${TEST_TEMP_DIR}/artifacts"
export OPSKIT_ARTIFACT_SOURCE_DIR="${TEST_TEMP_DIR}/artifacts"
export OPSKIT_RELEASE_PUBKEY="${TEST_TEMP_DIR}/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

cleanup() {
    rm -rf "${TEST_TEMP_DIR}"
}
trap cleanup EXIT

echo "=== Running acceptance_golden_plan.sh ==="

OS_FAMILIES=("debian" "rhel" "sles")
PROFILES=("direct" "tunnel" "private")

test_golden_plan() {
    local os="$1"
    local prof="$2"

    echo "--- Testing plan generation: ${os} x ${prof} ---"
    local golden_file="${FIXTURE_DIR}/plan_${os}_${prof}.json"
    local generated_file="${TEST_TEMP_DIR}/plan_${os}_${prof}.json"
    local os_rel_file="${FIXTURE_DIR}/${os}.os-release"

    if [[ ! -f "${golden_file}" ]]; then
        echo "FAIL: golden plan file not found: ${golden_file}" >&2
        return 1
    fi

    # Run opskit-bootstrap --plan-json with deterministic mock values
    OPSKIT_TEST_MODE="1" \
    OPSKIT_FORCE_SYSTEMD="1" \
    OPSKIT_OS_RELEASE_FILE="${os_rel_file}" \
    MOCK_NODE_FINGERPRINT="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
    MOCK_EXPIRES_AT="2026-11-10T12:00:00Z" \
    MOCK_KERNEL_RELEASE="6.1.0-28-amd64" \
    MOCK_DISK_FREE_GB="50" \
    MOCK_CLOCK_SKEW="0" \
    MOCK_RUNTIME_VERSION="4.9.3" \
    MOCK_CGROUP_CONTROLLERS="cpuset cpu io memory hugetlb pids rdma misc dmem" \
    MOCK_APPARMOR_STATUS="enforcing" \
    MOCK_SELINUX_STATUS="absent" \
    OPSKIT_SKIP_DISK_CHECK="1" \
    OPSKIT_SKIP_BIND_CHECK="1" \
    "${BOOTSTRAP_BIN}" --profile "${prof}" --no-probe --plan-json "${generated_file}" >/dev/null

    # Deep equality assertion against golden fixture (contractual plan conformance)
    python3 -B -c "
import json, sys

with open('${golden_file}', 'r') as f:
    golden = json.load(f)

with open('${generated_file}', 'r') as f:
    generated = json.load(f)

assert golden == generated, f'Plan semantic mismatch for ${os} x ${prof}:\nGolden: {json.dumps(golden, indent=2)}\nGenerated: {json.dumps(generated, indent=2)}'
" || {
        echo "FAIL: generated plan differs from golden plan for ${os} x ${prof}" >&2
        echo "FAIL: generated plan differs from golden plan for ${os} x ${prof}" >&2
        diff -u "${golden_file}" "${generated_file}" || true
        return 1
    }

    echo "PASS: Golden plan verified for ${os} x ${prof}."
}

# Run matrix
for os in "${OS_FAMILIES[@]}"; do
    for prof in "${PROFILES[@]}"; do
        test_golden_plan "${os}" "${prof}"
    done
done

echo "ALL GOLDEN PLAN ACCEPTANCE TESTS PASSED."
