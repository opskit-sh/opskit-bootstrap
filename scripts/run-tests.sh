#!/usr/bin/env bash
# Unified test suite runner for opskit-bootstrap.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=================================================================="
echo "Running OpsKit Bootstrap Acceptance and Conformance Test Suite"
echo "=================================================================="

TEST_SCRIPTS=(
    "${REPO_ROOT}/scripts/check-docs.sh"
    "${REPO_ROOT}/tests/acceptance_manifest.sh"
    "${REPO_ROOT}/tests/acceptance_golden_plan.sh"
    "${REPO_ROOT}/tests/acceptance_probe.sh"
    "${REPO_ROOT}/tests/acceptance_uninstall.sh"
    "${REPO_ROOT}/tests/acceptance_privilege_audit.sh"
    "${REPO_ROOT}/tests/acceptance_os_matrix.sh"
    "${REPO_ROOT}/tests/acceptance_docker_rootless.sh"
)

TOTAL=${#TEST_SCRIPTS[@]}
PASSED=0

for test_script in "${TEST_SCRIPTS[@]}"; do
    test_name="$(basename "${test_script}")"
    echo ""
    echo ">>> Running ${test_name}..."
    if bash "${test_script}"; then
        echo ">>> ${test_name}: PASSED"
        PASSED=$((PASSED + 1))
    else
        echo ">>> ${test_name}: FAILED" >&2
        exit 1
    fi
done

echo ""
echo "=================================================================="
echo "Summary: ${PASSED}/${TOTAL} test suites passed cleanly."
echo "=================================================================="
