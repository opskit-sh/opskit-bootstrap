#!/usr/bin/env bash
# Acceptance test suite for inbound reachability probing and profile auto-negotiation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export OPSKIT_TEST_MODE=1

BOOTSTRAP_BIN="${REPO_ROOT}/bin/opskit-bootstrap"
TEST_TEMP_DIR="$(mktemp -d)"

source "${REPO_ROOT}/tests/setup_test_env.sh"
setup_test_artifacts "${TEST_TEMP_DIR}/artifacts"
export OPSKIT_ARTIFACT_SOURCE_DIR="${TEST_TEMP_DIR}/artifacts"
export OPSKIT_RELEASE_PUBKEY="${TEST_TEMP_DIR}/artifacts/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"
export OPSKIT_SKIP_BIND_CHECK="1"

cleanup() {
    if [[ -n "${PROBE_SERVER_PID:-}" ]]; then
        kill "${PROBE_SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf "${TEST_TEMP_DIR}"
}
trap cleanup EXIT

echo "=== Running acceptance_probe.sh ==="

# Mock probe server in python on ephemeral port
MOCK_RESPONSE_FILE="${TEST_TEMP_DIR}/mock_response.json"

python3 -B - << EOF &
import http.server
import socketserver
import json
import sys

class ProbeHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            with open("${MOCK_RESPONSE_FILE}", "r") as f:
                body = f.read().encode("utf-8")
        except Exception:
            body = b'{"reachable": false, "reason": "default"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReusableTCPServer(("127.0.0.1", 0), ProbeHandler) as httpd:
    port = httpd.server_address[1]
    with open("${TEST_TEMP_DIR}/port", "w") as pf:
        pf.write(str(port))
    httpd.serve_forever()
EOF
PROBE_SERVER_PID=$!

while [[ ! -f "${TEST_TEMP_DIR}/port" ]]; do
    sleep 0.05
done
PROBE_PORT="$(cat "${TEST_TEMP_DIR}/port")"
PROBE_URL="http://127.0.0.1:${PROBE_PORT}/probe"

# Test 1: External probe succeeds -> direct profile retained
test_probe_success() {
    echo "--- Test 1: External probe succeeds -> direct profile retained ---"
    cat << 'EOF' > "${MOCK_RESPONSE_FILE}"
{"reachable": true, "reachable_v4": true, "reachable_v6": false}
EOF

    local plan_file="${TEST_TEMP_DIR}/plan_success.json"
    OPSKIT_PROBE_SERVER="${PROBE_URL}" \
    OPSKIT_SKIP_DISK_CHECK="1" \
    "${BOOTSTRAP_BIN}" --yes --plan-json "${plan_file}" >/dev/null

    local prof
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"
    local status
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"

    if [[ "${prof}" != "direct" ]]; then
        echo "FAIL: expected direct profile on successful probe, got ${prof}" >&2
        return 1
    fi
    if [[ "${status}" != "verified" ]]; then
        echo "FAIL: expected verified status on successful probe, got ${status}" >&2
        return 1
    fi
    echo "PASS: Direct profile confirmed by external probe."
}

# Test 2: External probe fails (CGNAT) without explicit profile -> auto-downgrade to tunnel
test_probe_cgnat_downgrade() {
    echo "--- Test 2: External probe fails (CGNAT) -> auto-downgrade to tunnel ---"
    cat << 'EOF' > "${MOCK_RESPONSE_FILE}"
{"reachable": false, "reason": "carrier_grade_nat"}
EOF

    local plan_file="${TEST_TEMP_DIR}/plan_cgnat.json"
    local output
    output="$(
        OPSKIT_PROBE_SERVER="${PROBE_URL}" \
        OPSKIT_SKIP_DISK_CHECK="1" \
        "${BOOTSTRAP_BIN}" --yes --plan-json "${plan_file}" 2>&1
    )"

    local prof
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"
    local status
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"

    if [[ "${prof}" != "tunnel" ]]; then
        echo "FAIL: expected tunnel profile after failed probe, got ${prof}" >&2
        return 1
    fi
    if [[ "${status}" != "failed" ]]; then
        echo "FAIL: expected failed status on probe failure, got ${status}" >&2
        return 1
    fi
    if [[ "${output}" != *"Downgrading profile to 'tunnel'"* ]]; then
        echo "FAIL: missing explanation of downgrade in output: ${output}" >&2
        return 1
    fi
    echo "PASS: Probe failure cleanly downgraded profile to tunnel with explanation."
}

# Test 3: External probe fails but explicit --profile direct passed -> warns but keeps direct
test_probe_explicit_direct_override() {
    echo "--- Test 3: Explicit --profile direct on probe failure ---"
    cat << 'EOF' > "${MOCK_RESPONSE_FILE}"
{"reachable": false, "reason": "blocked"}
EOF

    local plan_file="${TEST_TEMP_DIR}/plan_explicit_direct.json"
    local output
    output="$(
        OPSKIT_PROBE_SERVER="${PROBE_URL}" \
        OPSKIT_SKIP_DISK_CHECK="1" \
        "${BOOTSTRAP_BIN}" --profile direct --plan-json "${plan_file}" 2>&1
    )"

    local prof
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"

    if [[ "${prof}" != "direct" ]]; then
        echo "FAIL: expected direct profile when explicitly requested, got ${prof}" >&2
        return 1
    fi
    if [[ "${output}" != *"Continuing with direct profile"* ]]; then
        echo "FAIL: expected explicit override warning in output: ${output}" >&2
        return 1
    fi
    echo "PASS: Explicit --profile direct honored despite probe failure."
}

# Test 4: --no-probe flag skips probe call entirely
test_no_probe_flag() {
    echo "--- Test 4: --no-probe flag ---"
    local plan_file="${TEST_TEMP_DIR}/plan_no_probe.json"
    # Point to invalid server to ensure no request is attempted
    OPSKIT_PROBE_SERVER="http://127.0.0.1:59999/nonexistent" \
    OPSKIT_SKIP_DISK_CHECK="1" \
    "${BOOTSTRAP_BIN}" --profile direct --no-probe --plan-json "${plan_file}" >/dev/null

    local status
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"

    if [[ "${status}" != "skipped" ]]; then
        echo "FAIL: expected skipped probe status with --no-probe, got ${status}" >&2
        return 1
    fi
    echo "PASS: --no-probe skipped external reachability check."
}

# Test 5: IPv6-only reachability -> partial verification, auto-downgrade to tunnel
test_ipv6_reachability() {
    echo "--- Test 5: IPv6-only reachability -> partial verification & tunnel downgrade ---"
    cat << 'EOF' > "${MOCK_RESPONSE_FILE}"
{"reachable": true, "reachable_v4": false, "reachable_v6": true}
EOF

    local plan_file="${TEST_TEMP_DIR}/plan_ipv6.json"
    OPSKIT_PROBE_SERVER="${PROBE_URL}" \
    OPSKIT_SKIP_DISK_CHECK="1" \
    "${BOOTSTRAP_BIN}" --yes --plan-json "${plan_file}" >/dev/null

    local prof status v4 v6
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"
    v4="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['reachable_v4'])")"
    v6="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['reachable_v6'])")"

    if [[ "${prof}" != "tunnel" ]]; then
        echo "FAIL: expected tunnel downgrade on IPv6-only probe, got ${prof}" >&2
        return 1
    fi
    if [[ "${status}" != "partial" ]]; then
        echo "FAIL: expected partial status on IPv6-only probe, got ${status}" >&2
        return 1
    fi
    if [[ "${v4}" != "False" ]]; then
        echo "FAIL: expected reachable_v4 to be false, got ${v4}" >&2
        return 1
    fi
    if [[ "${v6}" != "True" ]]; then
        echo "FAIL: expected reachable_v6 to be true, got ${v6}" >&2
        return 1
    fi
    echo "PASS: IPv6-only reachability recorded as partial and downgraded to tunnel."
}

# Test 6: Dual-vantage check: both vantage points pass -> verified & direct
test_dual_vantage_success() {
    echo "--- Test 6: Dual-vantage check: both vantage points pass ---"
    cat << 'EOF' > "${MOCK_RESPONSE_FILE}"
{
    "vantage_points": [
        {"name": "ord", "reachable_v4": true, "reachable_v6": false},
        {"name": "fra", "reachable_v4": true, "reachable_v6": false}
    ]
}
EOF

    local plan_file="${TEST_TEMP_DIR}/plan_dual_success.json"
    OPSKIT_PROBE_SERVER="${PROBE_URL}" \
    OPSKIT_SKIP_DISK_CHECK="1" \
    "${BOOTSTRAP_BIN}" --yes --plan-json "${plan_file}" >/dev/null

    local prof status
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"

    if [[ "${prof}" != "direct" ]]; then
        echo "FAIL: expected direct profile on dual-vantage success, got ${prof}" >&2
        return 1
    fi
    if [[ "${status}" != "verified" ]]; then
        echo "FAIL: expected verified status on dual-vantage success, got ${status}" >&2
        return 1
    fi
    echo "PASS: Dual-vantage probe verified direct profile."
}

# Test 7: Dual-vantage check: single vantage point passes -> partial & downgrade to tunnel
test_dual_vantage_partial() {
    echo "--- Test 7: Dual-vantage check: single vantage point passes ---"
    cat << 'EOF' > "${MOCK_RESPONSE_FILE}"
{
    "vantage_points": [
        {"name": "ord", "reachable_v4": true, "reachable_v6": false},
        {"name": "fra", "reachable_v4": false, "reachable_v6": false}
    ]
}
EOF

    local plan_file="${TEST_TEMP_DIR}/plan_dual_partial.json"
    OPSKIT_PROBE_SERVER="${PROBE_URL}" \
    OPSKIT_SKIP_DISK_CHECK="1" \
    "${BOOTSTRAP_BIN}" --yes --plan-json "${plan_file}" >/dev/null

    local prof status
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"

    if [[ "${prof}" != "tunnel" ]]; then
        echo "FAIL: expected tunnel downgrade on single vantage pass, got ${prof}" >&2
        return 1
    fi
    if [[ "${status}" != "partial" ]]; then
        echo "FAIL: expected partial status on single vantage pass, got ${status}" >&2
        return 1
    fi
    echo "PASS: Dual-vantage partial pass correctly downgraded to tunnel."
}

# Test 8: Active default v6 route with v6 unreachable -> partial & downgrade to tunnel
test_active_v6_route_unreachable() {
    echo "--- Test 8: Active default v6 route with v6 probe false ---"
    cat << 'EOF' > "${MOCK_RESPONSE_FILE}"
{"reachable": true, "reachable_v4": true, "reachable_v6": false}
EOF

    local plan_file="${TEST_TEMP_DIR}/plan_v6_route_fail.json"
    OPSKIT_PROBE_SERVER="${PROBE_URL}" \
    OPSKIT_SKIP_DISK_CHECK="1" \
    MOCK_HAS_V6_ROUTE="1" \
    "${BOOTSTRAP_BIN}" --yes --plan-json "${plan_file}" >/dev/null

    local prof status
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"

    if [[ "${prof}" != "tunnel" ]]; then
        echo "FAIL: expected tunnel downgrade when v6 route is active but v6 unreachable, got ${prof}" >&2
        return 1
    fi
    if [[ "${status}" != "partial" ]]; then
        echo "FAIL: expected partial status when v6 route is active but v6 unreachable, got ${status}" >&2
        return 1
    fi
    echo "PASS: Active v6 route with failed v6 reachability records partial and downgrades to tunnel."
}

# Test 9: Non-interactive without --profile and without probe capability defaults to tunnel
test_non_interactive_no_probe_default() {
    echo "--- Test 9: Non-interactive default without probe capability ---"
    local plan_file="${TEST_TEMP_DIR}/plan_non_interactive.json"
    local output
    output="$(
        OPSKIT_SKIP_DISK_CHECK="1" \
        "${BOOTSTRAP_BIN}" --yes --no-probe --plan-json "${plan_file}" 2>&1
    )"

    local prof status
    prof="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['profile'])")"
    status="$(python3 -B -c "import json; d=json.load(open('${plan_file}')); print(d['probe_results']['status'])")"

    if [[ "${prof}" != "tunnel" ]]; then
        echo "FAIL: expected tunnel default in non-interactive invocation without profile/probe, got ${prof}" >&2
        return 1
    fi
    if [[ "${status}" != "skipped" ]]; then
        echo "FAIL: expected skipped probe status, got ${status}" >&2
        return 1
    fi
    if [[ "${output}" != *"defaults to 'tunnel'"* ]]; then
        echo "FAIL: missing explanation of default to tunnel in output: ${output}" >&2
        return 1
    fi
    echo "PASS: Non-interactive without probe capability cleanly defaults to tunnel with explanation."
}

test_probe_success
test_probe_cgnat_downgrade
test_probe_explicit_direct_override
test_no_probe_flag
test_ipv6_reachability
test_dual_vantage_success
test_dual_vantage_partial
test_active_v6_route_unreachable
test_non_interactive_no_probe_default

echo "ALL PROBE ACCEPTANCE TESTS PASSED."
