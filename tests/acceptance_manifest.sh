#!/usr/bin/env bash
# Acceptance test suite for release manifest verification and artifact installation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BOOTSTRAP_BIN="${REPO_ROOT}/bin/opskit-bootstrap"

export OPSKIT_TEST_MODE="1"

# Source bootstrap libraries
source "${REPO_ROOT}/lib/common.sh"
source "${REPO_ROOT}/lib/manifest.sh"
source "${REPO_ROOT}/tests/setup_test_env.sh"

TEST_TEMP_DIR="$(mktemp -d)"

cleanup() {
    # Stop background test HTTP servers if running
    if [[ -n "${HTTP_SERVER_PID:-}" ]] && kill -0 "${HTTP_SERVER_PID}" 2>/dev/null; then
        kill "${HTTP_SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf "${TEST_TEMP_DIR}"
}
trap cleanup EXIT

echo "=== Running acceptance_manifest.sh ==="

# Generate ephemeral test keypair and signed fixtures at runtime
FIXTURE_DIR="${TEST_TEMP_DIR}/ephemeral_fixtures"
setup_test_artifacts "${FIXTURE_DIR}"
export OPSKIT_RELEASE_PUBKEY="${FIXTURE_DIR}/release.pub"
export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

# Test 1: Valid signed manifest installs artifact successfully from local directory
test_valid_manifest_install() {
    echo "--- Test 1: Valid signed manifest installation ---"
    local target_bin="${TEST_TEMP_DIR}/opskit_valid"
    export CLI_INSTALL_PATH="${target_bin}"
    export OPSKIT_ARTIFACT_SOURCE_DIR="${FIXTURE_DIR}"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    verify_and_install_cli

    if [[ ! -x "${target_bin}" ]]; then
        echo "FAIL: target binary not installed or not executable" >&2
        return 1
    fi

    local out
    out="$("${target_bin}")"
    if [[ "${out}" != *"opskit CLI 0.1.0 mock test"* ]]; then
        echo "FAIL: unexpected binary output: ${out}" >&2
        return 1
    fi
    echo "PASS: Valid manifest verified and installed."
}

# Test 2: Tampered signature fails with exit 8 and does not install
test_tampered_signature() {
    echo "--- Test 2: Tampered manifest signature rejection ---"
    local test_dir="${TEST_TEMP_DIR}/tampered_sig"
    mkdir -p "${test_dir}"
    cp "${FIXTURE_DIR}/release.pub" "${test_dir}/"
    cp "${FIXTURE_DIR}/release.key_id" "${test_dir}/"
    cp "${FIXTURE_DIR}/opskit-linux-"* "${test_dir}/"

    # Flip characters in signature
    python3 -B -c "
import json
with open('${FIXTURE_DIR}/release-manifest.json', 'r') as f:
    d = json.load(f)
sig = d['signatures'][0]['signature']
tampered_sig = ('0' if sig[0] != '0' else '1') + sig[1:]
d['signatures'][0]['signature'] = tampered_sig
with open('${test_dir}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"

    local target_bin="${TEST_TEMP_DIR}/opskit_tampered_sig"
    export CLI_INSTALL_PATH="${target_bin}"
    export OPSKIT_ARTIFACT_SOURCE_DIR="${test_dir}"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    set +e
    ( verify_and_install_cli ) >/dev/null 2>&1
    local code=$?
    set -e

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 on tampered signature, got ${code}" >&2
        return 1
    fi

    if [[ -f "${target_bin}" ]]; then
        echo "FAIL: target binary was installed despite tampered signature" >&2
        return 1
    fi
    echo "PASS: Tampered signature rejected with code 8."
}

# Test 3: Tampered binary payload digest fails with exit 8 and does not install
test_tampered_binary_digest() {
    echo "--- Test 3: Tampered binary digest rejection ---"
    local test_dir="${TEST_TEMP_DIR}/tampered_bin"
    mkdir -p "${test_dir}"
    cp "${FIXTURE_DIR}/release.pub" "${test_dir}/"
    cp "${FIXTURE_DIR}/release.key_id" "${test_dir}/"
    cp "${FIXTURE_DIR}/release-manifest.json" "${test_dir}/"
    cp "${FIXTURE_DIR}/opskit-linux-"* "${test_dir}/"

    local host_arch
    host_arch="$(uname -m)"
    echo "TAMPERED" >> "${test_dir}/opskit-linux-${host_arch}"

    local target_bin="${TEST_TEMP_DIR}/opskit_tampered_bin"
    export CLI_INSTALL_PATH="${target_bin}"
    export OPSKIT_ARTIFACT_SOURCE_DIR="${test_dir}"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    set +e
    ( verify_and_install_cli ) >/dev/null 2>&1
    local code=$?
    set -e

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 on tampered binary digest, got ${code}" >&2
        return 1
    fi

    if [[ -f "${target_bin}" ]]; then
        echo "FAIL: target binary was installed despite tampered binary" >&2
        return 1
    fi
    echo "PASS: Tampered binary digest rejected with code 8."
}

# Test 4: Missing architecture in manifest fails with exit 8
test_missing_architecture() {
    echo "--- Test 4: Missing architecture rejection ---"
    local test_dir="${TEST_TEMP_DIR}/missing_arch"
    mkdir -p "${test_dir}"
    cp "${FIXTURE_DIR}/release.key_id" "${test_dir}/"
    cp "${FIXTURE_DIR}/opskit-linux-"* "${test_dir}/"

    local temp_arch_key="${TEST_TEMP_DIR}/temp_arch.key"
    openssl genpkey -algorithm ed25519 -out "${temp_arch_key}" 2>/dev/null
    local temp_arch_pub="${test_dir}/release.pub"
    openssl pkey -in "${temp_arch_key}" -pubout -out "${temp_arch_pub}" 2>/dev/null

    python3 -B -c "
import json, subprocess, os
with open('${FIXTURE_DIR}/release-manifest.json', 'r') as f:
    d = json.load(f)
d['artifacts'] = {'opskit-linux-nonexistent': {'sha256': 'abc', 'size': 10}}
canon = json.dumps(d, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
canon_file = '${test_dir}/canon.tmp'
with open(canon_file, 'wb') as f:
    f.write(canon)
p = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${temp_arch_key}', '-rawin', '-in', canon_file], stdout=subprocess.PIPE, check=True)
os.remove(canon_file)
sig = p.stdout.hex()
d['signatures'] = [{'key_id': 'test-release-key-1', 'algorithm': 'ed25519', 'signature': sig}]
with open('${test_dir}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"
    rm -f "${temp_arch_key}"

    local target_bin="${TEST_TEMP_DIR}/opskit_missing_arch"
    export CLI_INSTALL_PATH="${target_bin}"
    export OPSKIT_ARTIFACT_SOURCE_DIR="${test_dir}"
    export OPSKIT_RELEASE_PUBKEY="${temp_arch_pub}"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    set +e
    ( verify_and_install_cli ) >/dev/null 2>&1
    local code=$?
    set -e

    export OPSKIT_RELEASE_PUBKEY="${FIXTURE_DIR}/release.pub"

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 on missing arch, got ${code}" >&2
        return 1
    fi
    echo "PASS: Missing architecture rejected with code 8."
}

# Test 5: Network download from local HTTP server installs verified artifact
test_network_http_download() {
    echo "--- Test 5: Remote HTTP manifest and payload download ---"
    local server_port=18081
    local http_dir="${TEST_TEMP_DIR}/http_server"
    mkdir -p "${http_dir}"
    cp -r "${FIXTURE_DIR}/"* "${http_dir}/"

    python3 -B -m http.server "${server_port}" --bind 127.0.0.1 --directory "${http_dir}" >/dev/null 2>&1 &
    HTTP_SERVER_PID=$!
    sleep 1

    local target_bin="${TEST_TEMP_DIR}/opskit_http_valid"
    export CLI_INSTALL_PATH="${target_bin}"
    unset OPSKIT_ARTIFACT_SOURCE_DIR
    export OPSKIT_MANIFEST_URL="http://127.0.0.1:${server_port}/release-manifest.json"
    export OPSKIT_RELEASE_PUBKEY="${FIXTURE_DIR}/release.pub"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    verify_and_install_cli

    if [[ ! -x "${target_bin}" ]]; then
        echo "FAIL: remote artifact not downloaded/installed" >&2
        return 1
    fi

    local out
    out="$("${target_bin}")"
    if [[ "${out}" != *"opskit CLI 0.1.0 mock test"* ]]; then
        echo "FAIL: unexpected binary output from network install: ${out}" >&2
        return 1
    fi

    kill "${HTTP_SERVER_PID}" 2>/dev/null || true
    unset HTTP_SERVER_PID
    echo "PASS: Network manifest and payload download verified."
}

# Test 6: Network download of tampered payload is rejected and not executed
test_network_tampered_payload_rejection() {
    echo "--- Test 6: Network download of tampered payload rejection ---"
    local server_port=18082
    local http_dir="${TEST_TEMP_DIR}/http_tampered"
    mkdir -p "${http_dir}"
    cp -r "${FIXTURE_DIR}/"* "${http_dir}/"

    local host_arch
    host_arch="$(uname -m)"
    echo "CORRUPTED_BYTES" >> "${http_dir}/opskit-linux-${host_arch}"

    python3 -B -m http.server "${server_port}" --bind 127.0.0.1 --directory "${http_dir}" >/dev/null 2>&1 &
    HTTP_SERVER_PID=$!
    sleep 1

    local target_bin="${TEST_TEMP_DIR}/opskit_http_tampered"
    export CLI_INSTALL_PATH="${target_bin}"
    unset OPSKIT_ARTIFACT_SOURCE_DIR
    export OPSKIT_MANIFEST_URL="http://127.0.0.1:${server_port}/release-manifest.json"
    export OPSKIT_RELEASE_PUBKEY="${FIXTURE_DIR}/release.pub"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    set +e
    ( verify_and_install_cli ) >/dev/null 2>&1
    local code=$?
    set -e

    kill "${HTTP_SERVER_PID}" 2>/dev/null || true
    unset HTTP_SERVER_PID

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 on tampered remote payload, got ${code}" >&2
        return 1
    fi

    if [[ -f "${target_bin}" ]]; then
        echo "FAIL: tampered remote payload was installed to ${target_bin}" >&2
        return 1
    fi

    echo "PASS: Remote tampered payload rejected without installing."
}

# Test 7: Missing manifest source fails with code 9 without creating stub CLI
test_missing_manifest_source_remedy() {
    echo "--- Test 7: Missing manifest source fails with exit 9 and remedy ---"
    local target_bin="${TEST_TEMP_DIR}/opskit_nonexistent_stub"
    rm -f "${target_bin}"
    export CLI_INSTALL_PATH="${target_bin}"
    unset OPSKIT_ARTIFACT_SOURCE_DIR
    unset OPSKIT_MANIFEST_URL

    set +e
    local out
    out="$( ( verify_and_install_cli ) 2>&1 )"
    local code=$?
    set -e

    if [[ ${code} -ne 9 ]]; then
        echo "FAIL: expected exit code 9 when manifest source missing, got ${code}" >&2
        return 1
    fi

    if [[ -f "${target_bin}" ]]; then
        echo "FAIL: stub CLI was fabricated when no manifest source was provided" >&2
        return 1
    fi

    if [[ "${out}" != *"Provide --artifact-dir"* ]]; then
        echo "FAIL: expected remedy message in error output, got: ${out}" >&2
        return 1
    fi

    echo "PASS: Missing manifest source exits 9 with remedy text, stub path completely eliminated."
}

# Test 8: Public key override forbidden in production outside test mode
test_pubkey_override_forbidden_in_production() {
    echo "--- Test 8: Public key override forbidden in production ---"
    local target_bin="${TEST_TEMP_DIR}/opskit_prod_refusal"
    set +e
    local out
    out="$( ( OPSKIT_TEST_MODE="0" OPSKIT_RELEASE_PUBKEY="${FIXTURE_DIR}/release.pub" OPSKIT_ARTIFACT_SOURCE_DIR="${FIXTURE_DIR}" verify_and_install_cli ) 2>&1 )"
    local code=$?
    set -e

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 when overriding release public key without OPSKIT_TEST_MODE=1, got ${code}" >&2
        return 1
    fi
    if [[ "${out}" != *"forbidden in production"* ]]; then
        echo "FAIL: expected forbidden message, got: ${out}" >&2
        return 1
    fi
    echo "PASS: Public key override cleanly rejected with code 8 outside test mode."
}

# Test 9: Pre-flight failure in compile_plan when no artifact source resolvable
test_compile_plan_preflight_no_artifact_source() {
    echo "--- Test 9: Pre-flight failure in compile_plan when no artifact source resolvable ---"
    local target_plan="${TEST_TEMP_DIR}/plan_no_source.json"
    set +e
    local out
    out="$( (
        unset OPSKIT_ARTIFACT_SOURCE_DIR
        unset OPSKIT_MANIFEST_URL
        unset FLAG_ARTIFACT_DIR
        env OPSKIT_TEST_MODE="1" OPSKIT_SKIP_DISK_CHECK="1" OPSKIT_CLI_INSTALL_PATH="${TEST_TEMP_DIR}/nonexistent_bin_path" \
            "${BOOTSTRAP_BIN}" --profile direct --no-probe --plan-json "${target_plan}"
    ) 2>&1 )"
    local code=$?
    set -e

    if [[ ${code} -ne 9 ]]; then
        echo "FAIL: expected exit code 9 on missing artifact source pre-flight, got ${code}" >&2
        return 1
    fi
    if [[ "${out}" != *"Provide --artifact-dir"* ]]; then
        echo "FAIL: expected remedy in output, got: ${out}" >&2
        return 1
    fi
    echo "PASS: Pre-flight in compile_plan failed before any mutations with code 9 and remedy."
}

# Test 10: Pre-flight failure in compile_plan when local manifest lacks host architecture
test_compile_plan_preflight_missing_architecture() {
    echo "--- Test 10: Pre-flight failure in compile_plan when local manifest lacks host architecture ---"
    local test_dir="${TEST_TEMP_DIR}/preflight_missing_arch"
    mkdir -p "${test_dir}"
    local temp_arch_key="${TEST_TEMP_DIR}/temp_arch_preflight.key"
    openssl genpkey -algorithm ed25519 -out "${temp_arch_key}" 2>/dev/null
    local temp_arch_pub="${test_dir}/release.pub"
    openssl pkey -in "${temp_arch_key}" -pubout -out "${temp_arch_pub}" 2>/dev/null
    echo "test-release-key-1" > "${test_dir}/release.key_id"

    python3 -B -c "
import json, subprocess, os
with open('${FIXTURE_DIR}/release-manifest.json', 'r') as f:
    d = json.load(f)
d.pop('signatures', None)
d['artifacts'] = {'opskit-linux-nonexistent_arch': {'sha256': '0'*64, 'size': 123}}
canon = json.dumps(d, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
canon_file = '${test_dir}/canon.tmp'
with open(canon_file, 'wb') as f:
    f.write(canon)
p = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${temp_arch_key}', '-rawin', '-in', canon_file], stdout=subprocess.PIPE, check=True)
os.remove(canon_file)
sig = p.stdout.hex()
d['signatures'] = [{'key_id': 'test-release-key-1', 'algorithm': 'ed25519', 'signature': sig}]
with open('${test_dir}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"
    rm -f "${temp_arch_key}"

    local target_plan="${TEST_TEMP_DIR}/plan_missing_arch.json"
    set +e
    local out
    out="$( (
        env OPSKIT_TEST_MODE="1" OPSKIT_SKIP_DISK_CHECK="1" \
            OPSKIT_RELEASE_PUBKEY="${temp_arch_pub}" \
            OPSKIT_EXPECTED_KEY_ID="test-release-key-1" \
            CLI_INSTALL_PATH="${TEST_TEMP_DIR}/nonexistent_bin_path" \
            "${BOOTSTRAP_BIN}" --profile direct --no-probe --artifact-dir "${test_dir}" --plan-json "${target_plan}"
    ) 2>&1 )"
    local code=$?
    set -e

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 on manifest missing architecture in compile_plan pre-flight, got ${code}" >&2
        return 1
    fi
    if [[ "${out}" != *"does not declare artifact for host architecture"* ]]; then
        echo "FAIL: expected missing architecture message, got: ${out}" >&2
        return 1
    fi
    echo "PASS: Missing host architecture in local manifest rejected in compile_plan pre-flight with code 8."
}

# Test 11: Mock test hooks forbidden in production outside OPSKIT_TEST_MODE=1
test_mock_test_hooks_forbidden_in_production() {
    echo "--- Test 11: Mock test hooks forbidden in production ---"
    local hooks=("MOCK_SELINUX_STATUS=Enforcing" "MOCK_RUNTIME_VERSION=1.2.3" "MOCK_CGROUP_CONTROLLERS=cpu memory" "MOCK_APPARMOR_STATUS=1" "OPSKIT_TEST_FORCE_PACKAGES=1")

    for hook_assign in "${hooks[@]}"; do
        local var_name="${hook_assign%%=*}"
        local var_val="${hook_assign#*=}"
        set +e
        local out
        out="$( env OPSKIT_TEST_MODE="0" "${var_name}=${var_val}" "${BOOTSTRAP_BIN}" --dry-run 2>&1 )"
        local code=$?
        set -e

        if [[ ${code} -ne 8 ]]; then
            echo "FAIL: expected exit code 8 when setting ${var_name} without OPSKIT_TEST_MODE=1, got ${code}" >&2
            return 1
        fi
        if [[ "${out}" != *"is forbidden in production unless OPSKIT_TEST_MODE=1"* ]]; then
            echo "FAIL: expected forbidden message for ${var_name}, got: ${out}" >&2
            return 1
        fi
    done
    echo "PASS: All mock test hooks strictly refused with code 8 outside OPSKIT_TEST_MODE=1."
}

# Test 12: Ledger conformance fixture verification
test_ledger_conformance_fixture() {
    echo "--- Test 12: Ledger conformance fixture verification ---"
    source "${REPO_ROOT}/lib/ledger.sh"
    local fixture_key="${REPO_ROOT}/tests/fixtures/ledger/ledger.key"
    local fixture_entry="${REPO_ROOT}/tests/fixtures/ledger/entry_packages_two.jsonl"

    export LEDGER_KEY_FILE="${fixture_key}"
    local line
    line="$(cat "${fixture_entry}")"
    if ! verify_ledger_line "${line}" 1; then
        echo "FAIL: Conformance fixture entry failed verification against fixture key" >&2
        return 1
    fi
    echo "PASS: Conformance fixture 2-package ledger line verified with canonical HMAC."
}

# Test 13: Missing canonicalize helper fails with exit 8 and clean message
test_missing_canonicalize_helper_refusal() {
    echo "--- Test 13: Missing canonicalize helper fails with exit 8 and clean error message ---"
    local fake_lib="${TEST_TEMP_DIR}/fake_lib"
    mkdir -p "${fake_lib}"

    set +e
    local out
    out="$( ( LIB_DIR="${fake_lib}" ensure_canonicalize_helper ) 2>&1 )"
    local code=$?
    set -e

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 when canonicalize.py is missing, got ${code}" >&2
        return 1
    fi
    if [[ "${out}" != *"Required canonicalization helper not found"* ]]; then
        echo "FAIL: expected clear error message, got: ${out}" >&2
        return 1
    fi
    echo "PASS: Missing canonicalize helper cleanly refused with code 8 and real error message."
}

test_valid_manifest_install
test_tampered_signature
test_tampered_binary_digest
test_missing_architecture
test_network_http_download
test_network_tampered_payload_rejection
test_missing_manifest_source_remedy
test_pubkey_override_forbidden_in_production
test_compile_plan_preflight_no_artifact_source
test_compile_plan_preflight_missing_architecture
test_mock_test_hooks_forbidden_in_production
test_ledger_conformance_fixture
test_missing_canonicalize_helper_refusal

# Test 14: Empty or missing key_id in manifest signature is rejected with exit 8
test_empty_key_id_rejection() {
    echo "--- Test 14: Empty signature key_id rejection ---"
    local test_dir="${TEST_TEMP_DIR}/empty_key_id"
    mkdir -p "${test_dir}"
    cp "${FIXTURE_DIR}/release.pub" "${test_dir}/"
    cp "${FIXTURE_DIR}/release.key_id" "${test_dir}/"
    cp "${FIXTURE_DIR}/opskit-linux-"* "${test_dir}/"

    local temp_key="${TEST_TEMP_DIR}/empty_kid.key"
    openssl genpkey -algorithm ed25519 -out "${temp_key}" 2>/dev/null
    openssl pkey -in "${temp_key}" -pubout -out "${test_dir}/release.pub" 2>/dev/null

    python3 -B -c "
import json, subprocess, os
with open('${FIXTURE_DIR}/release-manifest.json', 'r') as f:
    d = json.load(f)
d.pop('signatures', None)
canon = json.dumps(d, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
canon_file = '${test_dir}/canon.tmp'
with open(canon_file, 'wb') as f:
    f.write(canon)
p = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${temp_key}', '-rawin', '-in', canon_file], stdout=subprocess.PIPE, check=True)
os.remove(canon_file)
d['signatures'] = [{'key_id': '', 'algorithm': 'ed25519', 'signature': p.stdout.hex()}]
with open('${test_dir}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"
    rm -f "${temp_key}"

    local target_bin="${TEST_TEMP_DIR}/opskit_empty_kid"
    export CLI_INSTALL_PATH="${target_bin}"
    export OPSKIT_ARTIFACT_SOURCE_DIR="${test_dir}"
    export OPSKIT_RELEASE_PUBKEY="${test_dir}/release.pub"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    set +e
    local out
    out="$( ( verify_and_install_cli ) 2>&1 )"
    local code=$?
    set -e
    export OPSKIT_RELEASE_PUBKEY="${FIXTURE_DIR}/release.pub"

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 on empty key_id, got ${code}: ${out}" >&2
        return 1
    fi
    if [[ "${out}" != *"missing required key_id"* ]]; then
        echo "FAIL: expected missing required key_id error, got: ${out}" >&2
        return 1
    fi
    echo "PASS: Empty signature key_id cleanly rejected with exit 8."
}

# Test 15: Zero or non-positive artifact size is rejected with exit 8
test_non_positive_size_rejection() {
    echo "--- Test 15: Zero artifact size rejection ---"
    local test_dir="${TEST_TEMP_DIR}/zero_size"
    mkdir -p "${test_dir}"
    cp "${FIXTURE_DIR}/release.key_id" "${test_dir}/"
    cp "${FIXTURE_DIR}/opskit-linux-"* "${test_dir}/"

    local temp_key="${TEST_TEMP_DIR}/zero_size.key"
    openssl genpkey -algorithm ed25519 -out "${temp_key}" 2>/dev/null
    openssl pkey -in "${temp_key}" -pubout -out "${test_dir}/release.pub" 2>/dev/null

    python3 -B -c "
import json, subprocess, os
with open('${FIXTURE_DIR}/release-manifest.json', 'r') as f:
    d = json.load(f)
d.pop('signatures', None)
for art in d['artifacts'].values():
    art['size'] = 0
canon = json.dumps(d, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
canon_file = '${test_dir}/canon.tmp'
with open(canon_file, 'wb') as f:
    f.write(canon)
p = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${temp_key}', '-rawin', '-in', canon_file], stdout=subprocess.PIPE, check=True)
os.remove(canon_file)
d['signatures'] = [{'key_id': 'test-release-key-1', 'algorithm': 'ed25519', 'signature': p.stdout.hex()}]
with open('${test_dir}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"
    rm -f "${temp_key}"

    local target_bin="${TEST_TEMP_DIR}/opskit_zero_size"
    export CLI_INSTALL_PATH="${target_bin}"
    export OPSKIT_ARTIFACT_SOURCE_DIR="${test_dir}"
    export OPSKIT_RELEASE_PUBKEY="${test_dir}/release.pub"
    export OPSKIT_EXPECTED_KEY_ID="test-release-key-1"

    set +e
    local out
    out="$( ( verify_and_install_cli ) 2>&1 )"
    local code=$?
    set -e
    export OPSKIT_RELEASE_PUBKEY="${FIXTURE_DIR}/release.pub"

    if [[ ${code} -ne 8 ]]; then
        echo "FAIL: expected exit code 8 on size=0, got ${code}: ${out}" >&2
        return 1
    fi
    if [[ "${out}" != *"non-positive size"* ]]; then
        echo "FAIL: expected non-positive size error, got: ${out}" >&2
        return 1
    fi
    echo "PASS: Zero artifact size cleanly rejected with exit 8."
}

# Test 16: Preflight in compile_plan rejects missing or tampered local binary before apply
test_preflight_checks_local_binary_presence_and_digest() {
    echo "--- Test 16: Preflight rejects missing/corrupted local binary before apply ---"
    local missing_dir="${TEST_TEMP_DIR}/preflight_missing_bin"
    mkdir -p "${missing_dir}"
    cp "${FIXTURE_DIR}/release-manifest.json" "${FIXTURE_DIR}/release.pub" "${FIXTURE_DIR}/release.key_id" "${missing_dir}/"

    local target_plan="${TEST_TEMP_DIR}/plan_missing_bin.json"
    set +e
    local out_missing
    out_missing="$( (
        env OPSKIT_TEST_MODE="1" OPSKIT_SKIP_DISK_CHECK="1" \
            OPSKIT_RELEASE_PUBKEY="${missing_dir}/release.pub" \
            OPSKIT_EXPECTED_KEY_ID="test-release-key-1" \
            OPSKIT_CLI_INSTALL_PATH="${TEST_TEMP_DIR}/nonexistent_cli" \
            "${BOOTSTRAP_BIN}" --profile direct --no-probe --artifact-dir "${missing_dir}" --plan-json "${target_plan}"
    ) 2>&1 )"
    local code_missing=$?
    set -e
    if [[ ${code_missing} -ne 8 ]] || [[ "${out_missing}" != *"not found in source directory"* ]]; then
        echo "FAIL: preflight did not reject missing local binary cleanly (code=${code_missing}): ${out_missing}" >&2
        return 1
    fi

    # Tampered local binary in source dir
    cp "${FIXTURE_DIR}/opskit-linux-"* "${missing_dir}/"
    echo "CORRUPT" >> "${missing_dir}/opskit-linux-$(uname -m)"
    set +e
    local out_tampered
    out_tampered="$( (
        env OPSKIT_TEST_MODE="1" OPSKIT_SKIP_DISK_CHECK="1" \
            OPSKIT_RELEASE_PUBKEY="${missing_dir}/release.pub" \
            OPSKIT_EXPECTED_KEY_ID="test-release-key-1" \
            OPSKIT_CLI_INSTALL_PATH="${TEST_TEMP_DIR}/nonexistent_cli" \
            "${BOOTSTRAP_BIN}" --profile direct --no-probe --artifact-dir "${missing_dir}" --plan-json "${target_plan}"
    ) 2>&1 )"
    local code_tampered=$?
    set -e
    if [[ ${code_tampered} -ne 8 ]] || [[ "${out_tampered}" != *"digest mismatch"* ]]; then
        echo "FAIL: preflight did not reject tampered local binary cleanly (code=${code_tampered}): ${out_tampered}" >&2
        return 1
    fi
    echo "PASS: Preflight rejected missing and tampered local artifacts at plan time."
}

# Test 17: Preflight rejects --artifact-dir missing release-manifest.json and refuses bare binary without source
test_missing_manifest_in_artifact_dir_and_no_binary_fallback() {
    echo "--- Test 17: Missing release-manifest.json in --artifact-dir and no bare-binary fallback ---"
    local empty_art_dir="${TEST_TEMP_DIR}/empty_art_dir"
    mkdir -p "${empty_art_dir}"
    local target_plan="${TEST_TEMP_DIR}/plan_empty_art.json"

    set +e
    local out_empty
    out_empty="$( (
        env -u OPSKIT_ARTIFACT_SOURCE_DIR -u OPSKIT_MANIFEST_URL \
            OPSKIT_TEST_MODE="1" OPSKIT_SKIP_DISK_CHECK="1" \
            OPSKIT_CLI_INSTALL_PATH="${TEST_TEMP_DIR}/nonexistent_cli" \
            "${BOOTSTRAP_BIN}" --profile direct --no-probe --artifact-dir "${empty_art_dir}" --plan-json "${target_plan}"
    ) 2>&1 )"
    local code_empty=$?
    set -e
    if [[ ${code_empty} -ne 8 ]] || [[ "${out_empty}" != *"Release manifest not found"* ]]; then
        echo "FAIL: missing release-manifest.json in --artifact-dir was not rejected cleanly (code=${code_empty}): ${out_empty}" >&2
        return 1
    fi

    # Pre-existing executable at CLI_INSTALL_PATH must NEVER satisfy artifact source requirement
    local existing_bin="${TEST_TEMP_DIR}/existing_cli_bin"
    printf '#!/bin/sh\necho fake\n' > "${existing_bin}"
    chmod 0755 "${existing_bin}"
    set +e
    local out_bare
    out_bare="$( (
        env -u OPSKIT_ARTIFACT_SOURCE_DIR -u OPSKIT_MANIFEST_URL \
            OPSKIT_TEST_MODE="1" OPSKIT_SKIP_DISK_CHECK="1" \
            OPSKIT_CLI_INSTALL_PATH="${existing_bin}" \
            "${BOOTSTRAP_BIN}" --profile direct --no-probe --plan-json "${target_plan}"
    ) 2>&1 )"
    local code_bare=$?
    set -e
    if [[ ${code_bare} -ne 9 ]] || [[ "${out_bare}" != *"Provide --artifact-dir"* ]]; then
        echo "FAIL: bare executable at CLI_INSTALL_PATH bypassed missing-source refusal (code=${code_bare}): ${out_bare}" >&2
        return 1
    fi
    echo "PASS: Missing manifest in --artifact-dir (exit 8) and bare binary without source (exit 9) rejected cleanly."
}

test_empty_key_id_rejection
test_non_positive_size_rejection
test_preflight_checks_local_binary_presence_and_digest
test_missing_manifest_in_artifact_dir_and_no_binary_fallback

# Test 18: Path traversal in manifest filename rejected before download/copy
test_filename_path_traversal_rejection() {
    echo "--- Test 18: Path traversal in manifest filename rejection ---"
    local test_dir="${TEST_TEMP_DIR}/traversal"
    mkdir -p "${test_dir}"
    local temp_key="${TEST_TEMP_DIR}/trav.key"
    openssl genpkey -algorithm ed25519 -out "${temp_key}" 2>/dev/null
    openssl pkey -in "${temp_key}" -pubout -out "${test_dir}/release.pub" 2>/dev/null
    echo "test-release-key-1" > "${test_dir}/release.key_id"

    python3 -B -c "
import json, subprocess, os
with open('${FIXTURE_DIR}/release-manifest.json', 'r') as f:
    d = json.load(f)
d.pop('signatures', None)
host_arch = os.uname().machine
d['artifacts'][f'opskit-linux-{host_arch}']['filename'] = '../../evil-payload'
canon = json.dumps(d, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
canon_file = '${test_dir}/canon.tmp'
with open(canon_file, 'wb') as f:
    f.write(canon)
p = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${temp_key}', '-rawin', '-in', canon_file], stdout=subprocess.PIPE, check=True)
os.remove(canon_file)
d['signatures'] = [{'key_id': 'test-release-key-1', 'algorithm': 'ed25519', 'signature': p.stdout.hex()}]
with open('${test_dir}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"
    rm -f "${temp_key}"

    local target_bin="${TEST_TEMP_DIR}/opskit_trav"
    set +e
    local out
    out="$( ( OPSKIT_ARTIFACT_SOURCE_DIR="${test_dir}" OPSKIT_RELEASE_PUBKEY="${test_dir}/release.pub" OPSKIT_EXPECTED_KEY_ID="test-release-key-1" CLI_INSTALL_PATH="${target_bin}" verify_and_install_cli ) 2>&1 )"
    local code=$?
    set -e
    if [[ ${code} -ne 8 ]] || [[ "${out}" != *"Invalid artifact filename"* ]]; then
        echo "FAIL: expected exit 8 on filename traversal, got ${code}: ${out}" >&2
        return 1
    fi
    echo "PASS: Manifest filename path traversal rejected with exit 8."
}

# Test 19: Path-override env vars rejected in production and dangerous paths rejected in test mode
test_path_override_gating() {
    echo "--- Test 19: Path-override env var gating ---"
    for pvar in OPSKIT_BOOTSTRAP_STATE_DIR OPSKIT_SERVICE_STATE_DIR OPSKIT_CLI_INSTALL_PATH OPSKIT_SYSTEMD_SYSTEM_DIR OPSKIT_SUBUID_FILE OPSKIT_SUBGID_FILE; do
        set +e
        local out
        out="$( env OPSKIT_TEST_MODE="0" "${pvar}=/tmp/override_test" "${BOOTSTRAP_BIN}" --dry-run 2>&1 )"
        local code=$?
        set -e
        if [[ ${code} -ne 8 ]] || [[ "${out}" != *"forbidden in production"* ]]; then
            echo "FAIL: ${pvar} not rejected outside test mode (code=${code}): ${out}" >&2
            return 1
        fi
    done
    for bad_path in "/" "/etc" "/etc/systemd" "/var/lib" "/tmp/../etc"; do
        set +e
        local bad_out
        bad_out="$( env OPSKIT_TEST_MODE="1" OPSKIT_SERVICE_STATE_DIR="${bad_path}" "${BOOTSTRAP_BIN}" --dry-run 2>&1 )"
        local bad_rc=$?
        set -e
        if [[ ${bad_rc} -ne 8 ]]; then
            echo "FAIL: dangerous override '${bad_path}' not rejected in test mode (code=${bad_rc}): ${bad_out}" >&2
            return 1
        fi
    done
    echo "PASS: Privileged path-override env vars strictly gated and validated."
}

# Test 20: Non-HTTPS remote URLs rejected and production release bundle locks down test mode
test_https_enforcement_and_production_bundle() {
    echo "--- Test 20: HTTPS URL enforcement and production release bundle lockdown ---"
    set +e
    local http_out file_out
    http_out="$( ( OPSKIT_TEST_MODE="0" validate_remote_url "http://example.com/manifest.json" "manifest URL" ) 2>&1 )"
    local http_rc=$?
    file_out="$( ( validate_remote_url "file:///etc/passwd" "manifest URL" ) 2>&1 )"
    local file_rc=$?
    set -e
    if [[ ${http_rc} -ne 8 || ${file_rc} -ne 8 ]]; then
        echo "FAIL: insecure URLs were not rejected (http=${http_rc}, file=${file_rc})" >&2
        return 1
    fi

    local prod_bundle="${TEST_TEMP_DIR}/prod_bundle"
    bash "${REPO_ROOT}/scripts/build-release.sh" "${prod_bundle}" >/dev/null
    set +e
    local prod_out
    prod_out="$( env OPSKIT_TEST_MODE="1" "${prod_bundle}/bin/opskit-bootstrap" --dry-run 2>&1 )"
    local prod_rc=$?
    set -e
    if [[ ${prod_rc} -ne 8 ]] || [[ "${prod_out}" != *"disabled in production builds"* ]]; then
        echo "FAIL: production bundle allowed OPSKIT_TEST_MODE=1 (rc=${prod_rc}): ${prod_out}" >&2
        return 1
    fi
    echo "PASS: Non-HTTPS URLs rejected and production bundle locked down against OPSKIT_TEST_MODE=1."
}

# Test 21: Multi-signature rotation key_id selection and duplicate JSON key rejection
test_multisig_and_strict_json() {
    echo "--- Test 21: Multi-signature key rotation and strict duplicate-key JSON rejection ---"
    local test_dir="${TEST_TEMP_DIR}/multisig"
    mkdir -p "${test_dir}"
    cp "${FIXTURE_DIR}/opskit-linux-"* "${test_dir}/"

    local key_old="${TEST_TEMP_DIR}/old.key" key_new="${TEST_TEMP_DIR}/new.key"
    openssl genpkey -algorithm ed25519 -out "${key_old}" 2>/dev/null
    openssl genpkey -algorithm ed25519 -out "${key_new}" 2>/dev/null
    openssl pkey -in "${key_new}" -pubout -out "${test_dir}/release.pub" 2>/dev/null
    echo "key-new-2026" > "${test_dir}/release.key_id"

    python3 -B -c "
import json, subprocess, os
with open('${FIXTURE_DIR}/release-manifest.json', 'r') as f:
    d = json.load(f)
d.pop('signatures', None)
canon = json.dumps(d, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
cf = '${test_dir}/canon.tmp'
with open(cf, 'wb') as f:
    f.write(canon)
sig_old = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${key_old}', '-rawin', '-in', cf], stdout=subprocess.PIPE, check=True).stdout.hex()
sig_new = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', '${key_new}', '-rawin', '-in', cf], stdout=subprocess.PIPE, check=True).stdout.hex()
os.remove(cf)
d['signatures'] = [
    {'key_id': 'key-old-2025', 'algorithm': 'ed25519', 'signature': sig_old},
    {'key_id': 'key-new-2026', 'algorithm': 'ed25519', 'signature': sig_new}
]
with open('${test_dir}/release-manifest.json', 'w') as f:
    json.dump(d, f)
"
    rm -f "${key_old}" "${key_new}"

    local target_bin="${TEST_TEMP_DIR}/opskit_multisig"
    CLI_INSTALL_PATH="${target_bin}" OPSKIT_ARTIFACT_SOURCE_DIR="${test_dir}" OPSKIT_RELEASE_PUBKEY="${test_dir}/release.pub" OPSKIT_EXPECTED_KEY_ID="key-new-2026" verify_and_install_cli
    test -x "${target_bin}"

    # Duplicate key JSON must fail canonicalize.py
    echo '{"a":1,"a":2}' > "${test_dir}/dup.json"
    if python3 -B "${REPO_ROOT}/lib/canonicalize.py" "${test_dir}/dup.json" >/dev/null 2>&1; then
        echo "FAIL: canonicalize.py accepted duplicate JSON keys" >&2
        return 1
    fi
    echo "PASS: Multi-signature rotation and strict duplicate-key JSON rejection verified."
}

test_filename_path_traversal_rejection
test_path_override_gating
test_https_enforcement_and_production_bundle
test_multisig_and_strict_json

echo "ALL MANIFEST ACCEPTANCE TESTS PASSED."
