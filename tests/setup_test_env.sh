#!/usr/bin/env bash
# Helper to generate ephemeral Ed25519 test credentials and sign test fixtures at runtime.
set -euo pipefail

setup_test_artifacts() {
    local target_dir="$1"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local fixture_dir="${script_dir}/fixtures/manifest"

    mkdir -p "${target_dir}"

    local temp_key
    temp_key="$(mktemp)"

    # Generate ephemeral Ed25519 private key
    openssl genpkey -algorithm ed25519 -out "${temp_key}" 2>/dev/null
    # Extract ephemeral public key
    openssl pkey -in "${temp_key}" -pubout -out "${target_dir}/release.pub" 2>/dev/null

    echo "test-release-key-1" > "${target_dir}/release.key_id"
    cp "${fixture_dir}/opskit-"* "${target_dir}/"

    # Canonicalize and sign manifest using ephemeral key
    local canon_file="${target_dir}/canon.tmp"
    python3 -B "${script_dir}/../lib/canonicalize.py" --strip signatures "${fixture_dir}/release-manifest.json" > "${canon_file}"
    local sig
    sig="$(openssl pkeyutl -sign -inkey "${temp_key}" -rawin -in "${canon_file}" 2>/dev/null | python3 -B -c "import sys; print(sys.stdin.buffer.read().hex())")"
    rm -f "${canon_file}"

    python3 -B -c "
import json, sys
target_dir, sig = sys.argv[1:3]
with open('${fixture_dir}/release-manifest.json', 'r', encoding='utf-8') as f:
    d = json.load(f)
d['signatures'] = [{'key_id': 'test-release-key-1', 'algorithm': 'ed25519', 'signature': sig}]
with open(f'{target_dir}/release-manifest.json', 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2)
" "${target_dir}" "${sig}"

    # Delete ephemeral private key immediately
    rm -f "${temp_key}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <target_directory>" >&2
        exit 1
    fi
    setup_test_artifacts "$1"
fi
