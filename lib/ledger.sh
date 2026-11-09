#!/usr/bin/env bash
# Tamper-evident applied mutation ledger (/var/lib/opskit-bootstrap/apply.jsonl) and offline vendoring.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh is loaded

ensure_bootstrap_state_dir() {
    if [[ ! -d "${BOOTSTRAP_STATE_DIR}" ]]; then
        mkdir -p "${BOOTSTRAP_STATE_DIR}"
        chmod 0700 "${BOOTSTRAP_STATE_DIR}"
        if [[ "${EUID}" -eq 0 ]]; then
            chown root:root "${BOOTSTRAP_STATE_DIR}"
        fi
    fi
}

cleanup_lock_only_state_dir() {
    if [[ -d "${BOOTSTRAP_STATE_DIR}" ]]; then
        local entries
        entries="$(ls -A "${BOOTSTRAP_STATE_DIR}" 2>/dev/null || true)"
        if [[ "${entries}" == ".state.lock" || -z "${entries}" ]]; then
            rm -f "${BOOTSTRAP_STATE_DIR}/.state.lock"
            rmdir "${BOOTSTRAP_STATE_DIR}" 2>/dev/null || true
        fi
    fi
}

ensure_ledger_key() {
    ensure_bootstrap_state_dir
    if [[ ! -f "${LEDGER_KEY_FILE}" ]]; then
        (
            flock -x 200
            if [[ ! -f "${LEDGER_KEY_FILE}" ]]; then
                local tmp_key
                tmp_key="$(mktemp "${BOOTSTRAP_STATE_DIR}/.key.XXXXXX")"
                openssl rand -hex 32 > "${tmp_key}"
                chmod 0600 "${tmp_key}"
                if [[ "${EUID}" -eq 0 ]]; then
                    chown root:root "${tmp_key}"
                fi
                mv -n "${tmp_key}" "${LEDGER_KEY_FILE}" 2>/dev/null || rm -f "${tmp_key}"
            fi
        ) 200>"${BOOTSTRAP_STATE_DIR}/.ledger.lock"
    fi
}

compute_entry_hmac() {
    local payload="$1"
    ensure_ledger_key
    ensure_canonicalize_helper
    printf '%s' "${payload}" | python3 -B -c "
import hmac, hashlib, json, sys
sys.path.insert(0, sys.argv[2])
from canonicalize import canonical_bytes
with open(sys.argv[1], 'rb') as kf:
    key = kf.read().strip()
raw = sys.stdin.read()
d = json.loads(raw)
canon = canonical_bytes(d, strip_keys={'hmac'})
sys.stdout.write(hmac.new(key, canon, hashlib.sha256).hexdigest())
" "${LEDGER_KEY_FILE}" "${LIB_DIR}"
}

record_mutation() {
    local mutation_id="$1"
    local class="$2"
    local before_fp="$3"
    local after_fp="$4"
    local plan_hash="$5"
    local metadata_json="${6:-}"
    if [[ -z "${metadata_json}" ]]; then
        metadata_json="{}"
    fi

    ensure_bootstrap_state_dir
    local already_recorded=false
    if is_mutation_recorded "${mutation_id}"; then
        already_recorded=true
        local should_update
        should_update="$(python3 -B -c "
import json, sys
mid = sys.argv[2]
try:
    new_meta = json.loads(sys.argv[3])
except Exception:
    print('no'); sys.exit(0)
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get('mutation_id') == mid:
            if d.get('metadata') != new_meta:
                print('yes:' + str(d.get('before_fingerprint', '')))
            else:
                print('no')
            sys.exit(0)
print('no')
" "${LEDGER_FILE}" "${mutation_id}" "${metadata_json}" 2>/dev/null || echo "no")"
        if [[ "${should_update}" != yes:* ]]; then
            return 0
        fi
        local orig_before="${should_update#yes:}"
        if [[ -n "${orig_before}" ]]; then
            before_fp="${orig_before}"
        fi
    fi
    ensure_ledger_key

    local ts
    ts="$(timestamp_rfc3339)"

    # Base entry payload (excluding hmac)
    local raw_entry
    raw_entry="{\"timestamp\":\"$(json_escape "${ts}")\",\"mutation_id\":\"$(json_escape "${mutation_id}")\",\"class\":\"$(json_escape "${class}")\",\"before_fingerprint\":\"$(json_escape "${before_fp}")\",\"after_fingerprint\":\"$(json_escape "${after_fp}")\",\"plan_hash\":\"$(json_escape "${plan_hash}")\",\"metadata\":${metadata_json}}"

    # Compute HMAC over canonical representation
    local hmac
    hmac="$(compute_entry_hmac "${raw_entry}")"

    # Assemble signed entry
    local signed_entry
    signed_entry="$(python3 -B -c "
import json, sys
d = json.loads(sys.argv[1])
d['hmac'] = sys.argv[2]
sys.stdout.write(json.dumps(d, separators=(',', ':')))
" "${raw_entry}" "${hmac}")"

    # Self-check: validate that signed_entry is strictly valid JSON with known mutation_id
    local valid
    valid="$(python3 -B -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
    known = {'packages', 'service_user', 'subuid_allocation', 'user_linger', 'edge_socket_units', 'edge_system_unit', 'firewall_rules', 'service_units', 'cloudflared_unit', 'security_labels', 'fetch_cli'}
    if d.get('mutation_id') not in known:
        print('unknown mutation_id')
        sys.exit(1)
    if 'hmac' not in d or 'plan_hash' not in d:
        print('missing required fields')
        sys.exit(1)
    print('ok')
except Exception as e:
    print(f'error: {e}')
    sys.exit(1)
" "${signed_entry}" 2>/dev/null || echo "error")"

    if [[ "${valid}" != "ok" ]]; then
        die "${EXIT_RUNTIME_ERROR}" "Refusing to append invalid JSON ledger entry: ${signed_entry} (${valid})"
    fi

    if ${already_recorded}; then
        local tmp_ledger
        tmp_ledger="$(mktemp "${BOOTSTRAP_STATE_DIR}/.ledger.XXXXXX")"
        chmod 0600 "${tmp_ledger}"
        if [[ "${EUID}" -eq 0 ]]; then
            chown root:root "${tmp_ledger}"
        fi
        python3 -B -c "
import json, sys
mid = sys.argv[2]
replacement = sys.argv[3].rstrip('\n') + '\n'
replaced = False
with open(sys.argv[1], 'r') as f_in, open(sys.argv[4], 'w') as f_out:
    for line in f_in:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            d = json.loads(stripped)
            if d.get('mutation_id') == mid:
                if not replaced:
                    f_out.write(replacement)
                    replaced = True
                continue
        except Exception:
            pass
        f_out.write(line if line.endswith('\n') else line + '\n')
" "${LEDGER_FILE}" "${mutation_id}" "${signed_entry}" "${tmp_ledger}"
        mv -f "${tmp_ledger}" "${LEDGER_FILE}"
    else
        echo "${signed_entry}" >> "${LEDGER_FILE}"
    fi
}

verify_ledger_line() {
    local line="$1"
    local line_num="$2"

    if [[ -z "${line}" ]]; then
        echo "Line ${line_num}: empty line in ledger" >&2
        return 1
    fi

    # 1. JSON parse & structure check
    local check_res
    check_res="$(python3 -B -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
    known = {'packages', 'service_user', 'subuid_allocation', 'user_linger', 'edge_socket_units', 'edge_system_unit', 'firewall_rules', 'service_units', 'cloudflared_unit', 'security_labels', 'fetch_cli'}
    mut_id = d.get('mutation_id')
    if not mut_id:
        print('missing mutation_id'); sys.exit(1)
    if mut_id not in known:
        print(f'unknown mutation_id: {mut_id}'); sys.exit(1)
    for req in ['timestamp', 'class', 'before_fingerprint', 'after_fingerprint', 'plan_hash', 'metadata', 'hmac']:
        if req not in d:
            print(f'missing required field: {req}'); sys.exit(1)
    print('ok')
except Exception as e:
    print(f'invalid json: {e}'); sys.exit(1)
" "${line}" 2>&1 || true)"

    if [[ "${check_res}" != "ok" ]]; then
        echo "Line ${line_num} verification failed: ${check_res}" >&2
        return 1
    fi

    # 2. HMAC verification (fails closed if key is missing)
    ensure_canonicalize_helper
    if [[ ! -f "${LEDGER_KEY_FILE}" ]]; then
        echo "Line ${line_num} verification failed: missing HMAC key file '${LEDGER_KEY_FILE}'" >&2
        return 1
    fi

    local hmac_check
    hmac_check="$(python3 -B -c "
import hmac, hashlib, json, sys
sys.path.insert(0, sys.argv[3])
from canonicalize import canonical_bytes
try:
    with open(sys.argv[1], 'rb') as kf:
        key = kf.read().strip()
    d = json.loads(sys.argv[2])
    entry_hmac = d.get('hmac', '')
    canon = canonical_bytes(d, strip_keys={'hmac'})
    expected_hmac = hmac.new(key, canon, hashlib.sha256).hexdigest()
    if hmac.compare_digest(entry_hmac, expected_hmac):
        print('ok')
    else:
        print('mismatch')
except Exception as e:
    print(f'error: {e}')
" "${LEDGER_KEY_FILE}" "${line}" "${LIB_DIR}" 2>/dev/null || echo "error")"

    if [[ "${hmac_check}" != "ok" ]]; then
        echo "Line ${line_num} verification failed: HMAC signature mismatch (tampered or corrupt line)" >&2
        return 1
    fi

    return 0
}

validate_entire_ledger() {
    if [[ ! -f "${LEDGER_FILE}" ]]; then
        return 0
    fi

    if [[ ! -f "${LEDGER_KEY_FILE}" ]]; then
        echo "Ledger verification failed: ledger exists at '${LEDGER_FILE}' but HMAC key '${LEDGER_KEY_FILE}' is missing." >&2
        return 1
    fi

    local line_num=1
    local has_errors=false
    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" ]] && continue
        if ! verify_ledger_line "${line}" "${line_num}"; then
            has_errors=true
        fi
        line_num=$((line_num + 1))
    done < "${LEDGER_FILE}"

    if ${has_errors}; then
        return 1
    fi
    return 0
}

vendor_uninstaller() {
    ensure_bootstrap_state_dir
    local target_bin="${BOOTSTRAP_STATE_DIR}/opskit-bootstrap"
    local target_lib_dir="${BOOTSTRAP_STATE_DIR}/lib"

    # If running from inside the vendored copy, no-op the copy!
    local real_state real_lib real_bin
    real_state="$(cd "${BOOTSTRAP_STATE_DIR}" 2>/dev/null && pwd -P || echo "${BOOTSTRAP_STATE_DIR}")"
    real_lib="$(cd "${LIB_DIR:-/nonexistent}" 2>/dev/null && pwd -P || echo "${LIB_DIR:-}")"
    real_bin="$(cd "${BIN_DIR:-/nonexistent}" 2>/dev/null && pwd -P || echo "${BIN_DIR:-}")"

    if [[ "${real_lib}/" == "${real_state}/"* || "${real_bin}/" == "${real_state}/"* ]]; then
        return 0
    fi

    # For the refresh case (repo copy over an older vendored copy), stage to a temp dir and swap atomically
    local stage_dir
    stage_dir="$(mktemp -d "${BOOTSTRAP_STATE_DIR}/.vendor.XXXXXX")"
    chmod 0700 "${stage_dir}"
    mkdir -p "${stage_dir}/lib/family"

    if [[ -n "${LIB_DIR:-}" && -d "${LIB_DIR}" ]]; then
        cp -r "${LIB_DIR}/"* "${stage_dir}/lib/"
        find "${stage_dir}/lib" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        find "${stage_dir}/lib" -type f -name "*.py[cod]" -delete 2>/dev/null || true
    fi
    if [[ -n "${BIN_DIR:-}" && -f "${BIN_DIR}/opskit-bootstrap" ]]; then
        cp "${BIN_DIR}/opskit-bootstrap" "${stage_dir}/opskit-bootstrap"
    elif [[ -n "${BIN_DIR:-}" && -f "${BIN_DIR}/bin/opskit-bootstrap" ]]; then
        cp "${BIN_DIR}/bin/opskit-bootstrap" "${stage_dir}/opskit-bootstrap"
    fi
    chmod 0755 "${stage_dir}/opskit-bootstrap" 2>/dev/null || true

    rm -rf "${target_lib_dir}.old" 2>/dev/null || true
    if [[ -d "${target_lib_dir}" ]]; then
        mv "${target_lib_dir}" "${target_lib_dir}.old"
    fi
    mv "${stage_dir}/lib" "${target_lib_dir}"
    rm -rf "${target_lib_dir}.old" 2>/dev/null || true

    if [[ -f "${stage_dir}/opskit-bootstrap" ]]; then
        mv "${stage_dir}/opskit-bootstrap" "${target_bin}"
    fi
    rm -rf "${stage_dir}"

    chmod 0755 "${target_bin}"
    chmod 0700 "${target_lib_dir}"
    if [[ "${EUID}" -eq 0 ]]; then
        chown -R root:root "${BOOTSTRAP_STATE_DIR}"
    fi
    log_info "Vendored uninstaller and local ledger to ${BOOTSTRAP_STATE_DIR}."
}

is_mutation_recorded() {
    local id="$1"
    if [[ -f "${LEDGER_FILE}" ]]; then
        grep -qE "\"mutation_id\"[[:space:]]*:[[:space:]]*\"${id}\"" "${LEDGER_FILE}"
    else
        return 1
    fi
}

get_recorded_profile_from_ledger() {
    if [[ ! -f "${LEDGER_FILE}" ]]; then
        return 0
    fi
    python3 -B -c "
import json, sys
prof = None
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            meta = d.get('metadata', {})
            if isinstance(meta, dict):
                p = meta.get('profile')
                if p: prof = p
            mid = d.get('mutation_id')
            if mid in ('edge_socket_units', 'edge_system_unit'):
                prof = 'direct'
            elif mid == 'cloudflared_unit' and prof != 'direct':
                prof = 'tunnel'
        except Exception:
            pass
print(prof or 'private')
" "${LEDGER_FILE}"
}
