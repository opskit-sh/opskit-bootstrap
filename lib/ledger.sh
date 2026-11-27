#!/usr/bin/env bash
# Tamper-evident chained applied mutation ledger (/var/lib/opskit-bootstrap/apply.jsonl) and offline vendoring.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh is loaded

ensure_bootstrap_state_dir() {
    ensure_safe_dir_no_symlink "${BOOTSTRAP_STATE_DIR}"
    mkdir -p "${BOOTSTRAP_STATE_DIR}"
    chmod 0700 "${BOOTSTRAP_STATE_DIR}"
    if [[ "${EUID}" -eq 0 ]]; then
        chown root:root "${BOOTSTRAP_STATE_DIR}"
    fi
}

cleanup_lock_only_state_dir() {
    if [[ -d "${BOOTSTRAP_STATE_DIR}" && ! -L "${BOOTSTRAP_STATE_DIR}" ]]; then
        local entries
        entries="$(ls -A "${BOOTSTRAP_STATE_DIR}" 2>/dev/null || true)"
        if [[ -z "${entries}" ]]; then
            rmdir "${BOOTSTRAP_STATE_DIR}" 2>/dev/null || true
            return 0
        fi
        local only_locks=true entry
        while IFS= read -r entry; do
            [[ -z "${entry}" ]] && continue
            if [[ "${entry}" != ".state.lock" && "${entry}" != ".ledger.lock" ]]; then
                only_locks=false
                break
            fi
        done <<< "${entries}"
        if ${only_locks}; then
            rm -f "${BOOTSTRAP_STATE_DIR}/.state.lock" "${BOOTSTRAP_STATE_DIR}/.ledger.lock"
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
                chmod 0600 "${tmp_key}"
                openssl rand -hex 32 > "${tmp_key}"
                chmod 0600 "${tmp_key}"
                if [[ "${EUID}" -eq 0 ]]; then
                    chown root:root "${tmp_key}"
                fi
                mv -n "${tmp_key}" "${LEDGER_KEY_FILE}" 2>/dev/null || rm -f "${tmp_key}"
            fi
        ) 200>"${BOOTSTRAP_STATE_DIR}/.ledger.lock"
    fi
    chmod 0600 "${LEDGER_KEY_FILE}" 2>/dev/null || true
    if [[ "${EUID}" -eq 0 ]]; then
        chown root:root "${LEDGER_KEY_FILE}" 2>/dev/null || true
    fi
}

compute_entry_hmac() {
    local payload="$1"
    ensure_ledger_key
    ensure_canonicalize_helper
    printf '%s' "${payload}" | python3 -B -c "
import hmac, hashlib, sys
sys.path.insert(0, sys.argv[2])
from canonicalize import loads_strict, canonical_bytes
with open(sys.argv[1], 'rb') as kf:
    key = kf.read().strip()
raw = sys.stdin.read()
d = loads_strict(raw)
canon = canonical_bytes(d, strip_keys={'hmac'})
sys.stdout.write(hmac.new(key, canon, hashlib.sha256).hexdigest())
" "${LEDGER_KEY_FILE}" "${LIB_DIR}"
}

# Atomically rewrite chained apply.jsonl and ledger.head (mode 0600, fsynced).
# Args: <remove_ids_csv> <new_profile_or_empty>
rewrite_chained_ledger() {
    local remove_ids_csv="${1:-}"
    local new_prof="${2:-}"
    if [[ ! -f "${LEDGER_FILE}" ]]; then
        return 0
    fi
    ensure_canonicalize_helper
    ensure_ledger_key
    python3 -B -c '
import hashlib, hmac, json, os, sys, tempfile

ledger_path, head_path, key_path, lib_dir, remove_csv, new_prof = sys.argv[1:7]
sys.path.insert(0, lib_dir)
from canonicalize import loads_strict, canonical_bytes

with open(key_path, "rb") as kf:
    key = kf.read().strip()

remove_ids = {x for x in remove_csv.split(",") if x}
entries = []
with open(ledger_path, "r", encoding="utf-8") as fin:
    for line in fin:
        stripped = line.strip()
        if not stripped:
            continue
        d = loads_strict(stripped)
        if d.get("mutation_id") in remove_ids:
            continue
        if new_prof:
            md = d.get("metadata")
            if not isinstance(md, dict):
                md = {}
                d["metadata"] = md
            md["profile"] = new_prof
        entries.append(d)

def atomic_write_0600(target, content):
    parent = os.path.dirname(target) or "."
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".ledger.")
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        with os.fdopen(fd, "w", encoding="utf-8") as fout:
            fout.write(content)
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    dfd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

if not entries:
    for p in (ledger_path, head_path):
        if os.path.exists(p):
            os.unlink(p)
    sys.exit(0)

prev_hmac = "genesis"
out_lines = []
for idx, d in enumerate(entries, start=1):
    d["seq"] = idx
    d["prev_hmac"] = prev_hmac
    d.pop("hmac", None)
    canon = canonical_bytes(d, strip_keys={"hmac"})
    sig = hmac.new(key, canon, hashlib.sha256).hexdigest()
    d["hmac"] = sig
    prev_hmac = sig
    out_lines.append(json.dumps(d, separators=(",", ":")) + "\n")

head_obj = {"count": len(entries), "head_hmac": prev_hmac}
head_mac = hmac.new(key, canonical_bytes(head_obj), hashlib.sha256).hexdigest()
head_obj["mac"] = head_mac

atomic_write_0600(ledger_path, "".join(out_lines))
atomic_write_0600(head_path, json.dumps(head_obj, separators=(",", ":")) + "\n")
' "${LEDGER_FILE}" "${LEDGER_HEAD_FILE}" "${LEDGER_KEY_FILE}" "${LIB_DIR}" "${remove_ids_csv}" "${new_prof}"
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
    ensure_canonicalize_helper
    ensure_ledger_key

    local ts
    ts="$(timestamp_rfc3339)"

    local status
    status="$(python3 -B -c '
import hashlib, hmac, json, os, sys, tempfile

ledger_path, head_path, key_path, lib_dir = sys.argv[1:5]
ts, mid, cls, before_fp, after_fp, plan_hash, meta_raw = sys.argv[5:12]
sys.path.insert(0, lib_dir)
from canonicalize import loads_strict, canonical_bytes

known = {
    "packages", "service_user", "subuid_allocation", "cgroup_delegation",
    "user_linger", "rootless_docker", "edge_socket_units", "edge_system_unit",
    "firewall_rules", "service_units", "cloudflared_unit", "security_labels", "fetch_cli"
}
if mid not in known:
    print(f"error:unknown mutation_id {mid}")
    sys.exit(0)

try:
    new_meta = loads_strict(meta_raw)
    if not isinstance(new_meta, dict):
        raise ValueError("metadata must be JSON object")
except Exception as e:
    print(f"error:invalid metadata: {e}")
    sys.exit(0)

with open(key_path, "rb") as kf:
    key = kf.read().strip()

entries = []
if os.path.exists(ledger_path):
    with open(ledger_path, "r", encoding="utf-8") as fin:
        for line in fin:
            stripped = line.strip()
            if not stripped:
                continue
            entries.append(loads_strict(stripped))

existing_idx = None
for idx, d in enumerate(entries):
    if d.get("mutation_id") == mid:
        existing_idx = idx
        break

if existing_idx is not None:
    cur = entries[existing_idx]
    if cur.get("metadata") == new_meta and cur.get("after_fingerprint") == after_fp:
        print("unchanged")
        sys.exit(0)
    orig_before = cur.get("before_fingerprint") or before_fp
    entries[existing_idx] = {
        "timestamp": ts,
        "mutation_id": mid,
        "class": cls,
        "before_fingerprint": orig_before,
        "after_fingerprint": after_fp,
        "plan_hash": plan_hash,
        "metadata": new_meta,
    }
else:
    entries.append({
        "timestamp": ts,
        "mutation_id": mid,
        "class": cls,
        "before_fingerprint": before_fp,
        "after_fingerprint": after_fp,
        "plan_hash": plan_hash,
        "metadata": new_meta,
    })

prev_hmac = "genesis"
out_lines = []
for seq_num, d in enumerate(entries, start=1):
    d["seq"] = seq_num
    d["prev_hmac"] = prev_hmac
    d.pop("hmac", None)
    canon = canonical_bytes(d, strip_keys={"hmac"})
    sig = hmac.new(key, canon, hashlib.sha256).hexdigest()
    d["hmac"] = sig
    prev_hmac = sig
    out_lines.append(json.dumps(d, separators=(",", ":")) + "\n")

head_obj = {"count": len(entries), "head_hmac": prev_hmac}
head_obj["mac"] = hmac.new(key, canonical_bytes(head_obj), hashlib.sha256).hexdigest()

def atomic_write_0600(target, content):
    parent = os.path.dirname(target) or "."
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".ledger.")
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        with os.fdopen(fd, "w", encoding="utf-8") as fout:
            fout.write(content)
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    dfd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

atomic_write_0600(ledger_path, "".join(out_lines))
atomic_write_0600(head_path, json.dumps(head_obj, separators=(",", ":")) + "\n")
print("ok")
' "${LEDGER_FILE}" "${LEDGER_HEAD_FILE}" "${LEDGER_KEY_FILE}" "${LIB_DIR}" "${ts}" "${mutation_id}" "${class}" "${before_fp}" "${after_fp}" "${plan_hash}" "${metadata_json}" 2>/dev/null || echo "error:python_failure")"

    case "${status}" in
        ok|unchanged)
            return 0
            ;;
        *)
            die "${EXIT_RUNTIME_ERROR}" "Refusing to record invalid ledger entry for '${mutation_id}' (${status#error:})"
            ;;
    esac
}

verify_ledger_line() {
    local line="$1"
    local line_num="$2"

    if [[ -z "${line}" ]]; then
        echo "Line ${line_num}: empty line in ledger" >&2
        return 1
    fi

    ensure_canonicalize_helper
    if [[ ! -f "${LEDGER_KEY_FILE}" ]]; then
        echo "Line ${line_num} verification failed: missing HMAC key file '${LEDGER_KEY_FILE}'" >&2
        return 1
    fi

    local check_res
    check_res="$(python3 -B -c "
import hmac, hashlib, sys
sys.path.insert(0, sys.argv[3])
from canonicalize import loads_strict, canonical_bytes
try:
    d = loads_strict(sys.argv[2])
    if not isinstance(d, dict):
        print('invalid json: entry must be object'); sys.exit(0)
    known = {'packages', 'service_user', 'subuid_allocation', 'cgroup_delegation', 'user_linger', 'rootless_docker', 'edge_socket_units', 'edge_system_unit', 'firewall_rules', 'service_units', 'cloudflared_unit', 'security_labels', 'fetch_cli'}
    mut_id = d.get('mutation_id')
    if not mut_id:
        print('missing mutation_id'); sys.exit(0)
    if mut_id not in known:
        print(f'unknown mutation_id: {mut_id}'); sys.exit(0)
    for req in ['timestamp', 'class', 'before_fingerprint', 'after_fingerprint', 'plan_hash', 'metadata', 'seq', 'prev_hmac', 'hmac']:
        if req not in d:
            print(f'missing required field: {req}'); sys.exit(0)
    seq = d.get('seq')
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        print('invalid seq'); sys.exit(0)
    if not isinstance(d.get('prev_hmac'), str) or not d.get('prev_hmac'):
        print('invalid prev_hmac'); sys.exit(0)
    with open(sys.argv[1], 'rb') as kf:
        key = kf.read().strip()
    entry_hmac = str(d.get('hmac', ''))
    canon = canonical_bytes(d, strip_keys={'hmac'})
    expected_hmac = hmac.new(key, canon, hashlib.sha256).hexdigest()
    if hmac.compare_digest(entry_hmac, expected_hmac):
        print('ok')
    else:
        print('mismatch')
except Exception as e:
    print(f'invalid json: {e}')
" "${LEDGER_KEY_FILE}" "${line}" "${LIB_DIR}" 2>/dev/null || echo "error")"

    if [[ "${check_res}" != "ok" ]]; then
        echo "Line ${line_num} verification failed: ${check_res}" >&2
        return 1
    fi

    return 0
}

validate_entire_ledger() {
    if [[ ! -f "${LEDGER_FILE}" ]]; then
        if [[ -f "${LEDGER_KEY_FILE}" || -f "${LEDGER_HEAD_FILE}" ]]; then
            echo "Ledger verification failed: ledger file '${LEDGER_FILE}' is missing while key or head anchor exists." >&2
            return 1
        fi
        return 0
    fi

    if [[ ! -f "${LEDGER_KEY_FILE}" ]]; then
        echo "Ledger verification failed: ledger exists at '${LEDGER_FILE}' but HMAC key '${LEDGER_KEY_FILE}' is missing." >&2
        return 1
    fi

    if [[ ! -f "${LEDGER_HEAD_FILE}" ]]; then
        echo "Ledger verification failed: ledger head anchor '${LEDGER_HEAD_FILE}' is missing (possible truncation)." >&2
        return 1
    fi

    ensure_canonicalize_helper

    local chain_res
    chain_res="$(python3 -B -c '
import hashlib, hmac, sys
sys.path.insert(0, sys.argv[4])
from canonicalize import loads_strict, canonical_bytes

ledger_path, head_path, key_path = sys.argv[1:4]
known = {
    "packages", "service_user", "subuid_allocation", "cgroup_delegation",
    "user_linger", "rootless_docker", "edge_socket_units", "edge_system_unit",
    "firewall_rules", "service_units", "cloudflared_unit", "security_labels", "fetch_cli"
}
try:
    with open(key_path, "rb") as kf:
        key = kf.read().strip()
    with open(ledger_path, "r", encoding="utf-8") as lf:
        raw_lines = lf.readlines()
    if not raw_lines:
        print("Ledger verification failed: ledger file is empty (truncated).")
        sys.exit(0)
    expected_prev = "genesis"
    count = 0
    for idx, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.rstrip("\r\n")
        if not line:
            print(f"Line {idx}: empty line in ledger")
            sys.exit(0)
        d = loads_strict(line)
        if not isinstance(d, dict):
            print(f"Line {idx} verification failed: entry is not a JSON object")
            sys.exit(0)
        mut_id = d.get("mutation_id")
        if not mut_id or mut_id not in known:
            print(f"Line {idx} verification failed: invalid or unknown mutation_id {mut_id!r}")
            sys.exit(0)
        for req in ("timestamp", "class", "before_fingerprint", "after_fingerprint", "plan_hash", "metadata", "seq", "prev_hmac", "hmac"):
            if req not in d:
                print(f"Line {idx} verification failed: missing required field {req}")
                sys.exit(0)
        seq = d.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq != idx:
            print(f"Line {idx} verification failed: sequence number mismatch (expected {idx}, got {seq!r})")
            sys.exit(0)
        if d.get("prev_hmac") != expected_prev:
            print(f"Line {idx} verification failed: chain link mismatch (prev_hmac)")
            sys.exit(0)
        entry_hmac = str(d.get("hmac", ""))
        expected_hmac = hmac.new(key, canonical_bytes(d, strip_keys={"hmac"}), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(entry_hmac, expected_hmac):
            print(f"Line {idx} verification failed: HMAC signature mismatch (tampered or corrupt line)")
            sys.exit(0)
        expected_prev = entry_hmac
        count += 1

    with open(head_path, "r", encoding="utf-8") as hf:
        head_obj = loads_strict(hf.read())
    if not isinstance(head_obj, dict):
        print("Ledger verification failed: head anchor is not a JSON object")
        sys.exit(0)
    head_mac = str(head_obj.get("mac", ""))
    expected_head_mac = hmac.new(
        key,
        canonical_bytes({"count": head_obj.get("count"), "head_hmac": head_obj.get("head_hmac")}),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(head_mac, expected_head_mac):
        print("Ledger verification failed: head anchor MAC mismatch")
        sys.exit(0)
    head_count = head_obj.get("count")
    if head_count != count or head_obj.get("head_hmac") != expected_prev:
        print(f"Ledger verification failed: ledger truncated or reordered (head count={head_count}, actual={count})")
        sys.exit(0)
    print("OK")
except Exception as e:
    print(f"Ledger verification failed: {e}")
' "${LEDGER_FILE}" "${LEDGER_HEAD_FILE}" "${LEDGER_KEY_FILE}" "${LIB_DIR}" 2>/dev/null || echo "Ledger verification failed: internal error")"

    if [[ "${chain_res}" != "OK" ]]; then
        echo "${chain_res}" >&2
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

    # Stage to a temp dir and swap atomically
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
