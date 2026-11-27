#!/usr/bin/env bash
# Release manifest verification (opskit.release-manifest/v1) and artifact fetching.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh is loaded

readonly PINNED_RELEASE_PUBKEY_SHA256="6abf0bdbabcbdcad6aaaa1391580b3e452fe50b5d1a61a626642b11bf176417f"
readonly PINNED_RELEASE_KEY_ID="opskit-release-2026"

get_release_pubkey() {
    if [[ -n "${OPSKIT_RELEASE_PUBKEY:-}" ]]; then
        if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" != "1" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "OPSKIT_RELEASE_PUBKEY override is forbidden in production builds."
        fi
        if [[ "${OPSKIT_TEST_MODE:-0}" != "1" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "OPSKIT_RELEASE_PUBKEY override is forbidden in production unless OPSKIT_TEST_MODE=1 is set."
        fi
        echo "${OPSKIT_RELEASE_PUBKEY}"
        return 0
    fi
    local mf_dir pub_path=""
    mf_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${LIB_DIR:-${mf_dir}}/release.pub" ]]; then
        pub_path="${LIB_DIR:-${mf_dir}}/release.pub"
    elif [[ -f "${mf_dir}/../keys/release.pub" ]]; then
        pub_path="${mf_dir}/../keys/release.pub"
    elif [[ -f "${BOOTSTRAP_STATE_DIR}/lib/release.pub" ]]; then
        pub_path="${BOOTSTRAP_STATE_DIR}/lib/release.pub"
    fi
    if [[ -n "${pub_path}" ]]; then
        local actual_pub_sha
        actual_pub_sha="$(compute_sha256 "${pub_path}" 2>/dev/null || true)"
        if [[ "${actual_pub_sha}" != "${PINNED_RELEASE_PUBKEY_SHA256}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Bundled release public key at '${pub_path}' failed pinned digest verification."
        fi
        echo "${pub_path}"
    fi
}

get_expected_key_id() {
    if [[ -n "${OPSKIT_EXPECTED_KEY_ID:-}" ]]; then
        if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" != "1" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "OPSKIT_EXPECTED_KEY_ID override is forbidden in production builds."
        fi
        if [[ "${OPSKIT_TEST_MODE:-0}" != "1" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "OPSKIT_EXPECTED_KEY_ID override is forbidden in production unless OPSKIT_TEST_MODE=1 is set."
        fi
        echo "${OPSKIT_EXPECTED_KEY_ID}"
        return 0
    fi
    echo "${PINNED_RELEASE_KEY_ID}"
}

CLI_MUTATION_METADATA=""
CLI_MUTATION_AFTER_FP=""
CLI_MUTATION_BEFORE_FP=""
_MANIFEST_VERSION=""
_ART_SHA=""
_ART_SIZE=""
_ART_FILENAME=""
_EDGE_ART_PRESENT="false"
_EDGE_ART_SHA=""
_EDGE_ART_SIZE=""
_EDGE_ART_FILENAME=""
_EDGE_INSTALLED_VERSION=""
_EDGE_INSTALLED_PATH=""
_EDGE_CURRENT_LINK=""
_EDGE_INSTALLED_SHA=""

canonicalize_manifest() {
    local src="$1"
    local dst="$2"
    ensure_canonicalize_helper
    python3 -B "${LIB_DIR}/canonicalize.py" --strip signatures "${src}" > "${dst}" || die "${EXIT_VALIDATION_ERROR}" "Failed to canonicalize manifest at '${src}'."
}

# Restrict manifest artifact filenames to safe single-component basenames (no traversal).
validate_safe_artifact_filename() {
    local fname="$1"
    if [[ -z "${fname}" || "${fname}" == *".."* || ! "${fname}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Invalid artifact filename '${fname}' in release manifest."
    fi
}

# Verify manifest schema, Ed25519 signature, and pinned key_id; cleans up temp files on every path.
_verify_manifest_signature() {
    local manifest_path="$1"
    local pubkey_path="$2"
    local cleanup_dir="${3:-}"

    _mf_fail() {
        local code="$1"
        local msg="$2"
        rm -f "${canonical_manifest_tmp:-}" "${sig_tmp:-}" 2>/dev/null || true
        if [[ -n "${cleanup_dir}" ]]; then
            rm -rf "${cleanup_dir}" 2>/dev/null || true
        fi
        die "${code}" "${msg}"
    }

    if [[ ! -f "${manifest_path}" ]]; then
        _mf_fail "${EXIT_VALIDATION_ERROR}" "Release manifest not found at '${manifest_path}'."
    fi
    if [[ -z "${pubkey_path}" || ! -f "${pubkey_path}" ]]; then
        _mf_fail "${EXIT_VALIDATION_ERROR}" "Release public key not found at '${pubkey_path:-<unset>}'."
    fi

    ensure_canonicalize_helper

    local exp_key_id
    exp_key_id="$(get_expected_key_id)"
    if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && -z "${OPSKIT_EXPECTED_KEY_ID:-}" ]]; then
        local local_key_id_file="${pubkey_path%.pub}.key_id"
        if [[ -f "${local_key_id_file}" ]]; then
            exp_key_id="$(tr -d ' \n\r' < "${local_key_id_file}")"
        fi
    fi
    if [[ -z "${exp_key_id}" ]]; then
        _mf_fail "${EXIT_VALIDATION_ERROR}" "Expected release key_id is not configured for manifest verification."
    fi

    local canonical_manifest_tmp sig_tmp
    canonical_manifest_tmp="$(mktemp)"
    sig_tmp="$(mktemp)"

    local extract_status=""
    extract_status="$(python3 -B -c "
import json, sys
sys.path.insert(0, sys.argv[4])
from canonicalize import loads_strict, canonical_bytes

try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        d = loads_strict(f.read())
except Exception as e:
    print(f'PARSE_ERR:{e}')
    sys.exit(0)

if not isinstance(d, dict) or d.get('schema') != 'opskit.release-manifest/v1':
    print('BAD_SCHEMA')
    sys.exit(0)

sigs = d.get('signatures')
if not isinstance(sigs, list):
    print('NO_SIG')
    sys.exit(0)

ed_sigs = [s for s in sigs if isinstance(s, dict) and s.get('algorithm') == 'ed25519']
if not ed_sigs:
    print('NO_SIG')
    sys.exit(0)

exp_kid = sys.argv[2]
non_empty_kids = [s for s in ed_sigs if isinstance(s.get('key_id'), str) and s.get('key_id')]
if not non_empty_kids:
    print('MISSING_KEY_ID')
    sys.exit(0)

matched = [s for s in non_empty_kids if s.get('key_id') == exp_kid]
if not matched:
    print('KEY_ID_MISMATCH:' + str(non_empty_kids[0].get('key_id', '')))
    sys.exit(0)

sig_hex = matched[0].get('signature', '')
if not isinstance(sig_hex, str) or not sig_hex:
    print('NO_SIG')
    sys.exit(0)

try:
    sig_bytes = bytes.fromhex(sig_hex)
except ValueError:
    print('BAD_HEX')
    sys.exit(0)

with open(sys.argv[3], 'wb') as sf:
    sf.write(sig_bytes)
with open(sys.argv[5], 'wb') as cf:
    cf.write(canonical_bytes(d, strip_keys={'signatures'}))
print('OK')
" "${manifest_path}" "${exp_key_id}" "${sig_tmp}" "${LIB_DIR}" "${canonical_manifest_tmp}" 2>/dev/null || echo "PARSE_ERR:unexpected")"

    case "${extract_status}" in
        OK) ;;
        BAD_SCHEMA)
            _mf_fail "${EXIT_VALIDATION_ERROR}" "Release manifest declares unsupported or missing schema (expected 'opskit.release-manifest/v1')."
            ;;
        NO_SIG)
            _mf_fail "${EXIT_VALIDATION_ERROR}" "Manifest does not contain a supported Ed25519 signature."
            ;;
        MISSING_KEY_ID)
            _mf_fail "${EXIT_VALIDATION_ERROR}" "Release manifest Ed25519 signature is missing required key_id."
            ;;
        KEY_ID_MISMATCH:*)
            local got_kid="${extract_status#KEY_ID_MISMATCH:}"
            _mf_fail "${EXIT_VALIDATION_ERROR}" "Release manifest key_id mismatch (expected '${exp_key_id}', got '${got_kid}'). Untrusted manifest."
            ;;
        BAD_HEX)
            _mf_fail "${EXIT_VALIDATION_ERROR}" "Release manifest Ed25519 signature contains invalid hex encoding."
            ;;
        PARSE_ERR:*)
            _mf_fail "${EXIT_VALIDATION_ERROR}" "Failed to parse release manifest at '${manifest_path}'."
            ;;
        *)
            _mf_fail "${EXIT_VALIDATION_ERROR}" "Release manifest signature extraction failed."
            ;;
    esac

    local verify_ok=false
    if openssl pkeyutl -verify -pubin -inkey "${pubkey_path}" -rawin -in "${canonical_manifest_tmp}" -sigfile "${sig_tmp}" >/dev/null 2>&1; then
        verify_ok=true
    fi
    rm -f "${canonical_manifest_tmp}" "${sig_tmp}"
    if ! ${verify_ok}; then
        if [[ -n "${cleanup_dir}" ]]; then
            rm -rf "${cleanup_dir}" 2>/dev/null || true
        fi
        die "${EXIT_VALIDATION_ERROR}" "Release manifest signature verification failed for '${manifest_path}'. Untrusted manifest."
    fi
}

# Parse and validate manifest version and arch-specific artifacts into
# _MANIFEST_VERSION, _ART_*, and _EDGE_ART_*.
_extract_manifest_artifact() {
    local manifest_path="$1"
    local host_arch="$2"
    local cleanup_dir="${3:-}"
    local artifact_key="opskit-linux-${host_arch}"
    local edge_key="opskit-edge-linux-${host_arch}"

    _MANIFEST_VERSION=""
    _ART_SHA=""
    _ART_SIZE=""
    _ART_FILENAME=""
    _EDGE_ART_PRESENT="false"
    _EDGE_ART_SHA=""
    _EDGE_ART_SIZE=""
    _EDGE_ART_FILENAME=""

    local preflight_info
    preflight_info="$(python3 -B -c "
import sys
sys.path.insert(0, sys.argv[4])
from canonicalize import loads_strict
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    d = loads_strict(f.read())
ver = str(d.get('version', '') or '')
arts = d.get('artifacts', {})
k = sys.argv[2]
ek = sys.argv[3]
if not isinstance(arts, dict) or k not in arts or not isinstance(arts[k], dict):
    print('missing')
    sys.exit(0)
art = arts[k]
sha = str(art.get('sha256', '') or '')
sz = art.get('size', '')
fn = str(art.get('filename', k) or k)
if any(c in fn for c in ('|', '\n', '\r')) or any(c in sha for c in ('|', '\n', '\r')) or any(c in ver for c in ('|', '\n', '\r')):
    print('invalid')
    sys.exit(0)
ep = 'false'
esha = ''
esz = ''
efn = ''
if ek in arts:
    if not isinstance(arts[ek], dict):
        print('invalid_edge')
        sys.exit(0)
    ep = 'true'
    eart = arts[ek]
    esha = str(eart.get('sha256', '') or '')
    esz = eart.get('size', '')
    efn = str(eart.get('filename', ek) or ek)
    if any(c in efn for c in ('|', '\n', '\r')) or any(c in esha for c in ('|', '\n', '\r')):
        print('invalid_edge')
        sys.exit(0)
print(f'ok|{ver}|{sha}|{sz}|{fn}|{ep}|{esha}|{esz}|{efn}')
" "${manifest_path}" "${artifact_key}" "${edge_key}" "${LIB_DIR}" 2>/dev/null || echo "missing")"

    if [[ "${preflight_info}" == "missing" || "${preflight_info}" == "invalid_edge" || "${preflight_info}" != ok\|* ]]; then
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        if [[ "${preflight_info}" == "invalid_edge" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Release manifest declares malformed edge artifact entry '${edge_key}'."
        fi
        die "${EXIT_VALIDATION_ERROR}" "Release manifest does not declare artifact for host architecture '${host_arch}'."
    fi

    IFS='|' read -r _ _MANIFEST_VERSION _ART_SHA _ART_SIZE _ART_FILENAME _EDGE_ART_PRESENT _EDGE_ART_SHA _EDGE_ART_SIZE _EDGE_ART_FILENAME <<< "${preflight_info}"
    if [[ -z "${_ART_SHA}" ]]; then
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Release manifest artifact '${artifact_key}' is missing sha256 digest."
    fi
    if [[ ! "${_ART_SIZE}" =~ ^[0-9]+$ || "${_ART_SIZE}" -le 0 ]]; then
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Release manifest artifact '${artifact_key}' declares invalid or non-positive size '${_ART_SIZE}'."
    fi
    if [[ -z "${_ART_FILENAME}" || "${_ART_FILENAME}" == *".."* || ! "${_ART_FILENAME}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Invalid artifact filename '${_ART_FILENAME}' in release manifest."
    fi

    if [[ "${CHOSEN_PROFILE:-}" == "direct" && "${_EDGE_ART_PRESENT}" != "true" ]]; then
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Release manifest does not declare edge artifact '${edge_key}' for host architecture '${host_arch}' required by direct profile."
    fi

    if [[ "${_EDGE_ART_PRESENT}" == "true" ]]; then
        if [[ -z "${_MANIFEST_VERSION}" || "${_MANIFEST_VERSION}" == *".."* || "${_MANIFEST_VERSION}" == "current" || ! "${_MANIFEST_VERSION}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]]; then
            [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
            die "${EXIT_VALIDATION_ERROR}" "Release manifest declares invalid or missing version '${_MANIFEST_VERSION}'."
        fi
        if [[ -z "${_EDGE_ART_SHA}" ]]; then
            [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
            die "${EXIT_VALIDATION_ERROR}" "Release manifest edge artifact '${edge_key}' is missing sha256 digest."
        fi
        if [[ ! "${_EDGE_ART_SIZE}" =~ ^[0-9]+$ || "${_EDGE_ART_SIZE}" -le 0 ]]; then
            [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
            die "${EXIT_VALIDATION_ERROR}" "Release manifest edge artifact '${edge_key}' declares invalid or non-positive size '${_EDGE_ART_SIZE}'."
        fi
        if [[ -z "${_EDGE_ART_FILENAME}" || "${_EDGE_ART_FILENAME}" == *".."* || ! "${_EDGE_ART_FILENAME}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
            [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
            die "${EXIT_VALIDATION_ERROR}" "Invalid edge artifact filename '${_EDGE_ART_FILENAME}' in release manifest."
        fi
    fi
}

verify_and_install_cli() {
    CLI_MUTATION_METADATA=""
    CLI_MUTATION_AFTER_FP=""
    CLI_MUTATION_BEFORE_FP=""
    _EDGE_INSTALLED_VERSION=""
    _EDGE_INSTALLED_PATH=""
    _EDGE_CURRENT_LINK=""
    _EDGE_INSTALLED_SHA=""

    local manifest_source="${OPSKIT_MANIFEST_URL:-}"
    local artifact_source_dir="${OPSKIT_ARTIFACT_SOURCE_DIR:-}"
    local pubkey_path
    pubkey_path="$(get_release_pubkey)"

    if [[ -n "${FLAG_ARTIFACT_DIR:-}" && -d "${FLAG_ARTIFACT_DIR}" ]]; then
        artifact_source_dir="${FLAG_ARTIFACT_DIR}"
    fi

    # 1. Local artifact directory mode
    if [[ -n "${artifact_source_dir}" && -d "${artifact_source_dir}" ]]; then
        local manifest_path="${artifact_source_dir}/release-manifest.json"
        verify_local_manifest_and_install "${manifest_path}" "${pubkey_path}" "${artifact_source_dir}"
        return 0
    fi

    # 2. Remote network mode
    if [[ -n "${manifest_source}" ]]; then
        download_and_verify_manifest "${manifest_source}"
        return 0
    fi

    # 3. Check for local artifacts beside script (derived from defined BIN_DIR/LIB_DIR)
    local local_artifacts=""
    if [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}/artifacts" && -f "${BIN_DIR}/artifacts/release-manifest.json" ]]; then
        local_artifacts="${BIN_DIR}/artifacts"
    elif [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}/../artifacts" && -f "${BIN_DIR}/../artifacts/release-manifest.json" ]]; then
        local_artifacts="${BIN_DIR}/../artifacts"
    elif [[ -n "${LIB_DIR:-}" && -d "${LIB_DIR}/../artifacts" && -f "${LIB_DIR}/../artifacts/release-manifest.json" ]]; then
        local_artifacts="${LIB_DIR}/../artifacts"
    fi
    if [[ -n "${local_artifacts}" ]]; then
        local manifest_path="${local_artifacts}/release-manifest.json"
        verify_local_manifest_and_install "${manifest_path}" "${pubkey_path}" "${local_artifacts}"
        return 0
    fi

    # 4. Neither provided: hard failure with remedy text (an existing on-disk binary is never an artifact source)
    die "${EXIT_NETWORK_ERROR}" "No release manifest source provided. Provide --artifact-dir <path> (or set OPSKIT_ARTIFACT_SOURCE_DIR) for offline installation, or set OPSKIT_MANIFEST_URL to download release artifacts."
}

verify_local_manifest_preflight() {
    local manifest_path="$1"
    local pubkey_path="$2"
    local host_arch="$3"

    _verify_manifest_signature "${manifest_path}" "${pubkey_path}"
    _extract_manifest_artifact "${manifest_path}" "${host_arch}"

    local artifact_key="opskit-linux-${host_arch}"
    local base_dir artifact_path actual_sha actual_size
    base_dir="$(dirname "${manifest_path}")"
    artifact_path="${base_dir}/${_ART_FILENAME}"
    if [[ ! -f "${artifact_path}" ]]; then
        artifact_path="${base_dir}/${artifact_key}"
    fi
    if [[ ! -f "${artifact_path}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Artifact '${_ART_FILENAME}' not found in source directory '${base_dir}'."
    fi
    actual_sha="$(compute_sha256 "${artifact_path}")"
    if [[ "${actual_sha}" != "${_ART_SHA}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Artifact '${_ART_FILENAME}' digest mismatch (expected ${_ART_SHA}, got ${actual_sha}). Tampered binary rejected."
    fi
    actual_size="$(wc -c < "${artifact_path}" | tr -d '[:space:]')"
    if [[ "${actual_size}" -ne "${_ART_SIZE}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Artifact '${_ART_FILENAME}' size mismatch (expected ${_ART_SIZE}, got ${actual_size})."
    fi

    if [[ "${CHOSEN_PROFILE:-}" == "direct" ]] || { [[ "${_EDGE_ART_PRESENT}" == "true" && -n "${CHOSEN_PROFILE:-}" ]]; }; then
        local edge_key="opskit-edge-linux-${host_arch}"
        local edge_path="${base_dir}/${_EDGE_ART_FILENAME}"
        if [[ ! -f "${edge_path}" ]]; then
            edge_path="${base_dir}/${edge_key}"
        fi
        if [[ ! -f "${edge_path}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Edge artifact '${_EDGE_ART_FILENAME}' not found in source directory '${base_dir}'."
        fi
        local edge_actual_sha edge_actual_size
        edge_actual_sha="$(compute_sha256 "${edge_path}")"
        if [[ "${edge_actual_sha}" != "${_EDGE_ART_SHA}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Edge artifact '${_EDGE_ART_FILENAME}' digest mismatch (expected ${_EDGE_ART_SHA}, got ${edge_actual_sha}). Tampered binary rejected."
        fi
        edge_actual_size="$(wc -c < "${edge_path}" | tr -d '[:space:]')"
        if [[ "${edge_actual_size}" -ne "${_EDGE_ART_SIZE}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Edge artifact '${_EDGE_ART_FILENAME}' size mismatch (expected ${_EDGE_ART_SIZE}, got ${edge_actual_size})."
        fi
    fi
}

_cli_originated_from_opskit() {
    local ledger="${LEDGER_FILE:-${BOOTSTRAP_STATE_DIR}/apply.jsonl}"
    if [[ -f "${ledger}" && ! -f "${CLI_INSTALL_PATH}.pre-bootstrap" ]]; then
        if python3 -B -c "
import json, sys
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get('mutation_id') == 'fetch_cli':
            md = d.get('metadata', {})
            if d.get('before_fingerprint') == 'absent' and not (isinstance(md, dict) and md.get('pre_existing', False)):
                sys.exit(0)
sys.exit(1)
" "${ledger}" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Resolve pre-existing / backup state before installing a verified CLI binary.
# Sets _CLI_PRE_EXISTING, _CLI_BACKUP_PATH, _CLI_PREVIOUS_SHA, _CLI_BEFORE_FP.
# Returns 0 if installation should proceed, or 1 if destination already matches expected_sha.
_prepare_cli_install_state() {
    local expected_sha="$1"
    _CLI_PRE_EXISTING=false
    _CLI_BACKUP_PATH=""
    _CLI_PREVIOUS_SHA=""
    _CLI_BEFORE_FP="absent"

    if [[ -f "${CLI_INSTALL_PATH}.pre-bootstrap" ]]; then
        _CLI_PRE_EXISTING=true
        _CLI_BACKUP_PATH="${CLI_INSTALL_PATH}.pre-bootstrap"
        _CLI_PREVIOUS_SHA="$(compute_sha256 "${_CLI_BACKUP_PATH}")"
        _CLI_BEFORE_FP="present:${_CLI_PREVIOUS_SHA}"
    fi

    if [[ -f "${CLI_INSTALL_PATH}" ]]; then
        local current_sha
        current_sha="$(compute_sha256 "${CLI_INSTALL_PATH}")"
        if [[ "${current_sha}" == "${expected_sha}" ]]; then
            log_info "CLI binary at ${CLI_INSTALL_PATH} already matches verified release digest (${expected_sha})."
            local backup_existing=false
            if [[ -f "${CLI_INSTALL_PATH}.pre-bootstrap" ]]; then
                backup_existing=true
                _CLI_BACKUP_PATH="${CLI_INSTALL_PATH}.pre-bootstrap"
                _CLI_BEFORE_FP="present:$(compute_sha256 "${_CLI_BACKUP_PATH}")"
            elif _cli_originated_from_opskit; then
                backup_existing=false
                _CLI_BACKUP_PATH=""
                _CLI_BEFORE_FP="absent"
            else
                _CLI_BEFORE_FP="present:${current_sha}"
            fi
            _CLI_PRE_EXISTING="${backup_existing}"
            _CLI_PREVIOUS_SHA="${current_sha}"
            _CLI_INSTALLED_SHA="${expected_sha}"
            CLI_MUTATION_METADATA="{\"path\":\"$(json_escape "${CLI_INSTALL_PATH}")\",\"installed_sha256\":\"$(json_escape "${expected_sha}")\",\"pre_existing\":${backup_existing},\"backup_path\":\"$(json_escape "${_CLI_BACKUP_PATH}")\",\"previous_sha256\":\"$(json_escape "${current_sha}")\"}"
            CLI_MUTATION_AFTER_FP="present:digest-verified"
            CLI_MUTATION_BEFORE_FP="${_CLI_BEFORE_FP}"
            return 1
        fi
        if _cli_originated_from_opskit; then
            _CLI_PRE_EXISTING=false
            _CLI_BACKUP_PATH=""
            _CLI_PREVIOUS_SHA="${current_sha}"
            _CLI_BEFORE_FP="absent"
        else
            _CLI_PRE_EXISTING=true
            _CLI_BACKUP_PATH="${CLI_INSTALL_PATH}.pre-bootstrap"
            if [[ ! -f "${_CLI_BACKUP_PATH}" ]]; then
                cp -a "${CLI_INSTALL_PATH}" "${_CLI_BACKUP_PATH}"
                log_info "Backed up pre-existing CLI binary to ${_CLI_BACKUP_PATH}."
                _CLI_PREVIOUS_SHA="${current_sha}"
            else
                log_info "Preserved original pre-bootstrap backup at ${_CLI_BACKUP_PATH}."
                _CLI_PREVIOUS_SHA="$(compute_sha256 "${_CLI_BACKUP_PATH}")"
            fi
            _CLI_BEFORE_FP="present:${_CLI_PREVIOUS_SHA}"
        fi
    fi
    return 0
}

# Copy candidate binary into a root-owned 0600 staging file in destination directory FIRST,
# then verify SHA-256 and byte size on that private copy before chmod 0755 and atomic mv
# (eliminates source-directory TOCTOU races).
_verify_staged_and_install_cli() {
    local src_path="$1"
    local expected_sha="$2"
    local expected_size="$3"
    local label_name="$4"
    local cleanup_dir="${5:-}"
    local keep_dir_on_success="${6:-false}"

    local install_dir
    install_dir="$(dirname "${CLI_INSTALL_PATH}")"
    mkdir -p "${install_dir}"
    if [[ -L "${CLI_INSTALL_PATH}" ]]; then
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Refusing to install CLI over symbolic link '${CLI_INSTALL_PATH}'."
    fi

    local tmp_install
    tmp_install="$(mktemp "${CLI_INSTALL_PATH}.tmp.XXXXXX")"
    chmod 0600 "${tmp_install}"
    if [[ "${EUID}" -eq 0 ]]; then
        chown root:root "${tmp_install}"
    fi

    if ! cp "${src_path}" "${tmp_install}"; then
        rm -f "${tmp_install}"
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_RUNTIME_ERROR}" "Failed to stage verified CLI binary to '${tmp_install}'."
    fi

    local actual_sha actual_size
    actual_sha="$(compute_sha256 "${tmp_install}")"
    if [[ "${actual_sha}" != "${expected_sha}" ]]; then
        rm -f "${tmp_install}"
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Artifact '${label_name}' digest mismatch (expected ${expected_sha}, got ${actual_sha}). Tampered binary rejected."
    fi
    actual_size="$(wc -c < "${tmp_install}" | tr -d '[:space:]')"
    if [[ "${actual_size}" -ne "${expected_size}" ]]; then
        rm -f "${tmp_install}"
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Artifact '${label_name}' size mismatch (expected ${expected_size}, got ${actual_size})."
    fi

    _CLI_INSTALLED_SHA="${actual_sha}"
    if ! _prepare_cli_install_state "${expected_sha}"; then
        rm -f "${tmp_install}"
        if [[ "${keep_dir_on_success}" != "true" && -n "${cleanup_dir}" ]]; then
            rm -rf "${cleanup_dir}" 2>/dev/null || true
        fi
        return 0
    fi
    CLI_MUTATION_BEFORE_FP="${_CLI_BEFORE_FP}"

    log_info "Artifact digest verified (${actual_sha}). Installing to ${CLI_INSTALL_PATH}..."
    chmod 0755 "${tmp_install}"
    if [[ "${EUID}" -eq 0 ]]; then
        chown root:root "${tmp_install}"
    fi
    mv -f "${tmp_install}" "${CLI_INSTALL_PATH}"
    if [[ "${keep_dir_on_success}" != "true" && -n "${cleanup_dir}" ]]; then
        rm -rf "${cleanup_dir}" 2>/dev/null || true
    fi

    CLI_MUTATION_METADATA="{\"path\":\"$(json_escape "${CLI_INSTALL_PATH}")\",\"installed_sha256\":\"$(json_escape "${actual_sha}")\",\"pre_existing\":${_CLI_PRE_EXISTING},\"backup_path\":\"$(json_escape "${_CLI_BACKUP_PATH}")\",\"previous_sha256\":\"$(json_escape "${_CLI_PREVIOUS_SHA}")\"}"
    CLI_MUTATION_AFTER_FP="installed:${CLI_INSTALL_PATH}"
    log_info "Installed static CLI to ${CLI_INSTALL_PATH} (mode 0755)."
}

# Stage edge binary into a root-owned 0600 file first, verify SHA-256 and byte length,
# then write into SERVICE_USER-owned versions/<version>/opskit-edge and atomically swap
# the versions/current symlink as SERVICE_USER (never following symlinks as root).
_verify_staged_and_install_edge() {
    local src_path="$1"
    local expected_sha="$2"
    local expected_size="$3"
    local label_name="$4"
    local cleanup_dir="${5:-}"

    local tmp_stage
    tmp_stage="$(mktemp)"
    chmod 0600 "${tmp_stage}"
    if [[ "${EUID}" -eq 0 ]]; then
        chown root:root "${tmp_stage}"
    fi

    if ! cp "${src_path}" "${tmp_stage}"; then
        rm -f "${tmp_stage}"
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_RUNTIME_ERROR}" "Failed to stage verified edge binary to '${tmp_stage}'."
    fi

    local actual_sha actual_size
    actual_sha="$(compute_sha256 "${tmp_stage}")"
    if [[ "${actual_sha}" != "${expected_sha}" ]]; then
        rm -f "${tmp_stage}"
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Edge artifact '${label_name}' digest mismatch (expected ${expected_sha}, got ${actual_sha}). Tampered binary rejected."
    fi
    actual_size="$(wc -c < "${tmp_stage}" | tr -d '[:space:]')"
    if [[ "${actual_size}" -ne "${expected_size}" ]]; then
        rm -f "${tmp_stage}"
        [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
        die "${EXIT_VALIDATION_ERROR}" "Edge artifact '${label_name}' size mismatch (expected ${expected_size}, got ${actual_size})."
    fi

    ensure_safe_dir_no_symlink "${SERVICE_STATE_DIR}"
    if [[ ! -d "${SERVICE_STATE_DIR}" ]]; then
        mkdir -p "${SERVICE_STATE_DIR}"
        chmod 0750 "${SERVICE_STATE_DIR}"
        if [[ "${EUID}" -eq 0 ]] && id "${SERVICE_USER}" >/dev/null 2>&1; then
            chown "${SERVICE_USER}:${SERVICE_GROUP}" "${SERVICE_STATE_DIR}"
        fi
    fi

    local versions_dir="${SERVICE_STATE_DIR}/versions"
    local ver_dir="${versions_dir}/${_MANIFEST_VERSION}"
    local ver_bin="${ver_dir}/opskit-edge"
    local current_link="${versions_dir}/current"

    local already_ok=false
    if [[ -L "${current_link}" && "$(readlink "${current_link}" 2>/dev/null || true)" == "${_MANIFEST_VERSION}" && -f "${ver_bin}" && -x "${ver_bin}" ]]; then
        local existing_sha
        existing_sha="$(compute_sha256 "${ver_bin}" 2>/dev/null || true)"
        if [[ "${existing_sha}" == "${actual_sha}" ]]; then
            already_ok=true
        fi
    fi

    if ! ${already_ok}; then
        if ! run_as_service_user '
            set -eu
            versions_dir="$1"
            version="$2"
            ver_dir="${versions_dir}/${version}"
            mkdir -p "${versions_dir}" "${ver_dir}"
            chmod 0750 "${versions_dir}" "${ver_dir}"
            umask 077
            tmp_bin="$(mktemp "${ver_dir}/.opskit-edge.XXXXXX")"
            cat > "${tmp_bin}"
            chmod 0755 "${tmp_bin}"
            mv -f "${tmp_bin}" "${ver_dir}/opskit-edge"
            if [ -d "${versions_dir}/current" ] && [ ! -L "${versions_dir}/current" ]; then
                rmdir "${versions_dir}/current"
            fi
            tmp_link="${versions_dir}/.current.tmp.$$"
            rm -f "${tmp_link}"
            ln -s -- "${version}" "${tmp_link}"
            mv -Tf "${tmp_link}" "${versions_dir}/current"
        ' "${versions_dir}" "${_MANIFEST_VERSION}" < "${tmp_stage}"; then
            rm -f "${tmp_stage}"
            [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true
            die "${EXIT_RUNTIME_ERROR}" "Failed to install versioned opskit-edge binary into '${ver_bin}'."
        fi
        log_info "Edge artifact digest verified (${actual_sha}). Installed to ${ver_bin} (symlink ${current_link} -> ${_MANIFEST_VERSION})."
    else
        log_info "Edge binary at ${current_link}/opskit-edge already matches verified release digest (${actual_sha})."
    fi

    rm -f "${tmp_stage}"
    [[ -n "${cleanup_dir}" ]] && rm -rf "${cleanup_dir}" 2>/dev/null || true

    _EDGE_INSTALLED_VERSION="${_MANIFEST_VERSION}"
    _EDGE_INSTALLED_PATH="${ver_bin}"
    _EDGE_CURRENT_LINK="${current_link}"
    _EDGE_INSTALLED_SHA="${actual_sha}"
}

_finalize_fetch_cli_metadata() {
    local edge_fields=""
    if [[ -n "${_EDGE_INSTALLED_SHA:-}" ]]; then
        edge_fields=",\"edge_version\":\"$(json_escape "${_EDGE_INSTALLED_VERSION}")\",\"edge_path\":\"$(json_escape "${_EDGE_INSTALLED_PATH}")\",\"edge_current_link\":\"$(json_escape "${_EDGE_CURRENT_LINK}")\",\"edge_sha256\":\"$(json_escape "${_EDGE_INSTALLED_SHA}")\""
    fi
    CLI_MUTATION_METADATA="{\"path\":\"$(json_escape "${CLI_INSTALL_PATH}")\",\"installed_sha256\":\"$(json_escape "${_CLI_INSTALLED_SHA}")\",\"pre_existing\":${_CLI_PRE_EXISTING},\"backup_path\":\"$(json_escape "${_CLI_BACKUP_PATH}")\",\"previous_sha256\":\"$(json_escape "${_CLI_PREVIOUS_SHA}")\"${edge_fields}}"
}

verify_local_manifest_and_install() {
    local manifest_path="$1"
    local pubkey_path="$2"
    local base_dir="$3"

    log_info "Verifying release manifest '${manifest_path}'..."
    _verify_manifest_signature "${manifest_path}" "${pubkey_path}"
    log_info "Release manifest signature verified successfully."

    local host_arch
    host_arch="$(uname -m)"
    _extract_manifest_artifact "${manifest_path}" "${host_arch}"

    local artifact_key="opskit-linux-${host_arch}"
    local artifact_path="${base_dir}/${_ART_FILENAME}"
    if [[ ! -f "${artifact_path}" ]]; then
        artifact_path="${base_dir}/${artifact_key}"
    fi
    if [[ ! -f "${artifact_path}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Artifact '${_ART_FILENAME}' not found in source directory."
    fi

    _verify_staged_and_install_cli "${artifact_path}" "${_ART_SHA}" "${_ART_SIZE}" "${_ART_FILENAME}"

    if [[ "${CHOSEN_PROFILE:-}" == "direct" ]] || { [[ "${_EDGE_ART_PRESENT}" == "true" && -n "${CHOSEN_PROFILE:-}" ]] && id "${SERVICE_USER}" >/dev/null 2>&1; }; then
        local edge_key="opskit-edge-linux-${host_arch}"
        local edge_path="${base_dir}/${_EDGE_ART_FILENAME}"
        if [[ ! -f "${edge_path}" ]]; then
            edge_path="${base_dir}/${edge_key}"
        fi
        if [[ ! -f "${edge_path}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Edge artifact '${_EDGE_ART_FILENAME}' not found in source directory."
        fi
        _verify_staged_and_install_edge "${edge_path}" "${_EDGE_ART_SHA}" "${_EDGE_ART_SIZE}" "${_EDGE_ART_FILENAME}"
        _finalize_fetch_cli_metadata
    fi
}

download_and_verify_manifest() {
    local url="$1"
    validate_remote_url "${url}" "manifest URL"

    log_info "Fetching release manifest from ${url}..."
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    chmod 0700 "${tmp_dir}"

    set_curl_proto_flags "${url}"
    local curl_flags=(-s -S --fail --max-time 30 "${CURL_PROTO_FLAGS[@]}" --max-filesize 1048576)
    [[ -n "${FLAG_PROXY:-}" ]] && curl_flags+=(--proxy "${FLAG_PROXY}")
    [[ -n "${FLAG_CACERT:-}" ]] && curl_flags+=(--cacert "${FLAG_CACERT}")

    curl "${curl_flags[@]}" -o "${tmp_dir}/release-manifest.json" "${url}" || {
        rm -rf "${tmp_dir}"
        die "${EXIT_NETWORK_ERROR}" "Failed to download release manifest from ${url}. Check network connectivity, proxy settings, or custom CA bundle."
    }

    local pubkey_file
    pubkey_file="$(get_release_pubkey)"
    if [[ -z "${pubkey_file}" || ! -f "${pubkey_file}" ]]; then
        rm -rf "${tmp_dir}"
        die "${EXIT_VALIDATION_ERROR}" "No trusted release public key available for manifest verification."
    fi

    _verify_manifest_signature "${tmp_dir}/release-manifest.json" "${pubkey_file}" "${tmp_dir}"
    log_info "Remote release manifest signature verified successfully."

    local host_arch
    host_arch="$(uname -m)"
    _extract_manifest_artifact "${tmp_dir}/release-manifest.json" "${host_arch}" "${tmp_dir}"

    local install_edge=false
    if [[ "${CHOSEN_PROFILE:-}" == "direct" ]] || { [[ "${_EDGE_ART_PRESENT}" == "true" && -n "${CHOSEN_PROFILE:-}" ]] && id "${SERVICE_USER}" >/dev/null 2>&1; }; then
        install_edge=true
    fi

    local base_url artifact_url
    base_url="$(dirname "${url}")"
    artifact_url="${base_url}/${_ART_FILENAME}"
    validate_remote_url "${artifact_url}" "artifact URL"

    log_info "Downloading release payload from ${artifact_url}..."
    set_curl_proto_flags "${artifact_url}"
    local payload_curl_flags=(-s -S --fail --max-time 120 "${CURL_PROTO_FLAGS[@]}" --max-filesize 268435456)
    [[ -n "${FLAG_PROXY:-}" ]] && payload_curl_flags+=(--proxy "${FLAG_PROXY}")
    [[ -n "${FLAG_CACERT:-}" ]] && payload_curl_flags+=(--cacert "${FLAG_CACERT}")

    # Always write payload to a fixed path inside tmp_dir regardless of manifest filename.
    curl "${payload_curl_flags[@]}" -o "${tmp_dir}/payload.bin" "${artifact_url}" || {
        rm -rf "${tmp_dir}"
        die "${EXIT_NETWORK_ERROR}" "Failed to download release payload from ${artifact_url}. Check network connectivity, proxy settings, or custom CA bundle."
    }

    local keep_tmp="false"
    ${install_edge} && keep_tmp="true"
    _verify_staged_and_install_cli "${tmp_dir}/payload.bin" "${_ART_SHA}" "${_ART_SIZE}" "${_ART_FILENAME}" "${tmp_dir}" "${keep_tmp}"

    if ${install_edge}; then
        local edge_url="${base_url}/${_EDGE_ART_FILENAME}"
        validate_remote_url "${edge_url}" "edge artifact URL"
        log_info "Downloading edge release payload from ${edge_url}..."
        set_curl_proto_flags "${edge_url}"
        local edge_curl_flags=(-s -S --fail --max-time 120 "${CURL_PROTO_FLAGS[@]}" --max-filesize 268435456)
        [[ -n "${FLAG_PROXY:-}" ]] && edge_curl_flags+=(--proxy "${FLAG_PROXY}")
        [[ -n "${FLAG_CACERT:-}" ]] && edge_curl_flags+=(--cacert "${FLAG_CACERT}")

        curl "${edge_curl_flags[@]}" -o "${tmp_dir}/edge-payload.bin" "${edge_url}" || {
            rm -rf "${tmp_dir}"
            die "${EXIT_NETWORK_ERROR}" "Failed to download edge release payload from ${edge_url}. Check network connectivity, proxy settings, or custom CA bundle."
        }
        _verify_staged_and_install_edge "${tmp_dir}/edge-payload.bin" "${_EDGE_ART_SHA}" "${_EDGE_ART_SIZE}" "${_EDGE_ART_FILENAME}" "${tmp_dir}"
        _finalize_fetch_cli_metadata
    fi
}
