#!/usr/bin/env bash
# Shared constants, logging, and error handling routines for opskit-bootstrap.
set -euo pipefail

# Standard exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_GENERAL_ERROR=1
readonly EXIT_USAGE_ERROR=2
readonly EXIT_NOT_FOUND=3
readonly EXIT_CONFLICT=4
readonly EXIT_SAFETY_GUARD=5
readonly EXIT_RUNTIME_ERROR=6
readonly EXIT_HEALTH_FAILED=7
readonly EXIT_VALIDATION_ERROR=8
readonly EXIT_NETWORK_ERROR=9
readonly EXIT_AUTH_REQUIRED=10

# Default filesystem paths
if [[ -z "${LIB_DIR:-}" ]]; then
    LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
BOOTSTRAP_STATE_DIR="${OPSKIT_BOOTSTRAP_STATE_DIR:-/var/lib/opskit-bootstrap}"
LEDGER_FILE="${BOOTSTRAP_STATE_DIR}/apply.jsonl"
LEDGER_KEY_FILE="${BOOTSTRAP_STATE_DIR}/ledger.key"
SERVICE_USER="opskit"
SERVICE_GROUP="opskit"
SERVICE_STATE_DIR="${OPSKIT_SERVICE_STATE_DIR:-/var/lib/opskit}"
CLI_INSTALL_PATH="${OPSKIT_CLI_INSTALL_PATH:-/usr/local/bin/opskit}"
SYSTEMD_SYSTEM_DIR="${OPSKIT_SYSTEMD_SYSTEM_DIR:-/etc/systemd/system}"

ensure_canonicalize_helper() {
    if [[ ! -f "${LIB_DIR}/canonicalize.py" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Required canonicalization helper not found at '${LIB_DIR}/canonicalize.py'."
    fi
}

# Validate test hooks against OPSKIT_TEST_MODE
validate_test_hooks() {
    local mock_vars=(
        "MOCK_KERNEL_RELEASE"
        "MOCK_DISK_FREE_GB"
        "MOCK_NODE_FINGERPRINT"
        "MOCK_EXPIRES_AT"
        "MOCK_CLOCK_SKEW"
        "OPSKIT_SKIP_DISK_CHECK"
        "OPSKIT_OS_RELEASE_FILE"
        "OPSKIT_SUBUID_START"
        "OPSKIT_SUBUID_COUNT"
        "OPSKIT_FORCE_CGROUPS_V2"
        "OPSKIT_FORCE_SYSTEMD"
        "MOCK_HAS_V6_ROUTE"
        "OPSKIT_RELEASE_PUBKEY"
        "OPSKIT_EXPECTED_KEY_ID"
        "MOCK_SELINUX_STATUS"
        "MOCK_RUNTIME_VERSION"
        "MOCK_CGROUP_CONTROLLERS"
        "MOCK_APPARMOR_STATUS"
        "OPSKIT_TEST_FORCE_PACKAGES"
    )
    if [[ "${OPSKIT_TEST_MODE:-0}" != "1" ]]; then
        for var in "${mock_vars[@]}"; do
            if [[ -n "${!var:-}" ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Test hook environment variable '${var}' is forbidden in production unless OPSKIT_TEST_MODE=1 is set."
            fi
        done
    fi
}

# Logging helpers
log_info() {
    echo "opskit-bootstrap: $*" >&2
}

log_warn() {
    echo "opskit-bootstrap: warning: $*" >&2
}

log_error() {
    echo "opskit-bootstrap: error: $*" >&2
}

die() {
    local code="$1"
    shift
    log_error "$*"
    exit "${code}"
}

# Privilege assertion
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "${EXIT_SAFETY_GUARD}" "root privileges required to execute bootstrap (run with sudo)"
    fi
}

# Escape strings for valid JSON insertion
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    printf '%s' "${str}"
}

# Compute SHA-256 digest of a string or file
compute_sha256() {
    if [[ -f "$1" ]]; then
        [[ -r "$1" ]] || return 1
        sha256sum "$1" | awk '{print $1}'
    else
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    fi
}

# RFC 3339 UTC timestamp
timestamp_rfc3339() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Compare an on-disk file against a generator command's stdout using SHA-256
# so minimal environments without diffutils/cmp remain supported.
file_matches_expected() {
    local path="$1"
    shift
    [[ -f "${path}" && -r "${path}" ]] || return 1
    local file_sha expected_sha
    file_sha="$(compute_sha256 "${path}")" || return 1
    expected_sha="$("$@" | sha256sum | awk '{print $1}')"
    [[ "${file_sha}" == "${expected_sha}" ]]
}

# Collect OpsKit-tagged firewall rules that survived attempted removal across stacks
# (including inactive ufw staged rules and permanent/offline firewalld rules when applicable).
collect_tagged_firewall_survivors() {
    local include_nft_collision=false
    local exclude_stack=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --include-nft-collision)
                include_nft_collision=true
                shift
                ;;
            --exclude-stack)
                exclude_stack="${2:-}"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done

    local survivors=()
    _add_fw_survivor() {
        local item="$1"
        local existing
        for existing in "${survivors[@]+"${survivors[@]}"}"; do
            if [[ "${existing}" == "${item}" ]]; then
                return 0
            fi
        done
        survivors+=("${item}")
    }

    local parsed_meta="" meta_parse_rc=0
    parsed_meta="$(python3 -B -c "
import json, sys
ports = {('443', 'tcp'), ('80', 'tcp')}
pre_existing = set()
fw_zones = []
has_recorded_stack = False
has_firewalld_stack = False
for raw in sys.argv[1:]:
    if not raw or raw == '{}':
        continue
    d = json.loads(raw)
    if not isinstance(d, dict):
        raise ValueError('firewall metadata must be a JSON object')
    candidates = [d.get('rule443'), d.get('rule80')] if ('rule443' in d or 'rule80' in d) else [d]
    for r in candidates:
        if not isinstance(r, dict) or not r:
            continue
        stack = str(r.get('stack', '') or '')
        pre = bool(r.get('pre_existing', False))
        port = int(r.get('port', 0) or 0)
        proto = str(r.get('proto', 'tcp') or 'tcp')
        zone = str(r.get('zone', '') or '')
        if stack:
            has_recorded_stack = True
            if stack == 'firewalld':
                has_firewalld_stack = True
        if port > 0:
            ports.add((str(port), proto))
            if stack and pre:
                pre_existing.add(f'{stack}:{port}:{proto}')
            if stack == 'firewalld' and zone and zone not in fw_zones:
                fw_zones.append(zone)
print('CHECK_FIREWALLD:' + ('true' if (not has_recorded_stack or has_firewalld_stack) else 'false'))
for p, pr in sorted(ports):
    print(f'PORT:{p}:{pr}')
for item in sorted(pre_existing):
    print(f'PRE:{item}')
for z in fw_zones:
    print(f'ZONE:{z}')
" "$@" 2>/dev/null)" || meta_parse_rc=$?

    if [[ ${meta_parse_rc} -ne 0 ]]; then
        log_warn "Failed to parse recorded firewall metadata during survivor check; falling back to canonical ports 443/tcp and 80/tcp."
        parsed_meta=$'CHECK_FIREWALLD:true\nPORT:443:tcp\nPORT:80:tcp'
    fi

    local target_ports=() pre_existing_keys=() recorded_fw_zones=()
    local check_firewalld=true
    while IFS= read -r mline; do
        [[ -z "${mline}" ]] && continue
        case "${mline}" in
            CHECK_FIREWALLD:false)
                check_firewalld=false
                ;;
            CHECK_FIREWALLD:true)
                check_firewalld=true
                ;;
            PORT:*)
                target_ports+=("${mline#PORT:}")
                ;;
            PRE:*)
                pre_existing_keys+=("${mline#PRE:}")
                ;;
            ZONE:*)
                recorded_fw_zones+=("${mline#ZONE:}")
                ;;
        esac
    done <<< "${parsed_meta}"
    if [[ ${#target_ports[@]} -eq 0 ]]; then
        target_ports=("443:tcp" "80:tcp")
    fi

    _is_fw_preexisting() {
        local needle="$1"
        local item
        for item in "${pre_existing_keys[@]+"${pre_existing_keys[@]}"}"; do
            [[ "${item}" == "${needle}" ]] && return 0
        done
        return 1
    }

    # Check nftables tagged rules (and colliding opskit-* tags when requested)
    if [[ "${exclude_stack}" != "nftables" ]] && command -v nft >/dev/null 2>&1; then
        local nft_chain_out=""
        nft_chain_out="$(nft list chain inet opskit input 2>/dev/null || true)"
        if [[ -n "${nft_chain_out}" ]]; then
            local tp_entry c_port c_proto
            for tp_entry in "${target_ports[@]}"; do
                IFS=: read -r c_port c_proto <<< "${tp_entry}"
                if grep -F "comment \"opskit-${c_port}\"" >/dev/null 2>&1 <<< "${nft_chain_out}"; then
                    _add_fw_survivor "${c_port}/${c_proto}"
                fi
            done
            if ${include_nft_collision} && grep 'comment "opskit-' >/dev/null 2>&1 <<< "${nft_chain_out}"; then
                _add_fw_survivor "nftables:inet:opskit"
            fi
        fi
    fi

    # Check iptables tagged rules
    if [[ "${exclude_stack}" != "iptables" ]] && command -v iptables >/dev/null 2>&1; then
        local tp_entry c_port c_proto
        for tp_entry in "${target_ports[@]}"; do
            IFS=: read -r c_port c_proto <<< "${tp_entry}"
            if iptables -C INPUT -p "${c_proto}" --dport "${c_port}" -m comment --comment "opskit-${c_port}" -j ACCEPT >/dev/null 2>&1; then
                _add_fw_survivor "${c_port}/${c_proto}"
            fi
        done
    fi

    # Check ufw staged/active tagged rules unconditionally (rules carry explicit opskit-<port> tags)
    if [[ "${exclude_stack}" != "ufw" ]]; then
        local ufw_status_out="" ufw_added_out=""
        if command -v ufw >/dev/null 2>&1; then
            ufw_status_out="$(ufw status 2>/dev/null || true)"
            ufw_added_out="$(ufw show added 2>/dev/null || true)"
        fi
        local tp_entry c_port c_proto
        for tp_entry in "${target_ports[@]}"; do
            IFS=: read -r c_port c_proto <<< "${tp_entry}"
            if _is_fw_preexisting "ufw:${c_port}:${c_proto}"; then
                continue
            fi
            local hex_tag=""
            hex_tag="$(python3 -B -c "import sys; print(sys.argv[1].encode().hex())" "opskit-${c_port}" 2>/dev/null || true)"
            if [[ -n "${hex_tag}" ]] && grep -qE "(^|[[:space:]])comment=${hex_tag}(20[0-9a-fA-F]*)?([[:space:]]|$)" /etc/ufw/user.rules /etc/ufw/user6.rules 2>/dev/null; then
                _add_fw_survivor "ufw:${c_port}/${c_proto}"
            elif command -v ufw >/dev/null 2>&1; then
                if grep -E "^(${c_port}/${c_proto}|${c_port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW.*#[[:space:]]*opskit-${c_port}([[:space:]]|$)" >/dev/null 2>&1 <<< "${ufw_status_out}" \
                   || grep -E "^ufw allow (${c_port}/${c_proto}|${c_port})([[:space:]]|$).*(comment 'opskit-${c_port}([[:space:]][^']*)?'|comment \"opskit-${c_port}([[:space:]][^\"]*)?\"|comment opskit-${c_port})([[:space:]]|$)" >/dev/null 2>&1 <<< "${ufw_added_out}"; then
                    _add_fw_survivor "ufw:${c_port}/${c_proto}"
                fi
            fi
        done
    fi

    # Check firewalld only when metadata names stack=firewalld or no valid rule-stack metadata exists;
    # untagged firewalld ports must not be flagged when another stack owns the node.
    if [[ "${exclude_stack}" != "firewalld" ]] && ${check_firewalld}; then
        local fw_target_zones=("${recorded_fw_zones[@]+"${recorded_fw_zones[@]}"}")
        if [[ ${#fw_target_zones[@]} -eq 0 ]]; then
            local default_zone=""
            if [[ -f /etc/firewalld/firewalld.conf ]]; then
                default_zone="$(awk -F= '/^[[:space:]]*DefaultZone[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/firewalld/firewalld.conf 2>/dev/null || true)"
            fi
            [[ -z "${default_zone}" ]] && default_zone="public"
            fw_target_zones=("${default_zone}")
        fi

        local tp_entry c_port c_proto
        for tp_entry in "${target_ports[@]}"; do
            IFS=: read -r c_port c_proto <<< "${tp_entry}"
            if _is_fw_preexisting "firewalld:${c_port}:${c_proto}"; then
                continue
            fi
            local fw_found=false z
            if command -v firewall-cmd >/dev/null 2>&1; then
                for z in "${fw_target_zones[@]}"; do
                    if firewall-cmd --zone="${z}" --query-port="${c_port}/${c_proto}" >/dev/null 2>&1 \
                       || firewall-cmd --permanent --zone="${z}" --query-port="${c_port}/${c_proto}" >/dev/null 2>&1; then
                        fw_found=true
                        break
                    fi
                done
                if ! ${fw_found} && command -v firewall-offline-cmd >/dev/null 2>&1 && ! systemctl is-active --quiet firewalld 2>/dev/null; then
                    for z in "${fw_target_zones[@]}"; do
                        if firewall-offline-cmd --zone="${z}" --query-port="${c_port}/${c_proto}" >/dev/null 2>&1; then
                            fw_found=true
                            break
                        fi
                    done
                fi
            elif command -v firewall-offline-cmd >/dev/null 2>&1; then
                for z in "${fw_target_zones[@]}"; do
                    if firewall-offline-cmd --zone="${z}" --query-port="${c_port}/${c_proto}" >/dev/null 2>&1; then
                        fw_found=true
                        break
                    fi
                done
            fi
            if ! ${fw_found}; then
                local zone_xml_paths=()
                for z in "${fw_target_zones[@]}"; do
                    [[ -f "/etc/firewalld/zones/${z}.xml" ]] && zone_xml_paths+=("/etc/firewalld/zones/${z}.xml")
                done
                if [[ ${#zone_xml_paths[@]} -gt 0 ]] && python3 -B -c "
import re, sys, xml.etree.ElementTree as ET
target_port, target_proto = sys.argv[1], sys.argv[2]
for path in sys.argv[3:]:
    try:
        root = ET.parse(path).getroot()
        for elem in root.findall('port'):
            if elem.attrib.get('port') == target_port and elem.attrib.get('protocol') == target_proto:
                sys.exit(0)
    except ET.ParseError:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                cleaned = re.sub(r'<!--.*?(?:-->|$)', '', f.read(), flags=re.DOTALL)
                for m in re.finditer(r'<port\b([^>]*)>', cleaned):
                    attrs = m.group(1)
                    if re.search(rf'\bport=[\"\']{re.escape(target_port)}[\"\']', attrs) and re.search(rf'\bprotocol=[\"\']{re.escape(target_proto)}[\"\']', attrs):
                        sys.exit(0)
        except Exception:
            pass
    except Exception:
        pass
sys.exit(1)
" "${c_port}" "${c_proto}" "${zone_xml_paths[@]}" 2>/dev/null; then
                    fw_found=true
                fi
            fi
            if ${fw_found}; then
                _add_fw_survivor "firewalld:${c_port}/${c_proto}"
            fi
        done
    fi

    local s
    for s in "${survivors[@]+"${survivors[@]}"}"; do
        echo "${s}"
    done
}
