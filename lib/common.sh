#!/usr/bin/env bash
# Shared constants, security helpers, logging, and error handling for opskit-bootstrap.
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

# Build-time switch: scripts/build-release.sh stamps this to 0 in production bundles.
readonly OPSKIT_TEST_HOOKS_COMPILED=1

# Default filesystem paths
if [[ -z "${LIB_DIR:-}" ]]; then
    LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
BOOTSTRAP_STATE_DIR="${OPSKIT_BOOTSTRAP_STATE_DIR:-/var/lib/opskit-bootstrap}"
LEDGER_FILE="${BOOTSTRAP_STATE_DIR}/apply.jsonl"
LEDGER_KEY_FILE="${BOOTSTRAP_STATE_DIR}/ledger.key"
LEDGER_HEAD_FILE="${BOOTSTRAP_STATE_DIR}/ledger.head"
SERVICE_USER="opskit"
SERVICE_GROUP="opskit"
SERVICE_STATE_DIR="${OPSKIT_SERVICE_STATE_DIR:-/var/lib/opskit}"
CLI_INSTALL_PATH="${OPSKIT_CLI_INSTALL_PATH:-/usr/local/bin/opskit}"
SYSTEMD_SYSTEM_DIR="${OPSKIT_SYSTEMD_SYSTEM_DIR:-/etc/systemd/system}"
SUBUID_FILE="${OPSKIT_SUBUID_FILE:-/etc/subuid}"
SUBGID_FILE="${OPSKIT_SUBGID_FILE:-/etc/subgid}"

ensure_canonicalize_helper() {
    if [[ ! -f "${LIB_DIR}/canonicalize.py" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Required canonicalization helper not found at '${LIB_DIR}/canonicalize.py'."
    fi
}

# Validate canonical absolute paths for test-mode path overrides.
validate_override_path() {
    local var_name="$1"
    local path_val="$2"
    if [[ -z "${path_val}" ]]; then
        return 0
    fi
    if [[ "${path_val}" != /* ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Path override '${var_name}' must be an absolute path (got '${path_val}')."
    fi
    if [[ "${path_val}" =~ [[:space:][:cntrl:]] ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Path override '${var_name}' contains invalid whitespace or control characters."
    fi
    if [[ "${path_val}" =~ (^|/)\.\.(/|$) ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Path override '${var_name}' must not contain '..' traversal segments."
    fi
    local normalized="${path_val}"
    while [[ "${normalized}" != "/" && "${normalized}" == */ ]]; do
        normalized="${normalized%/}"
    done
    if [[ -L "${normalized}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Path override '${var_name}' must not be a symbolic link ('${normalized}')."
    fi
    case "${normalized}" in
        /|/bin|/bin/*|/boot|/boot/*|/dev|/dev/*|/etc|/etc/*|/home|/lib|/lib/*|/lib64|/lib64/*|/opt|/proc|/proc/*|/root|/root/*|/run|/sbin|/sbin/*|/srv|/sys|/sys/*|/tmp|/usr|/usr/*|/var|/var/lib)
            die "${EXIT_VALIDATION_ERROR}" "Path override '${var_name}' targets protected system path '${normalized}'."
            ;;
    esac
}

# Reject symbolic links on privileged state directories before root mutations.
ensure_safe_dir_no_symlink() {
    local dir_path="$1"
    if [[ -L "${dir_path}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Refusing privileged operation on symbolic link '${dir_path}'."
    fi
}

# Validate test hooks against build-time flag and OPSKIT_TEST_MODE.
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
        "MOCK_DOCKER_ROOTLESS_USABLE"
        "MOCK_CGROUP_DELEGATION"
        "OPSKIT_FORCE_RUNTIME_VERIFY"
        "OPSKIT_VERIFY_IMAGE"
        "OPSKIT_TEST_FORCE_PACKAGES"
        "OPSKIT_BOOTSTRAP_STATE_DIR"
        "OPSKIT_SERVICE_STATE_DIR"
        "OPSKIT_CLI_INSTALL_PATH"
        "OPSKIT_SYSTEMD_SYSTEM_DIR"
        "OPSKIT_SUBUID_FILE"
        "OPSKIT_SUBGID_FILE"
        "OPSKIT_SKIP_BIND_CHECK"
        "OPSKIT_DISABLE_IPV6_TEST"
    )
    if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" != "1" ]]; then
        if [[ "${OPSKIT_TEST_MODE:-0}" == "1" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "OPSKIT_TEST_MODE=1 is disabled in production builds."
        fi
        for var in "${mock_vars[@]}"; do
            if [[ -n "${!var:-}" ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Test hook environment variable '${var}' is forbidden in production builds."
            fi
        done
        return 0
    fi
    if [[ "${OPSKIT_TEST_MODE:-0}" != "1" ]]; then
        for var in "${mock_vars[@]}"; do
            if [[ -n "${!var:-}" ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Test hook environment variable '${var}' is forbidden in production unless OPSKIT_TEST_MODE=1 is set."
            fi
        done
        return 0
    fi

    validate_override_path "OPSKIT_BOOTSTRAP_STATE_DIR" "${OPSKIT_BOOTSTRAP_STATE_DIR:-}"
    validate_override_path "OPSKIT_SERVICE_STATE_DIR" "${OPSKIT_SERVICE_STATE_DIR:-}"
    validate_override_path "OPSKIT_CLI_INSTALL_PATH" "${OPSKIT_CLI_INSTALL_PATH:-}"
    validate_override_path "OPSKIT_SYSTEMD_SYSTEM_DIR" "${OPSKIT_SYSTEMD_SYSTEM_DIR:-}"
    validate_override_path "OPSKIT_SUBUID_FILE" "${OPSKIT_SUBUID_FILE:-}"
    validate_override_path "OPSKIT_SUBGID_FILE" "${OPSKIT_SUBGID_FILE:-}"
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

# Detect whether host kernel has IPv6 networking enabled.
# Upstream Linux IPv6 sysctl documentation: https://docs.kernel.org/networking/ip-sysctl.html
has_ipv6_stack() {
    if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_DISABLE_IPV6_TEST:-0}" == "1" ]]; then
        return 1
    fi
    if [[ -f /proc/net/if_inet6 ]]; then
        local disabled="0"
        if [[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
            disabled="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)"
        fi
        if [[ "${disabled}" != "1" ]]; then
            return 0
        fi
    fi
    if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" ]]; then
        return 0
    fi
    return 1
}

# Resolve the service user's home directory from passwd rather than hardcoding /home/<user>.
resolve_service_user_home() {
    local user="${1:-${SERVICE_USER}}"
    local home_dir=""
    if command -v getent >/dev/null 2>&1; then
        home_dir="$(getent passwd "${user}" 2>/dev/null | cut -d: -f6 || true)"
    fi
    if [[ -z "${home_dir}" && -f /etc/passwd ]]; then
        home_dir="$(awk -F: -v u="${user}" '$1 == u {print $6; exit}' /etc/passwd 2>/dev/null || true)"
    fi
    if [[ -z "${home_dir}" ]]; then
        home_dir="/home/${user}"
    fi
    printf '%s' "${home_dir}"
}

# Execute a /bin/sh snippet strictly as SERVICE_USER with lock FDs closed and clean environment.
# Prevents root symlink-following attacks inside user-owned directories (Linux fs.protected_symlinks).
run_as_service_user() {
    local script="$1"
    shift
    local svc_home
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    if [[ "${EUID}" -eq 0 ]]; then
        if command -v runuser >/dev/null 2>&1; then
            local wrapped_script
            wrapped_script=$'cd "${HOME:-/}" 2>/dev/null || cd /\n'"${script}"
            ( cd / && runuser -u "${SERVICE_USER}" -- env -u BASH_ENV -u ENV -u PWD HOME="${svc_home}" USER="${SERVICE_USER}" LOGNAME="${SERVICE_USER}" /bin/sh -c "${wrapped_script}" sh "$@" ) 200>&- 201>&-
        else
            python3 -B -c '
import os, pwd, sys
pw = pwd.getpwnam(sys.argv[1])
os.chdir("/")
os.initgroups(pw.pw_name, pw.pw_gid)
os.setgid(pw.pw_gid)
os.setuid(pw.pw_uid)
try:
    os.chdir(pw.pw_dir)
except OSError:
    os.chdir("/")
env = {k: v for k, v in os.environ.items() if k not in ("BASH_ENV", "ENV", "PWD")}
env["HOME"] = pw.pw_dir
env["USER"] = pw.pw_name
env["LOGNAME"] = pw.pw_name
env["PWD"] = os.getcwd()
os.execvpe("/bin/sh", ["/bin/sh", "-c", sys.argv[2], "sh", *sys.argv[3:]], env)
' "${SERVICE_USER}" "${script}" "$@" 200>&- 201>&-
        fi
    elif [[ "$(id -un 2>/dev/null || true)" == "${SERVICE_USER}" ]]; then
        ( cd "${svc_home}" 2>/dev/null || cd /; env -u BASH_ENV -u ENV -u PWD HOME="${svc_home}" /bin/sh -c "${script}" sh "$@" ) 200>&- 201>&-
    else
        die "${EXIT_SAFETY_GUARD}" "Cannot execute operation as service user '${SERVICE_USER}' without root privileges."
    fi
}

# Atomically write stdin to a file owned by SERVICE_USER without touching user paths as root.
write_user_file() {
    local dest_path="$1"
    local mode="${2:-0644}"
    run_as_service_user '
        set -eu
        dest="$1"
        mode="$2"
        dir="$(dirname "$dest")"
        mkdir -p "$dir"
        umask 077
        tmp="$(mktemp "$dir/.opskit-tmp.XXXXXX")"
        cat > "$tmp"
        chmod "$mode" "$tmp"
        mv -f "$tmp" "$dest"
    ' "${dest_path}" "${mode}"
}

# Remove a file inside SERVICE_USER home strictly as SERVICE_USER (never follows symlinks as root).
remove_user_file() {
    local target_path="$1"
    if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
        return 0
    fi
    run_as_service_user '
        rm -f -- "$1"
    ' "${target_path}" 2>/dev/null || true
}

# Enforce HTTPS for remote downloads/probes (loopback HTTP allowed only in compiled test mode).
# Upstream curl protocol restriction documentation: https://curl.se/docs/manpage.html#--proto
validate_remote_url() {
    local url="$1"
    local label="${2:-remote URL}"
    if [[ -z "${url}" || "${url}" =~ [[:space:][:cntrl:]] ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Invalid ${label}: URL is empty or contains invalid characters."
    fi
    if [[ "${url}" =~ ^https://[^[:space:]]+$ ]]; then
        return 0
    fi
    if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" ]]; then
        if [[ "${url}" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/|$) ]]; then
            return 0
        fi
    fi
    die "${EXIT_VALIDATION_ERROR}" "Untrusted ${label} '${url}': HTTPS is required."
}

set_curl_proto_flags() {
    local url="$1"
    if [[ "${url}" == https://* ]]; then
        CURL_PROTO_FLAGS=(--proto "=https" --proto-redir "=https" --tlsv1.2)
    else
        CURL_PROTO_FLAGS=(--proto "=http" --proto-redir "=http")
    fi
}

# Check whether systemd user manager configuration enables Delegate=yes.
# Upstream systemd resource control documentation:
# https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
has_systemd_delegate_yes() {
    local uid="${1:-}"
    local dirs=("${SYSTEMD_SYSTEM_DIR}/user@.service.d" "/usr/lib/systemd/system/user@.service.d")
    if [[ -n "${uid}" ]]; then
        dirs+=("${SYSTEMD_SYSTEM_DIR}/user@${uid}.service.d")
    fi
    local d f
    for d in "${dirs[@]}"; do
        [[ -d "${d}" ]] || continue
        for f in "${d}"/*.conf; do
            [[ -f "${f}" ]] || continue
            if grep -qE '^[[:space:]]*Delegate[[:space:]]*=[[:space:]]*yes([[:space:]]|$)' "${f}" 2>/dev/null; then
                return 0
            fi
        done
    done
    if [[ -f /usr/lib/systemd/system/user@.service ]] && grep -qE '^[[:space:]]*Delegate[[:space:]]*=[[:space:]]*yes([[:space:]]|$)' /usr/lib/systemd/system/user@.service 2>/dev/null; then
        return 0
    fi
    return 1
}

# Resolve the rootless Docker Unix socket path for the service user, never returning a rootful socket.
# Upstream rootless Docker documentation: https://docs.docker.com/engine/security/rootless/
resolve_service_user_docker_socket() {
    local user="$1"
    local uid=""
    uid="$(id -u "${user}" 2>/dev/null || true)"
    local svc_home
    svc_home="$(resolve_service_user_home "${user}")"
    local candidate_sock=""
    local env_dir="${svc_home}/.config/environment.d"
    if [[ -d "${env_dir}" ]]; then
        local env_host=""
        env_host="$(grep -hE '^[[:space:]]*DOCKER_HOST=' "${env_dir}"/*.conf 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "\"'[:space:]" || true)"
        if [[ "${env_host}" == unix://* ]]; then
            candidate_sock="${env_host#unix://}"
        fi
    fi
    if [[ -z "${candidate_sock}" && -n "${uid}" ]]; then
        if [[ -S "/run/user/${uid}/docker.sock" || -d "/run/user/${uid}" ]]; then
            candidate_sock="/run/user/${uid}/docker.sock"
        elif [[ -S "${svc_home}/.docker/run/docker.sock" ]]; then
            candidate_sock="${svc_home}/.docker/run/docker.sock"
        else
            candidate_sock="/run/user/${uid}/docker.sock"
        fi
    fi
    if [[ -n "${candidate_sock}" ]]; then
        local resolved_sock=""
        if [[ -e "${candidate_sock}" || -L "${candidate_sock}" ]]; then
            resolved_sock="$(readlink -f -- "${candidate_sock}" 2>/dev/null || true)"
        else
            local parent_dir leaf_name resolved_parent
            parent_dir="$(dirname "${candidate_sock}")"
            leaf_name="$(basename "${candidate_sock}")"
            if [[ -d "${parent_dir}" ]]; then
                resolved_parent="$(readlink -f -- "${parent_dir}" 2>/dev/null || true)"
                [[ -n "${resolved_parent}" ]] && resolved_sock="${resolved_parent}/${leaf_name}"
            else
                resolved_sock="${candidate_sock}"
            fi
        fi
        [[ -n "${resolved_sock}" ]] && candidate_sock="${resolved_sock}"
        local resolved_home="${svc_home}"
        [[ -d "${svc_home}" ]] && resolved_home="$(readlink -f -- "${svc_home}" 2>/dev/null || echo "${svc_home}")"
        if [[ "${candidate_sock}" == "/var/run/docker.sock" || "${candidate_sock}" == "/run/docker.sock" ]]; then
            candidate_sock=""
        elif [[ -n "${uid}" && "${candidate_sock}" != "/run/user/${uid}/"* && "${candidate_sock}" != "${resolved_home}/"* ]]; then
            candidate_sock=""
        elif [[ -S "${candidate_sock}" && -n "${uid}" ]]; then
            local sock_uid
            sock_uid="$(stat -c %u "${candidate_sock}" 2>/dev/null || echo "")"
            if [[ -n "${sock_uid}" && "${sock_uid}" != "${uid}" ]]; then
                candidate_sock=""
            fi
        fi
    fi
    printf '%s' "${candidate_sock}"
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
ports = set()
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
if not ports:
    ports = {('443', 'tcp'), ('80', 'tcp')}
else:
    ports.add(('443', 'tcp'))
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

    # Check iptables and ip6tables tagged rules
    if [[ "${exclude_stack}" != "iptables" ]]; then
        if command -v iptables >/dev/null 2>&1; then
            local tp_entry c_port c_proto
            for tp_entry in "${target_ports[@]}"; do
                IFS=: read -r c_port c_proto <<< "${tp_entry}"
                if iptables -C INPUT -p "${c_proto}" --dport "${c_port}" -m comment --comment "opskit-${c_port}" -j ACCEPT >/dev/null 2>&1; then
                    _add_fw_survivor "${c_port}/${c_proto}"
                fi
            done
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            local tp_entry c_port c_proto
            for tp_entry in "${target_ports[@]}"; do
                IFS=: read -r c_port c_proto <<< "${tp_entry}"
                if ip6tables -C INPUT -p "${c_proto}" --dport "${c_port}" -m comment --comment "opskit-${c_port}" -j ACCEPT >/dev/null 2>&1; then
                    _add_fw_survivor "ip6tables:${c_port}/${c_proto}"
                fi
            done
        fi
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

# Shared firewall primitives across distribution family adapters (firewalld -> ufw -> nftables -> iptables/ip6tables).
opskit_fw_has_rule() {
    local port="$1"
    local proto="${2:-tcp}"
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --query-port="${port}/${proto}" >/dev/null 2>&1 \
            && firewall-cmd --permanent --query-port="${port}/${proto}" >/dev/null 2>&1 \
            && return 0 || return 1
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE '^Status:[[:space:]]+active'; then
        local ufw_out
        ufw_out="$(ufw status 2>/dev/null || true)"
        if grep -qE "^(${port}/${proto}|${port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW.*#[[:space:]]*opskit-${port}([[:space:]]|$)" <<< "${ufw_out}" \
           || grep -qE "^(${port}/${proto}|${port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW[[:space:]]+(IN[[:space:]]+)?Anywhere([[:space:]]|$)" <<< "${ufw_out}"; then
            return 0
        fi
        return 1
    elif command -v nft >/dev/null 2>&1; then
        nft list chain inet opskit input 2>/dev/null | grep -F "comment \"opskit-${port}\"" >/dev/null 2>&1 && return 0 || return 1
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT >/dev/null 2>&1 || return 1
        if command -v ip6tables >/dev/null 2>&1 && has_ipv6_stack && ip6tables -L INPUT >/dev/null 2>&1; then
            ip6tables -C INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT >/dev/null 2>&1 || return 1
        fi
        return 0
    fi
    return 1
}

opskit_fw_has_tagged_rule() {
    local port="$1"
    local proto="${2:-tcp}"
    if command -v nft >/dev/null 2>&1; then
        if nft list chain inet opskit input 2>/dev/null | grep -F "comment \"opskit-${port}\"" >/dev/null 2>&1; then
            return 0
        fi
    fi
    if command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT >/dev/null 2>&1; then
            return 0
        fi
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        if ip6tables -C INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

opskit_fw_apply_rule() {
    local port="$1"
    local proto="${2:-tcp}"
    local prior_owned="${3:-false}"

    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        local pre_existing="false"
        local has_rt=false has_perm=false
        firewall-cmd --query-port="${port}/${proto}" >/dev/null 2>&1 && has_rt=true
        firewall-cmd --permanent --query-port="${port}/${proto}" >/dev/null 2>&1 && has_perm=true

        if ${has_rt} && ${has_perm}; then
            if [[ "${prior_owned}" != "true" ]]; then
                pre_existing="true"
            fi
        else
            if ! ${has_rt}; then
                firewall-cmd --add-port="${port}/${proto}" >/dev/null || die "${EXIT_RUNTIME_ERROR}" "Failed to add runtime firewalld port ${port}/${proto}."
            fi
            if ! ${has_perm}; then
                firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null || die "${EXIT_RUNTIME_ERROR}" "Failed to add permanent firewalld port ${port}/${proto}."
            fi
            pre_existing="false"
        fi
        local fw_zone
        fw_zone="$(firewall-cmd --get-default-zone 2>/dev/null || true)"
        if [[ -z "${fw_zone}" && -f /etc/firewalld/firewalld.conf ]]; then
            fw_zone="$(awk -F= '/^[[:space:]]*DefaultZone[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/firewalld/firewalld.conf 2>/dev/null || true)"
        fi
        [[ -z "${fw_zone}" ]] && fw_zone="public"
        local post_state
        post_state="$(compute_sha256 "$(firewall-cmd --list-ports 2>/dev/null)")"
        echo "{\"stack\":\"firewalld\",\"zone\":\"$(json_escape "${fw_zone}")\",\"port\":${port},\"proto\":\"${proto}\",\"pre_existing\":${pre_existing},\"rule\":\"--add-port=${port}/${proto}\",\"delete_rule\":\"--remove-port=${port}/${proto}\",\"post_state\":\"${post_state}\"}"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE '^Status:[[:space:]]+active'; then
        local pre_existing="false"
        local ufw_status_out
        ufw_status_out="$(ufw status 2>/dev/null || true)"
        if grep -E "^(${port}/${proto}|${port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW.*#[[:space:]]*opskit-${port}([[:space:]]|$)" >/dev/null 2>&1 <<< "${ufw_status_out}"; then
            pre_existing="false"
        elif grep -E "^(${port}/${proto}|${port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW[[:space:]]+(IN[[:space:]]+)?Anywhere([[:space:]]|$)" >/dev/null 2>&1 <<< "${ufw_status_out}"; then
            pre_existing="true"
        else
            ufw allow "${port}/${proto}" comment "opskit-${port}" >/dev/null || die "${EXIT_RUNTIME_ERROR}" "Failed to apply ufw allow ${port}/${proto}."
            pre_existing="false"
        fi
        local post_state
        post_state="$(compute_sha256 "$(ufw status 2>/dev/null)")"
        echo "{\"stack\":\"ufw\",\"port\":${port},\"proto\":\"${proto}\",\"pre_existing\":${pre_existing},\"rule\":\"allow ${port}/${proto} comment opskit-${port}\",\"delete_rule\":\"delete allow ${port}/${proto} comment opskit-${port}\",\"post_state\":\"${post_state}\"}"
    elif command -v nft >/dev/null 2>&1; then
        nft add table inet opskit || die "${EXIT_RUNTIME_ERROR}" "Failed to create nftables table 'inet opskit'."
        nft add chain inet opskit input '{ type filter hook input priority 0; policy accept; }' || die "${EXIT_RUNTIME_ERROR}" "Failed to create nftables chain 'inet opskit input'."
        local handle
        handle="$(nft -a list chain inet opskit input 2>/dev/null | grep "comment \"opskit-${port}\"" | grep -o 'handle [0-9]\+' | awk '{print $2}' | tail -n1 || true)"
        if [[ -z "${handle}" ]]; then
            nft add rule inet opskit input "${proto}" dport "${port}" accept comment "\"opskit-${port}\"" || die "${EXIT_RUNTIME_ERROR}" "Failed to add nftables rule for port ${port}."
            handle="$(nft -a list chain inet opskit input 2>/dev/null | grep "comment \"opskit-${port}\"" | grep -o 'handle [0-9]\+' | awk '{print $2}' | tail -n1 || true)"
        fi
        [[ -z "${handle}" ]] && handle="0"
        local post_state
        post_state="$(compute_sha256 "$(nft list table inet opskit 2>/dev/null)")"
        echo "{\"stack\":\"nftables\",\"family\":\"inet\",\"table\":\"opskit\",\"chain\":\"input\",\"port\":${port},\"proto\":\"${proto}\",\"handle\":${handle},\"rule\":\"${proto} dport ${port} accept\",\"post_state\":\"${post_state}\"}"
    elif command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT >/dev/null 2>&1; then
            iptables -I INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT || die "${EXIT_RUNTIME_ERROR}" "Failed to add iptables rule for port ${port}."
        fi
        if command -v ip6tables >/dev/null 2>&1 && has_ipv6_stack && ip6tables -L INPUT >/dev/null 2>&1; then
            if ! ip6tables -C INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -I INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT || die "${EXIT_RUNTIME_ERROR}" "Failed to add ip6tables rule for port ${port}."
            fi
        fi
        local post_state
        post_state="$(compute_sha256 "$(iptables -S INPUT 2>/dev/null)")"
        echo "{\"stack\":\"iptables\",\"port\":${port},\"proto\":\"${proto}\",\"rule\":\"-I INPUT -p ${proto} --dport ${port} -m comment --comment opskit-${port} -j ACCEPT\",\"delete_rule\":\"-D INPUT -p ${proto} --dport ${port} -m comment --comment opskit-${port} -j ACCEPT\",\"post_state\":\"${post_state}\"}"
    else
        echo "{\"stack\":\"none\",\"rule\":\"none\"}"
    fi
}

opskit_fw_remove_rule() {
    local meta_json="${1:-}"
    [[ -z "${meta_json}" ]] && meta_json="{}"
    local stack port proto handle pre_existing zone
    stack="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(d.get('stack', '') if isinstance(d, dict) else '')" "${meta_json}" 2>/dev/null || true)"
    port="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(int(d.get('port', 0) or 0) if isinstance(d, dict) else 0)" "${meta_json}" 2>/dev/null || echo 0)"
    proto="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(d.get('proto', 'tcp') or 'tcp' if isinstance(d, dict) else 'tcp')" "${meta_json}" 2>/dev/null || echo tcp)"
    handle="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(int(d.get('handle', 0) or 0) if isinstance(d, dict) else 0)" "${meta_json}" 2>/dev/null || echo 0)"
    pre_existing="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(str(bool(d.get('pre_existing', False))).lower() if isinstance(d, dict) else 'false')" "${meta_json}" 2>/dev/null || echo false)"
    zone="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(d.get('zone', '') if isinstance(d, dict) else '')" "${meta_json}" 2>/dev/null || true)"
    [[ "${port}" =~ ^[0-9]+$ ]] || port=0
    [[ "${handle}" =~ ^[0-9]+$ ]] || handle=0

    _remove_nft() {
        if ! command -v nft >/dev/null 2>&1; then
            return 0
        fi
        local target_ports=()
        if [[ "${port}" -gt 0 ]]; then
            target_ports=("${port}")
        else
            target_ports=(443 80)
        fi
        local port_csv
        port_csv="$(IFS=,; echo "${target_ports[*]}")"

        local live_handles=""
        local nft_json=""
        nft_json="$(nft -j list chain inet opskit input 2>/dev/null || true)"
        if [[ -n "${nft_json}" ]]; then
            live_handles="$(python3 -B -c "
import json, sys
targets = {f'opskit-{p}' for p in sys.argv[2].split(',') if p}
try:
    data = json.loads(sys.argv[1])
except Exception:
    sys.exit(0)
for item in data.get('nftables', []):
    rule = item.get('rule')
    if not rule:
        continue
    if rule.get('comment', '') in targets and rule.get('handle') is not None:
        print(rule['handle'])
" "${nft_json}" "${port_csv}" 2>/dev/null || true)"
        else
            for tp in "${target_ports[@]}"; do
                local found
                found="$(nft -a list chain inet opskit input 2>/dev/null | grep -F "comment \"opskit-${tp}\"" | grep -o 'handle [0-9]\+' | awk '{print $2}' || true)"
                [[ -n "${found}" ]] && live_handles="${live_handles}"$'\n'"${found}"
            done
        fi

        local deleted_any=false
        if [[ -n "${live_handles}" ]]; then
            for h in ${live_handles}; do
                if nft delete rule inet opskit input handle "${h}" 2>/dev/null; then
                    deleted_any=true
                fi
            done
        fi

        if ! ${deleted_any} && [[ "${handle}" -gt 0 ]]; then
            local handle_status=""
            if [[ -n "${nft_json}" ]]; then
                handle_status="$(python3 -B -c "
import json, sys
target_h = int(sys.argv[2])
targets = {f'opskit-{p}' for p in sys.argv[3].split(',') if p}
try:
    data = json.loads(sys.argv[1])
except Exception:
    print('unknown')
    sys.exit(0)
for item in data.get('nftables', []):
    rule = item.get('rule')
    if rule and rule.get('handle') == target_h:
        c = rule.get('comment', '')
        if c in targets:
            print('match')
        else:
            print(f'mismatch:{c}')
        sys.exit(0)
print('absent')
" "${nft_json}" "${handle}" "${port_csv}" 2>/dev/null || echo "unknown")"
            fi
            if [[ "${handle_status}" == "match" ]]; then
                nft delete rule inet opskit input handle "${handle}" 2>/dev/null || true
            elif [[ "${handle_status}" == mismatch:* ]]; then
                local live_comment="${handle_status#mismatch:}"
                log_warn "Skipping stale recorded nftables handle ${handle} in table 'inet opskit': live rule comment ('${live_comment:-<none>}') does not match targeted OpsKit rule."
            fi
        fi

        if nft list table inet opskit >/dev/null 2>&1; then
            local table_json rule_summary
            table_json="$(nft -j list table inet opskit 2>/dev/null || true)"
            if [[ -n "${table_json}" ]]; then
                rule_summary="$(python3 -B -c "
import json, sys
try:
    data = json.loads(sys.argv[1])
except Exception:
    print('unknown:0:0')
    sys.exit(0)
total_rules = 0
opskit_port_rules = 0
other_objects = 0
for item in data.get('nftables', []):
    rule = item.get('rule')
    if rule:
        total_rules += 1
        if rule.get('comment', '') in {'opskit-443', 'opskit-80'}:
            opskit_port_rules += 1
        continue
    ch = item.get('chain')
    if ch and ch.get('name', '') != 'input':
        other_objects += 1
    elif any(k in item for k in ('set', 'map', 'flowtable', 'counter', 'quota', 'ct helper', 'ct timeout', 'ct expectation', 'limit', 'secmark', 'synproxy')):
        other_objects += 1
print(f'ok:{total_rules}:{opskit_port_rules}:{other_objects}')
" "${table_json}" 2>/dev/null || echo "unknown:0:0:0")"
                if [[ "${rule_summary}" == ok:* ]]; then
                    local total_rules opskit_port_rules other_objects
                    IFS=: read -r _ total_rules opskit_port_rules other_objects <<< "${rule_summary}"
                    if [[ "${total_rules}" -eq 0 && "${other_objects}" -eq 0 ]]; then
                        nft delete chain inet opskit input 2>/dev/null || true
                        nft delete table inet opskit 2>/dev/null || true
                    elif [[ "${opskit_port_rules}" -eq 0 ]]; then
                        if [[ -z "${_OPSKIT_NFT_RETAIN_WARNED:-}" ]]; then
                            log_warn "Retaining nftables table 'inet opskit': ${total_rules} non-OpsKit or untagged rule(s) and ${other_objects} non-rule or custom chain object(s) remain in OpsKit-managed namespace."
                            _OPSKIT_NFT_RETAIN_WARNED=1
                        fi
                    fi
                fi
            fi
        fi
    }

    _remove_iptables() {
        local target_ports=()
        if [[ "${port}" -gt 0 ]]; then
            target_ports=("${port}")
        else
            target_ports=(443 80)
        fi
        local tp
        if command -v iptables >/dev/null 2>&1; then
            for tp in "${target_ports[@]}"; do
                while iptables -D INPUT -p "${proto}" --dport "${tp}" -m comment --comment "opskit-${tp}" -j ACCEPT 2>/dev/null; do :; done
            done
        fi
        if command -v ip6tables >/dev/null 2>&1; then
            for tp in "${target_ports[@]}"; do
                while ip6tables -D INPUT -p "${proto}" --dport "${tp}" -m comment --comment "opskit-${tp}" -j ACCEPT 2>/dev/null; do :; done
            done
        fi
    }

    _remove_ufw() {
        if [[ "${pre_existing}" == "true" ]]; then
            return 0
        fi
        if ! command -v ufw >/dev/null 2>&1; then
            return 0
        fi
        local target_ports=()
        if [[ "${port}" -gt 0 ]]; then
            target_ports=("${port}")
        else
            target_ports=(443 80)
        fi
        local tp
        if ufw status 2>/dev/null | grep -qE '^Status:[[:space:]]+active'; then
            for tp in "${target_ports[@]}"; do
                local rule_nums
                rule_nums="$(ufw status numbered 2>/dev/null | awk -v tag="opskit-${tp}" '
                    $0 ~ ("#[[:space:]]*" tag "([[:space:]]|$)") {
                        if (match($0, /\[[[:space:]]*[0-9]+/)) {
                            num = substr($0, RSTART + 1, RLENGTH - 1)
                            gsub(/[[:space:]]/, "", num)
                            print num
                        }
                    }
                ' | sort -rn || true)"
                if [[ -n "${rule_nums}" ]]; then
                    local rnum
                    for rnum in ${rule_nums}; do
                        ufw --force delete "${rnum}" >/dev/null 2>&1 || true
                    done
                else
                    ufw --force delete allow "${tp}/${proto}" comment "opskit-${tp}" >/dev/null 2>&1 || true
                fi
            done
        else
            for tp in "${target_ports[@]}"; do
                ufw --force delete allow "${tp}/${proto}" comment "opskit-${tp}" >/dev/null 2>&1 || true
            done
        fi
    }

    _remove_firewalld() {
        if [[ "${pre_existing}" == "true" ]]; then
            return 0
        fi
        if ! command -v firewall-cmd >/dev/null 2>&1 && ! command -v firewall-offline-cmd >/dev/null 2>&1; then
            return 0
        fi
        local target_ports=()
        if [[ "${port}" -gt 0 ]]; then
            target_ports=("${port}")
        else
            target_ports=(443 80)
        fi
        local zone_args=()
        [[ -n "${zone}" ]] && zone_args=("--zone=${zone}")
        local tp
        for tp in "${target_ports[@]}"; do
            if command -v firewall-cmd >/dev/null 2>&1; then
                if systemctl is-active --quiet firewalld 2>/dev/null; then
                    firewall-cmd "${zone_args[@]}" --remove-port="${tp}/${proto}" >/dev/null 2>&1 || true
                    firewall-cmd --permanent "${zone_args[@]}" --remove-port="${tp}/${proto}" >/dev/null 2>&1 || true
                else
                    firewall-cmd --permanent "${zone_args[@]}" --remove-port="${tp}/${proto}" >/dev/null 2>&1 || {
                        if command -v firewall-offline-cmd >/dev/null 2>&1; then
                            firewall-offline-cmd "${zone_args[@]}" --remove-port="${tp}/${proto}" >/dev/null 2>&1 || true
                        fi
                    }
                fi
            elif command -v firewall-offline-cmd >/dev/null 2>&1; then
                firewall-offline-cmd "${zone_args[@]}" --remove-port="${tp}/${proto}" >/dev/null 2>&1 || true
            fi
        done
    }

    case "${stack}" in
        firewalld)
            _remove_firewalld
            ;;
        ufw)
            _remove_ufw
            ;;
        nftables)
            _remove_nft
            ;;
        iptables)
            _remove_iptables
            ;;
        *)
            _remove_nft
            _remove_iptables
            ;;
    esac
}
