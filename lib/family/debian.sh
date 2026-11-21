#!/usr/bin/env bash
# Debian family package and system configuration adapter (Debian 13+, Ubuntu 24.04+).
set -euo pipefail

family_install_packages() {
    local pkgs=("$@")
    if [[ ${#pkgs[@]} -eq 0 ]]; then
        return 0
    fi
    log_info "Installing Debian packages: ${pkgs[*]} via apt-get..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    local reinstall_pkgs=()
    local install_pkgs=()
    for p in "${pkgs[@]}"; do
        if dpkg -s "${p}" >/dev/null 2>&1; then
            reinstall_pkgs+=("${p}")
        else
            install_pkgs+=("${p}")
        fi
    done
    if [[ ${#reinstall_pkgs[@]} -gt 0 ]]; then
        apt-get install -y --reinstall --no-install-recommends "${reinstall_pkgs[@]}"
    fi
    if [[ ${#install_pkgs[@]} -gt 0 ]]; then
        apt-get install -y --no-install-recommends "${install_pkgs[@]}"
    fi
}

family_create_service_user() {
    local user="$1"
    local group="$2"
    if ! getent group "${group}" >/dev/null 2>&1; then
        groupadd -r "${group}" 2>/dev/null || true
    fi
    local nologin_shell="/usr/sbin/nologin"
    if [[ ! -x "${nologin_shell}" ]]; then
        if [[ -x "/sbin/nologin" ]]; then
            nologin_shell="/sbin/nologin"
        else
            nologin_shell="/bin/false"
        fi
    fi
    if ! id "${user}" >/dev/null 2>&1; then
        local created=false
        # Upstream system user drop-in configuration format: https://www.freedesktop.org/software/systemd/man/latest/sysusers.d.html
        if command -v systemd-sysusers >/dev/null 2>&1; then
            mkdir -p /etc/sysusers.d
            echo "u ${user} - \"OpsKit Service Account\" /home/${user} ${nologin_shell}" > "/etc/sysusers.d/${user}.conf"
            if systemd-sysusers >/dev/null 2>&1 && id "${user}" >/dev/null 2>&1; then
                created=true
                mkdir -p "/home/${user}"
                chown "${user}:${group}" "/home/${user}"
                chmod 0750 "/home/${user}"
            else
                rm -f "/etc/sysusers.d/${user}.conf"
            fi
        fi
        if ! ${created}; then
            useradd -r -m -g "${group}" -d "/home/${user}" -s "${nologin_shell}" "${user}"
            chmod 0750 "/home/${user}"
        fi
        log_info "Created service account '${user}' with group '${group}'."
    fi
}

family_has_firewall_rule() {
    local port="$1"
    local proto="${2:-tcp}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -w "active" >/dev/null 2>&1; then
        ufw status 2>/dev/null | grep -E "^(${port}/${proto}|${port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW" >/dev/null 2>&1 && return 0 || return 1
    elif command -v nft >/dev/null 2>&1; then
        nft list chain inet opskit input 2>/dev/null | grep -F "comment \"opskit-${port}\"" >/dev/null 2>&1 && return 0 || return 1
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p "${proto}" --dport "${port}" -m comment --comment "opskit-${port}" -j ACCEPT >/dev/null 2>&1 && return 0 || return 1
    fi
    return 1
}

family_has_tagged_opskit_firewall_rule() {
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
    return 1
}

family_apply_firewall_rule() {
    local port="$1"
    local proto="${2:-tcp}"
    local _prior_owned="${3:-false}"

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -w "active" >/dev/null 2>&1; then
        local pre_existing="false"
        local ufw_status_out
        ufw_status_out="$(ufw status 2>/dev/null || true)"
        if grep -E "^(${port}/${proto}|${port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW.*#[[:space:]]*opskit-${port}([[:space:]]|$)" >/dev/null 2>&1 <<< "${ufw_status_out}"; then
            pre_existing="false"
        elif grep -E "^(${port}/${proto}|${port})([[:space:]]+\(v6\))?[[:space:]]+ALLOW" >/dev/null 2>&1 <<< "${ufw_status_out}"; then
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
        local post_state
        post_state="$(compute_sha256 "$(iptables -S INPUT 2>/dev/null)")"
        echo "{\"stack\":\"iptables\",\"port\":${port},\"proto\":\"${proto}\",\"rule\":\"-I INPUT -p ${proto} --dport ${port} -m comment --comment opskit-${port} -j ACCEPT\",\"delete_rule\":\"-D INPUT -p ${proto} --dport ${port} -m comment --comment opskit-${port} -j ACCEPT\",\"post_state\":\"${post_state}\"}"
    else
        echo "{\"stack\":\"none\",\"rule\":\"none\"}"
    fi
}

family_remove_firewall_rule() {
    local meta_json="${1:-}"
    [[ -z "${meta_json}" ]] && meta_json="{}"
    local stack port proto handle pre_existing
    stack="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(d.get('stack', '') if isinstance(d, dict) else '')" "${meta_json}" 2>/dev/null || true)"
    port="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(int(d.get('port', 0) or 0) if isinstance(d, dict) else 0)" "${meta_json}" 2>/dev/null || echo 0)"
    proto="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(d.get('proto', 'tcp') or 'tcp' if isinstance(d, dict) else 'tcp')" "${meta_json}" 2>/dev/null || echo tcp)"
    handle="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(int(d.get('handle', 0) or 0) if isinstance(d, dict) else 0)" "${meta_json}" 2>/dev/null || echo 0)"
    pre_existing="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(str(bool(d.get('pre_existing', False))).lower() if isinstance(d, dict) else 'false')" "${meta_json}" 2>/dev/null || echo false)"
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

        # Stale recorded-handle fallback: resolve candidate handle's comment first
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

        # Decide table/chain deletion strictly by live rule and object counts
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
        if ! command -v iptables >/dev/null 2>&1; then
            return 0
        fi
        local target_ports=()
        if [[ "${port}" -gt 0 ]]; then
            target_ports=("${port}")
        else
            target_ports=(443 80)
        fi
        for tp in "${target_ports[@]}"; do
            while iptables -D INPUT -p "${proto}" --dport "${tp}" -m comment --comment "opskit-${tp}" -j ACCEPT 2>/dev/null; do :; done
        done
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
        for tp in "${target_ports[@]}"; do
            ufw --force delete allow "${tp}/${proto}" comment "opskit-${tp}" >/dev/null 2>&1 || true
        done
    }

    case "${stack}" in
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
