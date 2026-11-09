#!/usr/bin/env bash
# Mutation executor for opskit-bootstrap applying the closed mutation inventory.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes all libraries are loaded

is_mutation_planned() {
    local id="$1"
    for m in "${PLAN_MUTATIONS[@]}"; do
        if [[ "${m}" =~ \"id\":\"${id}\" ]]; then
            return 0
        fi
    done
    return 1
}

apply_mutations() {
    if ${NO_CHANGES}; then
        log_info "Host already bootstrapped; no changes required."
        vendor_uninstaller
        return 0
    fi

    log_info "Applying approved bootstrap plan (${PLAN_HASH})..."

    # 1. Packages
    if is_mutation_planned "packages"; then
        local pkgs=()
        ${PODMAN_PACKAGE_NEEDED} && pkgs+=("podman")
        if ${UIDMAP_PACKAGE_NEEDED}; then
            case "${DETECTED_FAMILY}" in
                debian) pkgs+=("uidmap") ;;
                rhel) pkgs+=("shadow-utils") ;;
                sles) pkgs+=("shadow") ;;
            esac
        fi
        if [[ ${#pkgs[@]} -eq 0 ]] && [[ "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_TEST_FORCE_PACKAGES:-0}" == "1" ]]; then
            case "${DETECTED_FAMILY}" in
                debian) pkgs=("podman" "uidmap") ;;
                rhel) pkgs=("podman" "shadow-utils") ;;
                sles) pkgs=("podman" "shadow") ;;
            esac
        fi
        family_install_packages "${pkgs[@]}"
        local pkgs_json
        pkgs_json="$(python3 -B -c "import json, sys; print(json.dumps(sys.argv[1:], separators=(',', ':')))" "${pkgs[@]}")"
        record_mutation "packages" "H" "absent" "installed" "${PLAN_HASH}" "{\"packages\":${pkgs_json},\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
    fi

    # Capture pre-apply sysusers marker before Step 2 mutates the host
    local pre_apply_sysusers_marker=false
    if ${SERVICE_USER_EXISTS:-false} && [[ -f "/etc/sysusers.d/${SERVICE_USER}.conf" ]]; then
        pre_apply_sysusers_marker=true
    fi

    # 2. Service user & group (preserve pre-existing admin accounts on purge)
    local user_created_by_opskit=false
    if is_mutation_planned "service_user"; then
        local u_uid u_gid
        if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
            family_create_service_user "${SERVICE_USER}" "${SERVICE_GROUP}"
            u_uid="$(id -u "${SERVICE_USER}")"
            u_gid="$(id -g "${SERVICE_USER}")"
            user_created_by_opskit=true
            record_mutation "service_user" "H" "absent" "present:uid=${u_uid}:gid=${u_gid}" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"group\":\"${SERVICE_GROUP}\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        elif [[ -f "/etc/sysusers.d/${SERVICE_USER}.conf" ]]; then
            # Crash-window reconciliation: user exists with OpsKit sysusers.d drop-in marker
            u_uid="$(id -u "${SERVICE_USER}")"
            u_gid="$(id -g "${SERVICE_USER}")"
            user_created_by_opskit=true
            record_mutation "service_user" "H" "absent" "present:uid=${u_uid}:gid=${u_gid}" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"group\":\"${SERVICE_GROUP}\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        else
            # Pre-existing admin user without OpsKit sysusers.d marker: record and never purge
            u_uid="$(id -u "${SERVICE_USER}")"
            u_gid="$(id -g "${SERVICE_USER}")"
            record_mutation "service_user" "H" "present:uid=${u_uid}:gid=${u_gid}" "present:uid=${u_uid}:gid=${u_gid}" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"group\":\"${SERVICE_GROUP}\",\"created\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded pre-existing service account '${SERVICE_USER}' (uid=${u_uid}, preserved on purge)."
        fi
    fi

    # 3. Subuid / Subgid allocation
    if is_mutation_planned "subuid_allocation"; then
        allocate_subordinate_ids "${user_created_by_opskit}" "${pre_apply_sysusers_marker}"
    fi

    # 4. User linger (anchor ownership to pre-apply LINGER_ACTIVE verdict)
    if is_mutation_planned "user_linger"; then
        if ${LINGER_ACTIVE:-false} && ! ${pre_apply_sysusers_marker}; then
            record_mutation "user_linger" "H" "present:enabled" "enabled" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"enabled\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded pre-existing systemd user linger for '${SERVICE_USER}' (preserved on purge)."
        elif [[ -f "/var/lib/systemd/linger/${SERVICE_USER}" && ! -f "/etc/sysusers.d/${SERVICE_USER}.conf" ]] && ! ${user_created_by_opskit}; then
            record_mutation "user_linger" "H" "present:enabled" "enabled" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"enabled\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded pre-existing systemd user linger for '${SERVICE_USER}' (preserved on purge)."
        else
            log_info "Enabling systemd user linger for '${SERVICE_USER}'..."
            if command -v loginctl >/dev/null 2>&1; then
                loginctl enable-linger "${SERVICE_USER}" 2>/dev/null || true
            fi
            mkdir -p /var/lib/systemd/linger
            touch "/var/lib/systemd/linger/${SERVICE_USER}"
            record_mutation "user_linger" "H" "disabled" "enabled" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"enabled\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        fi
    fi

    # Create service state directories
    mkdir -p "${SERVICE_STATE_DIR}"/{edge,versions/current,logs,state}
    chmod 0750 "${SERVICE_STATE_DIR}"
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${SERVICE_STATE_DIR}"
    fi

    # User systemd config directory
    local user_systemd_dir="/home/${SERVICE_USER}/.config/systemd/user"
    mkdir -p "${user_systemd_dir}"
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "/home/${SERVICE_USER}/.config"
    fi

    # 5. Direct profile: root socket units & system unit & firewall
    if [[ "${CHOSEN_PROFILE}" == "direct" ]]; then
        is_mutation_planned "edge_socket_units" && install_edge_socket_units
        is_mutation_planned "edge_system_unit" && install_edge_system_unit
        is_mutation_planned "firewall_rules" && install_firewall_rules
    fi

    # 8. Service units
    is_mutation_planned "service_units" && install_user_units "${user_systemd_dir}"

    # 9. Tunnel profile: cloudflared user unit template
    if [[ "${CHOSEN_PROFILE}" == "tunnel" ]]; then
        is_mutation_planned "cloudflared_unit" && install_cloudflared_unit "${user_systemd_dir}"
    fi

    # 10. Security labels
    if is_mutation_planned "security_labels"; then
        apply_security_labels
    fi

    # 11. Fetch CLI binary via signed manifest
    if is_mutation_planned "fetch_cli"; then
        verify_and_install_cli
        local after_fp="${CLI_MUTATION_AFTER_FP:-installed:${CLI_INSTALL_PATH}}"
        local before_fp="${CLI_MUTATION_BEFORE_FP:-absent}"
        record_mutation "fetch_cli" "H" "${before_fp}" "${after_fp}" "${PLAN_HASH}" "${CLI_MUTATION_METADATA}"
    fi

    # Vendor uninstaller and state
    vendor_uninstaller

    log_info "Bootstrap completed successfully under '${CHOSEN_PROFILE}' profile."
}

allocate_subordinate_ids() {
    local user_created_by_opskit="${1:-false}"
    local pre_apply_sysusers_marker="${2:-false}"
    log_info "Checking subordinate UID/GID range for '${SERVICE_USER}'..."
    mkdir -p "$(dirname "${SUBUID_FILE}")" "$(dirname "${SUBGID_FILE}")"
    touch "${SUBUID_FILE}" "${SUBGID_FILE}"

    # Preserve any prior per-file OpsKit ownership recorded in the ledger across partial repairs
    local prior_subuid=false prior_subgid=false
    if [[ -f "${LEDGER_FILE}" ]] && is_mutation_recorded "subuid_allocation"; then
        local prior_flags
        prior_flags="$(python3 -B -c "
import json, sys
for line in open(sys.argv[1], 'r'):
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        if d.get('mutation_id') == 'subuid_allocation':
            md = d.get('metadata', {})
            if isinstance(md, dict):
                a = bool(md.get('allocated', False))
                u = bool(md.get('subuid_allocated', a))
                g = bool(md.get('subgid_allocated', a))
                print(f'{str(u).lower()}:{str(g).lower()}')
                sys.exit(0)
    except Exception:
        pass
print('false:false')
" "${LEDGER_FILE}" 2>/dev/null || echo "false:false")"
        IFS=: read -r prior_subuid prior_subgid <<< "${prior_flags}"
    fi

    local existing_subuid="" existing_subgid=""
    if grep -q "^${SERVICE_USER}:" "${SUBUID_FILE}" 2>/dev/null; then
        existing_subuid="$(grep "^${SERVICE_USER}:" "${SUBUID_FILE}" | head -n1 | cut -d: -f2-3)"
    fi
    if grep -q "^${SERVICE_USER}:" "${SUBGID_FILE}" 2>/dev/null; then
        existing_subgid="$(grep "^${SERVICE_USER}:" "${SUBGID_FILE}" | head -n1 | cut -d: -f2-3)"
    fi

    if [[ -n "${existing_subuid}" && -n "${existing_subgid}" ]]; then
        local subuid_owned=false subgid_owned=false alloc_all=false
        if ${prior_subuid} || ${pre_apply_sysusers_marker} || ! ${SUBUID_ENTRY_PRESENT:-false}; then
            subuid_owned=true
        fi
        if ${prior_subgid} || ${pre_apply_sysusers_marker} || ! ${SUBGID_ENTRY_PRESENT:-false}; then
            subgid_owned=true
        fi
        if ${subuid_owned} && ${subgid_owned}; then
            alloc_all=true
            record_mutation "subuid_allocation" "H" "none" "${existing_subuid}" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"range\":\"${existing_subuid}\",\"allocated\":true,\"subuid_allocated\":true,\"subgid_allocated\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        else
            record_mutation "subuid_allocation" "H" "present:${existing_subuid}" "${existing_subuid}" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"range\":\"${existing_subuid}\",\"allocated\":${alloc_all},\"subuid_allocated\":${subuid_owned},\"subgid_allocated\":${subgid_owned},\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded existing subuid/subgid range ${existing_subuid} for '${SERVICE_USER}' (subuid_owned=${subuid_owned}, subgid_owned=${subgid_owned})."
        fi
        return 0
    fi

    # Determine range to write for any missing file (reuse single-file entry or compute max across both files)
    local target_range="${existing_subuid:-${existing_subgid}}"
    local before_fp="none"
    if [[ -n "${target_range}" ]]; then
        before_fp="present:${target_range}"
    else
        local max_uid=100000
        local f
        for f in "${SUBUID_FILE}" "${SUBGID_FILE}"; do
            if [[ -s "${f}" ]]; then
                while IFS=: read -r _ start count; do
                    if [[ -n "${start}" && "${start}" =~ ^[0-9]+$ ]]; then
                        local end=$(( start + ${count:-65536} ))
                        if [[ ${end} -gt ${max_uid} ]]; then
                            max_uid=${end}
                        fi
                    fi
                done < "${f}"
            fi
        done
        local new_start="${OPSKIT_SUBUID_START:-${max_uid}}"
        local count="${OPSKIT_SUBUID_COUNT:-65536}"
        target_range="${new_start}:${count}"
    fi

    local subuid_added=false subgid_added=false
    if [[ -z "${existing_subuid}" ]]; then
        echo "${SERVICE_USER}:${target_range}" >> "${SUBUID_FILE}"
        subuid_added=true
    elif ${prior_subuid} || ${pre_apply_sysusers_marker} || ! ${SUBUID_ENTRY_PRESENT:-false}; then
        subuid_added=true
    fi
    if [[ -z "${existing_subgid}" ]]; then
        echo "${SERVICE_USER}:${target_range}" >> "${SUBGID_FILE}"
        subgid_added=true
    elif ${prior_subgid} || ${pre_apply_sysusers_marker} || ! ${SUBGID_ENTRY_PRESENT:-false}; then
        subgid_added=true
    fi

    local alloc_flag=false
    if ${subuid_added} && ${subgid_added}; then
        alloc_flag=true
    fi
    record_mutation "subuid_allocation" "H" "${before_fp}" "${target_range}" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"range\":\"${target_range}\",\"allocated\":${alloc_flag},\"subuid_allocated\":${subuid_added},\"subgid_allocated\":${subgid_added},\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
    log_info "Configured subuid/subgid range ${target_range} for '${SERVICE_USER}' (subuid_owned=${subuid_added}, subgid_owned=${subgid_added})."
}

install_edge_socket_units() {
    mkdir -p "${SYSTEMD_SYSTEM_DIR}"

    expected_edge_443_socket > "${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket"
    expected_edge_80_socket > "${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket"

    chmod 0644 "${SYSTEMD_SYSTEM_DIR}/opskit-edge-"*.socket
    chown root:root "${SYSTEMD_SYSTEM_DIR}/opskit-edge-"*.socket

    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable --now opskit-edge-443.socket opskit-edge-80.socket
        systemctl is-active --quiet opskit-edge-443.socket || die "${EXIT_RUNTIME_ERROR}" "opskit-edge-443.socket failed to activate"
        systemctl is-active --quiet opskit-edge-80.socket || die "${EXIT_RUNTIME_ERROR}" "opskit-edge-80.socket failed to activate"
    fi

    record_mutation "edge_socket_units" "H" "absent" "installed" "${PLAN_HASH}" "{\"units\":[\"opskit-edge-443.socket\",\"opskit-edge-80.socket\"],\"profile\":\"direct\"}"
    log_info "Installed root-owned socket units for ports 443 and 80."
}

install_edge_system_unit() {
    mkdir -p "${SYSTEMD_SYSTEM_DIR}"

    expected_edge_system_service > "${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"

    chmod 0644 "${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"
    chown root:root "${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"

    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi

    record_mutation "edge_system_unit" "H" "absent" "installed" "${PLAN_HASH}" "{\"unit\":\"opskit-edge.service\",\"profile\":\"direct\"}"
    log_info "Installed root-owned edge service unit with User=${SERVICE_USER}."
}

install_firewall_rules() {
    log_info "Applying firewall allowances for ports 443 and 80 in ${FIREWALL_STACK}..."
    local prior_r443_owned="false" prior_r80_owned="false"
    if [[ -f "${LEDGER_FILE}" ]]; then
        local prior_owned
        prior_owned="$(python3 -B -c "
import json, sys
r443 = 'false'
r80 = 'false'
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if d.get('mutation_id') == 'firewall_rules':
                md = d.get('metadata', {})
                a = md.get('rule443', {})
                b = md.get('rule80', {})
                if isinstance(a, dict) and a.get('stack') == 'firewalld' and not a.get('pre_existing', False):
                    r443 = 'true'
                if isinstance(b, dict) and b.get('stack') == 'firewalld' and not b.get('pre_existing', False):
                    r80 = 'true'
        except Exception:
            pass
print(f'{r443}:{r80}')
" "${LEDGER_FILE}" 2>/dev/null || echo "false:false")"
        IFS=: read -r prior_r443_owned prior_r80_owned <<< "${prior_owned}"
    fi
    local rule443 rule80
    rule443="$(family_apply_firewall_rule 443 tcp "${prior_r443_owned}")"
    rule80="$(family_apply_firewall_rule 80 tcp "${prior_r80_owned}")"

    record_mutation "firewall_rules" "H" "default" "allowed:443,80" "${PLAN_HASH}" "{\"rule443\":${rule443},\"rule80\":${rule80},\"profile\":\"direct\"}"
}

install_user_units() {
    local target_dir="$1"

    expected_user_cloud_service > "${target_dir}/opskit-cloud.service"

    if [[ "${CHOSEN_PROFILE}" != "direct" ]]; then
        expected_user_edge_service > "${target_dir}/opskit-edge.service"
    fi

    chmod 0644 "${target_dir}/opskit-"*.service
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${target_dir}"
    fi

    record_mutation "service_units" "U" "absent" "installed" "${PLAN_HASH}" "{\"directory\":\"${target_dir}\",\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
}

install_cloudflared_unit() {
    local target_dir="$1"
    expected_user_cloudflared_service > "${target_dir}/cloudflared.service"
    chmod 0644 "${target_dir}/cloudflared.service"
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${target_dir}/cloudflared.service"
    fi
    record_mutation "cloudflared_unit" "U" "absent" "installed" "${PLAN_HASH}" "{\"unit\":\"cloudflared.service\",\"profile\":\"tunnel\"}"
}

apply_security_labels() {
    log_info "Applying SELinux container storage context to ${SERVICE_STATE_DIR}..."
    if command -v chcon >/dev/null 2>&1; then
        chcon -R -t container_file_t "${SERVICE_STATE_DIR}" 2>/dev/null || true
    fi
    record_mutation "security_labels" "H" "default" "container_file_t" "${PLAN_HASH}" "{\"context\":\"container_file_t\",\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
}
