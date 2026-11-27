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

    # Vendor uninstaller and state directory BEFORE any mutation so partial failures remain reversible
    vendor_uninstaller

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
        if ${DOCKER_ROOTLESS_PACKAGE_NEEDED:-false}; then
            local rd_pkg
            for rd_pkg in $(family_rootless_docker_packages); do
                pkgs+=("${rd_pkg}")
            done
        fi
        if [[ ${#pkgs[@]} -eq 0 ]] && [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_TEST_FORCE_PACKAGES:-0}" == "1" ]]; then
            case "${DETECTED_FAMILY}" in
                debian) pkgs=("podman" "uidmap") ;;
                rhel) pkgs=("podman" "shadow-utils") ;;
                sles) pkgs=("podman" "shadow") ;;
            esac
        fi
        family_install_packages "${pkgs[@]}" || die "${EXIT_RUNTIME_ERROR}" "Failed to install required container runtime packages: ${pkgs[*]}."
        if [[ "${DETECTED_RUNTIME}" == "docker" ]] && ! ${DOCKER_ROOTLESS_USABLE:-false}; then
            if ! command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1 || ! command -v rootlesskit >/dev/null 2>&1; then
                die "${EXIT_VALIDATION_ERROR}" "Rootless Docker setup tools (dockerd-rootless-setuptool.sh and rootlesskit) are unavailable after package installation; cannot convert pre-installed Docker to rootless mode."
            fi
        fi
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
            record_mutation "service_user" "H" "absent" "present:uid=${u_uid}:gid=${u_gid}" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"group\":\"$(json_escape "${SERVICE_GROUP}")\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        elif [[ -f "/etc/sysusers.d/${SERVICE_USER}.conf" ]]; then
            u_uid="$(id -u "${SERVICE_USER}")"
            u_gid="$(id -g "${SERVICE_USER}")"
            user_created_by_opskit=true
            record_mutation "service_user" "H" "absent" "present:uid=${u_uid}:gid=${u_gid}" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"group\":\"$(json_escape "${SERVICE_GROUP}")\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        else
            u_uid="$(id -u "${SERVICE_USER}")"
            u_gid="$(id -g "${SERVICE_USER}")"
            record_mutation "service_user" "H" "present:uid=${u_uid}:gid=${u_gid}" "present:uid=${u_uid}:gid=${u_gid}" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"group\":\"$(json_escape "${SERVICE_GROUP}")\",\"created\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded pre-existing service account '${SERVICE_USER}' (uid=${u_uid}, preserved on purge)."
        fi
    fi

    # 3. Subuid / Subgid allocation
    if is_mutation_planned "subuid_allocation"; then
        allocate_subordinate_ids "${user_created_by_opskit}" "${pre_apply_sysusers_marker}"
    fi

    # 3b. Systemd cgroup v2 delegation (before linger starts user@.service)
    if is_mutation_planned "cgroup_delegation"; then
        apply_cgroup_delegation
    fi

    # 4. User linger (anchor ownership to pre-apply LINGER_ACTIVE verdict)
    if is_mutation_planned "user_linger"; then
        if ${LINGER_ACTIVE:-false} && ! ${pre_apply_sysusers_marker}; then
            record_mutation "user_linger" "H" "present:enabled" "enabled" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"enabled\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded pre-existing systemd user linger for '${SERVICE_USER}' (preserved on purge)."
        elif [[ -f "/var/lib/systemd/linger/${SERVICE_USER}" && ! -f "/etc/sysusers.d/${SERVICE_USER}.conf" ]] && ! ${user_created_by_opskit}; then
            record_mutation "user_linger" "H" "present:enabled" "enabled" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"enabled\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded pre-existing systemd user linger for '${SERVICE_USER}' (preserved on purge)."
        else
            log_info "Enabling systemd user linger for '${SERVICE_USER}'..."
            if ${SYSTEMD_RUNNING} && [[ -S /run/dbus/system_bus_socket ]] && command -v loginctl >/dev/null 2>&1; then
                loginctl enable-linger "${SERVICE_USER}" || die "${EXIT_RUNTIME_ERROR}" "Failed to enable systemd user linger for '${SERVICE_USER}'."
            elif command -v loginctl >/dev/null 2>&1; then
                loginctl enable-linger "${SERVICE_USER}" 2>/dev/null || true
            fi
            mkdir -p /var/lib/systemd/linger
            touch "/var/lib/systemd/linger/${SERVICE_USER}"
            record_mutation "user_linger" "H" "disabled" "enabled" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"enabled\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        fi
    fi

    # Create service state directory non-recursively (never create versions/current as a directory)
    ensure_safe_dir_no_symlink "${SERVICE_STATE_DIR}"
    if [[ ! -d "${SERVICE_STATE_DIR}" ]]; then
        mkdir -p "${SERVICE_STATE_DIR}"
        chmod 0750 "${SERVICE_STATE_DIR}"
        if id "${SERVICE_USER}" >/dev/null 2>&1; then
            chown "${SERVICE_USER}:${SERVICE_GROUP}" "${SERVICE_STATE_DIR}"
        fi
    fi
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        run_as_service_user '
            set -eu
            for d in "$@"; do
                mkdir -p "$d"
                chmod 0750 "$d"
            done
        ' "${SERVICE_STATE_DIR}/edge" "${SERVICE_STATE_DIR}/versions" "${SERVICE_STATE_DIR}/logs" "${SERVICE_STATE_DIR}/state"
    fi

    # User systemd config directory (created strictly as SERVICE_USER)
    local svc_home user_systemd_dir
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    user_systemd_dir="${svc_home}/.config/systemd/user"
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        run_as_service_user '
            set -eu
            mkdir -p "$1"
            chmod 0755 "$1"
        ' "${user_systemd_dir}"
    fi

    # 4b. Rootless Docker provisioning (when Docker is selected)
    if [[ "${DETECTED_RUNTIME}" == "docker" ]] && is_mutation_planned "rootless_docker"; then
        provision_rootless_docker
    fi

    # 5a. Fetch verified CLI and versioned opskit-edge binary BEFORE unit/socket activation
    if is_mutation_planned "fetch_cli"; then
        verify_and_install_cli
        local after_fp="${CLI_MUTATION_AFTER_FP:-installed:${CLI_INSTALL_PATH}}"
        local before_fp="${CLI_MUTATION_BEFORE_FP:-absent}"
        record_mutation "fetch_cli" "H" "${before_fp}" "${after_fp}" "${PLAN_HASH}" "${CLI_MUTATION_METADATA}"
    fi

    # 5b. Direct profile: system edge unit FIRST, then socket units, then firewall rules
    if [[ "${CHOSEN_PROFILE}" == "direct" ]]; then
        is_mutation_planned "edge_system_unit" && install_edge_system_unit
        is_mutation_planned "edge_socket_units" && install_edge_socket_units
        is_mutation_planned "firewall_rules" && install_firewall_rules
    fi

    # 8. User exposure unit (tunnel/private profiles only)
    if [[ "${CHOSEN_PROFILE}" != "direct" ]]; then
        is_mutation_planned "service_units" && install_user_units "${user_systemd_dir}"
    fi

    # 9. Tunnel profile: cloudflared user unit template
    if [[ "${CHOSEN_PROFILE}" == "tunnel" ]]; then
        is_mutation_planned "cloudflared_unit" && install_cloudflared_unit "${user_systemd_dir}"
    fi

    # 10. Security labels
    if is_mutation_planned "security_labels"; then
        apply_security_labels
    fi

    # 12. Fail-closed runtime and cgroup delegation verification
    verify_rootless_runtime_and_delegation

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
            record_mutation "subuid_allocation" "H" "none" "${existing_subuid}" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"range\":\"$(json_escape "${existing_subuid}")\",\"allocated\":true,\"subuid_allocated\":true,\"subgid_allocated\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        else
            record_mutation "subuid_allocation" "H" "present:${existing_subuid}" "${existing_subuid}" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"range\":\"$(json_escape "${existing_subuid}")\",\"allocated\":${alloc_all},\"subuid_allocated\":${subuid_owned},\"subgid_allocated\":${subgid_owned},\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
            log_info "Recorded existing subuid/subgid range ${existing_subuid} for '${SERVICE_USER}' (subuid_owned=${subuid_owned}, subgid_owned=${subgid_owned})."
        fi
        return 0
    fi

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
                    if [[ -n "${start}" && "${start}" =~ ^[0-9]+$ && "${count:-65536}" =~ ^[0-9]+$ ]]; then
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
        if [[ ! "${new_start}" =~ ^[0-9]+$ || ! "${count}" =~ ^[0-9]+$ || "${count}" -le 0 || $(( new_start + count )) -gt 4294967295 ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Calculated subordinate UID/GID range (${new_start}:${count}) exceeds 32-bit UID space."
        fi
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
    record_mutation "subuid_allocation" "H" "${before_fp}" "${target_range}" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"range\":\"$(json_escape "${target_range}")\",\"allocated\":${alloc_flag},\"subuid_allocated\":${subuid_added},\"subgid_allocated\":${subgid_added},\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
    log_info "Configured subuid/subgid range ${target_range} for '${SERVICE_USER}' (subuid_owned=${subuid_added}, subgid_owned=${subgid_added})."
}

install_edge_system_unit() {
    mkdir -p "${SYSTEMD_SYSTEM_DIR}"
    local svc_path="${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"
    local before_fp="absent"
    if [[ -f "${svc_path}" ]]; then
        before_fp="sha256:$(compute_sha256 "${svc_path}")"
    fi

    expected_edge_system_service > "${svc_path}"
    chmod 0644 "${svc_path}"
    chown root:root "${svc_path}"

    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi

    local unit_sha
    unit_sha="$(compute_sha256 "${svc_path}")"
    local http_80_bool="true"
    [[ "${FLAG_NO_HTTP:-false}" == "true" ]] && http_80_bool="false"
    record_mutation "edge_system_unit" "H" "${before_fp}" "sha256:${unit_sha}" "${PLAN_HASH}" "{\"unit\":\"opskit-edge.service\",\"sha256\":\"${unit_sha}\",\"http_80\":${http_80_bool},\"profile\":\"direct\"}"
    log_info "Installed root-owned hardened edge service unit with User=${SERVICE_USER}."
}

install_edge_socket_units() {
    mkdir -p "${SYSTEMD_SYSTEM_DIR}"
    local s443="${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket"
    local s80="${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket"

    local before_443="absent" before_80="absent"
    [[ -f "${s443}" ]] && before_443="$(compute_sha256 "${s443}")"
    [[ -f "${s80}" ]] && before_80="$(compute_sha256 "${s80}")"
    local before_fp="absent"
    if [[ "${before_443}" != "absent" || "${before_80}" != "absent" ]]; then
        before_fp="sha256:$(compute_sha256 "${before_443}:${before_80}")"
    fi

    expected_edge_443_socket > "${s443}"
    chmod 0644 "${s443}"
    chown root:root "${s443}"

    local active_units=("opskit-edge-443.socket")
    local http_80_bool="true"
    if [[ "${FLAG_NO_HTTP:-false}" == "true" ]]; then
        http_80_bool="false"
        if [[ -f "${s80}" ]]; then
            if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
                systemctl disable --now opskit-edge-80.socket 2>/dev/null || true
            fi
            rm -f "${s80}"
        fi
    else
        expected_edge_80_socket > "${s80}"
        chmod 0644 "${s80}"
        chown root:root "${s80}"
        active_units+=("opskit-edge-80.socket")
    fi

    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable --now "${active_units[@]}"
        local u
        for u in "${active_units[@]}"; do
            systemctl is-active --quiet "${u}" || die "${EXIT_RUNTIME_ERROR}" "${u} failed to activate"
        done
    fi

    local sha443 sha80="absent" combined_sha units_json sha_map_json
    sha443="$(compute_sha256 "${s443}")"
    if [[ "${http_80_bool}" == "true" ]]; then
        sha80="$(compute_sha256 "${s80}")"
        combined_sha="$(compute_sha256 "${sha443}:${sha80}")"
        units_json='["opskit-edge-443.socket","opskit-edge-80.socket"]'
        sha_map_json="{\"opskit-edge-443.socket\":\"${sha443}\",\"opskit-edge-80.socket\":\"${sha80}\"}"
    else
        combined_sha="${sha443}"
        units_json='["opskit-edge-443.socket"]'
        sha_map_json="{\"opskit-edge-443.socket\":\"${sha443}\"}"
    fi

    record_mutation "edge_socket_units" "H" "${before_fp}" "sha256:${combined_sha}" "${PLAN_HASH}" "{\"units\":${units_json},\"unit_sha256\":${sha_map_json},\"http_80\":${http_80_bool},\"profile\":\"direct\"}"
    log_info "Installed root-owned socket unit(s): ${active_units[*]}."
}

install_firewall_rules() {
    local http_80_bool="true"
    [[ "${FLAG_NO_HTTP:-false}" == "true" ]] && http_80_bool="false"
    if [[ "${http_80_bool}" == "true" ]]; then
        log_info "Applying firewall allowances for ports 443 and 80 in ${FIREWALL_STACK}..."
    else
        log_info "Applying firewall allowance for port 443 in ${FIREWALL_STACK}..."
    fi

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

    local pre_fw_fp="absent"
    if [[ "${FIREWALL_STACK}" == "nftables" ]] && command -v nft >/dev/null 2>&1; then
        pre_fw_fp="sha256:$(compute_sha256 "$(nft list table inet opskit 2>/dev/null || echo none)")"
    elif [[ "${FIREWALL_STACK}" == "iptables" ]] && command -v iptables >/dev/null 2>&1; then
        pre_fw_fp="sha256:$(compute_sha256 "$(iptables -S INPUT 2>/dev/null || echo none)")"
    elif [[ "${FIREWALL_STACK}" == "ufw" ]] && command -v ufw >/dev/null 2>&1; then
        pre_fw_fp="sha256:$(compute_sha256 "$(ufw status 2>/dev/null || echo none)")"
    elif [[ "${FIREWALL_STACK}" == "firewalld" ]] && command -v firewall-cmd >/dev/null 2>&1; then
        pre_fw_fp="sha256:$(compute_sha256 "$(firewall-cmd --list-ports 2>/dev/null || echo none)")"
    fi

    local rule443 rule80
    rule443="$(family_apply_firewall_rule 443 tcp "${prior_r443_owned}")"
    if [[ "${http_80_bool}" == "true" ]]; then
        rule80="$(family_apply_firewall_rule 80 tcp "${prior_r80_owned}")"
        record_mutation "firewall_rules" "H" "${pre_fw_fp}" "allowed:443,80" "${PLAN_HASH}" "{\"rule443\":${rule443},\"rule80\":${rule80},\"http_80\":true,\"profile\":\"direct\"}"
    else
        record_mutation "firewall_rules" "H" "${pre_fw_fp}" "allowed:443" "${PLAN_HASH}" "{\"rule443\":${rule443},\"http_80\":false,\"profile\":\"direct\"}"
    fi
}

install_user_units() {
    local target_dir="$1"
    expected_user_edge_service | write_user_file "${target_dir}/opskit-edge.service" 0644
    local unit_sha
    unit_sha="$(compute_sha256 "${target_dir}/opskit-edge.service")"
    record_mutation "service_units" "U" "absent" "sha256:${unit_sha}" "${PLAN_HASH}" "{\"directory\":\"$(json_escape "${target_dir}")\",\"unit\":\"opskit-edge.service\",\"sha256\":\"${unit_sha}\",\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
}

install_cloudflared_unit() {
    local target_dir="$1"
    expected_user_cloudflared_service | write_user_file "${target_dir}/cloudflared.service" 0644
    local unit_sha
    unit_sha="$(compute_sha256 "${target_dir}/cloudflared.service")"
    record_mutation "cloudflared_unit" "U" "absent" "sha256:${unit_sha}" "${PLAN_HASH}" "{\"unit\":\"cloudflared.service\",\"sha256\":\"${unit_sha}\",\"profile\":\"tunnel\"}"
}

apply_security_labels() {
    log_info "Applying SELinux container storage context to ${SERVICE_STATE_DIR}..."
    if command -v chcon >/dev/null 2>&1; then
        chcon -R -t container_file_t "${SERVICE_STATE_DIR}" 2>/dev/null || true
    fi
    record_mutation "security_labels" "H" "default" "container_file_t" "${PLAN_HASH}" "{\"context\":\"container_file_t\",\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
}

apply_cgroup_delegation() {
    # Upstream systemd cgroup v2 delegation for per-user service managers:
    # https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
    local dropin_dir="${SYSTEMD_SYSTEM_DIR}/user@.service.d"
    local dropin_file="${dropin_dir}/opskit-delegate.conf"
    local svc_uid=""
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        svc_uid="$(id -u "${SERVICE_USER}")"
    fi

    if [[ ! -f "${dropin_file}" ]] && has_systemd_delegate_yes "${svc_uid}"; then
        if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload 2>/dev/null || true
            if [[ -n "${svc_uid}" ]] && systemctl is-active --quiet "user@${svc_uid}.service" 2>/dev/null; then
                local del_ctrls=""
                del_ctrls="$(systemctl show "user@${svc_uid}.service" -p DelegateControllers --value 2>/dev/null || true)"
                if [[ "${del_ctrls}" != *"memory"* || "${del_ctrls}" != *"cpu"* || "${del_ctrls}" != *"pids"* ]]; then
                    systemctl restart "user@${svc_uid}.service" || die "${EXIT_RUNTIME_ERROR}" "Failed to restart user@${svc_uid}.service to activate cgroup delegation."
                fi
            fi
        fi
        record_mutation "cgroup_delegation" "H" "present:admin" "present:delegate=yes" "${PLAN_HASH}" "{\"dropin\":\"$(json_escape "${dropin_file}")\",\"created\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        log_info "Recorded pre-existing systemd cgroup delegation configuration (preserved on purge)."
        return 0
    fi

    mkdir -p "${dropin_dir}"
    chmod 0755 "${dropin_dir}"
    expected_cgroup_delegate_conf > "${dropin_file}"
    chmod 0644 "${dropin_file}"
    if [[ "${EUID}" -eq 0 ]]; then
        chown root:root "${dropin_file}"
    fi

    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        if [[ -n "${svc_uid}" ]] && systemctl is-active --quiet "user@${svc_uid}.service" 2>/dev/null; then
            systemctl restart "user@${svc_uid}.service" || die "${EXIT_RUNTIME_ERROR}" "Failed to restart user@${svc_uid}.service to activate cgroup delegation."
        fi
    fi

    record_mutation "cgroup_delegation" "H" "absent" "present:delegate=yes" "${PLAN_HASH}" "{\"dropin\":\"$(json_escape "${dropin_file}")\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
    log_info "Configured systemd cgroup v2 delegation (Delegate=yes) at '${dropin_file}'."
}

provision_rootless_docker() {
    # Upstream rootless Docker provisioning via dockerd-rootless-setuptool.sh:
    # https://docs.docker.com/engine/security/rootless/
    if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot provision rootless Docker: service user '${SERVICE_USER}' does not exist."
    fi
    local svc_uid svc_home
    svc_uid="$(id -u "${SERVICE_USER}")"
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    local docker_env_dir="${svc_home}/.config/environment.d"
    local docker_env_file="${docker_env_dir}/opskit-docker.conf"

    if ${DOCKER_ROOTLESS_USABLE:-false}; then
        local existing_sock
        existing_sock="$(resolve_service_user_docker_socket "${SERVICE_USER}")"
        if [[ ! -f "${docker_env_file}" ]] && ! grep -qhE '^[[:space:]]*DOCKER_HOST=' "${docker_env_dir}"/*.conf 2>/dev/null; then
            printf 'DOCKER_HOST=unix://%s\n' "${existing_sock:-/run/user/${svc_uid}/docker.sock}" | write_user_file "${docker_env_file}" 0644
        fi
        local eff_sock="${existing_sock:-/run/user/${svc_uid}/docker.sock}"
        record_mutation "rootless_docker" "U" "present:rootless" "present:rootless" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"socket\":\"$(json_escape "${eff_sock}")\",\"env_file\":\"$(json_escape "${docker_env_file}")\",\"created\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
        log_info "Recorded pre-existing rootless Docker setup for '${SERVICE_USER}' (preserved on purge)."
        return 0
    fi

    if ! command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1 || ! command -v rootlesskit >/dev/null 2>&1; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot convert pre-installed Docker to rootless mode: dockerd-rootless-setuptool.sh or rootlesskit not found."
    fi
    if ! command -v newuidmap >/dev/null 2>&1 || ! command -v newgidmap >/dev/null 2>&1; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot convert pre-installed Docker to rootless mode: newuidmap/newgidmap not found."
    fi
    if ! grep -q "^${SERVICE_USER}:" "${SUBUID_FILE}" 2>/dev/null || ! grep -q "^${SERVICE_USER}:" "${SUBGID_FILE}" 2>/dev/null; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot convert pre-installed Docker to rootless mode: subordinate UID/GID mapping missing for '${SERVICE_USER}'."
    fi

    if ${SYSTEMD_RUNNING} && [[ -S /run/dbus/system_bus_socket ]]; then
        local wait_i=0
        while [[ ! -d "/run/user/${svc_uid}" && ${wait_i} -lt 10 ]]; do
            sleep 0.5
            wait_i=$((wait_i + 1))
        done
    fi

    log_info "Provisioning rootless Docker for '${SERVICE_USER}' via dockerd-rootless-setuptool.sh..."
    local setup_out="" setup_rc=0
    setup_out="$(run_as_service_user '
        set -eu
        export HOME="$1"
        if [ -d "$2" ]; then
            export XDG_RUNTIME_DIR="$2"
            export DBUS_SESSION_BUS_ADDRESS="unix:path=$2/bus"
        fi
        dockerd-rootless-setuptool.sh install
    ' "${svc_home}" "/run/user/${svc_uid}" 2>&1)" || setup_rc=$?

    if [[ ${setup_rc} -ne 0 ]]; then
        die "${EXIT_RUNTIME_ERROR}" "Rootless Docker provisioning failed for '${SERVICE_USER}' (exit ${setup_rc}): ${setup_out}"
    fi

    # Persist DOCKER_HOST in systemd user environment.d
    # Upstream environment.d(5): https://www.freedesktop.org/software/systemd/man/latest/environment.d.html
    local rootless_sock="/run/user/${svc_uid}/docker.sock"
    if [[ ! -d "/run/user/${svc_uid}" && -d "${svc_home}/.docker/run" ]]; then
        rootless_sock="${svc_home}/.docker/run/docker.sock"
    fi
    printf 'DOCKER_HOST=unix://%s\n' "${rootless_sock}" | write_user_file "${docker_env_file}" 0644

    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        systemctl --user --machine="${SERVICE_USER}@" set-environment "DOCKER_HOST=unix://${rootless_sock}" 2>/dev/null || true
        if [[ -f "${svc_home}/.config/systemd/user/docker.service" ]]; then
            systemctl --user --machine="${SERVICE_USER}@" start docker.service 2>/dev/null || true
        fi
    fi

    local sock_wait=0
    while [[ ! -S "${rootless_sock}" && ${sock_wait} -lt 20 ]]; do
        sleep 0.5
        sock_wait=$((sock_wait + 1))
    done

    record_mutation "rootless_docker" "U" "absent" "present:rootless" "${PLAN_HASH}" "{\"user\":\"$(json_escape "${SERVICE_USER}")\",\"socket\":\"$(json_escape "${rootless_sock}")\",\"env_file\":\"$(json_escape "${docker_env_file}")\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
    log_info "Provisioned rootless Docker for '${SERVICE_USER}' at '${rootless_sock}'."
}

verify_rootless_runtime_and_delegation() {
    if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
        die "${EXIT_RUNTIME_ERROR}" "Runtime verification failed: service user '${SERVICE_USER}' does not exist."
    fi
    local svc_uid svc_home
    svc_uid="$(id -u "${SERVICE_USER}")"
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"

    # 1. Verify cgroup delegation configuration and active systemd user delegation
    if ! has_systemd_delegate_yes "${svc_uid}"; then
        die "${EXIT_RUNTIME_ERROR}" "Cgroup delegation verification failed: Delegate=yes is not configured for user@.service."
    fi
    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active --quiet "user@${svc_uid}.service" 2>/dev/null && [[ -S /run/dbus/system_bus_socket ]]; then
            systemctl start "user@${svc_uid}.service" 2>/dev/null || true
        fi
        if systemctl is-active --quiet "user@${svc_uid}.service" 2>/dev/null; then
            local del_ctrls=""
            del_ctrls="$(systemctl show "user@${svc_uid}.service" -p DelegateControllers --value 2>/dev/null || true)"
            if [[ "${del_ctrls}" != *"memory"* || "${del_ctrls}" != *"cpu"* || "${del_ctrls}" != *"pids"* ]]; then
                die "${EXIT_RUNTIME_ERROR}" "Cgroup delegation verification failed: user@${svc_uid}.service DelegateControllers='${del_ctrls}' lacks required memory/cpu/pids controllers."
            fi
        elif [[ -S /run/dbus/system_bus_socket ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Cgroup delegation verification failed: user@${svc_uid}.service is inactive under systemd."
        fi
    fi

    # 2. Verify chosen runtime is rootless-functional as SERVICE_USER
    if [[ "${DETECTED_RUNTIME}" == "docker" ]]; then
        local sock
        sock="$(resolve_service_user_docker_socket "${SERVICE_USER}")"
        if [[ -z "${sock}" || ! -S "${sock}" ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Rootless Docker verification failed: rootless socket '${sock:-<unset>}' for '${SERVICE_USER}' does not exist. Cannot fall back to rootful /var/run/docker.sock."
        fi
        local sec_opts=""
        sec_opts="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" DOCKER_HOST="unix://$3" docker info --format "{{.SecurityOptions}}"' "${svc_home}" "/run/user/${svc_uid}" "${sock}" 2>/dev/null || true)"
        if [[ "${sec_opts}" != *"rootless"* ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Rootless Docker verification failed: 'docker info' as '${SERVICE_USER}' on '${sock}' did not report rootless mode (SecurityOptions='${sec_opts}')."
        fi

        local verify_img="${OPSKIT_VERIFY_IMAGE:-}"
        local explicit_verify_img=false
        [[ -n "${verify_img}" ]] && explicit_verify_img=true
        if [[ -z "${verify_img}" ]]; then
            verify_img="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" DOCKER_HOST="unix://$3" docker images -q 2>/dev/null | head -n1' "${svc_home}" "/run/user/${svc_uid}" "${sock}" 2>/dev/null || true)"
        fi
        if [[ -n "${verify_img}" ]]; then
            if [[ ! "${verify_img}" =~ ^[A-Za-z0-9._:/@-]+$ ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Invalid container image identifier '${verify_img}'."
            fi
            local mem_out=""
            mem_out="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" DOCKER_HOST="unix://$3" docker run --rm --network none --memory 33554432 --entrypoint "" "$4" /bin/sh -c "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null"' "${svc_home}" "/run/user/${svc_uid}" "${sock}" "${verify_img}" 2>/dev/null | tr -d '[:space:]' || true)"
            if [[ -n "${mem_out}" || ${explicit_verify_img} == true ]]; then
                if [[ ! "${mem_out}" =~ ^[0-9]+$ ]] || [[ "${mem_out}" -gt 33554432 ]]; then
                    die "${EXIT_RUNTIME_ERROR}" "Rootless Docker cgroup memory limit verification failed (expected <= 33554432, got '${mem_out:-empty}')."
                fi
            fi
        fi
        log_info "Verified rootless Docker functionality and cgroup delegation for '${SERVICE_USER}'."
    elif [[ "${DETECTED_RUNTIME}" == "podman" ]]; then
        if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" ]] && ! ${SYSTEMD_RUNNING} && [[ "${OPSKIT_FORCE_RUNTIME_VERIFY:-0}" != "1" ]]; then
            command -v podman >/dev/null 2>&1 || die "${EXIT_RUNTIME_ERROR}" "Podman binary not found after bootstrap."
            command -v newuidmap >/dev/null 2>&1 || die "${EXIT_RUNTIME_ERROR}" "newuidmap not found after bootstrap."
            log_info "Verified cgroup delegation config and Podman prerequisites for '${SERVICE_USER}' (container test mode without systemd PID 1)."
            return 0
        fi
        local rootless_flag=""
        local podman_extra=""
        rootless_flag="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" podman info --format "{{.Host.Security.Rootless}}"' "${svc_home}" "/run/user/${svc_uid}" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "${rootless_flag}" != "true" && "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" ]]; then
            podman_extra="--storage-driver vfs"
            rootless_flag="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" podman --storage-driver vfs info --format "{{.Host.Security.Rootless}}"' "${svc_home}" "/run/user/${svc_uid}" 2>/dev/null | tr -d '[:space:]' || true)"
        fi
        if [[ "${rootless_flag}" != "true" ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Rootless Podman verification failed for '${SERVICE_USER}' (Rootless='${rootless_flag}')."
        fi
        local verify_img="${OPSKIT_VERIFY_IMAGE:-}"
        local explicit_verify_img=false
        [[ -n "${verify_img}" ]] && explicit_verify_img=true
        if [[ -z "${verify_img}" ]]; then
            if [[ -n "${podman_extra}" ]]; then
                verify_img="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" podman --storage-driver vfs images -q 2>/dev/null | head -n1' "${svc_home}" "/run/user/${svc_uid}" 2>/dev/null || true)"
            else
                verify_img="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" podman images -q 2>/dev/null | head -n1' "${svc_home}" "/run/user/${svc_uid}" 2>/dev/null || true)"
            fi
        fi
        if [[ -n "${verify_img}" ]]; then
            if [[ ! "${verify_img}" =~ ^[A-Za-z0-9._:/@-]+$ ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Invalid container image identifier '${verify_img}'."
            fi
            local mem_out=""
            if [[ -n "${podman_extra}" ]]; then
                mem_out="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" podman --storage-driver vfs run --rm --network none --memory 33554432 --entrypoint "" "$3" /bin/sh -c "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null"' "${svc_home}" "/run/user/${svc_uid}" "${verify_img}" 2>/dev/null | tr -d '[:space:]' || true)"
            else
                mem_out="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" podman run --rm --network none --memory 33554432 --entrypoint "" "$3" /bin/sh -c "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null"' "${svc_home}" "/run/user/${svc_uid}" "${verify_img}" 2>/dev/null | tr -d '[:space:]' || true)"
            fi
            if [[ -n "${mem_out}" || ${explicit_verify_img} == true ]]; then
                if [[ ! "${mem_out}" =~ ^[0-9]+$ ]] || [[ "${mem_out}" -gt 33554432 ]]; then
                    die "${EXIT_RUNTIME_ERROR}" "Rootless Podman cgroup memory limit verification failed (expected <= 33554432, got '${mem_out:-empty}')."
                fi
            fi
        fi
        log_info "Verified rootless Podman functionality and cgroup delegation for '${SERVICE_USER}'."
    fi
}
