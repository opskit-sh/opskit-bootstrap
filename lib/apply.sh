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
        if ${DOCKER_ROOTLESS_PACKAGE_NEEDED:-false}; then
            local rd_pkg
            for rd_pkg in $(family_rootless_docker_packages); do
                pkgs+=("${rd_pkg}")
            done
        fi
        if [[ ${#pkgs[@]} -eq 0 ]] && [[ "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_TEST_FORCE_PACKAGES:-0}" == "1" ]]; then
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

    # 3b. Systemd cgroup v2 delegation (before linger starts user@.service)
    if is_mutation_planned "cgroup_delegation"; then
        apply_cgroup_delegation
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

    # 4b. Rootless Docker provisioning (when Docker is selected)
    if [[ "${DETECTED_RUNTIME}" == "docker" ]] && is_mutation_planned "rootless_docker"; then
        provision_rootless_docker
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

    # 12. Fail-closed runtime and cgroup delegation verification
    verify_rootless_runtime_and_delegation

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

apply_cgroup_delegation() {
    # Upstream systemd cgroup v2 delegation for per-user service managers:
    # https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
    local dropin_dir="${SYSTEMD_SYSTEM_DIR}/user@.service.d"
    local dropin_file="${dropin_dir}/opskit-delegate.conf"
    local svc_uid=""
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        svc_uid="$(id -u "${SERVICE_USER}")"
    fi

    # Check if an administrator already configured Delegate=yes outside OpsKit's drop-in
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
        record_mutation "cgroup_delegation" "H" "present:admin" "present:delegate=yes" "${PLAN_HASH}" "{\"dropin\":\"${dropin_file}\",\"created\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
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

    record_mutation "cgroup_delegation" "H" "absent" "present:delegate=yes" "${PLAN_HASH}" "{\"dropin\":\"${dropin_file}\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
    log_info "Configured systemd cgroup v2 delegation (Delegate=yes) at '${dropin_file}'."
}

provision_rootless_docker() {
    # Upstream rootless Docker provisioning via dockerd-rootless-setuptool.sh:
    # https://docs.docker.com/engine/security/rootless/
    if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot provision rootless Docker: service user '${SERVICE_USER}' does not exist."
    fi
    local svc_uid
    svc_uid="$(id -u "${SERVICE_USER}")"
    local docker_env_dir="/home/${SERVICE_USER}/.config/environment.d"
    local docker_env_file="${docker_env_dir}/opskit-docker.conf"

    if ${DOCKER_ROOTLESS_USABLE:-false}; then
        local existing_sock
        existing_sock="$(resolve_service_user_docker_socket "${SERVICE_USER}")"
        if [[ ! -f "${docker_env_file}" ]] && ! grep -qhE '^[[:space:]]*DOCKER_HOST=' "${docker_env_dir}"/*.conf 2>/dev/null; then
            mkdir -p "${docker_env_dir}"
            printf 'DOCKER_HOST=unix://%s\n' "${existing_sock:-/run/user/${svc_uid}/docker.sock}" > "${docker_env_file}"
            chmod 0644 "${docker_env_file}"
            chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${docker_env_dir}"
        fi
        record_mutation "rootless_docker" "U" "present:rootless" "present:rootless" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"socket\":\"${existing_sock:-/run/user/${svc_uid}/docker.sock}\",\"env_file\":\"${docker_env_file}\",\"created\":false,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
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

    # Wait briefly for loginctl enable-linger to populate /run/user/<uid> when systemd + dbus are running
    if ${SYSTEMD_RUNNING} && [[ -S /run/dbus/system_bus_socket ]]; then
        local wait_i=0
        while [[ ! -d "/run/user/${svc_uid}" && ${wait_i} -lt 10 ]]; do
            sleep 0.5
            wait_i=$((wait_i + 1))
        done
    fi

    log_info "Provisioning rootless Docker for '${SERVICE_USER}' via dockerd-rootless-setuptool.sh..."
    local xdg_rt_export=""
    if [[ -d "/run/user/${svc_uid}" ]]; then
        xdg_rt_export="export XDG_RUNTIME_DIR='/run/user/${svc_uid}' DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/${svc_uid}/bus'"
    fi
    local setup_out="" setup_rc=0
    setup_out="$(su -s /bin/bash "${SERVICE_USER}" -c "
        export HOME='/home/${SERVICE_USER}'
        ${xdg_rt_export}
        dockerd-rootless-setuptool.sh install
    " 201>&- 2>&1)" || setup_rc=$?

    if [[ ${setup_rc} -ne 0 ]]; then
        die "${EXIT_RUNTIME_ERROR}" "Rootless Docker provisioning failed for '${SERVICE_USER}' (exit ${setup_rc}): ${setup_out}"
    fi

    # Persist DOCKER_HOST in systemd user environment.d
    # Upstream environment.d(5): https://www.freedesktop.org/software/systemd/man/latest/environment.d.html
    local rootless_sock="/run/user/${svc_uid}/docker.sock"
    if [[ ! -d "/run/user/${svc_uid}" && -d "/home/${SERVICE_USER}/.docker/run" ]]; then
        rootless_sock="/home/${SERVICE_USER}/.docker/run/docker.sock"
    fi
    mkdir -p "${docker_env_dir}"
    printf 'DOCKER_HOST=unix://%s\n' "${rootless_sock}" > "${docker_env_file}"
    chmod 0644 "${docker_env_file}"
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${docker_env_dir}"

    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        systemctl --user --machine="${SERVICE_USER}@" set-environment "DOCKER_HOST=unix://${rootless_sock}" 2>/dev/null || true
        if [[ -f "/home/${SERVICE_USER}/.config/systemd/user/docker.service" ]]; then
            systemctl --user --machine="${SERVICE_USER}@" start docker.service 2>/dev/null || true
        fi
    fi

    local sock_wait=0
    while [[ ! -S "${rootless_sock}" && ${sock_wait} -lt 20 ]]; do
        sleep 0.5
        sock_wait=$((sock_wait + 1))
    done

    record_mutation "rootless_docker" "U" "absent" "present:rootless" "${PLAN_HASH}" "{\"user\":\"${SERVICE_USER}\",\"socket\":\"${rootless_sock}\",\"env_file\":\"${docker_env_file}\",\"created\":true,\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\"}"
    log_info "Provisioned rootless Docker for '${SERVICE_USER}' at '${rootless_sock}'."
}

verify_rootless_runtime_and_delegation() {
    if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
        die "${EXIT_RUNTIME_ERROR}" "Runtime verification failed: service user '${SERVICE_USER}' does not exist."
    fi
    local svc_uid
    svc_uid="$(id -u "${SERVICE_USER}")"

    # 1. Verify cgroup delegation configuration and active systemd user delegation
    if ! has_systemd_delegate_yes "${svc_uid}"; then
        die "${EXIT_RUNTIME_ERROR}" "Cgroup delegation verification failed: Delegate=yes is not configured for user@.service."
    fi
    if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet "user@${svc_uid}.service" 2>/dev/null; then
            local del_ctrls=""
            del_ctrls="$(systemctl show "user@${svc_uid}.service" -p DelegateControllers --value 2>/dev/null || true)"
            if [[ "${del_ctrls}" != *"memory"* || "${del_ctrls}" != *"cpu"* || "${del_ctrls}" != *"pids"* ]]; then
                die "${EXIT_RUNTIME_ERROR}" "Cgroup delegation verification failed: user@${svc_uid}.service DelegateControllers='${del_ctrls}' lacks required memory/cpu/pids controllers."
            fi
        fi
    fi

    # 2. Verify chosen runtime is rootless-functional as SERVICE_USER (and memory limit enforced when an image is present)
    if [[ "${DETECTED_RUNTIME}" == "docker" ]]; then
        local sock
        sock="$(resolve_service_user_docker_socket "${SERVICE_USER}")"
        if [[ -z "${sock}" || ! -S "${sock}" ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Rootless Docker verification failed: rootless socket '${sock:-<unset>}' for '${SERVICE_USER}' does not exist. Cannot fall back to rootful /var/run/docker.sock."
        fi
        local sec_opts=""
        sec_opts="$(su -s /bin/sh "${SERVICE_USER}" -c "HOME='/home/${SERVICE_USER}' XDG_RUNTIME_DIR='/run/user/${svc_uid}' DOCKER_HOST='unix://${sock}' docker info --format '{{.SecurityOptions}}'" 201>&- 2>/dev/null || true)"
        if [[ "${sec_opts}" != *"rootless"* ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Rootless Docker verification failed: 'docker info' as '${SERVICE_USER}' on '${sock}' did not report rootless mode (SecurityOptions='${sec_opts}')."
        fi

        local verify_img="${OPSKIT_VERIFY_IMAGE:-}"
        if [[ -z "${verify_img}" ]]; then
            verify_img="$(su -s /bin/sh "${SERVICE_USER}" -c "HOME='/home/${SERVICE_USER}' XDG_RUNTIME_DIR='/run/user/${svc_uid}' DOCKER_HOST='unix://${sock}' docker images -q 2>/dev/null | head -n1" 201>&- || true)"
        fi
        if [[ -n "${verify_img}" ]]; then
            local mem_out=""
            mem_out="$(su -s /bin/sh "${SERVICE_USER}" -c "HOME='/home/${SERVICE_USER}' XDG_RUNTIME_DIR='/run/user/${svc_uid}' DOCKER_HOST='unix://${sock}' docker run --rm --network none --memory 33554432 '${verify_img}' sh -c 'cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null'" 201>&- 2>/dev/null | tr -d '[:space:]' || true)"
            if [[ ! "${mem_out}" =~ ^[0-9]+$ ]] || [[ "${mem_out}" -gt 33554432 ]]; then
                die "${EXIT_RUNTIME_ERROR}" "Rootless Docker cgroup memory limit verification failed (expected <= 33554432, got '${mem_out:-empty}')."
            fi
        fi
        log_info "Verified rootless Docker functionality and cgroup delegation for '${SERVICE_USER}'."
    elif [[ "${DETECTED_RUNTIME}" == "podman" ]]; then
        if [[ "${OPSKIT_TEST_MODE:-0}" == "1" ]] && ! ${SYSTEMD_RUNNING} && [[ "${OPSKIT_FORCE_RUNTIME_VERIFY:-0}" != "1" ]]; then
            command -v podman >/dev/null 2>&1 || die "${EXIT_RUNTIME_ERROR}" "Podman binary not found after bootstrap."
            command -v newuidmap >/dev/null 2>&1 || die "${EXIT_RUNTIME_ERROR}" "newuidmap not found after bootstrap."
            log_info "Verified cgroup delegation config and Podman prerequisites for '${SERVICE_USER}' (container test mode without systemd PID 1)."
            return 0
        fi
        local rootless_flag=""
        local podman_extra=""
        rootless_flag="$(su -s /bin/sh "${SERVICE_USER}" -c "HOME='/home/${SERVICE_USER}' XDG_RUNTIME_DIR='/run/user/${svc_uid}' podman info --format '{{.Host.Security.Rootless}}'" 201>&- 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "${rootless_flag}" != "true" && "${OPSKIT_TEST_MODE:-0}" == "1" ]]; then
            podman_extra="--storage-driver vfs"
            rootless_flag="$(su -s /bin/sh "${SERVICE_USER}" -c "HOME='/home/${SERVICE_USER}' XDG_RUNTIME_DIR='/run/user/${svc_uid}' podman ${podman_extra} info --format '{{.Host.Security.Rootless}}'" 201>&- 2>/dev/null | tr -d '[:space:]' || true)"
        fi
        if [[ "${rootless_flag}" != "true" ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Rootless Podman verification failed for '${SERVICE_USER}' (Rootless='${rootless_flag}')."
        fi
        local verify_img="${OPSKIT_VERIFY_IMAGE:-}"
        if [[ -z "${verify_img}" ]]; then
            verify_img="$(su -s /bin/sh "${SERVICE_USER}" -c "HOME='/home/${SERVICE_USER}' XDG_RUNTIME_DIR='/run/user/${svc_uid}' podman ${podman_extra} images -q 2>/dev/null | head -n1" 201>&- || true)"
        fi
        if [[ -n "${verify_img}" ]]; then
            local mem_out=""
            mem_out="$(su -s /bin/sh "${SERVICE_USER}" -c "HOME='/home/${SERVICE_USER}' XDG_RUNTIME_DIR='/run/user/${svc_uid}' podman ${podman_extra} run --rm --network none --memory 33554432 '${verify_img}' sh -c 'cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null'" 201>&- 2>/dev/null | tr -d '[:space:]' || true)"
            if [[ ! "${mem_out}" =~ ^[0-9]+$ ]] || [[ "${mem_out}" -gt 33554432 ]]; then
                die "${EXIT_RUNTIME_ERROR}" "Rootless Podman cgroup memory limit verification failed (expected <= 33554432, got '${mem_out:-empty}')."
            fi
        fi
        log_info "Verified rootless Podman functionality and cgroup delegation for '${SERVICE_USER}'."
    fi
}
