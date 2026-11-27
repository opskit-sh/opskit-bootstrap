#!/usr/bin/env bash
# Machine plan compilation (opskit.bootstrap-plan/v1) and trust contract generation.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh, detect.sh, probe.sh are loaded

generate_node_fingerprint() {
    if [[ -n "${MOCK_NODE_FINGERPRINT:-}" ]]; then
        echo "${MOCK_NODE_FINGERPRINT}"
        return 0
    fi
    local source_id=""
    if [[ -f /etc/machine-id ]]; then
        source_id="$(cat /etc/machine-id)"
    elif [[ -f /var/lib/dbus/machine-id ]]; then
        source_id="$(cat /var/lib/dbus/machine-id)"
    else
        local host
        host="$(cat /proc/sys/kernel/hostname 2>/dev/null || uname -n 2>/dev/null || echo "localhost")"
        source_id="${host}-$(uname -m)"
    fi
    compute_sha256 "${source_id}"
}

# Upstream systemd socket unit directives:
# https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html
# Upstream IPv6 dual-stack socket binding semantics:
# https://man7.org/linux/man-pages/man7/ipv6.7.html
expected_edge_443_socket() {
    cat << 'EOF'
[Unit]
Description=OpsKit Edge Inbound HTTPS Socket Activation (Port 443)

[Socket]
ListenStream=0.0.0.0:443
EOF
    if has_ipv6_stack; then
        cat << 'EOF'
ListenStream=[::]:443
BindIPv6Only=ipv6-only
EOF
    fi
    cat << 'EOF'
FileDescriptorName=443
NonBlocking=true
Service=opskit-edge.service

[Install]
WantedBy=sockets.target
EOF
}

expected_edge_80_socket() {
    cat << 'EOF'
[Unit]
Description=OpsKit Edge Inbound HTTP Socket Activation (Port 80)

[Socket]
ListenStream=0.0.0.0:80
EOF
    if has_ipv6_stack; then
        cat << 'EOF'
ListenStream=[::]:80
BindIPv6Only=ipv6-only
EOF
    fi
    cat << 'EOF'
FileDescriptorName=80
NonBlocking=true
Service=opskit-edge.service

[Install]
WantedBy=sockets.target
EOF
}

# Upstream systemd execution sandboxing directives:
# https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
expected_edge_system_service() {
    local sock_deps="opskit-edge-443.socket"
    if [[ "${FLAG_NO_HTTP:-false}" != "true" ]]; then
        sock_deps="opskit-edge-443.socket opskit-edge-80.socket"
    fi
    cat << EOF
[Unit]
Description=OpsKit Edge Ingress Server (Direct Profile)
After=network.target ${sock_deps}
Requires=${sock_deps}

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
Environment=OPSKIT_EDGE_STATE_DIR=${SERVICE_STATE_DIR}/edge
Environment=XDG_STATE_HOME=${SERVICE_STATE_DIR}/state
Environment=XDG_CONFIG_HOME=${SERVICE_STATE_DIR}/config
ExecStart=${SERVICE_STATE_DIR}/versions/current/opskit-edge
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536
UMask=0027
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths=${SERVICE_STATE_DIR}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
}

expected_user_edge_service() {
    cat << EOF
[Unit]
Description=OpsKit Edge Exposure Boundary (User Scope)
After=network.target

[Service]
Type=simple
ExecStart=${SERVICE_STATE_DIR}/versions/current/opskit-edge
Restart=always
RestartSec=3s

[Install]
WantedBy=default.target
EOF
}

expected_user_cloudflared_service() {
    cat << 'EOF'
[Unit]
Description=Cloudflare Tunnel Ingress Service
After=network.target

[Service]
Type=simple
ExecStart=cloudflared tunnel run
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target
EOF
}

expected_cgroup_delegate_conf() {
    # Upstream systemd cgroup v2 user delegation drop-in:
    # https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
    cat << 'EOF'
# Configured by opskit-bootstrap for rootless container cgroup v2 resource limits
[Service]
Delegate=yes
EOF
}

compile_plan() {
    # Validate existing ledger before planning
    if [[ -f "${LEDGER_FILE}" ]]; then
        if ! validate_entire_ledger; then
            die "${EXIT_VALIDATION_ERROR}" "Existing ledger at '${LEDGER_FILE}' failed integrity verification. Refusing to compile plan."
        fi
    else
        # Warn once per run when host state exists without a ledger file
        if [[ -z "${_PRE_STATE_WARNED:-}" ]]; then
            local pre_state=()
            ${SERVICE_USER_EXISTS} && pre_state+=("service user '${SERVICE_USER}'")
            ${SUBUID_ALLOCATED} && pre_state+=("subordinate ID allocation")
            [[ -d "${SERVICE_STATE_DIR}" ]] && pre_state+=("state directory '${SERVICE_STATE_DIR}'")
            if [[ ${#pre_state[@]} -gt 0 ]]; then
                log_warn "Host state exists (${pre_state[*]}) but ledger file '${LEDGER_FILE}' is absent. Pre-existing resources not created by OpsKit will be recorded and preserved."
                _PRE_STATE_WARNED=1
            fi
        fi
    fi

    NODE_FINGERPRINT="$(generate_node_fingerprint)"
    PLAN_MUTATIONS=()

    local svc_home
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    local user_unit_dir="${svc_home}/.config/systemd/user"
    local esc_user esc_subuid esc_subgid esc_systemd esc_service_dir esc_cli esc_user_unit_dir
    esc_user="$(json_escape "${SERVICE_USER}")"
    esc_subuid="$(json_escape "${SUBUID_FILE}")"
    esc_subgid="$(json_escape "${SUBGID_FILE}")"
    esc_systemd="$(json_escape "${SYSTEMD_SYSTEM_DIR}")"
    esc_service_dir="$(json_escape "${SERVICE_STATE_DIR}")"
    esc_cli="$(json_escape "${CLI_INSTALL_PATH}")"
    esc_user_unit_dir="$(json_escape "${user_unit_dir}")"

    # Surface profile transition teardown in the approved plan when switching profiles
    if [[ -f "${LEDGER_FILE}" ]]; then
        local recorded_prof
        recorded_prof="$(get_recorded_profile_from_ledger)"
        if [[ -n "${recorded_prof}" && "${recorded_prof}" != "${CHOSEN_PROFILE}" ]]; then
            local trans_req_root=false trans_desc="" trans_target=""
            if [[ "${recorded_prof}" == "direct" ]]; then
                trans_req_root=true
                trans_desc="Remove retired direct-profile socket units, system edge unit, and firewall rules during transition to '${CHOSEN_PROFILE}'"
                trans_target="${esc_systemd}/opskit-edge*.socket, ${esc_systemd}/opskit-edge.service, $(json_escape "${FIREWALL_STACK}")"
            elif [[ "${recorded_prof}" == "tunnel" ]]; then
                trans_desc="Remove retired cloudflared user unit during transition to '${CHOSEN_PROFILE}'"
                trans_target="${esc_user_unit_dir}/cloudflared.service"
            else
                trans_desc="Remove retired user-scope opskit-edge unit during transition to '${CHOSEN_PROFILE}'"
                trans_target="${esc_user_unit_dir}/opskit-edge.service"
            fi
            PLAN_MUTATIONS+=(
                "{\"id\":\"profile_transition\",\"class\":\"H\",\"requires_root\":${trans_req_root},\"description\":\"$(json_escape "${trans_desc}")\",\"target\":\"${trans_target}\",\"rollback\":\"Re-run bootstrap with --profile $(json_escape "${recorded_prof}")\"}"
            )
        fi
    fi

    # Mutation 1: Packages
    local need_packages=false
    if ${PODMAN_PACKAGE_NEEDED} || ${UIDMAP_PACKAGE_NEEDED} || ${DOCKER_ROOTLESS_PACKAGE_NEEDED:-false}; then
        need_packages=true
    elif [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_TEST_FORCE_PACKAGES:-0}" == "1" ]]; then
        need_packages=true
    fi
    if ${need_packages}; then
        local pkgs=()
        ${PODMAN_PACKAGE_NEEDED} && pkgs+=("podman")
        if ${UIDMAP_PACKAGE_NEEDED}; then
            case "${DETECTED_FAMILY}" in
                debian) pkgs+=("uidmap") ;;
                rhel) pkgs+=("shadow-utils") ;;
                sles) pkgs+=("shadow") ;;
                *) pkgs+=("uidmap") ;;
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
                *) pkgs=("podman" "uidmap") ;;
            esac
        fi
        local pkg_list
        pkg_list="$(IFS=', '; echo "${pkgs[*]}")"
        local target_tool
        case "${DETECTED_FAMILY}" in
            debian) target_tool="apt-get" ;;
            rhel) target_tool="dnf" ;;
            sles) target_tool="zypper" ;;
            *) target_tool="${DETECTED_FAMILY} package manager" ;;
        esac
        PLAN_MUTATIONS+=(
            "{\"id\":\"packages\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install missing container runtime packages: $(json_escape "${pkg_list}")\",\"target\":\"$(json_escape "${target_tool}")\",\"rollback\":\"Retain installed system packages for host stability\"}"
        )
    fi

    # Mutation 2: Service user (reconcile on Run 1 even if pre-existing so Run 2 is a no-op)
    local need_service_user=false
    if ! ${SERVICE_USER_EXISTS} || ! is_mutation_recorded "service_user"; then
        need_service_user=true
    fi
    if ${need_service_user}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"service_user\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Provision rootless service account and primary group '${esc_user}'\",\"target\":\"/etc/passwd, /etc/group\",\"rollback\":\"userdel -r ${esc_user}\"}"
        )
    fi

    # Mutation 3: Subuid / Subgid allocation (reconcile on Run 1 even if pre-existing)
    local need_subuid=false
    if ! ${SUBUID_ALLOCATED} || ! is_mutation_recorded "subuid_allocation"; then
        need_subuid=true
    fi
    if ${need_subuid}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"subuid_allocation\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Allocate subordinate UID/GID range for '${esc_user}' (65536 IDs, no clobber)\",\"target\":\"${esc_subuid}, ${esc_subgid}\",\"rollback\":\"Remove allocated range from subuid and subgid files\"}"
        )
    fi

    # Mutation 3b: Systemd cgroup v2 delegation (Delegate=yes)
    # Upstream systemd resource control: https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
    local delegate_dropin="${SYSTEMD_SYSTEM_DIR}/user@.service.d/opskit-delegate.conf"
    local esc_delegate_dropin
    esc_delegate_dropin="$(json_escape "${delegate_dropin}")"
    local need_cgroup_delegation=false
    if ! ${CGROUP_DELEGATION_ENABLED}; then
        need_cgroup_delegation=true
    elif [[ -f "${delegate_dropin}" ]] && ! file_matches_expected "${delegate_dropin}" expected_cgroup_delegate_conf; then
        need_cgroup_delegation=true
    elif [[ -f "${delegate_dropin}" && "${EUID:-1}" -eq 0 && "$(stat -c '%a:%u:%g' "${delegate_dropin}" 2>/dev/null || true)" != "644:0:0" ]]; then
        need_cgroup_delegation=true
    elif ! is_mutation_recorded "cgroup_delegation"; then
        need_cgroup_delegation=true
    fi
    if ${need_cgroup_delegation}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"cgroup_delegation\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Enable systemd cgroup v2 delegation (Delegate=yes) for user slice '${esc_user}'\",\"target\":\"${esc_delegate_dropin}\",\"rollback\":\"rm -f ${esc_delegate_dropin} && systemctl daemon-reload\"}"
        )
    fi

    # Mutation 4: User linger (reconcile on Run 1 even if pre-existing)
    local need_linger=false
    if ! ${LINGER_ACTIVE} || ! is_mutation_recorded "user_linger"; then
        need_linger=true
    fi
    if ${need_linger}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"user_linger\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Enable systemd user linger for '${esc_user}' to allow background service execution\",\"target\":\"/var/lib/systemd/linger/${esc_user}\",\"rollback\":\"loginctl disable-linger ${esc_user}\"}"
        )
    fi

    # Mutation 4b: Rootless Docker provisioning (when Docker is selected)
    # Upstream rootless Docker setup: https://docs.docker.com/engine/security/rootless/
    if [[ "${DETECTED_RUNTIME}" == "docker" ]]; then
        local docker_env_file="${svc_home}/.config/environment.d/opskit-docker.conf"
        local esc_docker_env
        esc_docker_env="$(json_escape "${docker_env_file}")"
        local need_rootless_docker=false
        if ! ${DOCKER_ROOTLESS_USABLE}; then
            need_rootless_docker=true
        elif ! is_mutation_recorded "rootless_docker"; then
            need_rootless_docker=true
        fi
        if ${need_rootless_docker}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"rootless_docker\",\"class\":\"U\",\"requires_root\":false,\"description\":\"Provision rootless Docker daemon and DOCKER_HOST for '${esc_user}'\",\"target\":\"${esc_user_unit_dir}/docker.service, ${esc_docker_env}\",\"rollback\":\"dockerd-rootless-setuptool.sh uninstall && rm -f ${esc_docker_env}\"}"
            )
        fi
    fi

    # Mutations for direct profile (system edge unit MUST be installed before socket units)
    if [[ "${CHOSEN_PROFILE}" == "direct" ]]; then
        # Mutation 5a: Edge system service unit
        local need_edge_system=false
        local esvc_path="${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"
        if [[ ! -f "${esvc_path}" ]]; then
            need_edge_system=true
        elif ! file_matches_expected "${esvc_path}" expected_edge_system_service; then
            need_edge_system=true
        elif [[ "${EUID:-1}" -eq 0 && "$(stat -c '%a:%u:%g' "${esvc_path}" 2>/dev/null || true)" != "644:0:0" ]]; then
            need_edge_system=true
        elif [[ -f "${LEDGER_FILE}" ]] && ! is_mutation_recorded "edge_system_unit"; then
            need_edge_system=true
        fi
        if ${need_edge_system}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"edge_system_unit\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install root-owned systemd service unit for edge process (User=${esc_user})\",\"target\":\"${esc_systemd}/opskit-edge.service\",\"rollback\":\"systemctl disable --now opskit-edge.service && rm -f ${esc_systemd}/opskit-edge.service\"}"
            )
        fi

        # Mutation 5b: Edge socket units (port 443 + optional port 80)
        local need_sockets=false
        local s443_path="${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket"
        local s80_path="${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket"
        if [[ ! -f "${s443_path}" ]] || ! file_matches_expected "${s443_path}" expected_edge_443_socket; then
            need_sockets=true
        elif [[ "${EUID:-1}" -eq 0 && "$(stat -c '%a:%u:%g' "${s443_path}" 2>/dev/null || true)" != "644:0:0" ]]; then
            need_sockets=true
        elif [[ "${FLAG_NO_HTTP:-false}" != "true" ]] && { [[ ! -f "${s80_path}" ]] || ! file_matches_expected "${s80_path}" expected_edge_80_socket || [[ "${EUID:-1}" -eq 0 && "$(stat -c '%a:%u:%g' "${s80_path}" 2>/dev/null || true)" != "644:0:0" ]]; }; then
            need_sockets=true
        elif [[ "${FLAG_NO_HTTP:-false}" == "true" && -f "${s80_path}" ]]; then
            need_sockets=true
        elif [[ "${SYSTEMD_RUNNING:-false}" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
            if ! systemctl is-enabled --quiet opskit-edge-443.socket 2>/dev/null || ! systemctl is-active --quiet opskit-edge-443.socket 2>/dev/null; then
                need_sockets=true
            elif [[ "${FLAG_NO_HTTP:-false}" != "true" ]] && { ! systemctl is-enabled --quiet opskit-edge-80.socket 2>/dev/null || ! systemctl is-active --quiet opskit-edge-80.socket 2>/dev/null; }; then
                need_sockets=true
            fi
        fi
        if ! ${need_sockets} && [[ -f "${LEDGER_FILE}" ]] && ! is_mutation_recorded "edge_socket_units"; then
            need_sockets=true
        fi
        if ${need_sockets}; then
            if [[ "${FLAG_NO_HTTP:-false}" == "true" ]]; then
                PLAN_MUTATIONS+=(
                    "{\"id\":\"edge_socket_units\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install inert systemd socket activation unit for port 443\",\"target\":\"${esc_systemd}/opskit-edge-443.socket\",\"rollback\":\"systemctl disable --now opskit-edge-443.socket && rm -f ${esc_systemd}/opskit-edge-443.socket\"}"
                )
            else
                PLAN_MUTATIONS+=(
                    "{\"id\":\"edge_socket_units\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install inert systemd socket activation units for port 443 and port 80\",\"target\":\"${esc_systemd}/opskit-edge-443.socket, ${esc_systemd}/opskit-edge-80.socket\",\"rollback\":\"systemctl disable --now opskit-edge-443.socket opskit-edge-80.socket && rm -f ${esc_systemd}/opskit-edge-*.socket\"}"
                )
            fi
        fi

        # Mutation 7: Firewall rules (ledger-based reconciliation)
        local need_firewall=false
        if ! family_has_firewall_rule 443 tcp; then
            need_firewall=true
        elif [[ "${FLAG_NO_HTTP:-false}" != "true" ]] && ! family_has_firewall_rule 80 tcp; then
            need_firewall=true
        elif [[ -f "${LEDGER_FILE}" ]] && ! is_mutation_recorded "firewall_rules"; then
            need_firewall=true
        fi
        if ${need_firewall}; then
            local esc_fw
            esc_fw="$(json_escape "${FIREWALL_STACK}")"
            if [[ "${FLAG_NO_HTTP:-false}" == "true" ]]; then
                PLAN_MUTATIONS+=(
                    "{\"id\":\"firewall_rules\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Allow inbound TCP traffic on port 443 in ${esc_fw}\",\"target\":\"${esc_fw} allow tcp 443\",\"rollback\":\"Remove allowed rule for port 443 from ${esc_fw}\"}"
                )
            else
                PLAN_MUTATIONS+=(
                    "{\"id\":\"firewall_rules\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Allow inbound TCP traffic on ports 443 and 80 in ${esc_fw}\",\"target\":\"${esc_fw} allow tcp 443, 80\",\"rollback\":\"Remove allowed rule for ports 443 and 80 from ${esc_fw}\"}"
                )
            fi
        fi
    fi

    # Mutation 8: User exposure unit (tunnel/private profiles only; opskit-cloud.service is owned by enrollment)
    if [[ "${CHOSEN_PROFILE}" != "direct" ]]; then
        local need_service_units=false
        if [[ ! -f "${user_unit_dir}/opskit-edge.service" ]]; then
            need_service_units=true
        elif ! file_matches_expected "${user_unit_dir}/opskit-edge.service" expected_user_edge_service; then
            need_service_units=true
        elif [[ -f "${LEDGER_FILE}" ]] && { ! is_mutation_recorded "service_units" || [[ "$(get_recorded_profile_from_ledger)" != "${CHOSEN_PROFILE}" ]]; }; then
            need_service_units=true
        fi
        if ${need_service_units}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"service_units\",\"class\":\"U\",\"requires_root\":false,\"description\":\"Install user unit for opskit-edge under service account\",\"target\":\"${esc_user_unit_dir}\",\"rollback\":\"systemctl --user disable --now opskit-edge.service && rm -f ${esc_user_unit_dir}/opskit-edge.service\"}"
            )
        fi
    fi

    # Mutation 9: Tunnel unit (tunnel profile only, ledger-based reconciliation)
    if [[ "${CHOSEN_PROFILE}" == "tunnel" ]]; then
        local need_tunnel_unit=false
        if [[ ! -f "${user_unit_dir}/cloudflared.service" ]]; then
            need_tunnel_unit=true
        elif ! file_matches_expected "${user_unit_dir}/cloudflared.service" expected_user_cloudflared_service; then
            need_tunnel_unit=true
        elif [[ -f "${LEDGER_FILE}" ]] && ! is_mutation_recorded "cloudflared_unit"; then
            need_tunnel_unit=true
        fi
        if ${need_tunnel_unit}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"cloudflared_unit\",\"class\":\"U\",\"requires_root\":false,\"description\":\"Install user service template for cloudflared tunnel daemon\",\"target\":\"${esc_user_unit_dir}/cloudflared.service\",\"rollback\":\"rm -f ${esc_user_unit_dir}/cloudflared.service\"}"
            )
        fi
    fi

    # Mutation 10: Security labels (if SELinux active and labeling missing/drifted)
    if [[ "${SELINUX_STATUS}" != "absent" && "${SELINUX_STATUS}" != "disabled" ]]; then
        local need_security_labels=false
        if [[ ! -d "${SERVICE_STATE_DIR}" ]] || ! is_mutation_recorded "security_labels"; then
            need_security_labels=true
        else
            local cur_ctx=""
            cur_ctx="$(stat -c %C "${SERVICE_STATE_DIR}" 2>/dev/null || true)"
            if [[ -n "${cur_ctx}" && "${cur_ctx}" != "?" && "${cur_ctx}" != *"container_file_t"* ]]; then
                need_security_labels=true
            fi
        fi
        if ${need_security_labels}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"security_labels\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Apply SELinux container storage contexts to service state directories\",\"target\":\"${esc_service_dir}\",\"rollback\":\"restorecon -R ${esc_service_dir}\"}"
            )
        fi
    fi

    # Mutation 11: CLI binary and versioned edge installation (ledger-based reconciliation and pre-flight check)
    local cli_needs_install=false
    local rec_cli_sha="" rec_edge_sha=""
    local edge_current_link="${SERVICE_STATE_DIR}/versions/current"
    local edge_current_bin="${edge_current_link}/opskit-edge"
    if [[ -f "${LEDGER_FILE}" ]]; then
        local cli_meta_shas
        cli_meta_shas="$(python3 -B -c "
import json, sys
cli_s = ''
edge_s = ''
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if d.get('mutation_id') == 'fetch_cli':
                md = d.get('metadata', {})
                if isinstance(md, dict):
                    cli_s = str(md.get('installed_sha256', '') or '')
                    edge_s = str(md.get('edge_sha256', '') or '')
        except Exception:
            pass
print(f'{cli_s}|{edge_s}')
" "${LEDGER_FILE}" 2>/dev/null || echo "|")"
        IFS='|' read -r rec_cli_sha rec_edge_sha <<< "${cli_meta_shas}"
    fi
    if [[ ! -f "${CLI_INSTALL_PATH}" || ! -x "${CLI_INSTALL_PATH}" ]]; then
        cli_needs_install=true
    elif ! is_mutation_recorded "fetch_cli"; then
        cli_needs_install=true
    elif [[ -n "${rec_cli_sha}" ]]; then
        local cur_cli_sha
        cur_cli_sha="$(compute_sha256 "${CLI_INSTALL_PATH}")"
        if [[ "${cur_cli_sha}" != "${rec_cli_sha}" ]]; then
            cli_needs_install=true
        fi
    fi
    if ! ${cli_needs_install} && [[ "${CHOSEN_PROFILE:-}" == "direct" || -n "${rec_edge_sha}" ]]; then
        if [[ ! -L "${edge_current_link}" || ! -f "${edge_current_bin}" || ! -x "${edge_current_bin}" ]]; then
            cli_needs_install=true
        elif [[ -n "${rec_edge_sha}" ]]; then
            local cur_edge_sha
            cur_edge_sha="$(compute_sha256 "${edge_current_bin}")"
            if [[ "${cur_edge_sha}" != "${rec_edge_sha}" ]]; then
                cli_needs_install=true
            fi
        fi
    fi
    if ! ${cli_needs_install} && [[ -n "${FLAG_ARTIFACT_DIR:-}" || -n "${OPSKIT_ARTIFACT_SOURCE_DIR:-}" ]]; then
        local source_manifest=""
        if [[ -n "${FLAG_ARTIFACT_DIR:-}" && -f "${FLAG_ARTIFACT_DIR}/release-manifest.json" ]]; then
            source_manifest="${FLAG_ARTIFACT_DIR}/release-manifest.json"
        elif [[ -n "${OPSKIT_ARTIFACT_SOURCE_DIR:-}" && -f "${OPSKIT_ARTIFACT_SOURCE_DIR}/release-manifest.json" ]]; then
            source_manifest="${OPSKIT_ARTIFACT_SOURCE_DIR}/release-manifest.json"
        fi
        if [[ -n "${source_manifest}" ]]; then
            local exp_shas exp_sha exp_edge_sha cur_sha cur_edge_sha_src
            exp_shas="$(python3 -B -c "
import json, sys
d = json.load(open(sys.argv[1]))
arts = d.get('artifacts', {})
cli_s = str(arts.get('opskit-linux-' + sys.argv[2], {}).get('sha256', '') or '')
edge_s = str(arts.get('opskit-edge-linux-' + sys.argv[2], {}).get('sha256', '') or '')
print(f'{cli_s}|{edge_s}')
" "${source_manifest}" "$(uname -m)" 2>/dev/null || echo "|")"
            IFS='|' read -r exp_sha exp_edge_sha <<< "${exp_shas}"
            cur_sha="$(compute_sha256 "${CLI_INSTALL_PATH}")"
            if [[ -n "${exp_sha}" && "${cur_sha}" != "${exp_sha}" ]]; then
                cli_needs_install=true
            elif [[ -n "${exp_edge_sha}" && -x "${edge_current_bin}" ]]; then
                cur_edge_sha_src="$(compute_sha256 "${edge_current_bin}")"
                if [[ "${cur_edge_sha_src}" != "${exp_edge_sha}" ]]; then
                    cli_needs_install=true
                fi
            fi
        fi
    fi

    if ${cli_needs_install}; then
        local has_artifact_source=false
        local local_manifest_path=""
        if [[ -n "${FLAG_ARTIFACT_DIR:-}" ]]; then
            if [[ ! -d "${FLAG_ARTIFACT_DIR}" ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Artifact directory '${FLAG_ARTIFACT_DIR}' does not exist."
            fi
            has_artifact_source=true
            local_manifest_path="${FLAG_ARTIFACT_DIR}/release-manifest.json"
        elif [[ -n "${OPSKIT_ARTIFACT_SOURCE_DIR:-}" ]]; then
            if [[ ! -d "${OPSKIT_ARTIFACT_SOURCE_DIR}" ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Artifact source directory '${OPSKIT_ARTIFACT_SOURCE_DIR}' does not exist."
            fi
            has_artifact_source=true
            local_manifest_path="${OPSKIT_ARTIFACT_SOURCE_DIR}/release-manifest.json"
        elif [[ -n "${OPSKIT_MANIFEST_URL:-}" ]]; then
            has_artifact_source=true
        elif [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}/artifacts" && -f "${BIN_DIR}/artifacts/release-manifest.json" ]]; then
            has_artifact_source=true
            local_manifest_path="${BIN_DIR}/artifacts/release-manifest.json"
        elif [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}/../artifacts" && -f "${BIN_DIR}/../artifacts/release-manifest.json" ]]; then
            has_artifact_source=true
            local_manifest_path="${BIN_DIR}/../artifacts/release-manifest.json"
        elif [[ -n "${LIB_DIR:-}" && -d "${LIB_DIR}/../artifacts" && -f "${LIB_DIR}/../artifacts/release-manifest.json" ]]; then
            has_artifact_source=true
            local_manifest_path="${LIB_DIR}/../artifacts/release-manifest.json"
        fi
        if ! ${has_artifact_source}; then
            die "${EXIT_NETWORK_ERROR}" "No release manifest source provided and ${CLI_INSTALL_PATH} requires verified installation. Provide --artifact-dir <path> (or set OPSKIT_ARTIFACT_SOURCE_DIR) for offline installation, or set OPSKIT_MANIFEST_URL to download release artifacts."
        fi

        if [[ -n "${local_manifest_path}" ]]; then
            local host_arch pubkey
            host_arch="$(uname -m)"
            pubkey="$(get_release_pubkey)"
            verify_local_manifest_preflight "${local_manifest_path}" "${pubkey}" "${host_arch}"
        fi

        PLAN_MUTATIONS+=(
            "{\"id\":\"fetch_cli\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install verified static opskit binary to ${esc_cli} via signed manifest\",\"target\":\"${esc_cli}\",\"rollback\":\"Restore pre-existing state or remove binary\"}"
        )
    fi

    NO_CHANGES=false
    if [[ ${#PLAN_MUTATIONS[@]} -eq 0 ]]; then
        NO_CHANGES=true
    fi

    local ctrl_json=""
    local i=0
    for c in "${CGROUP_CONTROLLERS[@]}"; do
        [[ $i -gt 0 ]] && ctrl_json+=", "
        ctrl_json+="\"$(json_escape "${c}")\""
        i=$((i + 1))
    done

    local mut_json=""
    i=0
    for m in "${PLAN_MUTATIONS[@]}"; do
        [[ $i -gt 0 ]] && mut_json+=", "
        mut_json+="${m}"
        i=$((i + 1))
    done

    local expires_at="${MOCK_EXPIRES_AT:-${PLAN_EXPIRES_AT:-}}"
    if [[ -z "${expires_at}" ]]; then
        expires_at="$(date -u -d '+1 hour' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")"
    fi
    PLAN_EXPIRES_AT="${expires_at}"

    local postcond_items=("\"service_user_rootless_functional\"" "\"cgroup_delegation_active\"")
    if [[ "${CHOSEN_PROFILE}" == "direct" && "${SYSTEMD_RUNNING}" == "true" ]]; then
        postcond_items+=("\"systemd_socket_units_active\"")
    fi
    postcond_items+=("\"cli_executable_verified\"" "\"ledger_recorded_offline\"")
    local postcond_json
    postcond_json="$(IFS=', '; echo "${postcond_items[*]}")"

    PLAN_JSON="{\"schema\":\"opskit.bootstrap-plan/v1\",\"node_fingerprint\":\"$(json_escape "${NODE_FINGERPRINT}")\",\"capabilities\":{\"os_id\":\"$(json_escape "${OS_ID}")\",\"os_version\":\"$(json_escape "${OS_VERSION_ID}")\",\"os_name\":\"$(json_escape "${OS_NAME}")\",\"kernel\":\"$(json_escape "${KERNEL_RELEASE}")\",\"kernel_ok\":true,\"cgroups_v2\":${CGROUPS_V2},\"cgroup_controllers\":[${ctrl_json}],\"systemd_running\":${SYSTEMD_RUNNING},\"systemd_user_manager\":${SYSTEMD_USER_MANAGER},\"runtime\":\"$(json_escape "${DETECTED_RUNTIME}")\",\"runtime_version\":\"$(json_escape "${RUNTIME_VERSION}")\",\"newuidmap_present\":${NEWUIDMAP_PRESENT},\"newgidmap_present\":${NEWGIDMAP_PRESENT},\"subuid_allocated\":${SUBUID_ALLOCATED},\"subuid_range\":\"$(json_escape "${EXISTING_SUBUID_RANGE}")\",\"service_user_present\":${SERVICE_USER_EXISTS},\"selinux_status\":\"$(json_escape "${SELINUX_STATUS}")\",\"apparmor_status\":\"$(json_escape "${APPARMOR_STATUS}")\",\"firewall_stack\":\"$(json_escape "${FIREWALL_STACK}")\",\"disk_free_gb\":${DISK_FREE_GB},\"clock_skew_seconds\":${CLOCK_SKEW_SECONDS},\"linger_enabled\":${LINGER_ACTIVE},\"docker_rootless_usable\":${DOCKER_ROOTLESS_USABLE},\"docker_daemon_rootful\":${DOCKER_DAEMON_ROOTFUL},\"cgroup_delegation_enabled\":${CGROUP_DELEGATION_ENABLED}},\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\",\"runtime\":\"$(json_escape "${DETECTED_RUNTIME}")\",\"mutations\":[${mut_json}],\"no_changes\":${NO_CHANGES},\"probe_results\":{\"status\":\"$(json_escape "${PROBE_STATUS}")\",\"reachable_v4\":${PROBE_REACHABLE_V4},\"reachable_v6\":${PROBE_REACHABLE_V6},\"details\":\"$(json_escape "${PROBE_DETAILS}")\"},\"postconditions\":[${postcond_json}],\"expires_at\":\"$(json_escape "${expires_at}")\"}"

    PLAN_HASH="$(compute_sha256 "${PLAN_JSON}")"
}

render_human_plan() {
    echo "=================================================================="
    echo "OpsKit Host Bootstrap Plan (opskit.bootstrap-plan/v1)"
    echo "=================================================================="
    echo "Node Fingerprint : ${NODE_FINGERPRINT}"
    echo "Distribution     : ${OS_NAME} (${OS_ID} ${OS_VERSION_ID})"
    echo "Kernel           : ${KERNEL_RELEASE}"
    echo "Ingress Profile  : ${CHOSEN_PROFILE}"
    echo "Runtime          : ${DETECTED_RUNTIME} ${RUNTIME_VERSION}"
    echo "Plan Hash        : ${PLAN_HASH}"
    echo "Plan Status      : $(if ${NO_CHANGES}; then echo "No changes needed (host already bootstrapped)"; else echo "${#PLAN_MUTATIONS[@]} mutation(s) required"; fi)"
    echo "=================================================================="
    if ${NO_CHANGES}; then
        echo "No host mutations are required."
    else
        echo "Planned Mutations:"
        local idx=1
        for m in "${PLAN_MUTATIONS[@]}"; do
            local desc target req_root
            desc="$(echo "${m}" | grep -oP '"description":"\K[^"]+')"
            target="$(echo "${m}" | grep -oP '"target":"\K[^"]+')"
            req_root="$(echo "${m}" | grep -oP '"requires_root":\K[^,}]+')"
            echo "  ${idx}. ${desc}"
            echo "     Target        : ${target}"
            echo "     Root Required : ${req_root}"
            idx=$((idx + 1))
        done
    fi
    echo "=================================================================="
}
