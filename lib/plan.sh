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

expected_edge_443_socket() {
    cat << EOF
[Unit]
Description=OpsKit Edge Inbound HTTPS Socket Activation (Port 443)
PartOf=opskit-edge.service

[Socket]
ListenStream=0.0.0.0:443
ListenStream=[::]:443
FileDescriptorName=443
SocketMode=0660
Service=opskit-edge.service

[Install]
WantedBy=sockets.target
EOF
}

expected_edge_80_socket() {
    cat << EOF
[Unit]
Description=OpsKit Edge Inbound HTTP Socket Activation (Port 80)
PartOf=opskit-edge.service

[Socket]
ListenStream=0.0.0.0:80
ListenStream=[::]:80
FileDescriptorName=80
SocketMode=0660
Service=opskit-edge.service

[Install]
WantedBy=sockets.target
EOF
}

expected_edge_system_service() {
    cat << EOF
[Unit]
Description=OpsKit Edge Ingress Server (Direct Profile)
After=network.target
Requires=opskit-edge-443.socket

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=/var/lib/opskit/versions/current/opskit-edge
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536
NonBlocking=true

[Install]
WantedBy=multi-user.target
EOF
}

expected_user_cloud_service() {
    cat << 'EOF'
[Unit]
Description=OpsKit Cloud Node Broker
After=network.target

[Service]
Type=simple
ExecStart=/var/lib/opskit/versions/current/opskit cloud service
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target
EOF
}

expected_user_edge_service() {
    cat << 'EOF'
[Unit]
Description=OpsKit Edge Exposure Boundary (User Scope)
After=network.target

[Service]
Type=simple
ExecStart=/var/lib/opskit/versions/current/opskit-edge
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

    # Mutation 1: Packages
    local need_packages=false
    if ${PODMAN_PACKAGE_NEEDED} || ${UIDMAP_PACKAGE_NEEDED}; then
        need_packages=true
    elif [[ "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_TEST_FORCE_PACKAGES:-0}" == "1" ]]; then
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
        if [[ ${#pkgs[@]} -eq 0 ]] && [[ "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_TEST_FORCE_PACKAGES:-0}" == "1" ]]; then
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
            "{\"id\":\"packages\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install missing container runtime packages: ${pkg_list}\",\"target\":\"${target_tool}\",\"rollback\":\"Remove installed packages\"}"
        )
    fi

    # Mutation 2: Service user (reconcile on Run 1 even if pre-existing so Run 2 is a no-op)
    local need_service_user=false
    if ! ${SERVICE_USER_EXISTS} || ! is_mutation_recorded "service_user"; then
        need_service_user=true
    fi
    if ${need_service_user}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"service_user\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Provision rootless service account and primary group '${SERVICE_USER}'\",\"target\":\"/etc/passwd, /etc/group\",\"rollback\":\"userdel -r ${SERVICE_USER}\"}"
        )
    fi

    # Mutation 3: Subuid / Subgid allocation (reconcile on Run 1 even if pre-existing)
    local need_subuid=false
    if ! ${SUBUID_ALLOCATED} || ! is_mutation_recorded "subuid_allocation"; then
        need_subuid=true
    fi
    if ${need_subuid}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"subuid_allocation\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Allocate subordinate UID/GID range for '${SERVICE_USER}' (65536 IDs, no clobber)\",\"target\":\"${SUBUID_FILE}, ${SUBGID_FILE}\",\"rollback\":\"Remove allocated range from subuid and subgid files\"}"
        )
    fi

    # Mutation 4: User linger (reconcile on Run 1 even if pre-existing)
    local need_linger=false
    if ! ${LINGER_ACTIVE} || ! is_mutation_recorded "user_linger"; then
        need_linger=true
    fi
    if ${need_linger}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"user_linger\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Enable systemd user linger for '${SERVICE_USER}' to allow background service execution\",\"target\":\"/var/lib/systemd/linger/${SERVICE_USER}\",\"rollback\":\"loginctl disable-linger ${SERVICE_USER}\"}"
        )
    fi

    # Mutations for direct profile
    if [[ "${CHOSEN_PROFILE}" == "direct" ]]; then
        # Mutation 5: Edge socket units (ledger-based reconciliation)
        local need_sockets=false
        if [[ ! -f "${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket" || ! -f "${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket" ]]; then
            need_sockets=true
        elif ! file_matches_expected "${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket" expected_edge_443_socket || ! file_matches_expected "${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket" expected_edge_80_socket; then
            need_sockets=true
        elif [[ -f "${LEDGER_FILE}" ]] && ! is_mutation_recorded "edge_socket_units"; then
            need_sockets=true
        fi
        if ${need_sockets}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"edge_socket_units\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install inert systemd socket activation units for port 443 and port 80\",\"target\":\"${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket, ${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket\",\"rollback\":\"systemctl disable --now opskit-edge-443.socket opskit-edge-80.socket && rm -f ${SYSTEMD_SYSTEM_DIR}/opskit-edge-*.socket\"}"
            )
        fi

        # Mutation 6: Edge system service unit (ledger-based reconciliation)
        local need_edge_system=false
        if [[ ! -f "${SYSTEMD_SYSTEM_DIR}/opskit-edge.service" ]]; then
            need_edge_system=true
        elif ! file_matches_expected "${SYSTEMD_SYSTEM_DIR}/opskit-edge.service" expected_edge_system_service; then
            need_edge_system=true
        elif [[ -f "${LEDGER_FILE}" ]] && ! is_mutation_recorded "edge_system_unit"; then
            need_edge_system=true
        fi
        if ${need_edge_system}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"edge_system_unit\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install root-owned systemd service unit for edge process (User=${SERVICE_USER})\",\"target\":\"${SYSTEMD_SYSTEM_DIR}/opskit-edge.service\",\"rollback\":\"systemctl disable --now opskit-edge.service && rm -f ${SYSTEMD_SYSTEM_DIR}/opskit-edge.service\"}"
            )
        fi

        # Mutation 7: Firewall rules (ledger-based reconciliation)
        local need_firewall=false
        if ! family_has_firewall_rule 443 tcp || ! family_has_firewall_rule 80 tcp; then
            need_firewall=true
        elif [[ -f "${LEDGER_FILE}" ]] && ! is_mutation_recorded "firewall_rules"; then
            need_firewall=true
        fi
        if ${need_firewall}; then
            PLAN_MUTATIONS+=(
                "{\"id\":\"firewall_rules\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Allow inbound TCP traffic on ports 443 and 80 in ${FIREWALL_STACK}\",\"target\":\"${FIREWALL_STACK} allow tcp 443, 80\",\"rollback\":\"Remove allowed rule for ports 443 and 80 from ${FIREWALL_STACK}\"}"
            )
        fi
    fi

    # Mutation 8: User service units (ledger-based reconciliation)
    local user_unit_dir="/home/${SERVICE_USER}/.config/systemd/user"
    local need_service_units=false
    if [[ ! -f "${user_unit_dir}/opskit-cloud.service" ]]; then
        need_service_units=true
    elif ! file_matches_expected "${user_unit_dir}/opskit-cloud.service" expected_user_cloud_service; then
        need_service_units=true
    elif [[ "${CHOSEN_PROFILE}" != "direct" && ! -f "${user_unit_dir}/opskit-edge.service" ]]; then
        need_service_units=true
    elif [[ "${CHOSEN_PROFILE}" != "direct" ]] && ! file_matches_expected "${user_unit_dir}/opskit-edge.service" expected_user_edge_service; then
        need_service_units=true
    elif [[ -f "${LEDGER_FILE}" ]] && { ! is_mutation_recorded "service_units" || [[ "$(get_recorded_profile_from_ledger)" != "${CHOSEN_PROFILE}" ]]; }; then
        need_service_units=true
    fi
    if ${need_service_units}; then
        PLAN_MUTATIONS+=(
            "{\"id\":\"service_units\",\"class\":\"U\",\"requires_root\":false,\"description\":\"Install user units for opskit-cloud and opskit-edge under service account\",\"target\":\"${user_unit_dir}\",\"rollback\":\"rm -f ${user_unit_dir}/opskit-*.service\"}"
        )
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
                "{\"id\":\"cloudflared_unit\",\"class\":\"U\",\"requires_root\":false,\"description\":\"Install user service template for cloudflared tunnel daemon\",\"target\":\"${user_unit_dir}/cloudflared.service\",\"rollback\":\"rm -f ${user_unit_dir}/cloudflared.service\"}"
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
                "{\"id\":\"security_labels\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Apply SELinux container storage contexts to service state directories\",\"target\":\"${SERVICE_STATE_DIR}\",\"rollback\":\"restorecon -R ${SERVICE_STATE_DIR}\"}"
            )
        fi
    fi

    # Mutation 11: CLI binary installation (ledger-based reconciliation and pre-flight check)
    local cli_needs_install=false
    if [[ ! -f "${CLI_INSTALL_PATH}" || ! -x "${CLI_INSTALL_PATH}" ]]; then
        cli_needs_install=true
    elif ! is_mutation_recorded "fetch_cli"; then
        cli_needs_install=true
    elif [[ -f "${LEDGER_FILE}" ]]; then
        local rec_cli_sha cur_cli_sha
        rec_cli_sha="$(python3 -B -c "
import json, sys
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if d.get('mutation_id') == 'fetch_cli':
                print(d.get('metadata', {}).get('installed_sha256', ''))
        except Exception:
            pass
" "${LEDGER_FILE}" 2>/dev/null || true)"
        if [[ -n "${rec_cli_sha}" ]]; then
            cur_cli_sha="$(compute_sha256 "${CLI_INSTALL_PATH}")"
            if [[ "${cur_cli_sha}" != "${rec_cli_sha}" ]]; then
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
            local exp_sha cur_sha
            exp_sha="$(python3 -B -c "import json, sys; d=json.load(open(sys.argv[1])); print(d.get('artifacts',{}).get('opskit-linux-' + sys.argv[2], {}).get('sha256',''))" "${source_manifest}" "$(uname -m)" 2>/dev/null || true)"
            cur_sha="$(compute_sha256 "${CLI_INSTALL_PATH}")"
            if [[ -n "${exp_sha}" && "${cur_sha}" != "${exp_sha}" ]]; then
                cli_needs_install=true
            fi
        fi
    fi

    if ${cli_needs_install}; then
        # Pre-flight check: ensure an explicit manifest source is resolvable (never treat on-disk binary as source)
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

        # Pre-flight validation of local manifest architecture, signature, and payload digest/size
        if [[ -n "${local_manifest_path}" ]]; then
            local host_arch
            host_arch="$(uname -m)"
            local pubkey
            pubkey="$(get_release_pubkey)"
            verify_local_manifest_preflight "${local_manifest_path}" "${pubkey}" "${host_arch}"
        fi

        PLAN_MUTATIONS+=(
            "{\"id\":\"fetch_cli\",\"class\":\"H\",\"requires_root\":true,\"description\":\"Install verified static opskit binary to ${CLI_INSTALL_PATH} via signed manifest\",\"target\":\"${CLI_INSTALL_PATH}\",\"rollback\":\"Restore pre-existing state or remove binary\"}"
        )
    fi

    NO_CHANGES=false
    if [[ ${#PLAN_MUTATIONS[@]} -eq 0 ]]; then
        NO_CHANGES=true
    fi

    # Assemble canonical JSON machine plan
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

    local postcond_items=("\"service_user_rootless_functional\"")
    if [[ "${CHOSEN_PROFILE}" == "direct" && "${SYSTEMD_RUNNING}" == "true" ]]; then
        postcond_items+=("\"systemd_socket_units_active\"")
    fi
    postcond_items+=("\"cli_executable_verified\"" "\"ledger_recorded_offline\"")
    local postcond_json
    postcond_json="$(IFS=', '; echo "${postcond_items[*]}")"

    PLAN_JSON="{\"schema\":\"opskit.bootstrap-plan/v1\",\"node_fingerprint\":\"$(json_escape "${NODE_FINGERPRINT}")\",\"capabilities\":{\"os_id\":\"$(json_escape "${OS_ID}")\",\"os_version\":\"$(json_escape "${OS_VERSION_ID}")\",\"os_name\":\"$(json_escape "${OS_NAME}")\",\"kernel\":\"$(json_escape "${KERNEL_RELEASE}")\",\"kernel_ok\":true,\"cgroups_v2\":${CGROUPS_V2},\"cgroup_controllers\":[${ctrl_json}],\"systemd_running\":${SYSTEMD_RUNNING},\"systemd_user_manager\":${SYSTEMD_USER_MANAGER},\"runtime\":\"$(json_escape "${DETECTED_RUNTIME}")\",\"runtime_version\":\"$(json_escape "${RUNTIME_VERSION}")\",\"newuidmap_present\":${NEWUIDMAP_PRESENT},\"newgidmap_present\":${NEWGIDMAP_PRESENT},\"subuid_allocated\":${SUBUID_ALLOCATED},\"subuid_range\":\"$(json_escape "${EXISTING_SUBUID_RANGE}")\",\"service_user_present\":${SERVICE_USER_EXISTS},\"selinux_status\":\"$(json_escape "${SELINUX_STATUS}")\",\"apparmor_status\":\"$(json_escape "${APPARMOR_STATUS}")\",\"firewall_stack\":\"$(json_escape "${FIREWALL_STACK}")\",\"disk_free_gb\":${DISK_FREE_GB},\"clock_skew_seconds\":${CLOCK_SKEW_SECONDS},\"linger_enabled\":${LINGER_ACTIVE}},\"profile\":\"$(json_escape "${CHOSEN_PROFILE}")\",\"runtime\":\"$(json_escape "${DETECTED_RUNTIME}")\",\"mutations\":[${mut_json}],\"no_changes\":${NO_CHANGES},\"probe_results\":{\"status\":\"$(json_escape "${PROBE_STATUS}")\",\"reachable_v4\":${PROBE_REACHABLE_V4},\"reachable_v6\":${PROBE_REACHABLE_V6},\"details\":\"$(json_escape "${PROBE_DETAILS}")\"},\"postconditions\":[${postcond_json}],\"expires_at\":\"${expires_at}\"}"

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
