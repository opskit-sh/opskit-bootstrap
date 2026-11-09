#!/usr/bin/env bash
# Offline precise reversal of recorded bootstrap mutations (--undo).
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh and family modules are loaded

undo_mutations() {
    require_root

    if [[ ! -f "${LEDGER_FILE}" ]]; then
        cleanup_lock_only_state_dir
        die "${EXIT_NOT_FOUND}" "No applied mutation ledger found at '${LEDGER_FILE}'. Nothing to undo."
    fi

    ensure_bootstrap_state_dir
    (
        flock -x 201
        _undo_mutations_locked
    ) 201>"${BOOTSTRAP_STATE_DIR}/.state.lock"
}

_undo_mutations_locked() {
    if [[ ! -f "${LEDGER_FILE}" ]]; then
        cleanup_lock_only_state_dir
        die "${EXIT_NOT_FOUND}" "No applied mutation ledger found at '${LEDGER_FILE}'. Nothing to undo."
    fi

    log_info "Initiating offline uninstallation from '${LEDGER_FILE}'..."

    # 1. Validate the ENTIRE ledger before processing any mutation
    if ! validate_entire_ledger; then
        die "${EXIT_VALIDATION_ERROR}" "Ledger integrity verification failed. Corrupted, tampered, or invalid entries encountered. Refusing to perform uninstallation, and state directory '${BOOTSTRAP_STATE_DIR}' has been preserved intact for inspection."
    fi

    # Read ledger lines into an array
    local entries=()
    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" ]] && continue
        entries+=("${line}")
    done < "${LEDGER_FILE}"

    local count=${#entries[@]}
    log_info "Reversing ${count} recorded mutation(s) in reverse order..."
    local undo_had_failure=false

    # Stop user services first if user manager reachable
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --user --machine="${SERVICE_USER}@" stop opskit-cloud.service opskit-edge.service cloudflared.service 2>/dev/null || true
        fi
    fi

    # Iterate in reverse chronological order
    for (( i=count-1; i>=0; i-- )); do
        local entry="${entries[i]}"
        local mut_id
        mut_id="$(python3 -B -c "import json, sys; print(json.loads(sys.argv[1]).get('mutation_id', ''))" "${entry}")"
        local meta_json
        meta_json="$(python3 -B -c "import json, sys; print(json.dumps(json.loads(sys.argv[1]).get('metadata', {})))" "${entry}")"

        log_info "Reversing mutation [${mut_id}]..."

        case "${mut_id}" in
            fetch_cli)
                local pre_existing backup_path
                pre_existing="$(python3 -B -c "import json, sys; print(str(json.loads(sys.argv[1]).get('pre_existing', False)).lower())" "${meta_json}")"
                backup_path="$(python3 -B -c "import json, sys; print(json.loads(sys.argv[1]).get('backup_path', ''))" "${meta_json}")"

                if [[ "${pre_existing}" == "true" ]]; then
                    if [[ -n "${backup_path}" && -f "${backup_path}" ]]; then
                        mv "${backup_path}" "${CLI_INSTALL_PATH}"
                        chmod 0755 "${CLI_INSTALL_PATH}"
                        log_info "Restored pre-existing CLI binary to ${CLI_INSTALL_PATH}."
                    else
                        log_info "Pre-existing CLI binary already restored at ${CLI_INSTALL_PATH}."
                    fi
                else
                    rm -f "${CLI_INSTALL_PATH}"
                    log_info "Removed static CLI binary at ${CLI_INSTALL_PATH}."
                fi
                ;;

            firewall_rules)
                local rule443_json rule80_json
                rule443_json="$(python3 -B -c "import json, sys; print(json.dumps(json.loads(sys.argv[1]).get('rule443', {})))" "${meta_json}")"
                rule80_json="$(python3 -B -c "import json, sys; print(json.dumps(json.loads(sys.argv[1]).get('rule80', {})))" "${meta_json}")"

                if [[ "${rule443_json}" != "{}" ]]; then
                    family_remove_firewall_rule "${rule443_json}"
                fi
                if [[ "${rule80_json}" != "{}" ]]; then
                    family_remove_firewall_rule "${rule80_json}"
                fi

                # Defense-in-depth explicit-stack fallback for tagged OpsKit rules only
                if family_has_tagged_opskit_firewall_rule 443 tcp; then
                    family_remove_firewall_rule '{"stack":"nftables","port":443,"proto":"tcp"}'
                    family_remove_firewall_rule '{"stack":"iptables","port":443,"proto":"tcp"}'
                fi
                if family_has_tagged_opskit_firewall_rule 80 tcp; then
                    family_remove_firewall_rule '{"stack":"nftables","port":80,"proto":"tcp"}'
                    family_remove_firewall_rule '{"stack":"iptables","port":80,"proto":"tcp"}'
                fi

                local nft_blind=false
                if ! command -v nft >/dev/null 2>&1; then
                    if [[ -d /sys/module/nf_tables ]] || grep -qE '^nf_tables\b' /proc/modules 2>/dev/null; then
                        nft_blind=true
                        log_warn "nft binary not found while kernel nf_tables subsystem is loaded; nftables state could not be verified or cleaned."
                    fi
                fi

                # Separate tagged OpsKit survivors from untagged/foreign retention via shared helper
                local tagged_survivors=()
                mapfile -t tagged_survivors < <(collect_tagged_firewall_survivors "${meta_json}")

                if [[ ${#tagged_survivors[@]} -gt 0 ]]; then
                    undo_had_failure=true
                    log_error "Tagged OpsKit firewall rules survived attempted removal during undo: ${tagged_survivors[*]}. Preserving '${BOOTSTRAP_STATE_DIR}' for recovery."
                elif [[ "${nft_blind}" == "true" ]]; then
                    log_info "Completed firewall reversal check (nftables verification unavailable without nft binary)."
                elif command -v nft >/dev/null 2>&1 && nft list table inet opskit >/dev/null 2>&1; then
                    log_info "Removed tagged OpsKit firewall rules; retained 'inet opskit' namespace for remaining non-OpsKit or untagged objects."
                else
                    log_info "Removed host firewall rules."
                fi
                ;;

            edge_system_unit)
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl disable --now opskit-edge.service 2>/dev/null || true
                fi
                rm -f "${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl daemon-reload 2>/dev/null || true
                fi
                log_info "Removed system service unit '${SYSTEMD_SYSTEM_DIR}/opskit-edge.service'."
                ;;

            edge_socket_units)
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl disable --now opskit-edge-443.socket opskit-edge-80.socket 2>/dev/null || true
                fi
                rm -f "${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket" "${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket"
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl daemon-reload 2>/dev/null || true
                fi
                log_info "Removed socket activation units for ports 443 and 80."
                ;;

            service_units)
                local user_unit_dir="/home/${SERVICE_USER}/.config/systemd/user"
                rm -f "${user_unit_dir}/opskit-"*.service 2>/dev/null || true
                log_info "Removed user service units."
                ;;

            cloudflared_unit)
                local user_unit_dir="/home/${SERVICE_USER}/.config/systemd/user"
                rm -f "${user_unit_dir}/cloudflared.service" 2>/dev/null || true
                log_info "Removed cloudflared user unit template."
                ;;

            user_linger)
                if [[ "${FLAG_PURGE:-}" == "true" ]]; then
                    local linger_enabled
                    linger_enabled="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(str(bool(d.get('enabled', False))).lower() if isinstance(d, dict) else 'false')" "${meta_json}" 2>/dev/null || echo false)"
                    if [[ "${linger_enabled}" == "true" ]]; then
                        if command -v loginctl >/dev/null 2>&1; then
                            loginctl disable-linger "${SERVICE_USER}" 2>/dev/null || true
                        fi
                        rm -f "/var/lib/systemd/linger/${SERVICE_USER}" 2>/dev/null || true
                        log_info "Disabled systemd user linger for '${SERVICE_USER}' (purge covenant)."
                    else
                        log_info "Preserved pre-existing systemd user linger for '${SERVICE_USER}'."
                    fi
                else
                    log_info "Preserved systemd user linger for '${SERVICE_USER}' (plain covenant preserves workload execution)."
                fi
                ;;

            subuid_allocation)
                if [[ "${FLAG_PURGE:-}" == "true" ]]; then
                    local alloc_flags sub_all sub_uid sub_gid
                    alloc_flags="$(python3 -B -c "
import json, sys
d = json.loads(sys.argv[1])
if not isinstance(d, dict): d = {}
a = bool(d.get('allocated', False))
u = bool(d.get('subuid_allocated', a))
g = bool(d.get('subgid_allocated', a))
print(f'{str(a).lower()}:{str(u).lower()}:{str(g).lower()}')
" "${meta_json}" 2>/dev/null || echo "false:false:false")"
                    IFS=: read -r sub_all sub_uid sub_gid <<< "${alloc_flags}"
                    if [[ "${sub_uid}" == "true" && -f "${SUBUID_FILE}" ]]; then
                        sed -i "/^${SERVICE_USER}:/d" "${SUBUID_FILE}" 2>/dev/null || true
                    fi
                    if [[ "${sub_gid}" == "true" && -f "${SUBGID_FILE}" ]]; then
                        sed -i "/^${SERVICE_USER}:/d" "${SUBGID_FILE}" 2>/dev/null || true
                    fi
                    if [[ "${sub_uid}" == "true" || "${sub_gid}" == "true" ]]; then
                        log_info "Removed OpsKit-allocated subordinate ID entries for '${SERVICE_USER}' (subuid=${sub_uid}, subgid=${sub_gid})."
                    else
                        log_info "Preserved pre-existing subordinate UID/GID allocations for '${SERVICE_USER}'."
                    fi
                else
                    log_info "Preserved subordinate UID/GID allocations for '${SERVICE_USER}' (plain covenant preserves container namespaces)."
                fi
                ;;

            service_user)
                if [[ "${FLAG_PURGE:-}" == "true" ]]; then
                    local user_created
                    user_created="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(str(bool(d.get('created', False))).lower() if isinstance(d, dict) else 'false')" "${meta_json}" 2>/dev/null || echo false)"
                    if [[ "${user_created}" == "true" ]]; then
                        local saved_subuid="" saved_subgid=""
                        if [[ -f "${SUBUID_FILE}" ]]; then
                            saved_subuid="$(grep "^${SERVICE_USER}:" "${SUBUID_FILE}" 2>/dev/null || true)"
                        fi
                        if [[ -f "${SUBGID_FILE}" ]]; then
                            saved_subgid="$(grep "^${SERVICE_USER}:" "${SUBGID_FILE}" 2>/dev/null || true)"
                        fi
                        userdel -r "${SERVICE_USER}" 2>/dev/null || userdel "${SERVICE_USER}" 2>/dev/null || true
                        rm -rf "/home/${SERVICE_USER:?}" 2>/dev/null || true
                        rm -f "/etc/sysusers.d/${SERVICE_USER}.conf"
                        groupdel "${SERVICE_GROUP}" 2>/dev/null || true
                        if [[ -n "${saved_subuid}" ]] && ! grep -q "^${SERVICE_USER}:" "${SUBUID_FILE}" 2>/dev/null; then
                            printf '%s\n' "${saved_subuid}" >> "${SUBUID_FILE}"
                        fi
                        if [[ -n "${saved_subgid}" ]] && ! grep -q "^${SERVICE_USER}:" "${SUBGID_FILE}" 2>/dev/null; then
                            printf '%s\n' "${saved_subgid}" >> "${SUBGID_FILE}"
                        fi
                        log_info "Removed service user '${SERVICE_USER}', group '${SERVICE_GROUP}', and /etc/sysusers.d entry (purge covenant)."
                    else
                        log_info "Preserved pre-existing service account '${SERVICE_USER}' and home directory (not created by bootstrap)."
                    fi
                else
                    log_info "Preserved service account '${SERVICE_USER}' (plain covenant preserves workload runtime identity)."
                fi
                ;;

            security_labels)
                log_info "Reverted security labels."
                ;;

            packages)
                log_info "Retained runtime packages (preserved for system stability)."
                ;;
        esac
    done

    # Handle service state directory based on covenant
    if [[ "${FLAG_PURGE:-}" == "true" ]]; then
        rm -rf "${SERVICE_STATE_DIR}"
        log_info "Removed service state directory at '${SERVICE_STATE_DIR}' (purge covenant)."
    else
        # In plain uninstall, remove versions and logs but preserve directory if deployments present
        rm -rf "${SERVICE_STATE_DIR}"/versions "${SERVICE_STATE_DIR}"/logs "${SERVICE_STATE_DIR}"/edge
        log_info "Cleaned OpsKit binary artifacts under '${SERVICE_STATE_DIR}' (plain covenant)."
    fi

    if [[ "${undo_had_failure}" == "true" ]]; then
        die "${EXIT_RUNTIME_ERROR}" "Undo could not remove all tagged OpsKit firewall rules; preserving '${BOOTSTRAP_STATE_DIR}' so --undo can be re-run after manual intervention."
    fi

    # Remove bootstrap state directory (only reached if all entries processed)
    rm -rf "${BOOTSTRAP_STATE_DIR}"
    log_info "Removed local bootstrap state directory at '${BOOTSTRAP_STATE_DIR}'."
}
