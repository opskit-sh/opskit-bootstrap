#!/usr/bin/env bash
# Offline precise reversal of recorded bootstrap mutations (--undo).
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh, ledger.sh, and family modules are loaded

_confirm_destructive_purge() {
    if [[ "${FLAG_PURGE:-}" != "true" || "${FLAG_YES:-}" == "true" ]]; then
        return 0
    fi
    local svc_home expected_host
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    expected_host="$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "")"
    if [[ -t 0 ]]; then
        echo "WARNING: Destructive purge (--undo --purge) will permanently remove:" >&2
        echo "  - OpsKit-managed units, firewall rules, and CLI binary" >&2
        echo "  - Service user '${SERVICE_USER}' and home directory '${svc_home}'" >&2
        echo "  - Service state directory '${SERVICE_STATE_DIR}'" >&2
        echo "  - OpsKit-allocated subordinate IDs and bootstrap ledger '${BOOTSTRAP_STATE_DIR}'" >&2
        read -r -p "Type this node's hostname (${expected_host}) to confirm purge: " typed_host
        if [[ -z "${expected_host}" || "${typed_host}" != "${expected_host}" ]]; then
            die "${EXIT_SAFETY_GUARD}" "Hostname confirmation mismatch; destructive purge cancelled."
        fi
    else
        die "${EXIT_SAFETY_GUARD}" "Destructive --undo --purge requires confirmation. Pass --yes in non-interactive environments."
    fi
}

# Remove only the exact OpsKit-allocated "<user>:<range>" line (or fallback to ^<user>: when range absent).
_remove_exact_subid_entry() {
    local subid_file="$1"
    local user="$2"
    local range="${3:-}"
    [[ -f "${subid_file}" ]] || return 0
    python3 -B -c '
import os, stat, sys, tempfile

path, user, exact_range = sys.argv[1:4]
prefix = f"{user}:"
exact_line = f"{user}:{exact_range}" if exact_range else ""
with open(path, "r", encoding="utf-8") as fin:
    lines = fin.readlines()

new_lines = []
removed = False
for line in lines:
    stripped = line.rstrip("\r\n")
    if exact_line:
        if not removed and stripped == exact_line:
            removed = True
            continue
    else:
        if stripped.startswith(prefix):
            removed = True
            continue
    new_lines.append(line)

if not removed:
    sys.exit(0)

st = os.stat(path)
parent = os.path.dirname(path) or "."
fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".subid.")
try:
    os.fchmod(fd, stat.S_IMODE(st.st_mode))
    if os.geteuid() == 0:
        os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, "w", encoding="utf-8") as fout:
        fout.writelines(new_lines)
        fout.flush()
        os.fsync(fout.fileno())
    os.replace(tmp_path, path)
except Exception:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    raise
' "${subid_file}" "${user}" "${range}"
}

undo_mutations() {
    require_root

    if [[ ! -f "${LEDGER_FILE}" ]]; then
        if [[ -f "${LEDGER_KEY_FILE}" || -f "${LEDGER_HEAD_FILE}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Ledger integrity verification failed: '${LEDGER_FILE}' is missing while key or head anchor exists. Preserving '${BOOTSTRAP_STATE_DIR}' intact."
        fi
        cleanup_lock_only_state_dir
        die "${EXIT_NOT_FOUND}" "No applied mutation ledger found at '${LEDGER_FILE}'. Nothing to undo."
    fi

    _confirm_destructive_purge

    ensure_bootstrap_state_dir
    (
        flock -x 201
        _undo_mutations_locked
    ) 201>"${BOOTSTRAP_STATE_DIR}/.state.lock"
}

_undo_mutations_locked() {
    if [[ ! -f "${LEDGER_FILE}" ]]; then
        if [[ -f "${LEDGER_KEY_FILE}" || -f "${LEDGER_HEAD_FILE}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Ledger integrity verification failed: '${LEDGER_FILE}' is missing while key or head anchor exists. Preserving '${BOOTSTRAP_STATE_DIR}' intact."
        fi
        cleanup_lock_only_state_dir
        die "${EXIT_NOT_FOUND}" "No applied mutation ledger found at '${LEDGER_FILE}'. Nothing to undo."
    fi

    log_info "Initiating offline uninstallation from '${LEDGER_FILE}'..."

    # 1. Validate the ENTIRE chained ledger before processing any mutation
    if ! validate_entire_ledger; then
        die "${EXIT_VALIDATION_ERROR}" "Ledger integrity verification failed. Corrupted, tampered, or invalid entries encountered. Refusing to perform uninstallation, and state directory '${BOOTSTRAP_STATE_DIR}' has been preserved intact for inspection."
    fi

    local entries=()
    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" ]] && continue
        entries+=("${line}")
    done < "${LEDGER_FILE}"

    local count=${#entries[@]}
    log_info "Reversing ${count} recorded mutation(s) in reverse order..."
    local undo_had_failure=false
    local reversed_ids=()
    local preserved_ids=()

    local svc_home user_unit_dir
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    user_unit_dir="${svc_home}/.config/systemd/user"

    # Stop and disable OpsKit user exposure units if user manager reachable
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --user --machine="${SERVICE_USER}@" disable --now opskit-edge.service cloudflared.service 2>/dev/null || true
        fi
    fi

    # Iterate in reverse chronological order
    local i
    for (( i=count-1; i>=0; i-- )); do
        local entry="${entries[i]}"
        local mut_id meta_json
        mut_id="$(python3 -B -c "import json, sys; print(json.loads(sys.argv[1]).get('mutation_id', ''))" "${entry}")"
        meta_json="$(python3 -B -c "import json, sys; print(json.dumps(json.loads(sys.argv[1]).get('metadata', {})))" "${entry}")"

        log_info "Reversing mutation [${mut_id}]..."

        case "${mut_id}" in
            fetch_cli)
                local cli_meta_vals pre_existing backup_path edge_path edge_current_link
                cli_meta_vals="$(python3 -B -c "
import json, sys
d = json.loads(sys.argv[1])
if not isinstance(d, dict): d = {}
pe = 'true' if d.get('pre_existing', False) else 'false'
bp = str(d.get('backup_path', '') or '')
ep = str(d.get('edge_path', '') or '')
el = str(d.get('edge_current_link', '') or '')
print(f'{pe}|{bp}|{ep}|{el}')
" "${meta_json}" 2>/dev/null || echo "false|||")"
                IFS='|' read -r pre_existing backup_path edge_path edge_current_link <<< "${cli_meta_vals}"

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
                if [[ -n "${edge_current_link}" || -n "${edge_path}" ]] && id "${SERVICE_USER}" >/dev/null 2>&1; then
                    run_as_service_user '
                        if [ -n "$1" ]; then
                            rm -f -- "$1"
                        fi
                        if [ -n "$2" ]; then
                            rm -f -- "$2"
                            rmdir "$(dirname "$2")" 2>/dev/null || true
                        fi
                    ' "${edge_current_link}" "${edge_path}" 2>/dev/null || true
                    log_info "Removed versioned opskit-edge binary and current symlink."
                fi
                reversed_ids+=("fetch_cli")
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

                local tagged_survivors=()
                mapfile -t tagged_survivors < <(collect_tagged_firewall_survivors "${meta_json}")

                if [[ ${#tagged_survivors[@]} -gt 0 ]]; then
                    undo_had_failure=true
                    preserved_ids+=("firewall_rules")
                    log_error "Tagged OpsKit firewall rules survived attempted removal during undo: ${tagged_survivors[*]}. Preserving '${BOOTSTRAP_STATE_DIR}' for recovery."
                else
                    reversed_ids+=("firewall_rules")
                    if [[ "${nft_blind}" == "true" ]]; then
                        log_info "Completed firewall reversal check (nftables verification unavailable without nft binary)."
                    elif command -v nft >/dev/null 2>&1 && nft list table inet opskit >/dev/null 2>&1; then
                        log_info "Removed tagged OpsKit firewall rules; retained 'inet opskit' namespace for remaining non-OpsKit or untagged objects."
                    else
                        log_info "Removed host firewall rules."
                    fi
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
                reversed_ids+=("edge_system_unit")
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
                reversed_ids+=("edge_socket_units")
                log_info "Removed socket activation units for ports 443 and 80."
                ;;

            service_units)
                if id "${SERVICE_USER}" >/dev/null 2>&1; then
                    if command -v systemctl >/dev/null 2>&1; then
                        systemctl --user --machine="${SERVICE_USER}@" disable --now opskit-edge.service 2>/dev/null || true
                    fi
                    remove_user_file "${user_unit_dir}/opskit-edge.service"
                fi
                reversed_ids+=("service_units")
                log_info "Removed user exposure unit."
                ;;

            cloudflared_unit)
                if id "${SERVICE_USER}" >/dev/null 2>&1; then
                    if command -v systemctl >/dev/null 2>&1; then
                        systemctl --user --machine="${SERVICE_USER}@" disable --now cloudflared.service 2>/dev/null || true
                    fi
                    remove_user_file "${user_unit_dir}/cloudflared.service"
                fi
                reversed_ids+=("cloudflared_unit")
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
                    reversed_ids+=("user_linger")
                else
                    preserved_ids+=("user_linger")
                    log_info "Preserved systemd user linger for '${SERVICE_USER}' (plain covenant preserves workload execution)."
                fi
                ;;

            rootless_docker)
                if [[ "${FLAG_PURGE:-}" == "true" ]]; then
                    local rd_created
                    rd_created="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(str(bool(d.get('created', False))).lower() if isinstance(d, dict) else 'false')" "${meta_json}" 2>/dev/null || echo false)"
                    if [[ "${rd_created}" == "true" ]]; then
                        if id "${SERVICE_USER}" >/dev/null 2>&1; then
                            local svc_uid
                            svc_uid="$(id -u "${SERVICE_USER}")"
                            if command -v systemctl >/dev/null 2>&1; then
                                systemctl --user --machine="${SERVICE_USER}@" disable --now docker.service docker.socket 2>/dev/null || true
                            fi
                            if command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1; then
                                run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" DBUS_SESSION_BUS_ADDRESS="unix:path=$2/bus" dockerd-rootless-setuptool.sh uninstall' "${svc_home}" "/run/user/${svc_uid}" 2>/dev/null || true
                            fi
                            remove_user_file "${user_unit_dir}/docker.service"
                            remove_user_file "${user_unit_dir}/docker.socket"
                            remove_user_file "${svc_home}/.config/environment.d/opskit-docker.conf"
                            run_as_service_user 'rmdir "$1" 2>/dev/null || true' "${svc_home}/.config/environment.d" 2>/dev/null || true
                        fi
                        log_info "Removed rootless Docker provisioning for '${SERVICE_USER}' (purge covenant)."
                    else
                        log_info "Preserved pre-existing rootless Docker configuration for '${SERVICE_USER}'."
                    fi
                    reversed_ids+=("rootless_docker")
                else
                    preserved_ids+=("rootless_docker")
                    log_info "Preserved rootless Docker configuration for '${SERVICE_USER}' (plain covenant preserves workload execution)."
                fi
                ;;

            cgroup_delegation)
                if [[ "${FLAG_PURGE:-}" == "true" ]]; then
                    local cg_created cg_dropin
                    cg_created="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(str(bool(d.get('created', False))).lower() if isinstance(d, dict) else 'false')" "${meta_json}" 2>/dev/null || echo false)"
                    cg_dropin="$(python3 -B -c "import json, sys; d=json.loads(sys.argv[1]); print(d.get('dropin', '') if isinstance(d, dict) else '')" "${meta_json}" 2>/dev/null || true)"
                    [[ -z "${cg_dropin}" ]] && cg_dropin="${SYSTEMD_SYSTEM_DIR}/user@.service.d/opskit-delegate.conf"
                    if [[ "${cg_created}" == "true" ]]; then
                        rm -f "${cg_dropin}"
                        rmdir "$(dirname "${cg_dropin}")" 2>/dev/null || true
                        if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
                            systemctl daemon-reload 2>/dev/null || true
                        fi
                        log_info "Removed systemd cgroup delegation drop-in '${cg_dropin}' (purge covenant)."
                    else
                        log_info "Preserved pre-existing systemd cgroup delegation configuration."
                    fi
                    reversed_ids+=("cgroup_delegation")
                else
                    preserved_ids+=("cgroup_delegation")
                    log_info "Preserved systemd cgroup delegation configuration (plain covenant preserves workload resource limits)."
                fi
                ;;

            subuid_allocation)
                if [[ "${FLAG_PURGE:-}" == "true" ]]; then
                    local alloc_info sub_uid sub_gid sub_range
                    alloc_info="$(python3 -B -c "
import json, sys
d = json.loads(sys.argv[1])
if not isinstance(d, dict): d = {}
a = bool(d.get('allocated', False))
u = bool(d.get('subuid_allocated', a))
g = bool(d.get('subgid_allocated', a))
rng = str(d.get('range', '') or '')
print(f'{str(u).lower()}|{str(g).lower()}|{rng}')
" "${meta_json}" 2>/dev/null || echo "false|false|")"
                    IFS='|' read -r sub_uid sub_gid sub_range <<< "${alloc_info}"
                    if [[ "${sub_uid}" == "true" && -f "${SUBUID_FILE}" ]]; then
                        _remove_exact_subid_entry "${SUBUID_FILE}" "${SERVICE_USER}" "${sub_range}"
                    fi
                    if [[ "${sub_gid}" == "true" && -f "${SUBGID_FILE}" ]]; then
                        _remove_exact_subid_entry "${SUBGID_FILE}" "${SERVICE_USER}" "${sub_range}"
                    fi
                    if [[ "${sub_uid}" == "true" || "${sub_gid}" == "true" ]]; then
                        log_info "Removed OpsKit-allocated subordinate ID entries for '${SERVICE_USER}' (subuid=${sub_uid}, subgid=${sub_gid})."
                    else
                        log_info "Preserved pre-existing subordinate UID/GID allocations for '${SERVICE_USER}'."
                    fi
                    reversed_ids+=("subuid_allocation")
                else
                    preserved_ids+=("subuid_allocation")
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
                        if id "${SERVICE_USER}" >/dev/null 2>&1; then
                            local del_uid
                            del_uid="$(id -u "${SERVICE_USER}")"
                            if command -v loginctl >/dev/null 2>&1; then
                                loginctl terminate-user "${SERVICE_USER}" 2>/dev/null || true
                            fi
                            if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
                                systemctl stop "user@${del_uid}.service" 2>/dev/null || true
                            fi
                            if ! userdel -r "${SERVICE_USER}" 2>/dev/null; then
                                userdel "${SERVICE_USER}" 2>/dev/null || true
                            fi
                        fi
                        if id "${SERVICE_USER}" >/dev/null 2>&1; then
                            undo_had_failure=true
                            preserved_ids+=("service_user")
                            log_error "Failed to remove service account '${SERVICE_USER}' (active processes remain). Stop running user processes and re-run --undo --purge."
                        else
                            if [[ -n "${svc_home}" && "${svc_home}" != "/" && ! -L "${svc_home}" ]]; then
                                rm -rf "${svc_home}" 2>/dev/null || true
                            fi
                            rm -f "/etc/sysusers.d/${SERVICE_USER}.conf"
                            groupdel "${SERVICE_GROUP}" 2>/dev/null || true
                            if [[ -n "${saved_subuid}" ]] && ! grep -q "^${SERVICE_USER}:" "${SUBUID_FILE}" 2>/dev/null; then
                                printf '%s\n' "${saved_subuid}" >> "${SUBUID_FILE}"
                            fi
                            if [[ -n "${saved_subgid}" ]] && ! grep -q "^${SERVICE_USER}:" "${SUBGID_FILE}" 2>/dev/null; then
                                printf '%s\n' "${saved_subgid}" >> "${SUBGID_FILE}"
                            fi
                            reversed_ids+=("service_user")
                            log_info "Removed service user '${SERVICE_USER}', group '${SERVICE_GROUP}', and /etc/sysusers.d entry (purge covenant)."
                        fi
                    else
                        reversed_ids+=("service_user")
                        log_info "Preserved pre-existing service account '${SERVICE_USER}' and home directory (not created by bootstrap)."
                    fi
                else
                    preserved_ids+=("service_user")
                    log_info "Preserved service account '${SERVICE_USER}' (plain covenant preserves workload runtime identity)."
                fi
                ;;

            security_labels)
                if command -v restorecon >/dev/null 2>&1 && [[ -d "${SERVICE_STATE_DIR}" ]]; then
                    restorecon -R "${SERVICE_STATE_DIR}" 2>/dev/null || true
                fi
                reversed_ids+=("security_labels")
                log_info "Reverted security labels."
                ;;

            packages)
                if [[ "${FLAG_PURGE:-}" == "true" ]]; then
                    reversed_ids+=("packages")
                else
                    preserved_ids+=("packages")
                fi
                log_info "Retained runtime packages (preserved for system stability)."
                ;;
        esac
    done

    # Handle service state directory based on covenant
    ensure_safe_dir_no_symlink "${SERVICE_STATE_DIR}"
    if [[ "${FLAG_PURGE:-}" == "true" ]]; then
        if [[ "${undo_had_failure}" == "false" ]]; then
            rm -rf "${SERVICE_STATE_DIR}"
            log_info "Removed service state directory at '${SERVICE_STATE_DIR}' (purge covenant)."
        fi
    else
        rm -rf "${SERVICE_STATE_DIR}"/versions "${SERVICE_STATE_DIR}"/logs "${SERVICE_STATE_DIR}"/edge
        log_info "Cleaned OpsKit binary artifacts under '${SERVICE_STATE_DIR}' (plain covenant)."
    fi

    if [[ "${undo_had_failure}" == "true" ]]; then
        die "${EXIT_RUNTIME_ERROR}" "Undo could not complete full removal; preserving '${BOOTSTRAP_STATE_DIR}' so --undo can be re-run after resolving blocking artifacts."
    fi

    ensure_safe_dir_no_symlink "${BOOTSTRAP_STATE_DIR}"
    if [[ "${FLAG_PURGE:-}" == "true" || ${#preserved_ids[@]} -eq 0 ]]; then
        rm -rf "${BOOTSTRAP_STATE_DIR}"
        log_info "Removed local bootstrap state directory at '${BOOTSTRAP_STATE_DIR}'."
    else
        local reversed_csv=""
        if [[ ${#reversed_ids[@]} -gt 0 ]]; then
            reversed_csv="$(IFS=,; echo "${reversed_ids[*]}")"
        fi
        rewrite_chained_ledger "${reversed_csv}" ""
        if [[ ! -f "${LEDGER_FILE}" ]]; then
            rm -rf "${BOOTSTRAP_STATE_DIR}"
            log_info "Removed local bootstrap state directory at '${BOOTSTRAP_STATE_DIR}'."
        else
            log_info "Retained '${BOOTSTRAP_STATE_DIR}' with preserved host-level ledger entries for future --undo --purge."
        fi
    fi
}
