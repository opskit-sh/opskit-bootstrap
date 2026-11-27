#!/usr/bin/env bash
# Drift detection and authorized configuration repair (--repair).
set -euo pipefail

# Sourced by opskit-bootstrap; assumes all libraries are loaded

rewrite_ledger_profile_and_resign() {
    local new_prof="$1"
    local remove_ids_csv="${2:-}"
    rewrite_chained_ledger "${remove_ids_csv}" "${new_prof}"
}

_audit_unit_perm_and_dropins() {
    local unit_path="$1"
    local mut_id="$2"
    local unit_name
    unit_name="$(basename "${unit_path}")"
    if [[ -f "${unit_path}" ]]; then
        local mode_owner
        mode_owner="$(stat -c '%a:%u:%g' "${unit_path}" 2>/dev/null || true)"
        if [[ "${mode_owner}" != "644:0:0" ]]; then
            DRIFTED_ITEMS+=("${mut_id}: Permissions/ownership on '${unit_path}' drifted (${mode_owner}, expected 644:0:0)")
        fi
    fi
    local dropin_dir="${unit_path}.d"
    if [[ -d "${dropin_dir}" ]]; then
        local f
        for f in "${dropin_dir}"/*.conf; do
            [[ -f "${f}" ]] || continue
            DRIFTED_ITEMS+=("${mut_id}: Unexpected systemd drop-in '${f}' on managed unit '${unit_name}'")
        done
    fi
}

perform_profile_transition_cleanup() {
    local old_prof="$1"
    local new_prof="$2"

    log_info "Reversing artifacts from '${old_prof}' profile not needed in '${new_prof}' profile..."
    local svc_home user_unit_dir
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    user_unit_dir="${svc_home}/.config/systemd/user"
    local remove_ids=()

    # From tunnel -> direct or private: disable & remove cloudflared if recorded in ledger
    if [[ "${old_prof}" == "tunnel" && "${new_prof}" != "tunnel" ]]; then
        if [[ -f "${LEDGER_FILE}" ]] && grep -q '"mutation_id":"cloudflared_unit"' "${LEDGER_FILE}"; then
            if command -v systemctl >/dev/null 2>&1; then
                systemctl --user --machine="${SERVICE_USER}@" disable --now cloudflared.service 2>/dev/null || true
            fi
            remove_user_file "${user_unit_dir}/cloudflared.service"
            remove_ids+=("cloudflared_unit")
        fi
    fi

    # From any non-direct profile -> direct: disable & remove user-scope opskit-edge.service
    if [[ "${old_prof}" != "direct" && "${new_prof}" == "direct" ]]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --user --machine="${SERVICE_USER}@" disable --now opskit-edge.service 2>/dev/null || true
        fi
        remove_user_file "${user_unit_dir}/opskit-edge.service"
        if [[ -f "${LEDGER_FILE}" ]] && grep -q '"mutation_id":"service_units"' "${LEDGER_FILE}"; then
            remove_ids+=("service_units")
        fi
    fi

    # From direct -> tunnel or private: remove socket units, system unit, firewall rules
    if [[ "${old_prof}" == "direct" && "${new_prof}" != "direct" ]]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now opskit-edge-443.socket opskit-edge-80.socket opskit-edge.service 2>/dev/null || true
            systemctl daemon-reload 2>/dev/null || true
        fi
        rm -f "${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket" "${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket" "${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"

        local all_fw_meta_json="" fw_meta_args=()
        if [[ -f "${LEDGER_FILE}" ]]; then
            all_fw_meta_json="$(python3 -B -c "
import json, sys
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if d.get('mutation_id') == 'firewall_rules':
                print(json.dumps(d.get('metadata', {})))
        except Exception:
            pass
" "${LEDGER_FILE}" 2>/dev/null || true)"

            if [[ -n "${all_fw_meta_json}" ]]; then
                while IFS= read -r fw_meta_json; do
                    [[ -z "${fw_meta_json}" ]] && continue
                    fw_meta_args+=("${fw_meta_json}")
                    local rule443_json rule80_json
                    rule443_json="$(python3 -B -c "import json, sys; print(json.dumps(json.loads(sys.argv[1]).get('rule443', {})))" "${fw_meta_json}" 2>/dev/null || echo "{}")"
                    rule80_json="$(python3 -B -c "import json, sys; print(json.dumps(json.loads(sys.argv[1]).get('rule80', {})))" "${fw_meta_json}" 2>/dev/null || echo "{}")"

                    if [[ "${rule443_json}" != "{}" ]]; then
                        family_remove_firewall_rule "${rule443_json}"
                    fi
                    if [[ "${rule80_json}" != "{}" ]]; then
                        family_remove_firewall_rule "${rule80_json}"
                    fi
                done <<< "${all_fw_meta_json}"
            fi
        fi

        if family_has_tagged_opskit_firewall_rule 443 tcp || family_has_tagged_opskit_firewall_rule 80 tcp || (command -v nft >/dev/null 2>&1 && nft list chain inet opskit input 2>/dev/null | grep 'comment "opskit-' >/dev/null 2>&1); then
            family_remove_firewall_rule '{"stack":"nftables","port":443,"proto":"tcp"}'
            family_remove_firewall_rule '{"stack":"nftables","port":80,"proto":"tcp"}'
            family_remove_firewall_rule '{"stack":"iptables","port":443,"proto":"tcp"}'
            family_remove_firewall_rule '{"stack":"iptables","port":80,"proto":"tcp"}'
        fi

        local nft_blind=false
        if ! command -v nft >/dev/null 2>&1; then
            if [[ -d /sys/module/nf_tables ]] || grep -qE '^nf_tables\b' /proc/modules 2>/dev/null; then
                nft_blind=true
                log_warn "nft binary not found while kernel nf_tables subsystem is loaded; nftables state could not be verified or cleaned."
            fi
        fi

        local surviving_rules=()
        mapfile -t surviving_rules < <(collect_tagged_firewall_survivors --include-nft-collision "${fw_meta_args[@]+"${fw_meta_args[@]}"}")

        if [[ ${#surviving_rules[@]} -gt 0 ]]; then
            log_warn "Host firewall artifacts still present after attempted removal: ${surviving_rules[*]}"
            die "${EXIT_RUNTIME_ERROR}" "Cannot complete profile transition: failed to remove host firewall rules (${surviving_rules[*]}). Ledger entries retained."
        fi

        if [[ "${nft_blind}" == "true" ]]; then
            log_info "Completed firewall reversal check (nftables verification unavailable without nft binary)."
        elif command -v nft >/dev/null 2>&1 && nft list table inet opskit >/dev/null 2>&1; then
            log_info "Removed tagged OpsKit firewall rules; retained 'inet opskit' namespace for remaining non-OpsKit or untagged objects."
        else
            log_info "Removed host firewall rules."
        fi

        remove_ids+=("edge_socket_units" "edge_system_unit" "firewall_rules")
    fi

    local remove_ids_csv=""
    if [[ ${#remove_ids[@]} -gt 0 ]]; then
        remove_ids_csv="$(IFS=,; echo "${remove_ids[*]}")"
    fi
    rewrite_ledger_profile_and_resign "${new_prof}" "${remove_ids_csv}"
}

_audit_repair_state() {
    RECORDED_PROFILE="$(get_recorded_profile_from_ledger)"

    if [[ -n "${FLAG_PROFILE:-}" && "${FLAG_PROFILE}" != "${RECORDED_PROFILE}" ]]; then
        CHOSEN_PROFILE="${FLAG_PROFILE}"
    else
        CHOSEN_PROFILE="${RECORDED_PROFILE}"
    fi

    DRIFTED_ITEMS=()

    if [[ "${CHOSEN_PROFILE}" != "${RECORDED_PROFILE}" ]]; then
        DRIFTED_ITEMS+=("profile: Target profile '${CHOSEN_PROFILE}' differs from recorded profile '${RECORDED_PROFILE}' (transition required)")
    fi

    # Audit packages
    if grep -q '"mutation_id":"packages"' "${LEDGER_FILE}"; then
        local pkgs_recorded
        pkgs_recorded="$(python3 -B -c "
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        d = json.loads(line)
        if d.get('mutation_id') == 'packages':
            for p in d.get('metadata', {}).get('packages', []):
                print(p)
" "${LEDGER_FILE}" 2>/dev/null || true)"
        for pkg in ${pkgs_recorded}; do
            case "${pkg}" in
                podman)
                    if ! command -v podman >/dev/null 2>&1; then
                        DRIFTED_ITEMS+=("packages: Missing podman binary")
                    fi
                    ;;
                uidmap|shadow-utils|shadow)
                    if ! command -v newuidmap >/dev/null 2>&1 || ! command -v newgidmap >/dev/null 2>&1; then
                        DRIFTED_ITEMS+=("packages: Missing user namespace utilities (newuidmap/newgidmap)")
                    fi
                    ;;
                docker-ce-rootless-extras|docker-rootless-extras)
                    if ! command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1 || ! command -v rootlesskit >/dev/null 2>&1; then
                        DRIFTED_ITEMS+=("packages: Missing rootless Docker utilities (dockerd-rootless-setuptool.sh/rootlesskit)")
                    fi
                    ;;
            esac
        done
        if [[ -z "${pkgs_recorded}" ]]; then
            if ! command -v podman >/dev/null 2>&1; then
                DRIFTED_ITEMS+=("packages: Missing podman binary")
            fi
            if ! command -v newuidmap >/dev/null 2>&1 || ! command -v newgidmap >/dev/null 2>&1; then
                DRIFTED_ITEMS+=("packages: Missing user namespace utilities (newuidmap/newgidmap)")
            fi
        fi
    fi

    # Audit service user
    if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
        DRIFTED_ITEMS+=("service_user: Account '${SERVICE_USER}' is missing")
    fi

    # Audit linger
    if [[ ! -f "/var/lib/systemd/linger/${SERVICE_USER}" ]]; then
        DRIFTED_ITEMS+=("user_linger: Systemd user linger is not active for '${SERVICE_USER}'")
    fi

    # Audit systemd cgroup delegation if recorded
    if grep -q '"mutation_id":"cgroup_delegation"' "${LEDGER_FILE}"; then
        local cg_created
        cg_created="$(python3 -B -c "
import json, sys
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if d.get('mutation_id') == 'cgroup_delegation':
                print(str(bool(d.get('metadata', {}).get('created', False))).lower())
        except Exception:
            pass
" "${LEDGER_FILE}" 2>/dev/null || echo false)"
        local cg_dropin="${SYSTEMD_SYSTEM_DIR}/user@.service.d/opskit-delegate.conf"
        if [[ "${cg_created}" == "true" ]]; then
            if [[ ! -f "${cg_dropin}" ]]; then
                DRIFTED_ITEMS+=("cgroup_delegation: Missing '${cg_dropin}'")
            elif ! file_matches_expected "${cg_dropin}" expected_cgroup_delegate_conf; then
                DRIFTED_ITEMS+=("cgroup_delegation: Content of '${cg_dropin}' has drifted from expected template")
            else
                local cg_mo
                cg_mo="$(stat -c '%a:%u:%g' "${cg_dropin}" 2>/dev/null || true)"
                if [[ "${cg_mo}" != "644:0:0" ]]; then
                    DRIFTED_ITEMS+=("cgroup_delegation: Permissions/ownership on '${cg_dropin}' drifted (${cg_mo}, expected 644:0:0)")
                fi
            fi
        elif ! has_systemd_delegate_yes; then
            DRIFTED_ITEMS+=("cgroup_delegation: Delegate=yes is no longer active for user@.service")
        fi
    fi

    # Audit rootless Docker if recorded
    if grep -q '"mutation_id":"rootless_docker"' "${LEDGER_FILE}"; then
        local rd_sock
        rd_sock="$(resolve_service_user_docker_socket "${SERVICE_USER}")"
        if [[ -z "${rd_sock}" || ! -S "${rd_sock}" ]]; then
            DRIFTED_ITEMS+=("rootless_docker: Rootless Docker socket '${rd_sock:-<unset>}' is missing or unreachable for '${SERVICE_USER}'")
        fi
    fi

    # Audit subordinate IDs (both subuid and subgid)
    if ! grep -q "^${SERVICE_USER}:" "${SUBUID_FILE}" 2>/dev/null; then
        DRIFTED_ITEMS+=("subuid_allocation: Subordinate UID allocation is missing for '${SERVICE_USER}'")
    fi
    if ! grep -q "^${SERVICE_USER}:" "${SUBGID_FILE}" 2>/dev/null; then
        DRIFTED_ITEMS+=("subuid_allocation: Subordinate GID allocation is missing for '${SERVICE_USER}'")
    fi

    # Determine recorded http_80 posture
    local recorded_http_80="true"
    recorded_http_80="$(python3 -B -c "
import json, sys
val = 'true'
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if d.get('mutation_id') in ('edge_socket_units', 'edge_system_unit', 'firewall_rules'):
                md = d.get('metadata', {})
                if isinstance(md, dict) and 'http_80' in md:
                    val = 'true' if md['http_80'] else 'false'
        except Exception:
            pass
print(val)
" "${LEDGER_FILE}" 2>/dev/null || echo true)"

    # Honor explicit --no-http if passed during repair
    local audit_http_80="${recorded_http_80}"
    if [[ "${FLAG_NO_HTTP:-false}" == "true" ]]; then
        audit_http_80="false"
    fi

    # Audit socket units if in ledger
    if grep -q '"mutation_id":"edge_socket_units"' "${LEDGER_FILE}"; then
        local s443="${SYSTEMD_SYSTEM_DIR}/opskit-edge-443.socket"
        local s80="${SYSTEMD_SYSTEM_DIR}/opskit-edge-80.socket"
        if [[ ! -f "${s443}" ]]; then
            DRIFTED_ITEMS+=("edge_socket_units: Missing '${s443}'")
        elif ! file_matches_expected "${s443}" expected_edge_443_socket; then
            DRIFTED_ITEMS+=("edge_socket_units: Content of '${s443}' has drifted from expected template")
        else
            _audit_unit_perm_and_dropins "${s443}" "edge_socket_units"
        fi
        if [[ "${audit_http_80}" == "true" ]]; then
            if [[ ! -f "${s80}" ]]; then
                DRIFTED_ITEMS+=("edge_socket_units: Missing '${s80}'")
            elif ! file_matches_expected "${s80}" expected_edge_80_socket; then
                DRIFTED_ITEMS+=("edge_socket_units: Content of '${s80}' has drifted from expected template")
            else
                _audit_unit_perm_and_dropins "${s80}" "edge_socket_units"
            fi
        fi
        if [[ "${SYSTEMD_RUNNING:-false}" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
            local check_units=("opskit-edge-443.socket")
            [[ "${audit_http_80}" == "true" ]] && check_units+=("opskit-edge-80.socket")
            local su
            for su in "${check_units[@]}"; do
                if [[ -f "${SYSTEMD_SYSTEM_DIR}/${su}" ]]; then
                    if ! systemctl is-enabled --quiet "${su}" 2>/dev/null; then
                        DRIFTED_ITEMS+=("edge_socket_units: Unit '${su}' is not enabled")
                    fi
                    if ! systemctl is-active --quiet "${su}" 2>/dev/null; then
                        DRIFTED_ITEMS+=("edge_socket_units: Unit '${su}' is not active")
                    fi
                fi
            done
        fi
    fi

    # Audit edge system unit if in ledger
    if grep -q '"mutation_id":"edge_system_unit"' "${LEDGER_FILE}"; then
        local esvc="${SYSTEMD_SYSTEM_DIR}/opskit-edge.service"
        if [[ ! -f "${esvc}" ]]; then
            DRIFTED_ITEMS+=("edge_system_unit: Missing '${esvc}'")
        elif ! file_matches_expected "${esvc}" expected_edge_system_service; then
            DRIFTED_ITEMS+=("edge_system_unit: Content of '${esvc}' has drifted from expected template")
        else
            _audit_unit_perm_and_dropins "${esvc}" "edge_system_unit"
        fi
    fi

    # Audit firewall rules if in ledger
    if grep -q '"mutation_id":"firewall_rules"' "${LEDGER_FILE}"; then
        if ! family_has_firewall_rule 443 tcp; then
            DRIFTED_ITEMS+=("firewall_rules: Inbound firewall rule for port 443 missing from active stack")
        elif [[ "${audit_http_80}" == "true" ]] && ! family_has_firewall_rule 80 tcp; then
            DRIFTED_ITEMS+=("firewall_rules: Inbound firewall rules for ports 443/80 missing from active stack")
        fi
    fi

    # Audit user service unit if in ledger (tunnel/private only)
    local svc_home user_unit_dir
    svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
    user_unit_dir="${svc_home}/.config/systemd/user"
    if grep -q '"mutation_id":"service_units"' "${LEDGER_FILE}"; then
        local usvc="${user_unit_dir}/opskit-edge.service"
        if [[ "${CHOSEN_PROFILE}" == "direct" ]]; then
            if [[ -f "${usvc}" ]]; then
                DRIFTED_ITEMS+=("service_units: Stray user-scope '${usvc}' present under direct profile")
            fi
        else
            if [[ ! -f "${usvc}" ]]; then
                DRIFTED_ITEMS+=("service_units: Missing '${usvc}'")
            elif ! file_matches_expected "${usvc}" expected_user_edge_service; then
                DRIFTED_ITEMS+=("service_units: Content of '${usvc}' has drifted from expected template")
            fi
        fi
    fi

    # Audit cloudflared unit if in ledger
    if grep -q '"mutation_id":"cloudflared_unit"' "${LEDGER_FILE}"; then
        local cfsvc="${user_unit_dir}/cloudflared.service"
        if [[ ! -f "${cfsvc}" ]]; then
            DRIFTED_ITEMS+=("cloudflared_unit: Missing '${cfsvc}'")
        elif ! file_matches_expected "${cfsvc}" expected_user_cloudflared_service; then
            DRIFTED_ITEMS+=("cloudflared_unit: Content of '${cfsvc}' has drifted from expected template")
        fi
    fi

    # Audit security labels if in ledger
    if grep -q '"mutation_id":"security_labels"' "${LEDGER_FILE}"; then
        if [[ -d "${SERVICE_STATE_DIR}" ]]; then
            local label
            label="$(stat -c %C "${SERVICE_STATE_DIR}" 2>/dev/null || true)"
            if [[ -n "${label}" && "${label}" != "?" && "${label}" != *"container_file_t"* ]]; then
                DRIFTED_ITEMS+=("security_labels: Context on '${SERVICE_STATE_DIR}' has drifted from container_file_t (${label})")
            fi
        fi
    fi

    # Audit CLI binary and versioned opskit-edge binary (existence, executable permission, and recorded SHA-256 digests)
    if grep -q '"mutation_id":"fetch_cli"' "${LEDGER_FILE}"; then
        local cli_meta_shas recorded_cli_sha recorded_edge_sha
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
        IFS='|' read -r recorded_cli_sha recorded_edge_sha <<< "${cli_meta_shas}"
        if [[ ! -f "${CLI_INSTALL_PATH}" ]]; then
            DRIFTED_ITEMS+=("fetch_cli: Missing executable at '${CLI_INSTALL_PATH}'")
        elif [[ ! -x "${CLI_INSTALL_PATH}" ]]; then
            DRIFTED_ITEMS+=("fetch_cli: Binary at '${CLI_INSTALL_PATH}' is not executable")
        elif [[ -n "${recorded_cli_sha}" ]]; then
            local actual_cli_sha
            actual_cli_sha="$(compute_sha256 "${CLI_INSTALL_PATH}")"
            if [[ "${actual_cli_sha}" != "${recorded_cli_sha}" ]]; then
                DRIFTED_ITEMS+=("fetch_cli: Digest mismatch at '${CLI_INSTALL_PATH}' (expected ${recorded_cli_sha})")
            fi
        fi
        if [[ "${CHOSEN_PROFILE}" == "direct" || -n "${recorded_edge_sha}" ]]; then
            local edge_link="${SERVICE_STATE_DIR}/versions/current"
            local edge_bin="${edge_link}/opskit-edge"
            if [[ ! -L "${edge_link}" ]]; then
                DRIFTED_ITEMS+=("fetch_cli: Missing versioned symlink '${edge_link}'")
            elif [[ ! -f "${edge_bin}" ]]; then
                DRIFTED_ITEMS+=("fetch_cli: Missing edge executable at '${edge_bin}'")
            elif [[ ! -x "${edge_bin}" ]]; then
                DRIFTED_ITEMS+=("fetch_cli: Edge binary at '${edge_bin}' is not executable")
            elif [[ -n "${recorded_edge_sha}" ]]; then
                local actual_edge_sha
                actual_edge_sha="$(compute_sha256 "${edge_bin}")"
                if [[ "${actual_edge_sha}" != "${recorded_edge_sha}" ]]; then
                    DRIFTED_ITEMS+=("fetch_cli: Digest mismatch at '${edge_bin}' (expected ${recorded_edge_sha})")
                fi
            fi
        fi
    fi
}

repair_configuration() {
    require_root

    if [[ -n "${FLAG_PROFILE:-}" ]]; then
        case "${FLAG_PROFILE}" in
            direct|tunnel|private) ;;
            *)
                die "${EXIT_USAGE_ERROR}" "Invalid profile '${FLAG_PROFILE}'. Valid profiles are: direct, tunnel, private."
                ;;
        esac
    fi

    if [[ ! -f "${LEDGER_FILE}" ]]; then
        if [[ -f "${LEDGER_KEY_FILE}" || -f "${LEDGER_HEAD_FILE}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Cannot repair: ledger '${LEDGER_FILE}' is missing while key or head anchor exists."
        fi
        cleanup_lock_only_state_dir
        die "${EXIT_NOT_FOUND}" "Cannot repair: no applied mutation ledger found at '${LEDGER_FILE}'."
    fi

    if ! validate_entire_ledger; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot repair: ledger integrity verification failed (corrupt or tampered entries)."
    fi

    log_info "Auditing system state against local ledger '${LEDGER_FILE}'..."
    _audit_repair_state

    if [[ -n "${FLAG_PROFILE:-}" && "${FLAG_PROFILE}" != "${RECORDED_PROFILE}" ]]; then
        log_warn "Requested profile '${FLAG_PROFILE}' differs from ledger profile '${RECORDED_PROFILE}'."
        if [[ -z "${FLAG_YES:-}" ]]; then
            if [[ -t 0 ]]; then
                read -r -p "Authorize profile transition from '${RECORDED_PROFILE}' to '${FLAG_PROFILE}'? [y/N]: " p_confirm
                case "${p_confirm}" in
                    y|Y|yes|YES) ;;
                    *)
                        die "${EXIT_SAFETY_GUARD}" "Profile transition cancelled by operator."
                        ;;
                esac
            else
                die "${EXIT_SAFETY_GUARD}" "Profile transition requires explicit authorization. Pass --yes to confirm transition from '${RECORDED_PROFILE}' to '${FLAG_PROFILE}'."
            fi
        fi
    fi

    if [[ ${#DRIFTED_ITEMS[@]} -eq 0 ]]; then
        log_info "No configuration drift detected. System state matches local ledger under '${CHOSEN_PROFILE}' profile."
        return 0
    fi

    log_warn "Configuration drift detected (${#DRIFTED_ITEMS[@]} item(s)) under '${CHOSEN_PROFILE}' profile:"
    for d in "${DRIFTED_ITEMS[@]}"; do
        echo "  - ${d}" >&2
    done

    if [[ -z "${FLAG_YES:-}" ]]; then
        if [[ -t 0 ]]; then
            read -r -p "Repair the above configuration drift? [y/N]: " confirm
            case "${confirm}" in
                y|Y|yes|YES) ;;
                *)
                    log_info "Repair cancelled by operator."
                    return 0
                    ;;
            esac
        else
            die "${EXIT_SAFETY_GUARD}" "Configuration drift detected. Pass --yes to authorize repair in non-interactive mode."
        fi
    fi

    ensure_bootstrap_state_dir
    (
        flock -x 201
        _apply_repair_locked
    ) 201>"${BOOTSTRAP_STATE_DIR}/.state.lock"
}

_apply_repair_locked() {
    if [[ ! -f "${LEDGER_FILE}" ]]; then
        if [[ -f "${LEDGER_KEY_FILE}" || -f "${LEDGER_HEAD_FILE}" ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Cannot repair: ledger '${LEDGER_FILE}' is missing while key or head anchor exists."
        fi
        cleanup_lock_only_state_dir
        die "${EXIT_NOT_FOUND}" "Cannot repair: no applied mutation ledger found at '${LEDGER_FILE}'."
    fi

    if ! validate_entire_ledger; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot repair: ledger integrity verification failed (corrupt or tampered entries)."
    fi

    _audit_repair_state
    if [[ ${#DRIFTED_ITEMS[@]} -eq 0 ]]; then
        log_info "No configuration drift detected. System state matches local ledger under '${CHOSEN_PROFILE}' profile."
        return 0
    fi

    log_info "Authorizing and applying repairs under profile '${CHOSEN_PROFILE}'..."
    if [[ "${CHOSEN_PROFILE}" != "${RECORDED_PROFILE}" ]]; then
        perform_profile_transition_cleanup "${RECORDED_PROFILE}" "${CHOSEN_PROFILE}"
    fi
    detect_capabilities
    if [[ "${CHOSEN_PROFILE}" == "direct" ]]; then
        verify_local_bind
    fi
    if [[ "${CHOSEN_PROFILE}" == "direct" && "${RECORDED_PROFILE}" == "direct" ]]; then
        local old_fw_meta_args=()
        if [[ -f "${LEDGER_FILE}" ]]; then
            local old_fw_raw=""
            old_fw_raw="$(python3 -B -c "
import json, sys
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if d.get('mutation_id') == 'firewall_rules':
                print(json.dumps(d.get('metadata', {})))
        except Exception:
            pass
" "${LEDGER_FILE}" 2>/dev/null || true)"
            if [[ -n "${old_fw_raw}" ]]; then
                while IFS= read -r mline; do
                    [[ -n "${mline}" ]] && old_fw_meta_args+=("${mline}")
                done <<< "${old_fw_raw}"
            fi
        fi
        if [[ ${#old_fw_meta_args[@]} -gt 0 ]]; then
            local fw_m superseded_rules=""
            for fw_m in "${old_fw_meta_args[@]}"; do
                superseded_rules="$(python3 -B -c "
import json, sys
active_stack = sys.argv[2]
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(0)
for key in ('rule443', 'rule80'):
    r = d.get(key)
    if isinstance(r, dict):
        st = str(r.get('stack', '') or '')
        if st in ('nftables', 'iptables') and st != active_stack:
            print(json.dumps(r))
" "${fw_m}" "${FIREWALL_STACK}" 2>/dev/null || true)"
                if [[ -n "${superseded_rules}" ]]; then
                    local sup_rule
                    while IFS= read -r sup_rule; do
                        [[ -n "${sup_rule}" ]] && family_remove_firewall_rule "${sup_rule}"
                    done <<< "${superseded_rules}"
                fi
            done
        fi
        local other_stack_survivors=()
        mapfile -t other_stack_survivors < <(collect_tagged_firewall_survivors --exclude-stack "${FIREWALL_STACK}" "${old_fw_meta_args[@]+"${old_fw_meta_args[@]}"}")
        if [[ ${#other_stack_survivors[@]} -gt 0 ]]; then
            die "${EXIT_RUNTIME_ERROR}" "Cannot complete repair: OpsKit firewall rules remain staged or active outside active stack '${FIREWALL_STACK}' (${other_stack_survivors[*]}). Ledger entries retained."
        fi
    fi
    PROBE_STATUS="reconstructed_from_ledger"
    PROBE_REACHABLE_V4=false
    PROBE_REACHABLE_V6=false
    PROBE_DETAILS="Profile reconstructed from local audit ledger."
    compile_plan
    apply_mutations
    log_info "Repair completed successfully."
}
