#!/usr/bin/env bash
# Inbound reachability probing and exposure profile negotiation.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh is loaded

resolve_profile() {
    PROBE_STATUS="not_probed"
    PROBE_REACHABLE_V4=false
    PROBE_REACHABLE_V6=false
    PROBE_DETAILS=""

    # 1. If explicit profile flag passed, validate and use it
    if [[ -n "${FLAG_PROFILE:-}" ]]; then
        case "${FLAG_PROFILE}" in
            direct|tunnel|private)
                CHOSEN_PROFILE="${FLAG_PROFILE}"
                ;;
            *)
                die "${EXIT_USAGE_ERROR}" "Invalid profile '${FLAG_PROFILE}'. Valid profiles are: direct, tunnel, private."
                ;;
        esac
    else
        # 2. Interactive intent question or non-interactive default
        local intent=""
        if [[ -t 0 ]] && [[ -z "${FLAG_YES:-}" ]]; then
            echo "" >&2
            echo "==================================================================" >&2
            echo "Reachability Intent Question:" >&2
            echo "Can this machine accept inbound HTTPS from the public internet on TCP 443?" >&2
            echo "==================================================================" >&2
            read -r -p "[yes / no / not sure]: " answer
            answer="$(echo "${answer}" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            case "${answer}" in
                y|yes) intent="yes" ;;
                n|no) intent="no" ;;
                *) intent="not_sure" ;;
            esac
        else
            # Non-interactive without explicit profile
            if [[ -z "${OPSKIT_PROBE_SERVER:-}" || -n "${FLAG_NO_PROBE:-}" ]]; then
                # Non-interactive without probe capability: default to least-privileged 'tunnel' profile
                CHOSEN_PROFILE="tunnel"
                PROBE_STATUS="skipped"
                PROBE_DETAILS="Non-interactive invocation without an explicit --profile defaults to least-privileged 'tunnel' profile."
                log_info "Non-interactive invocation without --profile defaults to 'tunnel'. Pass --profile direct to explicitly request direct ingress."
                return 0
            else
                intent="not_sure"
            fi
        fi

        case "${intent}" in
            no)
                CHOSEN_PROFILE="tunnel"
                PROBE_STATUS="skipped"
                PROBE_DETAILS="Operator selected tunnel profile (no public inbound access)."
                return 0
                ;;
            yes)
                CHOSEN_PROFILE="direct"
                ;;
            not_sure)
                if [[ -n "${OPSKIT_PROBE_SERVER:-}" ]]; then
                    CHOSEN_PROFILE="direct"
                else
                    CHOSEN_PROFILE="tunnel"
                    PROBE_STATUS="skipped"
                    PROBE_DETAILS="Uncertain inbound reachability without probe server defaults to 'tunnel' profile."
                    log_info "Uncertain inbound reachability without probe capability defaults to 'tunnel' profile."
                    return 0
                fi
                ;;
        esac
    fi

    # 3. Handle private profile
    if [[ "${CHOSEN_PROFILE}" == "private" ]]; then
        PROBE_STATUS="skipped"
        PROBE_DETAILS="Private profile selected: no public ingress probing required."
        return 0
    fi

    # 4. Handle tunnel profile
    if [[ "${CHOSEN_PROFILE}" == "tunnel" ]]; then
        PROBE_STATUS="skipped"
        PROBE_DETAILS="Tunnel profile selected: ingress established via outbound overlay."
        return 0
    fi

    # 5. Direct profile probing + mandatory local bind verification
    if [[ -n "${FLAG_NO_PROBE:-}" ]]; then
        PROBE_STATUS="skipped"
        PROBE_DETAILS="Probe skipped by --no-probe flag; local bind verification only."
        verify_local_bind
        return 0
    fi

    local probe_url="${OPSKIT_PROBE_SERVER:-}"
    if [[ -n "${probe_url}" ]]; then
        perform_external_probe "${probe_url}"
        if [[ "${CHOSEN_PROFILE}" == "direct" ]]; then
            verify_local_bind
        fi
    else
        verify_local_bind
        PROBE_STATUS="verified_local"
        PROBE_DETAILS="Port 443 local bind available. Authoritative reachability will be confirmed via ACME TLS-ALPN-01."
    fi
}

# Verify that required direct-profile TCP ports (443, and 80 unless --no-http)
# are not bound by a foreign process (e.g., nginx/apache/caddy).
verify_local_bind() {
    if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && "${OPSKIT_SKIP_BIND_CHECK:-0}" == "1" ]]; then
        return 0
    fi

    local ports=(443)
    if [[ "${FLAG_NO_HTTP:-false}" != "true" ]]; then
        ports+=(80)
    fi

    local p
    for p in "${ports[@]}"; do
        # Skip if OpsKit's own systemd socket unit is already actively holding this port.
        if [[ "${SYSTEMD_RUNNING:-false}" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
            if systemctl is-active --quiet "opskit-edge-${p}.socket" 2>/dev/null; then
                continue
            fi
        fi

        local occupant=""
        if command -v ss >/dev/null 2>&1; then
            occupant="$(ss -Htlpn 2>/dev/null | awk -v port="${p}" '
                {
                    addr = $4
                    if (addr ~ ("(^|:|\\])" port "$")) {
                        print $0
                        exit
                    }
                }
            ' || true)"
        elif [[ -r /proc/net/tcp || -r /proc/net/tcp6 ]]; then
            local hex_port
            hex_port="$(printf '%04X' "${p}")"
            occupant="$(awk -v hp="${hex_port}" '
                NR > 1 {
                    split($2, a, ":")
                    if (toupper(a[2]) == hp && $4 == "0A") {
                        print $2
                        exit
                    }
                }
            ' /proc/net/tcp /proc/net/tcp6 2>/dev/null || true)"
        fi

        if [[ -n "${occupant}" ]]; then
            if [[ "${occupant}" == *"opskit-edge"* ]]; then
                continue
            fi
            local proc_desc="unknown process (run with sudo to identify)"
            if [[ "${occupant}" == *"users:("* ]]; then
                proc_desc="$(sed -n 's/.*users:((\([^)]*\)).*/\1/p' <<< "${occupant}")"
                [[ -z "${proc_desc}" ]] && proc_desc="${occupant}"
            fi
            if [[ "${p}" == "80" ]]; then
                die "${EXIT_CONFLICT}" "Port 80 is already in use by a foreign service (${proc_desc}). Stop or reconfigure that service, re-run with --no-http to bind only TCP 443 (ACME TLS-ALPN-01), or choose --profile tunnel / --profile private."
            else
                die "${EXIT_CONFLICT}" "Port 443 is already in use by a foreign service (${proc_desc}). Stop or reconfigure that service to free TCP 443, or choose --profile tunnel / --profile private."
            fi
        fi
    done
}

perform_external_probe() {
    local probe_endpoint="$1"
    validate_remote_url "${probe_endpoint}" "probe server URL"
    set_curl_proto_flags "${probe_endpoint}"

    log_info "Probing inbound TCP 443 reachability via ${probe_endpoint}..."

    local probe_curl_flags=(-s -S --max-time 10 "${CURL_PROTO_FLAGS[@]}" --max-filesize 65536)
    [[ -n "${FLAG_PROXY:-}" ]] && probe_curl_flags+=(--proxy "${FLAG_PROXY}")
    [[ -n "${FLAG_CACERT:-}" ]] && probe_curl_flags+=(--cacert "${FLAG_CACERT}")

    local probe_response=""
    probe_response="$(curl "${probe_curl_flags[@]}" -X POST "${probe_endpoint}" 2>/dev/null || true)"

    local has_v6_route="false"
    if [[ "${MOCK_HAS_V6_ROUTE:-0}" == "1" ]]; then
        has_v6_route="true"
    elif command -v ip >/dev/null 2>&1; then
        if ip -6 route show default 2>/dev/null | grep '^default' >/dev/null 2>&1; then
            has_v6_route="true"
        fi
    fi

    local result
    result="$(python3 -B -c "
import json, sys
raw = sys.argv[1].strip()
has_v6_route = (sys.argv[2] == 'true')
if not raw:
    print('failed:false:false:empty_response')
    sys.exit(0)
try:
    d = json.loads(raw)
    vps = d.get('vantage_points', [])
    if vps:
        if len(vps) < 2:
            any_v4 = any(vp.get('reachable_v4', vp.get('reachable', False)) for vp in vps)
            any_v6 = any(vp.get('reachable_v6', False) for vp in vps)
            print(f'partial:{str(any_v4).lower()}:{str(any_v6).lower()}:single_vantage_insufficient')
            sys.exit(0)

        vp_results = []
        for vp in vps:
            v4 = vp.get('reachable_v4', vp.get('reachable', False))
            v6 = vp.get('reachable_v6', False)
            vp_results.append((v4, v6))

        all_v4 = all(r[0] for r in vp_results)
        all_v6 = all(r[1] for r in vp_results)
        any_v4 = any(r[0] for r in vp_results)
        any_v6 = any(r[1] for r in vp_results)

        if not (any_v4 or any_v6):
            print('failed:false:false:all_vantages_unreachable')
            sys.exit(0)

        if not all_v4:
            print(f'partial:{str(any_v4).lower()}:{str(any_v6).lower()}:dual_vantage_v4_failed')
            sys.exit(0)

        if has_v6_route and not all_v6:
            print(f'partial:{str(all_v4).lower()}:{str(any_v6).lower()}:dual_vantage_v6_failed_with_active_route')
            sys.exit(0)

        print(f'verified:{str(all_v4).lower()}:{str(all_v6).lower()}:ok')
    else:
        v4_pass = d.get('reachable_v4', d.get('reachable', False))
        v6_pass = d.get('reachable_v6', False)

        if not (v4_pass or v6_pass):
            print('failed:false:false:unreachable')
            sys.exit(0)

        if not v4_pass:
            print(f'partial:false:{str(v6_pass).lower()}:v6_only_unsupported')
            sys.exit(0)

        if has_v6_route and not v6_pass:
            print(f'partial:{str(v4_pass).lower()}:false:v6_route_active_but_unreachable')
            sys.exit(0)

        print(f'verified:{str(v4_pass).lower()}:{str(v6_pass).lower()}:ok')
except Exception as e:
    print('failed:false:false:parse_error')
" "${probe_response}" "${has_v6_route}" 2>/dev/null || echo "failed:false:false:error")"

    local status v4 v6 reason
    status="$(echo "${result}" | cut -d: -f1)"
    v4="$(echo "${result}" | cut -d: -f2)"
    v6="$(echo "${result}" | cut -d: -f3)"
    reason="$(echo "${result}" | cut -d: -f4)"

    [[ "${v4}" == "true" ]] && PROBE_REACHABLE_V4=true
    [[ "${v6}" == "true" ]] && PROBE_REACHABLE_V6=true

    case "${status}" in
        verified)
            PROBE_STATUS="verified"
            PROBE_DETAILS="Inbound reachability on TCP 443 confirmed by external probe (IPv4=${PROBE_REACHABLE_V4}, IPv6=${PROBE_REACHABLE_V6})."
            return 0
            ;;
        partial)
            PROBE_STATUS="partial"
            PROBE_DETAILS="Inbound reachability partially confirmed (${reason}); dual-vantage and complete dual-stack reachability required."
            log_warn "External reachability probe returned partial verification (${reason})."
            ;;
        failed|*)
            PROBE_STATUS="failed"
            PROBE_DETAILS="Inbound reachability check failed (port blocked, filtered, or behind carrier-grade NAT)."
            log_warn "External probe could not reach TCP 443."
            ;;
    esac

    if [[ -n "${FLAG_PROFILE:-}" && "${FLAG_PROFILE}" == "direct" ]]; then
        log_warn "External reachability probe failed/partial for port 443, but --profile direct was explicitly requested. Continuing with direct profile."
    else
        log_warn "Inbound reachability not verified. Downgrading profile to 'tunnel'."
        CHOSEN_PROFILE="tunnel"
    fi
}
