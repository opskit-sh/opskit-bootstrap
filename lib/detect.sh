#!/usr/bin/env bash
# Read-only system capability and hardware detection for opskit-bootstrap.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh is loaded

# Minimal OS-family + Python 3 discovery used by offline --undo without running pre-bootstrap gates.
detect_os_family() {
    validate_test_hooks
    local os_release_file="${OPSKIT_OS_RELEASE_FILE:-/etc/os-release}"
    if [[ ! -f "${os_release_file}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot identify host operating system: '${os_release_file}' not found."
    fi

    OS_ID=""
    OS_NAME=""
    OS_VERSION_ID=""
    OS_VERSION=""
    ID_LIKE=""

    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        key="$(echo "${key}" | tr -d '[:space:]')"
        value="${value%\"}"
        value="${value#\"}"
        case "${key}" in
            ID) OS_ID="${value}" ;;
            NAME) OS_NAME="${value}" ;;
            VERSION_ID) OS_VERSION_ID="${value}" ;;
            VERSION) OS_VERSION="${value}" ;;
            ID_LIKE) ID_LIKE="${value}" ;;
        esac
    done < "${os_release_file}"

    DETECTED_FAMILY=""
    case "${OS_ID}" in
        debian|ubuntu)
            DETECTED_FAMILY="debian"
            ;;
        rhel|centos|rocky|almalinux|fedora)
            DETECTED_FAMILY="rhel"
            ;;
        sles|sled|sles_sap|opensuse-leap|opensuse-tumbleweed)
            DETECTED_FAMILY="sles"
            ;;
        *)
            if [[ "${ID_LIKE}" =~ (rhel|centos|fedora) ]]; then
                DETECTED_FAMILY="rhel"
            elif [[ "${ID_LIKE}" =~ (suse|opensuse) ]]; then
                DETECTED_FAMILY="sles"
            elif [[ "${ID_LIKE}" =~ (debian|ubuntu) ]]; then
                DETECTED_FAMILY="debian"
            else
                die "${EXIT_VALIDATION_ERROR}" "Unsupported distribution '${OS_ID}'. Supported distributions are Debian 13+, Ubuntu 24.04+, RHEL 9+, Fedora Server 39+, and SLES 15 SP7+."
            fi
            ;;
    esac

    if ! command -v python3 >/dev/null 2>&1; then
        local remedy=""
        case "${DETECTED_FAMILY}" in
            debian) remedy="Install Python 3 via 'apt-get update && apt-get install -y python3'." ;;
            rhel) remedy="Install Python 3 via 'dnf install -y python3'." ;;
            sles) remedy="Install Python 3 via 'zypper install -y python3'." ;;
            *) remedy="Install Python 3 using your system package manager." ;;
        esac
        die "${EXIT_VALIDATION_ERROR}" "Python 3 is required for release manifest cryptographic verification and ledger validation. ${remedy}"
    fi
}

detect_capabilities() {
    detect_os_family

    # Enforce strict distribution ID and version gates (no un-gated ID_LIKE fallback).
    case "${OS_ID}" in
        debian)
            local major_version="${OS_VERSION_ID%%.*}"
            if [[ -z "${major_version}" ]] || ! [[ "${major_version}" =~ ^[0-9]+$ ]] || [[ "${major_version}" -lt 13 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Debian 13 (trixie) or higher required; found Debian ${OS_VERSION_ID:-unknown}. Upgrade to Debian 13 using 'apt-get dist-upgrade'."
            fi
            ;;
        ubuntu)
            local major_version="${OS_VERSION_ID%%.*}"
            if [[ -z "${major_version}" ]] || ! [[ "${major_version}" =~ ^[0-9]+$ ]] || [[ "${major_version}" -lt 24 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Ubuntu 24.04 LTS (noble) or higher required; found Ubuntu ${OS_VERSION_ID:-unknown}. Upgrade using 'do-release-upgrade'."
            fi
            ;;
        rhel|centos|rocky|almalinux)
            local major_version="${OS_VERSION_ID%%.*}"
            if [[ -z "${major_version}" ]] || ! [[ "${major_version}" =~ ^[0-9]+$ ]] || [[ "${major_version}" -lt 9 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Enterprise Linux 9 or higher required; found ${OS_NAME} ${OS_VERSION_ID:-unknown}. Upgrade using 'dnf system-upgrade'."
            fi
            ;;
        fedora)
            local major_version="${OS_VERSION_ID%%.*}"
            if [[ -z "${major_version}" ]] || ! [[ "${major_version}" =~ ^[0-9]+$ ]] || [[ "${major_version}" -lt 39 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Fedora Server 39 or higher required; found Fedora ${OS_VERSION_ID:-unknown}. Upgrade using 'dnf system-upgrade'."
            fi
            ;;
        sles|sled|sles_sap)
            local major_version="${OS_VERSION_ID%%.*}"
            local sp_version="0"
            if [[ "${OS_VERSION_ID}" == *.* ]]; then
                sp_version="${OS_VERSION_ID#*.}"
                sp_version="${sp_version%%.*}"
            fi
            if [[ -z "${major_version}" ]] || ! [[ "${major_version}" =~ ^[0-9]+$ ]] || ! [[ "${sp_version}" =~ ^[0-9]+$ ]] \
               || [[ "${major_version}" -lt 15 ]] || [[ "${major_version}" -eq 15 && "${sp_version}" -lt 7 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "SUSE Linux Enterprise Server 15 SP7+ required; found ${OS_NAME} ${OS_VERSION_ID:-unknown}. Upgrade via YaST or 'zypper migration'."
            fi
            ;;
        opensuse-leap)
            local major_version="${OS_VERSION_ID%%.*}"
            local minor_version="0"
            if [[ "${OS_VERSION_ID}" == *.* ]]; then
                minor_version="${OS_VERSION_ID#*.}"
                minor_version="${minor_version%%.*}"
            fi
            if [[ -z "${major_version}" ]] || ! [[ "${major_version}" =~ ^[0-9]+$ ]] || ! [[ "${minor_version}" =~ ^[0-9]+$ ]] \
               || [[ "${major_version}" -lt 15 ]] || [[ "${major_version}" -eq 15 && "${minor_version}" -lt 6 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "openSUSE Leap 15.6+ required; found openSUSE Leap ${OS_VERSION_ID:-unknown}. Upgrade via 'zypper dup'."
            fi
            ;;
        opensuse-tumbleweed)
            ;;
        *)
            die "${EXIT_VALIDATION_ERROR}" "Unsupported distribution '${OS_ID}'. Supported distributions are Debian 13+, Ubuntu 24.04+, RHEL 9+, Fedora Server 39+, and SLES 15 SP7+."
            ;;
    esac

    # Linux kernel gate: >= 5.4
    # Upstream isolation floor (user namespaces + cgroups v2): https://man7.org/linux/man-pages/man7/user_namespaces.7.html
    KERNEL_RELEASE="${MOCK_KERNEL_RELEASE:-$(uname -r)}"
    local k_major k_minor
    k_major="$(echo "${KERNEL_RELEASE}" | cut -d. -f1)"
    k_minor="$(echo "${KERNEL_RELEASE}" | cut -d. -f2)"
    k_minor="${k_minor%%[^0-9]*}"
    if [[ ! "${k_major}" =~ ^[0-9]+$ || ! "${k_minor}" =~ ^[0-9]+$ ]] || [[ "${k_major}" -lt 5 ]] || [[ "${k_major}" -eq 5 && "${k_minor}" -lt 4 ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Linux kernel 5.4 or higher required for rootless container isolation; found kernel ${KERNEL_RELEASE}."
    fi

    # cgroups v2 check (unified hierarchy required; hybrid v1+v2 is rejected)
    # Upstream cgroups v2 hierarchy and resource controllers: https://docs.kernel.org/admin-guide/cgroup-v2.html
    CGROUPS_V2=false
    CGROUP_CONTROLLERS=()
    if [[ -n "${MOCK_CGROUP_CONTROLLERS:-}" ]]; then
        CGROUPS_V2=true
        read -r -a CGROUP_CONTROLLERS <<< "${MOCK_CGROUP_CONTROLLERS}"
    elif [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
        CGROUPS_V2=true
        while IFS= read -r ctrl; do
            [[ -n "${ctrl}" ]] && CGROUP_CONTROLLERS+=("${ctrl}")
        done < <(tr ' ' '\n' < /sys/fs/cgroup/cgroup.controllers)
    elif [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && -n "${OPSKIT_FORCE_CGROUPS_V2:-}" ]]; then
        CGROUPS_V2=true
        CGROUP_CONTROLLERS=("cpu" "memory" "io" "pids")
    fi

    if ! ${CGROUPS_V2}; then
        die "${EXIT_VALIDATION_ERROR}" "Unified cgroups v2 hierarchy (/sys/fs/cgroup/cgroup.controllers) is required for rootless container resource isolation."
    fi

    # systemd system manager verification
    SYSTEMD_RUNNING=false
    if [[ -d /run/systemd/system ]]; then
        SYSTEMD_RUNNING=true
    elif [[ -n "${OPSKIT_FORCE_SYSTEMD:-}" ]]; then
        SYSTEMD_RUNNING=true
    else
        local p1_comm
        p1_comm="$(cat /proc/1/comm 2>/dev/null || true)"
        if [[ "${p1_comm}" =~ (systemd|init) ]]; then
            SYSTEMD_RUNNING=true
        fi
    fi

    # systemd user manager verification
    # Upstream systemd per-user service manager execution environment: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
    SYSTEMD_USER_MANAGER=false
    if ${SYSTEMD_RUNNING}; then
        if [[ -d /usr/lib/systemd/user || -d /etc/systemd/user || -d /run/systemd/user ]]; then
            SYSTEMD_USER_MANAGER=true
        elif command -v systemctl >/dev/null 2>&1; then
            SYSTEMD_USER_MANAGER=true
        fi
    fi

    # Container runtime discovery
    RUNTIME_CHOICE="${FLAG_RUNTIME:-auto}"
    case "${RUNTIME_CHOICE}" in
        auto|podman|docker) ;;
        *)
            die "${EXIT_USAGE_ERROR}" "Invalid runtime '${RUNTIME_CHOICE}'. Valid runtimes are: auto, podman, docker."
            ;;
    esac
    DETECTED_RUNTIME=""
    RUNTIME_VERSION=""
    PODMAN_PACKAGE_NEEDED=false
    DOCKER_ROOTLESS_USABLE=false
    DOCKER_DAEMON_ROOTFUL=false
    DOCKER_ROOTLESS_PACKAGE_NEEDED=false
    CGROUP_DELEGATION_ENABLED=false

    if [[ "${RUNTIME_CHOICE}" == "docker" ]]; then
        if command -v docker >/dev/null 2>&1; then
            DETECTED_RUNTIME="docker"
            RUNTIME_VERSION="$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')"
        else
            die "${EXIT_VALIDATION_ERROR}" "Runtime 'docker' requested but docker executable not found in PATH."
        fi
    elif [[ "${RUNTIME_CHOICE}" == "podman" || "${RUNTIME_CHOICE}" == "auto" ]]; then
        if [[ -n "${MOCK_RUNTIME_VERSION:-}" ]]; then
            DETECTED_RUNTIME="podman"
            RUNTIME_VERSION="${MOCK_RUNTIME_VERSION}"
        elif command -v podman >/dev/null 2>&1; then
            DETECTED_RUNTIME="podman"
            RUNTIME_VERSION="$(podman --version 2>/dev/null | awk '{print $3}')"
            # Version gate: Podman >= 4.4 required for systemd Quadlet support
            # Upstream Quadlet generator specification (merged Podman 4.4): https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html
            local p_major p_minor
            p_major="$(echo "${RUNTIME_VERSION}" | cut -d. -f1)"
            p_minor="$(echo "${RUNTIME_VERSION}" | cut -d. -f2)"
            p_minor="${p_minor%%[^0-9]*}"
            if [[ ! "${p_major}" =~ ^[0-9]+$ || ! "${p_minor}" =~ ^[0-9]+$ ]] || [[ "${p_major}" -lt 4 ]] || [[ "${p_major}" -eq 4 && "${p_minor}" -lt 4 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Podman 4.4+ required for Quadlet; found Podman ${RUNTIME_VERSION}. Upgrade podman using your system package manager."
            fi
        else
            if [[ "${RUNTIME_CHOICE}" == "auto" ]] && command -v docker >/dev/null 2>&1; then
                DETECTED_RUNTIME="docker"
                RUNTIME_VERSION="$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')"
            else
                DETECTED_RUNTIME="podman"
                PODMAN_PACKAGE_NEEDED=true
            fi
        fi
    fi

    # User namespace tools
    # Upstream user namespace subordinate mapping toolchain: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
    NEWUIDMAP_PRESENT=false
    NEWGIDMAP_PRESENT=false
    UIDMAP_PACKAGE_NEEDED=false
    if command -v newuidmap >/dev/null 2>&1; then
        NEWUIDMAP_PRESENT=true
    fi
    if command -v newgidmap >/dev/null 2>&1; then
        NEWGIDMAP_PRESENT=true
    fi
    if ! ${NEWUIDMAP_PRESENT} || ! ${NEWGIDMAP_PRESENT}; then
        UIDMAP_PACKAGE_NEEDED=true
    fi

    # Subuid and Subgid files (audit both before marking allocation complete)
    # Upstream subordinate user and group ID range specifications: https://man7.org/linux/man-pages/man5/subuid.5.html and https://man7.org/linux/man-pages/man5/subgid.5.html
    SUBUID_FILE="${OPSKIT_SUBUID_FILE:-/etc/subuid}"
    SUBGID_FILE="${OPSKIT_SUBGID_FILE:-/etc/subgid}"
    SUBUID_ALLOCATED=false
    SUBUID_ENTRY_PRESENT=false
    SUBGID_ENTRY_PRESENT=false
    EXISTING_SUBUID_RANGE=""
    EXISTING_SUBGID_RANGE=""
    _validate_subid_entry() {
        local label="$1"
        local range="$2"
        local sub_start sub_count
        sub_start="$(echo "${range}" | cut -d: -f1)"
        sub_count="$(echo "${range}" | cut -d: -f2)"
        if [[ ! "${sub_start}" =~ ^[0-9]+$ || ! "${sub_count}" =~ ^[0-9]+$ ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Invalid non-numeric subordinate ${label} range for '${SERVICE_USER}': ${range}."
        fi
        if [[ "${sub_count}" -le 0 || "${sub_count}" -gt 1000000000 || $(( sub_start + sub_count )) -gt 4294967295 ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Subordinate ${label} range count for '${SERVICE_USER}' out of bounds (${range})."
        fi
    }
    if [[ -f "${SUBUID_FILE}" ]] && grep -q "^${SERVICE_USER}:" "${SUBUID_FILE}" 2>/dev/null; then
        SUBUID_ENTRY_PRESENT=true
        EXISTING_SUBUID_RANGE="$(grep "^${SERVICE_USER}:" "${SUBUID_FILE}" | head -n1 | cut -d: -f2-)"
        _validate_subid_entry "UID" "${EXISTING_SUBUID_RANGE}"
    fi
    if [[ -f "${SUBGID_FILE}" ]] && grep -q "^${SERVICE_USER}:" "${SUBGID_FILE}" 2>/dev/null; then
        SUBGID_ENTRY_PRESENT=true
        EXISTING_SUBGID_RANGE="$(grep "^${SERVICE_USER}:" "${SUBGID_FILE}" | head -n1 | cut -d: -f2-)"
        _validate_subid_entry "GID" "${EXISTING_SUBGID_RANGE}"
        [[ -z "${EXISTING_SUBUID_RANGE}" ]] && EXISTING_SUBUID_RANGE="${EXISTING_SUBGID_RANGE}"
    fi
    if ${SUBUID_ENTRY_PRESENT} && ${SUBGID_ENTRY_PRESENT}; then
        SUBUID_ALLOCATED=true
    fi

    # Service user inspection (audit UID/GID != 0 and ban privileged groups)
    SERVICE_USER_EXISTS=false
    SERVICE_USER_IN_DOCKER=false
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        SERVICE_USER_EXISTS=true
        local svc_uid_chk svc_gid_chk svc_groups
        svc_uid_chk="$(id -u "${SERVICE_USER}")"
        svc_gid_chk="$(id -g "${SERVICE_USER}")"
        if [[ "${svc_uid_chk}" -eq 0 || "${svc_gid_chk}" -eq 0 ]]; then
            die "${EXIT_VALIDATION_ERROR}" "Service user '${SERVICE_USER}' must not have UID 0 or primary GID 0."
        fi
        svc_groups="$(id -Gn "${SERVICE_USER}" 2>/dev/null || true)"
        if grep -qw "docker" <<< "${svc_groups}"; then
            die "${EXIT_VALIDATION_ERROR}" "Service user '${SERVICE_USER}' is in the 'docker' group. The docker group grants unconfined host access, violating the rootless security boundary. Remove the user from the docker group before bootstrapping."
        fi
        local priv_grp
        for priv_grp in sudo wheel root adm lxd libvirt disk shadow; do
            if grep -qw "${priv_grp}" <<< "${svc_groups}"; then
                die "${EXIT_VALIDATION_ERROR}" "Service user '${SERVICE_USER}' is a member of privileged group '${priv_grp}'. Remove this membership before bootstrapping."
            fi
        done
    fi

    # Systemd linger status
    LINGER_ACTIVE=false
    if [[ -d "/var/lib/systemd/linger" ]] && [[ -f "/var/lib/systemd/linger/${SERVICE_USER}" ]]; then
        LINGER_ACTIVE=true
    fi

    # Rootless Docker capability detection (when Docker runtime is selected)
    # Upstream rootless Docker socket and SecurityOptions verification:
    # https://docs.docker.com/engine/security/rootless/
    if [[ "${DETECTED_RUNTIME}" == "docker" ]]; then
        if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && -n "${MOCK_DOCKER_ROOTLESS_USABLE:-}" ]]; then
            if [[ "${MOCK_DOCKER_ROOTLESS_USABLE}" == "true" ]]; then
                DOCKER_ROOTLESS_USABLE=true
                DOCKER_DAEMON_ROOTFUL=false
            else
                DOCKER_ROOTLESS_USABLE=false
                DOCKER_DAEMON_ROOTFUL=true
            fi
        else
            if [[ -S /var/run/docker.sock || -S /run/docker.sock ]] || pgrep -u root -x dockerd >/dev/null 2>&1 || systemctl is-active --quiet docker 2>/dev/null; then
                DOCKER_DAEMON_ROOTFUL=true
            elif command -v dockerd >/dev/null 2>&1; then
                DOCKER_DAEMON_ROOTFUL=true
            fi

            if ${SERVICE_USER_EXISTS}; then
                local svc_uid svc_home candidate_sock
                svc_uid="$(id -u "${SERVICE_USER}")"
                svc_home="$(resolve_service_user_home "${SERVICE_USER}")"
                candidate_sock="$(resolve_service_user_docker_socket "${SERVICE_USER}")"
                if [[ -n "${candidate_sock}" && -S "${candidate_sock}" ]]; then
                    local probed_opts=""
                    if [[ "${EUID}" -eq 0 ]]; then
                        probed_opts="$(run_as_service_user 'HOME="$1" XDG_RUNTIME_DIR="$2" DOCKER_HOST="unix://$3" docker info --format "{{.SecurityOptions}}"' "${svc_home}" "/run/user/${svc_uid}" "${candidate_sock}" 2>/dev/null || true)"
                    elif [[ "$(id -un 2>/dev/null || true)" == "${SERVICE_USER}" ]]; then
                        probed_opts="$(HOME="${svc_home}" XDG_RUNTIME_DIR="/run/user/${svc_uid}" DOCKER_HOST="unix://${candidate_sock}" docker info --format '{{.SecurityOptions}}' 2>/dev/null || true)"
                    else
                        probed_opts="rootless"
                    fi
                    if [[ "${probed_opts}" == *"rootless"* ]]; then
                        DOCKER_ROOTLESS_USABLE=true
                    fi
                fi
            fi

            if ! ${DOCKER_ROOTLESS_USABLE}; then
                if ! command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1 || ! command -v rootlesskit >/dev/null 2>&1; then
                    DOCKER_ROOTLESS_PACKAGE_NEEDED=true
                fi
            fi
        fi
    fi

    # Systemd user slice cgroup v2 delegation detection
    # Upstream systemd cgroup delegation and rootless container requirements:
    # https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
    # https://rootlesscontaine.rs/getting-started/common/cgroup2/
    if [[ "${OPSKIT_TEST_HOOKS_COMPILED}" == "1" && "${OPSKIT_TEST_MODE:-0}" == "1" && -n "${MOCK_CGROUP_DELEGATION:-}" ]]; then
        if [[ "${MOCK_CGROUP_DELEGATION}" == "true" ]]; then
            CGROUP_DELEGATION_ENABLED=true
        else
            CGROUP_DELEGATION_ENABLED=false
        fi
    else
        local svc_uid_cg=""
        if ${SERVICE_USER_EXISTS}; then
            svc_uid_cg="$(id -u "${SERVICE_USER}")"
        fi
        if has_systemd_delegate_yes "${svc_uid_cg}"; then
            CGROUP_DELEGATION_ENABLED=true
            if ${SYSTEMD_RUNNING} && command -v systemctl >/dev/null 2>&1 && [[ -n "${svc_uid_cg}" ]]; then
                if systemctl is-active --quiet "user@${svc_uid_cg}.service" 2>/dev/null; then
                    local del_ctrls=""
                    del_ctrls="$(systemctl show "user@${svc_uid_cg}.service" -p DelegateControllers --value 2>/dev/null || true)"
                    if [[ "${del_ctrls}" != *"memory"* || "${del_ctrls}" != *"cpu"* || "${del_ctrls}" != *"pids"* ]]; then
                        CGROUP_DELEGATION_ENABLED=false
                    fi
                fi
            fi
        fi
    fi

    # Security modules audit (never disabled)
    SELINUX_STATUS="absent"
    if [[ -n "${MOCK_SELINUX_STATUS:-}" ]]; then
        SELINUX_STATUS="${MOCK_SELINUX_STATUS}"
    elif command -v getenforce >/dev/null 2>&1; then
        SELINUX_STATUS="$(getenforce | tr '[:upper:]' '[:lower:]')"
    fi

    APPARMOR_STATUS="absent"
    if [[ -n "${MOCK_APPARMOR_STATUS:-}" ]]; then
        APPARMOR_STATUS="${MOCK_APPARMOR_STATUS}"
    elif [[ -d /sys/kernel/security/apparmor ]]; then
        if command -v aa-status >/dev/null 2>&1; then
            if aa-status --enabled 2>/dev/null; then
                APPARMOR_STATUS="enforcing"
            else
                APPARMOR_STATUS="disabled"
            fi
        else
            APPARMOR_STATUS="present"
        fi
    fi

    # Firewall stack detection (matches family_apply_firewall_rule precedence)
    FIREWALL_STACK="none"
    if command -v firewalld >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        FIREWALL_STACK="firewalld"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qE '^Status:[[:space:]]+active'; then
        FIREWALL_STACK="ufw"
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_STACK="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_STACK="iptables"
    fi

    # Disk space verification: >= 5 GiB (5,242,880 KB) on /var and distinct /home mount
    local target_mount="/var"
    [[ ! -d "${target_mount}" ]] && target_mount="/"
    local avail_kb
    avail_kb="$(df -Pk "${target_mount}" 2>/dev/null | awk 'NR==2 {print $4}')"
    DISK_FREE_GB="${MOCK_DISK_FREE_GB:-$(( ${avail_kb:-0} / 1048576 ))}"
    if [[ -z "${OPSKIT_SKIP_DISK_CHECK:-}" ]]; then
        if [[ -n "${MOCK_DISK_FREE_GB:-}" ]]; then
            if [[ ! "${MOCK_DISK_FREE_GB}" =~ ^[0-9]+$ ]] || [[ "${MOCK_DISK_FREE_GB}" -lt 5 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "At least 5 GiB of free disk space is required on ${target_mount}; found ${MOCK_DISK_FREE_GB} GiB."
            fi
        else
            if [[ "${avail_kb:-0}" -lt 5242880 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "At least 5 GiB of free disk space is required on ${target_mount}; found ${DISK_FREE_GB} GiB."
            fi
            if [[ -d /home ]]; then
                local var_dev home_dev home_kb home_gb
                var_dev="$(stat -c %d "${target_mount}" 2>/dev/null || echo "")"
                home_dev="$(stat -c %d /home 2>/dev/null || echo "")"
                if [[ -n "${var_dev}" && -n "${home_dev}" && "${var_dev}" != "${home_dev}" ]]; then
                    home_kb="$(df -Pk /home 2>/dev/null | awk 'NR==2 {print $4}')"
                    home_gb="$(( ${home_kb:-0} / 1048576 ))"
                    if [[ "${home_kb:-0}" -lt 5242880 ]]; then
                        die "${EXIT_VALIDATION_ERROR}" "At least 5 GiB of free disk space is required on /home; found ${home_gb} GiB."
                    fi
                fi
            fi
        fi
    fi

    # Clock skew evaluation: warn > 60s, hard fail > 300s
    CLOCK_SKEW_SECONDS="${MOCK_CLOCK_SKEW:-}"
    if [[ -z "${CLOCK_SKEW_SECONDS}" ]]; then
        CLOCK_SKEW_SECONDS=0
        if command -v chronyc >/dev/null 2>&1; then
            local offset
            offset="$(chronyc tracking 2>/dev/null | awk '/System time/ {print $4; exit} /Last offset/ {print $4; exit}' | tr -d '+' | cut -d. -f1 || echo 0)"
            CLOCK_SKEW_SECONDS="${offset:-0}"
        elif command -v timedatectl >/dev/null 2>&1; then
            local td_status
            td_status="$(timedatectl status 2>/dev/null || true)"
            if grep -qi "System clock synchronized: yes" <<< "${td_status}"; then
                CLOCK_SKEW_SECONDS=0
            elif grep -qi "System clock synchronized: no" <<< "${td_status}"; then
                log_warn "System clock is not synchronized via NTP (timedatectl reports 'System clock synchronized: no')."
                local ts_offset
                ts_offset="$(timedatectl timesync-status 2>/dev/null | awk '/Offset:/ {print $2}' | tr -d '+s' | cut -d. -f1 || true)"
                if [[ "${ts_offset}" =~ ^-?[0-9]+$ ]]; then
                    CLOCK_SKEW_SECONDS="${ts_offset}"
                fi
            fi
        fi
    fi
    local abs_skew="${CLOCK_SKEW_SECONDS#-}"
    if [[ "${abs_skew}" =~ ^[0-9]+$ ]]; then
        if [[ "${abs_skew}" -gt 300 ]]; then
            die "${EXIT_VALIDATION_ERROR}" "System clock skew (${CLOCK_SKEW_SECONDS}s) exceeds maximum allowable threshold of 300s. Synchronize time via NTP before bootstrapping."
        elif [[ "${abs_skew}" -gt 60 ]]; then
            log_warn "System clock skew is ${CLOCK_SKEW_SECONDS}s (> 60s)."
        fi
    fi
}
