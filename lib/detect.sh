#!/usr/bin/env bash
# Read-only system capability and hardware detection for opskit-bootstrap.
set -euo pipefail

# Sourced by opskit-bootstrap; assumes common.sh is loaded

detect_capabilities() {
    validate_test_hooks
    local os_release_file="${OPSKIT_OS_RELEASE_FILE:-/etc/os-release}"
    if [[ ! -f "${os_release_file}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Cannot identify host operating system: '${os_release_file}' not found."
    fi

    # Read distribution metadata
    OS_ID=""
    OS_NAME=""
    OS_VERSION_ID=""
    OS_VERSION=""
    ID_LIKE=""

    # Source os-release in a subshell or parse key=value lines
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

    # Determine distribution family and enforce version gates
    DETECTED_FAMILY=""
    case "${OS_ID}" in
        debian)
            DETECTED_FAMILY="debian"
            local major_version="${OS_VERSION_ID%%.*}"
            if [[ -z "${major_version}" ]] || [[ "${major_version}" -lt 13 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Debian 13 (trixie) or higher required; found Debian ${OS_VERSION_ID:-unknown}. Upgrade to Debian 13 using 'apt-get dist-upgrade'."
            fi
            ;;
        rhel|centos|rocky|almalinux)
            DETECTED_FAMILY="rhel"
            local major_version="${OS_VERSION_ID%%.*}"
            if [[ -z "${major_version}" ]] || [[ "${major_version}" -lt 9 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Enterprise Linux 9 or higher required; found ${OS_NAME} ${OS_VERSION_ID:-unknown}. Upgrade using 'dnf system-upgrade'."
            fi
            ;;
        fedora)
            DETECTED_FAMILY="rhel"
            local major_version="${OS_VERSION_ID%%.*}"
            if [[ -z "${major_version}" ]] || [[ "${major_version}" -lt 39 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "Fedora Server 39 or higher required; found Fedora ${OS_VERSION_ID:-unknown}. Upgrade using 'dnf system-upgrade'."
            fi
            ;;
        sles|sled|sles_sap)
            DETECTED_FAMILY="sles"
            local major_version="${OS_VERSION_ID%%.*}"
            local sp_version="${OS_VERSION_ID#*.}"
            if [[ -z "${major_version}" ]] || [[ "${major_version}" -lt 15 ]] || [[ "${major_version}" -eq 15 && "${sp_version}" -lt 7 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "SUSE Linux Enterprise Server 15 SP7+ required; found ${OS_NAME} ${OS_VERSION_ID:-unknown}. Upgrade via YaST or 'zypper migration'."
            fi
            ;;
        opensuse-leap)
            DETECTED_FAMILY="sles"
            local major_version="${OS_VERSION_ID%%.*}"
            local minor_version="${OS_VERSION_ID#*.}"
            if [[ -z "${major_version}" ]] || [[ "${major_version}" -lt 15 ]] || [[ "${major_version}" -eq 15 && "${minor_version}" -lt 6 ]]; then
                die "${EXIT_VALIDATION_ERROR}" "openSUSE Leap 15.6+ required; found openSUSE Leap ${OS_VERSION_ID:-unknown}. Upgrade via 'zypper dup'."
            fi
            ;;
        opensuse-tumbleweed)
            DETECTED_FAMILY="sles"
            ;;
        *)
            # Check ID_LIKE fallbacks
            if [[ "${ID_LIKE}" =~ (rhel|centos|fedora) ]]; then
                DETECTED_FAMILY="rhel"
            elif [[ "${ID_LIKE}" =~ (suse|opensuse) ]]; then
                DETECTED_FAMILY="sles"
            elif [[ "${ID_LIKE}" =~ (debian) ]]; then
                DETECTED_FAMILY="debian"
            else
                die "${EXIT_VALIDATION_ERROR}" "Unsupported distribution '${OS_ID}'. Supported distributions are Debian 13+, RHEL 9+, Fedora Server 39+, and SLES 15 SP7+."
            fi
            ;;
    esac

    # Enforce Python 3 dependency
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

    # Linux kernel gate: >= 5.4
    KERNEL_RELEASE="${MOCK_KERNEL_RELEASE:-$(uname -r)}"
    local k_major k_minor
    k_major="$(echo "${KERNEL_RELEASE}" | cut -d. -f1)"
    k_minor="$(echo "${KERNEL_RELEASE}" | cut -d. -f2)"
    if [[ "${k_major}" -lt 5 ]] || [[ "${k_major}" -eq 5 && "${k_minor}" -lt 4 ]]; then
        die "${EXIT_VALIDATION_ERROR}" "Linux kernel 5.4 or higher required for rootless container isolation; found kernel ${KERNEL_RELEASE}."
    fi

    # cgroups v2 check
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
    elif grep -q "cgroup2" /proc/mounts 2>/dev/null; then
        CGROUPS_V2=true
        CGROUP_CONTROLLERS=("cpu" "memory" "io" "pids")
    elif [[ "${OPSKIT_TEST_MODE:-0}" == "1" ]] && [[ -n "${OPSKIT_FORCE_CGROUPS_V2:-}" ]]; then
        CGROUPS_V2=true
        CGROUP_CONTROLLERS=("cpu" "memory" "io" "pids")
    fi

    if ! ${CGROUPS_V2}; then
        die "${EXIT_VALIDATION_ERROR}" "cgroups v2 is required for rootless container resource isolation; cgroup2 mount not detected."
    fi

    # systemd system manager verification
    SYSTEMD_RUNNING=false
    if [[ -d /run/systemd/system ]]; then
        SYSTEMD_RUNNING=true
    elif [[ -n "${OPSKIT_FORCE_SYSTEMD:-}" ]]; then
        SYSTEMD_RUNNING=true
    else
        # In container environments, check PID 1 or comm
        local p1_comm
        p1_comm="$(cat /proc/1/comm 2>/dev/null || true)"
        if [[ "${p1_comm}" =~ (systemd|init) ]]; then
            SYSTEMD_RUNNING=true
        fi
    fi

    # systemd user manager verification
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
    DETECTED_RUNTIME=""
    RUNTIME_VERSION=""
    PODMAN_PACKAGE_NEEDED=false

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
            local p_major p_minor
            p_major="$(echo "${RUNTIME_VERSION}" | cut -d. -f1)"
            p_minor="$(echo "${RUNTIME_VERSION}" | cut -d. -f2)"
            if [[ "${p_major}" -lt 4 ]] || [[ "${p_major}" -eq 4 && "${p_minor}" -lt 4 ]]; then
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

    # Service user inspection
    SERVICE_USER_EXISTS=false
    SERVICE_USER_IN_DOCKER=false
    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        SERVICE_USER_EXISTS=true
        # Audit docker group: BANNED by security model
        if id -Gn "${SERVICE_USER}" 2>/dev/null | grep -qw "docker"; then
            die "${EXIT_VALIDATION_ERROR}" "Service user '${SERVICE_USER}' is in the 'docker' group. The docker group grants unconfined host access, violating the rootless security boundary. Remove the user from the docker group before bootstrapping."
        fi
    fi

    # Systemd linger status
    LINGER_ACTIVE=false
    if [[ -d "/var/lib/systemd/linger" ]] && [[ -f "/var/lib/systemd/linger/${SERVICE_USER}" ]]; then
        LINGER_ACTIVE=true
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
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -w "active" >/dev/null 2>&1; then
        FIREWALL_STACK="ufw"
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_STACK="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_STACK="iptables"
    fi

    # Disk space verification: >= 5 GiB (5,242,880 KB)
    local target_mount="/var"
    [[ ! -d "${target_mount}" ]] && target_mount="/"
    local avail_kb
    avail_kb="$(df -Pk "${target_mount}" 2>/dev/null | awk 'NR==2 {print $4}')"
    DISK_FREE_GB="${MOCK_DISK_FREE_GB:-$(( ${avail_kb:-0} / 1048576 ))}"
    if [[ "${avail_kb:-0}" -lt 5242880 ]] && [[ -z "${OPSKIT_SKIP_DISK_CHECK:-}" ]] && [[ -z "${MOCK_DISK_FREE_GB:-}" ]]; then
        die "${EXIT_VALIDATION_ERROR}" "At least 5 GiB of free disk space is required on ${target_mount}; found ${DISK_FREE_GB} GiB."
    fi

    # Clock skew evaluation: warn > 60s, hard fail > 300s
    CLOCK_SKEW_SECONDS="${MOCK_CLOCK_SKEW:-}"
    if [[ -z "${CLOCK_SKEW_SECONDS}" ]]; then
        CLOCK_SKEW_SECONDS=0
        if command -v chronyc >/dev/null 2>&1; then
            local offset
            offset="$(chronyc tracking 2>/dev/null | awk '/Last offset/ {print $4}' | tr -d '+' | cut -d. -f1 || echo 0)"
            CLOCK_SKEW_SECONDS="${offset:-0}"
        elif command -v timedatectl >/dev/null 2>&1; then
            if timedatectl status 2>/dev/null | grep -qi "System clock synchronized: yes"; then
                CLOCK_SKEW_SECONDS=0
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
    # In test mode or when no external reference exists, clock skew is 0
}
