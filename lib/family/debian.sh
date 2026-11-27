#!/usr/bin/env bash
# Debian family package and system configuration adapter (Debian 13+, Ubuntu 24.04+).
set -euo pipefail

family_rootless_docker_packages() {
    # Upstream rootless Docker extras package for Debian/Ubuntu:
    # https://docs.docker.com/engine/security/rootless/
    local pkgs=("docker-ce-rootless-extras")
    if ! command -v slirp4netns >/dev/null 2>&1 && ! command -v pasta >/dev/null 2>&1; then
        pkgs+=("slirp4netns")
    fi
    echo "${pkgs[*]}"
}

family_install_packages() {
    local pkgs=("$@")
    if [[ ${#pkgs[@]} -eq 0 ]]; then
        return 0
    fi
    log_info "Installing Debian packages: ${pkgs[*]} via apt-get..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    local reinstall_pkgs=()
    local install_pkgs=()
    for p in "${pkgs[@]}"; do
        if dpkg -s "${p}" >/dev/null 2>&1; then
            reinstall_pkgs+=("${p}")
        else
            install_pkgs+=("${p}")
        fi
    done
    if [[ ${#reinstall_pkgs[@]} -gt 0 ]]; then
        apt-get install -y --reinstall --no-install-recommends "${reinstall_pkgs[@]}"
    fi
    if [[ ${#install_pkgs[@]} -gt 0 ]]; then
        apt-get install -y --no-install-recommends "${install_pkgs[@]}"
    fi
}

family_create_service_user() {
    local user="$1"
    local group="$2"
    if ! getent group "${group}" >/dev/null 2>&1; then
        groupadd -r "${group}" 2>/dev/null || true
    fi
    local nologin_shell="/usr/sbin/nologin"
    if [[ ! -x "${nologin_shell}" ]]; then
        if [[ -x "/sbin/nologin" ]]; then
            nologin_shell="/sbin/nologin"
        else
            nologin_shell="/bin/false"
        fi
    fi
    if ! id "${user}" >/dev/null 2>&1; then
        local created=false
        # Upstream system user drop-in configuration format: https://www.freedesktop.org/software/systemd/man/latest/sysusers.d.html
        if command -v systemd-sysusers >/dev/null 2>&1; then
            mkdir -p /etc/sysusers.d
            echo "u ${user} - \"OpsKit Service Account\" /home/${user} ${nologin_shell}" > "/etc/sysusers.d/${user}.conf"
            if systemd-sysusers >/dev/null 2>&1 && id "${user}" >/dev/null 2>&1; then
                created=true
                ensure_safe_dir_no_symlink "/home/${user}"
                mkdir -p "/home/${user}"
                chown "${user}:${group}" "/home/${user}"
                chmod 0750 "/home/${user}"
            else
                rm -f "/etc/sysusers.d/${user}.conf"
            fi
        fi
        if ! ${created}; then
            useradd -r -m -g "${group}" -d "/home/${user}" -s "${nologin_shell}" "${user}"
            chmod 0750 "/home/${user}"
        fi
        log_info "Created service account '${user}' with group '${group}'."
    fi
}

family_has_firewall_rule() {
    opskit_fw_has_rule "$@"
}

family_has_tagged_opskit_firewall_rule() {
    opskit_fw_has_tagged_rule "$@"
}

family_apply_firewall_rule() {
    opskit_fw_apply_rule "$@"
}

family_remove_firewall_rule() {
    opskit_fw_remove_rule "$@"
}
