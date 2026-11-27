# Manual Setup (Without the Bootstrapper)

This guide is the transparency counterpart to `opskit-bootstrap`. The bootstrapper
is a **convenience**, not a requirement: every mutation it performs is a bounded,
documented system change that an operator can reproduce **by hand** on any
supported distribution. Nothing here is a black box — each stage names the exact
command, what it changes, why it is needed, and the authoritative upstream
documentation it follows.

The trust contract this document upholds:

- **One-time privileged setup, zero persistent root.** Root is used only to create
  the service account, subordinate ID ranges, linger, the rootless runtime, and
  (for the `direct` exposure profile) inert socket-activation units and firewall
  rules. No OpsKit process ever runs as root afterwards; the binaries refuse an
  effective UID of 0 and never invoke `sudo`.
- **Closed mutation inventory.** The stages below are the complete set. If a step
  is not listed here, OpsKit does not perform it.
- **Reversible.** Each stage has a manual undo (last section), so a node can be
  returned to its prior state without a network fetch.

> The bootstrapper automates exactly these stages and records them in a
> tamper-evident ledger so `--undo` can reverse them. Doing them by hand trades
> the ledger for your own change control.

## 0. What you are reproducing

`opskit-bootstrap` performs these stages, in order (direct profile shown; the
`tunnel`/`private` profiles skip the socket units and firewall):

1. Create the service user/group (if absent).
2. Allocate subordinate UID/GID ranges.
3. Enable systemd linger for the service user.
4. Install/convert a rootless container runtime (Podman ≥ 4.4 or rootless Docker).
5. Delegate cgroup v2 controllers to the user manager.
6. Install the OpsKit binaries under a user-owned, versioned directory.
7. `direct` only: install root-owned socket-activation units for `:443` (and
   optional `:80`) plus the `opskit-edge` service unit.
8. `direct` only: open the firewall for `443`/`tcp` (and `80`/`tcp`).

Each stage below is OS-family aware. Pick the family that matches your host:
**Debian** (Debian 13+, Ubuntu 24.04+), **RHEL** (RHEL/Alma/Rocky 9/10, Fedora
39+), or **SUSE** (SLES 15 SP7+, openSUSE Leap 15.6+/Tumbleweed).

## 1. Prerequisites (all families)

| Requirement | Why | Evidence |
|---|---|---|
| Linux kernel ≥ 5.4 | Rootless user namespaces | kernel.org |
| cgroups v2 (unified) | Memory/CPU/pids limits | <https://docs.kernel.org/admin-guide/cgroup-v2.html> |
| systemd (system + user manager) | Unit + socket activation | <https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html> |
| `newuidmap` / `newgidmap` | Subordinate ID mapping | <https://man7.org/linux/man-pages/man8/newuidmap.8.html> |
| `/etc/subuid`, `/etc/subgid` | Subordinate ranges | <https://man7.org/linux/man-pages/man5/subuid.5.html> |
| Python 3 | Bootstrap helper only (not needed for manual) | — |
| ≥ 5 GiB free on `/var` and `/home` | Workload + image storage | — |

Install the package set for your family:

- **Debian/Ubuntu:** `sudo apt-get install -y podman uidmap`
- **RHEL/Fedora:** `sudo dnf install -y podman shadow-utils`
- **SUSE:** `sudo zypper install -y podman shadow`

(Use `docker` + `dockerd-rootless-setuptool.sh` instead of Podman if you prefer
Docker; both are supported.)

## 2. Service user and group

Create a dedicated, unprivileged service account. It must **not** be UID 0 and
must **not** join the `docker` group (membership grants unconfined host access).

```sh
sudo groupadd --system opskit
sudo useradd --system --gid opskit --home-dir /home/opskit \
     --create-home --shell /usr/sbin/nologin opskit
sudo install -d -m 0750 -o opskit -g opskit /home/opskit
```

*Why:* isolation — workloads run as this account, never as root or as a
privileged group. *Evidence:* `useradd(8)`, `groupadd(8)`.

## 3. Subordinate UID/GID ranges

Rootless containers map a range of host IDs into the container. Allocate a
non-overlapping block of 65,536 IDs per user.

```sh
echo "opskit:165536:65536" | sudo tee -a /etc/subuid
echo "opskit:165536:65536" | sudo tee -a /etc/subgid
```

*Why:* the runtime needs a subuid/subgid range to emulate root inside the
container without host root. *Evidence:* `subuid(5)`, `podman(1)`.

## 4. Linger

Allow the user manager to run without an active login session (so units survive
logout).

```sh
sudo loginctl enable-linger opskit
```

*Why:* the edge and workloads must run in the background. *Evidence:*
`loginctl(1)`.

## 5. Rootless runtime

Confirm the runtime is rootless (no `sudo`):

```sh
# Podman
podman info --format '{{.Host.Security.Rootless}}'   # -> true
# Docker (rootless)
docker info --format '{{.SecurityOptions}}'           # -> rootless
```

*Why:* all containers run unprivileged. *Evidence:* `podman(1)` rootless mode,
`dockerd-rootless(8)`.

## 6. cgroup v2 delegation

Delegate the memory/cpu/pids controllers to the user manager so limits apply.

```sh
sudo mkdir -p /etc/systemd/system/user@.service.d
sudo tee /etc/systemd/system/user@.service.d/opskit-delegate.conf >/dev/null <<'EOF'
[Service]
Delegate=yes
DelegateControllers=memory cpu pids
EOF
sudo systemctl daemon-reload
```

*Why:* without delegation the runtime cannot enforce `--memory`/`--cpus`.
*Evidence:* `systemd.resource-control(5)`, `user@.service(5)`.

> Profile note: this drop-in is a system-level delegation. If your policy forbids
> any root-owned unit outside the `direct` profile, treat a missing delegation as
> a hard prerequisite and enable it out-of-band.

## 7. OpsKit binaries (user-owned, versioned)

Install the binaries under a user-owned versioned tree and flip a `current`
symlink. Root-owned units reference `current/`, so updates need no root.

```sh
sudo install -d -m 0750 -o opskit -g opskit /var/lib/opskit/versions
sudo -u opskit install -d -m 0755 /var/lib/opskit/versions/0.1.0
sudo -u opskit install -m 0755 ./opskit            /var/lib/opskit/versions/0.1.0/opskit
sudo -u opskit install -m 0755 ./opskit-edge       /var/lib/opskit/versions/0.1.0/opskit-edge
sudo -u opskit ln -sfn /var/lib/opskit/versions/0.1.0 /var/lib/opskit/versions/current
```

*Why:* code/config/cert updates never require root. *Evidence:*
`install(1)`, `symlink(7)`.

## 8. Direct-profile exposure: socket activation + service

The privileged `:443`/`:80` bind lives **only** in inert root-owned socket units;
the unprivileged edge inherits the descriptors. `net.ipv4.ip_unprivileged_port_start`
is **never** changed.

```sh
# /etc/systemd/system/opskit-edge-443.socket
[Socket]
ListenStream=0.0.0.0:443
ListenStream=[::]:443
BindIPv6Only=ipv6-only
FileDescriptorName=443
NonBlocking=true
Service=opskit-edge.service

[Install]
WantedBy=sockets.target
```

```sh
# /etc/systemd/system/opskit-edge.service
[Service]
Type=simple
User=opskit
Group=opskit
ExecStart=/var/lib/opskit/versions/current/opskit-edge
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ReadWritePaths=/var/lib/opskit/edge /var/lib/opskit/logs /var/lib/opskit/state
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0027

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now opskit-edge-443.socket opskit-edge.service
```

*Why:* root binds the low port; no root process serves traffic; the edge is
confined. *Evidence:* `systemd.socket(5)`, `systemd.exec(5)`.

> The `:80` unit is optional (only for HTTP-01 ACME). If you do not need it, omit
> `opskit-edge-80.socket` and its `ListenStream`.

## 9. Firewall (direct only)

```sh
sudo ufw allow 443/tcp comment 'opskit'
# optional: sudo ufw allow 80/tcp comment 'opskit'
```

*Why:* the ACME TLS-ALPN-01 challenge and public ingress arrive on 443.
*Evidence:* `ufw(8)`.

## 10. Verify

```sh
opskit doctor          # all checks PASS
ss -ltnp | grep -E ':443|:80'
curl -s --unix-socket /var/lib/opskit/edge/health.sock http://localhost/health
```

## 11. Undo (by hand)

Reverse the stages in reverse order: stop/disable the units, remove the socket
units and service, remove the firewall rules, remove the versioned tree, disable
linger, remove the subuid/subgid lines, and (only if you created it) delete the
service user.

```sh
sudo systemctl disable --now opskit-edge.service opskit-edge-443.socket
sudo rm -f /etc/systemd/system/opskit-edge*.socket /etc/systemd/system/opskit-edge.service
sudo ufw delete allow 443/tcp
sudo loginctl disable-linger opskit
sudo sed -i '/^opskit:/d' /etc/subuid /etc/subgid
sudo userdel -r opskit   # only if bootstrap/manual created it
```

---

*This document is the manual path; `opskit-bootstrap` is the automated path. Both
perform the same closed set of stages above. External references are authoritative
upstream documentation.*