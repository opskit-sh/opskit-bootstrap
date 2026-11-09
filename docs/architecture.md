# Architecture

This document describes the architectural principles, execution lifecycle,
and operating system integration of `opskit-bootstrap`.

## 1. The one-time root model

OpsKit operates containerized workloads and network ingress without persistent
root privileges. The machine configuration requires elevated privileges only
once: during the execution of `opskit-bootstrap`.

```
                    +------------------------------------+
                    |  opskit-bootstrap (runs as root)   |
                    +------------------------------------+
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
         v                            v                            v
[System Accounts]            [systemd Infrastructure]        [Firewall Stack]
- opskit service user        - loginctl enable-linger        - Allow TCP 443 & 80
- subuid/subgid range        - opskit-edge-443.socket          (direct profile only)
- No docker group            - opskit-edge.service (User=)
                             - User services
                                      |
                                      v
                    +------------------------------------+
                    |  Unprivileged Runtime (opskit)     |
                    |  - Podman / Rootless Docker        |
                    |  - opskit-cloud user service       |
                    |  - opskit-edge unprivileged worker |
                    +------------------------------------+
```

After `opskit-bootstrap` completes, all OpsKit executables (`opskit` and
`opskit-edge`) refuse to execute with effective UID 0. System operations,
deployment lifecycle commands, configuration edits, container management,
and secret handling run entirely as the unprivileged service user (`opskit`).

## 2. Ingress profiles and privileged surface

The exposure boundary is governed by three distinct exposure profiles:

| Profile | Ingress Mechanism | Privileged Artifacts |
|---|---|---|
| `direct` | Inbound TCP traffic directly to node on ports 443 and 80 | Root-owned socket units (`opskit-edge-443.socket`, `opskit-edge-80.socket`), root-owned service unit (`opskit-edge.service`, `User=opskit`), host firewall rule |
| `tunnel` | Outbound encrypted overlay connection via cloudflared | Zero root-owned units beyond service account and systemd user linger |
| `private` | Local Unix domain sockets or private LAN/VPN access | Zero root-owned units beyond service account and systemd user linger |

### Socket activation under direct profile

Under the `direct` profile, binding privileged port 443 and port 80 without
running a root daemon is achieved using systemd socket activation
([sd_listen_fds(3)](https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html)):

1. Systemd binds listening stream sockets for port 443 (`opskit-edge-443.socket`)
   and port 80 (`opskit-edge-80.socket`) during system boot as root.
2. When traffic arrives or when the service is started, systemd activates
   `opskit-edge.service`.
3. The service unit declares `User=opskit` and `Group=opskit` in accordance
   with [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/systemd.exec.html).
4. Systemd drops all root capabilities and passes the open file descriptors
   starting at descriptor index 3 to the unprivileged process.
5. `opskit-edge` receives the file descriptors, verifies they are stream
   sockets via `SO_TYPE` and `SO_ACCEPTCONN`, classifies descriptors named `443`
   as TLS listeners, and begins serving traffic unprivileged.

## 3. Host integration and distribution family modules

`opskit-bootstrap` is structured as a single orchestrator script supported by
distribution family modules:

- **Orchestration core** (`lib/detect.sh`, `lib/plan.sh`, `lib/apply.sh`, `lib/ledger.sh`, `lib/undo.sh`):
  Implements capability detection, plan compilation, machine plan hashing,
  ledger recording, and uninstallation logic independent of distribution differences.
- **Distribution family modules** (`lib/family/debian.sh`, `lib/family/rhel.sh`, `lib/family/sles.sh`):
  Implements distribution-specific primitives:
  - **Service account creation**: Prefers declarative provisioning via `systemd-sysusers`
    with drop-in `/etc/sysusers.d/opskit.conf` in accordance with
    [sysusers.d(5)](https://www.freedesktop.org/software/systemd/man/sysusers.d.html),
    falling back to `useradd -r -s /usr/sbin/nologin -d /home/opskit -m opskit` where
    `systemd-sysusers` is unavailable.
  - **Firewall integration**:
    - Under `nftables`, manages an isolated table `inet opskit` with chain priority 0:
      `type filter hook input priority 0; policy accept;` in accordance with
      [nft(8)](https://man7.org/linux/man-pages/man8/nft.8.html). `inet opskit` is an
      OpsKit-managed namespace: administrator firewall rules and objects belong in separate tables or
      chains. OpsKit rules are tagged with exact port comments (`opskit-443`, `opskit-80`)
      and recorded by numerical handles, enabling exact surgical rule deletion during
      uninstallation and transitions without affecting foreign tables, foreign chains, or
      other rules. When all OpsKit rules are removed and `inet opskit` contains zero rules
      and no custom chains, sets, maps, or flowtables, both the `input` chain and table are deleted; if any foreign or untagged
      rule or non-rule object (such as a custom chain, set, map, or flowtable) remains inside `inet opskit`, OpsKit preserves the table, emits a single
      warning per run naming it, and allows profile transitions to proceed unless a colliding `opskit-*` comment remains in the chain.
    - Under `firewalld`, evaluates and manages permanent service and port rules via `firewall-cmd`, recording `pre_existing: true` when a port was already allowed so uninstallation and profile transitions preserve administrator-owned rules; removal removes permanent rules regardless of whether `firewalld` is currently active.
    - Under `ufw`, records `pre_existing: true` if an administrator rule already allows the port, otherwise adds rules tagged with `comment "opskit-443"` / `comment "opskit-80"` and removes only matching tagged rules regardless of whether `ufw` is currently active or disabled.

This design preserves byte-stable planning and identical command-line flags
across all platforms while respecting the native administration toolchains
of each operating system family.
