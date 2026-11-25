# Security Model and Invariants

This document outlines the security architecture, invariant guarantees,
and privileged boundaries enforced by `opskit-bootstrap`.

## 1. Security invariants

1. **Zero persistent root**: Following bootstrap completion, no OpsKit
   component runs with elevated privileges. All long-running services
   (`opskit-cloud`, `opskit-edge`) and interactive commands run under the
   unprivileged service account.
2. **Inert privileged artifacts**: Privileged state on the host is restricted
   to inert configuration:
   - Systemd socket activation units (`/etc/systemd/system/opskit-edge-443.socket`)
   - Systemd service units declaring `User=opskit`
   - Specific, fingerprinted host firewall rules
   All executables referenced by systemd units reside in user-owned paths under
   `/var/lib/opskit/versions/` and can be updated without root privileges.
3. **Signed release manifests**: Payloads are never piped directly from the
   network to an execution shell. Binary downloads require offline-verifiable
   Ed25519 signatures over an `opskit.release-manifest/v1` document, followed
   by exact SHA-256 digest validation.
4. **Mandatory access control**: SELinux and AppArmor are never disabled or
   weakened. The bootstrap script records the active MAC state and applies
   standard container labels (such as `container_file_t`) where appropriate.
5. **No sudoers modifications**: `opskit-bootstrap` never writes to
   `/etc/sudoers` or `/etc/sudoers.d/`, and never grants sudo permissions to
   the service user.
6. **No host networking manipulation**: Kernel ingress bridges, virtual
   ethernet pairs, or custom kernel modules are never created on the host.
   Workloads utilize user-space networking (`pasta` or rootless container networks).
7. **Privileged port restrictions**: Sysctl settings such as
   `net.ipv4.ip_unprivileged_port_start` are left untouched. Inbound access
   to ports 443 and 80 is granted strictly via systemd socket activation.

## 2. The closed mutation inventory

`opskit-bootstrap` applies mutations strictly from this closed inventory:

| Mutation ID | Class | Target | Description |
|---|---|---|---|
| `packages` | Host (H) | Package manager | Install required runtime packages (`podman`, `uidmap`, or rootless Docker extras) if absent |
| `service_user` | Host (H) | `/etc/passwd`, `/etc/group` | Provision dedicated service user and primary group |
| `subuid_allocation` | Host (H) | `/etc/subuid`, `/etc/subgid` | Allocate subordinate user and group ID ranges |
| `cgroup_delegation` | Host (H) | `/etc/systemd/system/user@.service.d/` | Enable `Delegate=yes` for systemd cgroup v2 controller delegation |
| `user_linger` | Host (H) | Systemd linger directory | Enable linger via `loginctl enable-linger` for background services |
| `rootless_docker` | User (U) | `~opskit/.config/systemd/user/`, `~opskit/.config/environment.d/` | Provision rootless Docker daemon and `DOCKER_HOST` when Docker is selected |
| `edge_socket_units` | Host (H) | `/etc/systemd/system/` | Install `opskit-edge-443.socket` and `opskit-edge-80.socket` (direct profile) |
| `edge_system_unit` | Host (H) | `/etc/systemd/system/` | Install `opskit-edge.service` with `User=opskit` (direct profile) |
| `firewall_rules` | Host (H) | Host firewall stack | Allow TCP 443 and 80 traffic (direct profile) |
| `service_units` | User (U) | `~opskit/.config/systemd/user/` | Install user services for `opskit-cloud` and `opskit-edge` |
| `cloudflared_unit` | User (U) | `~opskit/.config/systemd/user/` | Install user service template for cloudflared (tunnel profile) |
| `security_labels` | Host/User | Storage directories | Apply distribution security policy labels to state roots |
| `fetch_cli` | Host (H) | `/usr/local/bin/opskit` | Install verified static binary via signed release manifest |

Any system mutation outside this table is prohibited.

## 3. Ledger integrity and HMAC verification

To protect against ledger tampering, silent corruption, or injection of unauthorized
rollback instructions:

1. **HMAC Key Generation**: On initial bootstrap, a cryptographically secure 256-bit
   random key is created at `/var/lib/opskit-bootstrap/ledger.key` with mode `0600`
   owned exclusively by `root:root`.
2. **Per-entry Signing**: Every mutation record written to `apply.jsonl` includes an
   `hmac` field computed using HMAC-SHA256 over the canonical JSON representation of the entry
   dictionary (with the `hmac` key omitted). Canonicalization is performed via Python 3:
   `json.dumps(entry_without_hmac, sort_keys=True, separators=(',', ':')).encode('utf-8')`.
   Both entry emission and verification re-serialize through this canonical profile, guaranteeing
   byte-exact HMAC consistency regardless of formatting or whitespace in nested structures (such
   as `metadata.packages`). The HMAC is computed using Python 3 reading the 0600 key file
   directly via a file descriptor, ensuring the secret key never appears in process argv,
   environment variables, or command-line logs.
3. **Pre-execution Verification**: Prior to reversing mutations (`--undo`) or
   auditing state (`--repair`), `opskit-bootstrap` verifies the entire ledger from
   beginning to end:
   - Validates JSON grammar and required fields.
   - Confirms that `mutation_id` belongs to the closed inventory.
   - Recomputes and verifies the HMAC-SHA256 signature for each line.
4. **Fail-stop Guarantee**: If any line fails verification (due to tampering, truncation,
   or corruption), `opskit-bootstrap` logs the offending line, refuses to execute,
   preserves the state directory intact, and exits with code `8` (`VALIDATION_ERROR`).

## 4. The never-list

The following actions are strictly banned by construction:

- Modifying `net.ipv4.ip_unprivileged_port_start`
- Creating persistent background processes running as root
- Inserting kernel modules or modifying host routing tables
- Disabling SELinux, AppArmor, or host firewalls
- Adding the service user to the `docker` group
- Adding lines to `/etc/sudoers` or granting passwordless sudo
- Creating remote shell or SSH authorization backdoors
- Piping script payloads directly from remote URLs into a shell
