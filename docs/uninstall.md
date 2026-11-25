# Uninstall and Covenants

This document defines the uninstallation mechanics, the two distinct
uninstallation covenants, and the zero-trace verification guarantee.

## 1. The two uninstallation covenants

OpsKit defines two distinct uninstallation covenants:

| Covenant | Invocation | Privilege | Scope and Resource Boundary |
|---|---|---|---|
| **Plain Covenant** | `sudo opskit-bootstrap --undo` | Root (sudo) | Reverses host socket units, host service unit, firewall rules, and CLI executable. **Preserves the service user account, subordinate UID/GID allocations, systemd user linger, and user workloads** in `/home/opskit/` so existing container projects continue operating uninterrupted. |
| **Purge Covenant** | `sudo opskit-bootstrap --undo --purge` | Root (sudo) | Complete system purge. Reverses all mutations, stops user services, disables user linger, removes subordinate UID/GID ranges, deletes the service account and primary group, and recursively wipes the home directory `/home/opskit/` for a zero-trace return to pre-bootstrap state. |

Note that standalone `--purge` without `--undo` is rejected with exit code `2` (`USAGE_ERROR`).

The unprivileged CLI verb `opskit uninstall` performs application-scope workload
stopping and prints the exact privileged bootstrap command required for host rollback.

## 2. Offline reversal via the vendored ledger

At install time, `opskit-bootstrap` vendors its own executable, libraries, and the
HMAC-signed mutation ledger into `/var/lib/opskit-bootstrap/`:

- `apply.jsonl`: Tamper-evident, HMAC-SHA256 signed record of applied mutations. Each entry is individually authenticated via a per-line HMAC; profile transitions rewrite the ledger under root control to remove artifacts not needed by the active profile.
- `ledger.key`: Root-owned 0600 cryptographic key for ledger integrity verification.
- `opskit-bootstrap`: Standalone offline uninstaller executable.

Because all state is preserved locally on the node, uninstallation requires
no internet access or external repository connectivity.

Before reversing any mutation, `opskit-bootstrap --undo` validates the entire ledger
against `ledger.key`. If any line has been corrupted or tampered with, the uninstaller
halts immediately with exit code `8` (`VALIDATION_ERROR`) and preserves `/var/lib/opskit-bootstrap/`
untouched for forensic investigation.

### Reversal order

`opskit-bootstrap --undo` iterates through `/var/lib/opskit-bootstrap/apply.jsonl`
in reverse chronological order:

1. **CLI binary**: Restores pre-existing CLI executable from `/usr/local/bin/opskit.pre-bootstrap`
   if bootstrap found an existing binary (recorded in ledger metadata); otherwise removes
   `/usr/local/bin/opskit`.
2. **User service units**: Stops user units via `systemctl --user stop` (if user manager is
   active) and removes unit templates from `~opskit/.config/systemd/user/`.
5. **Firewall rules**: Reverses the exact rule recorded in metadata using exact port
   comment targeting (`opskit-443`, `opskit-80`), tag-scoped `ufw` deletion (`ufw --force delete ... comment ...`,
   skipping rules marked `pre_existing: true` and deleting OpsKit-tagged rules even if `ufw` was disabled
   after bootstrap so re-enabling `ufw` cannot resurrect them), `firewalld` permanent rule cleanup
   (skipping rules marked `pre_existing: true`, targeting the recorded zone when set, and removing permanent rules regardless of service active
   state), or comment-verified nftables handle lookup (skipping
   stale handles whose live comment does not match), plus cross-stack fallback restricted to live
   tagged `nftables` (`inet opskit input`) and `iptables` `opskit-443`/`opskit-80` rules if the active
   stack changed. Even if the `ufw` package binary was removed after bootstrap, the recorded
   metadata was empty (`{}`), or a same-profile `--repair` runs while staged tuples remain on a different
   stack, the survivor check still inspects `/etc/ufw/user.rules` / `/etc/ufw/user6.rules` (by full
   whitespace-terminated hex-encoded comment value) unconditionally for canonical ports `443` and `80`;
   when metadata names `firewalld` or no valid rule-stack metadata exists, it also inspects the recorded or default
   `/etc/firewalld/zones/<zone>.xml` for canonical ports `443` and `80` (without flagging unrelated `firewalld` ports when another stack owns the node) so staged rules cannot linger silently after ledger
   deletion or overwrite and resurrect upon package reinstall. Same-profile `--repair` checks for OpsKit
   artifacts on stacks other than the active stack before rewriting the ledger and refuses with exit code `6`
   (`RUNTIME_ERROR`) while retaining existing ledger entries if any staged tuples remain. If `inet opskit` holds zero rules and zero non-rule objects (custom chains, sets, maps,
   or flowtables) afterwards, the chain and table are deleted; if any foreign or untagged rules or objects
   remain inside the OpsKit-managed `inet opskit` namespace, the table is preserved and a single warning
   per run is emitted without blocking uninstallation. If OpsKit-tagged rules (`opskit-443` or `opskit-80`,
   or OpsKit-added `ufw` / `firewalld` runtime, permanent, or binary-absent conffile/zone-XML rules)
   survive deletion during `--undo`, the remaining reversal steps still finish, `/var/lib/opskit-bootstrap/`
   is preserved for retry (for example after reinstalling a removed firewall package), and `--undo` exits `6` (`RUNTIME_ERROR`). If `nft` is unavailable while the
   `nf_tables` kernel subsystem is loaded, a warning is emitted instead of claiming clean removal.
   Administrator rules should reside in separate tables or chains.
4. **Root service unit**: Stops `opskit-edge.service`, disables it, removes
   `/etc/systemd/system/opskit-edge.service`, and executes `systemctl daemon-reload`.
5. **Root socket units**: Stops `opskit-edge-443.socket` and `opskit-edge-80.socket`,
   disables them, removes the unit files, and executes `systemctl daemon-reload`.
6. **Rootless Docker & cgroup delegation**: Under plain covenant, rootless Docker provisioning and systemd user slice cgroup delegation are preserved so existing container workloads continue operating with enforced resource limits; under `--purge`, OpsKit-provisioned `docker.service` / `opskit-docker.conf` and `/etc/systemd/system/user@.service.d/opskit-delegate.conf` are removed (pre-existing administrator configurations are preserved).
7. **Systemd user linger**: Under plain covenant, linger is preserved; under `--purge`,
   disables linger via `loginctl disable-linger opskit` only if the ledger records it was enabled by OpsKit.
8. **Subordinate IDs**: Under plain covenant, subordinate UID/GID mappings are preserved;
   under `--purge`, removes only the OpsKit-allocated `/etc/subuid` / `/etc/subgid` entries (preserving pre-existing ranges).
9. **Service user**: Under plain covenant, the service account is preserved; under `--purge`,
   removes user `opskit`, group `opskit`, drop-in `/etc/sysusers.d/opskit.conf` (preventing resurrection by `systemd-sysusers`),
   and `/home/opskit/` only when the ledger records the account was created by OpsKit (pre-existing admin accounts and home directories are preserved).
10. **Bootstrap state**: Removes `/var/lib/opskit-bootstrap/` and all vendored libraries.

### Profile transitions and gate refusal during `--repair`

When transitioning away from the `direct` profile via `--repair --profile tunnel` or `--repair --profile private`:

1. **Systemd unit teardown runs first**: Root-owned socket units (`opskit-edge-443.socket`, `opskit-edge-80.socket`) and the system service unit (`opskit-edge.service`) are stopped, disabled, and removed before host firewall cleanup runs.
2. **Exact firewall removal and fail-closed verification gate**: Firewall cleanup removes only OpsKit-managed port rules (`opskit-443`, `opskit-80`), including staged `ufw` rules and permanent `firewalld` rules regardless of active state while preserving untagged rules or extra table objects inside `inet opskit` (with a single retention warning per run) and never touching untagged or pre-existing administrator `ufw` or `firewalld` rules. Using the same tagged-survivor verification check as `--undo` (including binary-free fallback checks against `/etc/ufw/user.rules`/`user6.rules` and `/etc/firewalld/zones/*.xml`), it verifies that no OpsKit-owned `nftables`, `iptables`, `ufw` (active, staged, or conffile-only), or `firewalld` (runtime, permanent, or zone-XML-only) rules or colliding `opskit-*` tags inside `inet opskit input` remain before removing the firewall entries from the ledger.
3. **Gate refusal ordering and re-runnability**: If the verification gate detects surviving artifacts (such as a failed firewall command or a colliding `opskit-*` comment inside the `inet opskit` chain), `--repair` refuses the transition with exit code `6` (`RUNTIME_ERROR`) and retains the existing ledger entries (`edge_socket_units`, `edge_system_unit`, `firewall_rules`) untouched. Because systemd units may already be removed before the gate fires, the previous profile may no longer be actively serving; however, the state remains safely re-runnable: after clearing the blocking firewall artifact, re-running `--repair --profile <target>` completes the transition, or running `--repair` without changing profiles detects the removed units as drift and restores them.

## 3. Zero-trace verification

Under the purge covenant (`--undo --purge`), a successful uninstallation restores
the host completely to its pre-bootstrap state:

- No OpsKit unit files remain in `/etc/systemd/system/` or `~/.config/systemd/user/`
- No OpsKit firewall rules remain in the active firewall stack
- No service user or group remains in `/etc/passwd` or `/etc/group`
- No subordinate UID/GID allocations remain in `/etc/subuid` or `/etc/subgid`
- No user linger files remain in `/var/lib/systemd/linger/`
- No entries remain in `/var/lib/opskit-bootstrap/` or `/home/opskit/`

This property is validated by end-to-end acceptance tests that snapshot the
filesystem, systemd unit list, user database, and firewall tables before
bootstrap and assert exact equality after `--undo --purge`.
