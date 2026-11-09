# opskit-bootstrap

The host bootstrap script and offline uninstaller for nodes running OpsKit software.

`opskit-bootstrap` is the single privileged surface in the OpsKit platform.
It establishes the rootless container execution environment, provisions the
service account, configures subordinate UID/GID mappings, enables systemd
user linger, optionally installs inert root-owned socket activation units for
public exposure under the direct profile, and records a tamper-evident ledger of
applied system mutations (authenticated via per-line HMACs, with profile transitions
rewritten under root control).

## Supported distributions

| OS Family | Supported Distributions | Package Toolchain |
|---|---|---|
| Debian | Debian 13 (trixie) or higher | `apt-get` |
| Enterprise Linux | RHEL 9/10, AlmaLinux 9/10, Rocky Linux 9/10, Fedora Server 39+ | `dnf` |
| SUSE | SLES 15 SP7+, openSUSE Leap 15.6+ | `zypper` |

## Architecture and Seam

`opskit-bootstrap` uses a unified entry point script (`bin/opskit-bootstrap`)
that shares a common core library across all supported operating systems.
Distribution-specific differences (package management, default firewall stack,
system user creation mechanics) are encapsulated inside distribution family
modules under `lib/family/`.

The entry contract, flags, ledger format, plan schema, and exit codes are
strictly identical across all distributions.

## Command-line flags

| Flag | Argument | Description |
|---|---|---|
| `--dry-run` | None | Evaluate system capabilities, compile the mutation plan, display human-readable plan, and exit without applying changes |
| `--plan-json` | `<path>` | Export the machine plan (`opskit.bootstrap-plan/v1`) to the specified path and exit without applying changes |
| `--yes` | None | Automatically accept the compiled plan without interactive confirmation |
| `--profile` | `<direct\|tunnel\|private>` | Explicitly select the exposure profile. Overrides reachability probe and interactive intent prompt |
| `--runtime` | `<podman\|docker\|auto>` | Explicitly choose the container runtime engine (defaults to auto-detection: Podman 4.4+ preferred) |
| `--proxy` | `<url>` | HTTP/HTTPS proxy URL for network requests |
| `--cacert` | `<path>` | Custom CA certificate bundle for network requests |
| `--artifact-dir` | `<path>` | Local directory containing signed release manifest and pre-downloaded binaries for offline installs |
| `--no-probe` | None | Skip external inbound TCP 443 reachability probing; verify local port binding only |
| `--undo` | None | Offline uninstaller: sequentially reverse mutations recorded in `/var/lib/opskit-bootstrap/apply.jsonl` |
| `--purge` | None | Complete removal option (valid only with `--undo`). Reverses mutations and removes service user, home directory, and data |
| `--repair` | None | Audit system state against the local ledger, display detected configuration drift, and repair upon authorization |

## Security model

1. **One-time root execution**: Privilege is required only during the initial
   execution of `opskit-bootstrap` (or `--undo` / `--repair`). Installed
   OpsKit binaries refuse to run with effective UID 0.
2. **Closed mutation inventory**: The script only applies mutations from a
   strictly bounded set (service user, subuid/subgid, linger, socket units,
   firewall rule, CLI placement). Unspecified modifications are forbidden.
3. **Inert privileged artifacts**: Root-owned files are limited to systemd
   socket activation units (`opskit-edge-443.socket`, `opskit-edge-80.socket`)
   and a system service unit (`opskit-edge.service`) configured with
   `User=opskit`. All executable files referenced by these units are owned by
   the unprivileged service user under `/var/lib/opskit/versions/`.
4. **Offline and vendor-locked uninstaller**: During bootstrap, the script
   vendors its own executable and the signed mutation ledger into
   `/var/lib/opskit-bootstrap/`. Uninstallation (`--undo`) operates entirely
   offline from this local ledger without network access.
5. **Payload integrity**: Executable binaries are fetched only after
   verifying their SHA-256 digest against an authentic `opskit.release-manifest/v1`
   signed with a trusted Ed25519 release key.

## Exit codes

| Exit Code | Name | Meaning |
|---|---|---|
| `0` | `SUCCESS` | Requested operation completed successfully |
| `1` | `GENERAL_ERROR` | Unhandled runtime or operational failure |
| `2` | `USAGE_ERROR` | Unrecognized flag, missing argument, or invalid command-line invocation |
| `3` | `NOT_FOUND` | Required system component or executable not found |
| `4` | `CONFLICT` | Conflicting system state detected (for example, foreign service bound to port 443) |
| `5` | `SAFETY_GUARD` | Root privilege missing, interactive confirmation or transition approval omitted, or security invariant violation |
| `6` | `RUNTIME_ERROR` | System command or external tool execution failed |
| `8` | `VALIDATION_ERROR` | System requirement failed (OS gate, kernel version, Podman version, clock skew, disk space) or manifest/ledger signature verification failed |
| `9` | `NETWORK_ERROR` | Inbound reachability probe failed or release manifest/payload unavailable |

## Uninstallation covenants

Uninstallation supports two contractual covenants:

- **Plain covenant (`--undo`)**: Reverses host-level mutations recorded in the ledger (socket units, firewall rules, and CLI executable). The unprivileged service user, subordinate UID/GID mappings, user linger, and application workloads in the user home directory (`/home/opskit/`) are preserved intact.
- **Purge covenant (`--undo --purge`)**: Complete teardown of all OpsKit state. Reverses all mutations, disables user linger, removes subordinate UID/GID allocations, deletes the service account and its primary group, and recursively wipes the home directory and all workload data for a zero-trace restoration.

## Environment variables

| Variable | Description |
|---|---|
| `OPSKIT_PROBE_SERVER` | Custom reachability probe URL for external inbound verification endpoint |
| `OPSKIT_ARTIFACT_SOURCE_DIR` | Local directory containing signed release manifest and pre-downloaded binaries (equivalent to `--artifact-dir`) |
| `OPSKIT_MANIFEST_URL` | URL to remote signed release manifest for static CLI installation |

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Bootstrap Guide and Capabilities](docs/bootstrap.md)
- [Security Model and Boundaries](docs/security.md)
- [Uninstall and Covenants](docs/uninstall.md)
- [Release Manifest Specification](docs/manifest-spec.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
