# Bootstrap Guide and Capabilities

`opskit-bootstrap` prepares host systems for running OpsKit workloads. This
document details the capability discovery process, hardware and software
gates, reachability verification, and the machine plan format.

## Capability detection checklist

Before any mutation is proposed or applied, `opskit-bootstrap` performs a
read-only audit of host capabilities. All checks must pass; failing gates
exit with code `8` (`VALIDATION_ERROR`) and provide distribution-specific
remediation steps. Ubuntu runs through the debian family modules (apt),
capability-identical (cgroup v2 default since 22.04, Podman Quadlet since 24.04).
openSUSE Tumbleweed is accepted ungated (rolling release).

| Capability | Requirement | Detection Method | Failure Remedy |
|---|---|---|---|
| Operating System | Debian 13+, Ubuntu 24.04+ (incl. 25.x interim), RHEL 9+, Fedora 39+, SLES 15 SP7+, openSUSE Leap 15.6+ / Tumbleweed | `/etc/os-release` parsing | Hard gate failure with distro-specific upgrade guidance |
| Python 3 Runtime | Python 3 interpreter available | PATH executable lookup | Hard gate: install `python3` via package manager (`apt-get install -y python3`, `dnf install -y python3`, or `zypper install -y python3`) |
| Linux Kernel | Kernel version >= 5.4 | `uname -r` | Hard gate: upgrade host kernel to enable rootless container namespaces |
| cgroups v2 | cgroups v2 hierarchy mounted (available controllers recorded in machine plan) | `/sys/fs/cgroup/cgroup.controllers` or `cgroup2` in `/proc/mounts` | Hard gate: mount cgroups v2 hierarchy |
| Service Manager | systemd detection (`systemd_running` and user manager recorded) | `/run/systemd/system` or PID 1 process name check | Recorded for unit enablement and reload behavior |
| Container Runtime | Podman >= 4.4 (for Quadlet support) or rootless Docker | `podman --version` / `docker --version` + rootless socket probe | Hard gate if Podman < 4.4. Pre-installed rootful Docker is converted to rootless via `dockerd-rootless-setuptool.sh` or fails closed; Podman installed if absent |
| cgroup Delegation | `Delegate=yes` on systemd `user@.service` | `/etc/systemd/system/user@.service.d/` + `DelegateControllers` | Drop-in `opskit-delegate.conf` configured so memory, cpu, and pids limits are enforced |
| User Namespaces | `newuidmap` and `newgidmap` available | PATH executable lookup | Package install planned: `uidmap` (Debian), `shadow-utils` (RHEL), or `shadow` (SLES) |
| Subordinate IDs | `/etc/subuid` and `/etc/subgid` available | File existence and permissions | Ensure shadow utility files are present and writable |
| Security Modules | SELinux and AppArmor recorded | `getenforce` / `aa-status` | Recorded for context; security modules are never disabled |
| Firewall Stack | `nftables`, `firewalld`, `ufw`, or `iptables` | Daemon / tool detection | Active stack identified and recorded; rule fingerprinted |
| Disk Storage | Free disk space >= 5 GiB on target roots | `df -Pk /var /` | Free up storage on `/var` or root filesystem before continuing |
| Clock Skew | Clock offset within +-300 seconds (warn > +-60s) | Local clock against monotonic or reference | Synchronize system clock using chrony or systemd-timesyncd |
| User Linger | User linger support available | `loginctl` command availability | Enable systemd linger for background service execution |

## Service user and subordinate IDs

OpsKit runs workloads under an isolated service user account (default: `opskit`).

1. **Pre-existing user audit**: If user `opskit` already exists, `opskit-bootstrap`
   verifies its configuration rather than assuming suitability.
2. **Subuid range reuse**: Existing entries in `/etc/subuid` and `/etc/subgid`
   are preserved. The script inspects allocated ranges and reuses existing
   assignments. If no range is allocated, it assigns a non-overlapping block
   of 65,536 IDs in accordance with [subuid(5)](https://man7.org/linux/man-pages/man5/subuid.5.html).
3. **Group safety**: The service account is never placed into the `docker`
   group. Membership in the `docker` group grants unconfined host access,
   bypassing rootless security controls.
4. **Credential hygiene**: PAM and SSH configurations are never modified.

## Reachability and exposure negotiation

When `--profile` is not explicitly passed, `opskit-bootstrap` presents an
interactive intent question:

```text
Can this machine accept inbound HTTPS from the public internet on TCP 443? [yes/no/not sure]
```

- **`no`**: Automatically configures the `tunnel` profile. Zero public ports
  are opened; ingress is established via outbound encrypted tunnels.
- **`yes`**: Initiates reachability verification for the `direct` profile:
  - If a control-plane or probe endpoint is reachable, an external probe
    verifies inbound TCP 443 connectivity across IPv4 and IPv6.
  - If an external probe fails (e.g. carrier-grade NAT or restrictive host
    firewalls), `opskit-bootstrap` downgrades the plan to `tunnel` with an
    explicit explanatory notice.
  - In offline environments without external probe services, a local bind
    audit verifies that port 443 is available, noting that automated ACME
    TLS-ALPN-01 handshake completion will serve as authoritative reachability
    verification.
- **Explicit override**: Passing `--profile direct`, `--profile tunnel`, or
  `--profile private` skips intent prompting and honors operator intent. If
  `--profile direct` fails external probing, a warning is issued but the
  explicit choice is respected.

## Offline artifact source directory

For offline or network-restricted installations (such as the private profile), `opskit-bootstrap` supports
loading the signed release manifest and pre-downloaded static binaries from a
local directory using the `--artifact-dir <path>` flag or the
`OPSKIT_ARTIFACT_SOURCE_DIR` environment variable.

The directory must contain:
- `release-manifest.json`: The signed `opskit.release-manifest/v1` document.
- `opskit-linux-<arch>`: The static executable binary for the host architecture.

When provided, cryptographic verification (JCS canonicalization, Ed25519 signature
check, and SHA-256 payload digest verification) executes identically to network
downloads before installing to the target binary path.

## Re-runs and idempotency

`opskit-bootstrap` is strictly idempotent. Running `opskit-bootstrap` on an
already-bootstrapped node evaluates current system state against the local ledger
`/var/lib/opskit-bootstrap/apply.jsonl`. When all planned mutations are already
recorded in the ledger and verified present, the plan evaluates to `no_changes=true`
and exits `0` with `Host already bootstrapped; no changes required`.

When `OPSKIT_MANIFEST_URL` is configured, a re-run verifies against the ledger:
if the static CLI binary has already been installed and recorded in the ledger,
`fetch_cli` is omitted from the plan so that the re-run achieves `no_changes=true`.

## Environment variables

- `OPSKIT_PROBE_SERVER`: Overrides the external reachability probe endpoint URL.
- `OPSKIT_ARTIFACT_SOURCE_DIR`: Local directory containing signed release manifest and binaries (equivalent to `--artifact-dir`).
- `OPSKIT_MANIFEST_URL`: URL to remote signed release manifest.

## Test mode environment variables

`opskit-bootstrap` provides deterministic test hooks for automated container
acceptance suites. In production execution, all test hook variables are strictly
rejected with exit code `8` (`VALIDATION_ERROR`) unless `OPSKIT_TEST_MODE=1` is
explicitly set in the environment.

Protected test hook variables include:
- `MOCK_KERNEL_RELEASE`: Overrides kernel release string for version gating tests.
- `MOCK_DISK_FREE_GB`: Injects mock free storage capacity for disk boundary checks.
- `MOCK_NODE_FINGERPRINT`: Injects deterministic node fingerprint.
- `MOCK_EXPIRES_AT`: Injects static plan expiration timestamp.
- `MOCK_CLOCK_SKEW`: Simulates clock drift.
- `MOCK_HAS_V6_ROUTE`: Simulates host default IPv6 route status.
- `OPSKIT_SKIP_DISK_CHECK`: Skips minimum disk space evaluation in container test runs.
- `OPSKIT_OS_RELEASE_FILE`: Points to alternate `/etc/os-release` fixture.
- `OPSKIT_SUBUID_START` and `OPSKIT_SUBUID_COUNT`: Injects deterministic subordinate UID range.
- `OPSKIT_FORCE_CGROUPS_V2` and `OPSKIT_FORCE_SYSTEMD`: Simulates container virtualization attributes.

## Machine plan format (`opskit.bootstrap-plan/v1`)

The plan is a versioned JSON document recording detected capabilities,
selected profile, proposed mutations, and postconditions:

```json
{
  "schema": "opskit.bootstrap-plan/v1",
  "node_fingerprint": "8d3e2a...",
  "capabilities": {
    "os_id": "debian",
    "os_version": "13",
    "kernel_ok": true,
    "cgroups_v2": true,
    "runtime": "podman",
    "runtime_version": "5.0.0"
  },
  "profile": "direct",
  "runtime": "podman",
  "mutations": [
    {
      "id": "service_user",
      "class": "H",
      "requires_root": true,
      "description": "Create rootless service user and group 'opskit'",
      "target": "/etc/passwd, /etc/group",
      "rollback": "userdel -r opskit"
    }
  ],
  "no_changes": false,
  "probe_results": {
    "status": "verified",
    "reachable_v4": true,
    "reachable_v6": true,
    "details": "Inbound reachability confirmed on port 443"
  },
  "postconditions": [
    "service_user_rootless_functional",
    "systemd_socket_units_active"
  ],
  "expires_at": "2026-11-10T02:00:00Z"
}
```

The plan hash is the SHA-256 digest over the canonical JSON representation.
When authorization is granted (`--yes` or interactive confirmation), this
hash is bound into the apply record.
