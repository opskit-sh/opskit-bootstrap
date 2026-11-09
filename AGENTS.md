# AGENTS.md

A guide for AI agents and human contributors working in this repository.

## 1. Orientation

`opskit-bootstrap` is the one-time machine preparation and uninstallation tool
for nodes running OpsKit software. It configures the rootless environment
required to run containerized workloads and the unprivileged exposure boundary:
service user creation, subuid/subgid allocation, systemd user linger,
optional root-owned systemd socket activation for port 443/80 under the direct
profile, and host firewall configuration.

This repository is the only privileged surface in the OpsKit product. After
bootstrap executes, no installed OpsKit binary runs as root or requires `sudo`.

## 2. Repository layout

| Path | Role |
|---|---|
| `bin/opskit-bootstrap` | Main executable script |
| `lib/common.sh` | Shared utilities, output formatting, exit codes |
| `lib/detect.sh` | Read-only capability detection |
| `lib/probe.sh` | Inbound reachability probing and profile negotiation |
| `lib/plan.sh` | Machine plan generation (`opskit.bootstrap-plan/v1`) |
| `lib/manifest.sh` | Signed release manifest verification (`opskit.release-manifest/v1`) |
| `lib/ledger.sh` | Append-only apply ledger (`apply.jsonl`) |
| `lib/apply.sh` | Closed mutation applier |
| `lib/undo.sh` | Precise offline uninstaller |
| `lib/repair.sh` | Drift detection and authorized repair |
| `lib/family/` | Distribution-family adapters (Debian, RHEL/Fedora, SLES) |
| `docs/` | Architecture, security model, and usage documentation |
| `tests/` | Acceptance test suites and golden fixtures |

## 3. Golden rules

1. **One-time root, then none.** Privilege belongs strictly to the bootstrap
   script. Shipped binaries and subsequent operations run unprivileged.
2. **Capability detection, not OS recipes.** Inspect what exists, mutate only
   what is missing, and never overwrite administrator configuration.
3. **The mutation inventory is closed.** Unspecified mutations are forbidden.
   Any change must be documented, fingerprinted, and recorded in the ledger.
4. **Offline and reversible by construction.** The uninstaller and the
   applied mutation ledger are vendored locally at install time. Reversal
   (`--undo`) requires no network access and removes precisely the recorded
   state.
5. **Pay-for-what-you-use exposure.** Only the `direct` profile installs
   root-owned socket activation units and firewall rules. The `tunnel` and
   `private` profiles create zero root-owned systemd units beyond the service
   user and linger.
6. **No silent repair.** Configuration drift is detected and reported;
   remediation requires explicit authorization via `--repair`.
7. **No emojis** in code, comments, documentation, commit messages, or output.
8. **Cite authoritative upstream documentation** at implementation sites
   (for example systemd(1), podman(1), subuid(5), nftables(8), RFC 8785).

## 4. Testing

Run all acceptance test suites:

```bash
bash scripts/run-tests.sh
```

Tests run inside isolated containers or temporary environments; the host
system is never mutated.

## 5. Finishing checklist

- Code is formatted and clean.
- All acceptance test suites pass.
- Internal documentation links resolve (`bash scripts/check-docs.sh`).
- No internal identifiers or private references exist in commits or documentation.
