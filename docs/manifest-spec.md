# Release Manifest Specification (`opskit.release-manifest/v1`)

This document defines the schema, signature model, and verification process
for the OpsKit release manifest format: `opskit.release-manifest/v1`.

## 1. Format overview

The release manifest is an authenticated JSON document that maps platform
architectures to their corresponding binary artifacts, cryptographic digests,
and digital signatures.

```json
{
  "schema": "opskit.release-manifest/v1",
  "version": "0.1.0",
  "created_at": "2026-11-10T00:00:00Z",
  "artifacts": {
    "opskit-linux-x86_64": {
      "filename": "opskit-linux-x86_64",
      "arch": "x86_64",
      "os": "linux",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 18452104
    },
    "opskit-linux-aarch64": {
      "filename": "opskit-linux-aarch64",
      "arch": "aarch64",
      "os": "linux",
      "sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "size": 17892100
    }
  },
  "signatures": [
    {
      "key_id": "opskit-release-2026",
      "algorithm": "ed25519",
      "signature": "d3b07384d113edec49eaa6238ad5ff00..."
    }
  ]
}
```

## 2. Signature verification procedure

To verify a release manifest:

1. **Schema & Canonicalization**: The manifest `schema` must equal
   `opskit.release-manifest/v1`. Strict JSON parsing rejects duplicate object
   keys and non-finite numeric constants (RFC 8785). The manifest body is
   stripped of the `signatures` array and serialized via Python 3:
   `json.dumps(manifest_without_signatures, separators=(',', ':'), sort_keys=True, ensure_ascii=False, allow_nan=False).encode('utf-8')`.
2. **Signature verification**: Among `signatures` entries with `algorithm == "ed25519"`,
   the verifier selects the entry matching the pinned `key_id` (`opskit-release-2026`,
   supporting multi-signature key rotation) and verifies the raw canonical bytes
   against the pinned release public key (`keys/release.pub` / `lib/release.pub`,
   whose SHA-256 digest is pinned in production) via OpenSSL:
   `openssl pkeyutl -verify -pubin -inkey <pubkey> -rawin -in <canonical_bytes> -sigfile <signature_bytes>`.
3. **Artifact selection & filename safety**: The host architecture (`uname -m`)
   selects the corresponding artifact entry from `artifacts`. Declared `filename`
   values must match `^[A-Za-z0-9][A-Za-z0-9._-]*$` with no `..` traversal.
4. **Transport & Staged Digest/Size Verification**: Remote downloads require
   `https://` with TLS 1.2+, no redirects (`curl --proto =https --proto-redir =https --tlsv1.2`),
   and bounded `--max-filesize`. Remote payloads download to a fixed temporary file;
   local and remote payloads are copied into a root-owned `0600` staging file in the
   destination directory before computing SHA-256 digest and byte length on that
   private copy (preventing source-directory TOCTOU races).
5. **Atomic installation**: Only upon passing signature, digest, and size
   checks is the staged file `chmod 0755` and atomically moved to its final
   location (`/usr/local/bin/opskit`) owned by `root:root`.

If any verification step fails, the temporary file is deleted immediately,
nothing is executed, and `opskit-bootstrap` exits with code `8` (`VALIDATION_ERROR`).

## 3. Pinned release key

OpsKit release artifacts are signed by the root release key:
- **Key ID**: `opskit-release-2026`
- **Algorithm**: `ed25519`
- **Public Key**: Bundled with `opskit-bootstrap` at `keys/release.pub` and `lib/release.pub`.
- **Integrity**: Any manifest signed with an unexpected key ID or failing Ed25519 verification is immediately rejected.
