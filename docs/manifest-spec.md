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

1. **Canonicalization**: The manifest body is stripped of the `signatures`
   array. The remaining document is canonicalized using a JCS-compatible profile
   for this schema; numbers restricted to integers using Python 3:
   `json.dumps(manifest_without_signatures, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')`.
2. **Signature verification**: The raw canonical bytes are verified against
   the Ed25519 signature using the pinned release public key (`opskit-release-2026`
   committed in `keys/release.pub` and vendored in `lib/release.pub`) via OpenSSL:
   `openssl pkeyutl -verify -pubin -inkey <pubkey> -rawin -in <canonical_bytes> -sigfile <signature_bytes>`.
3. **Artifact selection**: The host architecture (`uname -m`) selects the
   corresponding artifact entry from `artifacts`.
4. **Digest verification**: The downloaded artifact is placed into an
   isolated temporary file and its SHA-256 digest is computed. The digest
   must match the `sha256` field in the manifest exactly.
5. **Size validation**: The byte length of the file must match the `size` field.
6. **Atomic installation**: Only upon passing signature, digest, and size
   checks is the artifact moved to its final location (`/usr/local/bin/opskit`)
   with file mode `0755` owned by `root:root`.

If any verification step fails, the temporary file is deleted immediately,
nothing is executed, and `opskit-bootstrap` exits with code `8` (`VALIDATION_ERROR`).

## 3. Pinned release key

OpsKit release artifacts are signed by the root release key:
- **Key ID**: `opskit-release-2026`
- **Algorithm**: `ed25519`
- **Public Key**: Bundled with `opskit-bootstrap` at `keys/release.pub` and `lib/release.pub`.
- **Integrity**: Any manifest signed with an unexpected key ID or failing Ed25519 verification is immediately rejected.
