"""Release artifact signing and verification.

``zhongli`` signs a release artifact by recording its name, size and SHA-256
in a canonical JSON manifest, signing the exact manifest bytes, and storing
manifest and signature in a JSON bundle. Verification accepts the artifact
only if the bundle is well formed, the signing key is trusted for the
expected package in a local trust store, the signature is valid, and the
metadata and artifact bytes match. Three profiles are supported:
``rsa-pss-sha256``, ``ecdsa-p256-sha256`` and ``ed25519``.

This documentation covers the Python modules behind the command-line tool.
The CLI is a thin layer over these functions; every command maps to one of
them.

| Command | Function |
| --- | --- |
| ``keygen`` | `zhongli.keygen.keygen` |
| ``sign`` | `zhongli.signing.sign` |
| ``verify`` | `zhongli.verification.verify` |
| ``trust add`` / ``list`` / ``remove`` | `zhongli.trust.add_trust`, `zhongli.trust.list_trust`, `zhongli.trust.remove_trust` |
| ``sbom create`` / ``sign`` / ``verify`` | `zhongli.sbom.create_sbom`, `zhongli.sbom.sign_sbom`, `zhongli.sbom.verify_release_with_sbom` |

## Modules

| Module | Responsibility |
| --- | --- |
| `zhongli.formats` | Strict JSON, canonical manifest bytes, bundle encoding and parsing |
| `zhongli.artifact` | Streaming size and SHA-256 of an artifact |
| `zhongli.keys` | Routes keys and profiles to their adapter; keyid computation |
| `zhongli.crypto` | One adapter per profile over PyCA ``cryptography`` |
| `zhongli.trust` | ``minisign-trust/v1`` validation, lookup and atomic updates |
| `zhongli.keygen` | Key pair generation and PEM output |
| `zhongli.signing` | Manifest construction and signing |
| `zhongli.verification` | The verifier and its fixed check order |
| `zhongli.sbom` | CycloneDX SBOM bound to a release artifact, signed and verified |
| `zhongli.cli` | Argument parsing and exit codes |

## Example

```python
from zhongli.keygen import keygen
from zhongli.signing import sign
from zhongli.trust import add_trust
from zhongli.verification import verify

key = keygen("ecdsa-p256-sha256", "keys/publisher")
with open(key.public_key_path, "rb") as stream:
    add_trust("trust.json", stream.read(), "contoh-app")

sign("dist/contoh-app.zip", "contoh-app", "1.0.0", key.private_key_path, "release.json")
result = verify("dist/contoh-app.zip", "release.json", "trust.json", "contoh-app", "1.0.0")
print(result.status, result.exit_code)   # OK 0
print(result.to_json())                  # the object printed by verify --json
```

The same flow with the CLI:

```sh
zhongli keygen --algorithm ecdsa-p256-sha256 --out keys/publisher
zhongli trust add --key keys/publisher.pub.pem --package contoh-app --store trust.json
zhongli sign --file dist/contoh-app.zip --package contoh-app --version 1.0.0 \\
  --key keys/publisher.key.pem --out release.json
zhongli verify --file dist/contoh-app.zip --bundle release.json \\
  --trust-store trust.json --package contoh-app --version 1.0.0 --json
```

## Verification statuses

Checks run in this order and stop at the first failure.

| Status | Exit | Meaning |
| --- | ---: | --- |
| ``INPUT_ERROR`` | 2 | Invalid options or expected values; an input cannot be read |
| ``FORMAT_ERROR`` | 1 | Bundle, manifest or trust store violates its format |
| ``UNSUPPORTED_ALGORITHM`` | 1 | The manifest names an unknown profile |
| ``KEY_NOT_TRUSTED`` | 1 | Keyid absent, trusted under another profile, or not allowed for the package |
| ``INVALID_SIGNATURE`` | 1 | The signature over the stored manifest bytes is invalid |
| ``METADATA_MISMATCH`` | 1 | Package, version or artifact basename differ from the expected values |
| ``ARTIFACT_MISMATCH`` | 1 | Artifact size or SHA-256 differ from the manifest |
| ``OK`` | 0 | All checks passed |

Functions that read files raise ``OSError`` for I/O failures and
``ValueError`` subclasses (`zhongli.formats.FormatError`,
`zhongli.keys.KeyValidationError`) for invalid content. The exceptions are
`zhongli.verification.verify` and `zhongli.sbom.verify_release_with_sbom`,
which never raise for bad inputs and report them as a status instead.
"""


def main() -> None:
    """Console script entry point; exits with the CLI's exit code."""
    from .cli import main as cli_main

    raise SystemExit(cli_main())
