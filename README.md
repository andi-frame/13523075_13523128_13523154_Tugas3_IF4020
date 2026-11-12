# if4020-signing

A Python CLI for signing software release manifests. Currently supports RSA-PSS
signing. ECDSA, Ed25519, `keygen`, trust management, verification, and container
execution are pending integration. The program name is provisional.

## Requirements

Python 3.13.x and [uv](https://docs.astral.sh/uv/). Dependencies are locked in
`uv.lock`: cryptography 50.0.2, cffi 2.1.1, pycparser 3.12; tests use pytest 9.2.0.
OpenSSL CLI is needed for interoperability tests; those tests skip if unavailable.

## Local usage

```sh
uv sync --locked
uv run if4020-signing --help
uv run if4020-signing --version
uv run if4020-signing sign --file tests/fixtures/rsa/demo.bin \
  --package demo --version 1.0 --key tests/fixtures/rsa/TEST_ONLY.key.pem \
  --out /tmp/demo.bundle.json
```

Keys in `tests/fixtures/rsa/` are public test fixtures. Never use them for real
releases. Signing returns exit 0 on success or 2 for invalid input or I/O errors.

## Formats and cryptography

- Manifest: `minisign-manifest/v1`, canonical UTF-8 JSON, at most 16 KiB;
  field order `schema, package, version, algorithm, keyid, artifact` and
  artifact field order `name, size, sha256`. No BOM or external whitespace.
- Bundle: `minisign-bundle/v1`, at most 64 KiB; fields
  `schema, manifest_b64, signature_b64`, using canonical RFC 4648 Base64.
  Duplicate, missing, extra, or incorrectly typed fields are rejected.
- RSA profile: `rsa-pss-sha256`, 3072-bit keys, exponent 65537, 384-byte signatures.
  [PyCA RSA API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/):
  `generate_private_key(public_exponent=65537, key_size=3072)`;
  `sign/verify(message, PSS(MGF1(SHA256()), salt_length=32), SHA256())`.
  The original manifest is hashed exactly once; PSS uses a random salt.
- Keys: unencrypted PKCS8 private PEM and rsaEncryption SPKI public PEM with
  canonical DER encoding. Fingerprint: lowercase `SHA256(DER_SPKI)`.
  See the [serialization API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/).

Artifacts are read as raw bytes for SHA-256 and size. Bundle writes are atomic;
output paths that would overwrite the artifact or private key are rejected.

## Tests and benchmarks

```sh
uv run pytest -q
uv run python benchmarks/run.py --out evidence/benchmarks/rsa-new-run
```

Benchmark output includes raw CSV, environment metadata, key/signature/bundle
sizes, median and nearest-rank P95. Defaults: 1 KiB/1 MiB/10 MiB artifacts,
5 keygens, 5 warmups and 30 samples per condition. Use a new output directory.
Initial RSA results: `evidence/benchmarks/rsa-initial/`.
Application verification and CI tests are pending integration.

## Container and CI/CD

The public image, pull/run instructions, examples for the remaining required
subcommands, and program-version/source-tag/image-digest mapping will be added
when the container and remaining commands are available.
