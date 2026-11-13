# if4020-signing

A Python CLI for signing software release manifests. Currently supports the
RSA-PSS and Ed25519 profiles, `keygen`, `sign` and trust store management.
ECDSA and verification are pending integration. The program name is provisional.

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

uv run if4020-signing keygen --algorithm ed25519 --out keys/publisher
uv run if4020-signing trust add --key keys/publisher.pub.pem \
  --package contoh-app --store trust.json
uv run if4020-signing trust list --store trust.json
uv run if4020-signing trust remove --keyid <keyid> --store trust.json
```

`keygen --algorithm <profile> --out <prefix>` writes `<prefix>.key.pem` (PKCS8,
mode 0600) and `<prefix>.pub.pem` (SPKI) and prints the keyid. Existing key files
are only replaced with `--force`. `sign` derives the profile from the private key.

Keys in `tests/fixtures/rsa/` are public test fixtures. Never use them for real
releases. `keygen`, `sign` and `trust` return exit 0 on success or 2 for invalid
input or I/O errors, including `trust remove` with an unknown keyid.

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
- Ed25519 profile: `ed25519`, Pure Ed25519 (RFC 8032) without pre-hash or context,
  64-byte deterministic signatures.
  [PyCA Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/):
  `Ed25519PrivateKey.generate()`; `sign(message)` / `verify(signature, message)`
  on the original manifest bytes. Keys follow RFC 8410 (no AlgorithmIdentifier
  parameters); public keys must be the canonical 44-byte SPKI encoding.
- Trust store: `minisign-trust/v1` with exactly `schema` and `keys`; each entry has
  exactly `keyid, algorithm, public_key_pem, packages`. Every entry is validated
  on load (profile matches key type/parameters, keyid matches the key, packages
  non-empty, unique, no wildcards, unique keyids); invalid stores are never
  overwritten. Updates are written to a temp file and atomically replaced.
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

The `Dockerfile` builds a `linux/amd64` image whose entrypoint is the CLI; the
build context contains only the project sources and lock file (no tests or keys).
`.github/workflows/publish-image.yml` publishes it to
`ghcr.io/dadecky/if4020-signing` on a `vX.Y.Z` tag matching the program version
and records the digest in the run summary.

```sh
docker pull ghcr.io/dadecky/if4020-signing@sha256:<digest>
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/output" ghcr.io/dadecky/if4020-signing@sha256:<digest> \
  keygen --algorithm ed25519 --out /output/publisher
```

`.github/workflows/release-pipeline.yml` is the consumer pipeline: it pulls the
image pinned in `ci/pipeline.env`, signs with a per-profile secret
(`SIGNING_KEY_RSA_PSS_SHA256`, `SIGNING_KEY_ECDSA_P256_SHA256`,
`SIGNING_KEY_ED25519`), verifies with `ci/trust.json` and only then writes a
deployment marker, and checks that the CLI runs with the runner UID/GID, no TTY
and `--network none`.

| Program version | Source tag | Image digest |
| --- | --- | --- |
| _pending first release_ | | |
