# zhongli

A command-line tool for signing software release artifacts and verifying them
before publication or deployment. It follows the blob-signing flow of Sigstore
Cosign, but with a local trust store instead of certificates or a transparency
log:

1. `sign` reads an artifact, records its name, size and SHA-256 in a release
   manifest, signs the exact manifest bytes and stores manifest and signature
   in a JSON bundle.
2. `verify` accepts the artifact only if the bundle is well formed, the signing
   key is trusted for the expected package, the signature is valid, and the
   metadata and artifact bytes match.

Three signature profiles are supported: `rsa-pss-sha256`, `ecdsa-p256-sha256`
and `ed25519`. The tool is distributed as a container image for CI/CD runners
and also runs directly with Python.

The name comes from Zhongli, the god of contracts in Genshin Impact: a release
manifest is a contract, and `verify` refuses any release that breaks it.

| | |
| --- | --- |
| Release | [zhongli 0.1.2](https://github.com/andi-frame/13523075_13523128_13523154_Tugas3_IF4020/releases/tag/v0.1.2) |
| Report | [`docs/13523075_13523128_13523154_Tugas3_IF4020.pdf`](docs/13523075_13523128_13523154_Tugas3_IF4020.pdf) |
| Image | [`andiframe/zhongli`](https://hub.docker.com/r/andiframe/zhongli) on Docker Hub, see [Container image](#container-image) |
| API documentation | <https://andi-frame.github.io/13523075_13523128_13523154_Tugas3_IF4020/> |
| CI evidence | [`evidence/ci/`](evidence/ci/) |

## Tech stack and dependencies

| Component | Version | Purpose |
| --- | --- | --- |
| Python | 3.13.x | Runtime (`requires-python = ">=3.13,<3.14"`) |
| [uv](https://docs.astral.sh/uv/) | 0.13.4 (image build) | Project and dependency management, `uv.lock` |
| [cryptography](https://cryptography.io/) | 50.0.2 | RSA-PSS, ECDSA, Ed25519, key serialization |
| cffi, pycparser | 2.1.1, 3.12 | Transitive dependencies of cryptography |
| [pytest](https://docs.pytest.org/) | 9.2.0 | Tests only (dev group) |
| [pdoc](https://pdoc.dev/) | 16.0.0 | API documentation only (docs group) |
| OpenSSL CLI | any 3.x | Tests only: independent interoperability checks; skipped if absent |
| `python:3.13-slim-bookworm` | Docker base image | Container runtime |

JSON, Base64, SHA-256 and the CLI use the Python standard library (`json`,
`base64`, `hashlib`, `argparse`). Manifest construction, strict parsing, trust
store management and the signing and verification flow are implemented in this
repository; no external signing application is invoked.

## Container image

The image runs the CLI as its entrypoint (`docker run --rm <image> <subcommand> ...`)
on `linux/amd64`. All dependencies are inside the image, so every command works
with `--network none`. It runs as an unprivileged user by default and accepts the
runner's UID/GID through `--user`. It is published to the public Docker Hub
repository [`andiframe/zhongli`](https://hub.docker.com/r/andiframe/zhongli) by
`.github/workflows/publish-image.yml`: as tag `X.Y.Z` when a `vX.Y.Z` tag that
matches the program version is pushed, or as `dev-<commit>` when the workflow is
started by hand. No credentials are needed to pull it.

| Program version | Source | Image tag | Image digest |
| --- | --- | --- | --- |
| 0.1.2 | [`v0.1.2`](https://github.com/andi-frame/13523075_13523128_13523154_Tugas3_IF4020/tree/v0.1.2) @ `067f9f542587` | `0.1.2` | `sha256:cdc390179abb33411089224169be0f351eb04d13906edfa3a6bbe7d26432779a` |

`ci/pipeline.env` pins the digest above. The [release image build](https://github.com/andi-frame/13523075_13523128_13523154_Tugas3_IF4020/actions/runs/44500855372) built this image from repository tag `v0.1.2` and verified an anonymous pull and offline CLI execution.

Always pin the image by digest, not by tag:

```sh
IMAGE=docker.io/andiframe/zhongli@sha256:cdc390179abb33411089224169be0f351eb04d13906edfa3a6bbe7d26432779a
docker pull "$IMAGE"
docker run --rm --network none "$IMAGE" --version
```

### Use on a CI/CD runner

Inputs are bind-mounted read-only, outputs go to a mounted directory, and the
private key is a temporary file from a CI secret, mounted read-only:

```sh
set -eu
: "${IMAGE:?}" "${SIGNING_KEY_FILE:?}"
trap 'rm -f "$SIGNING_KEY_FILE"' 0
mkdir -p out
docker pull "$IMAGE"

docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" \
  -v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" \
  "$IMAGE" sign --file /input/contoh-app.zip --package contoh-app \
  --version 1.0.0 --key /run/signing.key.pem --out /output/release.json

docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output:ro" \
  -v "$PWD/ci/trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/contoh-app.zip --bundle /output/release.json \
  --trust-store /trust.json --package contoh-app --version 1.0.0 --json \
  > out/verification.json
```

With `set -e`, a rejected release (exit 1) or an input error (exit 2) stops the
script before any deployment step. Never append `|| true` or use
`continue-on-error` on the verify step of a release path.

`.github/workflows/release-pipeline.yml` is the consumer pipeline. It pulls the
image pinned in `ci/pipeline.env` and runs these jobs:

| Scenario | Job | What it shows |
| --- | --- | --- |
| C01 | `sign` → `verify` → `deploy` (all three profiles) | A valid release is signed, verified and only then gets a deployment marker |
| C02 | `rejection` / `artifact-byte-changed` | One artifact byte changed after signing: `ARTIFACT_MISMATCH`, exit 1, no marker |
| C03 | `rejection` / `empty-trust-store`, `key-not-allowed-for-package` | `KEY_NOT_TRUSTED`, exit 1, no marker |
| C04 | `rejection` / `artifact-missing` | Artifact path does not exist: `INPUT_ERROR`, exit 2, no marker |
| C05 | `runtime-contract` | Runner UID/GID, no TTY, `--network none`, missing option fails with exit 2 |

All jobs run on GitHub-hosted `ubuntu-24.04` runners (Linux amd64, a new virtual
machine per job). [`evidence/ci/`](evidence/ci/) holds a copy of the last run: run
links, job logs, verification JSON, deployment markers and per-scenario results.

The signing keys come from the secrets `SIGNING_KEY_RSA_PSS_SHA256`,
`SIGNING_KEY_ECDSA_P256_SHA256` and `SIGNING_KEY_ED25519` and exist only for this
demo. The verify jobs never receive a private key. Trust stores are prepared in
`ci/` ahead of time and are never generated by the pipeline; see `ci/README.md`.

## Commands

| Command | Options | Output |
| --- | --- | --- |
| `keygen` | `--algorithm <profile> --out <prefix> [--force]` | `<prefix>.key.pem`, `<prefix>.pub.pem`, keyid on stdout |
| `sign` | `--file <path> --package <name> --version <version> --key <private.pem> --out <bundle.json>` | Bundle; the profile is taken from the private key |
| `verify` | `--file <path> --bundle <bundle.json> --trust-store <trust.json> --package <name> --version <version> [--json]` | Verification result |
| `trust add` | `--key <public.pem> --package <name> --store <trust.json>` | Keyid, profile and allowed packages; creates the store if missing |
| `trust list` | `--store <trust.json>` | One line per key: keyid, profile, packages |
| `trust remove` | `--keyid <keyid> --store <trust.json>` | Removed entry; exit 2 if the keyid is not in the store |
| `sbom create` | `--file <path> --package <name> --version <version> [--lock uv.lock] --out <sbom.json>` | CycloneDX SBOM of the artifact; see [Signed SBOM](#signed-sbom) |
| `sbom sign` | `--sbom <sbom.json> --package <name> --version <version> --key <private.pem> --out <sbom.bundle.json>` | SBOM bundle (same bundle format) |
| `sbom verify` | `--file <path> --bundle <bundle.json> --sbom <sbom.json> --sbom-bundle <sbom.bundle.json> --trust-store <trust.json> --package <name> --version <version> [--json]` | Result for both bundles and their binding |

`--help` and `--version` are available globally and `--help` on every command.
No command prompts for input or needs a TTY. Missing options, unknown options
and abbreviated options (for example `--pack`) fail immediately with exit 2.
Existing key files are replaced only with `keygen --force`.

```sh
zhongli keygen --algorithm ecdsa-p256-sha256 --out keys/publisher
zhongli trust add --key keys/publisher.pub.pem --package contoh-app --store trust.json
zhongli trust list --store trust.json
zhongli sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json
zhongli verify --file contoh-app.zip --bundle release.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json
zhongli trust remove --keyid <keyid> --store trust.json
```

### Verification result

Checks run in this order and stop at the first failure. No other key, profile
or trust store is tried, and the trust store is never updated from a bundle.

| Order | Status | Exit | Failure condition |
| ---: | --- | ---: | --- |
| 1 | `INPUT_ERROR` | 2 | Invalid options or expected values; an input file cannot be read |
| 2 | `FORMAT_ERROR` | 1 | Bundle, manifest or trust store violates its format, size limit, canonical serialization or Base64 rules; a trust store key does not match its profile or keyid |
| 3 | `UNSUPPORTED_ALGORITHM` | 1 | Manifest `algorithm` is not one of the three profiles |
| 4 | `KEY_NOT_TRUSTED` | 1 | Keyid not in the store, trusted under another profile, or not allowed for the expected package |
| 5 | `INVALID_SIGNATURE` | 1 | Signature invalid over the stored manifest bytes, including wrong length or out-of-range ECDSA values |
| 6 | `METADATA_MISMATCH` | 1 | Package, version or artifact basename differ from the expected values |
| 7 | `ARTIFACT_MISMATCH` | 1 | Artifact size or SHA-256 differ from the manifest |
| 8 | `OK` | 0 | All checks passed |

With `--json`, stdout holds exactly one JSON object followed by a newline;
diagnostics go to stderr. This also applies to usage errors such as a missing
option, an unknown option or an unexpected positional argument: all are reported
as `INPUT_ERROR`, including errors raised by the root argument parser.

```json
{"valid": true, "status": "OK", "message": "Signature and artifact are valid.", "algorithm": "ecdsa-p256-sha256", "keyid": "2339bbb4fed9733fdf3494cca5b32335b9770e67391dbbca99fd55b0d7e50668", "package": "demo", "version": "1.0"}
```

`algorithm`, `keyid`, `package` and `version` are `null` until the manifest has
been parsed. When `valid` is false they only explain the result and must not be
trusted. Without `--json`, an accepted release is reported on stdout and a
rejection on stderr. All other commands exit 0 on success and 2 on failure.

## File formats

**Manifest** (`minisign-manifest/v1`) is the signed message. It is canonical
UTF-8 JSON without BOM, whitespace, escapes or a trailing newline, at most
16 KiB, with fields in the order `schema, package, version, algorithm, keyid,
artifact` and `artifact` as `name, size, sha256`:

```json
{"schema":"minisign-manifest/v1","package":"demo","version":"1.0","algorithm":"ecdsa-p256-sha256","keyid":"2339bbb4…","artifact":{"name":"demo.bin","size":26,"sha256":"ee5fe9c6…"}}
```

Patterns: package `[a-z0-9][a-z0-9._-]{0,63}`, version
`[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`, artifact name
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, size an integer from 0 to 2^53 − 1 (booleans
are rejected), keyid and sha256 64 lowercase hex characters. The verifier parses
the manifest strictly, re-serializes it and requires a byte-for-byte match, then
checks the signature over the original bytes.

**Bundle** (`minisign-bundle/v1`) holds exactly `schema`, `manifest_b64` and
`signature_b64`, at most 64 KiB, UTF-8 without BOM. Field order and whitespace
are free. Both values use canonical RFC 4648 Base64 with padding and no
whitespace, checked by decoding and re-encoding.

**Trust store** (`minisign-trust/v1`) holds exactly `schema` and `keys`. Each
entry has exactly `keyid`, `algorithm`, `public_key_pem` and `packages`. Every
entry is validated on load: the key matches the profile and its parameters, the
keyid matches the key, packages are non-empty, unique and contain no wildcards,
and keyids are unique. Trust stores have no additional file-size cap; a valid
store remains readable after its package permissions grow. Invalid stores are never overwritten. Updates are written
to a temporary file in the same directory and then atomically replaced.

**Keys** are unencrypted PKCS#8 PEM (`PRIVATE KEY`) and SubjectPublicKeyInfo PEM
(`PUBLIC KEY`). The keyid is `hex_lower(SHA256(DER_SPKI))` of the re-exported
public key, so PEM line wrapping and line endings do not change it.

Strict JSON parsing rejects duplicate field names while parsing (via
`object_pairs_hook`), as well as `NaN`/`Infinity`, invalid UTF-8 and trailing data.

## Signed SBOM

An SBOM (Software Bill of Materials) lists what a release is made of. Here it
is a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) JSON file that names
the release artifact by its SHA-256. It is signed as a separate artifact with
the normal signing flow, so it gets an ordinary `minisign-bundle/v1` bundle
whose key is checked against the same trust store.

```sh
zhongli sign --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json
zhongli sbom create --file contoh-app.zip --package contoh-app --version 1.0.0 \
  --lock uv.lock --out sbom.json
zhongli sbom sign --sbom sbom.json --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out sbom.bundle.json
zhongli sbom verify --file contoh-app.zip --bundle release.json \
  --sbom sbom.json --sbom-bundle sbom.bundle.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json
```

**SBOM content.** `sbom create` hashes the artifact and writes the fields
below. Other CycloneDX fields are allowed when verifying; these are required.
The output is deterministic: no timestamp, and the serial number is a UUIDv5
of package, version and artifact SHA-256.

| Field | Type | Value |
| --- | --- | --- |
| `bomFormat`, `specVersion` | string | `"CycloneDX"`, `"1.6"` |
| `version` | integer | `1` (any positive integer is accepted) |
| `metadata.component.name`, `.version` | string | Package and version; must equal `--package` and `--version` |
| `metadata.component.hashes` | array | Exactly one `{"alg": "SHA-256", "content": "<64 lowercase hex>"}`: the artifact SHA-256 |
| `metadata.component.properties` | array | Exactly one `zhongli:artifact:name` (artifact basename) and one `zhongli:artifact:size` (decimal byte count) |
| `components` | array | Runtime dependencies from `--lock` (name, version, `pkg:pypi` purl); empty without `--lock` |

`sbom sign` refuses an SBOM that is invalid or names another package or
version. **`sbom verify`** runs `verify` on the release bundle and on the
SBOM bundle, parses the SBOM from the exact bytes whose signature was checked,
and compares its SHA-256, size and file name with the verified release
manifest. The result is the first failure in this order:

| Stage | Status | Exit | Example |
| --- | --- | ---: | --- |
| any | `INPUT_ERROR` | 2 | Artifact, bundle or SBOM file missing |
| `artifact` | any `verify` status | 1 | Artifact byte changed: `ARTIFACT_MISMATCH` |
| `sbom` | any `verify` status | 1 | SBOM edited after signing: `ARTIFACT_MISMATCH`; SBOM signed by an untrusted key: `KEY_NOT_TRUSTED` |
| `sbom` | `FORMAT_ERROR` | 1 | The signed file is not a CycloneDX SBOM in this form |
| `binding` | `SBOM_MISMATCH` | 1 | Artifact replaced and re-signed with a trusted key while the old SBOM was kept, or a valid SBOM of another artifact |
| – | `OK` | 0 | Both bundles valid and the SBOM names the verified artifact |

With `--json`, stdout is one object: `valid`, `status`, `stage`, `message`,
`artifact` and `sbom` (each a `verify --json` object), and `binding` (the
compared values and `match`, or `null` if a bundle failed). The `verify`
command and its statuses are unchanged.

## API documentation

The Python API is documented at
**<https://andi-frame.github.io/13523075_13523128_13523154_Tugas3_IF4020/>**:
one page per module with parameters, return values and their types, raised
exceptions and examples. The pages are generated from the docstrings and type
hints in `src/zhongli` with [pdoc](https://pdoc.dev/) and deployed to GitHub
Pages by `.github/workflows/api-docs.yml` on every change to `src/`. To build
them locally:

```sh
uv run --group docs pdoc --docformat google --output-directory site zhongli
```

## Profiles and library API

All profiles use the [PyCA cryptography](https://cryptography.io/) hazmat API.
Signatures are computed over the manifest bytes `M` from the bundle. For RSA and
ECDSA the library hashes `M` with SHA-256 exactly once; no digest is passed in
(no double hashing).

| Profile | Key | Sign / verify call | Signature |
| --- | --- | --- | --- |
| `rsa-pss-sha256` | [`rsa.generate_private_key(public_exponent=65537, key_size=3072)`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/); SPKI `rsaEncryption`, exactly 3072 bits, e = 65537 | `sign(M, PSS(mgf=MGF1(SHA256()), salt_length=32), SHA256())` | 384 bytes; random salt |
| `ecdsa-p256-sha256` | [`ec.generate_private_key(SECP256R1())`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/); named-curve OID, uncompressed SEC1 point | `sign(M, ECDSA(SHA256(), deterministic_signing=True))`, verify with `ECDSA(SHA256())` | 64 bytes `r ‖ s`, 32-byte big-endian each; RFC 6979 nonce |
| `ed25519` | [`Ed25519PrivateKey.generate()`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/); RFC 8410 without AlgorithmIdentifier parameters | `sign(M)` / `verify(signature, M)`, pure Ed25519, no pre-hash or context | 64 bytes; deterministic |

Key loading and export use the
[serialization API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/).
Private key import checks the PKCS#8 envelope and profile AlgorithmIdentifier
(OID and parameters), while the backend validates the key material. Standard
optional attributes such as `friendlyName` are accepted; SEC1/PKCS#1 data
disguised as `PRIVATE KEY` and trailing DER data are rejected. Public keys must be in canonical DER: a key that differs from its own re-export
(for example a compressed EC point, explicit curve parameters or an RSA-PSS
restricted OID) is rejected.

ECDSA details: the library returns DER, which `crypto/ecdsa.py` converts to
`r ‖ s` with `decode_dss_signature`; verification converts back with
`encode_dss_signature`. A signature that is not 64 bytes, or has `r` or `s`
outside `[1, n − 1]`, is invalid. Low-S normalization is neither applied nor
required. Nonces follow RFC 6979, so signing does not depend on a runtime random
number generator, and the implementation matches the RFC 6979 P-256 test vectors.
Key generation and the RSA-PSS salt use the operating system CSPRNG via OpenSSL.

## Local usage

```sh
uv sync --locked
uv run zhongli --help
uv run zhongli verify --file tests/fixtures/ecdsa/demo.bin \
  --bundle tests/fixtures/ecdsa/bundle.json --trust-store tests/fixtures/ecdsa/trust.json \
  --package demo --version 1.0 --json
```

`python -m zhongli` is equivalent to the `zhongli` script. The
program is developed and tested on Linux and also runs on Windows; key file
permissions (mode 0600) only apply on POSIX systems.

## Tests and evidence

```sh
uv run pytest -q                                            # unit, CLI and scenario tests
uv run python tests/scenarios.py --out <new-directory>      # U01-U14 and interoperability evidence
uv run python tests/sbom_scenarios.py --out <new-directory> # signed SBOM scenarios S01-S08
uv run python benchmarks/run.py --out <new-directory>       # performance measurements
```

- `tests/` covers each adapter (including RFC 8032 and RFC 6979 known-answer
  tests and OpenSSL interoperability in both directions), strict formats, trust
  store updates, key generation, signing, the verifier's check order and the
  CLI contract.
- `tests/scenarios.py` runs U01–U14 for all three profiles through the CLI, plus
  interoperability with the OpenSSL CLI (OpenSSL verifies our bundles and we
  verify signatures produced by OpenSSL). `evidence/scenarios/` holds the last
  run: inputs, outputs, commands, expected and actual results for each case.
- `tests/sbom_scenarios.py` runs the signed SBOM cases for all three profiles:
  valid release, SBOM content changed, artifact byte changed, artifact replaced
  and re-signed with the old SBOM kept, SBOM of another artifact, SBOM signed by
  an untrusted key, a signed file that is not an SBOM, and a missing SBOM.
  `evidence/sbom/` holds the last run.
- `benchmarks/run.py` measures key generation, artifact hashing, crypto sign and
  verify on the manifest, and end-to-end `sign`/`verify` for 1 KiB, 1 MiB and
  10 MiB artifacts (5 warm-up runs, 30 samples, monotonic `perf_counter_ns`,
  nearest-rank P95 at `ceil(0.95 n)`). Each end-to-end sample starts a fresh
  `python -m zhongli` process and includes CLI argument parsing, interpreter
  start-up and stdout written to a file (`verify --json`); container start-up
  is excluded. `evidence/benchmarks/all-profiles/` has
  raw CSV, environment metadata and `summary.md` for all three profiles on one
  machine. End-to-end RSA signing includes interpreter start-up and the validation
  OpenSSL runs when loading a 3072-bit private key, in addition to the signature itself.

Key pairs in `tests/fixtures/` and `evidence/` are named `TEST_ONLY` and exist
only for tests. Never use them for real releases.
