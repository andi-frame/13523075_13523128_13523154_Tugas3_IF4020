"""Verify a release bundle against an artifact and a user-managed trust store.

Checks run in a fixed order and stop at the first failure:

1. INPUT_ERROR: invalid options, or an input that cannot be read
2. FORMAT_ERROR: bundle, manifest or trust store violates its format
3. UNSUPPORTED_ALGORITHM: the manifest names an unknown profile
4. KEY_NOT_TRUSTED: keyid absent, profile differs, or package not allowed
5. INVALID_SIGNATURE: the signature over the stored manifest bytes is invalid
6. METADATA_MISMATCH: package, version or artifact basename differ
7. ARTIFACT_MISMATCH: artifact size or SHA-256 differ

No other key, profile or trust store is tried after a failure, and the trust
store is never modified.
"""

from dataclasses import dataclass
import enum
import os
from pathlib import Path
import re
from typing import Any

from . import keys
from .artifact import digest_stream
from .formats import (
    BUNDLE_LIMIT, PACKAGE_PATTERN, VERSION_PATTERN, FormatError,
    parse_bundle_strict, parse_manifest_strict,
)
from .trust import KeyNotTrustedError, find_authorized_key, parse_trust_store_strict


class Status(enum.StrEnum):
    """Verification status; `exit_code` is 0 for OK, 2 for INPUT_ERROR and 1 otherwise."""

    OK = "OK"
    INPUT_ERROR = "INPUT_ERROR"
    FORMAT_ERROR = "FORMAT_ERROR"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    METADATA_MISMATCH = "METADATA_MISMATCH"
    ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"

    @property
    def exit_code(self) -> int:
        if self is Status.OK:
            return 0
        return 2 if self is Status.INPUT_ERROR else 1


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of ``verify``.

    Metadata fields hold what was read from the manifest, or None if it could not
    be read yet. For any status other than OK they are diagnostic only and must
    not be treated as authentic.
    """

    status: Status
    message: str
    algorithm: str | None = None
    keyid: str | None = None
    package: str | None = None
    version: str | None = None

    @property
    def valid(self) -> bool:
        return self.status is Status.OK

    @property
    def exit_code(self) -> int:
        return self.status.exit_code

    def to_json(self) -> dict[str, Any]:
        """The object printed by ``verify --json``, with fields in the order of the specification."""
        return {
            "valid": self.valid, "status": str(self.status), "message": self.message,
            "algorithm": self.algorithm, "keyid": self.keyid,
            "package": self.package, "version": self.version,
        }


def _read_limited(path: Path, limit: int) -> bytes:
    # One byte past the limit is enough for the parser to report the size error
    # without reading an arbitrarily large file into memory.
    with path.open("rb") as stream:
        return stream.read(limit + 1)


def _describe(exc: OSError) -> str:
    if exc.filename is not None and exc.strerror:
        return f"Cannot read {os.fsdecode(exc.filename)}: {exc.strerror}"
    return f"Input/output error: {exc}"


def verify(
    artifact_path: str | os.PathLike, bundle_path: str | os.PathLike,
    trust_store_path: str | os.PathLike, expected_package: str, expected_version: str,
) -> VerificationResult:
    """Verify ``artifact_path`` against ``bundle_path`` using ``trust_store_path``.

    Args:
        artifact_path: The release artifact. Its basename must equal
            ``artifact.name`` in the signed manifest.
        bundle_path: A ``minisign-bundle/v1`` JSON file produced by ``sign``.
        trust_store_path: A ``minisign-trust/v1`` JSON file. It is read only.
        expected_package: The package the caller expects, for example ``"contoh-app"``.
        expected_version: The version the caller expects, for example ``"1.0.0"``.

    Returns:
        A `VerificationResult`. It never raises for invalid or unreadable
        inputs; those become ``INPUT_ERROR`` or ``FORMAT_ERROR``.

    Example:
        >>> result = verify("dist/contoh-app.zip", "release.json", "trust.json",
        ...                 "contoh-app", "1.0.0")
        >>> result.status, result.exit_code
        (<Status.OK: 'OK'>, 0)
    """
    return verify_with_manifest(artifact_path, bundle_path, trust_store_path,
                                expected_package, expected_version)[0]


def verify_with_manifest(
    artifact_path: str | os.PathLike, bundle_path: str | os.PathLike,
    trust_store_path: str | os.PathLike, expected_package: str, expected_version: str,
) -> tuple[VerificationResult, dict | None]:
    """Like `verify`, but also return the manifest that was verified.

    The manifest is returned only when the status is OK. It is then
    authentic: its signature was checked over the exact bytes it was parsed
    from, and the artifact matched it. Callers that bind further data to the
    release (the signed SBOM) use these values instead of reading the bundle
    a second time.
    """
    metadata: dict[str, str] = {}
    verified: dict | None = None

    def result(status: Status, message: str) -> tuple[VerificationResult, dict | None]:
        return VerificationResult(status, message, **metadata), verified if status is Status.OK else None

    for name, value, pattern in (("package", expected_package, PACKAGE_PATTERN),
                                 ("version", expected_version, VERSION_PATTERN)):
        if type(value) is not str or re.fullmatch(pattern, value) is None:
            return result(Status.INPUT_ERROR, f"Invalid expected {name}: {value!r}")

    artifact_path, bundle_path, trust_store_path = map(Path, (artifact_path, bundle_path, trust_store_path))
    try:
        bundle_bytes = _read_limited(bundle_path, BUNDLE_LIMIT)
        trust_bytes = trust_store_path.read_bytes()
        # The artifact stays open so that step 7 hashes the same file that was
        # checked for readability here.
        with artifact_path.open("rb") as artifact:
            try:
                manifest_bytes, signature = parse_bundle_strict(bundle_bytes)
                manifest = parse_manifest_strict(manifest_bytes)
                metadata.update((name, manifest[name]) for name in ("algorithm", "keyid", "package", "version"))
                store = parse_trust_store_strict(trust_bytes)
            except FormatError as exc:
                return result(Status.FORMAT_ERROR, str(exc))

            algorithm = manifest["algorithm"]
            if algorithm not in keys.PROFILES:
                return result(Status.UNSUPPORTED_ALGORITHM, f"Unsupported algorithm profile: {algorithm!r}")

            try:
                public_key = find_authorized_key(store, manifest["keyid"], algorithm, expected_package)
            except KeyNotTrustedError as exc:
                return result(Status.KEY_NOT_TRUSTED, str(exc))

            # Verified over the bytes stored in the bundle, never a re-serialization.
            if not keys.adapter_for_profile(algorithm).verify_bytes(public_key, manifest_bytes, signature):
                return result(Status.INVALID_SIGNATURE, f"Signature is not valid for {algorithm} key {manifest['keyid']}")

            for field, expected, actual in (
                ("package", expected_package, manifest["package"]),
                ("version", expected_version, manifest["version"]),
                ("artifact name", artifact_path.name, manifest["artifact"]["name"]),
            ):
                if expected != actual:
                    return result(Status.METADATA_MISMATCH,
                                  f"Manifest {field} {actual!r} does not match expected {expected!r}")

            try:
                size, sha256 = digest_stream(artifact)
            except FormatError as exc:
                return result(Status.ARTIFACT_MISMATCH, str(exc))
            if size != manifest["artifact"]["size"]:
                return result(Status.ARTIFACT_MISMATCH,
                              f"Artifact size {size} does not match manifest size {manifest['artifact']['size']}")
            if sha256 != manifest["artifact"]["sha256"]:
                return result(Status.ARTIFACT_MISMATCH, "Artifact SHA-256 does not match the manifest")
            verified = manifest
    except OSError as exc:
        return result(Status.INPUT_ERROR, _describe(exc))

    return result(Status.OK, "Signature and artifact are valid.")
