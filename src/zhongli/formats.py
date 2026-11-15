"""Strict JSON and canonical wire formats shared by sign, verify and trust."""

import base64
import binascii
import json
import re
from typing import Any

MANIFEST_LIMIT = 16 * 1024
BUNDLE_LIMIT = 64 * 1024
MAX_ARTIFACT_SIZE = 2**53 - 1
PACKAGE_PATTERN = r"[a-z0-9][a-z0-9._-]{0,63}"
VERSION_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}"
NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
HEX_PATTERN = r"[0-9a-f]{64}"


class FormatError(ValueError):
    """Invalid structure, encoding, schema or canonical serialization."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise FormatError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise FormatError(f"Invalid JSON constant: {value}")


def parse_json_strict(raw_bytes: bytes) -> Any:
    """Decode UTF-8 JSON, rejecting duplicate field names, ``NaN``/``Infinity`` and trailing data.

    Raises:
        FormatError: the bytes are not strict JSON.
    """
    try:
        return json.loads(
            raw_bytes.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise FormatError(f"Invalid JSON: {exc}") from exc


def _fields(value: Any, names: tuple[str, ...]) -> None:
    if type(value) is not dict or set(value) != set(names):
        raise FormatError(f"Expected exactly these fields: {', '.join(names)}")


def _string(value: Any, pattern: str, field: str) -> None:
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise FormatError(f"Invalid {field}")


def validate_manifest(manifest: dict) -> None:
    """Check fields, types and patterns of a ``minisign-manifest/v1`` object.

    Raises:
        FormatError: a field is missing, extra, of the wrong type or out of range.
    """
    _fields(manifest, ("schema", "package", "version", "algorithm", "keyid", "artifact"))
    if manifest["schema"] != "minisign-manifest/v1":
        raise FormatError("Unknown manifest schema")
    _string(manifest["package"], PACKAGE_PATTERN, "package")
    _string(manifest["version"], VERSION_PATTERN, "version")
    # Unknown profiles reach the verifier's UNSUPPORTED_ALGORITHM stage. Only
    # printable ASCII that needs no JSON escape is a well-formed value.
    _string(manifest["algorithm"], r'[\x20-\x7e]*', "algorithm")
    if '"' in manifest["algorithm"] or "\\" in manifest["algorithm"]:
        raise FormatError("Invalid algorithm")
    _string(manifest["keyid"], HEX_PATTERN, "keyid")
    artifact = manifest["artifact"]
    _fields(artifact, ("name", "size", "sha256"))
    _string(artifact["name"], NAME_PATTERN, "artifact.name")
    if type(artifact["size"]) is not int or not 0 <= artifact["size"] <= MAX_ARTIFACT_SIZE:
        raise FormatError("Invalid artifact.size")
    _string(artifact["sha256"], HEX_PATTERN, "artifact.sha256")


def serialize_manifest(manifest: dict) -> bytes:
    """Return the canonical manifest bytes, which are the bytes that get signed.

    UTF-8 without BOM, no whitespace, no escapes for non-ASCII, no trailing
    newline, fields in the order ``schema, package, version, algorithm, keyid,
    artifact`` and ``artifact`` as ``name, size, sha256``.

    Example:
        >>> serialize_manifest({"schema": "minisign-manifest/v1", "package": "demo", "version": "1.0",
        ...     "algorithm": "ed25519", "keyid": "ab" * 32,
        ...     "artifact": {"name": "demo.bin", "size": 3, "sha256": "cd" * 32}})[:44]
        b'{"schema":"minisign-manifest/v1","package":'

    Raises:
        FormatError: the manifest is invalid or larger than 16 KiB.
    """
    validate_manifest(manifest)
    ordered = {key: manifest[key] for key in (
        "schema", "package", "version", "algorithm", "keyid", "artifact"
    )}
    ordered["artifact"] = {key: manifest["artifact"][key] for key in ("name", "size", "sha256")}
    raw = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MANIFEST_LIMIT:
        raise FormatError("Manifest exceeds 16 KiB")
    return raw


def build_manifest(package: str, version: str, profile: str, keyid: str, artifact_info) -> dict:
    """Build and validate a manifest from release metadata and an `zhongli.artifact.ArtifactInfo`."""
    manifest = {
        "schema": "minisign-manifest/v1", "package": package, "version": version,
        "algorithm": profile, "keyid": keyid,
        "artifact": {"name": artifact_info.name, "size": artifact_info.size,
                     "sha256": artifact_info.sha256},
    }
    serialize_manifest(manifest)
    return manifest


def parse_manifest_strict(manifest_bytes: bytes) -> dict:
    """Parse manifest bytes and require that they are already canonical.

    The parsed manifest is re-serialized with `serialize_manifest`; any byte
    difference (whitespace, field order, escapes) is rejected.

    Raises:
        FormatError: invalid JSON, invalid manifest, or non-canonical bytes.
    """
    if len(manifest_bytes) > MANIFEST_LIMIT:
        raise FormatError("Manifest exceeds 16 KiB")
    manifest = parse_json_strict(manifest_bytes)
    if serialize_manifest(manifest) != manifest_bytes:
        raise FormatError("Manifest is not canonically serialized")
    return manifest


def _decode_base64(value: Any) -> bytes:
    if type(value) is not str:
        raise FormatError("Base64 value must be a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise FormatError("Invalid Base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise FormatError("Noncanonical Base64")
    return decoded


def encode_bundle(manifest_bytes: bytes, signature_bytes: bytes) -> bytes:
    """Encode a ``minisign-bundle/v1`` JSON object with canonical Base64 values.

    Raises:
        FormatError: the manifest is not canonical or the bundle exceeds 64 KiB.
    """
    parse_manifest_strict(manifest_bytes)
    raw = json.dumps({
        "schema": "minisign-bundle/v1",
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature_bytes).decode("ascii"),
    }, separators=(",", ":")).encode("utf-8")
    if len(raw) > BUNDLE_LIMIT:
        raise FormatError("Bundle exceeds 64 KiB")
    return raw


def parse_bundle_strict(bundle_bytes: bytes) -> tuple[bytes, bytes]:
    """Parse a bundle and return ``(manifest_bytes, signature_bytes)``.

    Field order and whitespace of the bundle are free. Both Base64 values must
    be canonical (padding, no whitespace) and the decoded manifest must be
    canonical. The signature length is not checked here; a wrong length is an
    invalid signature, not a format error.

    Raises:
        FormatError: the bundle or the manifest inside it is invalid.
    """
    if len(bundle_bytes) > BUNDLE_LIMIT:
        raise FormatError("Bundle exceeds 64 KiB")
    bundle = parse_json_strict(bundle_bytes)
    _fields(bundle, ("schema", "manifest_b64", "signature_b64"))
    if bundle["schema"] != "minisign-bundle/v1":
        raise FormatError("Unknown bundle schema")
    manifest = _decode_base64(bundle["manifest_b64"])
    signature = _decode_base64(bundle["signature_b64"])
    parse_manifest_strict(manifest)
    # Signature lengths belong to INVALID_SIGNATURE, not format validation.
    return manifest, signature
