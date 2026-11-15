"""Route key operations to the adapter for the key type or profile.

This module is the entry point for key handling. It implements the same
adapter contract as the modules in `zhongli.crypto`, so it can be passed to
`zhongli.signing.sign` as ``adapter``. It never validates keys itself: it only
decides which adapter owns a key or profile, and that adapter validates it.

Example:
    >>> from zhongli import keys
    >>> pair = keys.generate_keypair("ed25519")
    >>> pem = keys.export_public_spki_pem(pair.public_key)
    >>> keys.detect_public_profile(pem)
    'ed25519'
    >>> len(keys.fingerprint(pair.public_key))
    64
"""

import base64
import hashlib
import importlib
from types import ModuleType
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519 as backend_ed25519, rsa as backend_rsa

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")
"""The three supported profile names, in the order used throughout the program."""
_MODULES = {
    "rsa-pss-sha256": "zhongli.crypto.rsa",
    "ecdsa-p256-sha256": "zhongli.crypto.ecdsa",
    "ed25519": "zhongli.crypto.ed25519",
}


class KeyValidationError(ValueError):
    """The key cannot be mapped to a supported, available profile."""


class UnsupportedProfileError(ValueError):
    """The profile string is not one of the supported profiles."""


def adapter_for_profile(profile: str) -> ModuleType:
    """Return the adapter module for ``profile``, for example `zhongli.crypto.ecdsa`.

    Raises:
        UnsupportedProfileError: ``profile`` is not in `PROFILES`.
        KeyValidationError: the adapter module is missing from this build.
    """
    if profile not in _MODULES:
        raise UnsupportedProfileError(f"Unsupported algorithm profile: {profile!r}")
    try:
        return importlib.import_module(_MODULES[profile])
    except ModuleNotFoundError as exc:
        if exc.name != _MODULES[profile]:
            raise
        raise KeyValidationError(f"Profile {profile} is not available in this build") from exc


def _profile_of_backend_key(key: Any) -> str:
    if isinstance(key, (backend_rsa.RSAPrivateKey, backend_rsa.RSAPublicKey)):
        return "rsa-pss-sha256"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "ecdsa-p256-sha256"
    if isinstance(key, (backend_ed25519.Ed25519PrivateKey, backend_ed25519.Ed25519PublicKey)):
        return "ed25519"
    raise KeyValidationError("Unsupported key type")


def _adapter_for_key(key: Any) -> ModuleType:
    return adapter_for_profile(_profile_of_backend_key(key))


def _pem_der(pem_bytes: bytes, label: bytes) -> bytes:
    lines = pem_bytes.strip().splitlines()
    if len(lines) < 3 or lines[0].strip() != b"-----BEGIN " + label + b"-----" \
            or lines[-1].strip() != b"-----END " + label + b"-----":
        raise KeyValidationError("Expected a single " + label.decode() + " PEM block")
    try:
        return base64.b64decode(b"".join(line.strip() for line in lines[1:-1]), validate=True)
    except ValueError as exc:
        raise KeyValidationError("Invalid PEM encoding") from exc


def detect_private_profile(pem_bytes: bytes) -> str:
    """Return the profile of an unencrypted PKCS#8 ``PRIVATE KEY`` PEM.

    Only the key type is inspected; parameters are checked by the adapter
    when the key is loaded.

    Raises:
        KeyValidationError: not a single unencrypted PKCS#8 PEM block of a supported type.
    """
    try:
        key = serialization.load_der_private_key(_pem_der(pem_bytes, b"PRIVATE KEY"), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid unencrypted PKCS8 private key") from exc
    return _profile_of_backend_key(key)


def detect_public_profile(pem_bytes: bytes) -> str:
    """Return the profile of a SubjectPublicKeyInfo ``PUBLIC KEY`` PEM.

    Raises:
        KeyValidationError: not a single SPKI PEM block of a supported key type.
    """
    try:
        key = serialization.load_der_public_key(_pem_der(pem_bytes, b"PUBLIC KEY"))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid SPKI public key") from exc
    return _profile_of_backend_key(key)


def generate_keypair(profile: str):
    """Generate a new key pair for ``profile`` with the operating system CSPRNG.

    Returns:
        An object with ``private_key`` and ``public_key`` attributes holding
        PyCA cryptography key objects.
    """
    return adapter_for_profile(profile).generate_keypair(profile)


def load_private_key(pem_bytes: bytes):
    """Load and validate a PKCS#8 private key; the profile is derived from the key.

    Raises:
        KeyValidationError: unsupported type, or parameters that violate the profile
            (for example an RSA key that is not 3072 bits).
    """
    return adapter_for_profile(detect_private_profile(pem_bytes)).load_private_key(pem_bytes)


def load_public_key(pem_bytes: bytes):
    """Load and validate an SPKI public key; the profile is derived from the key."""
    return adapter_for_profile(detect_public_profile(pem_bytes)).load_public_key(pem_bytes)


def load_public_key_for_profile(pem_bytes: bytes, profile: str):
    """Load an SPKI public key and require that it belongs to ``profile``.

    Raises:
        KeyValidationError: the key type differs from ``profile`` or the key is invalid.
    """
    adapter = adapter_for_profile(profile)
    actual = detect_public_profile(pem_bytes)
    if actual != profile:
        raise KeyValidationError(f"Key type {actual} does not match profile {profile}")
    return adapter.load_public_key(pem_bytes)


def export_private_pkcs8_pem(private_key) -> bytes:
    """Encode a private key as unencrypted PKCS#8 PEM (``-----BEGIN PRIVATE KEY-----``)."""
    return _adapter_for_key(private_key).export_private_pkcs8_pem(private_key)


def export_private_pkcs8_der(private_key) -> bytes:
    """Encode a private key as unencrypted PKCS#8 DER (used for size measurements)."""
    return _adapter_for_key(private_key).export_private_pkcs8_der(private_key)


def export_public_spki_pem(public_key) -> bytes:
    """Encode a public key as SubjectPublicKeyInfo PEM (``-----BEGIN PUBLIC KEY-----``)."""
    return _adapter_for_key(public_key).export_public_spki_pem(public_key)


def export_public_spki_der(public_key) -> bytes:
    """Encode a public key as canonical SubjectPublicKeyInfo DER."""
    return _adapter_for_key(public_key).export_public_spki_der(public_key)


def public_from_private(private_key):
    """Return the public key that belongs to ``private_key``."""
    return _adapter_for_key(private_key).public_from_private(private_key)


def profile_of(validated_key) -> str:
    """Return the profile name of a private or public key object."""
    return _adapter_for_key(validated_key).profile_of(validated_key)


def fingerprint(public_key) -> str:
    """Return the keyid: ``hex_lower(SHA256(DER_SPKI))`` of the re-exported public key.

    Because the key is re-exported first, PEM line wrapping and line endings
    of the original file do not change the keyid.
    """
    return hashlib.sha256(export_public_spki_der(public_key)).hexdigest()


def sign_bytes(private_key, manifest_bytes: bytes) -> bytes:
    """Sign ``manifest_bytes`` with the profile of ``private_key``.

    Returns:
        The raw signature: 384 bytes for RSA-PSS, 64 bytes ``r || s`` for
        ECDSA, 64 bytes for Ed25519.
    """
    return _adapter_for_key(private_key).sign_bytes(private_key, manifest_bytes)


def verify_bytes(public_key, manifest_bytes: bytes, signature_bytes: bytes) -> bool:
    """Return whether ``signature_bytes`` is valid for ``manifest_bytes``.

    Never raises for a wrong signature, a wrong length or an invalid encoding;
    those all return ``False``.
    """
    return _adapter_for_key(public_key).verify_bytes(public_key, manifest_bytes, signature_bytes)
