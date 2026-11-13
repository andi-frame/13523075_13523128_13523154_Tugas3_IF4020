"""Dispatch key operations to the algorithm adapter matching the key or profile.

This module satisfies the same adapter contract as ``crypto.rsa`` and
``crypto.ed25519`` (it can be passed to ``signing.sign``), but selects the
concrete adapter from the key type. Validation of type, parameters and
encoding is always delegated to the owning adapter.
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
_MODULES = {
    "rsa-pss-sha256": "if4020_signing.crypto.rsa",
    "ecdsa-p256-sha256": "if4020_signing.crypto.ecdsa",
    "ed25519": "if4020_signing.crypto.ed25519",
}


class KeyValidationError(ValueError):
    """The key cannot be mapped to a supported, available profile."""


class UnsupportedProfileError(ValueError):
    """The profile string is not one of the supported profiles."""


def adapter_for_profile(profile: str) -> ModuleType:
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
    try:
        key = serialization.load_der_private_key(_pem_der(pem_bytes, b"PRIVATE KEY"), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid unencrypted PKCS8 private key") from exc
    return _profile_of_backend_key(key)


def detect_public_profile(pem_bytes: bytes) -> str:
    try:
        key = serialization.load_der_public_key(_pem_der(pem_bytes, b"PUBLIC KEY"))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid SPKI public key") from exc
    return _profile_of_backend_key(key)


def generate_keypair(profile: str):
    return adapter_for_profile(profile).generate_keypair(profile)


def load_private_key(pem_bytes: bytes):
    """Load a private key; the profile is derived from the key itself."""
    return adapter_for_profile(detect_private_profile(pem_bytes)).load_private_key(pem_bytes)


def load_public_key(pem_bytes: bytes):
    return adapter_for_profile(detect_public_profile(pem_bytes)).load_public_key(pem_bytes)


def load_public_key_for_profile(pem_bytes: bytes, profile: str):
    """Load a public key that must belong to ``profile`` (used by the trust store)."""
    adapter = adapter_for_profile(profile)
    actual = detect_public_profile(pem_bytes)
    if actual != profile:
        raise KeyValidationError(f"Key type {actual} does not match profile {profile}")
    return adapter.load_public_key(pem_bytes)


def export_private_pkcs8_pem(private_key) -> bytes:
    return _adapter_for_key(private_key).export_private_pkcs8_pem(private_key)


def export_private_pkcs8_der(private_key) -> bytes:
    return _adapter_for_key(private_key).export_private_pkcs8_der(private_key)


def export_public_spki_pem(public_key) -> bytes:
    return _adapter_for_key(public_key).export_public_spki_pem(public_key)


def export_public_spki_der(public_key) -> bytes:
    return _adapter_for_key(public_key).export_public_spki_der(public_key)


def public_from_private(private_key):
    return _adapter_for_key(private_key).public_from_private(private_key)


def profile_of(validated_key) -> str:
    return _adapter_for_key(validated_key).profile_of(validated_key)


def fingerprint(public_key) -> str:
    return hashlib.sha256(export_public_spki_der(public_key)).hexdigest()


def sign_bytes(private_key, manifest_bytes: bytes) -> bytes:
    return _adapter_for_key(private_key).sign_bytes(private_key, manifest_bytes)


def verify_bytes(public_key, manifest_bytes: bytes, signature_bytes: bytes) -> bool:
    return _adapter_for_key(public_key).verify_bytes(public_key, manifest_bytes, signature_bytes)
