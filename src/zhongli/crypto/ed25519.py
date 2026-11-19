"""Pure Ed25519 (RFC 8032, no pre-hash or context) with RFC 8410 keys."""

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ._pkcs8 import validate_pkcs8

PROFILE = "ed25519"
SIGNATURE_SIZE = 64
# SPKI prefix: id-Ed25519 (1.3.101.112) without parameters, then a 32-byte key.
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class KeyValidationError(ValueError):
    """Key type, encoding or parameters do not satisfy the Ed25519 profile."""


@dataclass(frozen=True)
class KeyPair:
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey


def _public(key) -> ed25519.Ed25519PublicKey:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        key = key.public_key()
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise KeyValidationError("Expected an Ed25519 key")
    return key


def _private(key) -> ed25519.Ed25519PrivateKey:
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise KeyValidationError("Expected an Ed25519 private key")
    return key


def _pem_der(pem: bytes, label: bytes) -> bytes:
    lines = pem.strip().splitlines()
    if len(lines) < 3 or lines[0] != b"-----BEGIN " + label + b"-----" or lines[-1] != b"-----END " + label + b"-----":
        raise KeyValidationError("Expected a single " + label.decode() + " PEM block")
    try:
        return base64.b64decode(b"".join(line.strip() for line in lines[1:-1]), validate=True)
    except ValueError as exc:
        raise KeyValidationError("Invalid PEM encoding") from exc


def generate_keypair(profile: str = PROFILE) -> KeyPair:
    if profile != PROFILE:
        raise KeyValidationError("Unsupported Ed25519 profile")
    # Seed comes from the OS CSPRNG.
    private = ed25519.Ed25519PrivateKey.generate()
    return KeyPair(private, private.public_key())


def load_private_key(pem_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    der = _pem_der(pem_bytes, b"PRIVATE KEY")
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid unencrypted PKCS8 private key") from exc
    key = _private(key)
    try:
        validate_pkcs8(der, export_private_pkcs8_der(key))
    except ValueError as exc:
        raise KeyValidationError(f"Invalid PKCS8 envelope: {exc}") from exc
    return key


def load_public_key(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
    der = _pem_der(pem_bytes, b"PUBLIC KEY")
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid SPKI public key") from exc
    key = _public(key)
    if der != export_public_spki_der(key) or not der.startswith(_SPKI_PREFIX):
        raise KeyValidationError("Expected canonical RFC 8410 Ed25519 SPKI encoding")
    return key


def export_private_pkcs8_pem(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return _private(private_key).private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def export_private_pkcs8_der(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return _private(private_key).private_bytes(serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def export_public_spki_pem(public_key: ed25519.Ed25519PublicKey) -> bytes:
    return _public(public_key).public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def export_public_spki_der(public_key: ed25519.Ed25519PublicKey) -> bytes:
    return _public(public_key).public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def public_from_private(private_key: ed25519.Ed25519PrivateKey) -> ed25519.Ed25519PublicKey:
    return _private(private_key).public_key()


def profile_of(validated_key) -> str:
    _public(validated_key)
    return PROFILE


def fingerprint(public_key: ed25519.Ed25519PublicKey) -> str:
    return hashlib.sha256(export_public_spki_der(public_key)).hexdigest()


def sign_bytes(private_key: ed25519.Ed25519PrivateKey, manifest_bytes: bytes) -> bytes:
    # No external pre-hash; SHA-512 runs inside Ed25519.
    return _private(private_key).sign(manifest_bytes)


def verify_bytes(public_key: ed25519.Ed25519PublicKey, manifest_bytes: bytes, signature_bytes: bytes) -> bool:
    key = _public(public_key)
    if len(signature_bytes) != SIGNATURE_SIZE:
        return False
    try:
        key.verify(signature_bytes, manifest_bytes)
    except InvalidSignature:
        return False
    return True
