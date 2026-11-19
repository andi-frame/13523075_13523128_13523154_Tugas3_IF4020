"""RSA-3072/PSS-SHA256, MGF1-SHA256, 32-byte salt."""

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._pkcs8 import validate_pkcs8

PROFILE = "rsa-pss-sha256"
SIGNATURE_SIZE = 384


class KeyValidationError(ValueError):
    """Key type, encoding or parameters do not satisfy the RSA profile."""


@dataclass(frozen=True)
class KeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey


def _public(key) -> rsa.RSAPublicKey:
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyValidationError("Expected an RSA key")
    if key.key_size != 3072 or key.public_numbers().e != 65537:
        raise KeyValidationError("RSA requires 3072 bits and public exponent 65537")
    return key


def _private(key) -> rsa.RSAPrivateKey:
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyValidationError("Expected an RSA private key")
    _public(key)
    return key


def _pem_der(pem: bytes, label: bytes) -> bytes:
    lines = pem.strip().splitlines()
    if len(lines) < 3 or lines[0] != b"-----BEGIN " + label + b"-----" or lines[-1] != b"-----END " + label + b"-----":
        raise KeyValidationError("Expected a single " + label.decode() + " PEM block")
    try:
        return base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except ValueError as exc:
        raise KeyValidationError("Invalid PEM encoding") from exc


def generate_keypair(profile: str = PROFILE) -> KeyPair:
    if profile != PROFILE:
        raise KeyValidationError("Unsupported RSA profile")
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return KeyPair(private, private.public_key())


def load_private_key(pem_bytes: bytes) -> rsa.RSAPrivateKey:
    der = _pem_der(pem_bytes, b"PRIVATE KEY")
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid unencrypted PKCS8 private key") from exc
    _private(key)
    try:
        validate_pkcs8(der, export_private_pkcs8_der(key))
    except ValueError as exc:
        raise KeyValidationError(f"Invalid PKCS8 envelope: {exc}") from exc
    return key


def load_public_key(pem_bytes: bytes) -> rsa.RSAPublicKey:
    der = _pem_der(pem_bytes, b"PUBLIC KEY")
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid SPKI public key") from exc
    _public(key)
    if der != export_public_spki_der(key):
        raise KeyValidationError("Expected canonical SPKI rsaEncryption encoding")
    return key


def export_private_pkcs8_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return _private(private_key).private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def export_private_pkcs8_der(private_key: rsa.RSAPrivateKey) -> bytes:
    return _private(private_key).private_bytes(serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def export_public_spki_pem(public_key: rsa.RSAPublicKey) -> bytes:
    return _public(public_key).public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def export_public_spki_der(public_key: rsa.RSAPublicKey) -> bytes:
    return _public(public_key).public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def public_from_private(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    return _private(private_key).public_key()


def profile_of(validated_key) -> str:
    _public(validated_key)
    return PROFILE


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    return hashlib.sha256(export_public_spki_der(public_key)).hexdigest()


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def sign_bytes(private_key: rsa.RSAPrivateKey, manifest_bytes: bytes) -> bytes:
    return _private(private_key).sign(manifest_bytes, _pss(), hashes.SHA256())


def verify_bytes(public_key: rsa.RSAPublicKey, manifest_bytes: bytes, signature_bytes: bytes) -> bool:
    key = _public(public_key)
    if len(signature_bytes) != SIGNATURE_SIZE:
        return False
    try:
        key.verify(signature_bytes, manifest_bytes, _pss(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True
