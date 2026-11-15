"""ECDSA over NIST P-256 with SHA-256 and raw ``r || s`` signatures.

Nonces are derived deterministically as specified by RFC 6979, so signing does
not depend on the quality of a runtime random number generator. Key generation
still uses the OS CSPRNG.
"""

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)

PROFILE = "ecdsa-p256-sha256"
SIGNATURE_SIZE = 64
SCALAR_SIZE = 32
# Order of the P-256 base point (FIPS 186-5, SEC 2).
CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class KeyValidationError(ValueError):
    """Key type, encoding or parameters do not satisfy the ECDSA profile."""


@dataclass(frozen=True)
class KeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey


def _check_curve(key) -> None:
    if not isinstance(key.curve, ec.SECP256R1):
        raise KeyValidationError(f"ECDSA requires curve P-256, got {key.curve.name}")


def _public(key) -> ec.EllipticCurvePublicKey:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise KeyValidationError("Expected an EC key")
    _check_curve(key)
    return key


def _private(key) -> ec.EllipticCurvePrivateKey:
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise KeyValidationError("Expected an EC private key")
    _check_curve(key)
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
        raise KeyValidationError("Unsupported ECDSA profile")
    private = ec.generate_private_key(ec.SECP256R1())
    return KeyPair(private, private.public_key())


def load_private_key(pem_bytes: bytes) -> ec.EllipticCurvePrivateKey:
    der = _pem_der(pem_bytes, b"PRIVATE KEY")
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid unencrypted PKCS8 private key") from exc
    return _private(key)


def load_public_key(pem_bytes: bytes) -> ec.EllipticCurvePublicKey:
    der = _pem_der(pem_bytes, b"PUBLIC KEY")
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise KeyValidationError("Invalid SPKI public key") from exc
    key = _public(key)
    # The re-export uses the named-curve OID and an uncompressed SEC1 point, so
    # compressed points and explicit curve parameters fail this comparison.
    if der != export_public_spki_der(key):
        raise KeyValidationError("Expected canonical SPKI with named curve P-256 and an uncompressed point")
    return key


def export_private_pkcs8_pem(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return _private(private_key).private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def export_private_pkcs8_der(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return _private(private_key).private_bytes(serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def export_public_spki_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return _public(public_key).public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def export_public_spki_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return _public(public_key).public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def public_from_private(private_key: ec.EllipticCurvePrivateKey) -> ec.EllipticCurvePublicKey:
    return _private(private_key).public_key()


def profile_of(validated_key) -> str:
    _public(validated_key)
    return PROFILE


def fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    return hashlib.sha256(export_public_spki_der(public_key)).hexdigest()


def der_to_raw(der_signature: bytes) -> bytes:
    """Convert an ASN.1 DER ``Ecdsa-Sig-Value`` to ``r || s`` (32 bytes each)."""
    r, s = decode_dss_signature(der_signature)
    if not (0 < r < CURVE_ORDER and 0 < s < CURVE_ORDER):
        raise ValueError("ECDSA signature component out of range")
    return r.to_bytes(SCALAR_SIZE, "big") + s.to_bytes(SCALAR_SIZE, "big")


def raw_to_der(raw_signature: bytes) -> bytes:
    """Convert ``r || s`` to DER. Range checks are the caller's responsibility."""
    if len(raw_signature) != SIGNATURE_SIZE:
        raise ValueError("ECDSA raw signature must be 64 bytes")
    r = int.from_bytes(raw_signature[:SCALAR_SIZE], "big")
    s = int.from_bytes(raw_signature[SCALAR_SIZE:], "big")
    return encode_dss_signature(r, s)


def sign_bytes(private_key: ec.EllipticCurvePrivateKey, manifest_bytes: bytes) -> bytes:
    # The library hashes the message with SHA-256 exactly once; passing the raw
    # manifest (not a digest) avoids double hashing.
    algorithm = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    return der_to_raw(_private(private_key).sign(manifest_bytes, algorithm))


def verify_bytes(public_key: ec.EllipticCurvePublicKey, manifest_bytes: bytes, signature_bytes: bytes) -> bool:
    key = _public(public_key)
    if len(signature_bytes) != SIGNATURE_SIZE:
        return False
    r = int.from_bytes(signature_bytes[:SCALAR_SIZE], "big")
    s = int.from_bytes(signature_bytes[SCALAR_SIZE:], "big")
    if not (0 < r < CURVE_ORDER and 0 < s < CURVE_ORDER):
        return False
    try:
        key.verify(encode_dss_signature(r, s), manifest_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True
