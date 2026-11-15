import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, rsa as backend_rsa

from zhongli import keys
from zhongli.crypto import ecdsa, ed25519, rsa


@pytest.fixture(scope="module")
def pairs():
    return {"ed25519": ed25519.generate_keypair(), "rsa-pss-sha256": rsa.generate_keypair(),
            "ecdsa-p256-sha256": ecdsa.generate_keypair()}


@pytest.mark.parametrize("profile", keys.PROFILES)
def test_dispatch_roundtrip(pairs, profile):
    pair = pairs[profile]
    adapter = keys.adapter_for_profile(profile)
    private_pem = adapter.export_private_pkcs8_pem(pair.private_key)
    public_pem = adapter.export_public_spki_pem(pair.public_key)
    assert keys.detect_private_profile(private_pem) == profile
    assert keys.detect_public_profile(public_pem) == profile
    private = keys.load_private_key(private_pem)
    public = keys.load_public_key_for_profile(public_pem, profile)
    assert keys.profile_of(private) == profile
    assert keys.fingerprint(public) == adapter.fingerprint(pair.public_key)
    assert keys.fingerprint(keys.public_from_private(private)) == keys.fingerprint(public)
    assert keys.export_public_spki_pem(public) == public_pem
    signature = keys.sign_bytes(private, b"manifest")
    assert keys.verify_bytes(public, b"manifest", signature)
    assert not keys.verify_bytes(public, b"other", signature)


@pytest.mark.parametrize("profile", keys.PROFILES)
def test_generate_keypair(profile):
    pair = keys.generate_keypair(profile)
    assert keys.profile_of(pair.private_key) == profile


def test_profile_mismatch_and_unknown(pairs):
    public_pem = ed25519.export_public_spki_pem(pairs["ed25519"].public_key)
    with pytest.raises(keys.KeyValidationError):
        keys.load_public_key_for_profile(public_pem, "rsa-pss-sha256")
    with pytest.raises(keys.UnsupportedProfileError):
        keys.adapter_for_profile("ed448")
    with pytest.raises(keys.UnsupportedProfileError):
        keys.generate_keypair("rsa-pkcs1v15-sha256")


def test_reject_unsupported_key_types():
    for key in (ed448.Ed448PrivateKey.generate(),):
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        with pytest.raises(keys.KeyValidationError):
            keys.load_private_key(pem)
    with pytest.raises(keys.KeyValidationError):
        keys.load_public_key(b"not a pem")


def test_rsa_parameters_still_enforced():
    key = backend_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with pytest.raises(ValueError):
        keys.load_private_key(pem)


def test_ecdsa_keys_route_to_ecdsa_profile():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    assert keys.detect_private_profile(pem) == "ecdsa-p256-sha256"
    assert keys.profile_of(keys.load_private_key(pem)) == "ecdsa-p256-sha256"


def test_ecdsa_curve_still_enforced():
    key = ec.generate_private_key(ec.SECP384R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with pytest.raises(ValueError):
        keys.load_private_key(pem)
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError):
        keys.load_public_key_for_profile(public, "ecdsa-p256-sha256")
