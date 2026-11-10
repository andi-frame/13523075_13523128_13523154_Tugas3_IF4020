import hashlib
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa as backend_rsa

from if4020_signing.crypto import rsa


@pytest.fixture(scope="module")
def pair():
    return rsa.generate_keypair()


def test_key_roundtrip_and_fingerprint(pair):
    private = rsa.load_private_key(rsa.export_private_pkcs8_pem(pair.private_key))
    pem = rsa.export_public_spki_pem(pair.public_key)
    public = rsa.load_public_key(pem.replace(b'\n', b'\r\n'))
    assert private.private_numbers() == pair.private_key.private_numbers()
    assert public.public_numbers() == pair.public_key.public_numbers()
    assert rsa.profile_of(private) == rsa.PROFILE
    assert rsa.fingerprint(public) == hashlib.sha256(rsa.export_public_spki_der(public)).hexdigest()
    assert rsa.fingerprint(rsa.public_from_private(private)) == rsa.fingerprint(public)


def test_randomized_pss_u14(pair):
    message = b'original manifest bytes'
    first = rsa.sign_bytes(pair.private_key, message)
    second = rsa.sign_bytes(pair.private_key, message)
    assert len(first) == len(second) == 384
    assert first != second
    assert rsa.verify_bytes(pair.public_key, message, first)
    assert rsa.verify_bytes(pair.public_key, message, second)
    assert not rsa.verify_bytes(pair.public_key, message + b'!', first)
    assert not rsa.verify_bytes(pair.public_key, message, bytes([first[0] ^ 1]) + first[1:])
    assert not rsa.verify_bytes(pair.public_key, message, first[:-1])
    assert not rsa.verify_bytes(pair.public_key, message, first + b'!')


@pytest.mark.parametrize("bits,exponent", [(2048, 65537), (4096, 65537), (3072, 3)])
def test_reject_wrong_parameters(bits, exponent):
    key = backend_rsa.generate_private_key(public_exponent=exponent, key_size=bits)
    with pytest.raises(rsa.KeyValidationError):
        rsa.sign_bytes(key, b'message')
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(rsa.KeyValidationError):
        rsa.load_public_key(pem)


def test_reject_wrong_type_and_pem(pair):
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(rsa.KeyValidationError):
        rsa.verify_bytes(key.public_key(), b'm', b'')
    for pem in (b'invalid', rsa.export_public_spki_pem(pair.public_key),
                pair.private_key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())):
        with pytest.raises(rsa.KeyValidationError):
            rsa.load_private_key(pem)
    public = rsa.export_public_spki_pem(pair.public_key)
    with pytest.raises(rsa.KeyValidationError):
        rsa.load_public_key(public + public)


@pytest.mark.parametrize("salt,mgf", [(0, hashes.SHA256()), (padding.PSS.MAX_LENGTH, hashes.SHA256()), (32, hashes.SHA384())])
def test_reject_wrong_pss_parameters(pair, salt, mgf):
    sig = pair.private_key.sign(b'm', padding.PSS(mgf=padding.MGF1(mgf), salt_length=salt), hashes.SHA256())
    assert not rsa.verify_bytes(pair.public_key, b'm', sig)


def test_openssl_interoperability_both_directions(pair, tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("OpenSSL CLI is required for independent interoperability evidence")
    message = b'canonical manifest bytes\x00\xff'
    (tmp_path / 'message').write_bytes(message)
    (tmp_path / 'private.pem').write_bytes(rsa.export_private_pkcs8_pem(pair.private_key))
    (tmp_path / 'public.pem').write_bytes(rsa.export_public_spki_pem(pair.public_key))
    (tmp_path / 'signature').write_bytes(rsa.sign_bytes(pair.private_key, message))
    options = ['-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32',
               '-sigopt', 'rsa_mgf1_md:sha256']
    verified = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', 'public.pem',
                              '-signature', 'signature', *options, 'message'],
                             cwd=tmp_path, capture_output=True, check=True)
    assert b'Verified OK' in verified.stdout
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', 'private.pem', '-out',
                    'external.sig', *options, 'message'], cwd=tmp_path, capture_output=True, check=True)
    assert rsa.verify_bytes(pair.public_key, message, (tmp_path / 'external.sig').read_bytes())
