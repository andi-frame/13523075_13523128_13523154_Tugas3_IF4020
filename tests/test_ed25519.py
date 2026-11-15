import base64
import hashlib
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519 as backend_ed25519, rsa as backend_rsa

from zhongli.crypto import ed25519

# RFC 8032 section 7.1, TEST 1 (empty message).
RFC_SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
    "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


@pytest.fixture(scope="module")
def pair():
    return ed25519.generate_keypair()


def _pem(der: bytes, label: str) -> bytes:
    body = base64.b64encode(der).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)).encode()


def test_key_roundtrip_and_fingerprint(pair):
    private = ed25519.load_private_key(ed25519.export_private_pkcs8_pem(pair.private_key))
    pem = ed25519.export_public_spki_pem(pair.public_key)
    public = ed25519.load_public_key(pem.replace(b"\n", b"\r\n"))
    raw = serialization.Encoding.Raw
    assert private.public_key().public_bytes(raw, serialization.PublicFormat.Raw) == \
        pair.public_key.public_bytes(raw, serialization.PublicFormat.Raw)
    der = ed25519.export_public_spki_der(public)
    assert len(der) == 44 and der.startswith(bytes.fromhex("302a300506032b6570032100"))
    assert ed25519.profile_of(private) == ed25519.PROFILE == "ed25519"
    assert ed25519.fingerprint(public) == hashlib.sha256(der).hexdigest()
    assert ed25519.fingerprint(ed25519.public_from_private(private)) == ed25519.fingerprint(public)


def test_rfc8032_test_vector():
    private = backend_ed25519.Ed25519PrivateKey.from_private_bytes(RFC_SECRET)
    public = ed25519.public_from_private(private)
    assert public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == RFC_PUBLIC
    assert ed25519.sign_bytes(private, b"") == RFC_SIGNATURE
    assert ed25519.verify_bytes(public, b"", RFC_SIGNATURE)


def test_deterministic_signature_u14(pair):
    message = b"original manifest bytes"
    first = ed25519.sign_bytes(pair.private_key, message)
    second = ed25519.sign_bytes(pair.private_key, message)
    # RFC 8032 derives the nonce from the private key and message: identical output.
    assert len(first) == 64 and first == second
    assert ed25519.verify_bytes(pair.public_key, message, first)


def test_reject_tampering_and_lengths(pair):
    message = b"manifest"
    sig = ed25519.sign_bytes(pair.private_key, message)
    assert not ed25519.verify_bytes(pair.public_key, message + b"!", sig)
    assert not ed25519.verify_bytes(pair.public_key, message, bytes([sig[0] ^ 1]) + sig[1:])
    assert not ed25519.verify_bytes(pair.public_key, message, sig[:-1])
    assert not ed25519.verify_bytes(pair.public_key, message, sig + b"\x00")
    assert not ed25519.verify_bytes(pair.public_key, message, b"")
    other = ed25519.generate_keypair()
    assert not ed25519.verify_bytes(other.public_key, message, sig)


def test_not_prehashed(pair):
    message = b"manifest"
    sig = ed25519.sign_bytes(pair.private_key, message)
    assert not ed25519.verify_bytes(pair.public_key, hashlib.sha512(message).digest(), sig)


def test_reject_wrong_key_types(pair):
    rsa_key = backend_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ed448_key = ed448.Ed448PrivateKey.generate()
    for key in (rsa_key, ed448_key):
        with pytest.raises(ed25519.KeyValidationError):
            ed25519.sign_bytes(key, b"m")
        pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with pytest.raises(ed25519.KeyValidationError):
            ed25519.load_public_key(pub)
        with pytest.raises(ed25519.KeyValidationError):
            ed25519.load_private_key(priv)


def test_reject_bad_pem(pair):
    public = ed25519.export_public_spki_pem(pair.public_key)
    private = ed25519.export_private_pkcs8_pem(pair.private_key)
    for pem in (b"invalid", public + public, public.replace(b"PUBLIC KEY", b"RSA PUBLIC KEY")):
        with pytest.raises(ed25519.KeyValidationError):
            ed25519.load_public_key(pem)
    for pem in (b"invalid", public, private.replace(b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY")):
        with pytest.raises(ed25519.KeyValidationError):
            ed25519.load_private_key(pem)


def test_reject_spki_with_parameters(pair):
    raw = pair.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # AlgorithmIdentifier with an explicit NULL parameter violates RFC 8410.
    der = bytes.fromhex("302c300706032b65700500032100") + raw
    with pytest.raises(ed25519.KeyValidationError):
        ed25519.load_public_key(_pem(der, "PUBLIC KEY"))


def test_openssl_interoperability_both_directions(pair, tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("OpenSSL CLI is required for independent interoperability evidence")
    message = b'{"schema":"minisign-manifest/v1"}\x00\xff'
    (tmp_path / "message").write_bytes(message)
    (tmp_path / "public.pem").write_bytes(ed25519.export_public_spki_pem(pair.public_key))
    (tmp_path / "signature").write_bytes(ed25519.sign_bytes(pair.private_key, message))

    def run(*args):
        return subprocess.run(["openssl", *args], cwd=tmp_path, capture_output=True, check=True)

    verified = run("pkeyutl", "-verify", "-pubin", "-inkey", "public.pem", "-rawin",
                   "-in", "message", "-sigfile", "signature")
    assert b"Signature Verified Successfully" in verified.stdout

    run("genpkey", "-algorithm", "ED25519", "-out", "external.key.pem")
    run("pkey", "-in", "external.key.pem", "-pubout", "-out", "external.pub.pem")
    run("pkey", "-pubin", "-in", "external.pub.pem", "-outform", "DER", "-out", "external.pub.der")
    run("pkeyutl", "-sign", "-inkey", "external.key.pem", "-rawin", "-in", "message", "-out", "external.sig")
    external_private = ed25519.load_private_key((tmp_path / "external.key.pem").read_bytes())
    external_public = ed25519.load_public_key((tmp_path / "external.pub.pem").read_bytes())
    signature = (tmp_path / "external.sig").read_bytes()
    assert ed25519.verify_bytes(external_public, message, signature)
    # Deterministic Ed25519: our signature with the OpenSSL key matches OpenSSL's.
    assert ed25519.sign_bytes(external_private, message) == signature
    assert ed25519.fingerprint(external_public) == \
        hashlib.sha256((tmp_path / "external.pub.der").read_bytes()).hexdigest()
