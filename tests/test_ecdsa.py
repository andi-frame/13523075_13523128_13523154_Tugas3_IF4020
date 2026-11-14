import base64
import hashlib
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519 as backend_ed25519, rsa as backend_rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from if4020_signing.crypto import ecdsa

N = ecdsa.CURVE_ORDER

# RFC 6979 appendix A.2.5: P-256 key and SHA-256 signatures.
RFC_PRIVATE = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC_PUBLIC_X = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
RFC_PUBLIC_Y = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
RFC_VECTORS = {
    b"sample": (0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
                0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
    b"test": (0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
              0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083),
}


@pytest.fixture(scope="module")
def pair():
    return ecdsa.generate_keypair()


def _pem(der: bytes, label: str) -> bytes:
    body = base64.b64encode(der).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)).encode()


def _raw(r: int, s: int) -> bytes:
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_key_roundtrip_and_fingerprint(pair):
    private = ecdsa.load_private_key(ecdsa.export_private_pkcs8_pem(pair.private_key))
    pem = ecdsa.export_public_spki_pem(pair.public_key)
    public = ecdsa.load_public_key(pem.replace(b"\n", b"\r\n"))
    assert private.private_numbers() == pair.private_key.private_numbers()
    assert public.public_numbers() == pair.public_key.public_numbers()
    der = ecdsa.export_public_spki_der(public)
    # SPKI: id-ecPublicKey + prime256v1 OIDs, then 0x04 || X || Y (SEC1 uncompressed).
    assert len(der) == 91 and der[26] == 0x04
    assert bytes.fromhex("06072a8648ce3d0201" "06082a8648ce3d030107") in der
    assert ecdsa.profile_of(private) == ecdsa.PROFILE == "ecdsa-p256-sha256"
    assert ecdsa.fingerprint(public) == hashlib.sha256(der).hexdigest()
    assert ecdsa.fingerprint(ecdsa.public_from_private(private)) == ecdsa.fingerprint(public)


@pytest.mark.parametrize("message", sorted(RFC_VECTORS))
def test_rfc6979_known_answer(message):
    private = ec.derive_private_key(RFC_PRIVATE, ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    assert (numbers.x, numbers.y) == (RFC_PUBLIC_X, RFC_PUBLIC_Y)
    signature = ecdsa.sign_bytes(private, message)
    assert signature == _raw(*RFC_VECTORS[message])
    assert ecdsa.verify_bytes(private.public_key(), message, signature)


def test_signature_is_raw_r_s_and_hashes_once(pair):
    message = b"original manifest bytes"
    signature = ecdsa.sign_bytes(pair.private_key, message)
    assert len(signature) == 64
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    assert 0 < r < N and 0 < s < N
    der = ecdsa.raw_to_der(signature)
    assert decode_dss_signature(der) == (r, s)
    # Equivalent to ECDSA over the single SHA-256 digest of the manifest bytes.
    pair.public_key.verify(der, hashlib.sha256(message).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
    assert not ecdsa.verify_bytes(pair.public_key, hashlib.sha256(message).digest(), signature)


def test_deterministic_signature_u14(pair):
    message = b"original manifest bytes"
    first = ecdsa.sign_bytes(pair.private_key, message)
    second = ecdsa.sign_bytes(pair.private_key, message)
    # RFC 6979 derives k from the private key and message digest: identical output.
    assert first == second
    assert ecdsa.verify_bytes(pair.public_key, message, first)
    assert ecdsa.sign_bytes(pair.private_key, message + b"!") != first


def test_der_conversion_roundtrip_and_padding():
    # Small components must be left-padded to 32 bytes.
    raw = _raw(1, 2)
    der = ecdsa.raw_to_der(raw)
    assert der == bytes.fromhex("3006020101020102")
    assert ecdsa.der_to_raw(der) == raw
    with pytest.raises(ValueError):
        ecdsa.raw_to_der(raw[:-1])
    with pytest.raises(ValueError):
        ecdsa.der_to_raw(ecdsa.raw_to_der(_raw(0, 1)))


def test_reject_tampering_and_lengths(pair):
    message = b"manifest"
    signature = ecdsa.sign_bytes(pair.private_key, message)
    assert not ecdsa.verify_bytes(pair.public_key, message + b"!", signature)
    assert not ecdsa.verify_bytes(pair.public_key, message, bytes([signature[0] ^ 1]) + signature[1:])
    assert not ecdsa.verify_bytes(pair.public_key, message, signature[:-1] + bytes([signature[-1] ^ 0x80]))
    for bad in (b"", signature[:-1], signature + b"\x00", ecdsa.raw_to_der(signature)):
        assert not ecdsa.verify_bytes(pair.public_key, message, bad)
    assert not ecdsa.verify_bytes(ecdsa.generate_keypair().public_key, message, signature)


@pytest.mark.parametrize("r,s", [(0, 1), (1, 0), (0, 0), (N, 1), (1, N), (N + 1, 1), (2**256 - 1, 2**256 - 1)],
                         ids=["r=0", "s=0", "zero", "r=n", "s=n", "r>n", "all-ff"])
def test_out_of_domain_components_are_invalid(pair, r, s):
    assert not ecdsa.verify_bytes(pair.public_key, b"manifest", _raw(r, s))


def test_high_s_is_accepted(pair):
    message = b"manifest"
    signature = ecdsa.sign_bytes(pair.private_key, message)
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    # (r, n - s) is also a valid ECDSA signature; low-S normalization is not required.
    assert ecdsa.verify_bytes(pair.public_key, message, _raw(r, N - s))


@pytest.mark.parametrize("curve", [ec.SECP384R1(), ec.SECP256K1()], ids=["p384", "secp256k1"])
def test_reject_other_curves(curve):
    key = ec.generate_private_key(curve)
    with pytest.raises(ecdsa.KeyValidationError):
        ecdsa.sign_bytes(key, b"m")
    with pytest.raises(ecdsa.KeyValidationError):
        ecdsa.verify_bytes(key.public_key(), b"m", bytes(64))
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    with pytest.raises(ecdsa.KeyValidationError):
        ecdsa.load_public_key(public)
    with pytest.raises(ecdsa.KeyValidationError):
        ecdsa.load_private_key(private)


def test_reject_other_key_types():
    for key in (backend_rsa.generate_private_key(public_exponent=65537, key_size=2048),
                backend_ed25519.Ed25519PrivateKey.generate()):
        with pytest.raises(ecdsa.KeyValidationError):
            ecdsa.sign_bytes(key, b"m")
        public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(ecdsa.KeyValidationError):
            ecdsa.load_public_key(public)


def test_reject_compressed_point(pair):
    point = pair.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    der = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + point
    with pytest.raises(ecdsa.KeyValidationError):
        ecdsa.load_public_key(_pem(der, "PUBLIC KEY"))


def test_reject_bad_pem(pair):
    public = ecdsa.export_public_spki_pem(pair.public_key)
    private = ecdsa.export_private_pkcs8_pem(pair.private_key)
    for pem in (b"invalid", public + public, public.replace(b"PUBLIC KEY", b"EC PUBLIC KEY")):
        with pytest.raises(ecdsa.KeyValidationError):
            ecdsa.load_public_key(pem)
    sec1 = pair.private_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption())
    for pem in (b"invalid", public, sec1):
        with pytest.raises(ecdsa.KeyValidationError):
            ecdsa.load_private_key(pem)
    assert private.startswith(b"-----BEGIN PRIVATE KEY-----")


def _openssl(tmp_path, *args):
    return subprocess.run(["openssl", *args], cwd=tmp_path, capture_output=True, check=True)


requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="OpenSSL CLI is required for independent interoperability evidence")


@requires_openssl
def test_openssl_interoperability_both_directions(pair, tmp_path):
    message = b'{"schema":"minisign-manifest/v1"}\x00\xff'
    (tmp_path / "message").write_bytes(message)
    (tmp_path / "public.pem").write_bytes(ecdsa.export_public_spki_pem(pair.public_key))
    # OpenSSL expects DER, so the raw r || s signature is converted first.
    (tmp_path / "signature.der").write_bytes(ecdsa.raw_to_der(ecdsa.sign_bytes(pair.private_key, message)))
    verified = _openssl(tmp_path, "dgst", "-sha256", "-verify", "public.pem",
                        "-signature", "signature.der", "message")
    assert b"Verified OK" in verified.stdout

    _openssl(tmp_path, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-pkeyopt", "ec_param_enc:named_curve", "-out", "external.key.pem")
    _openssl(tmp_path, "pkey", "-in", "external.key.pem", "-pubout", "-out", "external.pub.pem")
    _openssl(tmp_path, "pkey", "-pubin", "-in", "external.pub.pem", "-outform", "DER", "-out", "external.pub.der")
    _openssl(tmp_path, "dgst", "-sha256", "-sign", "external.key.pem", "-out", "external.sig", "message")
    external_private = ecdsa.load_private_key((tmp_path / "external.key.pem").read_bytes())
    external_public = ecdsa.load_public_key((tmp_path / "external.pub.pem").read_bytes())
    raw = ecdsa.der_to_raw((tmp_path / "external.sig").read_bytes())
    assert ecdsa.verify_bytes(external_public, message, raw)
    assert ecdsa.fingerprint(external_public) == \
        hashlib.sha256((tmp_path / "external.pub.der").read_bytes()).hexdigest()
    assert ecdsa.fingerprint(ecdsa.public_from_private(external_private)) == ecdsa.fingerprint(external_public)


@requires_openssl
def test_openssl_rfc6979_signature_matches(pair, tmp_path):
    message = b"canonical manifest bytes"
    (tmp_path / "message").write_bytes(message)
    (tmp_path / "private.pem").write_bytes(ecdsa.export_private_pkcs8_pem(pair.private_key))
    try:
        _openssl(tmp_path, "dgst", "-sha256", "-sign", "private.pem", "-sigopt", "nonce-type:1",
                 "-out", "deterministic.sig", "message")
    except subprocess.CalledProcessError:
        pytest.skip("OpenSSL older than 3.2 lacks deterministic ECDSA (nonce-type:1)")
    external = ecdsa.der_to_raw((tmp_path / "deterministic.sig").read_bytes())
    assert ecdsa.sign_bytes(pair.private_key, message) == external


@requires_openssl
def test_reject_explicit_curve_parameters(tmp_path):
    _openssl(tmp_path, "ecparam", "-name", "prime256v1", "-param_enc", "explicit", "-genkey",
             "-noout", "-out", "explicit.key.pem")
    try:
        _openssl(tmp_path, "pkey", "-in", "explicit.key.pem", "-pubout", "-out", "explicit.pub.pem")
    except subprocess.CalledProcessError:
        pytest.skip("OpenSSL build cannot export explicit-parameter keys")
    with pytest.raises(ecdsa.KeyValidationError):
        ecdsa.load_public_key((tmp_path / "explicit.pub.pem").read_bytes())
