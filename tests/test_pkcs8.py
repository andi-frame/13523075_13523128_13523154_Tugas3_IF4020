"""PKCS#8 attributes are metadata, not part of the public-key identity."""

import base64
from pathlib import Path
import shutil
import subprocess

import pytest

from zhongli import keys
from zhongli.signing import sign
from zhongli.verification import verify

FIXTURES = Path(__file__).parent / "fixtures"


def tlv(tag, content):
    size = len(content)
    length = bytes([size]) if size < 128 else (bytes([0x80 + (size.bit_length() + 7) // 8])
                                              + size.to_bytes((size.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + length + content


def with_friendly_name(der):
    offset = 2 if der[1] < 128 else 2 + (der[1] & 0x7f)
    # PKCS#9 friendlyName, SET OF BMPString, inside [0] IMPLICIT Attributes.
    attribute = tlv(0x30, bytes.fromhex("06092a864886f70d010914")
                    + tlv(0x31, tlv(0x1e, "publisher".encode("utf-16-be"))))
    der = tlv(0x30, der[offset:] + tlv(0xa0, attribute))
    return b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(der) + b"-----END PRIVATE KEY-----\n"


@pytest.mark.parametrize("name", ["rsa", "ecdsa", "ed25519"])
def test_standard_pkcs8_attributes_preserve_identity_and_signing(name, tmp_path):
    fixture = FIXTURES / name
    original = keys.load_private_key((fixture / "TEST_ONLY.key.pem").read_bytes())
    private = tmp_path / "publisher.key.pem"
    private.write_bytes(with_friendly_name(keys.export_private_pkcs8_der(original)))
    if shutil.which("openssl"):
        subprocess.run(["openssl", "pkey", "-in", str(private), "-check", "-noout"],
                       check=True, capture_output=True)
    loaded = keys.load_private_key(private.read_bytes())
    assert keys.fingerprint(keys.public_from_private(loaded)) == keys.fingerprint(keys.public_from_private(original))
    bundle = tmp_path / "release.json"
    sign(fixture / "demo.bin", "demo", "1.0", private, bundle)
    assert verify(fixture / "demo.bin", bundle, fixture / "trust.json", "demo", "1.0").valid


@pytest.mark.parametrize("name", ["rsa", "ecdsa", "ed25519"])
def test_private_key_info_rejects_trailing_der(name):
    original = keys.load_private_key((FIXTURES / name / "TEST_ONLY.key.pem").read_bytes())
    der = keys.export_private_pkcs8_der(original) + b"\x00"
    pem = b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(der) + b"-----END PRIVATE KEY-----\n"
    with pytest.raises(ValueError):
        keys.load_private_key(pem)
