import base64
import hashlib
import json

import pytest

from if4020_signing.artifact import ArtifactInfo, read_artifact
from if4020_signing.formats import (
    BUNDLE_LIMIT, MANIFEST_LIMIT, FormatError, build_manifest, encode_bundle,
    parse_bundle_strict, parse_json_strict, parse_manifest_strict, serialize_manifest,
)


@pytest.fixture
def manifest():
    return build_manifest("demo", "1.0", "rsa-pss-sha256", "a" * 64,
                          ArtifactInfo("demo.bin", 0, hashlib.sha256(b"").hexdigest()))


def test_literal_canonical_manifest(manifest):
    expected = (b'{"schema":"minisign-manifest/v1","package":"demo","version":"1.0",'
                b'"algorithm":"rsa-pss-sha256","keyid":"' + b'a' * 64
                + b'","artifact":{"name":"demo.bin","size":0,"sha256":'
                b'"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}')
    assert serialize_manifest(manifest) == expected
    assert parse_manifest_strict(expected) == manifest
    assert serialize_manifest(dict(reversed(list(manifest.items())))) == expected


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"a":{"x":1,"x":2}}', b'{"x":1,"\\u0078":2}',
    b'NaN', b'Infinity', b'-Infinity', b'\xef\xbb\xbf{}', b'"\xff"',
    b'{} trailing', b'[' * 2000,
])
def test_strict_json_rejects_invalid(raw):
    with pytest.raises(FormatError):
        parse_json_strict(raw)


@pytest.mark.parametrize("field,value", [
    ("package", "Demo"), ("package", "a" * 65), ("version", "v/1"),
    ("keyid", "A" * 64), ("keyid", None), ("algorithm", 1), ("algorithm", "é"),
    ("schema", None), ("extra", 1),
])
def test_invalid_manifest_fields(manifest, field, value):
    manifest[field] = value
    with pytest.raises(FormatError):
        serialize_manifest(manifest)


@pytest.mark.parametrize("field,value", [
    ("size", True), ("size", 1.0), ("size", -1), ("size", 2**53),
    ("name", "../demo.bin"), ("name", "a" * 129), ("sha256", "0" * 63),
    ("extra", 1),
])
def test_invalid_artifact_fields(manifest, field, value):
    manifest["artifact"][field] = value
    with pytest.raises(FormatError):
        serialize_manifest(manifest)


def test_missing_and_wrong_structure(manifest):
    for value in (None, [], {"schema": "minisign-manifest/v1"}):
        with pytest.raises(FormatError):
            serialize_manifest(value)
    del manifest["artifact"]["size"]
    with pytest.raises(FormatError):
        serialize_manifest(manifest)


def test_noncanonical_manifest(manifest):
    raw = serialize_manifest(manifest)
    variants = [raw + b'\n', b' ' + raw, json.dumps(manifest).encode(),
                raw.replace(b'"size":0', b'"size":-0'),
                raw.replace(b'"size":0', b'"size":0e0'),
                raw.replace(b'demo', b'\\u0064emo'),
                json.dumps(dict(reversed(list(manifest.items()))), separators=(",", ":")).encode()]
    for variant in variants:
        with pytest.raises(FormatError):
            parse_manifest_strict(variant)


def test_unknown_profile_is_not_format_error(manifest):
    manifest["algorithm"] = "future-profile"
    assert parse_manifest_strict(serialize_manifest(manifest))["algorithm"] == "future-profile"


def test_bundle_whitespace_and_order_u13(manifest):
    raw = serialize_manifest(manifest)
    bundle = json.loads(encode_bundle(raw, b"signature"))
    reordered = json.dumps(dict(reversed(list(bundle.items()))), indent=4).encode() + b'\n'
    assert parse_bundle_strict(reordered) == (raw, b"signature")


@pytest.mark.parametrize("value", ["Zg", "Zh==", "Zg===", "Zg==\n", "-w==", "é", None, 1])
def test_base64_rejections_u10(manifest, value):
    bundle = json.loads(encode_bundle(serialize_manifest(manifest), b'f'))
    bundle["signature_b64"] = value
    with pytest.raises(FormatError):
        parse_bundle_strict(json.dumps(bundle).encode())


def test_bundle_structure_and_limits(manifest):
    raw = encode_bundle(serialize_manifest(manifest), b"")
    assert parse_bundle_strict(raw)[1] == b""  # algorithm layer decides validity
    for invalid in [raw[:-1] + b',"schema":"minisign-bundle/v1"}',
                    raw[:-1] + b',"extra":1}', b'[]', b'\xef\xbb\xbf' + raw,
                    b' ' * (BUNDLE_LIMIT + 1)]:
        with pytest.raises(FormatError):
            parse_bundle_strict(invalid)
    with pytest.raises(FormatError):
        parse_manifest_strict(b' ' * (MANIFEST_LIMIT + 1))
    bundle = json.loads(raw)
    bundle["manifest_b64"] = base64.b64encode(b' ' * (MANIFEST_LIMIT + 1)).decode()
    with pytest.raises(FormatError):
        parse_bundle_strict(json.dumps(bundle).encode())


@pytest.mark.parametrize("content", [b"", b"hello\r\n", bytes(range(256)) * 8193])
def test_artifact_bytes(tmp_path, content):
    path = tmp_path / "demo.bin"
    path.write_bytes(content)
    assert read_artifact(path) == ArtifactInfo("demo.bin", len(content), hashlib.sha256(content).hexdigest())
    assert path.read_bytes() == content
