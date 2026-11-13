import pytest

from if4020_signing.crypto import ed25519
from if4020_signing.formats import parse_bundle_strict, parse_manifest_strict
from if4020_signing.signing import sign


@pytest.fixture(scope="module")
def pair():
    return ed25519.generate_keypair()


@pytest.fixture
def key_path(tmp_path, pair):
    path = tmp_path / "publisher.key.pem"
    path.write_bytes(ed25519.export_private_pkcs8_pem(pair.private_key))
    return path


@pytest.mark.parametrize("content", [b"hello\r\n", bytes(range(256)), b""], ids=["text", "binary", "empty"])
def test_sign_ed25519_artifacts_u01(tmp_path, key_path, pair, content):
    artifact, output = tmp_path / "demo.bin", tmp_path / "bundle.json"
    artifact.write_bytes(content)
    result = sign(artifact, "demo", "1.0.0", key_path, output)
    manifest_bytes, signature = parse_bundle_strict(output.read_bytes())
    manifest = parse_manifest_strict(manifest_bytes)
    assert result.algorithm == manifest["algorithm"] == "ed25519"
    assert result.keyid == manifest["keyid"] == ed25519.fingerprint(pair.public_key)
    assert len(signature) == 64
    assert ed25519.verify_bytes(pair.public_key, manifest_bytes, signature)
    assert artifact.read_bytes() == content


def test_identical_manifest_identical_signature_u14(tmp_path, key_path, pair):
    artifact = tmp_path / "demo.bin"
    artifact.write_bytes(b"release")
    first = sign(artifact, "demo", "1.0.0", key_path, tmp_path / "first.json")
    second = sign(artifact, "demo", "1.0.0", key_path, tmp_path / "second.json")
    assert first.manifest_bytes == second.manifest_bytes
    assert first.signature_bytes == second.signature_bytes
    assert (tmp_path / "first.json").read_bytes() == (tmp_path / "second.json").read_bytes()
    for result in (first, second):
        assert ed25519.verify_bytes(pair.public_key, result.manifest_bytes, result.signature_bytes)
