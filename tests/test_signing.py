import json
import subprocess

import pytest

from zhongli.crypto import rsa
from zhongli.formats import parse_bundle_strict, parse_manifest_strict
from zhongli.signing import sign


@pytest.fixture(scope="module")
def pair():
    return rsa.generate_keypair()


@pytest.fixture
def inputs(tmp_path, pair):
    artifact, key, output = (tmp_path / name for name in ("demo.bin", "private.pem", "bundle.json"))
    artifact.write_bytes(b'hello\x00\xff\r\n')
    key.write_bytes(rsa.export_private_pkcs8_pem(pair.private_key))
    return artifact, key, output


@pytest.mark.parametrize("content", [b'hello\r\n', bytes(range(256)), b''])
def test_sign_real_artifacts_u01(inputs, pair, content):
    artifact, key, output = inputs
    artifact.write_bytes(content)
    result = sign(artifact, "demo", "1.0", key, output)
    manifest, signature = parse_bundle_strict(output.read_bytes())
    assert rsa.verify_bytes(pair.public_key, manifest, signature)
    assert result.manifest_bytes == manifest
    assert result.keyid == rsa.fingerprint(pair.public_key)
    assert parse_manifest_strict(manifest)["artifact"]["size"] == len(content)
    assert artifact.read_bytes() == content
    assert key.read_bytes() == rsa.export_private_pkcs8_pem(pair.private_key)


@pytest.mark.parametrize("change", [lambda b: bytes([b[0] ^ 1]) + b[1:], lambda b: b + b'!', lambda b: b[:-1]])
def test_artifact_changes_u02_u03(inputs, pair, change):
    from zhongli.artifact import read_artifact

    artifact, key, output = inputs
    sign(artifact, "demo", "1.0", key, output)
    manifest, signature = parse_bundle_strict(output.read_bytes())
    artifact.write_bytes(change(artifact.read_bytes()))
    expected = parse_manifest_strict(manifest)["artifact"]
    actual = read_artifact(artifact)
    assert (actual.size, actual.sha256) != (expected["size"], expected["sha256"])
    assert rsa.verify_bytes(pair.public_key, manifest, signature)


def test_metadata_change_invalidates_signature_u04(inputs, pair):
    from zhongli.formats import serialize_manifest

    artifact, key, output = inputs
    sign(artifact, "demo", "1.0", key, output)
    manifest, signature = parse_bundle_strict(output.read_bytes())
    changed = parse_manifest_strict(manifest)
    changed["version"] = "2.0"
    assert not rsa.verify_bytes(pair.public_key, serialize_manifest(changed), signature)


def test_two_valid_bundles_u14(inputs, pair):
    artifact, key, output = inputs
    first = sign(artifact, "demo", "1.0", key, output)
    second = sign(artifact, "demo", "1.0", key, output)
    assert first.manifest_bytes == second.manifest_bytes
    assert first.signature_bytes != second.signature_bytes
    for result in (first, second):
        assert rsa.verify_bytes(pair.public_key, result.manifest_bytes, result.signature_bytes)


@pytest.mark.parametrize("target", ["artifact", "key", "hardlink", "symlink"])
def test_prevent_overwriting_inputs(inputs, target):
    artifact, key, output = inputs
    before_artifact, before_key = artifact.read_bytes(), key.read_bytes()
    if target == "artifact":
        output = artifact
    elif target == "key":
        output = key
    elif target == "hardlink":
        output.hardlink_to(key)
    else:
        try:
            output.symlink_to(artifact)
        except OSError:
            pytest.skip("Creating symlinks requires extra privileges on this platform")
    with pytest.raises(ValueError):
        sign(artifact, "demo", "1.0", key, output)
    assert artifact.read_bytes() == before_artifact
    assert key.read_bytes() == before_key


def test_failures_preserve_existing_bundle(inputs, monkeypatch):
    artifact, key, output = inputs
    output.write_bytes(b'previous bundle')
    with pytest.raises(ValueError):
        sign(artifact, "BAD/package", "1.0", key, output)
    assert output.read_bytes() == b'previous bundle'

    def fail_replace(*args):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("zhongli.signing.os.replace", fail_replace)
    with pytest.raises(OSError):
        sign(artifact, "demo", "1.0", key, output)
    assert output.read_bytes() == b'previous bundle'
    assert sorted(path.name for path in output.parent.iterdir()) == ['bundle.json', 'demo.bin', 'private.pem']


def test_cli_sign_success_and_failures(inputs, pair):
    artifact, key, output = inputs
    command = ['zhongli', 'sign', '--file', str(artifact), '--key', str(key),
               '--out', str(output), '--package', 'demo', '--version', '1.0']
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    manifest, signature = parse_bundle_strict(output.read_bytes())
    assert rsa.verify_bytes(pair.public_key, manifest, signature)
    artifact.unlink()
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 2
    assert result.stdout == ''
    assert 'INPUT_ERROR' in result.stderr
    result = subprocess.run(['zhongli', 'sign'], capture_output=True, text=True)
    assert result.returncode == 2


def test_cli_help_and_version():
    for option in ('--help', '--version'):
        result = subprocess.run(['zhongli', option], capture_output=True, text=True)
        assert result.returncode == 0
        assert result.stdout.strip()


def test_shared_rsa_fixture():
    from pathlib import Path
    from zhongli.artifact import read_artifact

    root = Path(__file__).parent / 'fixtures' / 'rsa'
    manifest, signature = parse_bundle_strict((root / 'bundle.json').read_bytes())
    public = rsa.load_public_key((root / 'TEST_ONLY.pub.pem').read_bytes())
    private = rsa.load_private_key((root / 'TEST_ONLY.key.pem').read_bytes())
    store = json.loads((root / 'trust.json').read_bytes())
    assert manifest == (root / 'manifest.json').read_bytes()
    assert rsa.verify_bytes(public, manifest, signature)
    assert rsa.fingerprint(public) == rsa.fingerprint(rsa.public_from_private(private))
    assert store['keys'][0]['keyid'] == rsa.fingerprint(public)
    assert store['keys'][0]['packages'] == ['demo']
    info = read_artifact(root / 'demo.bin')
    assert parse_manifest_strict(manifest)['artifact'] == {
        'name': info.name, 'size': info.size, 'sha256': info.sha256}
