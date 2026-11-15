import hashlib
import os
import stat
import subprocess

import pytest

from zhongli import keys
from zhongli.keygen import keygen

CLI = "zhongli"


def run(*args):
    return subprocess.run([CLI, *map(str, args)], capture_output=True, text=True, stdin=subprocess.DEVNULL)


@pytest.mark.parametrize("profile", keys.PROFILES)
def test_keygen_writes_matching_pair(tmp_path, profile):
    result = keygen(profile, tmp_path / "keys" / "publisher")
    private_pem = result.private_key_path.read_bytes()
    public_pem = result.public_key_path.read_bytes()
    assert result.private_key_path.name == "publisher.key.pem"
    assert result.public_key_path.name == "publisher.pub.pem"
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    private = keys.load_private_key(private_pem)
    public = keys.load_public_key_for_profile(public_pem, profile)
    assert keys.profile_of(private) == profile
    assert result.keyid == keys.fingerprint(public) == keys.fingerprint(keys.public_from_private(private))
    assert result.keyid == hashlib.sha256(keys.export_public_spki_der(public)).hexdigest()
    if os.name == "posix":  # Windows has no POSIX permission bits
        assert stat.S_IMODE(result.private_key_path.stat().st_mode) == 0o600
    assert sorted(p.name for p in result.private_key_path.parent.iterdir()) == \
        ["publisher.key.pem", "publisher.pub.pem"]


def test_keygen_requires_explicit_overwrite(tmp_path):
    first = keygen("ed25519", tmp_path / "publisher")
    original = first.private_key_path.read_bytes()
    with pytest.raises(FileExistsError):
        keygen("ed25519", tmp_path / "publisher")
    assert first.private_key_path.read_bytes() == original
    second = keygen("ed25519", tmp_path / "publisher", overwrite_explicit=True)
    assert second.private_key_path.read_bytes() != original
    assert second.keyid != first.keyid


def test_keygen_rejects_bad_input(tmp_path):
    with pytest.raises(ValueError):
        keygen("ed448", tmp_path / "publisher")
    with pytest.raises(ValueError):
        keygen("ed25519", tmp_path / "..")
    assert list(tmp_path.iterdir()) == []


def test_keygen_cli(tmp_path):
    prefix = tmp_path / "publisher"
    result = run("keygen", "--algorithm", "ed25519", "--out", prefix)
    assert result.returncode == 0, result.stderr
    keyid = keys.fingerprint(keys.load_public_key((tmp_path / "publisher.pub.pem").read_bytes()))
    assert keyid in result.stdout
    private_pem = (tmp_path / "publisher.key.pem").read_bytes()
    assert private_pem not in result.stdout.encode() and b"PRIVATE" not in result.stdout.encode()
    result = run("keygen", "--algorithm", "ed25519", "--out", prefix)
    assert result.returncode == 2 and "--force" in result.stderr and result.stdout == ""
    assert (tmp_path / "publisher.key.pem").read_bytes() == private_pem
    assert run("keygen", "--algorithm", "ed25519", "--out", prefix, "--force").returncode == 0
    assert (tmp_path / "publisher.key.pem").read_bytes() != private_pem
    assert run("keygen", "--algorithm", "dsa", "--out", prefix).returncode == 2
    assert run("keygen", "--out", prefix).returncode == 2


def test_cli_end_to_end_keygen_trust_sign(tmp_path):
    prefix, store, artifact, bundle = (tmp_path / n for n in ("publisher", "trust.json", "app.bin", "release.json"))
    artifact.write_bytes(b"\x00release\xff")
    assert run("keygen", "--algorithm", "ed25519", "--out", prefix).returncode == 0
    assert run("trust", "add", "--key", f"{prefix}.pub.pem", "--package", "contoh-app", "--store", store).returncode == 0
    result = run("sign", "--file", artifact, "--package", "contoh-app", "--version", "1.0.0",
                 "--key", f"{prefix}.key.pem", "--out", bundle)
    assert result.returncode == 0, result.stderr
    assert "ed25519" in result.stdout
