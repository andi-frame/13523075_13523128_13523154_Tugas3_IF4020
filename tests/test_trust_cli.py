import json
import subprocess

import pytest

from if4020_signing.crypto import ed25519

CLI = "if4020-signing"


def run(*args):
    return subprocess.run([CLI, *map(str, args)], capture_output=True, text=True, stdin=subprocess.DEVNULL)


@pytest.fixture(scope="module")
def pair():
    return ed25519.generate_keypair()


@pytest.fixture
def pub(tmp_path, pair):
    path = tmp_path / "publisher.pub.pem"
    path.write_bytes(ed25519.export_public_spki_pem(pair.public_key))
    return path


def test_trust_add_list_remove(tmp_path, pub, pair):
    store = tmp_path / "trust.json"
    keyid = ed25519.fingerprint(pair.public_key)
    result = run("trust", "add", "--key", pub, "--package", "demo", "--store", store)
    assert result.returncode == 0, result.stderr
    assert keyid in result.stdout and "ed25519" in result.stdout and "demo" in result.stdout
    before = store.read_bytes()
    result = run("trust", "add", "--key", pub, "--package", "demo", "--store", store)
    assert result.returncode == 0 and "no change" in result.stdout
    assert store.read_bytes() == before
    assert run("trust", "add", "--key", pub, "--package", "other", "--store", store).returncode == 0
    result = run("trust", "list", "--store", store)
    assert result.returncode == 0
    assert result.stdout.strip() == f"{keyid}  ed25519  demo,other"
    result = run("trust", "remove", "--keyid", keyid, "--store", store)
    assert result.returncode == 0 and keyid in result.stdout
    assert json.loads(store.read_bytes())["keys"] == []
    assert run("trust", "list", "--store", store).stdout.strip() == "No trusted keys."


def test_trust_failures_exit_2(tmp_path, pub, pair):
    store = tmp_path / "trust.json"
    keyid = ed25519.fingerprint(pair.public_key)
    assert run("trust", "remove", "--keyid", keyid, "--store", store).returncode == 2
    store.write_text('{"schema":"minisign-trust/v1","keys":[]}')
    result = run("trust", "remove", "--keyid", keyid, "--store", store)
    assert result.returncode == 2 and result.stdout == "" and "not in the trust store" in result.stderr
    assert run("trust", "list", "--store", tmp_path / "missing.json").returncode == 2
    assert run("trust", "add", "--key", tmp_path / "missing.pem", "--package", "demo", "--store", store).returncode == 2
    assert run("trust", "add", "--key", pub, "--package", "*", "--store", store).returncode == 2
    store.write_text("{broken")
    assert run("trust", "add", "--key", pub, "--package", "demo", "--store", store).returncode == 2
    assert store.read_text() == "{broken"
    assert run("trust", "add", "--key", pub).returncode == 2
    assert run("trust").returncode == 2
