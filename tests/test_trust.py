import json
import os
from pathlib import Path

import pytest

from zhongli import trust
from zhongli.crypto import ed25519, rsa
from zhongli.formats import FormatError

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def ed_pair():
    return ed25519.generate_keypair()


@pytest.fixture(scope="module")
def other_ed_pair():
    return ed25519.generate_keypair()


@pytest.fixture(scope="module")
def rsa_pair():
    return rsa.generate_keypair()


def _pem(pair, adapter=ed25519) -> bytes:
    return adapter.export_public_spki_pem(pair.public_key)


def _entry(pair, adapter=ed25519, **overrides) -> dict:
    entry = {"keyid": adapter.fingerprint(pair.public_key), "algorithm": adapter.PROFILE,
             "public_key_pem": _pem(pair, adapter).decode(), "packages": ["demo"]}
    entry.update(overrides)
    return entry


def _store(*entries) -> bytes:
    return json.dumps({"schema": "minisign-trust/v1", "keys": list(entries)}).encode()


def test_add_creates_store_and_is_idempotent(tmp_path, ed_pair):
    path = tmp_path / "trust.json"
    result = trust.add_trust(path, _pem(ed_pair), "demo")
    assert result.changed and result.created_store
    assert result.entry.keyid == ed25519.fingerprint(ed_pair.public_key)
    assert result.entry.algorithm == "ed25519" and result.entry.packages == ("demo",)
    data = json.loads(path.read_bytes())
    assert data["schema"] == "minisign-trust/v1" and list(data["keys"][0]) == \
        ["keyid", "algorithm", "public_key_pem", "packages"]
    before = path.read_bytes()
    again = trust.add_trust(path, _pem(ed_pair).replace(b"\n", b"\r\n"), "demo")
    assert not again.changed and path.read_bytes() == before


def test_add_merges_packages_for_same_key(tmp_path, ed_pair, rsa_pair):
    path = tmp_path / "trust.json"
    trust.add_trust(path, _pem(ed_pair), "demo")
    result = trust.add_trust(path, _pem(ed_pair), "other-app")
    assert result.changed and result.entry.packages == ("demo", "other-app")
    trust.add_trust(path, _pem(rsa_pair, rsa), "demo")
    entries = trust.list_trust(path)
    assert [entry.algorithm for entry in entries] == ["ed25519", "rsa-pss-sha256"]
    assert len(entries) == 2


def test_add_rejects_invalid_inputs(tmp_path, ed_pair):
    path = tmp_path / "trust.json"
    for package in ("*", "Demo", "", "a" * 65):
        with pytest.raises(ValueError):
            trust.add_trust(path, _pem(ed_pair), package)
    with pytest.raises(ValueError):
        trust.add_trust(path, ed25519.export_private_pkcs8_pem(ed_pair.private_key), "demo")
    assert not path.exists()


def test_add_does_not_overwrite_invalid_store(tmp_path, ed_pair):
    path = tmp_path / "trust.json"
    path.write_bytes(b'{"schema":"minisign-trust/v1","keys":[],"keys":[]}')
    before = path.read_bytes()
    with pytest.raises(FormatError):
        trust.add_trust(path, _pem(ed_pair), "demo")
    assert path.read_bytes() == before


def test_failed_write_keeps_previous_store(tmp_path, ed_pair, monkeypatch):
    path = tmp_path / "trust.json"
    trust.add_trust(path, _pem(ed_pair), "demo")
    before = path.read_bytes()

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        trust.add_trust(path, _pem(ed_pair), "another")
    with pytest.raises(OSError):
        trust.remove_trust(path, ed25519.fingerprint(ed_pair.public_key))
    assert path.read_bytes() == before
    assert sorted(item.name for item in tmp_path.iterdir()) == ["trust.json"]


def test_remove(tmp_path, ed_pair):
    path = tmp_path / "trust.json"
    trust.add_trust(path, _pem(ed_pair), "demo")
    keyid = ed25519.fingerprint(ed_pair.public_key)
    removed = trust.remove_trust(path, keyid)
    assert removed.keyid == keyid
    assert trust.list_trust(path) == ()
    with pytest.raises(trust.TrustKeyNotFoundError):
        trust.remove_trust(path, keyid)


def test_valid_stores_parse(ed_pair):
    assert trust.parse_trust_store_strict(_store()).entries == ()
    crlf = _entry(ed_pair, public_key_pem=_pem(ed_pair).decode().replace("\n", "\r\n"))
    assert len(trust.parse_trust_store_strict(_store(crlf)).entries) == 1
    rsa_fixture = trust.load_trust_store(FIXTURES / "rsa" / "trust.json")
    assert rsa_fixture.entries[0].algorithm == "rsa-pss-sha256"


@pytest.mark.parametrize("mutate", [
    lambda e, o, r: {**e, "extra": 1},
    lambda e, o, r: {k: v for k, v in e.items() if k != "packages"},
    lambda e, o, r: {**e, "keyid": None},
    lambda e, o, r: {**e, "keyid": e["keyid"].upper()},
    lambda e, o, r: {**e, "keyid": o["keyid"]},
    lambda e, o, r: {**e, "algorithm": "ed448"},
    lambda e, o, r: {**e, "algorithm": "rsa-pss-sha256"},
    lambda e, o, r: {**r, "algorithm": "ed25519"},
    lambda e, o, r: {**e, "public_key_pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"},
    lambda e, o, r: {**e, "public_key_pem": ["not", "a", "string"]},
    lambda e, o, r: {**e, "packages": []},
    lambda e, o, r: {**e, "packages": ["demo", "demo"]},
    lambda e, o, r: {**e, "packages": ["*"]},
    lambda e, o, r: {**e, "packages": "demo"},
    lambda e, o, r: {**e, "packages": [True]},
], ids=["extra-field", "missing-field", "null", "uppercase-keyid", "fingerprint-mismatch",
        "unknown-profile", "profile-vs-key-type", "rsa-labelled-ed25519", "bad-pem", "pem-type",
        "empty-packages", "duplicate-packages", "wildcard", "packages-type", "package-type"])
def test_invalid_entries_are_format_errors(ed_pair, other_ed_pair, rsa_pair, mutate):
    entry = _entry(ed_pair)
    raw = mutate(entry, _entry(other_ed_pair), _entry(rsa_pair, rsa))
    with pytest.raises(FormatError):
        trust.parse_trust_store_strict(_store(_entry(other_ed_pair), raw))


@pytest.mark.parametrize("raw", [
    b"", b"[]", b'{"schema":"minisign-trust/v1"}', b'{"schema":"minisign-trust/v2","keys":[]}',
    b'{"schema":"minisign-trust/v1","keys":{}}', b'{"schema":"minisign-trust/v1","keys":[],"extra":1}',
    b'{"schema":"minisign-trust/v1","schema":"minisign-trust/v1","keys":[]}',
    b'\xef\xbb\xbf{"schema":"minisign-trust/v1","keys":[]}', b'{"schema":"minisign-trust/v1","keys":[NaN]}',
])
def test_invalid_store_structure(raw):
    with pytest.raises(FormatError):
        trust.parse_trust_store_strict(raw)


def test_duplicate_keyid_rejected(ed_pair):
    with pytest.raises(FormatError):
        trust.parse_trust_store_strict(_store(_entry(ed_pair), _entry(ed_pair, packages=["other"])))


def test_lookup_success(ed_pair):
    store = trust.parse_trust_store_strict(_store(_entry(ed_pair)))
    key = trust.find_authorized_key(store, ed25519.fingerprint(ed_pair.public_key), "ed25519", "demo")
    assert ed25519.fingerprint(key) == ed25519.fingerprint(ed_pair.public_key)


def test_empty_or_removed_key_not_trusted_u06(tmp_path, ed_pair):
    keyid = ed25519.fingerprint(ed_pair.public_key)
    with pytest.raises(trust.KeyNotTrustedError):
        trust.find_authorized_key(trust.parse_trust_store_strict(_store()), keyid, "ed25519", "demo")
    path = tmp_path / "trust.json"
    trust.add_trust(path, _pem(ed_pair), "demo")
    trust.remove_trust(path, keyid)
    with pytest.raises(trust.KeyNotTrustedError):
        trust.find_authorized_key(trust.load_trust_store(path), keyid, "ed25519", "demo")


def test_key_allowed_only_for_other_package_u07(ed_pair):
    store = trust.parse_trust_store_strict(_store(_entry(ed_pair, packages=["other-app"])))
    with pytest.raises(trust.KeyNotTrustedError):
        trust.find_authorized_key(store, ed25519.fingerprint(ed_pair.public_key), "ed25519", "demo")


def test_other_key_same_profile_not_trusted_u12(ed_pair, other_ed_pair):
    store = trust.parse_trust_store_strict(_store(_entry(ed_pair)))
    with pytest.raises(trust.KeyNotTrustedError):
        trust.find_authorized_key(store, ed25519.fingerprint(other_ed_pair.public_key), "ed25519", "demo")


def test_profile_differs_from_manifest_not_trusted(ed_pair):
    store = trust.parse_trust_store_strict(_store(_entry(ed_pair)))
    with pytest.raises(trust.KeyNotTrustedError):
        trust.find_authorized_key(store, ed25519.fingerprint(ed_pair.public_key), "rsa-pss-sha256", "demo")
