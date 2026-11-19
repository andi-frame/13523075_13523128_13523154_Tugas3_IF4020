import json
from pathlib import Path
import subprocess
import sys

import pytest

from zhongli import keys
from zhongli.sbom import (
    SBOM_MISMATCH, SbomError, create_sbom, parse_sbom_strict, read_lock_components, serialize_sbom,
    sign_sbom, verify_release_with_sbom,
)
from zhongli.signing import sign
from zhongli.trust import add_trust

PACKAGE, VERSION = "contoh-app", "1.0.0"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def keypairs():
    return {profile: keys.generate_keypair(profile) for profile in keys.PROFILES}


class Release:
    """Artifact, release bundle, SBOM and SBOM bundle signed by one trusted key."""

    def __init__(self, root: Path, pair, other_pair):
        self.root = root
        self.key, self.other_key = root / "publisher.key.pem", root / "other.key.pem"
        self.key.write_bytes(keys.export_private_pkcs8_pem(pair.private_key))
        self.other_key.write_bytes(keys.export_private_pkcs8_pem(other_pair.private_key))
        self.store = root / "trust.json"
        add_trust(self.store, keys.export_public_spki_pem(pair.public_key), PACKAGE)
        self.artifact = root / "contoh-app.zip"
        self.artifact.write_bytes(b"PK\x03\x04release bytes\x00\xff")
        self.bundle, self.sbom, self.sbom_bundle = root / "release.json", root / "sbom.json", root / "sbom.bundle.json"
        sign(self.artifact, PACKAGE, VERSION, self.key, self.bundle)
        create_sbom(self.artifact, PACKAGE, VERSION, self.sbom, lock_path=ROOT / "uv.lock")
        sign_sbom(self.sbom, PACKAGE, VERSION, self.key, self.sbom_bundle)

    def verify(self, **overrides):
        args = {"artifact_path": self.artifact, "bundle_path": self.bundle, "sbom_path": self.sbom,
                "sbom_bundle_path": self.sbom_bundle, "trust_store_path": self.store,
                "expected_package": PACKAGE, "expected_version": VERSION, **overrides}
        return verify_release_with_sbom(**args)

    def edit_sbom(self, edit) -> None:
        data = json.loads(self.sbom.read_bytes())
        edit(data)
        self.sbom.write_bytes(serialize_sbom(data))


@pytest.fixture(params=keys.PROFILES)
def release(request, tmp_path, keypairs):
    profile = request.param
    other = keys.generate_keypair(profile)
    return Release(tmp_path, keypairs[profile], other)


def test_valid_release_and_sbom(release):
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == ("OK", None, 0)
    assert result.binding["match"] is True
    assert result.binding["artifact_sha256"] == result.binding["sbom_artifact_sha256"]
    assert result.artifact.valid and result.sbom.valid


def test_sbom_content_changed_after_signing(release):
    release.edit_sbom(lambda data: data["components"][0].update(version="0.0.1"))
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == ("ARTIFACT_MISMATCH", "sbom", 1)
    assert result.artifact.valid and result.binding is None


def test_sbom_hash_edited_after_signing(release):
    def edit(data):
        data["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
    release.edit_sbom(edit)
    assert (release.verify().status, release.verify().stage) == ("ARTIFACT_MISMATCH", "sbom")


def test_artifact_byte_changed(release):
    data = bytearray(release.artifact.read_bytes())
    data[4] ^= 0x01
    release.artifact.write_bytes(bytes(data))
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == ("ARTIFACT_MISMATCH", "artifact", 1)


def test_artifact_replaced_and_resigned_keeps_old_sbom(release):
    # The attacker holds a trusted key and re-signs a new artifact, but the SBOM
    # still names the original artifact: both bundles verify, the binding fails.
    release.artifact.write_bytes(b"PK\x03\x04replaced release bytes")
    sign(release.artifact, PACKAGE, VERSION, release.key, release.bundle)
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == (SBOM_MISMATCH, "binding", 1)
    assert result.artifact.valid and result.sbom.valid
    assert result.binding["match"] is False
    assert result.binding["artifact_sha256"] != result.binding["sbom_artifact_sha256"]


def test_valid_sbom_of_another_artifact(release, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "contoh-app.zip").write_bytes(b"another build with the same name")
    create_sbom(other / "contoh-app.zip", PACKAGE, VERSION, release.sbom)
    sign_sbom(release.sbom, PACKAGE, VERSION, release.key, release.sbom_bundle)
    result = release.verify()
    assert (result.status, result.stage) == (SBOM_MISMATCH, "binding")


def test_sbom_signed_by_untrusted_key(release):
    sign_sbom(release.sbom, PACKAGE, VERSION, release.other_key, release.sbom_bundle)
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == ("KEY_NOT_TRUSTED", "sbom", 1)


def test_signed_file_that_is_not_an_sbom(release):
    release.sbom.write_bytes(b'{"bomFormat": "SPDX"}\n')
    sign(release.sbom, PACKAGE, VERSION, release.key, release.sbom_bundle)
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == ("FORMAT_ERROR", "sbom", 1)


def test_missing_sbom_is_input_error(release):
    release.sbom.unlink()
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == ("INPUT_ERROR", "sbom", 2)


def test_input_error_takes_precedence_over_rejection(release):
    release.artifact.unlink()
    release.edit_sbom(lambda data: data.update(version=2))
    result = release.verify()
    assert (result.status, result.stage, result.exit_code) == ("INPUT_ERROR", "artifact", 2)


def test_expected_version_mismatch(release):
    result = release.verify(expected_version="2.0.0")
    assert (result.status, result.stage) == ("METADATA_MISMATCH", "artifact")


def test_sign_refuses_sbom_for_other_release(release, tmp_path):
    with pytest.raises(SbomError, match="describes contoh-app 1.0.0"):
        sign_sbom(release.sbom, PACKAGE, "2.0.0", release.key, tmp_path / "x.json")
    with pytest.raises(SbomError):
        release.sbom.write_bytes(b"not json")
        sign_sbom(release.sbom, PACKAGE, VERSION, release.key, tmp_path / "x.json")


def test_create_is_deterministic(tmp_path):
    artifact = tmp_path / "contoh-app.zip"
    artifact.write_bytes(b"same bytes")
    create_sbom(artifact, PACKAGE, VERSION, tmp_path / "a.json", lock_path=ROOT / "uv.lock")
    create_sbom(artifact, PACKAGE, VERSION, tmp_path / "b.json", lock_path=ROOT / "uv.lock")
    assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()
    with pytest.raises(ValueError, match="differ from the artifact"):
        create_sbom(artifact, PACKAGE, VERSION, artifact)


def test_lock_components_are_runtime_dependencies_only():
    names = [item["name"] for item in read_lock_components(ROOT / "uv.lock")]
    assert "cryptography" in names and "cffi" in names
    assert "pytest" not in names and "zhongli" not in names
    assert names == sorted(names)


@pytest.mark.parametrize("edit, message", [
    (lambda d: d.update(bomFormat="SPDX"), "bomFormat"),
    (lambda d: d.update(specVersion="1.5"), "specVersion"),
    (lambda d: d.update(version=True), "version"),
    (lambda d: d["metadata"]["component"].update(name="Bad Name"), "component.name"),
    (lambda d: d["metadata"]["component"]["hashes"].append({"alg": "SHA-256", "content": "a" * 64}), "exactly one"),
    (lambda d: d["metadata"]["component"]["hashes"][0].update(content="A" * 64), "SHA-256"),
    (lambda d: d["metadata"]["component"]["properties"].pop(), "exactly one"),
    (lambda d: d["metadata"]["component"]["properties"][1].update(value="-1"), "size"),
    (lambda d: d["metadata"]["component"]["properties"][0].update(value="../x"), "name"),
    (lambda d: d.update(components={}), "components"),
])
def test_parse_rejects_invalid_sbom(tmp_path, edit, message):
    artifact = tmp_path / "contoh-app.zip"
    artifact.write_bytes(b"x")
    create_sbom(artifact, PACKAGE, VERSION, tmp_path / "sbom.json")
    data = json.loads((tmp_path / "sbom.json").read_bytes())
    edit(data)
    with pytest.raises(SbomError, match=message):
        parse_sbom_strict(serialize_sbom(data))


def test_parse_rejects_duplicate_fields_and_bom():
    with pytest.raises(SbomError, match="Duplicate"):
        parse_sbom_strict(b'{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}')
    with pytest.raises(SbomError, match="BOM"):
        parse_sbom_strict(b"\xef\xbb\xbf{}")


def test_all_sbom_scenarios_pass(tmp_path):
    from sbom_scenarios import SCENARIOS, run, write_report

    out = tmp_path / "evidence"
    cases = run(out)
    write_report(out, cases)
    failed = [f"{c.id} {c.profile}: {c.actual_status}/{c.actual_stage} ({c.note})" for c in cases if not c.passed]
    assert not failed, "\n".join(failed)
    assert len(cases) == 3 * len(SCENARIOS)
    assert (out / "README.md").exists() and (out / "results.json").exists()


def _cli(*args, cwd):
    return subprocess.run([sys.executable, "-m", "zhongli", *args], cwd=cwd, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=120)


def test_cli_verify_json_and_exit_codes(release):
    common = ["sbom", "verify", "--file", "contoh-app.zip", "--bundle", "release.json", "--sbom", "sbom.json",
              "--sbom-bundle", "sbom.bundle.json", "--trust-store", "trust.json",
              "--package", PACKAGE, "--version", VERSION, "--json"]
    proc = _cli(*common, cwd=release.root)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert list(data) == ["valid", "status", "stage", "message", "artifact", "sbom", "binding"]
    assert data["valid"] is True and data["binding"]["match"] is True

    release.artifact.write_bytes(b"PK\x03\x04replaced")
    sign(release.artifact, PACKAGE, VERSION, release.key, release.bundle)
    proc = _cli(*common, cwd=release.root)
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["status"] == SBOM_MISMATCH
    assert proc.stdout.count(b"\n") == 1


def test_cli_usage_error_with_json_is_input_error(tmp_path):
    proc = _cli("sbom", "verify", "--file", "x", "--json", cwd=tmp_path)
    assert proc.returncode == 2
    data = json.loads(proc.stdout)
    assert (data["status"], data["stage"], data["valid"]) == ("INPUT_ERROR", None, False)


def test_cli_create_and_sign(tmp_path, keypairs):
    key = tmp_path / "k.key.pem"
    key.write_bytes(keys.export_private_pkcs8_pem(keypairs["ed25519"].private_key))
    (tmp_path / "contoh-app.zip").write_bytes(b"bytes")
    assert _cli("sbom", "create", "--file", "contoh-app.zip", "--package", PACKAGE, "--version", VERSION,
                "--out", "sbom.json", cwd=tmp_path).returncode == 0
    proc = _cli("sbom", "sign", "--sbom", "sbom.json", "--package", PACKAGE, "--version", VERSION,
                "--key", "k.key.pem", "--out", "sbom.bundle.json", cwd=tmp_path)
    assert proc.returncode == 0 and b"ed25519" in proc.stdout
    proc = _cli("sbom", "sign", "--sbom", "sbom.json", "--package", "other-app", "--version", VERSION,
                "--key", "k.key.pem", "--out", "x.json", cwd=tmp_path)
    assert proc.returncode == 2 and b"INPUT_ERROR" in proc.stderr


def test_cli_unknown_sbom_verify_option_is_json_input_error(tmp_path):
    proc = _cli("sbom", "verify", "--file", "x", "--bundle", "b", "--sbom", "s",
                "--sbom-bundle", "sb", "--trust-store", "t", "--package", "demo",
                "--version", "1.0", "--json", "--unknown", cwd=tmp_path)
    assert proc.returncode == 2 and proc.stdout.endswith(b"\n")
    data = json.loads(proc.stdout)
    assert data["status"] == "INPUT_ERROR" and data["valid"] is False and data["stage"] is None
