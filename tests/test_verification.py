import base64
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from if4020_signing import keys
from if4020_signing.formats import BUNDLE_LIMIT, parse_bundle_strict, parse_manifest_strict, serialize_manifest
from if4020_signing.signing import sign
from if4020_signing.trust import add_trust
from if4020_signing.verification import Status, verify

CLI = "if4020-signing"
PROFILES = keys.PROFILES
RESULT_FIELDS = ["valid", "status", "message", "algorithm", "keyid", "package", "version"]


@pytest.fixture(scope="module")
def keypairs():
    return {profile: keys.generate_keypair(profile) for profile in PROFILES}


@dataclass
class Release:
    root: Path
    artifact: Path
    bundle: Path
    store: Path
    profile: str
    pair: object
    package: str = "contoh-app"
    version: str = "1.0.0"

    @property
    def keyid(self) -> str:
        return keys.fingerprint(self.pair.public_key)

    def verify(self, **overrides):
        args = {"artifact_path": self.artifact, "bundle_path": self.bundle, "trust_store_path": self.store,
                "expected_package": self.package, "expected_version": self.version, **overrides}
        return verify(**args)

    def parts(self) -> tuple[bytes, bytes]:
        return parse_bundle_strict(self.bundle.read_bytes())

    def write_bundle(self, manifest: bytes, signature: bytes) -> None:
        """Write a bundle without validating it, so tests can store malformed parts."""
        self.bundle.write_text(json.dumps({
            "schema": "minisign-bundle/v1",
            "manifest_b64": base64.b64encode(manifest).decode(),
            "signature_b64": base64.b64encode(signature).decode(),
        }))


@pytest.fixture
def make_release(tmp_path, keypairs):
    def make(profile: str, content: bytes = b"release\x00\xff\r\n") -> Release:
        root = tmp_path / profile
        root.mkdir()
        pair = keypairs[profile]
        adapter = keys.adapter_for_profile(profile)
        key = root / "publisher.key.pem"
        key.write_bytes(adapter.export_private_pkcs8_pem(pair.private_key))
        artifact = root / "contoh-app.zip"
        artifact.write_bytes(content)
        store = root / "trust.json"
        add_trust(store, adapter.export_public_spki_pem(pair.public_key), "contoh-app")
        bundle = root / "release.json"
        sign(artifact, "contoh-app", "1.0.0", key, bundle)
        return Release(root, artifact, bundle, store, profile, pair)
    return make


def _replace_manifest_field(release: Release, path: tuple[str, ...], value) -> None:
    manifest_bytes, signature = release.parts()
    manifest = parse_manifest_strict(manifest_bytes)
    target = manifest
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    release.write_bundle(serialize_manifest(manifest), signature)


@pytest.mark.parametrize("profile", PROFILES)
def test_valid_release(make_release, profile):
    release = make_release(profile)
    before = (release.artifact.read_bytes(), release.store.read_bytes())
    result = release.verify()
    assert result.status is Status.OK and result.valid and result.exit_code == 0
    assert (result.algorithm, result.keyid, result.package, result.version) == \
        (profile, release.keyid, "contoh-app", "1.0.0")
    # Verification never modifies the artifact or the trust store.
    assert (release.artifact.read_bytes(), release.store.read_bytes()) == before


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("content", [b"plain text release\n", bytes(range(256)) * 16, b""],
                         ids=["text", "binary", "empty"])
def test_u01_text_binary_empty(make_release, profile, content):
    assert make_release(profile, content).verify().status is Status.OK


@pytest.mark.parametrize("profile", PROFILES)
def test_u05_signature_bit_flip(make_release, profile):
    release = make_release(profile)
    manifest, signature = release.parts()
    tampered = signature[:-1] + bytes([signature[-1] ^ 0x01])
    release.write_bundle(manifest, tampered)
    stored = json.loads(release.bundle.read_bytes())["signature_b64"]
    assert len(base64.b64decode(stored)) == len(signature)
    result = release.verify()
    assert result.status is Status.INVALID_SIGNATURE and result.exit_code == 1 and not result.valid


@pytest.mark.parametrize("profile", PROFILES)
def test_u08_expected_version_differs(make_release, profile):
    result = make_release(profile).verify(expected_version="1.0.1")
    assert result.status is Status.METADATA_MISMATCH and result.exit_code == 1
    # Metadata is reported for diagnostics only.
    assert result.version == "1.0.0"


@pytest.mark.parametrize("profile", PROFILES)
def test_u09_renamed_artifact(make_release, profile):
    release = make_release(profile)
    renamed = release.root / "contoh-app-renamed.zip"
    shutil.copyfile(release.artifact, renamed)
    result = release.verify(artifact_path=renamed)
    assert result.status is Status.METADATA_MISMATCH and "artifact name" in result.message


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("algorithm", ["rsa-pss-sha512", "ed448", "ECDSA-P256-SHA256", ""])
def test_u11_unsupported_algorithm(make_release, profile, algorithm):
    release = make_release(profile)
    _replace_manifest_field(release, ("algorithm",), algorithm)
    result = release.verify()
    assert result.status is Status.UNSUPPORTED_ALGORITHM and result.exit_code == 1
    assert result.algorithm == algorithm


@pytest.mark.parametrize("profile", PROFILES)
def test_artifact_content_changes(make_release, profile):
    release = make_release(profile)
    original = release.artifact.read_bytes()
    for changed in (bytes([original[0] ^ 1]) + original[1:], original + b"!", original[:-1]):
        release.artifact.write_bytes(changed)
        assert release.verify().status is Status.ARTIFACT_MISMATCH


@pytest.mark.parametrize("profile", PROFILES)
def test_changed_manifest_with_old_signature(make_release, profile):
    release = make_release(profile)
    _replace_manifest_field(release, ("version",), "1.0.1")
    assert release.verify(expected_version="1.0.1").status is Status.INVALID_SIGNATURE


@pytest.mark.parametrize("profile", PROFILES)
def test_trust_failures(make_release, keypairs, profile):
    release = make_release(profile)
    release.store.write_text('{"schema":"minisign-trust/v1","keys":[]}')
    assert release.verify().status is Status.KEY_NOT_TRUSTED
    release.store.unlink()
    adapter = keys.adapter_for_profile(profile)
    add_trust(release.store, adapter.export_public_spki_pem(release.pair.public_key), "other-app")
    assert release.verify().status is Status.KEY_NOT_TRUSTED


def test_trusted_key_with_other_profile_is_not_trusted(make_release):
    # The keyid names a trusted Ed25519 key, but the manifest claims RSA-PSS.
    release = make_release("ed25519")
    _replace_manifest_field(release, ("algorithm",), "rsa-pss-sha256")
    result = release.verify()
    assert result.status is Status.KEY_NOT_TRUSTED and "profile" in result.message


@pytest.mark.parametrize("length", [0, 32, 63, 65, 383])
def test_wrong_signature_length_is_invalid_signature(make_release, length):
    release = make_release("ecdsa-p256-sha256")
    manifest, _ = release.parts()
    release.write_bundle(manifest, b"\x01" * length)
    assert release.verify().status is Status.INVALID_SIGNATURE


def test_ecdsa_out_of_range_components_are_invalid_signature(make_release):
    release = make_release("ecdsa-p256-sha256")
    manifest, _ = release.parts()
    release.write_bundle(manifest, bytes(64))
    assert release.verify().status is Status.INVALID_SIGNATURE


@pytest.mark.parametrize("bundle", [
    b"{broken",
    b'{"schema":"minisign-bundle/v1","schema":"minisign-bundle/v1","manifest_b64":"","signature_b64":""}',
    b'{"schema":"minisign-bundle/v1","manifest_b64":"e30=","signature_b64":"AA=="}',
    b'{"schema":"minisign-bundle/v1","manifest_b64":"!!","signature_b64":"AA=="}',
    b" " * (BUNDLE_LIMIT + 1),
], ids=["json", "duplicate", "manifest-schema", "base64", "oversize"])
def test_malformed_bundle_is_format_error(make_release, bundle):
    release = make_release("ed25519")
    release.bundle.write_bytes(bundle)
    result = release.verify()
    assert result.status is Status.FORMAT_ERROR
    assert (result.algorithm, result.keyid, result.package, result.version) == (None,) * 4


def test_invalid_trust_store_is_format_error_and_reports_manifest(make_release):
    release = make_release("ed25519")
    data = json.loads(release.store.read_bytes())
    data["keys"][0]["keyid"] = "0" * 64
    release.store.write_text(json.dumps(data))
    result = release.verify()
    assert result.status is Status.FORMAT_ERROR and result.algorithm == "ed25519"


def test_check_order(make_release):
    release = make_release("ed25519")
    manifest_bytes, signature = release.parts()
    manifest = parse_manifest_strict(manifest_bytes)

    # INPUT_ERROR precedes FORMAT_ERROR.
    release.bundle.write_bytes(b"{broken")
    assert release.verify(artifact_path=release.root / "missing.zip").status is Status.INPUT_ERROR

    # FORMAT_ERROR precedes UNSUPPORTED_ALGORITHM.
    manifest["algorithm"] = "unknown"
    release.write_bundle(json.dumps(manifest).encode(), signature)
    assert release.verify().status is Status.FORMAT_ERROR

    # UNSUPPORTED_ALGORITHM precedes KEY_NOT_TRUSTED.
    release.write_bundle(serialize_manifest(manifest), signature)
    release.store.write_text('{"schema":"minisign-trust/v1","keys":[]}')
    assert release.verify().status is Status.UNSUPPORTED_ALGORITHM

    # KEY_NOT_TRUSTED precedes INVALID_SIGNATURE.
    release.write_bundle(manifest_bytes, bytes(64))
    assert release.verify().status is Status.KEY_NOT_TRUSTED

    # INVALID_SIGNATURE precedes METADATA_MISMATCH.
    adapter = keys.adapter_for_profile("ed25519")
    release.store.unlink()
    add_trust(release.store, adapter.export_public_spki_pem(release.pair.public_key), "contoh-app")
    assert release.verify(expected_version="9.9.9").status is Status.INVALID_SIGNATURE

    # METADATA_MISMATCH precedes ARTIFACT_MISMATCH.
    release.write_bundle(manifest_bytes, signature)
    release.artifact.write_bytes(b"different")
    assert release.verify(expected_version="9.9.9").status is Status.METADATA_MISMATCH
    assert release.verify().status is Status.ARTIFACT_MISMATCH


@pytest.mark.parametrize("missing", ["artifact_path", "bundle_path", "trust_store_path"])
def test_unreadable_inputs_are_input_errors(make_release, missing):
    release = make_release("ed25519")
    result = release.verify(**{missing: release.root / "missing"})
    assert result.status is Status.INPUT_ERROR and result.exit_code == 2
    assert "missing" in result.message


def test_directory_as_artifact_is_input_error(make_release):
    release = make_release("ed25519")
    assert release.verify(artifact_path=release.root).status is Status.INPUT_ERROR


@pytest.mark.parametrize("overrides", [{"expected_package": "Contoh App"}, {"expected_package": "*"},
                                       {"expected_version": ""}, {"expected_version": "1.0/1"}])
def test_malformed_expectations_are_input_errors(make_release, overrides):
    assert make_release("ed25519").verify(**overrides).status is Status.INPUT_ERROR


def run(*args, timeout=60):
    return subprocess.run([CLI, *map(str, args)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout)


def _verify_args(release: Release, **overrides) -> list:
    options = {"--file": release.artifact, "--bundle": release.bundle, "--trust-store": release.store,
               "--package": release.package, "--version": release.version, **overrides}
    return ["verify", *[item for pair in options.items() for item in pair]]


@pytest.mark.parametrize("profile", PROFILES)
def test_cli_json_success(make_release, profile):
    release = make_release(profile)
    result = run(*_verify_args(release), "--json")
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("}\n") and result.stdout.count("\n") == 1
    data = json.loads(result.stdout)
    assert list(data) == RESULT_FIELDS
    assert data == {"valid": True, "status": "OK", "message": data["message"], "algorithm": profile,
                    "keyid": release.keyid, "package": "contoh-app", "version": "1.0.0"}
    assert result.stderr == ""


def test_cli_json_rejection(make_release):
    release = make_release("ecdsa-p256-sha256")
    result = run(*_verify_args(release, **{"--version": "2.0.0"}), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert list(data) == RESULT_FIELDS
    assert data["valid"] is False and data["status"] == "METADATA_MISMATCH"
    assert "METADATA_MISMATCH" in result.stderr


def test_cli_json_input_error_has_null_metadata(make_release):
    release = make_release("ed25519")
    result = run(*_verify_args(release, **{"--file": release.root / "missing.zip"}), "--json")
    assert result.returncode == 2
    data = json.loads(result.stdout)
    assert data["status"] == "INPUT_ERROR" and data["valid"] is False
    assert [data[name] for name in RESULT_FIELDS[3:]] == [None] * 4


def test_cli_json_usage_error_is_reported_as_json(make_release):
    release = make_release("ed25519")
    result = run("verify", "--bundle", release.bundle, "--json")
    assert result.returncode == 2
    data = json.loads(result.stdout)
    assert data["status"] == "INPUT_ERROR" and "--file" in data["message"]
    assert "usage:" in result.stderr


def test_cli_plain_output(make_release):
    release = make_release("rsa-pss-sha256")
    result = run(*_verify_args(release))
    assert result.returncode == 0 and result.stdout.startswith("OK:") and release.keyid in result.stdout
    release.artifact.write_bytes(b"tampered")
    result = run(*_verify_args(release))
    assert result.returncode == 1 and result.stdout == "" and result.stderr.startswith("ARTIFACT_MISMATCH:")


@pytest.mark.parametrize("args", [
    ["verify"], ["verify", "--file", "a"], [], ["unknown"],
    ["verify", "--file", "a", "--bundle", "b", "--trust-store", "c", "--pack", "d", "--version", "1"],
], ids=["no-options", "partial", "no-command", "unknown-command", "abbreviated-option"])
def test_cli_usage_errors_exit_2_without_prompting(args):
    result = run(*args, timeout=30)
    assert result.returncode == 2 and result.stdout == "" and "usage:" in result.stderr


def test_cli_help_and_version():
    for option in ("--help", "--version"):
        result = run(option)
        assert result.returncode == 0 and result.stdout.strip()
    assert "verify" in run("--help").stdout
    assert "--trust-store" in run("verify", "--help").stdout


def test_python_module_entry_point():
    import sys
    result = subprocess.run([sys.executable, "-m", "if4020_signing", "--version"],
                            capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.startswith("if4020-signing ")
