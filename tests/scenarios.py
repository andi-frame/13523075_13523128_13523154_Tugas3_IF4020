"""Run test scenarios U01-U14 and OpenSSL interoperability checks through the CLI.

Every case runs in its own directory that keeps all inputs it used and the
verifier's JSON output. ``results.json`` and ``README.md`` record the command
sequence, expected and actual status and exit code of each case.

    uv run python tests/scenarios.py --out evidence/scenarios

Manipulated bundles are built here with plain ``json``/``base64`` code rather
than the package's own serializers, so the program is tested against inputs it
did not produce itself.
"""

import argparse
import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib.metadata import version as package_version
import json
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PROFILES = {"rsa-pss-sha256": "rsa", "ecdsa-p256-sha256": "ecdsa", "ed25519": "ed25519"}
# RSA-PSS uses a random salt; RFC 6979 ECDSA and Ed25519 are deterministic.
DETERMINISTIC = {"rsa-pss-sha256": False, "ecdsa-p256-sha256": True, "ed25519": True}
PACKAGE, VERSION, ARTIFACT = "contoh-app", "1.0.0", "contoh-app.zip"
ARTIFACTS = {
    "text": b"contoh-app 1.0.0\r\nrelease notes\n",
    "binary": b"PK\x03\x04" + bytes(range(256)) * 4 + b"\x00\xff",
    "empty": b"",
}
EXIT_CODES = {"OK": 0, "INPUT_ERROR": 2}


class ScenarioError(RuntimeError):
    """A preparation step failed, so the case could not reach its check."""


@dataclass
class Case:
    id: str
    variant: str
    profile: str
    title: str
    expected_status: str
    expected_exit: int
    directory: str = ""
    steps: list[dict] = field(default_factory=list)
    actual_status: str | None = None
    actual_exit: int | None = None
    output: dict | None = None
    note: str = ""
    passed: bool = False


def canonical(manifest: dict) -> bytes:
    return json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def ecdsa_der_to_raw(der: bytes) -> bytes:
    """Decode a P-256 DER signature; short-form lengths suffice for 32-byte scalars."""
    if der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("not a DER SEQUENCE")
    raw, index = b"", 2
    for _ in range(2):
        if der[index] != 0x02:
            raise ValueError("expected INTEGER")
        length = der[index + 1]
        raw += int.from_bytes(der[index + 2:index + 2 + length], "big").to_bytes(32, "big")
        index += 2 + length
    return raw


def ecdsa_raw_to_der(raw: bytes) -> bytes:
    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\x00") or b"\x00"
        if value[0] & 0x80:
            value = b"\x00" + value
        return b"\x02" + bytes([len(value)]) + value
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


class Context:
    """Helpers for one case; commands run inside the case directory."""

    def __init__(self, case: Case, directory: Path, short: str):
        self.case, self.dir, self.short = case, directory, short
        self.key = f"../keys/{short}.key.pem"
        self.pub = f"../keys/{short}.pub.pem"

    def path(self, name: str) -> Path:
        return self.dir / name

    def _run(self, display: list[str], argv: list[str]) -> subprocess.CompletedProcess:
        proc = subprocess.run(argv, cwd=self.dir, capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
        self.case.steps.append({"command": shlex.join(display), "exit_code": proc.returncode})
        return proc

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        return self._run(["zhongli", *args], [sys.executable, "-m", "zhongli", *args])

    def openssl(self, *args: str) -> subprocess.CompletedProcess:
        return self._run(["openssl", *args], ["openssl", *args])

    def require(self, proc: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
        if proc.returncode != 0:
            raise ScenarioError(proc.stderr.decode(errors="replace").strip() or "command failed")
        return proc

    def write_artifact(self, content: bytes, name: str = ARTIFACT) -> None:
        self.path(name).write_bytes(content)

    def sign(self, out: str = "release.json", key: str | None = None, file: str = ARTIFACT) -> None:
        self.require(self.cli("sign", "--file", file, "--package", PACKAGE, "--version", VERSION,
                              "--key", key or self.key, "--out", out))

    def verify(self, file: str = ARTIFACT, bundle: str = "release.json", store: str = "trust.json",
               package: str = PACKAGE, version: str = VERSION, output: str = "verification.json") -> dict:
        proc = self.cli("verify", "--file", file, "--bundle", bundle, "--trust-store", store,
                        "--package", package, "--version", version, "--json")
        self.path(output).write_bytes(proc.stdout)
        data = json.loads(proc.stdout)
        self.case.actual_status, self.case.actual_exit, self.case.output = data["status"], proc.returncode, data
        return data

    def read_bundle(self, name: str = "release.json") -> tuple[bytes, bytes]:
        data = json.loads(self.path(name).read_bytes())
        return base64.b64decode(data["manifest_b64"]), base64.b64decode(data["signature_b64"])

    def write_bundle(self, manifest: bytes, signature: bytes, name: str = "release.json") -> None:
        self.path(name).write_text(json.dumps({
            "schema": "minisign-bundle/v1", "manifest_b64": b64(manifest), "signature_b64": b64(signature),
        }, separators=(",", ":")), newline="\n")

    def edit_manifest(self, edit) -> None:
        manifest_bytes, signature = self.read_bundle()
        manifest = json.loads(manifest_bytes)
        edit(manifest)
        self.write_bundle(canonical(manifest), signature)


# Scenario bodies. Each prepares inputs, then runs the final verify.

def u01(ctx: Context) -> None:
    ctx.write_artifact(ARTIFACTS[ctx.case.variant])
    ctx.sign()
    ctx.verify()


def u02(ctx: Context) -> None:
    ctx.sign()
    data = bytearray(ctx.path(ARTIFACT).read_bytes())
    data[len(data) // 2] ^= 0x01
    ctx.write_artifact(bytes(data))
    ctx.case.note = "One byte flipped; size and name unchanged."
    ctx.verify()


def u03(ctx: Context) -> None:
    ctx.sign()
    data = ctx.path(ARTIFACT).read_bytes()
    ctx.write_artifact(data + b"\x00" if ctx.case.variant == "append" else data[:-1])
    ctx.verify()


def u04(ctx: Context) -> None:
    ctx.sign()
    ctx.edit_manifest(lambda manifest: manifest.update(version="1.0.1"))
    ctx.case.note = "Canonical manifest with version 1.0.1, signature of the 1.0.0 manifest."
    ctx.verify(version="1.0.1")


def u05(ctx: Context) -> None:
    ctx.sign()
    manifest, signature = ctx.read_bundle()
    ctx.write_bundle(manifest, signature[:-1] + bytes([signature[-1] ^ 0x01]))
    ctx.case.note = f"Lowest bit of the last signature byte flipped; length stays {len(signature)} bytes."
    ctx.verify()


def u06(ctx: Context) -> None:
    ctx.sign()
    if ctx.case.variant == "empty-store":
        ctx.path("trust.json").write_text('{"schema":"minisign-trust/v1","keys":[]}\n', newline="\n")
    else:
        keyid = json.loads(ctx.read_bundle()[0])["keyid"]
        ctx.require(ctx.cli("trust", "remove", "--keyid", keyid, "--store", "trust.json"))
    ctx.verify()


def u07(ctx: Context) -> None:
    ctx.path("trust.json").unlink()
    ctx.require(ctx.cli("trust", "add", "--key", ctx.pub, "--package", "other-app", "--store", "trust.json"))
    ctx.sign()
    ctx.verify()


def u08(ctx: Context) -> None:
    ctx.sign()
    ctx.verify(version="1.0.1")


def u09(ctx: Context) -> None:
    ctx.sign()
    shutil.copyfile(ctx.path(ARTIFACT), ctx.path("contoh-app-renamed.zip"))
    ctx.verify(file="contoh-app-renamed.zip")


def u10(ctx: Context) -> None:
    ctx.sign()
    manifest, signature = ctx.read_bundle()
    variant = ctx.case.variant
    if variant == "duplicate-bundle-field":
        ctx.path("release.json").write_text(
            '{"schema":"minisign-bundle/v1","schema":"minisign-bundle/v1",'
            f'"manifest_b64":"{b64(manifest)}","signature_b64":"{b64(signature)}"}}', newline="\n")
    elif variant == "duplicate-manifest-field":
        duplicated = manifest.replace(b'"package":"contoh-app",', b'"package":"contoh-app","package":"contoh-app",', 1)
        ctx.write_bundle(duplicated, signature)
    elif variant == "wrong-type":
        ctx.edit_manifest(lambda m: m["artifact"].update(size=str(m["artifact"]["size"])))
        ctx.case.note = 'artifact.size stored as a JSON string, e.g. "1030".'
    elif variant == "invalid-base64":
        encoded = b64(signature)
        ctx.path("release.json").write_text(json.dumps({
            "schema": "minisign-bundle/v1", "manifest_b64": b64(manifest),
            "signature_b64": "-" + encoded[1:],
        }), newline="\n")
        ctx.case.note = "First signature_b64 character replaced by '-', which is outside the RFC 4648 alphabet."
    elif variant == "oversized-manifest":
        oversized = manifest[:-1] + b" " * (16 * 1024 - len(manifest) + 1) + b"}"
        ctx.write_bundle(oversized, signature)
        ctx.case.note = f"Manifest padded to {len(oversized)} bytes (limit 16384)."
    ctx.verify()


def u11(ctx: Context) -> None:
    ctx.sign()
    ctx.edit_manifest(lambda manifest: manifest.update(algorithm="rsa-pss-sha512"))
    ctx.verify()


def u12(ctx: Context) -> None:
    ctx.require(ctx.cli("keygen", "--algorithm", ctx.case.profile, "--out", "TEST_ONLY_other"))
    ctx.sign(key="TEST_ONLY_other.key.pem")
    ctx.case.note = "Bundle keyid is the fingerprint of TEST_ONLY_other.pub.pem, which is not in trust.json."
    ctx.verify()


def u13(ctx: Context) -> None:
    ctx.sign()
    original = json.loads(ctx.path("release.json").read_bytes())
    reordered = {name: original[name] for name in ("signature_b64", "schema", "manifest_b64")}
    ctx.path("release.json").write_text("\n  " + json.dumps(reordered, indent="\t") + "\r\n\n", newline="")
    ctx.case.note = "Field order reversed, tab indentation and surrounding whitespace; Base64 strings unchanged."
    ctx.verify()


def u14(ctx: Context) -> bool:
    ctx.sign(out="first.json")
    ctx.sign(out="second.json")
    first = ctx.verify(bundle="first.json", output="first.verification.json")
    second = ctx.verify(bundle="second.json", output="second.verification.json")
    (m1, s1), (m2, s2) = ctx.read_bundle("first.json"), ctx.read_bundle("second.json")
    identical = s1 == s2
    expected = DETERMINISTIC[ctx.case.profile]
    reason = {
        "rsa-pss-sha256": "RSA-PSS draws a fresh 32-byte random salt for every signature",
        "ecdsa-p256-sha256": "RFC 6979 derives the nonce from the private key and the message digest",
        "ed25519": "Ed25519 derives the nonce from the private key and the message (RFC 8032)",
    }[ctx.case.profile]
    ctx.case.note = (f"Manifests identical: {m1 == m2}; signatures identical: {identical}. {reason}. "
                     f"Both verifications: {first['status']}, {second['status']}.")
    return m1 == m2 and identical == expected and first["status"] == "OK"


def interop_openssl_verifies(ctx: Context) -> None:
    """Our CLI signs; the OpenSSL CLI verifies the manifest bytes from the bundle."""
    ctx.sign()
    manifest, signature = ctx.read_bundle()
    ctx.path("manifest.bin").write_bytes(manifest)
    profile = ctx.case.profile
    if profile == "ecdsa-p256-sha256":
        ctx.path("signature.der").write_bytes(ecdsa_raw_to_der(signature))
        proc = ctx.openssl("dgst", "-sha256", "-verify", ctx.pub, "-signature", "signature.der", "manifest.bin")
    elif profile == "rsa-pss-sha256":
        ctx.path("signature.bin").write_bytes(signature)
        proc = ctx.openssl("dgst", "-sha256", "-verify", ctx.pub, "-signature", "signature.bin",
                           "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
                           "-sigopt", "rsa_mgf1_md:sha256", "manifest.bin")
    else:
        ctx.path("signature.bin").write_bytes(signature)
        proc = ctx.openssl("pkeyutl", "-verify", "-pubin", "-inkey", ctx.pub, "-rawin",
                           "-in", "manifest.bin", "-sigfile", "signature.bin")
    ctx.case.actual_status, ctx.case.actual_exit = ("OK" if proc.returncode == 0 else "REJECTED"), proc.returncode
    ctx.case.note = proc.stdout.decode(errors="replace").strip()


def interop_cli_verifies(ctx: Context) -> None:
    """The OpenSSL CLI signs the manifest bytes; our CLI verifies the resulting bundle."""
    ctx.sign(out="reference.json")
    manifest, _ = ctx.read_bundle("reference.json")
    ctx.path("manifest.bin").write_bytes(manifest)
    profile = ctx.case.profile
    if profile == "ecdsa-p256-sha256":
        ctx.require(ctx.openssl("dgst", "-sha256", "-sign", ctx.key, "-out", "openssl.sig.der", "manifest.bin"))
        signature = ecdsa_der_to_raw(ctx.path("openssl.sig.der").read_bytes())
    elif profile == "rsa-pss-sha256":
        ctx.require(ctx.openssl("dgst", "-sha256", "-sign", ctx.key, "-sigopt", "rsa_padding_mode:pss",
                                "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256",
                                "-out", "openssl.sig", "manifest.bin"))
        signature = ctx.path("openssl.sig").read_bytes()
    else:
        ctx.require(ctx.openssl("pkeyutl", "-sign", "-inkey", ctx.key, "-rawin", "-in", "manifest.bin",
                                "-out", "openssl.sig"))
        signature = ctx.path("openssl.sig").read_bytes()
    ctx.write_bundle(manifest, signature)
    ctx.case.note = f"Signature produced by OpenSSL ({len(signature)} bytes after conversion)."
    ctx.verify()


SCENARIOS = [
    ("U01", "text", "Sign and verify a text artifact", "OK", u01),
    ("U01", "binary", "Sign and verify a binary artifact", "OK", u01),
    ("U01", "empty", "Sign and verify an empty artifact", "OK", u01),
    ("U02", "", "One artifact byte changed, same size and name", "ARTIFACT_MISMATCH", u02),
    ("U03", "append", "One byte appended to the artifact", "ARTIFACT_MISMATCH", u03),
    ("U03", "truncate", "Last artifact byte removed", "ARTIFACT_MISMATCH", u03),
    ("U04", "", "Manifest version changed, old signature kept", "INVALID_SIGNATURE", u04),
    ("U05", "", "One signature bit flipped, valid Base64 and length", "INVALID_SIGNATURE", u05),
    ("U06", "empty-store", "Empty trust store", "KEY_NOT_TRUSTED", u06),
    ("U06", "removed-key", "Publisher key removed with trust remove", "KEY_NOT_TRUSTED", u06),
    ("U07", "", "Key trusted only for another package", "KEY_NOT_TRUSTED", u07),
    ("U08", "", "Valid bundle, different expected version", "METADATA_MISMATCH", u08),
    ("U09", "", "Artifact renamed, content unchanged", "METADATA_MISMATCH", u09),
    ("U10", "duplicate-bundle-field", "Duplicate field in the bundle", "FORMAT_ERROR", u10),
    ("U10", "duplicate-manifest-field", "Duplicate field in the manifest", "FORMAT_ERROR", u10),
    ("U10", "wrong-type", "Wrong data type in the manifest", "FORMAT_ERROR", u10),
    ("U10", "invalid-base64", "Invalid Base64 in the bundle", "FORMAT_ERROR", u10),
    ("U10", "oversized-manifest", "Manifest larger than 16 KiB", "FORMAT_ERROR", u10),
    ("U11", "", "Unsupported algorithm string in the manifest", "UNSUPPORTED_ALGORITHM", u11),
    ("U12", "", "Signed by another key of the same profile", "KEY_NOT_TRUSTED", u12),
    ("U13", "", "Bundle whitespace and field order changed", "OK", u13),
    ("U14", "", "Same manifest signed twice", "OK", u14),
    ("INT", "openssl-verifies", "OpenSSL CLI verifies a bundle signed by this program", "OK", interop_openssl_verifies),
    ("INT", "openssl-signs", "This program verifies a manifest signed by the OpenSSL CLI", "OK", interop_cli_verifies),
]


def _prepare_keys(out: Path) -> None:
    keys = out / "keys"
    keys.mkdir(parents=True)
    for profile, short in PROFILES.items():
        for suffix in ("key.pem", "pub.pem"):
            shutil.copyfile(FIXTURES / short / f"TEST_ONLY.{suffix}", keys / f"{short}.{suffix}")
        proc = subprocess.run([sys.executable, "-m", "zhongli", "trust", "add", "--key", f"{short}.pub.pem",
                               "--package", PACKAGE, "--store", f"{short}.trust.json"],
                              cwd=keys, capture_output=True, stdin=subprocess.DEVNULL)
        if proc.returncode != 0:
            raise ScenarioError(proc.stderr.decode(errors="replace"))


def run_scenarios(out: Path) -> list[Case]:
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} is not empty; use a new directory")
    _prepare_keys(out)
    has_openssl = shutil.which("openssl") is not None
    cases = []
    for profile, short in PROFILES.items():
        for scenario_id, variant, title, status, body in SCENARIOS:
            if scenario_id == "INT" and not has_openssl:
                continue
            case = Case(scenario_id, variant, profile, title, status, EXIT_CODES.get(status, 1))
            name = "-".join(filter(None, (scenario_id, variant, short)))
            directory = out / name
            directory.mkdir()
            case.directory = name
            shutil.copyfile(out / "keys" / f"{short}.trust.json", directory / "trust.json")
            (directory / ARTIFACT).write_bytes(ARTIFACTS["binary"])
            ctx = Context(case, directory, short)
            try:
                extra = body(ctx)
                case.passed = (case.actual_status == case.expected_status
                               and case.actual_exit == case.expected_exit and extra is not False)
            except (ScenarioError, ValueError, KeyError, subprocess.SubprocessError) as exc:
                case.note = f"Scenario could not run: {exc}"
            cases.append(case)
    return cases


def _environment() -> dict:
    openssl = shutil.which("openssl")
    openssl_version = subprocess.run([openssl, "version"], capture_output=True, text=True).stdout.strip() \
        if openssl else None
    return {"python": platform.python_version(), "platform": platform.platform(),
            "zhongli": package_version("zhongli"),
            "cryptography": package_version("cryptography"), "openssl_cli": openssl_version}


def write_report(out: Path, cases: list[Case]) -> None:
    environment = _environment()
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    (out / "results.json").write_text(json.dumps({
        "generated_at": generated, "environment": environment, "cases": [asdict(case) for case in cases],
    }, indent=2) + "\n", newline="\n")
    passed = sum(case.passed for case in cases)
    lines = [
        "# Test scenario evidence",
        "",
        "Generated by `tests/scenarios.py`; do not edit by hand. Reproduce with:",
        "",
        "```sh",
        "uv run python tests/scenarios.py --out <new-directory>",
        "```",
        "",
        f"Generated {generated} on {environment['platform']}, Python {environment['python']}, "
        f"zhongli {environment['zhongli']}, cryptography {environment['cryptography']}, "
        f"OpenSSL CLI: {environment['openssl_cli'] or 'not available'}.",
        "",
        "Each case directory holds its inputs (artifact, bundle, trust store) and the verifier output "
        "(`verification.json`). Keys in `keys/` are copies of the TEST_ONLY fixtures and must never be "
        "used outside tests. Commands are recorded relative to the case directory in `results.json`.",
        "",
        f"**{passed} of {len(cases)} cases passed.**",
        "",
        "| ID | Variant | Profile | Scenario | Expected | Actual | Result | Directory |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for case in cases:
        actual = f"{case.actual_status} / {case.actual_exit}" if case.actual_status else "-"
        lines.append(f"| {case.id} | {case.variant or '-'} | `{case.profile}` | {case.title} | "
                     f"{case.expected_status} / {case.expected_exit} | {actual} | "
                     f"{'pass' if case.passed else 'FAIL'} | [`{case.directory}`]({case.directory}/) |")
    notes = [case for case in cases if case.note]
    if notes:
        lines += ["", "## Notes", ""]
        lines += [f"- **{case.id} {case.variant} `{case.profile}`**: {case.note}" for case in notes]
    (out / "README.md").write_text("\n".join(lines) + "\n", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True, help="new, empty output directory")
    args = parser.parse_args()
    cases = run_scenarios(args.out)
    write_report(args.out, cases)
    failed = [case for case in cases if not case.passed]
    print(f"{len(cases) - len(failed)} of {len(cases)} cases passed; report in {args.out / 'README.md'}")
    for case in failed:
        print(f"FAIL {case.id} {case.variant} {case.profile}: {case.note or case.actual_status}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
