"""Run the signed-SBOM scenarios S01-S08 through the CLI for all three profiles.

Each case directory keeps the artifact, both bundles, the SBOM, the trust store
and the ``sbom verify --json`` output. ``results.json`` and ``README.md`` record
the commands, the expected and actual status, stage and exit code.

    uv run python tests/sbom_scenarios.py --out evidence/sbom
"""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys

from scenarios import (
    ARTIFACT, PACKAGE, PROFILES, VERSION, Case, Context, ScenarioError, _environment, _prepare_keys,
)

LOCK = Path(__file__).resolve().parents[1] / "uv.lock"


@dataclass
class SbomCase(Case):
    expected_stage: str | None = None
    actual_stage: str | None = None


class SbomContext(Context):
    def sbom_create(self, file: str = ARTIFACT, out: str = "sbom.json", lock: bool = True) -> None:
        args = ["sbom", "create", "--file", file, "--package", PACKAGE, "--version", VERSION, "--out", out]
        if lock:
            args += ["--lock", "../uv.lock"]
        self.require(self.cli(*args))

    def sbom_sign(self, sbom: str = "sbom.json", out: str = "sbom.bundle.json", key: str | None = None) -> None:
        self.require(self.cli("sbom", "sign", "--sbom", sbom, "--package", PACKAGE, "--version", VERSION,
                              "--key", key or self.key, "--out", out))

    def sbom_verify(self) -> dict:
        proc = self.cli("sbom", "verify", "--file", ARTIFACT, "--bundle", "release.json", "--sbom", "sbom.json",
                        "--sbom-bundle", "sbom.bundle.json", "--trust-store", "trust.json",
                        "--package", PACKAGE, "--version", VERSION, "--json")
        self.path("verification.json").write_bytes(proc.stdout)
        data = json.loads(proc.stdout)
        self.case.actual_status, self.case.actual_exit, self.case.output = data["status"], proc.returncode, data
        self.case.actual_stage = data["stage"]
        return data

    def signed_release(self) -> None:
        self.sign()
        self.sbom_create()
        self.sbom_sign()


def s01(ctx):
    ctx.signed_release()
    ctx.sbom_verify()


def s02(ctx):
    ctx.signed_release()
    data = json.loads(ctx.path("sbom.json").read_bytes())
    data["components"][0]["version"] = "0.0.1"
    ctx.path("sbom.json").write_text(json.dumps(data, indent=2) + "\n", newline="\n")
    ctx.case.note = "Version of the first component changed in sbom.json after sbom sign."
    ctx.sbom_verify()


def s03(ctx):
    ctx.signed_release()
    data = bytearray(ctx.path(ARTIFACT).read_bytes())
    data[len(data) // 2] ^= 0x01
    ctx.path(ARTIFACT).write_bytes(bytes(data))
    ctx.case.note = "One artifact byte flipped after signing; size and name unchanged."
    ctx.sbom_verify()


def s04(ctx):
    ctx.signed_release()
    ctx.write_artifact(b"PK\x03\x04replacement build" * 8)
    ctx.sign()
    ctx.case.note = ("Artifact replaced and release.json re-signed with the trusted key; sbom.json and "
                     "sbom.bundle.json still describe the original artifact.")
    ctx.sbom_verify()


def s05(ctx):
    ctx.signed_release()
    (ctx.path("other") / ARTIFACT).parent.mkdir()
    (ctx.path("other") / ARTIFACT).write_bytes(b"another build with the same file name")
    ctx.sbom_create(file=f"other/{ARTIFACT}")
    ctx.sbom_sign()
    ctx.case.note = "sbom.json was created and signed for another artifact with the same name and version."
    ctx.sbom_verify()


def s06(ctx):
    ctx.signed_release()
    ctx.require(ctx.cli("keygen", "--algorithm", ctx.case.profile, "--out", "TEST_ONLY_other"))
    ctx.sbom_sign(key="TEST_ONLY_other.key.pem")
    ctx.case.note = "sbom.bundle.json signed with a key that is not in trust.json."
    ctx.sbom_verify()


def s07(ctx):
    ctx.sign()
    ctx.path("sbom.json").write_text('{"bomFormat": "SPDX", "spdxVersion": "SPDX-2.3"}\n', newline="\n")
    ctx.sign(out="sbom.bundle.json", file="sbom.json")
    ctx.case.note = "A JSON file that is not a CycloneDX SBOM, signed with plain sign by the trusted key."
    ctx.sbom_verify()


def s08(ctx):
    ctx.signed_release()
    ctx.path("sbom.json").unlink()
    ctx.sbom_verify()


# (id, title, expected status, expected stage, body)
SCENARIOS = [
    ("S01", "Release and SBOM signed by the trusted key", "OK", None, s01),
    ("S02", "SBOM content changed after signing", "ARTIFACT_MISMATCH", "sbom", s02),
    ("S03", "One release artifact byte changed", "ARTIFACT_MISMATCH", "artifact", s03),
    ("S04", "Artifact replaced and re-signed, old SBOM kept", "SBOM_MISMATCH", "binding", s04),
    ("S05", "Valid SBOM of another artifact", "SBOM_MISMATCH", "binding", s05),
    ("S06", "SBOM signed by an untrusted key", "KEY_NOT_TRUSTED", "sbom", s06),
    ("S07", "Signed file is not a CycloneDX SBOM", "FORMAT_ERROR", "sbom", s07),
    ("S08", "SBOM file missing", "INPUT_ERROR", "sbom", s08),
]
EXIT_CODES = {"OK": 0, "INPUT_ERROR": 2}


def run(out: Path) -> list[SbomCase]:
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} is not empty; use a new directory")
    _prepare_keys(out)
    shutil.copyfile(LOCK, out / "uv.lock")
    cases = []
    for profile, short in PROFILES.items():
        for scenario_id, title, status, stage, body in SCENARIOS:
            case = SbomCase(scenario_id, "", profile, title, status, EXIT_CODES.get(status, 1),
                            expected_stage=stage)
            case.directory = f"{scenario_id}-{short}"
            directory = out / case.directory
            directory.mkdir()
            shutil.copyfile(out / "keys" / f"{short}.trust.json", directory / "trust.json")
            ctx = SbomContext(case, directory, short)
            ctx.write_artifact(b"PK\x03\x04" + bytes(range(256)) * 4)
            try:
                body(ctx)
                case.passed = (case.actual_status, case.actual_stage, case.actual_exit) == (
                    status, stage, case.expected_exit)
            except (ScenarioError, ValueError, KeyError, OSError) as exc:
                case.note = f"Scenario could not run: {exc}"
            cases.append(case)
    return cases


def write_report(out: Path, cases: list[SbomCase]) -> None:
    environment = _environment()
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    (out / "results.json").write_text(json.dumps({
        "generated_at": generated, "environment": environment, "cases": [asdict(case) for case in cases],
    }, indent=2) + "\n", newline="\n")
    passed = sum(case.passed for case in cases)
    lines = [
        "# Signed SBOM scenario evidence",
        "",
        "Generated by `tests/sbom_scenarios.py`; do not edit by hand. Reproduce with:",
        "",
        "```sh",
        "uv run python tests/sbom_scenarios.py --out <new-directory>",
        "```",
        "",
        f"Generated {generated} on {environment['platform']}, Python {environment['python']}, "
        f"zhongli {environment['zhongli']}, cryptography {environment['cryptography']}.",
        "",
        "Every case signs `contoh-app.zip` (`release.json`) and its CycloneDX SBOM (`sbom.json`, "
        "`sbom.bundle.json`, components from the copy of `uv.lock` in this directory) with the TEST_ONLY key "
        "of the profile, applies the change in the table and runs "
        "`sbom verify --json` (`verification.json`). The stage says which check failed: `artifact` "
        "(release bundle), `sbom` (SBOM bundle or SBOM content) or `binding` (the SBOM does not name the "
        "verified artifact).",
        "",
        f"**{passed} of {len(cases)} cases passed.**",
        "",
        "| ID | Profile | Scenario | Expected | Actual | Result | Directory |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for case in cases:
        actual = (f"{case.actual_status} / {case.actual_stage or '-'} / {case.actual_exit}"
                  if case.actual_status else "-")
        lines.append(f"| {case.id} | `{case.profile}` | {case.title} | "
                     f"{case.expected_status} / {case.expected_stage or '-'} / {case.expected_exit} | {actual} | "
                     f"{'pass' if case.passed else 'FAIL'} | [`{case.directory}`]({case.directory}/) |")
    notes = [case for case in cases if case.note and case.profile == "ed25519"]
    if notes:
        lines += ["", "## Notes", ""]
        lines += [f"- **{case.id}**: {case.note}" for case in notes]
    (out / "README.md").write_text("\n".join(lines) + "\n", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True, help="new, empty output directory")
    args = parser.parse_args()
    cases = run(args.out)
    write_report(args.out, cases)
    failed = [case for case in cases if not case.passed]
    print(f"{len(cases) - len(failed)} of {len(cases)} cases passed; report in {args.out / 'README.md'}")
    for case in failed:
        print(f"FAIL {case.id} {case.profile}: {case.note or case.actual_status}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
