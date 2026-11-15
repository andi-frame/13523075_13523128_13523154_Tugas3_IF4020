import base64
import json
from pathlib import Path

import pytest

from zhongli.verification import Status, verify
from scenarios import SCENARIOS, run_scenarios, write_report

FIXTURES = Path(__file__).parent / "fixtures"
UNIT_IDS = {f"U{number:02d}" for number in range(1, 15)}


def test_all_scenarios_pass(tmp_path):
    out = tmp_path / "evidence"
    cases = run_scenarios(out)
    write_report(out, cases)
    failed = [f"{c.id} {c.variant} {c.profile}: {c.actual_status} ({c.note})" for c in cases if not c.passed]
    assert not failed, "\n".join(failed)
    for profile in ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"):
        assert UNIT_IDS <= {c.id for c in cases if c.profile == profile}
    assert (out / "README.md").exists() and (out / "results.json").exists()


def test_every_unit_scenario_is_listed():
    assert UNIT_IDS <= {entry[0] for entry in SCENARIOS}


@pytest.mark.parametrize("name,profile", [("rsa", "rsa-pss-sha256"), ("ecdsa", "ecdsa-p256-sha256"),
                                          ("ed25519", "ed25519")])
def test_shared_fixture_verifies(name, profile):
    root = FIXTURES / name
    result = verify(root / "demo.bin", root / "bundle.json", root / "trust.json", "demo", "1.0")
    assert result.status is Status.OK and result.algorithm == profile
    bundle = json.loads((root / "bundle.json").read_bytes())
    assert base64.b64decode(bundle["manifest_b64"]) == (root / "manifest.json").read_bytes()
