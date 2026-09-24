"""v0.1.3 console compatibility: for every replay fixture that existed in v0.1.3 and whose report carries
no resolution, the default and --details console output is identical to v0.1.3's (captured from the
unmodified v0.1.3 code by scripts/snapshot_console.py). Only the "Generated:" timestamp is ignored."""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
GOLDEN = json.loads((ROOT / "tests" / "data" / "console_golden_v013.json").read_text(encoding="utf-8"))
_spec = importlib.util.spec_from_file_location("snap", ROOT / "scripts" / "snapshot_console.py")
snap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(snap)


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_console_output_unchanged_without_a_resolution(name, monkeypatch):
    from ipa_diagnose.engine.run import run_diagnosis
    from ipa_diagnose.evidence.collect import collect_evidence

    monkeypatch.chdir(ROOT)  # the golden file was captured with relative fixture paths
    fixture = pathlib.Path("tests") / "fixtures" / name
    report = run_diagnosis(collect_evidence(replay_dir=str(fixture)))
    if any(d.resolution_key for d in report.diagnoses):
        pytest.skip("fixture has a diagnosis that can carry a procedure; its new block is covered in tests/resolution")
    assert snap.render(fixture) == GOLDEN[name]["default"]
    assert snap.render(fixture, details=True) == GOLDEN[name]["details"]
