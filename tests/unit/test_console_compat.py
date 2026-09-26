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


_HEADINGS = {"ROOT CAUSE", "WHY", "EVIDENCE", "IMPACT", "DO THIS FIRST", "DO THIS NEXT", "ADDITIONAL ACTIONS",
             "CONFIDENCE", "LIMITATIONS", "VERIFY", "CHECKED FOR YOU", "FIX", "SAFE NEXT STEP"}
# v0.1.3 sections a withheld/absent fix deliberately replaces (the state-changing legacy actions stay in JSON).
_REPLACED = {"DO THIS FIRST", "ADDITIONAL ACTIONS"}


def _kept_lines(text: str):
    out, skip = [], False
    for line in text.splitlines():
        s = line.strip()
        if s in _HEADINGS or "─" in s:
            skip = s in _REPLACED
        if not skip and s:
            out.append(s)
    return out


def _with_resolutions(fixture: pathlib.Path, details: bool) -> str:
    import io
    import re

    from rich.console import Console

    from ipa_diagnose.engine.run import run_diagnosis
    from ipa_diagnose.evidence.collect import collect_evidence
    from ipa_diagnose.render.console import render_report
    from ipa_diagnose.resolution.checks import ReplayRunner
    from ipa_diagnose.resolution.engine import resolve_report

    report = run_diagnosis(collect_evidence(replay_dir=str(fixture)))
    resolve_report(report, ReplayRunner(str(fixture)))
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=120, force_terminal=False, color_system=None), details=details)
    text = re.sub(r"Generated: \S+", "Generated: <ts>", buf.getvalue())
    return re.sub(r"\(replayed from fixtures: [^)]*\)", "(replayed from fixtures: <dir>)", text)


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_v013_text_is_kept_when_a_procedure_is_involved(name, monkeypatch):
    """Fixtures whose diagnoses can carry a procedure: everything v0.1.3 printed (except the action sections a
    withheld or absent fix replaces) is still printed, in the same order, including --details."""

    from ipa_diagnose.engine.run import run_diagnosis
    from ipa_diagnose.evidence.collect import collect_evidence

    monkeypatch.chdir(ROOT)
    fixture = pathlib.Path("tests") / "fixtures" / name
    if not any(d.resolution_key for d in run_diagnosis(collect_evidence(replay_dir=str(fixture))).diagnoses):
        pytest.skip("covered byte-for-byte by test_console_output_unchanged_without_a_resolution")
    for mode, details in (("default", False), ("details", True)):
        new = _kept_lines(_with_resolutions(fixture, details))
        it = iter(new)
        missing = [line for line in _kept_lines(GOLDEN[name][mode]) if not any(line == n for n in it)]
        assert not missing, (mode, missing[:5])
