"""v0.1.3 JSON compatibility (release blocker): for every replay fixture that existed in v0.1.3, the v1
part of the JSON report is identical to the snapshot taken from the unmodified v0.1.3 code
(tests/data/v1_json_golden.json, scripts/snapshot_v1_json.py). Only ``generated_at`` (volatile) and the
free text of ``actions[].description`` (allowed to improve) are exempt. New data lives under ``v2``."""

from __future__ import annotations

import json
import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.resolution.checks import ReplayRunner
from ipa_diagnose.resolution.engine import resolve_report

ROOT = pathlib.Path(__file__).resolve().parents[1]
GOLDEN = json.loads((ROOT / "data" / "v1_json_golden.json").read_text(encoding="utf-8"))


def _strip(data):
    data = json.loads(json.dumps(data))
    for d in data.get("diagnoses", []):
        for a in d.get("actions", []):
            a.pop("description", None)
    return data


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_v1_json_is_unchanged(name):
    fixture = ROOT / "fixtures" / name
    report = run_diagnosis(collect_evidence(replay_dir=str(fixture)))
    resolve_report(report, ReplayRunner(str(fixture)))
    data = report_to_dict(report)
    v1 = {k: data[k] for k in GOLDEN[name]}
    assert _strip(v1) == _strip(GOLDEN[name])
    assert set(data) - set(GOLDEN[name]) <= {"generated_at", "report_schema_version", "v2"}
