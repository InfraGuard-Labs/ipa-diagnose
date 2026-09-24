"""Snapshot the v1 JSON report of every replay fixture (compatibility golden file).

Run against the *unmodified* v0.1.3 code to create tests/data/v1_json_golden.json;
tests/unit/test_v1_json_compat.py then asserts that later code produces the same v1
keys and values (only the volatile ``generated_at`` is ignored, and the free text of
``actions[].description`` is exempt by design).

Usage: PYTHONPATH=src python scripts/snapshot_v1_json.py tests/data/v1_json_golden.json
"""

from __future__ import annotations

import json
import pathlib
import sys

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.render.json_output import report_to_dict

ROOT = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures"
VOLATILE = {"generated_at"}


def v1_view(fixture: pathlib.Path) -> dict:
    report = run_diagnosis(collect_evidence(replay_dir=str(fixture)))
    data = report_to_dict(report)
    return {k: v for k, v in data.items() if k not in VOLATILE}


def fixtures() -> list:
    return sorted(p.parent for p in ROOT.rglob("healthcheck.json"))


def main(argv: list) -> int:
    out = {str(p.relative_to(ROOT)).replace("\\", "/"): v1_view(p) for p in fixtures()}
    pathlib.Path(argv[1]).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(len(out), "fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
