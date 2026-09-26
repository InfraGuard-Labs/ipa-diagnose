"""Snapshot the default console output (--no-ai) of every replay fixture (compatibility golden file).

Run with the v0.1.3 code on sys.path to create tests/data/console_golden_v013.json. The test
tests/unit/test_console_compat.py requires byte-identical output (apart from the "Generated:" timestamp)
for every fixture whose report carries no resolution.

Usage: PYTHONPATH=<v0.1.3 src> python scripts/snapshot_console.py FIXTURES_DIR OUT.json
"""

from __future__ import annotations

import io
import json
import pathlib
import re
import sys

from rich.console import Console

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.render.console import render_report

_TS = re.compile(r"Generated: \S+")
_REPLAY = re.compile(r"\(replayed from fixtures: [^)]*\)")


def render(fixture: pathlib.Path, details: bool = False) -> str:
    report = run_diagnosis(collect_evidence(replay_dir=str(fixture)))
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=120, force_terminal=False, color_system=None), details=details)
    return _REPLAY.sub("(replayed from fixtures: <dir>)", _TS.sub("Generated: <ts>", buf.getvalue()))


def main(argv) -> int:
    root = pathlib.Path(argv[1])
    out = {}
    for hc in sorted(root.rglob("healthcheck.json")):
        name = str(hc.parent.relative_to(root)).replace("\\", "/")
        out[name] = {"default": render(hc.parent), "details": render(hc.parent, True)}
    pathlib.Path(argv[2]).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(len(out), "fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
