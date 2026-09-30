#!/usr/bin/env python3
"""Write the SYNTHETIC replay fixtures for `ipa-diagnose replication --replay` under tests/fixtures/replication-mode/.

    python scripts/make_replication_fixtures.py           # write
    python scripts/make_replication_fixtures.py --check   # fail when the committed fixtures are out of date

They come from tests/replication/scenarios.py with a FIXED clock, so they never change by themselves. They describe
no live system (FIXTURE evidence); live rows are in docs/truth/replication-truth-matrix.md.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.replication import scenarios as S  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "replication-mode"
NOW = datetime.datetime(2026, 9, 29, 12, 0, 0, tzinfo=datetime.timezone.utc)

FIXTURES = {
    "healthy": lambda: S.Lab(now=NOW),
    "peer-ds-stopped": lambda: S.Lab(now=NOW).peer_ds_stopped(S.IPA02),
    "peer-unreachable": lambda: S.Lab(now=NOW).peer_unreachable(S.IPA02),
    "local-kdc-stopped": lambda: S.Lab(now=NOW).local_kdc_stopped(),
    "clock-skew": lambda: S.Lab(now=NOW).clock_skew(S.IPA02, 900),
    "ca-suffix-generation-mismatch": lambda: S.Lab(now=NOW).set_status(S.IPA02, S.GENERATION_TEXT, suffix="ca"),
    "reverse-not-observable": lambda: S.Lab(now=NOW).set_reverse(S.IPA02, status="NOT_RUN"),
    "middle-server-two-causes": lambda: S.Lab(me=S.IPA02, now=NOW).peer_ds_stopped(S.IPA01).peer_unreachable(S.IPA03),
}


def render(name: str) -> dict:
    return {"replication_checks.json": json.dumps(FIXTURES[name]().build(), indent=1, sort_keys=True) + "\n",
            "meta.json": json.dumps({"is_root": True, "note": "SYNTHETIC replication fixture "
                                     "(scripts/make_replication_fixtures.py); describes no live system"},
                                    indent=1) + "\n"}


def main(check: bool) -> int:
    stale = []
    for name in FIXTURES:
        for fname, text in render(name).items():
            p = OUT / name / fname
            if check:
                if not p.exists() or p.read_text(encoding="utf-8") != text:
                    stale.append(str(p.relative_to(ROOT)))
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8", newline="\n")
    if stale:
        print("out of date: " + ", ".join(stale))
        return 1
    print("replication fixtures " + ("up to date" if check else f"written to {OUT.relative_to(ROOT)}"))
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv))
