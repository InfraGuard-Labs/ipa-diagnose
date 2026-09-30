#!/usr/bin/env python3
"""Build docs/screenshots/1.0-candidate/ from REAL lab captures.

    python scripts/build_screenshots.py CAPTURE_DIR [CAPTURE_DIR ...]

CAPTURE_DIR holds NAME.txt / NAME.json pairs written by `scripts/lab_captures.py fetch RUN_ID DIR` (the exact text a
live lab run printed, published by that run as annotations) or by `scripts/lab_captures.py run` locally for REPLAY
captures. Nothing here runs ipa-diagnose or edits captured text: each image is drawn by
scripts/render_capture_svg.py from a stated line range of one capture, with a provenance banner. The raw captures are
copied next to the images (captures/) so every image can be checked against its source, and index.md is generated
with each image's command, commit, run, provenance, scenario, environment, safe claim and limitation.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from render_capture_svg import render  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "screenshots" / "1.0-candidate"

# lab environments, as recorded by each lab's "environment" step (env.txt / the environment annotation)
LABS = {
    "srv": "single FreeIPA server (integrated DNS + CA), freeipa-server 4.13.4-2.fc43, Fedora 43 container",
    "bundle": "single FreeIPA server (integrated DNS + CA), freeipa-server 4.13.4-2.fc43, Fedora 43 container",
    "access": "single FreeIPA server, freeipa-server 4.13.4-2.fc43, Fedora 43 container; fake LAB.TEST HBAC policy",
    "client": "FreeIPA server 4.13.4-2.fc43 + enrolled Fedora 43 client (freeipa-client 4.13.4-2.fc43, sssd 2.12.0)",
    "repl": "three FreeIPA 4.13.4 / 389-ds-base 3.1.5 / Fedora 43 servers in a line: ipa01 (CA, DNS) -- ipa02 (CA) "
            "-- ipa03",
}

# (image file, capture name, first line (0-based), number of lines, what it shows, safe claim, limitation, provenance)
MANIFEST: list = []


def _load(dirs: list) -> dict:
    caps = {}
    for d in dirs:
        for meta in pathlib.Path(d).glob("*.json"):
            txt = meta.with_suffix(".txt")
            if txt.exists():
                caps[meta.stem] = (json.loads(meta.read_text(encoding="utf-8")), txt.read_text(encoding="utf-8"))
    return caps


def _banner(prov: str, meta: dict) -> str:
    where = f"commit {meta.get('commit', '')[:7]}" + (f", run {meta['run_id']}" if meta.get("run_id") else "")
    return {"LIVE": f"REAL LIVE CAPTURE - FreeIPA 4.13.4 / Fedora 43 lab - {where}",
            "LIVE SIMULATED": f"LIVE SIMULATED (only ipa-diagnose's own clock shifted) - FreeIPA 4.13.4 lab - {where}",
            "REPLAY": f"FIXTURE REPLAY (NOT live) - recorded evidence - {where}"}[prov]


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    caps = _load(argv[1:])
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "captures").mkdir(exist_ok=True)
    rows, missing = [], []
    for m in MANIFEST:
        if m["capture"] not in caps:
            missing.append(m["capture"])
            continue
        meta, text = caps[m["capture"]]
        title = f"$ {meta['command']}   (exit {meta['exit']})"
        svg = render(text, title, _banner(m["prov"], meta), m["lines"], m["start"], wrap=120)
        (OUT / m["image"]).write_text(svg, encoding="utf-8", newline="\n")
        (OUT / "captures" / f"{m['capture']}.txt").write_text(text, encoding="utf-8", newline="\n")
        (OUT / "captures" / f"{m['capture']}.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n",
                                                                encoding="utf-8", newline="\n")
        total = len(text.splitlines())
        shown = f"lines {m['start'] + 1}-{min(total, m['start'] + m['lines'])} of {total}"
        rows.append((m, meta, shown))
    if missing:
        print(f"MISSING captures: {missing}")
        return 1
    _index(rows)
    print(f"{len(rows)} image(s) written to {OUT}")
    return 0


def _index(rows: list) -> None:
    lines = [
        "# 1.0-candidate screenshots: real CLI output only",
        "",
        "Every image is the exact text `ipa-diagnose` printed, drawn by `scripts/render_capture_svg.py` (ANSI colours "
        "stripped; a long output shows the stated line range, and some outputs are split over two images). Nothing is "
        "mocked, typed by hand or generated. The raw capture of each image, with its command, exit code, time, commit "
        "and run, is in [captures/](captures/). Images are built by `scripts/build_screenshots.py` from captures that "
        "the live lab runs published (`scripts/lab_captures.py`).",
        "",
        "**Provenance labels.** LIVE: a disposable FreeIPA lab on a free GitHub-hosted runner, the fault injected on "
        "purpose and confirmed independently, ipa-diagnose run blind. LIVE SIMULATED: a live lab where only "
        "ipa-diagnose's own process clock was shifted (libfaketime); no server clock was changed. REPLAY: recorded "
        "evidence, not a live system. **Pseudonymization:** the labs use only fake names (`lab.test`, `LAB.TEST`, "
        "`ipa01`-`ipa03`, `client1`, users `alice`/`bob`/`carol`/`dave`/`erin`, private 172.30/172.31 addresses); "
        "no real host, user, credential, ticket or key appears. Bundle output shows the bundle's own pseudonyms "
        "(`HOST-001`).",
        "",
        "Environment: " + "; ".join(f"**{k}**: {v}" for k, v in LABS.items()) + ". Only Fedora 43 and FreeIPA "
        "4.13.4 were used for these images; nothing here was captured on RHEL.",
        "",
        "| # | Image | Command (exit) | Provenance | Scenario | Safe public claim | Limitation |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, (m, meta, shown) in enumerate(rows, 1):
        run = f"[{meta['run_id']}](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/{meta['run_id']})" \
            if meta.get("run_id") else "local"
        lines.append(
            f"| {i:02d} | [`{m['image']}`]({m['image']}) ({shown}) | `{meta['command']}` ({meta['exit']}) | "
            f"{m['prov']}, commit `{meta.get('commit', '')[:7]}`, run {run} | {meta['scenario']} | {m['claim']} | "
            f"{m['limit']} |")
    lines += ["", "Historical screenshot sets (earlier code, kept unchanged): [v0.1.2](../v0.1.2/index.md), "
              "[v0.1.3](../v0.1.3/index.md), Slice 2 bundle captures in [slice2](../slice2/), and the fixture-based set "
              "in `artifacts/screenshots/`.", ""]
    (OUT / "index.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
