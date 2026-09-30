#!/usr/bin/env python3
"""Real CLI captures from the live labs, for the screenshot index (docs/screenshots/1.0-candidate/).

Run on the CI host next to a lab. It never changes the lab: it only runs a read-only ipa-diagnose command inside a
lab container (with a readable terminal width) and keeps its exact output, or publishes captures already taken.

    python3 scripts/lab_captures.py run NAME CONTAINER "SCENARIO" -- ipa-diagnose ARGS...   # capture one command
    python3 scripts/lab_captures.py emit SKIP                                               # publish (<= 10 notes)
    python3 scripts/lab_captures.py fetch RUN_ID OUT_DIR                                    # (maintainer) download

`run` executes `docker exec -e COLUMNS=120 CONTAINER <argv>` (never a shell) and writes out/captures/NAME.txt (the
exact stdout and stderr, as printed) and NAME.json (argv, container, exit code, time, scenario, lab commit). Extra
environment for the tool is passed as KEY=VALUE words before the program name (for example
IPA_DIAGNOSE_STATE_DIR=/tmp/cap-state, so a verify capture can read a copy of the baseline the lab's own verify
used, without changing the lab's saved state).

`emit` publishes the captures as GitHub notice annotations: each capture (metadata + text) is gzip-compressed and
base64-encoded, split into chunks, and printed as `::notice title=capture NAME i/n::CHUNK`. GitHub keeps at most 10
notices per step, so the workflow calls `emit 0`, `emit 10`, `emit 20`, ... in separate steps. `fetch` reassembles
them from the public check-run annotations API (no credentials) into OUT_DIR/NAME.txt and NAME.json.

Only fake lab identities exist in the labs (lab.test, LAB.TEST); nothing here reads credentials.
"""

from __future__ import annotations

import base64
import datetime
import gzip
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

OUT = pathlib.Path("out") / "captures"
CHUNK = 3500


def _chunks() -> list:
    res = []
    for meta_path in sorted(OUT.glob("*.json")):
        name = meta_path.stem
        text_path = OUT / f"{name}.txt"
        if not text_path.exists():
            continue
        payload = {"meta": json.loads(meta_path.read_text(encoding="utf-8")),
                   "text": text_path.read_text(encoding="utf-8", errors="replace")}
        blob = base64.b64encode(gzip.compress(json.dumps(payload).encode("utf-8"), mtime=0)).decode("ascii")
        parts = [blob[i:i + CHUNK] for i in range(0, len(blob), CHUNK)] or [""]
        for i, part in enumerate(parts):
            res.append((f"capture {name} {i + 1}/{len(parts)}", part))
    return res


def run(name: str, container: str, scenario: str, argv: list) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    env = []
    while argv and "=" in argv[0] and not argv[0].startswith("/"):
        env += ["-e", argv.pop(0)]
    exe = argv[0]
    if exe == "ipa-diagnose":
        exe = os.environ.get("IPA_DIAGNOSE_BIN", "/root/.local/bin/ipa-diagnose")
    user = os.environ.get("CAPTURE_USER", "root")
    full = ["docker", "exec", "-u", user, "-e", "COLUMNS=120", "-w", "/"] + env + [container, exe] + argv[1:]
    started = datetime.datetime.now(datetime.timezone.utc)
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=600)
        rc, text = p.returncode, p.stdout + (("\n" + p.stderr) if p.stderr.strip() else "")
    except subprocess.TimeoutExpired:
        rc, text = 124, "(capture timed out)"
    shown = " ".join(["ipa-diagnose" if argv[0] == "ipa-diagnose" else argv[0]] + argv[1:])
    meta = {"name": name, "container": container, "user": user, "command": shown,
            "env": [e for e in env if e != "-e"], "exit": rc, "scenario": scenario,
            "captured_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "commit": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""), "columns": 120}
    (OUT / f"{name}.txt").write_text(text, encoding="utf-8")
    (OUT / f"{name}.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    print(f"captured {name}: exit {rc}, {len(text.splitlines())} lines")
    return 0


def emit(skip: int) -> int:
    chunks = _chunks()
    for title, part in chunks[skip:skip + 10]:
        print(f"::notice title={title}::{part}")
    print(f"{len(chunks)} capture chunk(s) in total; this step published {len(chunks[skip:skip + 10])}")
    return 0


def _get(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "ipa-diagnose-lab-captures"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https API URL
        return json.loads(r.read().decode("utf-8"))


def fetch(run_id: str, out_dir: str) -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "InfraGuard-Labs/ipa-diagnose")
    jobs = _get(f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]
    parts: dict = {}
    for job in jobs:
        page = 1
        while True:
            anns = _get(f"https://api.github.com/repos/{repo}/check-runs/{job['id']}/annotations"
                        f"?per_page=100&page={page}")
            for a in anns:
                title = a.get("title") or ""
                if title.startswith("capture "):
                    _c, name, frac = title.split(" ")
                    i, n = (int(x) for x in frac.split("/"))
                    parts.setdefault(name, {})[i] = (n, a["message"])
            if len(anns) < 100:
                break
            page += 1
    dest = pathlib.Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    done = 0
    for name, got in sorted(parts.items()):
        n = next(iter(got.values()))[0]
        if sorted(got) != list(range(1, n + 1)):
            print(f"INCOMPLETE {name}: have {sorted(got)} of {n}")
            continue
        blob = "".join(got[i][1] for i in range(1, n + 1))
        payload = json.loads(gzip.decompress(base64.b64decode(blob)).decode("utf-8"))
        (dest / f"{name}.txt").write_text(payload["text"], encoding="utf-8")
        (dest / f"{name}.json").write_text(json.dumps(payload["meta"], indent=1, sort_keys=True), encoding="utf-8")
        done += 1
    print(f"{done} capture(s) written to {dest}")
    return 0


def main(argv: list) -> int:
    if len(argv) >= 6 and argv[1] == "run" and argv[5] == "--":
        return run(argv[2], argv[3], argv[4], argv[6:])
    if len(argv) == 3 and argv[1] == "emit":
        return emit(int(argv[2]))
    if len(argv) == 4 and argv[1] == "fetch":
        return fetch(argv[2], argv[3])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
