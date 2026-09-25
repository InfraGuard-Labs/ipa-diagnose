"""Live-lab helper for Slice 1: apply a procedure EXACTLY as ipa-diagnose printed it, and check verify.

Used only by .github/workflows/live-freeipa-scenarios.yml on a disposable FreeIPA container. It plays the
administrator: it reads the ``v2.resolutions`` entry from ipa-diagnose's --json output, asserts what was
offered (or withheld), runs each step's argv verbatim inside the container (``docker exec``, no shell),
and checks that ``ipa-diagnose verify`` reports RESOLVED with the fix's own checks passing.
Every assertion is appended to out/slice1-procedures.txt as PASS/FAIL; ``summary`` fails the job on any FAIL.

Usage:
  lab_procedure.py expect  JSON PROCEDURE_ID STATUS [NEEDLE]   # STATUS: OFFERED | WITHHELD | NONE
  lab_procedure.py apply   JSON PROCEDURE_ID CONTAINER LOG      # run the offered steps' argv verbatim
  lab_procedure.py verify  VERIFY_TXT LABEL                     # RESOLVED + fix checks pass
  lab_procedure.py summary
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

SUMMARY = pathlib.Path("out/slice1-procedures.txt")


def record(ok: bool, text: str) -> None:
    SUMMARY.parent.mkdir(exist_ok=True)
    with SUMMARY.open("a", encoding="utf-8") as fh:
        fh.write(f"{'PASS' if ok else 'FAIL'}: {text}\n")
    print(f"{'PASS' if ok else 'FAIL'}: {text}")


def resolution(json_file: str, procedure_id: str):
    try:
        data = json.loads(pathlib.Path(json_file).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return None, f"cannot read {json_file}: {e}"
    for r in data.get("v2", {}).get("resolutions", []):
        if r.get("procedure_id") == procedure_id:
            return r, None
    return None, f"no resolution for {procedure_id} in {json_file}"


def cmd_expect(json_file, procedure_id, status, needle=None) -> int:
    r, err = resolution(json_file, procedure_id)
    if r is None:
        record(False, f"{procedure_id}: {err}")
        return 1
    ok = r["status"] == status and (needle is None or any(needle in x for x in r.get("reasons", [])))
    if status == "OFFERED":
        ok = ok and bool(r["steps"]) and all(isinstance(s.get("argv"), list) for s in r["steps"])
    else:
        ok = ok and not r["steps"]
    record(ok, f"{procedure_id}: expected {status}{f' ({needle})' if needle else ''}, got {r['status']} "
               f"steps={[s['argv'] for s in r['steps']]} reasons={r.get('reasons')}")
    return 0 if ok else 1


def cmd_apply(json_file, procedure_id, container, log) -> int:
    r, err = resolution(json_file, procedure_id)
    if r is None or r["status"] != "OFFERED":
        record(False, f"{procedure_id}: nothing to apply ({err or r['status']})")
        return 1
    allowed = {"systemctl", "chmod", "chown", "chgrp", "chronyc", "getcert"}
    if any(not s.get("argv") or s["argv"][0] not in allowed for s in r["steps"]):
        record(False, f"{procedure_id}: refusing to run a program outside {sorted(allowed)}")
        return 1
    rc_all = 0
    with open(log, "w", encoding="utf-8") as fh:
        # The administrator's CONFIRM FIRST: run each printed read-only command and compare with the expected output.
        for c in r.get("confirm_first") or []:
            if c["argv"][0] not in ("stat", "readlink"):
                record(False, f"{procedure_id}: confirm command {c['argv'][0]!r} is not read-only")
                return 1
            proc = subprocess.run(["docker", "exec", container] + list(c["argv"]),  # noqa: S603
                                  capture_output=True, text=True, timeout=60)
            got = proc.stdout.strip()
            fh.write(f"$ {c['command']}\n{got}\n(expected {c['expected']})\n")
            ok = proc.returncode == 0 and got == c["expected"]
            record(ok, f"{procedure_id}: confirm-first {c['argv']} printed {got!r}, expected {c['expected']!r}")
            if not ok:
                return 1
        for step in r["steps"]:
            argv = ["docker", "exec", container] + list(step["argv"])
            fh.write(f"$ {' '.join(step['argv'])}\n")
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=600)  # noqa: S603 - argv from the report
            fh.write(proc.stdout + proc.stderr + f"exit={proc.returncode}\n")
            rc_all = rc_all or proc.returncode
    record(rc_all == 0, f"{procedure_id}: applied {[s['argv'] for s in r['steps']]} exactly as printed (exit {rc_all})")
    return rc_all


def cmd_verify(verify_txt, label) -> int:
    text = pathlib.Path(verify_txt).read_text(encoding="utf-8", errors="replace")
    ok = "RESOLVED" in text and "fix's own checks pass" in text and "STILL_PRESENT" not in text
    record(ok, f"{label}: verify reports RESOLVED with the fix's own checks passing")
    return 0 if ok else 1


def cmd_summary() -> int:
    text = SUMMARY.read_text(encoding="utf-8") if SUMMARY.exists() else "FAIL: no assertions recorded\n"
    print(text)
    return 1 if "FAIL:" in text else 0


def main(argv) -> int:
    cmd, args = argv[1], argv[2:]
    return {"expect": cmd_expect, "apply": cmd_apply, "verify": cmd_verify, "summary": cmd_summary}[cmd](*args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
