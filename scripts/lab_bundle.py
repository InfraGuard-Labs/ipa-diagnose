"""Live-lab support-bundle assertions (stdlib only; runs on the CI runner, outside the FreeIPA container).

    python3 scripts/lab_bundle.py check SCENARIO BUNDLE.tar.gz DIAGNOSE_BEFORE.json DIAGNOSE_AFTER.json 'SPEC-JSON'
    python3 scripts/lab_bundle.py skip  SCENARIO 'why'
    python3 scripts/lab_bundle.py summary          # exit 1 if any FAIL

Always checked for a bundle:
  - exactly the expected members, SHA256SUMS and manifest checksums match, archive metadata anonymous;
  - source_mode LIVE in the manifest and in every JSON member;
  - the bundle's overall status equals the diagnosis run just before it, and the diagnosis run just after it is the
    same (creating a bundle changed nothing);
  - none of the forbidden strings (env LAB_FORBIDDEN, '|'-separated: lab host/domain/realm/IP, the lab password and
    every planted canary) occurs anywhere in the decompressed archive, case-insensitively;
  - no fix command is present (no step argv/command, no "systemctl start").
SPEC keys (optional): overall_in [..], resolution {procedure, status}, collection_error_category text,
  completeness text, min_redacted int, pseudonym_classes [..].
Rows go to out/truth/bundle-results.jsonl.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile

OUT = pathlib.Path("out/truth")
RESULTS = OUT / "bundle-results.jsonl"
MEMBERS = ["README.txt", "manifest.json", "environment.json", "report.json", "healthcheck.json", "evidence.json",
           "collection-errors.json", "topology.json", "verification.json", "redaction-report.json", "SHA256SUMS"]


def _emit(scenario, verdict, checks, row):
    OUT.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"scenario": scenario, "verdict": verdict, "checks": checks,
                             "commit": os.environ.get("GITHUB_SHA"), **row}, sort_keys=True) + "\n")
    for ok, text in checks:
        print(("PASS" if ok else "FAIL") + f": {scenario}: {text}")


def _diag_key(report):
    return (report.get("overall_status"), sorted(d.get("diagnosis_id", "") for d in report.get("diagnoses") or []))


def _read(path):
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def check(scenario, bundle_path, before_path, after_path, spec_text, tag=None):
    spec = json.loads(spec_text or "{}")
    checks = []

    def ok(cond, text):
        checks.append([bool(cond), text])

    data = pathlib.Path(bundle_path).read_bytes()
    raw = gzip.decompress(data)
    ok(data[3] & 0x08 == 0 and data[4:8] == b"\0\0\0\0", "gzip header has no file name and mtime 0")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        infos = tar.getmembers()
        members = {ti.name.split("/", 1)[1]: tar.extractfile(ti).read() for ti in infos if ti.isreg()}
    ok([ti.name for ti in infos] == [f"ipa-diagnose-bundle/{n}" for n in MEMBERS], "exactly the expected members")
    ok(all(ti.uid == ti.gid == 0 and ti.uname == ti.gname == "" and ti.mode == 0o644 for ti in infos),
       "archive entries carry no owner identity")
    sums = dict(reversed(line.split("  ", 1)) for line in members["SHA256SUMS"].decode().splitlines())
    ok(all(hashlib.sha256(members[n]).hexdigest() == h for n, h in sums.items()) and len(sums) == 10,
       "SHA256SUMS matches every member")
    manifest = json.loads(members["manifest.json"])
    ok(all(hashlib.sha256(members[e["name"]]).hexdigest() == e["sha256"] for e in manifest["members"]),
       "manifest checksums match")
    ok(manifest["source_mode"] == "LIVE" and all(json.loads(members[n]).get("source_mode") == "LIVE"
                                                 for n in MEMBERS if n.endswith(".json")), "labelled LIVE everywhere")
    before = json.loads(pathlib.Path(before_path).read_text(encoding="utf-8"))
    after = json.loads(pathlib.Path(after_path).read_text(encoding="utf-8"))
    ok(manifest["overall_status"] == before.get("overall_status"),
       f"bundle status {manifest['overall_status']} = diagnosis status {before.get('overall_status')}")
    ok(_diag_key(before) == _diag_key(after), "the diagnosis after the bundle is the same as before it")
    text = raw.decode("utf-8", "replace").lower()
    forbidden = [f for f in os.environ.get("LAB_FORBIDDEN", "").split("|") if f] + spec.get("forbidden", [])
    leaked = [f for f in forbidden if f.lower() in text]
    ok(not leaked, f"none of {len(forbidden)} forbidden lab strings and canaries present"
       + (f" (LEAKED: {len(leaked)})" if leaked else ""))
    report = json.loads(members["report.json"])
    steps = [s for r in report["resolutions"] for s in r.get("steps") or []]
    ok(all("argv" not in s and "command" not in s for s in steps) and "systemctl start" not in text
       and "chmod o-" not in text, "no fix command in the bundle")
    if tag:
        ok("exit=0" in _read(f"out/{tag}-bundle.txt"), "bundle command exit 0")
        ok(_read(f"out/{tag}-state-before.txt") == _read(f"out/{tag}-state-after.txt")
           and _read(f"out/{tag}-state-before.txt"), "IPA unit states, saved verify baseline and files unchanged")
        mode = _read(f"out/{tag}-mode.txt")
        ok(mode.startswith("600 ") and "readable-by-others" not in mode, f"file mode 0600, unreadable by others ({mode.split()[:2]})")
        ok("exit=0" in _read(f"out/{tag}-preview.txt") and "nothing was written" in _read(f"out/{tag}-preview.txt"),
           "preview ran and wrote nothing")
        val = _read(f"out/{tag}-validate.txt")
        ok(": VALID" in val and "exit=0" in val, "bundle validate (as an unprivileged user) says VALID")
    if "overall_in" in spec:
        ok(manifest["overall_status"] in spec["overall_in"], f"overall in {spec['overall_in']}")
    if "resolution" in spec:
        want = spec["resolution"]
        got = [r for r in report["resolutions"] if r["procedure_id"] == want["procedure"]]
        ok(got and got[0]["status"] == want["status"] and got[0]["commands_omitted"] is True,
           f"resolution {want['procedure']} {want['status']} carried with commands omitted")
    if "collection_error_category" in spec:
        ce = json.loads(members["collection-errors.json"])
        ok(any(e["category"] == spec["collection_error_category"] for e in ce["errors"]),
           f"collection error category {spec['collection_error_category']}")
    if "completeness" in spec:
        ok(manifest["evidence_completeness"] == spec["completeness"], f"completeness {spec['completeness']}")
    red = json.loads(members["redaction-report.json"])
    if "pseudonym_classes" in spec:
        ok(set(spec["pseudonym_classes"]) <= set(red["pseudonymized_identifiers"]),
           f"pseudonymized classes include {spec['pseudonym_classes']}")
    verdict = "PASS" if all(c[0] for c in checks) else "FAIL"
    row = {"overall": manifest["overall_status"], "completeness": manifest["evidence_completeness"],
           "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "counts": manifest["counts"],
           "pseudonymized": red["pseudonymized_identifiers"], "redacted": red["redacted_values"],
           "resolutions": [{"procedure": r["procedure_id"], "status": r["status"], "tier": r["tier"],
                            "definitive": r["definitive"]} for r in report["resolutions"]],
           "content_complete": manifest["content_complete"]}
    _emit(scenario, verdict, checks, row)
    return 0 if verdict == "PASS" else 1


def main(argv):
    if argv[:1] == ["check"]:
        return check(*argv[1:7])
    if argv[:1] == ["skip"]:
        _emit(argv[1], "SKIP", [], {"skip_reason": argv[2]})
        print(f"SKIP: {argv[1]}: {argv[2]}")
        return 0
    if argv[:1] == ["summary"]:
        rows = [json.loads(x) for x in RESULTS.read_text(encoding="utf-8").splitlines()] if RESULTS.exists() else []
        for r in rows:
            print(f"{r['verdict']:5s} {r['scenario']}")
        return 1 if any(r["verdict"] == "FAIL" for r in rows) or not rows else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
