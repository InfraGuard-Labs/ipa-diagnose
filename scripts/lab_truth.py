"""Live-lab truth assertions: check what ipa-diagnose reported for one controlled scenario, and record a row
for the product truth matrix (docs/truth/). Used only by the live FreeIPA workflows.

    python3 scripts/lab_truth.py check  SCENARIO_ID REPORT.json 'SPEC-JSON'
    python3 scripts/lab_truth.py skip   SCENARIO_ID 'why'
    python3 scripts/lab_truth.py verify SCENARIO_ID VERIFY.json 'SPEC-JSON'
    python3 scripts/lab_truth.py summary            # exit 1 if any FAIL

SPEC keys (all optional):
  overall_in:           [statuses]      overall_status must be one of these
  overall_not:          [statuses]
  primary_contains:     text            the PRIMARY diagnosis title contains this (case-insensitive)
  primary_status:       DIAGNOSED | ...
  diagnosed_contains:   [texts]         some DIAGNOSED diagnosis title contains each text
  no_diagnosed:         [texts]         no DIAGNOSED diagnosis (any bucket) title contains any of these
  not_primary:          [texts]         no PRIMARY diagnosis title contains any of these
  related_contains:     [texts]         a RELATED_SYMPTOM title contains each text
  completeness_not:     level           evidence_completeness.level must not be this
  completeness:         level
  ruv_state_in:         [states]
  resolution:           {procedure, status, argv, no_argv0: [..], reason_contains}
  no_offered:           true            no v2 resolution is OFFERED
  no_diagnoses:         true            no diagnosis at all
  side_effect_contains: text            v2.side_effects mentions this text
  undiagnosed_only:     [checks]        every undiagnosed ipa-healthcheck finding is one of these checks
  verify_item:          {contains, outcome_in / outcome_not}   (verify only) the item whose title contains the text
  verify_outcome_in:    [outcomes]      (verify only) every item's outcome is in this list
  verify_not:           [outcomes]      (verify only) no item has these outcomes
"""

from __future__ import annotations

import json
import pathlib
import sys

OUT = pathlib.Path("out/truth")
RESULTS = OUT / "results.jsonl"


def _load(path: str):
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8", errors="replace")), None
    except (OSError, ValueError) as e:
        return None, f"cannot read {path}: {e}"


def _emit(scenario: str, verdict: str, checks: list, row: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"scenario": scenario, "verdict": verdict, "checks": checks, **row}, sort_keys=True) + "\n")
    for ok, text in checks:
        print(("PASS" if ok else "FAIL") + f": {scenario}: {text}")
    if verdict == "SKIP":
        print(f"SKIP: {scenario}: {row.get('skip_reason')}")


def _row(report: dict) -> dict:
    env = report.get("environment") or {}
    diags = report.get("diagnoses") or []
    res = (report.get("v2") or {}).get("resolutions") or []
    return {
        "freeipa": env.get("freeipa_version"), "os": f"{env.get('distro')}-{env.get('distro_version')}",
        "overall": report.get("overall_status"),
        "completeness": (report.get("evidence_completeness") or {}).get("level"),
        "ruv_state": (report.get("evidence_completeness") or {}).get("ruv_state"),
        "diagnoses": [{"title": d.get("title"), "priority": d.get("priority"), "status": d.get("status"),
                       "confidence": (d.get("confidence") or {}).get("level") if isinstance(d.get("confidence"), dict)
                       else d.get("confidence"), "severity": d.get("severity")} for d in diags],
        "resolutions": [{"procedure": r.get("procedure_id"), "status": r.get("status"),
                         "argv": [s.get("argv") for s in r.get("steps") or []], "tier": r.get("tier"),
                         "reasons": (r.get("reasons") or [])[:3]} for r in res],
    }


def _has(text, needle) -> bool:
    return needle.lower() in str(text or "").lower()


def check(scenario: str, path: str, spec: dict) -> list:
    report, err = _load(path)
    if report is None:
        return [(False, err)], {}
    diags = report.get("diagnoses") or []
    prim = [d for d in diags if d.get("priority") == "PRIMARY_PROBLEM"]
    diagnosed = [d for d in diags if d.get("status") == "DIAGNOSED"]
    res = (report.get("v2") or {}).get("resolutions") or []
    c = []
    if "overall_in" in spec:
        c.append((report.get("overall_status") in spec["overall_in"], f"overall {report.get('overall_status')} in {spec['overall_in']}"))
    if "overall_not" in spec:
        c.append((report.get("overall_status") not in spec["overall_not"], f"overall {report.get('overall_status')} not in {spec['overall_not']}"))
    if "primary_contains" in spec:
        c.append((any(_has(d.get("title"), spec["primary_contains"]) for d in prim),
                  f"PRIMARY contains {spec['primary_contains']!r} (got {[d.get('title') for d in prim]})"))
    if "primary_status" in spec:
        c.append((any(d.get("status") == spec["primary_status"] for d in prim), f"PRIMARY status {spec['primary_status']}"))
    for t in spec.get("diagnosed_contains", []):
        c.append((any(_has(d.get("title"), t) for d in diagnosed), f"a DIAGNOSED diagnosis mentions {t!r}"))
    for t in spec.get("no_diagnosed", []):
        bad = [d.get("title") for d in diagnosed if _has(d.get("title"), t)]
        c.append((not bad, f"no DIAGNOSED diagnosis mentions {t!r} (found {bad})"))
    for t in spec.get("not_primary", []):
        bad = [d.get("title") for d in prim if _has(d.get("title"), t)]
        c.append((not bad, f"PRIMARY is not {t!r} (found {bad})"))
    for t in spec.get("related_contains", []):
        c.append((any(_has(d.get("title"), t) and d.get("priority") == "RELATED_SYMPTOM" for d in diags),
                  f"{t!r} is a RELATED_SYMPTOM"))
    comp = report.get("evidence_completeness") or {}
    if "completeness" in spec:
        c.append((comp.get("level") == spec["completeness"], f"completeness {comp.get('level')} == {spec['completeness']}"))
    if "completeness_not" in spec:
        c.append((comp.get("level") != spec["completeness_not"], f"completeness {comp.get('level')} != {spec['completeness_not']}"))
    if "ruv_state_in" in spec:
        c.append((comp.get("ruv_state") in spec["ruv_state_in"], f"RUV state {comp.get('ruv_state')} in {spec['ruv_state_in']}"))
    if "side_effect_contains" in spec:
        se = (report.get("v2") or {}).get("side_effects") or []
        c.append((any(_has(x, spec["side_effect_contains"]) for x in se), f"side effect reported: {spec['side_effect_contains']!r} (got {se})"))
    if spec.get("no_diagnoses"):
        c.append((not diags, f"no diagnoses (got {[d.get('title') for d in diags]})"))
    if "undiagnosed_only" in spec:
        und = [(u.get("check"), u.get("message")) for u in report.get("undiagnosed_findings") or []]
        c.append((all(ch in spec["undiagnosed_only"] for ch, _ in und), f"undiagnosed findings only {spec['undiagnosed_only']} (got {und})"))
    if spec.get("no_offered"):
        off = [r.get("procedure_id") for r in res if r.get("status") == "OFFERED"]
        c.append((not off, f"no fix OFFERED (found {off})"))
    rs = spec.get("resolution")
    if rs:
        cand = [r for r in res if r.get("procedure_id") == rs["procedure"]]
        want = rs.get("status")
        hit = [r for r in cand if want is None or r.get("status") == want]
        c.append((bool(hit), f"{rs['procedure']} is {want} (got {[r.get('status') for r in cand]}, reasons "
                             f"{[x for r in cand for x in (r.get('reasons') or [])][:2]})"))
        for r in hit:
            argvs = [s.get("argv") for s in r.get("steps") or []]
            if "argv" in rs:
                c.append((rs["argv"] in argvs, f"step argv {rs['argv']} printed (got {argvs})"))
            for bad in rs.get("no_argv0", []):
                c.append((all(a and a[0] != bad for a in argvs), f"no step runs {bad!r}"))
            if "reason_contains" in rs:
                c.append((any(_has(x, rs["reason_contains"]) for x in r.get("reasons") or []),
                          f"a reason mentions {rs['reason_contains']!r}"))
    return c, _row(report)


def verify_check(scenario: str, path: str, spec: dict):
    data, err = _load(path)
    if data is None:
        return [(False, err)], {}
    items = data.get("items") or []
    outs = [i.get("outcome") for i in items]
    c = []
    if "verify_outcome_in" in spec:
        c.append((bool(items) and all(o in spec["verify_outcome_in"] for o in outs), f"verify outcomes {outs} all in {spec['verify_outcome_in']}"))
    if "verify_not" in spec:
        c.append((not any(o in spec["verify_not"] for o in outs), f"verify outcomes {outs} contain none of {spec['verify_not']}"))
    vi = spec.get("verify_item")
    if vi:
        hit = [i for i in items if vi["contains"].lower() in str(i.get("title", "")).lower()]
        ok = bool(hit) and all((i.get("outcome") in vi["outcome_in"]) if "outcome_in" in vi else (i.get("outcome") not in vi.get("outcome_not", []))
                               for i in hit)
        c.append((ok, f"verify item {vi['contains']!r}: {[i.get('outcome') for i in hit]} ({vi})"))
    row = _row(data.get("current_report") or {})
    row["verify"] = [{"title": i.get("title"), "outcome": i.get("outcome"), "detail": (i.get("detail") or "")[:300]} for i in items]
    return c, row


def main(argv) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "summary":
        rows = [json.loads(x) for x in RESULTS.read_text(encoding="utf-8").splitlines()] if RESULTS.exists() else []
        fails = [r for r in rows if r["verdict"] == "FAIL"]
        print(f"{len(rows)} scenario checks: {sum(r['verdict'] == 'PASS' for r in rows)} PASS, "
              f"{len(fails)} FAIL, {sum(r['verdict'] == 'SKIP' for r in rows)} SKIP")
        for r in fails:
            print("FAIL:", r["scenario"], [t for ok, t in r["checks"] if not ok])
        return 1 if fails else 0
    if cmd == "skip":
        _emit(argv[2], "SKIP", [], {"skip_reason": argv[3]})
        return 0
    scenario, path, spec = argv[2], argv[3], json.loads(argv[4])
    checks, row = (verify_check if cmd == "verify" else check)(scenario, path, spec)
    verdict = "PASS" if checks and all(ok for ok, _ in checks) else "FAIL"
    _emit(scenario, verdict, checks, row)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
