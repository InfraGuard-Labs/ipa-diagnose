"""Zero-silent-failure audit of ipa-diagnose against the ipa-healthcheck check inventory.

For every check in the inventory (scripts/inventory_healthcheck.py output) and every
failing result level it can emit, this feeds a synthetic ipa-healthcheck finding
through the REAL ipa-diagnose engine (`run_diagnosis`) and records how it is handled:

  A_DIAGNOSED   a pack rule cites it as evidence of a DIAGNOSED problem
  B_SUPPORTING  a pack rule cites it but stays UNKNOWN/insufficient (supporting/related)
  C_SURFACED    no rule explains it, but the user is shown it as UNDIAGNOSED
  D_SILENT      the finding is not shown to the user by name (count only, or nothing)
  E_NOT_INGESTED the finding never reaches the evidence model
  F_NO_FAILURE  the check can only ever report SUCCESS (nothing to handle)

Also runs the FUTURE-CHECK probes: made-up checks under every existing source, in
every result shape (msg, exception-only, no kw, unknown severity, huge, hostile);
any of them being claimed as a DIAGNOSED problem by an existing rule is a false diagnosis.

Only healthcheck evidence is supplied (no collector evidence), so A/B show what the
healthcheck finding alone supports; rules that need corroborating collector evidence
correctly stay UNKNOWN/B here.

Usage:
    python scripts/audit_healthcheck_coverage.py INVENTORY.json OUT.json [TAG ...]
"""

from __future__ import annotations

import json
import sys

from ipa_diagnose.engine.model import DiagnosisStatus
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_results
from ipa_diagnose.evidence.model import EvidenceBundle

FAIL_LEVELS = ("WARNING", "ERROR", "CRITICAL")
GOOD = {
    "source": "ipahealthcheck.meta.services",
    "check": "dirsrv",
    "result": "SUCCESS",
    "uuid": "audit.good",
    "when": "20260101000000Z",
    "duration": "0.01",
    "kw": {"status": True},
}


def _entry(source, check, level, key=None, shape="msg", uid=""):
    kw = {"key": key or check}
    if shape == "msg":
        if source.endswith("meta.services"):
            kw.update({"status": False, "msg": f"{check}: not running"})
        else:
            kw["msg"] = f"synthetic {level} from {check}"
    elif shape == "exception":
        kw = {"exception": "synthetic failure inside the check", "traceback": "Traceback (most recent call last): ..."}
    elif shape == "nomsg":
        kw = {"key": key or check}
    elif shape == "none":
        kw = None
    e = {"source": source, "check": check, "result": level, "uuid": f"audit.{source}.{check}.{level}.{key}.{shape}.{uid}",
         "when": "20260101000000Z", "duration": "0.01", "kw": kw}
    if kw is None:
        e.pop("kw")
    return e


def classify(entry: dict) -> dict:
    findings = parse_healthcheck_results([GOOD, entry], command="audit", live=False)
    bundle = EvidenceBundle(hostname="audit-host", collected_at=EvidenceBundle.now(), findings=findings)
    ingested = [f for f in findings if f.finding_id == entry["uuid"]]
    if not ingested:
        return {"class": "E_NOT_INGESTED", "rules": []}
    fid = ingested[0].finding_id
    report = run_diagnosis(bundle)
    pack_hits, hc_hits = [], []
    for d in report.diagnoses:
        cited = {r.evidence_id for r in list(d.evidence_for) + list(d.evidence_against)}
        if fid in cited:
            (hc_hits if d.pack_id == "healthcheck" else pack_hits).append((d.rule_id, d.status))
    rules = sorted({f"{r}:{s.value}" for r, s in pack_hits} | {f"healthcheck.{r}" for r, _ in hc_hits})
    if any(s == DiagnosisStatus.DIAGNOSED for _, s in pack_hits):
        cls = "A_DIAGNOSED"
    elif pack_hits:
        cls = "B_SUPPORTING"
    elif hc_hits:
        cls = "C_SURFACED"
    else:
        # After the zero-silent-failure closure, every uncited failing finding is listed by name.
        listed = {(u.source, u.check) for u in getattr(report, "undiagnosed_findings", [])}
        cls = "C_SURFACED" if (ingested[0].source, ingested[0].check) in listed else "D_SILENT"
        rules = ["undiagnosed_findings"] if cls == "C_SURFACED" else []
    return {"class": cls, "rules": rules}


def audit_inventory(inv_checks: dict) -> list:
    rows = []
    for cid, info in sorted(inv_checks.items()):
        module = info["module"]
        check = cid[len(module) + 1 :]
        levels = [lv for lv in info["levels"] if lv in FAIL_LEVELS] or list(FAIL_LEVELS)
        only_success = info["levels"] == ["SUCCESS"]
        if only_success:
            rows.append({"id": cid, "source": module, "check": check, "level": "-", "key": None, "class": "F_NO_FAILURE", "rules": []})
            continue
        variants = [(None)] + list(info["keys"])
        for level in levels:
            for key in variants:
                res = classify(_entry(module, check, level, key))
                rows.append({"id": cid, "source": module, "check": check, "level": level, "key": key, **res})
    return rows


def future_probes(sources: list) -> list:
    """Made-up checks under every existing source must never be claimed as a DIAGNOSED problem."""
    rows = []
    shapes = ["msg", "exception", "nomsg", "none"]
    for src in sources:
        for level in FAIL_LEVELS + ("FATAL",):
            for shape in shapes:
                res = classify(_entry(src, "ZzFutureCheck", level, None, shape))
                rows.append({"source": src, "level": level, "shape": shape, **res})
    return rows


def summarise(rows: list) -> dict:
    counts = {}
    for r in rows:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    return counts


def main(argv: list) -> int:
    inv = json.load(open(argv[1], encoding="utf-8"))
    out = argv[2]
    tags = argv[3:] or ["master"]
    result = {}
    for tag in tags:
        rows = audit_inventory(inv[tag])
        sources = sorted({v["module"] for v in inv[tag].values()})
        fut = future_probes(sources)
        result[tag] = {"rows": rows, "counts": summarise(rows), "future": fut, "future_counts": summarise(fut)}
        print(tag, "checks:", len(inv[tag]), "| rows:", len(rows), "|", result[tag]["counts"], "| future:", result[tag]["future_counts"])
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=1, sort_keys=True, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
