"""Support-bundle construction: the diagnosis that was just computed -> structured, sanitized bundle members.

Pipeline (docs/support-bundle.md):

    COLLECT MINIMUM -> STRUCTURE -> REMOVE PROHIBITED FIELDS -> REDACT -> PSEUDONYMIZE -> BOUND -> LEAK SELF-TEST
    -> WRITE

Nothing here collects anything new. The bundle is built from the evidence and report ipa-diagnose already produced
for this run, projected into a fixed set of members. Prohibited classes (raw tool output, fix commands, the local
replay path, anything under a secret-named field) are left out at the STRUCTURE step, before any text scanning runs.
"""

from __future__ import annotations

import collections
import dataclasses
import datetime
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from ipa_diagnose import __version__
from ipa_diagnose.bundle.sanitize import (
    CONST_ACCOUNTS, HARD_LIMIT, KEY_LIMIT, MAX_DEPTH, MAX_DICT_KEYS, MAX_LIST_ITEMS, PROSE_LIMIT, TEXT_LIMIT, Sanitizer,
    SanitizeTimeout)
from ipa_diagnose.engine.model import DiagnosisReport
from ipa_diagnose.evidence.healthcheck_catalog import CATALOG
from ipa_diagnose.evidence.model import EvidenceBundle, Severity
from ipa_diagnose.render.json_output import report_to_dict

BUNDLE_FORMAT = "ipa-diagnose-support-bundle"
BUNDLE_SCHEMA_VERSION = 1
TOP_DIR = "ipa-diagnose-bundle"
MEMBERS = ("README.txt", "manifest.json", "environment.json", "report.json", "healthcheck.json", "evidence.json",
           "collection-errors.json", "topology.json", "verification.json", "redaction-report.json", "SHA256SUMS")
# Members present only when asked for (`bundle --access USER HOST SERVICE`); a bundle without them stays valid.
OPTIONAL_MEMBERS = ("access.json",)
ALL_MEMBERS = MEMBERS[:MEMBERS.index("verification.json") + 1] + OPTIONAL_MEMBERS + MEMBERS[MEMBERS.index(
    "verification.json") + 1:]
DESCRIPTIONS = {
    "access.json": "one access question (ipa-diagnose access): states, FreeIPA's decision, rule paths; pseudonymized",
    "README.txt": "what this bundle is and is not, and how to inspect it",
    "manifest.json": "bundle format, versions, source mode, sanitization status, truncation, member checksums",
    "environment.json": "OS and FreeIPA component versions of the diagnosed host",
    "report.json": "the diagnosis: status, completeness, diagnoses, undiagnosed findings, resolutions (commands omitted)",
    "healthcheck.json": "ipa-healthcheck results, normalized (problems in full, successes as check names only)",
    "evidence.json": "targeted evidence items ipa-diagnose collected, structured",
    "collection-errors.json": "what could not be collected and what that leaves unverified",
    "topology.json": "replication agreements and RUV entries seen from this host",
    "verification.json": "context about a saved verify baseline (context only)",
    "redaction-report.json": "counts of what was pseudonymized, redacted, removed and truncated",
    "SHA256SUMS": "SHA-256 of every other member (sha256sum -c format)",
}
LIMITS = {
    "max_findings": 1000, "max_evidence_items": 500, "max_collection_errors": 200, "max_diagnoses": 200,
    "max_undiagnosed_findings": 500, "max_baseline_diagnoses": 100, "text_chars": TEXT_LIMIT, "prose_chars": PROSE_LIMIT,
    "key_chars": KEY_LIMIT, "unprocessed_text_chars": HARD_LIMIT, "max_mapping_keys": MAX_DICT_KEYS,
    "max_list_items": MAX_LIST_ITEMS, "max_nesting": MAX_DEPTH, "member_bytes": 8 * 1024 * 1024,
    "total_bytes": 32 * 1024 * 1024, "processing_seconds": 300,
}
VOLATILE_FIELDS = ["manifest.json:created_at", "README.txt:Created", "report.json:generated_at",
                   "healthcheck.json:findings[].when", "evidence.json:items[].collected_at"]
EXCLUDED_CLASSES = [
    "passwords and Directory Manager credentials", "private keys (TLS, SSH, CA)", "keytab contents",
    "Kerberos tickets and credential caches", "API, bearer and cloud tokens", "cookies and authorization headers",
    "AI provider credentials", "environment variables and shell history", "raw journals and raw tool output",
    "full LDAP entries and configuration files", "commands of offered fixes and rollbacks",
    "the local replay fixture path", "the pseudonym mapping itself",
]


class BundleTooLarge(Exception):
    pass


@dataclasses.dataclass
class Built:
    members: Dict[str, bytes]
    manifest: Dict[str, Any]
    privacy: Dict[str, Any]
    counts: Dict[str, int]
    sanitizer: Sanitizer
    source_mode: str
    local_host: Optional[str]


def _cap(seq: List[Any], limit: int, dropped: collections.Counter, name: str) -> List[Any]:
    if len(seq) > limit:
        dropped[name] += len(seq) - limit
        return seq[:limit]
    return seq


def _cited(report: DiagnosisReport) -> Dict[str, List[str]]:
    cited: Dict[str, List[str]] = collections.defaultdict(list)
    for d in report.diagnoses:
        for ref in list(d.evidence_for) + list(d.evidence_against):
            if d.diagnosis_id not in cited[ref.evidence_id]:
                cited[ref.evidence_id].append(d.diagnosis_id)
    return cited


def _raw_reason(evidence: EvidenceBundle, collector: str, shortened: Any) -> Any:
    """The collector's own, untruncated message. The report's reason was already shortened before any bundle
    processing, so where it was cut could hint at the length of a real name inside it; the bundle pipeline
    pseudonymizes the full text first and bounds it afterwards."""

    for e in evidence.collection_errors:
        if e.collector == collector:
            return str(e.message)
    return shortened


WITHHELD = "[WITHHELD: free text of a check this ipa-diagnose build does not know]"
# engine diagnoses whose text quotes raw ipa-healthcheck messages and keywords: regenerated from structured fields
_QUOTING_RULES = {("healthcheck", "unexplained-findings"), ("healthcheck", "healthcheck-check-failed")}


_PLACEHOLDER = __import__("re").compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,40})\}")


def _full_message(f) -> str:
    """The finding's message with its {placeholders} filled from its keywords, unshortened: the bundle redacts the
    full text first and bounds it afterwards (the report's display copy was already cut at 300 characters)."""

    kw = f.keywords if isinstance(f.keywords, dict) else {}
    if not f.message:
        return "(no message; fields: " + ", ".join(str(k) for k in list(kw)[:8]) + ")"
    return _PLACEHOLDER.sub(lambda m: str(kw.get(m.group(1), m.group(0))), f.message[:20000])


def _withheld_key(f) -> Any:
    return None if f.keywords.get("key") is None else "[WITHHELD]"


def _known_check(source: Any, check: Any) -> bool:
    return f"{source}.{check}" in CATALOG


def _project_report(report: DiagnosisReport, evidence: EvidenceBundle, mode: str,
                    dropped: collections.Counter) -> Dict[str, Any]:
    rd = report_to_dict(report)
    findings = {f.finding_id: f for f in evidence.findings}
    comp = dict(rd["evidence_completeness"])
    comp["unverified"] = [dict(u, reason=_raw_reason(evidence, u["collector"], u["reason"])) for u in comp["unverified"]]
    if comp.get("ruv_reason"):
        comp["ruv_reason"] = _raw_reason(evidence, "replication_agreements", comp["ruv_reason"])
    diagnoses = []
    for d in _cap(rd["diagnoses"], LIMITS["max_diagnoses"], dropped, "diagnoses"):
        d = dict(d)
        d.pop("ai_explanation", None)  # AI text is never part of a bundle
        if (d["pack_id"], d["rule_id"]) in _QUOTING_RULES:
            cited = [findings[r["evidence_id"]] for r in d["evidence_for"] if r["evidence_id"] in findings]
            d["why"] = (f"{len(cited)} ipa-healthcheck finding(s) that no ipa-diagnose rule explains: "
                        + "; ".join(f"{f.source}.{f.check} ({f.severity.value})" for f in cited)
                        + ". Their details are in healthcheck.json (text of checks this build does not know is "
                          "withheld). Rewritten for the bundle from structured fields.")
        d["actions"] = [
            {"description": a["description"], "risk": a["risk"], "reference": a["reference"],
             # read-only diagnostic commands (with placeholders) are kept; state-changing ones are omitted
             "command": a["command"] if a["risk"] == "SAFE" else None,
             "command_omitted": a["risk"] != "SAFE" and a["command"] is not None}
            for a in d["actions"]]
        diagnoses.append(d)
    undiagnosed = []
    for u, raw in zip(report.undiagnosed_findings, rd["undiagnosed_findings"]):
        entry = dict(raw, finding_id=u.finding_id)
        if u.finding_id in findings:
            entry["message"] = _full_message(findings[u.finding_id])
        if not _known_check(u.source, u.check):
            entry["message"] = WITHHELD
            entry["key"] = None if u.key is None else "[WITHHELD]"
        undiagnosed.append(entry)
    resolutions = []
    for r in rd["v2"]["resolutions"]:
        resolutions.append({
            "diagnosis_id": r["diagnosis_id"], "status": r["status"], "procedure_id": r["procedure_id"],
            "title": r["title"], "reasons": r["reasons"], "tier": r["tier"], "definitive": r["definitive"],
            "verification_label": r["verification_label"], "risk": r["risk"], "applies_to": r["applies_to"],
            "reference": r["reference"], "impact_note": r["impact_note"], "limitations": r["limitations"],
            "checked": [{"label": c["label"], "check": c["check"], "status": c["status"], "result": c["result"],
                         "source": c["source"]} for c in r["checked"]],
            "prerequisites": r["prerequisites"],
            "steps": [{"id": s["id"], "text": s["text"], "risk": s["risk"], "run_on": s["run_on"]} for s in r["steps"]],
            "what_changes": r["what_changes"],
            "verify": [v.get("text") if isinstance(v, dict) else v for v in r["verify"]],
            "rollback_step_count": len(r["rollback"]), "confirm_first_step_count": len(r["confirm_first"]),
            "commands_omitted": True,
            "evaluated_against": "RECORDED EVIDENCE" if mode == "REPLAY" else "THE DIAGNOSED HOST (LIVE)",
        })
    return {
        "source_mode": mode,
        "note": ("A recorded diagnosis, not live evidence. Every fix below was evaluated for the diagnosed host only; "
                 "its commands are omitted. Re-run ipa-diagnose on the machine you intend to change."),
        "report_schema_version": rd["report_schema_version"],
        "generated_at": rd["generated_at"],
        "hostname": rd["hostname"],
        "overall_status": rd["overall_status"],
        "fully_verified": rd["fully_verified"],
        "evidence_completeness": comp,
        "packs_evaluated": rd["packs_evaluated"],
        "unknown_severity_findings": rd["unknown_severity_findings"],
        "unclaimed_warnings": rd["unclaimed_warnings"],
        "undiagnosed_count": rd["undiagnosed_count"],
        "undiagnosed_findings": _cap(undiagnosed, LIMITS["max_undiagnosed_findings"], dropped, "undiagnosed_findings"),
        "diagnoses": diagnoses,
        "resolutions": resolutions,
        "service_states": rd["v2"]["service_states"],
        "side_effects": rd["v2"]["side_effects"],
    }


def _project_healthcheck(evidence: EvidenceBundle, report: DiagnosisReport, mode: str, cited, dropped) -> Dict[str, Any]:
    undiagnosed = {u.finding_id for u in report.undiagnosed_findings}
    problems, successes = [], []
    counts: Dict[str, int] = collections.Counter()
    for f in evidence.findings:
        counts[f.severity.value] += 1
        if f.severity == Severity.SUCCESS:
            successes.append({"finding_id": f.finding_id, "source": f.source, "check": f.check,
                              "severity": "SUCCESS",
                              "key": f.keywords.get("key") if f.qualified_check in CATALOG else _withheld_key(f)})
            continue
        known = f.qualified_check in CATALOG
        kw = {k: v for k, v in f.keywords.items() if k not in ("msg", "key")}
        entry = {
            "finding_id": f.finding_id, "source": f.source, "check": f.check, "severity": f.severity.value,
            "key": f.keywords.get("key") if known else _withheld_key(f), "message": f.message if known else WITHHELD,
            # a check this build does not know: which fields it reported, not their free-text values
            "keywords": kw if known else {"withheld_field_names": sorted(kw)},
            "when": f.raw.get("when") if isinstance(f.raw, dict) else None,
            "evidence_tier": "LIVE" if f.provenance.live else "REPLAY",
            "diagnosed_by": cited.get(f.finding_id, []),
            "undiagnosed": f.finding_id in undiagnosed,
            "check_known_to_this_build": f.qualified_check in CATALOG,
        }
        if f.severity == Severity.UNKNOWN:
            entry["result"] = f.raw.get("result") if isinstance(f.raw, dict) else None
        problems.append(entry)
    findings = _cap(problems + successes, LIMITS["max_findings"], dropped, "findings")
    return {
        "source_mode": mode,
        "collected": report.evidence_completeness.healthcheck_collected,
        "counts_by_severity": dict(sorted(counts.items())),
        "findings": findings,
        "note": "Problems are listed first and in full; successful checks are listed by name only.",
    }


_ITEM_DROP = {"klist_ticket": ("tickets", "raw"), "clock_sync": ("raw",), "certmonger_request": ("serial",)}


def _project_evidence(evidence: EvidenceBundle, mode: str, cited, dropped) -> Dict[str, Any]:
    items = sorted(evidence.items, key=lambda i: 0 if i.item_id in cited else 1)
    out = []
    for i in _cap(items, LIMITS["max_evidence_items"], dropped, "evidence_items"):
        data = {k: v for k, v in (i.data or {}).items() if k not in _ITEM_DROP.get(i.kind, ())}
        if i.kind == "klist_ticket":
            data["ticket_count"] = len(i.data.get("tickets") or [])
        summary = i.summary if len(i.summary or "") < 195 else "[shortened by the collector; the full text is in data]"
        out.append({
            "item_id": i.item_id, "kind": i.kind, "severity": i.severity.value if i.severity else None,
            "summary": summary, "data": data, "collected_by": i.provenance.source,
            "command": i.provenance.command, "collected_at": i.provenance.collected_at,
            "evidence_tier": "LIVE" if i.provenance.live else "REPLAY", "cited_by": cited.get(i.item_id, []),
        })
    return {"source_mode": mode, "items": out,
            "note": "Structured evidence only: raw tool output, ticket lists and certificate serials are not included."}


def _error_category(message: str, permission: bool) -> str:
    m = message.lower()
    if permission or "permission denied" in m or "not permitted" in m or "must be root" in m:
        return "permission"
    if "timed out" in m or "timeout" in m:
        return "timeout"
    if "not installed" in m or "not found" in m or "no such file" in m or "not on path" in m:
        return "not_available"
    if "malformed" in m or "invalid" in m or "json" in m or "parse" in m or "decode" in m:
        return "unparseable_output"
    return "other"


def _project_errors(evidence: EvidenceBundle, report: DiagnosisReport, mode: str, dropped) -> Dict[str, Any]:
    comp = report.evidence_completeness
    errors = []
    for e in _cap(list(evidence.collection_errors), LIMITS["max_collection_errors"], dropped, "collection_errors"):
        errors.append({
            "collector": e.collector, "category": _error_category(str(e.message), e.permission_related),
            "permission_related": e.permission_related, "message": str(e.message),
            "leaves_unverified": [u.capability for u in comp.unverified if u.collector == e.collector],
        })
    return {
        "source_mode": mode,
        "completeness": comp.level,
        "errors": errors,
        "unverified": [{"capability": u.capability, "collector": u.collector,
                        "reason": _raw_reason(evidence, u.collector, u.reason),
                        "permission_related": u.permission_related, "hint": u.hint} for u in comp.unverified],
    }


def _project_topology(evidence: EvidenceBundle, report: DiagnosisReport, mode: str) -> Dict[str, Any]:
    agreements = evidence.items_by_kind("replication_agreement")
    ruv = evidence.items_by_kind("replication_ruv")
    topo = evidence.items_by_kind("replication_topology")
    return {
        "source_mode": mode,
        "available": bool(agreements or ruv or topo),
        "local_host": evidence.hostname,
        "ruv_state": report.evidence_completeness.ruv_state,
        "agreements": [{"from": evidence.hostname, "to": a.data.get("peer"), "status": a.data.get("status"),
                        "last_update_status": a.data.get("last_update_status"),
                        "last_update_ended": a.data.get("last_update_ended")} for a in agreements],
        "ruv": [{k: v for k, v in r.data.items()} for r in ruv],
        "state": [t.data.get("state") for t in topo],
        "note": ("What this one host reported about replication. It does not say which server is at fault; the same "
                 "pseudonym means the same host in every member of this bundle."),
    }


def _project_verification(previous: Optional[Dict[str, Any]], mode: str) -> Dict[str, Any]:
    base = {"source_mode": mode, "context_only": True,
            "note": ("Context only. A saved baseline is never transferred: ipa-diagnose verify on any machine uses "
                     "that machine's own state and fresh read-only checks, never this bundle.")}
    if not previous:
        return dict(base, baseline_present=False)
    v2 = previous.get("v2") if isinstance(previous.get("v2"), dict) else {}
    vb = v2.get("verify_baseline") if isinstance(v2.get("verify_baseline"), dict) else {}
    fixes = [f for f in (vb.get("fixes") or []) if isinstance(f, dict)]
    carried = v2.get("carried_diagnoses") if isinstance(v2.get("carried_diagnoses"), list) else []
    return dict(
        base, baseline_present=True,
        baseline_generated_at=str(previous.get("generated_at")),
        baseline_host=str(previous.get("hostname") or ""),
        baseline_overall_status=str(previous.get("overall_status") or ""),
        baseline_diagnoses=[{"diagnosis_id": d.get("diagnosis_id"), "status": d.get("status"),
                             "priority": d.get("priority")}
                            for d in previous.get("diagnoses", [])[:LIMITS["max_baseline_diagnoses"]]],
        fixes_awaiting_verify=[{"diagnosis_id": str(f.get("diagnosis_id")), "procedure_id": str(f.get("procedure_id"))}
                               for f in fixes[:LIMITS["max_baseline_diagnoses"]]],
        carried_diagnoses_count=len(carried),
    )


def _project_environment(evidence: EvidenceBundle, report: DiagnosisReport, mode: str) -> Dict[str, Any]:
    env = report.environment
    meta = next((f.keywords for f in evidence.findings if f.source == "ipahealthcheck.meta.core"
                 and isinstance(f.keywords, dict) and f.keywords.get("ipa_version")), {})
    host = evidence.hostname
    domain = host.split(".", 1)[1] if "." in host.strip(".") else None
    return {
        "source_mode": mode,
        "host": host,
        "domain": domain,
        "distro": env.distro if env else None,
        "distro_version": env.distro_version if env else None,
        "freeipa_version": env.freeipa_version if env else None,
        "ipa_healthcheck_version": env.ipa_healthcheck_version if env else None,
        "directory_server_version": env.directory_server_version if env else None,
        "python_version": env.python_version if env else None,
        "detected_live": env.detected_live if env else None,
        # what ipa-healthcheck itself reported (MetaCheck), independent of ipa-diagnose's own detection
        "freeipa_version_reported_by_ipa_healthcheck": meta.get("ipa_version"),
        "fields_note": "null means the value was not detected (recorded evidence often does not include it).",
    }


def _dumps(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _readme(mode: str, created_at: str, local_host: Optional[str]) -> str:
    source = ("LIVE - collected from the diagnosed host when the bundle was created" if mode == "LIVE" else
              "REPLAY - read from a recorded fixture directory; it describes no live system")
    return f"""ipa-diagnose support bundle
===========================

Format:  {BUNDLE_FORMAT}, schema {BUNDLE_SCHEMA_VERSION}
Created: {created_at} by ipa-diagnose {__version__}
Source:  {source}
Host:    {local_host or "HOST-001"} (the host this bundle describes)

WHAT THIS IS
  One structured, sanitized snapshot of a single ipa-diagnose run, made to be reviewed
  and then shared with someone helping you troubleshoot FreeIPA / IdM. It was created on
  request; nothing was uploaded, and ipa-diagnose never sends a bundle anywhere.

WHAT THIS IS NOT
  Not a backup, not a sosreport, not a copy of logs, LDAP entries or configuration.
  Not live evidence: it records what one host reported at one time.
  Not instructions: fixes are listed by procedure and status only, without commands.
  Not encrypted: share it over a channel you trust.
  A recorded fix is never a fix for another machine; re-run ipa-diagnose there.

PRIVACY
  Host names, DNS domains, Kerberos realms, LDAP suffixes, Directory Server instance
  names, IP addresses, user, group, host group and service names that ipa-diagnose could
  identify are replaced by pseudonyms such as HOST-002 or REALM-001. Pseudonyms are
  numbered in this bundle only and are consistent across all of its files; the mapping
  to real names is not stored anywhere.
  Values that look like credentials are replaced with [REDACTED:category] and
  secret-named fields with [REMOVED]. Excluded by design: credentials of any kind,
  private keys, keytab contents, Kerberos tickets and caches, tokens, cookies, raw
  journals and raw tool output, full LDAP entries, configuration files, environment
  variables, shell history, and fix commands.
  Before the bundle was written, every file was scanned for the real identifiers that
  were replaced and for credential patterns; the bundle is only written if that scan
  finds nothing.
  Detection is pattern-based and cannot be perfect. The bundle still contains
  operational detail: service and unit names, versions, error text, timestamps,
  certificate expiry dates and the shape of the topology. Review it before sharing.
  redaction-report.json lists what was changed (counts only).

EVIDENCE TIERS
  manifest.json source_mode is LIVE or REPLAY; every other file repeats it.
  In report.json each resolution carries its knowledge tier and whether it was
  definitive for the diagnosed host: FIXTURE_ONLY (tested on recorded evidence only),
  LIVE_VERIFIED (applied and verified in a live lab), BUILT_IN_VERIFIED (also reviewed
  and promoted; definitive only on the exact live-verified FreeIPA version and OS).

CHECKING IT
  ipa-diagnose bundle validate <this file>     (reads the archive, extracts nothing)
  or, after extracting: sha256sum -c SHA256SUMS
  Checksums detect accidental change. They are not a signature and do not prove who
  made the bundle: anyone who edits it can recompute them.

IF YOU RECEIVED THIS BUNDLE
  Treat it as untrusted input. Prefer ipa-diagnose bundle validate over extracting it,
  and never run anything from it. Its content describes another system at another
  time and is never a diagnosis of the machine you are on.
"""


# PAM/HBAC service names that identify nothing about a deployment; any other service name is pseudonymized.
GENERIC_SERVICES = frozenset({
    "sshd", "login", "su", "su-l", "sudo", "sudo-i", "gdm", "gdm-password", "gdm-autologin", "gdm-smartcard",
    "kdm", "lightdm", "xdm", "sddm", "vsftpd", "proftpd", "pure-ftpd", "ftp", "crond", "systemd-user", "polkit-1",
    "cockpit", "xrdp-sesman", "other", "passwd", "screen", "tmux", "httpd",
})


def _project_access(result: Any, mode: str, s: Sanitizer) -> Dict[str, Any]:
    """STRUCTURE for one access answer: states, codes, flags, counts and rule paths only - no free text (summaries,
    titles and details embed names), no commands. Every name is replaced by a bundle pseudonym here, structurally;
    names the sanitizer keeps on purpose (admin, ipausers...) stay, and names too short for the text rules get a
    pseudonym of their own class."""

    from ipa_diagnose.access.evaluate import State
    from ipa_diagnose.access.output import ACCESS_SCHEMA_VERSION

    short: Dict[tuple, str] = {}

    def pn(cls: str, name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        low = name.strip().rstrip(".").lower()
        if cls == "SERVICE" and low in GENERIC_SERVICES:
            return low
        key = (cls, low)
        if key in s._map:  # the same identity already seen in the other members: the same pseudonym
            return s._map[key]
        if cls in ("USER", "GROUP") and low in CONST_ACCOUNTS:
            return low
        if key not in short:
            # A pseudonym number of its own, NOT registered for text replacement: these names are only ever written
            # here, structurally, and registering an access target such as "backup" or "support" would make the
            # self-test find the word in the bundle's own README and refuse the bundle.
            short[key] = s._alloc(cls)
        return short[key]

    kinds = {"user": ("USER", "GROUP"), "host": ("HOST", "HOSTGROUP"), "service": ("SERVICE", "SERVICE")}

    def side(sd, k: str) -> Dict[str, Any]:
        obj_cls, grp_cls = kinds[k]
        chain = [pn(obj_cls if i == 0 else grp_cls, c) if c != "..." else "..." for i, c in enumerate(sd.chain)]
        return {"how": sd.how, "via": pn(grp_cls, sd.via), "chain": chain, "chain_complete": sd.chain_complete,
                "count": sd.count}

    ev = result.evaluation
    t = result.targets
    rule_names = {e.rule for e in result.rules} | set(ev.matched)
    rule_pn = {n: f"RULE-{i + 1:03d}" for i, n in enumerate(sorted(rule_names, key=str.lower))}
    return {
        "source_mode": mode,
        "access_schema_version": ACCESS_SCHEMA_VERSION,
        "query": {"user": pn("USER", result.account.canonical or t.user),
                  "user_is_trusted_domain_form": bool(t.user_domain),
                  "host": pn("HOST", result.host.canonical or t.host),
                  "service": pn("SERVICE", result.service.canonical or t.service)},
        "authentication": {"state": result.authentication.state.value},
        # AUTHORIZATION, under a key the bundle's secret-field rule (which removes any "authoriz..." key) keeps
        "hbac_policy_decision": {"state": result.authorization.state.value,
                          "decided_by": "FreeIPA hbactest"
                          if result.authorization.state in (State.PASS, State.FAIL) else None},
        "runtime_access": {"state": result.runtime.state.value},
        "authoritative_evaluation": {"ran": ev.ran, "granted": ev.granted,
                                     "matched_rules": [rule_pn[n] for n in ev.matched],
                                     "not_matched_rule_count": ev.not_matched_count,
                                     "error_rule_count": len(ev.error_rules), "rule_list_truncated": ev.truncated,
                                     "failed": ev.error is not None},
        "account": {"exists": result.account.exists, "disabled": result.account.disabled,
                    "principal_expired": result.account.principal_expired,
                    "password_expired": result.account.password_expired},
        "host": {"exists": result.host.exists, "has_keytab": result.host.has_keytab},
        "service": {"exists": result.service.exists},
        "rules": [{"rule": rule_pn[e.rule], "matched_by_freeipa": e.matched_by_freeipa, "enabled": e.enabled,
                   "explanation_status": e.status,
                   "sides": {k: [side(x, k) for x in v] for k, v in e.sides.items()}} for e in result.rules],
        "explanation_status": result.explanation_status,
        "findings": [{"code": f.code, "blocking": f.blocking} for f in result.findings],
        "checks": [{"call": c.call.split(" ", 1)[0], "outcome": c.outcome} for c in result.checks],
        "resolution": {"status": "NONE", "commands_included": False},
        "note": "Names are bundle pseudonyms (rules are RULE-nnn in this file only). The decision is FreeIPA's own "
                "HBAC evaluation; runtime access was not tested.",
    }


def build(evidence: EvidenceBundle, report: DiagnosisReport, *, previous: Optional[Dict[str, Any]] = None,
          created_at: Optional[str] = None, access: Any = None) -> Built:
    mode = "REPLAY" if evidence.replay_source is not None else "LIVE"
    created_at = created_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dropped: collections.Counter = collections.Counter()
    cited = _cited(report)

    # STRUCTURE (+ remove prohibited classes): fixed projections of what this run already produced
    raw = {
        "environment.json": _project_environment(evidence, report, mode),
        "report.json": _project_report(report, evidence, mode, dropped),
        "healthcheck.json": _project_healthcheck(evidence, report, mode, cited, dropped),
        "evidence.json": _project_evidence(evidence, mode, cited, dropped),
        "collection-errors.json": _project_errors(evidence, report, mode, dropped),
        "topology.json": _project_topology(evidence, report, mode),
        "verification.json": _project_verification(previous, mode),
    }

    # identities: the diagnosed host first (HOST-001), its domain, the default realm, then everything discovered
    s = Sanitizer()
    s.deadline = time.monotonic() + LIMITS["processing_seconds"]
    for obj in raw.values():
        s.reserve(obj)
    if evidence.replay_source:
        for form in (evidence.replay_source, os.path.abspath(evidence.replay_source)):
            s.add_literal(form, "<replay-fixture>")
    home = os.path.expanduser("~")
    if home not in ("/", "/root", "~"):
        s.add_literal(home, "<home>")
    host = evidence.hostname.strip().rstrip(".")
    # the diagnosed host, its domain and realm are always pseudonymized, even inside a well-known public domain
    s.own_public_parent(host)
    s.add_host(host, force=True)
    if "." in host:
        domain = host.split(".", 1)[1]
        s.add_domain(domain, force=True)
        s.add_realm(domain.upper(), force=True)
    for f in evidence.findings:  # secret-field values from the raw evidence, including fields that are withheld
        s.track_secrets(f.keywords)
    for i in evidence.items:
        s.track_secrets(i.data)
    try:
        for obj in raw.values():
            s.discover(obj)
        if access is not None:  # after discovery, so a name also seen elsewhere keeps its pseudonym
            raw["access.json"] = _project_access(access, mode, s)
        # REDACT -> PSEUDONYMIZE -> BOUND, for every key and string
        final = {name: s.transform(obj) for name, obj in raw.items()}
    except SanitizeTimeout:
        raise BundleTooLarge(f"sanitizing the evidence took longer than {LIMITS['processing_seconds']} seconds")
    local_host = s.local_host_pseudonym(host)
    final["environment.json"]["note"] = f"{local_host or 'HOST-001'} is the host this bundle describes."

    counts = {
        "diagnoses": len(final["report.json"]["diagnoses"]),
        "resolutions": len(final["report.json"]["resolutions"]),
        "undiagnosed_findings": len(final["report.json"]["undiagnosed_findings"]),
        "healthcheck_findings": len(final["healthcheck.json"]["findings"]),
        "healthcheck_problems": sum(1 for f in final["healthcheck.json"]["findings"] if f["severity"] != "SUCCESS"),
        "evidence_items": len(final["evidence.json"]["items"]),
        "collection_errors": len(final["collection-errors.json"]["errors"]),
        "replication_agreements": len(final["topology.json"]["agreements"]),
    }
    truncation = {
        "strings_truncated": s.truncated, "strings_omitted_as_too_large": s.omitted,
        "structures_trimmed": s.structure_trimmed, "entries_dropped_by_limits": dict(sorted(dropped.items())),
    }
    complete = not (s.truncated or s.omitted or s.structure_trimmed or dropped)
    privacy = {
        "source_mode": mode,
        "pseudonymized_identifiers": s.pseudonym_counts(),
        "identifiers_found_only_by_host_name_heuristic": s.heuristic_hosts,
        "pseudonym_shaped_text_in_input": s.pseudonym_shaped_input,
        "redacted_values": dict(sorted(s.redactions.items())),
        "secret_named_fields_removed": s.removed_fields,
        "raw_output_fields_dropped": s.raw_fields_dropped,
        "certificate_serial_fields_removed": s.serial_fields_removed,
        "truncation": truncation,
        "excluded_by_design": EXCLUDED_CLASSES,
        "pseudonym_mapping_stored": False,
        "leak_self_test": "passed",
        "limitations": [
            "Secret and identity detection is pattern-based and cannot be complete.",
            "Names that appear only in free text and match no known host, domain, realm or pattern stay as written.",
            "Operational detail (unit names, versions, error text, timestamps, topology shape) remains.",
        ],
    }
    final["redaction-report.json"] = privacy

    members: Dict[str, bytes] = {"README.txt": _readme(mode, created_at, local_host).encode("utf-8")}
    for name in ALL_MEMBERS:
        if name in final:
            members[name] = _dumps(final[name])

    manifest = {
        "bundle_format": BUNDLE_FORMAT,
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "created_at": created_at,
        "created_by": {"tool": "ipa-diagnose", "version": __version__, "command": "ipa-diagnose bundle"},
        "source_mode": mode,
        "source_description": (
            "LIVE: collected from the diagnosed host (HOST-001) when the bundle was created" if mode == "LIVE" else
            "REPLAY: read from a recorded fixture directory (path not included); describes no live system"),
        "report_schema_version": final["report.json"]["report_schema_version"],
        "overall_status": final["report.json"]["overall_status"],
        "evidence_completeness": final["report.json"]["evidence_completeness"]["level"],
        "evidence_tiers": {
            "diagnostic_evidence": mode,
            "resolution_knowledge": sorted({r["tier"] for r in final["report.json"]["resolutions"] if r.get("tier")}),
        },
        "counts": counts,
        "sanitization": {
            "pipeline": ["structure", "remove prohibited fields", "redact", "pseudonymize", "bound", "leak self-test"],
            "pseudonymization": "bundle-local sequential pseudonyms; the mapping is not stored",
            "leak_self_test": "passed",
            "secret_detection_complete": False,
        },
        "truncation": truncation,
        "content_complete": complete,
        "limits": LIMITS,
        "volatile_fields": VOLATILE_FIELDS,
        "integrity": ("SHA-256 values detect accidental change. They are not a signature: anyone who edits the bundle "
                      "can recompute them."),
        "members": [{"name": n, "sha256": hashlib.sha256(members[n]).hexdigest(), "bytes": len(members[n]),
                     "content": DESCRIPTIONS[n]} for n in ALL_MEMBERS if n in members],
    }
    members["manifest.json"] = _dumps(manifest)
    sums = "".join(f"{hashlib.sha256(members[n]).hexdigest()}  {n}\n" for n in ALL_MEMBERS if n in members)
    members["SHA256SUMS"] = sums.encode("ascii")
    members = {n: members[n] for n in ALL_MEMBERS if n in members}

    for name, data in members.items():
        if len(data) > LIMITS["member_bytes"]:
            raise BundleTooLarge(f"{name} would be {len(data)} bytes (limit {LIMITS['member_bytes']})")
    if sum(len(d) for d in members.values()) > LIMITS["total_bytes"]:
        raise BundleTooLarge(f"the bundle would exceed {LIMITS['total_bytes']} bytes")
    return Built(members=members, manifest=manifest, privacy=privacy, counts=counts, sanitizer=s, source_mode=mode,
                 local_host=local_host)
