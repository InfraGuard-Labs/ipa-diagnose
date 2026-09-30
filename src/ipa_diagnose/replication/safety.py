"""Resolution Safety gate and No-Google gate for `ipa-diagnose replication` (Slice 5).

The Slice 1 resolution engine decides whether a procedure's own conditions hold (confidence, typed values,
applicability, fresh read-only checks, ``withhold_if``, prerequisites). BEFORE it is asked, this gate checks what a
replication investigation adds, every condition machine-checked and any unknown one withholding the fix:

* the deepest link of the diagnosis's cause chain(s) is ESTABLISHED and the diagnosis is that deepest cause;
* the role is PRIMARY or INDEPENDENT; the confidence is HIGH; nothing is UNDIAGNOSED, CONTRADICTING or TRANSIENT;
* the target is THIS server (subject ``server:<this host>``): no command is ever printed for another server;
* no contradiction anywhere in the investigation; the evidence is LIVE (REPLAY cannot satisfy these gates) and
  younger than :data:`MAX_EVIDENCE_AGE`;
* the exact target is revalidated with a FRESH check (the result the diagnosis rests on is re-read now);
* topology predicates the procedure declares (sole CA/KRA/DNS, renewal master, DNSSEC key master, articulation
  point) are ESTABLISHED as safe from a COMPLETE topology read;
* the procedure is on the allowlist of what Slice 5 may print at all (:data:`SLICE5_PROCEDURES`), its programs are
  allowlisted, and nothing in it matches a forbidden operation (:data:`FORBIDDEN`).

AFTER an OFFERED procedure, :func:`no_google` checks the completeness a "No-Google" claim needs (named target, exact
commands, host per step, prerequisites met, what changes, expected result, what to do if a step fails, risk, backup
or a reason from a closed list, rollback or a reason from a closed list, verification tied to the original incident)
and whether the procedure is LIVE-verified on this FreeIPA version and OS. Only then is the claim made.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
from typing import Any, Dict, List, Optional, Tuple

MAX_EVIDENCE_AGE = 300  # seconds

# The only procedures a replication diagnosis may lead to in Slice 5, with the No-Google metadata the catalogue
# format does not carry. Anything else is withheld whatever the catalogue says.
SLICE5_PROCEDURES: Dict[str, Dict[str, Any]] = {
    "proc.service.start-stopped-service": {
        "backup": "NO_DATA_CHANGED",
        "on_failure": ("If 'systemctl start' fails, the unit stays stopped and nothing else changed: read "
                       "'systemctl status {unit}' and 'journalctl -u {unit} -n 50' (read-only) for the reason, fix "
                       "that cause, and run ipa-diagnose replication again. Do not use 'ipactl start' instead: it "
                       "stops every IPA service when one of them fails to start."),
        "topology": (),
        "revalidate": ("systemd.unit", "service"),
    },
}
# closed lists of reasons a procedure may give for having no backup / no rollback step
BACKUP_REASONS = {
    "NO_DATA_CHANGED": "no backup is needed: the procedure starts a service; no file, configuration or directory "
                       "data is changed",
}
ROLLBACK_REASONS = {
    "RESTORES_PRIOR_STATE_ONLY": "no rollback is needed: the procedure only returns a service to its configured state",
}
ALLOWED_PROGRAMS = frozenset({"systemctl"})
ALLOWED_SYSTEMCTL = frozenset({"start"})
# operations Slice 5 never prints, whatever a catalogue entry says (checked on every argv and rollback argv)
FORBIDDEN = tuple(re.compile(p) for p in (
    r"(?i)\bipa-(?:cs)?replica-manage\b", r"(?i)clean-?(?:all)?ruv", r"(?i)force-?sync", r"(?i)re-?initiali[sz]e",
    r"(?i)\bserver-del\b", r"(?i)\btopologysegment-", r"(?i)\bipa-server-install\b", r"(?i)--uninstall\b",
    r"(?i)\bipa-getkeytab\b", r"(?i)\bipa-rmkeytab\b", r"(?i)\bktutil\b", r"(?i)\bldap(?:modify|add|delete|passwd)\b",
    r"(?i)\bdsconf\b", r"(?i)\bdsctl\b", r"(?i)\bmakestep\b", r"(?i)\bdate\s+-s\b", r"(?i)set-time\b",
    r"(?i)\bcertutil\b", r"(?i)\bipa-cert-fix\b", r"(?i)\bconfig-mod\b", r"(?i)\bipa-crlgen-manage\b",
    r"(?i)\brm\s", r"(?i)/var/lib/sss", r"(?i)\bsss_cache\b", r"(?i)\bdisable\b", r"(?i)\bmask\b",
))
TOPOLOGY_PREDICATES = ("not_sole_ca", "not_sole_kra", "not_sole_dns", "not_renewal_master", "not_dnssec_key_master",
                       "not_articulation_point")


@dataclasses.dataclass
class GateContext:
    me: str
    replay: bool
    trace: Any
    diagnoses: List[Any]
    chains: Dict[str, Any]
    topology: Dict[str, Any]
    runner: Any
    now: datetime.datetime = dataclasses.field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))


def _age(iso: Optional[str], now: datetime.datetime) -> Optional[float]:
    if not iso:
        return None
    try:
        t = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return (now - t).total_seconds()


def topology_predicate(name: str, me: str, topo: Dict[str, Any]) -> Optional[bool]:
    """True = safe, False = unsafe, None = not established (a partial topology read never makes a predicate true)."""

    if not topo or topo.get("complete") is not True:
        return None
    roles = topo.get("roles") or {}
    holders = lambda role: sorted(h for h, rs in roles.items() if role in rs)  # noqa: E731
    if name in ("not_sole_ca", "not_sole_kra", "not_sole_dns"):
        role = {"not_sole_ca": "CA", "not_sole_kra": "KRA", "not_sole_dns": "DNS"}[name]
        h = holders(role)
        if not h:
            return None  # no holder established: nothing is known, never "safe"
        return not (h == [me])
    if name in ("not_renewal_master", "not_dnssec_key_master"):
        holder = topo.get("renewal_master" if name == "not_renewal_master" else "dnssec_key_master")
        if holder is None:
            return None  # none, or more than one, flagged: not established
        return holder != me
    if name == "not_articulation_point":
        return all(me not in (s.get("articulation_points") or []) for s in (topo.get("suffixes") or {}).values())
    return None


def resolution_gate(d: Any, ctx: GateContext, procedure_id: Optional[str]) -> List[str]:
    """Reasons to withhold a fix for diagnosis `d` (empty: the Slice 1 engine may be asked)."""

    reasons: List[str] = []
    here = f"server:{ctx.me}"
    if d.subject != here or d.scope != "local":
        where = d.subject.split(":", 1)[-1]
        return [f"The cause is not on this server ({where}): ipa-diagnose prints no command for another server and "
                "changes nothing remotely. Follow the handoff instead."]
    if d.kind in ("UNDIAGNOSED", "CONTRADICTING", "TRANSIENT"):
        reasons.append(f"The diagnosis is {d.kind}: nothing is fixed on an unexplained, contradicting or transient "
                       "picture.")
    if d.role not in ("PRIMARY", "INDEPENDENT"):
        reasons.append(f"This is reported as {d.role}, not as a root cause: fix its cause first.")
    if d.confidence != "HIGH":
        reasons.append(f"The cause is established with {d.confidence.lower()} confidence only.")
    for cid in d.chain_ids:
        ch = ctx.chains.get(cid)
        if (ch is None or not ch.links or ch.links[-1].subject != d.subject or not ch.links[-1].evidence
                or ch.links[-1].capability != d.capability):
            reasons.append("The deepest proven link of its cause chain is not this diagnosis.")
            break
    if not d.chain_ids:
        reasons.append("No established cause chain rests on this diagnosis.")
    contra = [x for x in ctx.diagnoses if getattr(x, "role", "") == "CONTRADICTING"]
    if contra:
        reasons.append(f"Contradicting evidence was found ({contra[0].title}): no fix is shown while the evidence "
                       "disagrees.")
    if ctx.replay:
        reasons.append("This is recorded (REPLAY) evidence: it cannot revalidate the target now, so no command is "
                       "shown from it.")
    elif not d.evidence:
        reasons.append("The diagnosis names no evidence, so its age cannot be established.")
    else:
        for sid in d.evidence:
            r = ctx.trace.get(sid)
            age = _age(r.collected_at if r else None, ctx.now)
            if age is None or age > MAX_EVIDENCE_AGE or age < -5:
                reasons.append(f"The evidence it rests on ({sid}) is missing or older than {MAX_EVIDENCE_AGE} s: run "
                               "ipa-diagnose replication again.")
                break
    meta = SLICE5_PROCEDURES.get(procedure_id or "")
    if procedure_id and meta is None:
        reasons.append("This procedure is not one ipa-diagnose replication may print.")
    if meta is not None:
        for pred in meta.get("topology", ()):
            ok = topology_predicate(pred, ctx.me, ctx.topology)
            if ok is not True:
                reasons.append(f"Topology safety ({pred.replace('_', ' ')}) is "
                               f"{'violated' if ok is False else 'not established from a complete topology read'}.")
        if not ctx.replay and not reasons and meta.get("revalidate"):
            check, binding = meta["revalidate"]
            value = (d.bindings or {}).get(binding)
            fresh = ctx.runner.run(check, {binding: value}, fresh=True) if value else None
            if fresh is None or fresh.status != "OK":
                reasons.append("The target could not be re-checked just now, so it is not established that it is "
                               "still in the diagnosed state.")
            elif check == "systemd.unit" and fresh.fields.get("active_state") == "active":
                reasons.append(f"{fresh.fields.get('unit')} is running now (re-checked just now): the state changed "
                               "since the diagnosis. Run ipa-diagnose replication again.")
    return reasons


def check_offered(res: Any) -> List[str]:
    """Structural limits on an OFFERED procedure (allowlisted programs and sub-commands, no forbidden operation,
    local only, HIGH risk needs rollback and backup). Reasons to withhold it."""

    out: List[str] = []
    argvs = [(s.argv, ALLOWED_SYSTEMCTL) for s in res.steps] + [(r["argv"], frozenset({"stop"}))
                                                                 for r in res.rollback if r.get("argv")]
    for argv, verbs in argvs:
        if not argv or argv[0] not in ALLOWED_PROGRAMS:
            out.append(f"'{argv[0] if argv else ''}' is not a program ipa-diagnose replication may print.")
        elif argv[0] == "systemctl" and (len(argv) != 3 or argv[1] not in verbs):
            out.append("Only 'systemctl start UNIT' (and its rollback 'systemctl stop UNIT') may be printed.")
        joined = " ".join(argv)
        if any(rx.search(joined) for rx in FORBIDDEN):
            out.append("The procedure contains an operation Slice 5 never prints.")
    for s in res.steps:
        if s.run_on != "local":
            out.append("A step would not run on this server.")
    if res.risk == "HIGH" and (not res.rollback or not res.confirm_first):
        out.append("A HIGH-risk procedure needs a rollback and a backup/confirmation step.")
    return sorted(set(out))


def _live_match(proc_prov: Dict[str, Any], freeipa: Optional[str], os_id: str) -> Optional[Dict[str, Any]]:
    from ipa_diagnose.resolution.engine import _version

    here = _version(freeipa)
    for v in proc_prov.get("verified_on") or []:
        if v.get("tier") != "LIVE" or here is None:
            continue
        there = _version(v.get("freeipa"))
        if there is not None and there[:3] == here[:3] and str(v.get("os", "")).lower() == os_id:
            return v
    return None


def no_google(res: Any, procedure: Optional[Dict[str, Any]], me: str, freeipa: Optional[str], os_id: str,
              incident_criteria: List[str]) -> Dict[str, Any]:
    """Whether an OFFERED fix may claim that nothing needs to be looked up elsewhere, and what is missing if not."""

    meta = SLICE5_PROCEDURES.get(getattr(res, "procedure_id", "") or "", {})
    unit = next((a for s in res.steps for a in s.argv[2:3]), "the unit")
    checklist = {
        "named_target": bool(res.steps) and all(len(s.argv) >= 3 for s in res.steps),
        "exact_commands": bool(res.steps) and all(s.argv for s in res.steps),
        "host_per_step": all(s.run_on == "local" for s in res.steps),
        "prerequisites_met": all(p.state in ("met", "confirm") for p in res.prerequisites),
        "what_changes": bool(res.what_changes),
        "expected_result": all(bool(s.expected) for s in res.steps),
        "on_failure": bool(meta.get("on_failure")),
        "risk": bool(res.risk),
        "backup": bool(res.confirm_first) or meta.get("backup") in BACKUP_REASONS,
        "rollback": bool(res.rollback) or meta.get("rollback") in ROLLBACK_REASONS,
        "verification_tied_to_incident": bool(res.verify) and bool(incident_criteria),
        "live_verified_here": procedure is not None and _live_match(procedure.get("provenance") or {}, freeipa,
                                                                    os_id) is not None,
    }
    missing = [k for k, v in checklist.items() if not v]
    return {
        "claimed": not missing,
        "checklist": checklist,
        "missing": missing,
        "host": me,
        "on_failure": (meta.get("on_failure") or "").replace("{unit}", unit),
        "backup": BACKUP_REASONS.get(meta.get("backup", ""), "") if not res.confirm_first else "",
        "incident_criteria": list(incident_criteria),
    }


def procedure_by_id(pid: Optional[str]) -> Optional[Dict[str, Any]]:
    from ipa_diagnose.resolution.knowledge import load_catalogue

    cat, _ = load_catalogue()
    return next((p for p in cat if p.get("id") == pid), None)


def expected_procedure(resolution_key: Optional[str], variant: Optional[str]) -> Optional[str]:
    from ipa_diagnose.resolution.knowledge import load_catalogue

    cat, _ = load_catalogue()
    m = [p for p in cat if p["resolves"]["diagnosis"] == resolution_key and p["resolves"].get("variant") == variant]
    return sorted(m, key=lambda p: p["id"])[0]["id"] if m else None


def summarize(reasons: List[str]) -> Tuple[str, List[str]]:
    return ("WITHHELD" if reasons else "PASSED"), reasons
