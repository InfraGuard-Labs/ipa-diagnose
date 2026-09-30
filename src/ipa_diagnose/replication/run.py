"""Run one replication investigation: planner (L3) -> EnvironmentGraph (L2) -> cause chains and diagnoses (L4) ->
Resolution Safety gate + Slice 1 procedures + No-Google gate (L5). Verification (L6) is in replication/verify.py.

Statuses:
  NOT_AN_IPA_SERVER      this host is not an IPA server: nothing was investigated or guessed
  HEALTHY                every investigated agreement (both directions) is green and everything was checked
  HEALTHY_WITH_WARNINGS  as HEALTHY, with warnings (for example a clock drifting towards the Kerberos tolerance)
  PROBLEM_FOUND          a failure, an unexplained failure or contradicting evidence
  NOT_FULLY_VERIFIED     nothing failing was found, but something could not be checked (the reverse direction, a
                         dropped peer, a privilege gap) or an agreement is not green yet (transient)
"""

from __future__ import annotations

import dataclasses
import datetime
import os
from typing import Any, Dict, List, Optional

from ipa_diagnose.planner.core import Outcome, Trace, run_plan
from ipa_diagnose.replication import status as S
from ipa_diagnose.replication.causal import Chain
from ipa_diagnose.replication.diagnose import (
    CONTRADICTING, INDEPENDENT, PRIMARY, TRANSIENT, UNDIAGNOSED, ReplDiagnosis, diagnose,
)
from ipa_diagnose.replication.plan import plan_inputs, replication_plan

REPLICATION_SCHEMA_VERSION = "1.0"
REPLAY_FIELD_LIMIT = 800
"""recorded strings are kept as long as the live checks keep them (an agreement status names its Kerberos cause at
the end of a long line)."""
P, W, F, U, SK = Outcome.PASS, Outcome.WARN, Outcome.FAIL, Outcome.UNKNOWN, Outcome.SKIPPED
LOCAL_ESSENTIAL = ("server", "local.ds", "local.kdc", "local.storage", "local.keytab", "topology", "agreements")
SUBJECT_ESSENTIAL = ("peer.dns", "peer.port", "peer.rootdse", "gssapi")


@dataclasses.dataclass
class ReplicationResult:
    mode: str
    generated_at: str
    inputs: Dict[str, Any]
    trace: Trace
    diagnoses: List[ReplDiagnosis]
    chains: List[Chain]
    resolutions: Dict[str, Any]
    gates: Dict[str, Any]
    status: str
    completeness: Dict[str, Any]
    relationships: List[Dict[str, Any]]
    topology: Dict[str, Any]
    graph: Any
    environment: Dict[str, Any]
    handoffs: List[Dict[str, str]]
    limitations: List[str]
    notes: List[str]


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _gap(trace: Trace, r, depth: int = 0) -> bool:
    """A check that did not answer, or was not run for a reason that is not an observed failure upstream, is a gap."""

    if r.outcome == U:
        return True
    if r.outcome != SK or depth > 20:
        return False
    kind = r.skip_reason.split(":", 1)[0]
    if kind in ("privilege", "not applicable"):
        return not r.skip_reason.startswith("not applicable: the agreement binds with")
    if kind == "stopped":
        return not r.skip_reason.startswith("stopped: this host is not an IPA server")
    if kind == "blocked" and r.blocked_by:
        up = trace.get(r.blocked_by)
        return up is None or _gap(trace, up, depth + 1)
    if kind == "blocked":
        return True
    return False


def _completeness(trace: Trace, reverse: Dict[str, str], peer: Optional[str]) -> Dict[str, Any]:
    gaps: List[Dict[str, str]] = []
    for sid in LOCAL_ESSENTIAL:
        r = trace.get(sid)
        if r is None:
            continue
        if _gap(trace, r):
            gaps.append({"step": sid, "check": r.title, "reason": r.summary if r.outcome == U else r.skip_reason})
        elif sid == "topology" and r.outcome == W:
            gaps.append({"step": sid, "check": r.title, "reason": "the topology read was not confirmed complete"})
        elif sid == "agreements" and r.outcome in (P, W) and r.facts.get("complete") is not True:
            gaps.append({"step": sid, "check": r.title, "reason": "the agreements read was not confirmed complete"})
        elif sid == "agreements" and r.facts.get("peer_found") is False:
            gaps.append({"step": sid, "check": r.title, "reason": r.summary})
    pr = trace.get("principals")
    if pr is not None and _gap(trace, pr):
        gaps.append({"step": "principals", "check": pr.title, "reason": pr.summary or pr.skip_reason})
    enum = trace.enumerations.get("agreement")
    if enum and enum.get("status") not in ("COMPLETE", "NOT_ASKED"):
        gaps.append({"step": "agreement", "check": "outbound agreements investigated",
                     "reason": f"{enum['status']}: {enum.get('reason') or 'not every agreement was investigated'}"
                     + (f"; not investigated: {', '.join(enum.get('dropped') or [])}" if enum.get("dropped") else "")})
    for subj in (enum or {}).get("subjects") or []:
        for base in SUBJECT_ESSENTIAL:
            r = trace.get(base, subject=subj)
            if r is not None and _gap(trace, r):
                gaps.append({"step": r.step_id, "check": f"{r.title} [{subj}]",
                             "reason": r.summary if r.outcome == U else r.skip_reason})
        if reverse.get(subj) == "UNKNOWN":
            r = trace.get("reverse", subject=subj)
            why = (r.summary if r is not None and r.outcome == U else r.skip_reason if r is not None else "not run")
            gaps.append({"step": f"reverse@{subj}", "check": f"reverse direction [{subj}]",
                         "reason": f"not observed from this server ({why}); to read it from here, run "
                                   "'kinit admin' in the same (root) session and run again (sudo does not pass your own "
                                   "ticket on), or run ipa-diagnose replication on the peer"})
    return {"level": "complete" if not gaps else "partial", "not_verified": gaps, "scope": (
        f"only the agreements towards {peer} (--peer)" if peer else "every outbound agreement of this server"),
        "planner": trace.summary()}


def _status(diags: List[ReplDiagnosis], completeness: Dict[str, Any], server: bool) -> str:
    if not server:
        return "NOT_AN_IPA_SERVER"
    if any(d.severity == "FAIL" or d.role in (UNDIAGNOSED, CONTRADICTING) for d in diags):
        return "PROBLEM_FOUND"
    if completeness["level"] != "complete" or any(d.kind == TRANSIENT for d in diags):
        return "NOT_FULLY_VERIFIED"
    if diags:
        return "HEALTHY_WITH_WARNINGS"
    return "HEALTHY"


def _environment(trace: Trace) -> Dict[str, Any]:
    r = trace.get("server")
    f = r.fields if r is not None and r.outcome != SK else {}
    return {k: f.get(k) for k in ("host", "realm", "domain", "basedn", "ds_instance", "freeipa", "ds_version", "os",
                                  "os_version", "systemd", "is_ipa_server", "krb5_ktname")}


def _relationships(trace: Trace, me: Optional[str], reverse: Dict[str, str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    ag = trace.get("agreements")
    if ag is None or ag.outcome in (SK, U) or not me:
        return out
    enum = trace.enumerations.get("agreement") or {}
    investigated = set(enum.get("subjects") or [])
    for item in ag.facts.get("subjects") or []:
        if not isinstance(item, dict):
            continue
        subj = item["subject"]
        out.append({"subject": f"{item['suffix_kind']}:{me}>{item['consumer']}", "suffix": item["suffix_kind"],
                    "supplier": me, "consumer": item["consumer"], "direction": "outbound", "observed_from": me,
                    "source": "this server's own agreement entry", "transport": item.get("transport"),
                    "bind_method": item.get("bind_method"), "port": item.get("port"), "enabled": item.get("enabled"),
                    "state": item.get("status_class"), "status_text": item.get("status_text"),
                    "last_update_end": item.get("last_update_end"), "update_in_progress": item.get("update_in_progress"),
                    "investigated": subj in investigated})
        rv = trace.get("reverse", subject=subj)
        out.append({"subject": f"{item['suffix_kind']}:{item['consumer']}>{me}", "suffix": item["suffix_kind"],
                    "supplier": item["consumer"], "consumer": me, "direction": "inbound", "observed_from": me,
                    "source": (f"read from {item['consumer']} with the operator's ticket"
                               if rv is not None and rv.facts.get("visible") else "not observed"),
                    "state": {"OK": S.OK, "FAILING": "FAILING", "TRANSIENT": "TRANSIENT"}.get(
                        reverse.get(subj, "UNKNOWN"), "UNKNOWN"),
                    "status_text": rv.facts.get("status_text") if rv is not None and rv.facts.get("visible") else None,
                    "last_update_end": rv.facts.get("last_update_end") if rv is not None else None,
                    "update_in_progress": rv.facts.get("update_in_progress") if rv is not None else None,
                    "investigated": subj in investigated})
    return out


def incident_criteria(d: ReplDiagnosis, diags: List[ReplDiagnosis], resolution: Any) -> List[str]:
    out = []
    for key in d.explains:
        sym = next((x for x in diags if x.key == key), None)
        if sym is not None and sym.code in ("REPLICATION_FAILING", "REVERSE_REPLICATION_FAILING"):
            out.append(f"the agreement {sym.subject} reports success for a session that ended after this diagnosis, "
                       "with no update in progress")
    for v in getattr(resolution, "verify", []) or []:
        out.append(v.get("text", ""))
    out.append(f"{d.title}: no longer found by a fresh ipa-diagnose replication run")
    return [x for x in out if x]


def _resolve(diags: List[ReplDiagnosis], chains: List[Chain], env: Dict[str, Any], runner: Any, trace: Trace,
             topo: Dict[str, Any]) -> (Dict[str, Any], Dict[str, Any]):
    from ipa_diagnose.engine.model import Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, PriorityBucket
    from ipa_diagnose.evidence.model import EnvironmentInfo
    from ipa_diagnose.replication import safety as G
    from ipa_diagnose.resolution.engine import NONE, OFFERED, WITHHELD, Resolution, resolve_diagnosis
    from ipa_diagnose.resolution.knowledge import load_catalogue

    catalogue, error = load_catalogue()
    replay = bool(getattr(runner, "replay", False))
    info = EnvironmentInfo(distro=env.get("os"), distro_version=env.get("os_version"),
                           freeipa_version=env.get("freeipa"), detected_live=not replay)
    ctx = G.GateContext(me=env.get("host") or "", replay=replay, trace=trace, diagnoses=diags,
                        chains={c.chain_id: c for c in chains}, topology=topo, runner=runner)
    out: Dict[str, Any] = {}
    gates: Dict[str, Any] = {}
    for d in diags:
        if not d.resolution_key:
            continue
        variant = d.variant if d.resolution_key.startswith("healthcheck.") else None
        pid = G.expected_procedure(d.resolution_key, variant)
        proc = G.procedure_by_id(pid)
        if proc is None:
            continue
        diag_id = f"replication.{d.key}"
        if proc.get("kind") == "no_procedure":
            out[d.key] = Resolution(diagnosis_id=diag_id, status=NONE, procedure_id=pid, reasons=[proc["reason"]])
            continue
        reasons = G.resolution_gate(d, ctx, pid)
        ed = Diagnosis(pack_id="replication", rule_id=d.code,
                       status=DiagnosisStatus.DIAGNOSED if d.confidence in ("HIGH", "MEDIUM")
                       else DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                       title=d.title, why=d.detail,
                       confidence=Confidence({"HIGH": ConfidenceLevel.HIGH, "MEDIUM": ConfidenceLevel.MEDIUM}.get(
                           d.confidence, ConfidenceLevel.LOW), d.detail),
                       priority=PriorityBucket.PRIMARY if d.role == PRIMARY else
                       PriorityBucket.SECONDARY_INDEPENDENT if d.role == INDEPENDENT else PriorityBucket.RELATED_SYMPTOM,
                       diagnosis_id=diag_id, resolution_key=d.resolution_key, variant=variant,
                       bindings=dict(d.bindings), related_to_titles=[x.title for x in diags if x.key == d.related_to])
        preview = None
        if reasons:
            if replay and all("REPLAY" in r for r in reasons):
                try:  # parity: which procedure and argv the same evidence leads to (never to be run from REPLAY)
                    pr = resolve_diagnosis(ed, info, runner, catalogue)
                    if pr is not None and pr.status == OFFERED and not G.check_offered(pr):
                        preview = {"procedure_id": pr.procedure_id, "steps": [s.argv for s in pr.steps],
                                   "do_not_run": ("parity preview from RECORDED evidence: never revalidated on a "
                                                  "live host; not a command to run")}
                except Exception:  # noqa: BLE001
                    preview = None
            out[d.key] = Resolution(diagnosis_id=diag_id, status=WITHHELD, procedure_id=pid, title=proc.get("title", ""),
                                    reasons=reasons, tier=proc.get("provenance", {}).get("tier", ""), replay=replay)
            gates[d.key] = {"safety_gate": "WITHHELD", "reasons": reasons, "no_google": None,
                            "replay_preview": preview}
            continue
        try:
            res = resolve_diagnosis(ed, info, runner, catalogue)
        except Exception as e:  # noqa: BLE001 - a fix must never break the diagnosis
            res = Resolution(diagnosis_id=diag_id, status=WITHHELD,
                             reasons=[f"Internal error while preparing the fix ({type(e).__name__}); nothing is shown."])
        if res is None:
            continue
        ng = None
        if res.status == OFFERED:
            extra = G.check_offered(res)
            if extra:
                res.status, res.reasons = WITHHELD, extra
                res.steps, res.rollback, res.verify, res.what_changes, res.confirm_first = [], [], [], [], []
                res.baseline = None
            else:
                ng = G.no_google(res, proc, env.get("host") or "", env.get("freeipa"),
                                 f"{(env.get('os') or '').lower()}-{(env.get('os_version') or '').lower()}",
                                 incident_criteria(d, diags, res))
        out[d.key] = res
        gates[d.key] = {"safety_gate": "PASSED", "reasons": [], "no_google": ng, "replay_preview": None}
    if error:
        out["_catalogue_error"] = error
    return out, gates


LIMITATIONS = [
    "Replication is directional and per suffix: this server sees its OWN outbound agreements. The reverse direction "
    "is only reported when it could be read from the peer (read-only, with your own Kerberos ticket); otherwise it "
    "is NOT VERIFIED and a handoff to the peer is printed.",
    "Nothing is changed on this server or any other; no command runs on another server; fixes are printed only for "
    "causes on this server, and only when every safety gate passes.",
    "Re-initialization, force-sync, RUV clean-up, topology changes, server removal, keytab/principal/certificate "
    "changes and clock steps are never printed.",
    "A peer that does not answer is reported as unreachable from this server at a given time, never as gone or dead.",
    "RUV elements are candidates from this server's RUV only; other servers' RUVs are not read.",
    "Only FreeIPA versions and topologies listed in docs/truth/replication-truth-matrix.md were validated live.",
]


def investigate(runner: Any, peer: Optional[str] = None, is_root: Optional[bool] = None,
                max_seconds: Optional[float] = None) -> ReplicationResult:
    from ipa_diagnose.replication import graph_build, topology as TP
    from ipa_diagnose.resolution.checks import REGISTRY

    root = _is_root() if is_root is None else is_root
    inputs = plan_inputs(peer)
    kw = {"max_seconds": max_seconds} if max_seconds else {}
    trace, _ctx = run_plan(replication_plan(), runner, inputs, is_root=root, registry=REGISTRY, max_steps=120,
                           privilege_hint="run ipa-diagnose replication as root", **kw)
    env = _environment(trace)
    server = trace.get("server") is not None and trace.get("server").outcome == P
    try:
        diags, chains, extra = diagnose(trace, inputs)
    except (TypeError, ValueError, AttributeError, KeyError, OverflowError, IndexError):
        diags, chains, extra = [ReplDiagnosis(
            "EVIDENCE_UNUSABLE", f"server:{env.get('host') or 'this-host'}", "The collected evidence could not be "
            "interpreted", "REPLICATION", "FAIL", "LOW", "A check returned a value of an unexpected type, so no cause "
            "is concluded.", "Unknown.", [], "local", kind=UNDIAGNOSED, role=UNDIAGNOSED)], [], {"reverse": {},
                                                                                            "ruv_notes": []}
    topo_rec = trace.get("topology")
    topo = TP.summarize(topo_rec.fields if topo_rec is not None and topo_rec.outcome in (P, W) else {},
                        env.get("host") or "")
    resolutions, gates = _resolve(diags, chains, env, runner, trace, topo) if server else ({}, {})
    completeness = _completeness(trace, extra.get("reverse", {}), peer)
    graph = graph_build.build(trace, env.get("host"), env.get("freeipa"))
    handoffs = []
    seen = set()
    for d in diags:
        if d.handoff and (d.handoff["host"], d.handoff["command"]) not in seen:
            seen.add((d.handoff["host"], d.handoff["command"]))
            handoffs.append(dict(d.handoff, because=d.title))
    me = env.get("host")
    for subj, state in sorted(extra.get("reverse", {}).items()):
        consumer = subj.split(":", 1)[1]
        cmd = f"sudo ipa-diagnose replication --peer {me}"
        if state == "UNKNOWN" and (consumer, cmd) not in seen:
            seen.add((consumer, cmd))
            handoffs.append({"host": consumer, "command": cmd, "because": f"the reverse direction ({consumer} -> "
                             f"{me}) was not observed from {me}",
                             "why": f"{consumer} sees its own outbound agreements; nothing was changed anywhere."})
    notes = list(extra.get("ruv_notes") or [])
    me_ = env.get("host")
    for name, sfx in (topo.get("suffixes") or {}).items():
        cut = sorted({d.subject.split(">", 1)[1] for d in diags if d.code == "REPLICATION_FAILING"
                      and d.subject.startswith(f"{name}:{me_}>")} & set(sfx.get("neighbours_of_this_server") or []))
        if me_ in (sfx.get("articulation_points") or []) and len(cut) >= 2:
            notes.append(f"{me_} is an articulation point of the {name} topology and its agreements to "
                         f"{', '.join(cut)} fail: servers on different sides of {me_} do not replicate {name} "
                         "changes with each other until this is fixed")
    ag = trace.get("agreements")
    if ag is not None and ag.outcome in (P, W) and ag.facts.get("peer_found") is False:
        notes.append(f"this server has no outbound agreement towards {peer}")
    if server and ag is not None and ag.outcome in (P, W) and not ag.facts.get("subjects") and not peer:
        notes.append("this server has no outbound replication agreement (a single server, or its agreements are not "
                     "visible)")
    return ReplicationResult(
        mode="REPLAY" if getattr(runner, "replay", False) else "LIVE", generated_at=_now(), inputs={"peer": peer},
        trace=trace, diagnoses=diags, chains=chains, resolutions=resolutions, gates=gates,
        status=_status(diags, completeness, server), completeness=completeness,
        relationships=_relationships(trace, me, extra.get("reverse", {})), topology=topo, graph=graph,
        environment=env, handoffs=handoffs, limitations=list(LIMITATIONS), notes=notes)
