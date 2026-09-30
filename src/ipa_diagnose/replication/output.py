"""JSON and console output for `ipa-diagnose replication` (schema ``replication_schema_version`` 1.0, additive).

Every string passes through the same boundary as client mode (secret patterns redacted BEFORE shortening, then
control, escape and bidi characters removed). Commands come only from typed procedures (argv) or fixed, quoted
read-only suggestions and handoffs.
"""

from __future__ import annotations

from typing import Any, Dict, List

from rich.console import Console

from ipa_diagnose.client.output import _c
from ipa_diagnose.replication.run import REPLICATION_SCHEMA_VERSION, ReplicationResult


def headline(r: ReplicationResult) -> str:
    host = r.environment.get("host") or "this host"
    prim = [d for d in r.diagnoses if d.role == "PRIMARY"]
    indep = [d for d in r.diagnoses if d.role == "INDEPENDENT"]
    if r.status == "NOT_AN_IPA_SERVER":
        return f"{host}: not an IPA server. Replication is investigated on the IPA servers themselves; nothing was " \
               "checked or guessed."
    if r.status == "PROBLEM_FOUND":
        if prim:
            if indep:
                return f"{host}: {1 + len(indep)} independent problems: " + "; ".join(d.title for d in prim + indep) + "."
            return f"{host}: {prim[0].title}."
        return f"{host}: a replication problem was found, but its cause is not established (see UNDIAGNOSED)."
    if r.status == "NOT_FULLY_VERIFIED":
        if any(d.kind == "TRANSIENT" for d in r.diagnoses):
            return f"{host}: nothing failing was found, but an agreement is not green yet (transient; recheck later)."
        return f"{host}: nothing failing was found in what could be checked, but not everything could be checked."
    if r.status == "HEALTHY_WITH_WARNINGS":
        return f"{host}: replication works in every direction that was checked, with warnings."
    return f"{host}: every investigated replication agreement is green in both directions."


def _step(r) -> Dict[str, Any]:
    return {"step": r.step_id, "base_step": r.base_step or r.step_id, "subject": r.subject, "template": r.template,
            "capability": r.capability, "check": r.check, "title": r.title, "outcome": r.outcome.value,
            "summary": r.summary, "why_in_plan": r.why, "selected_because": r.selected_because or None,
            "skip_reason": r.skip_reason or None, "command": r.command or None, "check_status": r.status or None,
            "seconds": r.seconds, "collected_at": r.collected_at, "source": r.source or None,
            "reused_result": r.reused, "privilege": r.privilege, "side_effects": r.side_effects,
            "facts": {k: v for k, v in r.facts.items() if k != "subjects"}}


def to_dict(r: ReplicationResult) -> Dict[str, Any]:
    from ipa_diagnose.render.json_output import resolution_to_dict

    res = {k: v for k, v in r.resolutions.items() if not k.startswith("_")}
    subjects = sorted({d.subject for d in r.diagnoses} | {x["subject"] for x in r.relationships})
    doc = {
        "kind": "ipa-diagnose.replication",
        "replication_schema_version": REPLICATION_SCHEMA_VERSION,
        "source_mode": r.mode,
        "generated_at": r.generated_at,
        "question": "Does replication to and from this IPA server work, per suffix and direction, and if not, what is "
                    "the deepest proven cause?",
        "input": r.inputs,
        "environment": r.environment,
        "status": r.status,
        "answer": headline(r),
        "subjects": subjects,
        "relationships": r.relationships,
        "cause_chains": [c.as_dict() for c in r.chains],
        "diagnoses": [{"key": d.key, "code": d.code, "subject": d.subject, "role": d.role, "title": d.title,
                       "capability": d.capability, "severity": d.severity, "confidence": d.confidence,
                       "scope": d.scope, "kind": d.kind, "related_to": d.related_to, "explains": d.explains,
                       "chain_ids": d.chain_ids, "detail": d.detail, "impact": d.impact, "evidence_steps": d.evidence,
                       "next_steps": d.next_steps, "handoff": d.handoff, "resolution_key": d.resolution_key}
                      for d in r.diagnoses],
        "resolutions": {k: dict(resolution_to_dict(v), diagnosis_key=k, safety_gate=r.gates.get(k)) for k, v in
                        res.items()},
        "handoffs": r.handoffs,
        "verification": {
            "how": "ipa-diagnose replication --verify re-runs every check with fresh evidence and requires, for each "
                   "earlier failing agreement, a successful session that ended after the saved result, no update in "
                   "progress, and that its cause no longer fails. A check that cannot run is never counted as "
                   "resolved; a direction that cannot be observed is never reported as verified.",
            "criteria": {k: list(v.verify) for k, v in res.items() if v.status == "OFFERED"},
        },
        "completeness": r.completeness,
        "topology": r.topology,
        "environment_graph": r.graph.to_dict() if r.graph is not None else None,
        "planner_summary": r.trace.summary(),
        "trace": [_step(x) for x in r.trace.records],
        "notes": r.notes,
        "evidence": {"provenance": {"mode": r.mode, "read_only": True, "observed_from": r.environment.get("host"),
                                    "via": "fixed, read-only checks from a closed registry" if r.mode == "LIVE"
                                    else "recorded check results (REPLAY; describes no live system)"}},
        "limitations": r.limitations,
    }
    if "_catalogue_error" in r.resolutions:
        doc["resolution_catalogue_error"] = r.resolutions["_catalogue_error"]
    return _c(doc)


_MARK = {"PASS": "✓", "WARN": "!", "FAIL": "✗", "UNKNOWN": "?", "SKIPPED": "-"}
_STATE_STYLE = {"OK": "green", "FAILING": "red", "UNKNOWN": "yellow", "TRANSIENT": "yellow"}


def _state_label(x: Dict[str, Any]) -> str:
    st = x.get("state") or "UNKNOWN"
    if x["direction"] == "inbound":
        return {"OK": "OK", "FAILING": "FAILING", "TRANSIENT": "NOT GREEN YET"}.get(st, "NOT OBSERVED")
    return "OK" if st == "OK" else f"NOT GREEN YET ({st})" if st in ("BUSY", "BACKOFF", "NO_SESSIONS") else \
        f"FAILING ({st})"


def render(r: ReplicationResult, console: Console, details: bool = False) -> None:
    d = to_dict(r)
    p = lambda text="", style=None: console.print(text, markup=False, soft_wrap=True, style=style)  # noqa: E731
    env = d["environment"]
    src = "LIVE" if r.mode == "LIVE" else "REPLAY of recorded evidence (describes no live system)"
    p(f"ipa-diagnose replication: {env.get('host') or 'this host'}"
      + (f" (realm {env['realm']})" if env.get("realm") else ""), "bold")
    p(f"  {src}" + (f"; FreeIPA {env['freeipa']}" if env.get("freeipa") else "")
      + (f", 389-ds {env['ds_version']}" if env.get("ds_version") else "")
      + (f"; only agreements towards {d['input']['peer']}" if d["input"].get("peer") else ""))
    p()
    p(d["answer"], "bold")
    p()
    if d["relationships"]:
        p(f"REPLICATION (per suffix and direction; observed from {env.get('host')})", "bold")
        for x in d["relationships"]:
            label = _state_label(x)
            style = "green" if label == "OK" else "red" if label.startswith("FAILING") else "yellow"
            console.print(f"  {x['suffix']:<7} {x['supplier']} -> {x['consumer']}  ", end="", markup=False)
            console.print(label, style=style, end="", markup=False)
            extra = ""
            if x["direction"] == "outbound":
                extra = f"  [{x.get('transport')}/{x.get('bind_method')}, port {x.get('port')}]"
                if x.get("last_update_end"):
                    extra += f" last session ended {x['last_update_end']}"
                if not x.get("investigated"):
                    extra += " (not investigated: budget)"
            elif label == "NOT OBSERVED":
                extra = "  (not readable from here; see HANDOFF)"
            p(extra, "dim")
        p()
    diags = d["diagnoses"]
    p("ROOT CAUSE", "bold")
    if not diags:
        p("  none found in what was checked")
    chains = {c["chain_id"]: c for c in d["cause_chains"]}
    for x in diags:
        rel = ""
        if x["related_to"]:
            cause = next((y["title"] for y in diags if y["key"] == x["related_to"]), x["related_to"])
            rel = f" (caused by: {cause})"
        p(f"  [{x['role']}] {x['title']}{rel} - confidence {x['confidence']}", "bold" if x["role"] == "PRIMARY" else None)
        p(f"      {x['detail']}")
        if x["impact"] and x["role"] not in ("RELATED",):
            p(f"      Impact: {x['impact']}", "dim" if x["role"] == "WARNING" else None)
        if x["role"] in ("PRIMARY", "INDEPENDENT", "UNDIAGNOSED") or details:
            for cid in x["chain_ids"][:3]:
                c = chains.get(cid)
                if not c:
                    continue
                p("      Chain: " + "  ->  ".join(link["claim"] for link in c["links"]), "cyan")
                if c["boundary"]:
                    p(f"      Stops here: {c['boundary']}", "dim")
    p()
    if d["handoffs"]:
        p("HANDOFF (the remaining evidence is on another server; nothing was changed)", "bold")
        for h in d["handoffs"]:
            p(f"  On {h['host']} run:")
            p(f"    {h['command']}", "bold cyan")
            p(f"  Why: {h['because']}. {h['why']}", "dim")
        p()
    p("RESOLUTION (only for causes on this server)", "bold")
    res = d["resolutions"]
    shown = False
    for x in diags:
        rr = res.get(x["key"])
        if rr is None:
            continue
        shown = True
        gate = rr.get("safety_gate") or {}
        ng = gate.get("no_google") or {}
        if rr["status"] == "OFFERED":
            p(f"  For '{x['title']}': {rr['title']} (risk {rr['risk']}; ipa-diagnose never runs it)", "bold")
            p("    " + ("NO-GOOGLE: every step, its host, its expected result, what to do if it fails, backup, "
                        "rollback and verification are below, and this procedure was verified live on this FreeIPA "
                        "version and OS." if ng.get("claimed") else
                        "Complete as far as ipa-diagnose can tell, but not live-verified on this FreeIPA version/OS"
                        + (f" (missing: {', '.join(ng.get('missing') or [])})" if ng.get("missing") else "")
                        + ": check each step before running it."), "green" if ng.get("claimed") else "yellow")
            for pr in rr["prerequisites"]:
                p(f"    {'✓' if pr['state'] == 'met' else '!'} "
                  f"{'Before running, accept that: ' if pr['state'] == 'confirm' else ''}{pr['text']}")
            for i, stp in enumerate(rr["steps"], 1):
                p(f"    {i}. On {ng.get('host') or env.get('host')}: {stp['text']}")
                p(f"         {stp['command']}", "bold cyan")
                p(f"       Expected: {stp['expected']}")
            if ng.get("on_failure"):
                p(f"    If a step fails: {ng['on_failure']}")
            for w in rr["what_changes"]:
                p(f"    What changes: {w}")
            if ng.get("backup"):
                p(f"    Backup: {ng['backup']}")
            for rb in rr["rollback"]:
                p(f"    Rollback: {rb['text']}" + (f"  ->  {rb['command']}" if rb.get("command") else ""))
            if rr.get("limitations"):
                p(f"    Note: {rr['limitations']}")
            p("    Verify (tied to this incident):")
            for c in ng.get("incident_criteria") or []:
                p(f"      - {c}")
            p("      run: sudo ipa-diagnose replication --verify", "bold cyan")
        elif rr["status"] == "NONE":
            p(f"  For '{x['title']}': no fix is printed. " + " ".join(rr["reasons"]))
        else:
            p(f"  For '{x['title']}': no fix is shown (a safety gate did not pass):")
            for reason in rr["reasons"]:
                p(f"    - {reason}")
    if not shown:
        p("  No fix is printed" + (": nothing to fix." if not any(x["severity"] == "FAIL" for x in diags) else
                                   ": the causes found are not on this server, or no fix is established for them "
                                   "(see HANDOFF and the next read-only steps)."))
    nxt: List[str] = []
    for x in diags:
        for s in x["next_steps"]:
            if s not in nxt:
                nxt.append(s)
    if nxt:
        p("NEXT READ-ONLY STEPS", "bold")
        for s in nxt[:14]:
            p(f"  {s}")
    gaps = d["completeness"]["not_verified"]
    if gaps:
        p("NOT VERIFIED", "bold")
        for g in gaps[:20]:
            p(f"  - {g['check']}: {g['reason']}")
    for n in d["notes"]:
        p(f"NOTE: {n}", "dim")
    topo = d["topology"]
    if topo.get("read"):
        p("TOPOLOGY (context)", "bold")
        p(f"  servers: {', '.join(topo.get('servers') or []) or '?'}"
          + ("" if topo.get("complete") else " (read not confirmed complete)"))
        for name, s in (topo.get("suffixes") or {}).items():
            ap = s.get("articulation_points") or []
            p(f"  {name}: {len(s.get('segments') or [])} segment(s)"
              + (f"; articulation point(s): {', '.join(ap)}" if ap else ""))
        sole = topo.get("sole_role_holder") or {}
        if sole:
            p("  only one server holds: " + ", ".join(f"{k} ({v})" for k, v in sorted(sole.items())))
        if topo.get("renewal_master"):
            p(f"  CA renewal master: {topo['renewal_master']}")
    if details:
        p("CHECKED FOR YOU", "bold")
        for s in d["trace"]:
            if s["outcome"] == "SKIPPED":
                p(f"  - {s['title']}{' [' + s['subject'] + ']' if s['subject'] else ''}: {s['skip_reason']}", "dim")
                continue
            p(f"  {_MARK[s['outcome']]} {s['title']}{' [' + s['subject'] + ']' if s['subject'] else ''}: "
              f"{s['summary']}", {"FAIL": "red", "UNKNOWN": "yellow", "WARN": "yellow"}.get(s["outcome"]))
            if s["command"]:
                p(f"      read-only: {s['command']} ({s['seconds']} s)", "dim")
            if s["side_effects"] and s["side_effects"] != "none":
                p(f"      note: {s['side_effects']}", "dim")
    p("LIMITATIONS", "bold")
    for lim in d["limitations"] if details else d["limitations"][:2]:
        p("  " + lim)
    ps = d["planner_summary"]
    p(f"  planner: {ps['steps_run']} of {ps['steps_in_plan']} checks run, {ps['wall_seconds']} s; stop: "
      f"{ps['stop_reason']}", "dim")
