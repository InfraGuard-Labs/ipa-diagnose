"""JSON and console output for `ipa-diagnose client`.

Every string passes through ``sanitize_text`` at this boundary (terminal escapes, control and bidi characters
removed, length bounded), in JSON as on the console. Commands come only from typed procedures (argv) or fixed,
shell-quoted read-only suggestions.
"""

from __future__ import annotations

from typing import Any, Dict

from rich.console import Console

from ipa_diagnose.client.run import CLIENT_SCHEMA_VERSION, ClientResult
from ipa_diagnose.textsafe import sanitize_text


def _safe(v: str, limit: int) -> str:
    """Secret patterns are redacted BEFORE shortening (a cut secret could escape the patterns), then control, escape
    and bidi characters are removed. Check output (live or recorded) is untrusted: this applies to every string."""

    from ipa_diagnose.resolution.checks import _redact_log_line

    return sanitize_text(_redact_log_line(v[:4096]), limit)


def _c(v: Any, limit: int = 1200) -> Any:
    if isinstance(v, str):
        return _safe(v, limit)
    if isinstance(v, list):
        return [_c(x, limit) for x in v]
    if isinstance(v, tuple):
        return [_c(x, limit) for x in v]
    if isinstance(v, dict):
        return {_safe(str(k), 200): _c(x, limit) for k, x in v.items()}
    return v


def _step_dict(r) -> Dict[str, Any]:
    return {"step": r.step_id, "capability": r.capability, "check": r.check, "title": r.title,
            "outcome": r.outcome.value, "summary": r.summary, "why_in_plan": r.why,
            "selected_because": r.selected_because or None, "skip_reason": r.skip_reason or None,
            "command": r.command or None, "check_status": r.status or None, "seconds": r.seconds,
            "collected_at": r.collected_at, "source": r.source or None, "reused_result": r.reused,
            "privilege": r.privilege, "side_effects": r.side_effects, "attempts": r.attempts,
            "facts": {k: v for k, v in r.facts.items()}}


def headline(r: ClientResult) -> str:
    host = r.environment.get("host") or "this host"
    prim = next((d for d in r.diagnoses if d.role == "PRIMARY"), None)
    if r.status == "PROBLEM_FOUND":
        if prim:
            more = [d for d in r.diagnoses if d.role == "INDEPENDENT"]
            if more:
                return (f"{host}: {1 + len(more)} independent problems: {prim.title}; "
                        + "; ".join(d.title for d in more) + ".")
            return f"{host}: {prim.title}."
        return f"{host}: a problem was found, but its cause is not established (see UNDIAGNOSED under ROOT CAUSE)."
    if r.status == "NOT_FULLY_VERIFIED":
        return f"{host}: no problem found in what could be checked, but not everything could be checked."
    if r.status == "HEALTHY_WITH_WARNINGS":
        return f"{host}: enrolled and working, with warnings."
    return f"{host}: enrolled, and every client check that applies passed."


def to_dict(r: ClientResult) -> Dict[str, Any]:
    from ipa_diagnose.render.json_output import resolution_to_dict

    res = {k: v for k, v in r.resolutions.items() if not k.startswith("_")}
    doc = {
        "kind": "ipa-diagnose.client",
        "client_schema_version": CLIENT_SCHEMA_VERSION,
        "source_mode": r.mode,
        "generated_at": r.generated_at,
        "question": "Is this FreeIPA client correctly enrolled and able to resolve/authenticate identities, and if "
                    "not, why?",
        "input": r.inputs,
        "environment": r.environment,
        "status": r.status,
        "answer": headline(r),
        "authentication": {"state": r.authentication.state, "summary": r.authentication.summary,
                           "reasons": r.authentication.reasons,
                           "scope": "this host's authentication path to IPA; no credential was tested"},
        "authorization": {"state": r.authorization.state, "summary": r.authorization.summary,
                          "decided_by": "FreeIPA hbactest" if r.authorization.state in ("PASS", "FAIL") else None},
        "runtime_access": {"state": r.runtime.state, "summary": r.runtime.summary, "reasons": r.runtime.reasons,
                           "checked_on": r.environment.get("host")},
        "planner_summary": r.trace.summary(),
        "steps": [_step_dict(x) for x in r.trace.records],
        "diagnoses": [{"code": d.code, "role": d.role, "title": d.title, "capability": d.capability,
                       "confidence": d.confidence, "severity": d.severity, "related_to": d.related_to,
                       "detail": d.detail, "impact": d.impact, "evidence_steps": d.evidence,
                       "next_steps": d.next_steps, "resolution_key": d.resolution_key, "variant": d.variant,
                       "blocks_runtime_access": d.blocks_runtime, "blocks_authentication": d.blocks_authentication}
                      for d in r.diagnoses],
        "ruled_out": r.ruled_out,
        "resolution": {code: dict(resolution_to_dict(v), diagnosis_code=code) for code, v in res.items()},
        "verification": {
            "how": "ipa-diagnose client --verify re-runs every check with fresh evidence and compares it with the saved "
                   "result; a check that cannot run is never counted as resolved.",
            "criteria": {code: list(v.verify) for code, v in res.items() if v.status == "OFFERED"},
        },
        "completeness": r.completeness,
        "evidence": {"provenance": {"mode": r.mode, "read_only": True,
                                    "via": "fixed, read-only local checks from a closed registry" if r.mode == "LIVE"
                                    else "recorded check results (REPLAY; describes no live system)"}},
        "limitations": r.limitations,
    }
    if "_catalogue_error" in r.resolutions:
        doc["resolution_catalogue_error"] = r.resolutions["_catalogue_error"]
    return _c(doc)


_MARK = {"PASS": "✓", "WARN": "!", "FAIL": "✗", "UNKNOWN": "?", "SKIPPED": "-"}
_STYLE = {"PASS": "green", "FAIL": "red", "UNKNOWN": "yellow", "NOT_VERIFIED": "cyan"}
_LABEL = {"PASS": "PASS", "FAIL": "FAIL", "UNKNOWN": "UNKNOWN", "NOT_VERIFIED": "NOT VERIFIED"}
_ROLE = {"PRIMARY": "PRIMARY", "INDEPENDENT": "INDEPENDENT", "RELATED": "RELATED", "UNDIAGNOSED": "UNDIAGNOSED",
         "CONTRADICTING": "CONTRADICTING", "WARNING": "WARNING"}


def render(r: ClientResult, console: Console, details: bool = False) -> None:
    d = to_dict(r)  # already sanitized
    p = lambda text="", style=None: console.print(text, markup=False, soft_wrap=True, style=style)  # noqa: E731
    env = d["environment"]
    src = "LIVE" if r.mode == "LIVE" else "REPLAY of recorded evidence (describes no live system)"
    p(f"ipa-diagnose client: {env.get('host') or 'this host'}"
      + (f" (IPA domain {env['domain']}, server {env['server']})" if env.get("domain") else ""), "bold")
    who = ", ".join(x for x in (f"user {d['input']['user']}" if d["input"].get("user") else "",
                                f"service {d['input']['service']}" if d["input"].get("service") else "") if x)
    p(f"  {src}" + (f"; asked about {who}" if who else "")
      + (f"; SSSD {env['sssd']}" if env.get("sssd") else "") + (f", IPA client {env['ipa_client']}"
                                                                 if env.get("ipa_client") else ""))
    p()
    p(d["answer"], "bold")
    p()
    for label, key in (("AUTHENTICATION", "authentication"), ("AUTHORIZATION", "authorization"),
                       ("RUNTIME ACCESS", "runtime_access")):
        st = d[key]["state"]
        console.print(f"  {label:<15} ", end="", markup=False)
        console.print(f"{_LABEL.get(st, st):<13}", style=_STYLE.get(st), end="", markup=False)
        p(d[key]["summary"])
    p()
    diags = d["diagnoses"]
    p("ROOT CAUSE", "bold")
    if not diags:
        p("  none found in what was checked")
    for x in diags:
        rel = f" (caused by {next((y['title'] for y in diags if y['code'] == x['related_to']), x['related_to'])})" \
            if x["related_to"] else ""
        p(f"  [{_ROLE.get(x['role'], x['role'])}] {x['title']}{rel} - confidence {x['confidence']}",
          "bold" if x["role"] == "PRIMARY" else None)
        p(f"      {x['detail']}")
        if x["impact"]:
            p(f"      Impact: {x['impact']}", "dim" if x["role"] in ("RELATED", "WARNING") else None)
    p()
    p("CHECKED FOR YOU", "bold")
    ran = [s for s in d["steps"] if s["outcome"] != "SKIPPED"]
    for s in ran:
        p(f"  {_MARK[s['outcome']]} {s['title']}: {s['summary']}",
          {"FAIL": "red", "UNKNOWN": "yellow", "WARN": "yellow"}.get(s["outcome"]))
        if details:
            if s["selected_because"]:
                p(f"      why now: {s['selected_because']}", "dim")
            if s["command"]:
                p(f"      read-only: {s['command']} ({s['seconds']} s{', result reused' if s['reused_result'] else ''})",
                  "dim")
            if s["side_effects"] and s["side_effects"] != "none":
                p(f"      note: {s['side_effects']}", "dim")
    skipped = [s for s in d["steps"] if s["outcome"] == "SKIPPED"]
    if skipped:
        if details:
            p("  Not run:", "dim")
            for s in skipped:
                p(f"  - {s['title']}: {s['skip_reason']}", "dim")
        else:
            kinds = d["planner_summary"]["skipped_by_reason"]
            p("  (" + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + " check(s) not run; --details says "
              "why)", "dim")
    if d["ruled_out"]:
        p("RULED OUT", "bold")
        p("  " + "; ".join(d["ruled_out"]))
    p("RESOLUTION", "bold")
    res = d["resolution"]
    shown = False
    for x in diags:
        rr = res.get(x["code"])
        if rr is None:
            continue
        shown = True
        if rr["status"] == "OFFERED":
            p(f"  For '{x['title']}': {rr['title']} (risk {rr['risk']}; ipa-diagnose never runs it)", "bold")
            if rr["verification_label"]:
                p(f"    {rr['verification_label']}", "yellow")
            for pr in rr["prerequisites"]:
                p(f"    {'✓' if pr['state'] == 'met' else '!'} "
                  f"{'Before running, accept that: ' if pr['state'] == 'confirm' else ''}{pr['text']}")
            for i, stp in enumerate(rr["steps"], 1):
                p(f"    {i}. {stp['text']}")
                p(f"         {stp['command']}", "bold cyan")
            for w in rr["what_changes"]:
                p(f"    What changes: {w}")
            if rr["impact_note"]:
                p(f"    Why it matters: {rr['impact_note']}")
            for rb in rr["rollback"]:
                p(f"    Rollback: {rb['text']}" + (f"  ->  {rb['command']}" if rb.get("command") else ""))
            if rr.get("limitations"):
                p(f"    Note: {rr['limitations']}")
        elif rr["status"] == "NONE":
            p(f"  For '{x['title']}': no fix is shown. " + " ".join(rr["reasons"]))
        else:
            p(f"  For '{x['title']}': no fix is shown (a gate did not pass):")
            for reason in rr["reasons"]:
                p(f"    - {reason}")
    if not shown:
        p("  No fix is suggested" + ((": nothing was found in what could be checked (see NOT VERIFIED)."
                                      if d["completeness"]["not_verified"] else ": nothing to fix.") if not diags
                                     else "; the next read-only steps are below."))
    nxt = [(x["title"], s) for x in diags for s in x["next_steps"]]
    if nxt:
        p("NEXT READ-ONLY STEPS", "bold")
        for _title, s in nxt[:12]:
            p(f"  {s}")
    p("VERIFY", "bold")
    offered = [code for code, v in res.items() if v["status"] == "OFFERED"]
    if offered:
        p("  After a fix, run: ipa-diagnose client --verify" + _args(d) + "   (fresh checks; compares with this run)")
        for code in offered:
            for v in res[code]["verify"]:
                p(f"    - {v['text']}")
    else:
        p("  Run ipa-diagnose client" + _args(d) + " again after any change: every check is re-run with fresh "
          "evidence.")
    gaps = d["completeness"]["not_verified"]
    if gaps:
        p("NOT VERIFIED", "bold")
        for g in gaps:
            p(f"  - {g['check']}: {g['reason']}")
    p("LIMITATIONS", "bold")
    for lim in d["limitations"] if details else d["limitations"][:1]:
        p("  " + lim)
    ps = d["planner_summary"]
    p(f"  planner: {ps['steps_run']} of {ps['steps_in_plan']} checks run, {ps['results_reused']} result(s) reused, "
      f"{ps['wall_seconds']} s; stop: {ps['stop_reason']}", "dim")


def _args(d: Dict[str, Any]) -> str:
    import shlex

    out = ""
    if d["input"].get("user"):
        out += f" --user {shlex.quote(d['input']['user'])}"
    if d["input"].get("service"):
        out += f" --service {shlex.quote(d['input']['service'])}"
    return out

