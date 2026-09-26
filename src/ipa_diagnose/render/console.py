"""Default and --details terminal rendering.

Kept deliberately close to plain sectioned text (WHY / EVIDENCE / IMPACT / DO
THIS FIRST / VERIFY) rather than dense tables - the 30-60 second
comprehension bar this product is judged against favors a short linear
read over a dashboard the administrator has to parse. rich is used for
color/emphasis only, never to reorganize the structure.
"""

from __future__ import annotations

import shlex
from typing import Dict, Optional

from rich.console import Console
from rich.markup import escape as _rich_escape
from rich.rule import Rule
from rich.text import Text

from ipa_diagnose.engine.model import (
    Diagnosis,
    DiagnosisReport,
    DiagnosisStatus,
    OverallStatus,
    PriorityBucket,
    RiskLevel,
)

from ipa_diagnose.textsafe import clean_multiline


def escape(text) -> str:
    """Untrusted text -> safe to print: terminal escape/control characters
    removed AND rich markup neutralised."""

    return _rich_escape(clean_multiline(text))


_STATUS_STYLE = {
    OverallStatus.HEALTHY: "bold green",
    OverallStatus.DEGRADED: "bold yellow",
    OverallStatus.CRITICAL: "bold red",
    OverallStatus.UNKNOWN: "bold magenta",
    OverallStatus.NOT_FULLY_VERIFIED: "bold orange3",
}

_RISK_STYLE = {
    RiskLevel.SAFE: ("green", "SAFE — read-only, no state change."),
    RiskLevel.CAUTION: ("yellow", "CAUTION — changes state, but is reversible and scoped."),
    RiskLevel.HIGH_RISK: ("red", "HIGH RISK — potentially disruptive. Do not run without understanding the blast radius."),
}


def render_report(
    report: DiagnosisReport,
    console: Console,
    *,
    details: bool = False,
    ai_explanations: Optional[Dict[str, str]] = None,
) -> None:
    ai_explanations = ai_explanations or {}

    console.print(Rule("FreeIPA Diagnosis", style="cyan"))
    console.print(f"Host: {escape(report.hostname)}    Generated: {escape(report.generated_at)}")
    if report.replay_source:
        console.print(f"[dim](replayed from fixtures: {escape(report.replay_source)})[/dim]")
    status_style = _STATUS_STYLE[report.overall_status]
    console.print(Text.assemble(("Overall: ", "bold"), (report.overall_status.value, status_style)))
    _print_evidence_banner(report, console)
    for note in report.side_effects:
        console.print(f"[yellow]Note:[/yellow] {escape(note)}")
    if report.service_states:
        stopped = [f"{u}: {s}" for u, s in report.service_states.items() if s != "active"]
        console.print(Text("Service state, read by ipa-diagnose itself (ipa-healthcheck gave no results):", style="bold"))
        console.print("  " + escape(", ".join(stopped)) if stopped else "  all IPA units it checked are active")
        if stopped:
            console.print("  [dim]A stopped DNS, LDAP or Kerberos service can itself keep ipa-healthcheck from finishing.[/dim]")
    if report.overall_status == OverallStatus.NOT_FULLY_VERIFIED and report.undiagnosed_findings:
        console.print(
            f"[yellow]Not fully verified:[/yellow] {len(report.undiagnosed_findings)} ipa-healthcheck finding(s) "
            "that no ipa-diagnose rule explains remain (see UNDIAGNOSED below). No cause is claimed."
        )
    console.print()

    if not report.diagnoses:
        if report.evidence_completeness.level == "complete":
            if report.undiagnosed_findings or report.unclaimed_warnings:
                console.print(
                    "No problem was diagnosed by any rule and all expected evidence was collected, [bold yellow]but "
                    "ipa-healthcheck reported findings that no ipa-diagnose rule can explain[/bold yellow] "
                    "(listed below). They are not confirmed harmless - review them."
                )
            else:
                console.print(
                    "[bold green]No problems detected.[/bold green] All ipa-healthcheck checks passed and "
                    "all expected evidence was collected."
                )
        elif not report.evidence_completeness.healthcheck_collected:
            console.print(
                "[bold yellow]ipa-healthcheck produced no results, so its checks tell nothing about this server. "
                "This is NOT a healthy result.[/bold yellow]"
            )
        else:
            console.print(
                "[bold yellow]No problem was observed, but health could NOT be fully verified[/bold yellow] "
                "- see the evidence gaps above."
            )
        _print_undiagnosed(report, console, details=details)
        _print_coverage(report, console, details=details)
        return

    primaries = report.by_priority(PriorityBucket.PRIMARY)
    secondaries = report.by_priority(PriorityBucket.SECONDARY_INDEPENDENT)
    related = report.by_priority(PriorityBucket.RELATED_SYMPTOM)
    warnings = report.by_priority(PriorityBucket.WARNING)
    info = report.by_priority(PriorityBucket.INFORMATIONAL)

    res = report.resolutions or {}
    for d in primaries:
        _render_primary_block(d, console, ai_explanations.get(d.diagnosis_id), details=details,
                              resolution=res.get(d.diagnosis_id))

    if secondaries:
        console.print(Rule("OTHER INDEPENDENT PROBLEMS", style="yellow"))
        console.print("[dim]May or may not be related to the problem above - each needs its own investigation.[/dim]\n")
        for d in secondaries:
            _render_primary_block(d, console, ai_explanations.get(d.diagnosis_id), details=details, compact=not details,
                                  resolution=res.get(d.diagnosis_id))

    if related:
        console.print(Rule("RELATED SYMPTOMS", style="dim"))
        for d in related:
            if d.related_to_titles:
                relation = f"  (related to: {', '.join(d.related_to_titles)})"
            else:
                relation = ""
            console.print(f"  • {escape(d.title)}[dim]{escape(relation)}[/dim]")
            if details:
                console.print(f"    [dim]{escape(_first_line(d.why))}[/dim]")
        console.print()

    if warnings:
        with_fix = [d for d in warnings if d.diagnosis_id in res]
        plain = [d for d in warnings if d.diagnosis_id not in res]
        if plain:
            console.print(Rule("WARNINGS", style="dim"))
            for d in plain:
                console.print(f"  ⚠ {escape(d.title)}")
            console.print()
        for d in with_fix:
            _render_primary_block(d, console, ai_explanations.get(d.diagnosis_id), details=details,
                                  resolution=res.get(d.diagnosis_id), label="WARNING")

    if details and info:
        console.print(Rule("INFORMATIONAL", style="dim"))
        for d in info:
            console.print(f"  ℹ {escape(d.title)}")
        console.print()

    _print_undiagnosed(report, console, details=details)
    _print_coverage(report, console, details=details)


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else ""


def _render_primary_block(
    d: Diagnosis, console: Console, ai_explanation: Optional[str], *, details: bool, compact: bool = False,
    resolution=None, label: Optional[str] = None,
) -> None:
    if label is None:
        label = "PRIMARY PROBLEM" if d.priority == PriorityBucket.PRIMARY else "INDEPENDENT PROBLEM"
    console.print(Rule(label, style="red" if d.priority == PriorityBucket.PRIMARY else "yellow"))
    if resolution is not None and d.status == DiagnosisStatus.DIAGNOSED:
        console.print(Text("ROOT CAUSE", style="bold underline"))
    console.print(Text(d.title, style="bold"))
    console.print()

    if d.status != DiagnosisStatus.DIAGNOSED:
        console.print(Text("ROOT CAUSE", style="bold underline"))
        console.print("Unable to determine safely.\n")

    console.print(Text("WHY", style="bold underline"))
    console.print(escape((ai_explanation or d.why).strip()))
    if ai_explanation:
        console.print("[dim](explanation simplified by AI from the deterministic diagnosis above)[/dim]")
    console.print()

    if d.evidence_for:
        console.print(Text("EVIDENCE", style="bold underline"))
        for ref in d.evidence_for:
            console.print(f"  ✓ {escape(ref.why_relevant)}")
        if d.evidence_against:
            for ref in d.evidence_against:
                console.print(f"  [yellow]✗ (contradicts) {escape(ref.why_relevant)}[/yellow]")
        console.print()

    if resolution is not None and resolution.checks:
        _render_checked(resolution, console)

    if d.impact:
        console.print(Text("IMPACT", style="bold underline"))
        console.print(escape(d.impact))
        console.print()

    if resolution is not None:
        _render_resolution(d, resolution, console, details=details)
        return

    if d.status != DiagnosisStatus.DIAGNOSED and d.next_diagnostic_step:
        console.print(Text("DO THIS NEXT", style="bold underline"))
        console.print(escape(d.next_diagnostic_step))
        # next_diagnostic_step is always a safe, read-only disambiguation
        # step by contract (see Diagnosis.next_diagnostic_step's docstring)
        # - labeled explicitly so the safety signal is consistent with the
        # DIAGNOSED/"DO THIS FIRST" case below, not silently dropped here.
        safe_style, safe_label = _RISK_STYLE[RiskLevel.SAFE]
        console.print(f"Safety: [{safe_style}]{safe_label}[/{safe_style}]")
        console.print()
    elif d.actions:
        first = d.actions[0]
        console.print(Text("DO THIS FIRST", style="bold underline"))
        console.print(escape(first.description))
        if first.command:
            console.print(f"\n    [bold cyan]{escape(first.command)}[/bold cyan]\n")
        style, label = _RISK_STYLE[first.risk]
        console.print(f"Safety: [{style}]{label}[/{style}]")
        if len(d.actions) > 1 and not compact and not details:
            console.print(f"\n[dim]{len(d.actions) - 1} additional step(s) - see --details.[/dim]")
        console.print()

    if details and len(d.actions) > 1:
        console.print(Text("ADDITIONAL ACTIONS", style="bold underline"))
        for a in d.actions[1:]:
            style, label = _RISK_STYLE[a.risk]
            console.print(f"  - {escape(a.description)}")
            if a.command:
                console.print(f"      [cyan]{escape(a.command)}[/cyan]")
            console.print(f"    Safety: [{style}]{label}[/{style}]")
        console.print()

    if details:
        console.print(Text("CONFIDENCE", style="bold underline"))
        console.print(escape(f"{d.confidence.level.value}: {d.confidence.rationale}"))
        console.print()
        if d.limitations:
            console.print(Text("LIMITATIONS", style="bold underline"))
            console.print(escape(d.limitations))
            console.print()

    if d.verification:
        console.print(Text("VERIFY", style="bold underline"))
        console.print("After addressing this, confirm with:\n")
        console.print("    [bold]sudo ipa-diagnose verify[/bold]\n")
        if details:
            for v in d.verification:
                console.print(f"  - {escape(v.description)}")
        console.print()


_PROC_RISK = {
    "LOW": ("green", "LOW - a small, reversible change"),
    "MEDIUM": ("yellow", "MEDIUM - changes a running system; read each step before running it"),
    "HIGH": ("red", "HIGH - hard to reverse or affects other servers"),
}
_CHECK_MARK = {"OK": "-", "FAILED": "!", "NOT_RUN": "?", "DENIED": "?"}


def _render_checked(r, console: Console) -> None:
    console.print(Text("CHECKED FOR YOU", style="bold underline"))
    if r.replay:
        console.print("[dim]Read-only check results recorded in this replay fixture (not run now):[/dim]")
    else:
        console.print("[dim]Read-only checks ipa-diagnose ran on this host just now (results, not problems):[/dim]")
    for label, c in r.checks:
        mark = _CHECK_MARK.get(c.status, "?")
        result = c.display or c.status
        console.print(f"  {mark} {escape(label)}: {escape(result)}")
    console.print()


def _render_resolution(d: Diagnosis, r, console: Console, *, details: bool) -> None:
    """ROOT CAUSE -> WHY -> IMPACT (above) -> FIX -> PREREQUISITES -> WHAT THIS CHANGES -> RISK -> ROLLBACK -> VERIFY."""

    if r.status == "NONE":
        console.print(Text("FIX", style="bold underline"))
        console.print("[bold]No deterministic fix is shown.[/bold]")
        for reason in r.reasons:
            console.print(escape(reason))
        if r.reference:
            console.print(f"Documentation: {escape(r.reference)}")
        console.print()
        _render_safe_legacy_actions(d, console, details=details)
        _render_legacy_tail(d, console, details=details)
        return
    if r.status != "OFFERED":
        console.print(Text("FIX", style="bold underline"))
        console.print("[bold yellow]No fix is shown[/bold yellow] - ipa-diagnose shows a fix only when it could confirm, "
                      "with fresh read-only checks, that it applies here and is safe to suggest.")
        for reason in r.reasons:
            console.print(f"  - {escape(reason)}")
        console.print()
        _render_safe_legacy_actions(d, console, details=details)
        _render_legacy_tail(d, console, details=details)
        return

    console.print(Text("FIX", style="bold underline"))
    count = len(r.steps)
    console.print(f"[bold]{escape(r.title)}[/bold] - {count} step{'s' if count != 1 else ''} on this server, "
                  "run by you (ipa-diagnose never runs a fix itself).")
    if not r.definitive:
        console.print(f"[yellow]{escape(r.verification_label)}[/yellow]")
    if r.confirm_first:
        console.print("  [bold]First confirm[/bold] (read-only) that nothing changed since the checks above; "
                      "if the output differs, do not run the fix - run ipa-diagnose again:")
        for c in r.confirm_first:
            console.print(f"       [cyan]{escape(shlex.join(c['argv']))}[/cyan]   [dim]expected: {escape(c['expect'])}[/dim]")
    for i, st in enumerate(r.steps, 1):
        console.print(f"  {i}. {escape(st.text)}")
        console.print(f"       [bold cyan]{escape(st.command)}[/bold cyan]")
        if details:
            console.print(f"       [dim]expected: {escape(st.expected)} | risk {st.risk}[/dim]")
    for reason in r.reasons:  # e.g. a reported file that was skipped
        console.print(f"  [dim]note: {escape(reason)}[/dim]")
    console.print()

    if r.prerequisites:
        console.print(Text("PREREQUISITES", style="bold underline"))
        for p in r.prerequisites:
            if p.state == "met":
                console.print(f"  ✓ {escape(p.text)} ({'recorded' if r.replay else 'checked'})")
            else:
                console.print(f"  [yellow]! Before running, accept that:[/yellow] {escape(p.text)}")
        console.print()

    console.print(Text("WHAT THIS CHANGES", style="bold underline"))
    for w in r.what_changes:
        console.print(f"  - {escape(w)}")
    if r.impact_note:
        console.print(f"  [dim]Why it matters: {escape(r.impact_note)}[/dim]")
    console.print()

    style, text = _PROC_RISK.get(r.risk, ("yellow", r.risk))
    console.print(Text("RISK", style="bold underline"))
    console.print(f"[{style}]{text}[/{style}]")
    console.print()

    console.print(Text("ROLLBACK", style="bold underline"))
    for rb in r.rollback:
        console.print(f"  - {escape(rb['text'])}")
        if rb.get("argv"):
            console.print(f"       [cyan]{escape(shlex.join(rb['argv']))}[/cyan]")
    console.print()

    console.print(Text("VERIFY", style="bold underline"))
    console.print("After the fix, run (on the server):\n\n    [bold]sudo ipa-diagnose verify[/bold]\n")
    console.print("It re-runs the diagnosis and checks, with fresh evidence:")
    for v in r.verify:
        console.print(f"  - {escape(v['text'])}")
    console.print()
    if r.limitations:
        console.print(Text("LIMITATIONS", style="bold underline"))
        console.print(escape(r.limitations))
        console.print()

    if details:
        console.print(Text("CONFIDENCE", style="bold underline"))
        console.print(escape(f"{d.confidence.level.value}: {d.confidence.rationale}"))
        console.print()
        console.print(Text("ABOUT THIS FIX", style="bold underline"))
        console.print(escape(f"Procedure {r.procedure_id} | applies to: {r.applies_to} | knowledge tier: {r.tier}"))
        console.print(escape(r.verification_label))
        console.print()


def _render_legacy_tail(d: Diagnosis, console: Console, *, details: bool) -> None:
    """CONFIDENCE / LIMITATIONS / VERIFY exactly as v0.1.3 shows them, for diagnoses without an offered fix."""

    if details:
        console.print(Text("CONFIDENCE", style="bold underline"))
        console.print(escape(f"{d.confidence.level.value}: {d.confidence.rationale}"))
        console.print()
        if d.limitations:
            console.print(Text("LIMITATIONS", style="bold underline"))
            console.print(escape(d.limitations))
            console.print()
    if d.verification:
        console.print(Text("VERIFY", style="bold underline"))
        console.print("After addressing this, confirm with:\n")
        console.print("    [bold]sudo ipa-diagnose verify[/bold]\n")
        if details:
            for v in d.verification:
                console.print(f"  - {escape(v.description)}")
        console.print()


def _render_safe_legacy_actions(d: Diagnosis, console: Console, *, details: bool = False) -> None:
    """When no procedure is offered, only read-only guidance from the older action list is shown (state-changing
    legacy actions stay in the JSON only: the checks above found a reason not to show a fix)."""

    safe = [a for a in d.actions if a.risk == RiskLevel.SAFE]
    if not safe:
        return
    console.print(Text("SAFE NEXT STEP", style="bold underline"))
    console.print(escape(safe[0].description))
    if safe[0].command:
        console.print(f"\n    [bold cyan]{escape(safe[0].command)}[/bold cyan]\n")
    style, label = _RISK_STYLE[RiskLevel.SAFE]
    console.print(f"Safety: [{style}]{label}[/{style}]")
    console.print()
    if details and len(safe) > 1:
        console.print(Text("ADDITIONAL READ-ONLY STEPS", style="bold underline"))
        for a in safe[1:]:
            console.print(f"  - {escape(a.description)}")
            if a.command:
                console.print(f"      [cyan]{escape(a.command)}[/cyan]")
            console.print(f"    Safety: [{style}]{label}[/{style}]")
        console.print()


_VERIFY_STYLE = {
    "RESOLVED": ("green", "✓"),
    "STILL_PRESENT": ("red", "✗"),
    "PARTIALLY_RESOLVED": ("yellow", "≈"),
    "UNABLE_TO_VERIFY": ("dim", "?"),
    "CHANGED": ("yellow", "~"),
}


def render_verify(result, console: Console) -> None:
    console.print(Rule("Verification", style="cyan"))
    if result.previous_generated_at is None:
        console.print(
            "[yellow]No previous diagnosis found to verify against.[/yellow] "
            "Run [bold]sudo ipa-diagnose[/bold] first, then re-run verify after attempting a fix."
        )
        return

    console.print(f"[dim]Comparing against diagnosis from {escape(result.previous_generated_at)}[/dim]")
    if result.current_report is not None and getattr(result.current_report, "replay_source", None):
        console.print("[yellow]Replay: the fresh side of this comparison is recorded evidence from a fixture; "
                      "nothing was checked on this host now.[/yellow]")
    if result.current_report is not None:
        if result.current_report.evidence_completeness.level == "complete":
            console.print("[green]Evidence for this check: COMPLETE[/green]")
        _print_evidence_banner(result.current_report, console)
    console.print()
    if not result.items:
        if result.current_report is not None and result.current_report.evidence_completeness.level != "complete":
            console.print(
                "[yellow]The previous run found no problems, but fresh evidence is incomplete "
                "- health is NOT verified.[/yellow]"
            )
        else:
            console.print("[green]The previous run found no problems, so there is nothing to verify.[/green]")
        _print_verify_undiagnosed_note(result, console)
        return

    for item in result.items:
        style, mark = _VERIFY_STYLE[item.outcome.value]
        console.print(f"[{style}]{mark} {item.outcome.value}[/{style}]  {escape(item.title)}")
        console.print(f"    {escape(item.detail)}")
    console.print()

    if result.new_conditions:
        console.print(Rule("NEW CONDITION SINCE LAST RUN", style="yellow"))
        for d in result.new_conditions:
            console.print(f"  ⚠ {escape(d.title)}")
        console.print("[dim]Run `sudo ipa-diagnose` for full detail on this.[/dim]")
    _print_verify_undiagnosed_note(result, console)


def _print_verify_undiagnosed_note(result, console: Console) -> None:
    """Explain a non-zero verify exit that is not about the previously found problem."""

    rep = result.current_report
    if rep is not None and rep.undiagnosed_findings and rep.overall_status == OverallStatus.NOT_FULLY_VERIFIED:
        console.print(
            f"[yellow]Overall status is still NOT_FULLY_VERIFIED (exit 4):[/yellow] {len(rep.undiagnosed_findings)} "
            "ipa-healthcheck finding(s) that no ipa-diagnose rule explains remain. Run `sudo ipa-diagnose` to list them."
        )


def _print_evidence_banner(report: DiagnosisReport, console: Console) -> None:
    """Material evidence gaps are shown up front, not buried in a footer."""

    c = report.evidence_completeness
    if c.level == "complete" and c.ruv_state != "NOT_VERIFIED":
        return
    console.print(Text.assemble(("Evidence: ", "bold"), (c.level.upper(), "bold yellow")))
    if not c.healthcheck_collected:
        console.print("  [yellow]ipa-healthcheck evidence could not be collected - nothing can be reported healthy.[/yellow]")
    if c.ruv_state == "NOT_VERIFIED":
        console.print(
            f"  [yellow]RUV state: NOT VERIFIED[/yellow] - {escape(c.ruv_reason or 'unknown reason')} "
            "(this is NOT a stale-RUV finding; stale replica metadata could not be checked)"
        )
        ruv_cap = next((u for u in c.unverified if u.collector == "replication_agreements"), None)
        if ruv_cap is not None and ruv_cap.hint:
            console.print(f"    [cyan]What to do:[/cyan] {escape(ruv_cap.hint)}")
    for u in c.unverified:
        if u.collector == "replication_agreements" and c.ruv_state == "NOT_VERIFIED":
            continue
        console.print(f"  [yellow]NOT VERIFIED: {escape(u.capability)}[/yellow] - {escape(u.reason)}")
        if u.hint:
            console.print(f"    [cyan]What to do:[/cyan] {escape(u.hint)}")


_UNDIAGNOSED_DEFAULT_LIMIT = 8
_UNDIAGNOSED_DETAILS_LIMIT = 200


def _print_undiagnosed(report: DiagnosisReport, console: Console, *, details: bool = False) -> None:
    """ipa-healthcheck findings no rule explains: named, never only counted."""

    items = report.undiagnosed_findings
    if not items:
        return
    console.print(Rule("UNDIAGNOSED ipa-healthcheck FINDINGS", style="yellow"))
    console.print(
        f"[dim]{len(items)} finding(s) not explained by any ipa-diagnose rule. That does not mean they are "
        "harmless - review them with ipa-healthcheck. No cause is claimed.[/dim]"
    )
    shown = items[: _UNDIAGNOSED_DETAILS_LIMIT if details else _UNDIAGNOSED_DEFAULT_LIMIT]
    for u in shown:
        crash = " [check crashed]" if u.crashed else ""
        keyed = f" - {u.key}" if u.key and u.key not in u.message else ""
        console.print(f"  • \\[{escape(u.severity)}] {escape(u.source)}.{escape(u.check)}{escape(crash)}: {escape(u.message)}{escape(keyed)}")
        if details:
            since = f"check available since ipa-healthcheck {u.check_known_since}" if u.check_known_since else "not in this build's upstream check catalog"
            ver = f"; installed ipa-healthcheck {u.ipa_healthcheck_version}" if u.ipa_healthcheck_version else ""
            console.print(f"    [dim]{escape(since)}{escape(ver)}[/dim]" if not (u.crashed or not u.check_known_since) else f"    [dim]{escape(u.reason)} ({escape(since)}{escape(ver)})[/dim]")
    if len(shown) < len(items):
        hint = "use --json for all" if details else "use --details or --json for all"
        console.print(f"  [dim]... and {len(items) - len(shown)} more ({hint})[/dim]")
    console.print()


def _print_coverage(report: DiagnosisReport, console: Console, *, details: bool = False) -> None:
    console.print(Rule(style="dim"))
    if report.evidence_completeness.healthcheck_collected:
        console.print(f"[dim]Diagnostic packs evaluated: {', '.join(report.packs_evaluated)}[/dim]")
    else:
        console.print("[dim]Diagnostic packs: not evaluated (no ipa-healthcheck evidence to evaluate)[/dim]")
    if report.collection_errors:
        console.print(f"[yellow]Evidence collection issues ({len(report.collection_errors)}):[/yellow]")
        for err in report.collection_errors:
            console.print(f"  [yellow]- {escape(err)}[/yellow]")
    if report.unknown_severity_findings:
        console.print(f"[yellow]Unrecognized severity value(s) ({len(report.unknown_severity_findings)}):[/yellow]")
        for note in report.unknown_severity_findings:
            console.print(f"  [yellow]- {escape(note)}[/yellow]")
    if details and report.environment:
        env = report.environment
        parts = []
        if env.distro or env.distro_version:
            parts.append(f"OS: {env.distro or '?'} {env.distro_version or ''}".strip())
        if env.python_version:
            parts.append(f"Python: {env.python_version}")
        if env.freeipa_version:
            parts.append(f"FreeIPA: {env.freeipa_version}")
        if env.ipa_healthcheck_version:
            parts.append(f"ipa-healthcheck: {env.ipa_healthcheck_version}")
        if env.directory_server_version:
            parts.append(f"389-ds: {env.directory_server_version}")
        if parts:
            console.print(f"[dim]Environment ({'live' if env.detected_live else 'replayed'}): {escape(' | '.join(parts))}[/dim]")
