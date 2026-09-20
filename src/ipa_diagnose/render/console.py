"""Default and --details terminal rendering.

Kept deliberately close to plain sectioned text (WHY / EVIDENCE / IMPACT / DO
THIS FIRST / VERIFY) rather than dense tables - the 30-60 second
comprehension bar this product is judged against favors a short linear
read over a dashboard the administrator has to parse. rich is used for
color/emphasis only, never to reorganize the structure.
"""

from __future__ import annotations

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
    console.print()

    if not report.diagnoses:
        if report.evidence_completeness.level == "complete":
            if report.unclaimed_warnings:
                console.print(
                    "[bold green]No problems detected by any diagnostic rule[/bold green] and all expected evidence "
                    f"was collected. Note: ipa-healthcheck reported {report.unclaimed_warnings} warning(s) that no "
                    "rule covers (run `ipa-healthcheck` to see them)."
                )
            else:
                console.print(
                    "[bold green]No problems detected.[/bold green] All ipa-healthcheck checks passed and "
                    "all expected evidence was collected."
                )
        else:
            console.print(
                "[bold yellow]No problem was observed, but health could NOT be fully verified[/bold yellow] "
                "- see the evidence gaps above."
            )
        _print_coverage(report, console, details=details)
        return

    primaries = report.by_priority(PriorityBucket.PRIMARY)
    secondaries = report.by_priority(PriorityBucket.SECONDARY_INDEPENDENT)
    related = report.by_priority(PriorityBucket.RELATED_SYMPTOM)
    warnings = report.by_priority(PriorityBucket.WARNING)
    info = report.by_priority(PriorityBucket.INFORMATIONAL)

    for d in primaries:
        _render_primary_block(d, console, ai_explanations.get(d.diagnosis_id), details=details)

    if secondaries:
        console.print(Rule("OTHER INDEPENDENT PROBLEMS", style="yellow"))
        console.print("[dim]May or may not be related to the problem above - each needs its own investigation.[/dim]\n")
        for d in secondaries:
            _render_primary_block(d, console, ai_explanations.get(d.diagnosis_id), details=details, compact=not details)

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
        console.print(Rule("WARNINGS", style="dim"))
        for d in warnings:
            console.print(f"  ⚠ {escape(d.title)}")
        console.print()

    if details and info:
        console.print(Rule("INFORMATIONAL", style="dim"))
        for d in info:
            console.print(f"  ℹ {escape(d.title)}")
        console.print()

    _print_coverage(report, console, details=details)


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else ""


def _render_primary_block(
    d: Diagnosis, console: Console, ai_explanation: Optional[str], *, details: bool, compact: bool = False
) -> None:
    label = "PRIMARY PROBLEM" if d.priority == PriorityBucket.PRIMARY else "INDEPENDENT PROBLEM"
    console.print(Rule(label, style="red" if d.priority == PriorityBucket.PRIMARY else "yellow"))
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

    if d.impact:
        console.print(Text("IMPACT", style="bold underline"))
        console.print(escape(d.impact))
        console.print()

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


_VERIFY_STYLE = {
    "RESOLVED": ("green", "✓"),
    "STILL_PRESENT": ("red", "✗"),
    "PARTIALLY_RESOLVED": ("yellow", "≈"),
    "UNABLE_TO_VERIFY": ("dim", "?"),
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
