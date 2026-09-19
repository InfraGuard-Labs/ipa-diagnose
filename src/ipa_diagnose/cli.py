"""ipa-diagnose command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, Optional

from rich.console import Console

from ipa_diagnose import __version__
from ipa_diagnose.ai.prompt import explain_diagnosis
from ipa_diagnose.config import AIConfig, build_provider
from ipa_diagnose.engine.model import DiagnosisReport, PriorityBucket
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.evidence.model import EvidenceBundle
from ipa_diagnose.privacy.minimize import build_ai_payload
from ipa_diagnose.privacy.preview import render_preview
from ipa_diagnose.render.console import render_report, render_verify
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.verify import compare, default_state_path, load_previous_report, save_report

_EXPLAINABLE_PRIORITIES = {PriorityBucket.PRIMARY, PriorityBucket.SECONDARY_INDEPENDENT}


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--details", action="store_true", help="show full evidence, confidence, and all actions")
    parser.add_argument("--json", action="store_true", help="print the report as JSON instead of formatted text")
    parser.add_argument("--no-ai", action="store_true", help="never contact an AI provider, even if configured")
    parser.add_argument(
        "--ai-provider", choices=["openai", "anthropic", "bedrock"], default=None,
        help="override IPA_DIAGNOSE_AI_PROVIDER for this run",
    )
    parser.add_argument(
        "--replay", metavar="FIXTURE_DIR", default=None,
        help="read evidence from a fixture directory instead of the live host (development/testing)",
    )


def build_parser() -> argparse.ArgumentParser:
    # A single parser with one optional positional `command`, rather than
    # argparse subparsers: subparsers each get their own copy of the common
    # flags' defaults, which silently clobbers a flag given *before* the
    # subcommand name (e.g. `ipa-diagnose --replay DIR diagnose` would reset
    # --replay back to None). One shared namespace avoids that entirely.
    parser = argparse.ArgumentParser(prog="ipa-diagnose", description="FreeIPA / Red Hat IdM diagnostic tool")
    parser.add_argument("--version", action="version", version=f"ipa-diagnose {__version__}")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["diagnose", "verify", "ai-preview"],
        default="diagnose",
        help="diagnose (default): run diagnosis. verify: check if previously diagnosed problems cleared. "
        "ai-preview: show exactly what would be sent to the AI provider.",
    )
    _add_common_args(parser)
    return parser


def _ai_config_from_args(args: argparse.Namespace) -> AIConfig:
    return AIConfig.from_env_and_args(no_ai=args.no_ai, provider_arg=args.ai_provider)


def _collect_and_diagnose(args: argparse.Namespace) -> tuple[EvidenceBundle, DiagnosisReport]:
    bundle = collect_evidence(replay_dir=args.replay)
    report = run_diagnosis(bundle)
    return bundle, report


def _maybe_explain(
    report: DiagnosisReport, bundle: EvidenceBundle, args: argparse.Namespace, console: Console
) -> Dict[str, str]:
    explanations: Dict[str, str] = {}
    config = _ai_config_from_args(args)
    if config.provider == "none":
        return explanations
    provider = build_provider(config)
    if not provider.is_configured():
        console.print(
            f"[dim](AI provider '{config.provider}' is not configured - showing local explanation)[/dim]"
        )
        return explanations
    for d in report.diagnoses:
        if d.priority not in _EXPLAINABLE_PRIORITIES:
            continue
        text = explain_diagnosis(d, bundle, provider)
        if text:
            explanations[d.diagnosis_id] = text
        else:
            console.print(
                f"[dim](AI explanation unavailable for '{d.title}' - showing local explanation)[/dim]"
            )
    return explanations


def cmd_diagnose(args: argparse.Namespace, console: Console) -> int:
    bundle, report = _collect_and_diagnose(args)
    explanations = {} if args.json else _maybe_explain(report, bundle, args, console)

    if args.json:
        print(json.dumps(report_to_dict(report, explanations), indent=2))
    else:
        render_report(report, console, details=args.details, ai_explanations=explanations)

    save_report(default_state_path(), report)
    return _exit_code_for(report)


def cmd_verify(args: argparse.Namespace, console: Console) -> int:
    bundle, report = _collect_and_diagnose(args)
    previous = load_previous_report(default_state_path())
    result = compare(previous, report)

    if args.json:
        print(
            json.dumps(
                {
                    "previous_generated_at": result.previous_generated_at,
                    "items": [
                        {"diagnosis_id": i.diagnosis_id, "title": i.title, "outcome": i.outcome.value, "detail": i.detail}
                        for i in result.items
                    ],
                    "new_conditions": [d.title for d in result.new_conditions],
                    "current_report": report_to_dict(report),
                },
                indent=2,
            )
        )
    else:
        render_verify(result, console)

    save_report(default_state_path(), report)
    from ipa_diagnose.verify import VerifyOutcome

    if any(i.outcome == VerifyOutcome.UNABLE_TO_VERIFY for i in result.items) or (
        report.evidence_completeness.level != "complete"
    ):
        return 4  # verification is incomplete: never a clean 0
    return 0


def cmd_ai_preview(args: argparse.Namespace, console: Console) -> int:
    bundle, report = _collect_and_diagnose(args)
    explainable = [d for d in report.diagnoses if d.priority in _EXPLAINABLE_PRIORITIES]
    if not explainable:
        if report.evidence_completeness.level != "complete":
            console.print(
                "[yellow]No problem to explain, but evidence is incomplete (health NOT verified):[/yellow]"
            )
            for u in report.evidence_completeness.unverified:
                console.print(f"  - {u.capability}: {u.reason}", markup=False)
            return _exit_code_for(report)
        console.print("[green]No primary or independent problems to explain right now.[/green]")
        return 0
    for d in explainable:
        payload = build_ai_payload(bundle, d)
        render_preview(payload, console)
        console.print()
    return 0


def _exit_code_for(report: DiagnosisReport) -> int:
    from ipa_diagnose.engine.model import OverallStatus

    return {
        OverallStatus.HEALTHY: 0,
        OverallStatus.DEGRADED: 1,
        OverallStatus.CRITICAL: 2,
        OverallStatus.UNKNOWN: 3,
        OverallStatus.NOT_FULLY_VERIFIED: 4,
    }[report.overall_status]


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # highlight=False: rich's default ReprHighlighter auto-colors substrings
    # that look like paths/numbers/quoted strings inside plain evidence text
    # (e.g. a log message), which reads as noise, not signal, in this UI -
    # all intentional styling here is explicit markup, not auto-detected.
    console = Console(highlight=False)

    command = args.command or "diagnose"
    if os.name != "nt" and command in ("diagnose", "verify") and args.replay is None and os.geteuid() != 0:
        console.print(
            "[yellow]Warning: not running as root - live evidence collection (ipa-healthcheck, "
            "journalctl, certmonger) will likely fail or be incomplete.[/yellow]\n"
        )

    try:
        if command == "verify":
            return cmd_verify(args, console)
        if command == "ai-preview":
            return cmd_ai_preview(args, console)
        return cmd_diagnose(args, console)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
