"""Renders the exact outbound AI payload for `ipa-diagnose ai-preview`.

Deliberately thin: it must not reformat or re-derive anything build_ai_payload
didn't already produce, so what the administrator sees here is byte-for-byte
what ai/provider.py would send if AI were enabled.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ipa_diagnose.privacy.minimize import AIPayload


def render_preview(payload: AIPayload, console: Console) -> None:
    body = Text()
    body.append("System prompt:\n", style="bold")
    body.append(payload.system_prompt.strip() + "\n\n")
    body.append("User prompt (built from the diagnosis + selected evidence only):\n", style="bold")
    body.append(payload.user_prompt.strip())

    console.print(
        Panel(
            body,
            title=f"[bold]Exact payload that would be sent to the AI provider[/bold] ({payload.diagnosis_id})",
            border_style="cyan",
        )
    )
    console.print(
        f"[dim]Evidence sent: {len(payload.selected_evidence)} item(s). "
        f"Excluded from bundle: {payload.excluded_evidence_count} item(s) not relevant to this diagnosis.[/dim]"
    )
    style = "yellow" if payload.redaction_matches else "green"
    console.print(f"[{style}]{payload.redaction_summary()}[/{style}]")
