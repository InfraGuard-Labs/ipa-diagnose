"""Ties the privacy pipeline + AIProvider together, with a defense-in-depth
sanitizer on the way back out.

Structural safety guarantee (the important one): the rendered Actions section
in the CLI ALWAYS comes from `Diagnosis.actions` (deterministic Action
objects), never from AI output. An AI explanation is prose displayed
alongside that section, never a replacement for it. `sanitize_explanation`
below is a second, best-effort layer on top of that structural guarantee -
it catches an AI response that ignored its instructions and tried to invent
a new command anyway, and rejects the whole explanation rather than trying
to strip just the bad line (a partially-sanitized AI paragraph is more
misleading than falling back to the deterministic `why` text).
"""

from __future__ import annotations

import re
from typing import Optional

from ipa_diagnose.ai.provider import AIProvider, AIRequest, ProviderError
from ipa_diagnose.engine.model import Diagnosis
from ipa_diagnose.evidence.model import EvidenceBundle
from ipa_diagnose.privacy.minimize import build_ai_payload

# Deliberately NOT anchored to line-start (an earlier version was - a
# security review found that let prose-embedded suggestions like "you could
# try: getcert resubmit ..." slip through undetected) and deliberately a
# broad binary/keyword list rather than an exhaustive one, since the goal is
# "reject anything command-shaped we don't recognize as approved," not
# "recognize every dangerous command by name."
_COMMAND_LIKE = re.compile(
    # Zero-width lookbehind for the boundary (start-of-string, whitespace, or
    # a backtick) rather than a consuming group - otherwise match.group(0)
    # includes the boundary character and would never equal an approved
    # command string during comparison.
    r"(?<![^\s`])(?:\$\s*)?(?:sudo\s+)?(?:/usr/(?:s?bin)/)?"
    r"(ipa[\w-]*|getcert|kinit|klist|kvno|dsconf|dsctl|ldapmodify|ldapsearch|"
    r"systemctl|service|reboot|shutdown|halt|poweroff|init\s+0|"
    r"rm\b|mkfs[\w.]*|dd\b|userdel|groupdel|iptables|firewall-cmd|"
    r"dnf|yum|rpm\b|certutil|db2index[\w.]*|chmod|chown|kill(?:all)?|"
    r"curl|wget|python[\w.]*|perl|bash|sh\b|nc\b|ncat)\b",
    re.IGNORECASE,
)
_CODE_SPAN = re.compile(r"`([^`\n]{1,200})`")
_MAX_EXPLANATION_CHARS = 4000


def _looks_approved(candidate: str, approved_commands: set) -> bool:
    candidate = candidate.strip()
    # The span must be (part of) an approved command - never an approved
    # command with extra text appended.
    return any(candidate in cmd for cmd in approved_commands)


def sanitize_explanation(text: str, diagnosis: Diagnosis) -> Optional[str]:
    """Returns the explanation if it looks like prose only, else None (caller
    must fall back to the deterministic `why` text).

    Two independent checks, either of which rejects the whole response:
    1. Any command-shaped token (see _COMMAND_LIKE) appearing anywhere in
       the text, not just at a line's start.
    2. Any markdown-style inline code span (`` `...` ``) whose content isn't
       one of the diagnosis's own approved commands - this catches the
       common AI phrasing "run `<command>`" regardless of whether the
       command inside the backticks matches a known binary name.
    """

    if not text or not text.strip():
        return None
    if len(text) > _MAX_EXPLANATION_CHARS:
        return None

    approved_commands = {a.command for a in diagnosis.actions if a.command}

    for span_match in _CODE_SPAN.finditer(text):
        if not _looks_approved(span_match.group(1), approved_commands):
            return None

    for match in _COMMAND_LIKE.finditer(text):
        if not _looks_approved(match.group(0), approved_commands):
            return None

    return text.strip()


def explain_diagnosis(diagnosis: Diagnosis, bundle: EvidenceBundle, provider: AIProvider) -> Optional[str]:
    """Returns an AI explanation, or None on any failure/refusal/unsafe output -
    callers must always have a local-explanation fallback ready (Diagnosis.why),
    ipa-diagnose must remain fully useful with this returning None."""

    if not provider.is_configured():
        return None
    payload = build_ai_payload(bundle, diagnosis)
    try:
        response = provider.generate(
            AIRequest(system_prompt=payload.system_prompt, user_prompt=payload.user_prompt)
        )
    except ProviderError:
        return None
    return sanitize_explanation(response.text, diagnosis)
