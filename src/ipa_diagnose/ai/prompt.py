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
from ipa_diagnose.engine.model import Diagnosis, RiskLevel
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
    r"curl|wget|python[\w.]*|perl|bash|sh\b|nc\b|ncat|chronyc|chgrp|setfacl|restorecon|mv\b|cp\b)\b",
    re.IGNORECASE,
)
_CODE_SPAN = re.compile(r"`([^`\n]{1,200})`")
_MAX_EXPLANATION_CHARS = 4000


# Where the phrase started by a command-shaped word ends (code-span edge, line end, clause punctuation).
_PHRASE_END = re.compile(r"[`\n;,()]|\.(?:\s|$)|:\s")
_LEAD = re.compile(r"^(?:\$\s*)?(?:sudo\s+)?")


def _tokens(text: str) -> list:
    return _LEAD.sub("", text.strip()).split()


def _looks_approved(candidate: str, approved_commands: set) -> bool:
    """The candidate is an approved command, or its leading whole words (e.g. just the program name).

    Never an approved command with anything appended, and never a substring match: a bare
    `systemctl` inside an approved command must not approve `systemctl stop krb5kdc`."""

    got = _tokens(candidate)
    if not got:
        return True
    return any(got == _tokens(cmd)[:len(got)] for cmd in approved_commands)


def _approved_spans(text: str, approved_commands: set) -> list:
    """Character ranges where an approved command appears verbatim (followed by a word boundary)."""

    spans = []
    for cmd in approved_commands:
        start = text.find(cmd)
        while start != -1:
            end = start + len(cmd)
            if end == len(text) or not (text[end].isalnum() or text[end] in "-_/=@"):
                spans.append((start, end))
            start = text.find(cmd, start + 1)
    return spans


def sanitize_explanation(text: str, diagnosis: Diagnosis) -> Optional[str]:
    """Returns the explanation if it looks like prose only, else None (caller
    must fall back to the deterministic `why` text).

    Only the diagnosis's own SAFE (read-only) actions count as approved: an AI
    explanation must never bring back a state-changing command, in particular
    one the resolution framework withheld. Two independent checks, either of
    which rejects the whole response:
    1. Any markdown-style inline code span (`` `...` ``) that is not an
       approved command or its leading words - this catches the common AI
       phrasing "run `<command>`" whatever binary it names.
    2. Any command-shaped token (see _COMMAND_LIKE) anywhere in the text that
       is not inside a verbatim approved command: the phrase it starts must be
       an approved command or its leading words.
    """

    if not text or not text.strip():
        return None
    if len(text) > _MAX_EXPLANATION_CHARS:
        return None

    approved_commands = {a.command for a in diagnosis.actions if a.command and a.risk == RiskLevel.SAFE}

    for span_match in _CODE_SPAN.finditer(text):
        if not _looks_approved(span_match.group(1), approved_commands):
            return None

    covered = _approved_spans(text, approved_commands)
    for match in _COMMAND_LIKE.finditer(text):
        if any(a <= match.start() < b for a, b in covered):
            continue
        rest = text[match.start():]
        end = _PHRASE_END.search(rest)
        if not _looks_approved(rest[:end.start()] if end else rest, approved_commands):
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
    except Exception:  # noqa: BLE001 - a misbehaving provider adapter must never abort the diagnosis
        return None
    return sanitize_explanation(response.text, diagnosis)
