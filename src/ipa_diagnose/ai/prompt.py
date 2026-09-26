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
import unicodedata
from typing import Optional

from ipa_diagnose.ai.provider import AIProvider, AIRequest, ProviderError
from ipa_diagnose.engine.model import Diagnosis, RiskLevel
from ipa_diagnose.evidence.model import EvidenceBundle
from ipa_diagnose.privacy.minimize import build_ai_payload
from ipa_diagnose.textsafe import clean_multiline

# Deliberately NOT anchored to line-start (an earlier version was - a
# security review found that let prose-embedded suggestions like "you could
# try: getcert resubmit ..." slip through undetected) and deliberately a
# broad binary/keyword list rather than an exhaustive one, since the goal is
# "reject anything command-shaped we don't recognize as approved," not
# "recognize every dangerous command by name."
_COMMAND_LIKE = re.compile(
    # Zero-width lookbehind for the boundary (anything but a word, path or dot
    # character: quotes, brackets, '**', '|', '&&' all count) rather than a
    # consuming group, and any path prefix (/bin/, /usr/sbin/, ...).
    r"(?<![\w./-])(?:\$\s*)?(?:sudo\s+)?(?:/(?:usr/)?(?:local/)?s?bin/)?"
    r"(ipa[\w-]*|getcert|kinit|klist|kvno|dsconf|dsctl|ldapmodify|ldapsearch|ldapadd|ldapdelete|"
    r"systemctl|service\s+[\w@.-]+\s+(?:start|stop|restart|reload|status|condrestart)|reboot|shutdown|halt|poweroff|init\s+0|"
    r"rm\b|mkfs[\w.]*|dd\b|userdel|groupdel|usermod|passwd|iptables|firewall-cmd|"
    r"dnf|yum|rpm\b|certutil|pk12util|openssl|pki\b|db2index[\w.]*|chmod|chown|chgrp|p?kill(?:all)?|"
    r"curl|wget|python[\w.]*|perl|bash|sh\b|nc\b|ncat|ssh|scp|crontab|tee\b|sed\s+-i|truncate|shred|"
    r"chronyc|chronyd(?=\s+-)|ntpdate|ntpd(?=\s+-)|hwclock|timedatectl|date\s+(?:-\w+\s+)*(?:-s|--set)|setenforce|semanage|"
    r"setfacl|restorecon|journalctl|sss_cache|sssctl|ldappasswd|ldapmodrdn|ldapdelete|"
    r"kadmin[\w.]*|kdb5_util|ktutil|kdestroy|mv\b|cp\b|ln\b|unlink|useradd|groupadd|nmcli|authselect|setsebool|"
    r"bak2db|ldif2db|db2ldif|db2bak|dscreate|dsctl|pkispawn|pkidestroy|rndc|named-checkconf)\b",
    # case-sensitive on purpose: commands are typed in lower case, while prose says "IPA", "PKI", "Service"
)
_CODE_SPAN = re.compile(r"`([^`\n]{1,200})`")
_FENCED = re.compile(r"```[^\n]*\n?(.*?)```", re.DOTALL)
_INVISIBLE = re.compile("[­​-‏⁠-⁤﻿]")
_SHAPE = re.compile(r"(?<![\w./-])([A-Za-z][A-Za-z0-9_.+-]{0,40})\s+(?:--?[A-Za-z]|/[\w.-])")
_REDIRECT = re.compile(r"(?<![-=<])>{1,2}\s*[/~$]|\|\s*[A-Za-z]|\$\(|&&|;\s*[a-z]+\s+-")
_PROSE_WORDS = frozenset(
    "a an the in at on under from to of into inside within for with and or is are was were be as by via see "
    "file files directory directories dir path paths folder named called its their your this that these those "
    "not only both also like such than then when while if because between over below above near "
    "config configuration database log logs keytab keytabs certificate certificates socket link symlink "
    "mode owner group permissions exists missing location copy entry key keys store stored lives points "
    "reads writes uses check see inspect review read open look examine compare confirm".split()
)
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
    # Filter exactly what will be displayed: terminal escapes removed (they could split a command so the filter
    # misses it while the terminal shows it joined - round-7 review), compatibility forms folded (NFKC: full-width
    # letters), invisible characters dropped, and look-alike letters from other scripts refused outright.
    text = unicodedata.normalize("NFKC", clean_multiline(_INVISIBLE.sub("", text)))
    if any(ch.isalpha() and not ch.isascii() for ch in text):
        return None

    approved_commands = {a.command for a in diagnosis.actions if a.command and a.risk == RiskLevel.SAFE}

    for block in _FENCED.finditer(text):
        for line in block.group(1).splitlines():
            if line.strip() and not _looks_approved(line, approved_commands):
                return None
    text_wo_fences = _FENCED.sub(" ", text)
    for span_match in _CODE_SPAN.finditer(text_wo_fences):
        if not _looks_approved(span_match.group(1), approved_commands):
            return None

    # Backticks do not end a command phrase: "`chronyc` makestep" is the command "chronyc makestep".
    flat = text.replace("`", " ")
    covered = _approved_spans(flat, approved_commands)

    # Generic command shapes, whatever the program is called (a name list alone cannot be complete - round-6
    # review: bak2db, ldif2db, setsebool, kdestroy -A, ...): a word followed by an option or an absolute path,
    # a redirect to a path, or a pipe into a word. Ordinary prose ("the file /etc/krb5.conf") is exempt.
    for m in _SHAPE.finditer(flat):
        if m.group(1).lower() in _PROSE_WORDS or any(a <= m.start() < b for a, b in covered):
            continue
        return None
    if _REDIRECT.search(flat):
        return None
    for match in _COMMAND_LIKE.finditer(flat):
        if any(a <= match.start() < b for a, b in covered):
            continue
        rest = flat[match.start():]
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
