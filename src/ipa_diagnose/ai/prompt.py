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
from ipa_diagnose.engine.model import Diagnosis
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
    r"bak2db|ldif2db|db2ldif|db2bak|dscreate|dsctl|pkispawn|pkidestroy|rndc|named-checkconf|"
    r"init\s+[0-6]|telinit|realm\s+(?:leave|join|deny|permit)|fixfiles|podman|docker|nft|kexec|mount|umount|"
    r"swapoff|sysctl\s+-w|hostnamectl|update-crypto-policies|authconfig)\b",
    # case-sensitive on purpose: commands are typed in lower case, while prose says "IPA", "PKI", "Service"
)
_WORD_BREAK = re.compile(r"\w\\\w|(?<![\w:])//")  # "sys\temctl" (the shell drops the backslash), "//usr/bin/..."
# An instruction to run something, whatever it is called: "run realm leave", "execute the command foo bar".
_IMPERATIVE = re.compile(r"(?i)\b(?:run|execute|invoke|type|issue|enter)\s+(?:the\s+)?(?:command\s+)?[a-z][\w.-]*\s+[a-z0-9-]")
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


def sanitize_explanation(text: str, diagnosis: Diagnosis) -> Optional[str]:
    """Returns the explanation if it is prose only, else None (the caller falls back to the deterministic
    `why` text). An explanation may not contain any command at all - not even the diagnosis's own read-only
    ones: no backticks or code blocks, no known program name, no word followed by an option or an absolute
    path, no redirect, pipe, `$(`, `&&`, backslash-split word or `//` path. The text checked is exactly the
    text displayed. This is a filter, not a proof: never run a command that appears only in AI text.
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

    # No command text at all (round-8 review): allowing even the diagnosis's own read-only commands let an
    # explanation append options to one ("... --output-file /etc/krb5.conf") or drop its safety flag ("ipa
    # dns-update-system-records" without --dry-run). Commands are only ever shown by ipa-diagnose itself.
    if "`" in text or _WORD_BREAK.search(text) or _REDIRECT.search(text):
        return None
    for m in _SHAPE.finditer(text):
        if m.group(1).lower() not in _PROSE_WORDS:
            return None
    if _COMMAND_LIKE.search(text) or _IMPERATIVE.search(text):
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
