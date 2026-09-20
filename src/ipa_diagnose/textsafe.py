"""Sanitising of UNTRUSTED text (subprocess stderr, ipa-healthcheck messages,
fixture content) before it is stored in a diagnosis, printed to a terminal or
serialised: strips terminal escape sequences and control/format characters
(incl. bidi overrides), collapses whitespace and bounds the length."""

from __future__ import annotations

import re

DEFAULT_LIMIT = 300
_PRE_BOUND = 4096  # bound the work before any regex runs


def sanitize_text(text: object, limit: int = DEFAULT_LIMIT) -> str:
    text = str(text)[:_PRE_BOUND]
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)  # CSI sequences
    text = re.sub(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)?", "", text)  # OSC sequences
    text = re.sub(r"\x1b[P^_X][^\x1b]*(\x1b\\)?", "", text)  # DCS/PM/APC/SOS strings
    text = re.sub(r"\x1b[@-Z\\-_]", "", text)  # other 2-char ESC sequences
    text = "".join(ch if (ch == " " or ch.isprintable()) else " " for ch in text)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    room = limit - 3  # the ellipsis counts toward the bound
    cut = text[:room]
    space = cut.rfind(" ")
    if space >= room - 40:  # prefer a word boundary when one is close
        cut = cut[:space]
    return cut.rstrip(" ,;:-") + "..."


def clean_multiline(text: object, limit: int = 20000) -> str:
    """Like sanitize_text but keeps line structure (newlines/tabs): strips
    terminal escape sequences, control and format characters (incl. bidi
    overrides). Used when printing multi-paragraph diagnosis text that may
    quote untrusted ipa-healthcheck messages."""

    text = str(text)[:limit]
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)?", "", text)
    text = re.sub(r"\x1b[P^_X][^\x1b]*(\x1b\\)?", "", text)
    text = re.sub(r"\x1b[@-Z\\-_]", "", text)
    return "".join(ch if (ch in "\n\t" or ch.isprintable()) else " " for ch in text)


_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.,=-]{0,80}$")


def safe_token(value: object, placeholder: str) -> str:
    """A value taken from untrusted ipa-healthcheck output that is placed into a
    suggested (display-only) command: only a plain identifier is ever used;
    anything else becomes the placeholder."""

    text = str(value).strip()
    return text if _SAFE_TOKEN.match(text) else placeholder
