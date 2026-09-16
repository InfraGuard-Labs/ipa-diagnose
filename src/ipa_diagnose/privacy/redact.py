"""Secret detection and redaction.

Runs on EVERY piece of text/data before it can reach an AI provider, and
underlies `ipa-diagnose ai-preview` (which renders exactly what redact.py
produced - preview and the real call must never diverge, so both call this
same module, never a second copy of the logic).

Two independent redaction strategies, both applied:
  1. Field-name based (`_SENSITIVE_KEY_MARKERS`): dict keys that mean
     "this value is a secret" regardless of what the value looks like
     (e.g. a `kw` dict key literally named "password"). This catches secrets
     that don't match any known pattern.
  2. Pattern based (`_PATTERNS`): free-text scanning for the shapes real
     secrets take (API keys, private key blocks, keytab-looking base64,
     bearer tokens, generic long high-entropy tokens). This catches secrets
     embedded in log lines / messages where the field itself is just "msg".

Neither is complete on its own - field names lie and patterns miss novel
formats - so both always run.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Dict, List, Tuple

_SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "bearer",
    "private_key",
    "privatekey",
    "keytab",
    "credential",
    "bindpw",
    "bind_pw",
    "access_key",
    "secret_key",
    "session",
    "cookie",
    "authorization",
)

_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
    ("github_token", re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-_.=]{10,}\b")),
    ("basic_auth_url", re.compile(r"(?i)\b\w+://[^\s:@/]+:[^\s:@/]+@")),
    ("krb5_keytab_hex", re.compile(r"(?i)\bkeytab\S*[:=]\s*[0-9a-f]{32,}\b")),
    # Generic catch-all: a long run of base64/hex-looking characters is often
    # a key/token/hash even when no named pattern above matched it.
    ("high_entropy_token", re.compile(r"\b[A-Za-z0-9+/_\-]{40,}={0,2}\b")),
]


@dataclasses.dataclass
class RedactionReport:
    redacted_text: str
    matches: List[str] = dataclasses.field(default_factory=list)
    """Pattern/marker names that fired, e.g. ["aws_access_key", "field:password"]."""

    @property
    def anything_redacted(self) -> bool:
        return bool(self.matches)


def redact_text(text: str) -> RedactionReport:
    matches: List[str] = []
    result = text
    for name, pattern in _PATTERNS:
        def _sub(m: "re.Match", _name=name) -> str:
            matches.append(_name)
            return f"[REDACTED:{_name}]"

        result = pattern.sub(_sub, result)
    return RedactionReport(redacted_text=result, matches=matches)


def _is_sensitive_key(key: str) -> bool:
    key_l = key.lower()
    return any(marker in key_l for marker in _SENSITIVE_KEY_MARKERS)


def redact_mapping(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Recursively redacts a dict (e.g. a Finding's `kw`/`raw`). Returns the
    redacted copy plus the list of match names found, for the audit trail."""

    matches: List[str] = []

    def _walk(value: Any) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if isinstance(v, str) and _is_sensitive_key(k):
                    matches.append(f"field:{k}")
                    out[k] = "[REDACTED]"
                else:
                    out[k] = _walk(v)
            return out
        if isinstance(value, list):
            return [_walk(v) for v in value]
        if isinstance(value, str):
            report = redact_text(value)
            matches.extend(report.matches)
            return report.redacted_text
        return value

    return _walk(data), matches
