"""Fail-closed leak self-test, run over every finished member before anything is written.

A bundle is refused (nothing written) when any member contains:
  - a real identifier that was pseudonymized (host, domain, realm, suffix, instance, IP, user, group, ...),
  - text matching a credential pattern (sanitize.PATTERNS; checksum fields are exempt from the entropy rule only),
  - a control, escape or format character (text members may keep newlines and tabs),
  - a forbidden literal (the local replay path, the home directory),
  - malformed content (invalid UTF-8 or JSON, a malformed SHA256SUMS line).

Problems are reported by member and category only - never with the matched text.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Dict, Iterable, List, Sequence, Tuple

from ipa_diagnose.bundle.sanitize import find_secrets, invisible, iter_originals, secret_key, secret_value_re

# members that carry evidence (the manifest and redaction report are generated and name categories, not values)
EVIDENCE_MEMBERS = ("environment.json", "report.json", "healthcheck.json", "evidence.json", "collection-errors.json",
                    "topology.json", "verification.json")


def unremoved_secret_fields(value) -> int:
    """How many secret-named fields hold anything but [REMOVED], null or a boolean."""

    n = 0
    if isinstance(value, dict):
        for k, v in value.items():
            if secret_key(str(k), normalize=True) and not (v == "[REMOVED]" or v is None or isinstance(v, bool)):
                n += 1
            else:
                n += unremoved_secret_fields(v)
    elif isinstance(value, list):
        n += sum(unremoved_secret_fields(v) for v in value)
    return n


_SUMS_LINE = re.compile(r"[0-9a-f]{64}  [A-Za-z0-9._-]{1,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class LeakDetected(Exception):
    def __init__(self, problems: Sequence[Tuple[str, str]]):
        self.problems = sorted(set(problems))
        super().__init__("; ".join(f"{m}: {c}" for m, c in self.problems))


def _strings(value, key: str = ""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield "", str(k)
            yield from _strings(v, str(k))
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v, key)
    elif isinstance(value, str):
        yield key, value


def _bad_char(text: str, multiline: bool) -> bool:
    for ch in text:
        if multiline and ch in "\n\t":
            continue
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp") or ch == "\x1b" or (
                ord(ch) > 0x7F and invisible(ch)):
            return True
    return False


def scan_text(text: str, key: str = "", multiline: bool = False) -> List[str]:
    """Credential-pattern and control-character categories found in one string (used by validate too)."""

    out = []
    if _bad_char(text, multiline):
        out.append("control or format character")
    for name, _a, _b in find_secrets(text):
        if name == "high_entropy_token" and key == "sha256" and _HEX64.fullmatch(text):
            continue  # a checksum field, not a secret
        out.append(f"credential pattern ({name})")
    return out


def check(members: Dict[str, bytes], originals: Iterable[Tuple[str, str]], forbidden: Sequence[str] = (),
          secrets: Iterable[str] = ()) -> None:
    detectors = list(iter_originals(originals))
    literals = [f.lower() for f in forbidden if f and len(f) >= 4]
    secret_list = [(v, secret_value_re(v)) for v in sorted(set(secrets))]
    problems: List[Tuple[str, str]] = []

    active = detectors

    def scan(member: str, key: str, text: str, multiline: bool = False) -> None:
        for cat in scan_text(text, key, multiline):
            problems.append((member, cat))
        low = text.lower()
        for cls, rx, probe in active:
            if probe in low and rx.search(text):
                problems.append((member, f"real identifier ({cls})"))
        if any(lit in low for lit in literals):
            problems.append((member, "local path"))

    for name, data in members.items():
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append((name, "not valid UTF-8"))
            continue
        member_low = text.lower()
        # only identifiers whose probe occurs somewhere in this member can match in one of its strings
        # (JSON escapes are backslashes and quotes; probes never contain them - a SUFFIX probe is one label)
        active = [d for d in detectors if d[2] in member_low]
        if name == "SHA256SUMS":
            lines = text.split("\n")
            if lines[-1] != "" or not all(_SUMS_LINE.fullmatch(ln) for ln in lines[:-1]):
                problems.append((name, "malformed checksum line"))
            continue
        if name.endswith(".json"):
            try:
                obj = json.loads(text)
            except (ValueError, RecursionError):
                problems.append((name, "not valid JSON"))
                continue
            for key, s in _strings(obj):
                scan(name, key, s)
            if name in EVIDENCE_MEMBERS and unremoved_secret_fields(obj):
                problems.append((name, "secret-named field not removed"))
            if name in EVIDENCE_MEMBERS and secret_list and any(
                    rx.search(s) for _k, s in _strings(obj) for v, rx in secret_list if v in s):
                problems.append((name, "value of a secret-named field"))
        else:
            scan(name, "", text, multiline=True)
    if problems:
        raise LeakDetected(problems)
