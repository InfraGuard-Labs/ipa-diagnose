"""A small, bounded LDIF reader for the output of ``ldapsearch -LLL`` (untrusted text).

Only what the replication checks need: entries as ``{"dn": str, attr_lower: [values]}``. Folded lines are joined,
base64 values (``attr:: ...``) decoded as UTF-8 with replacement, everything is bounded (entries, values per
attribute, value length). Anything that does not look like LDIF is skipped, never guessed.
"""

from __future__ import annotations

import base64
import binascii
from typing import Dict, List

MAX_ENTRIES = 500
MAX_VALUES = 64
MAX_VALUE_LEN = 4096


def unfold(text: str) -> List[str]:
    lines: List[str] = []
    for raw in (text or "").splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def parse(text: str) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    cur: Dict[str, object] = {}
    for line in unfold(text):
        if not line.strip():
            if cur:
                entries.append(cur)
                cur = {}
            if len(entries) >= MAX_ENTRIES:
                break
            continue
        if line.startswith("#"):
            continue
        attr, sep, rest = line.partition(":")
        if not sep or not attr or " " in attr:
            continue
        if rest.startswith(":"):
            try:
                value = base64.b64decode(rest[1:].strip(), validate=False).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                continue
        else:
            value = rest[1:] if rest.startswith(" ") else rest
        value = value[:MAX_VALUE_LEN]
        key = attr.lower()
        if key == "dn":
            if cur:
                entries.append(cur)
            cur = {"dn": value}
            continue
        if not cur:
            continue
        vals = cur.setdefault(key, [])
        if isinstance(vals, list) and len(vals) < MAX_VALUES:
            vals.append(value)
    if cur and len(entries) < MAX_ENTRIES:
        entries.append(cur)
    return entries[:MAX_ENTRIES]


def first(entry: Dict[str, object], attr: str, default: str = "") -> str:
    v = entry.get(attr.lower())
    if isinstance(v, list) and v:
        return str(v[0])
    return default


def values(entry: Dict[str, object], attr: str) -> List[str]:
    v = entry.get(attr.lower())
    return [str(x) for x in v] if isinstance(v, list) else []
