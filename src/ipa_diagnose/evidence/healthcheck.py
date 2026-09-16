"""Normalizes ipa-healthcheck's JSON output into Finding objects.

ipa-healthcheck JSON is a flat array of objects shaped like:

    {
      "source": "ipahealthcheck.ds.replication",
      "check": "ReplicationCheck",
      "result": "SUCCESS" | "WARNING" | "ERROR" | "CRITICAL",
      "uuid": "...",
      "when": "20260101120000Z",
      "duration": "0.012345",
      "kw": {"key": "...", "msg": "...", ...}
    }

An unrecognized `result` value (a future ipa-healthcheck severity we don't
know about yet) is treated as WARNING rather than raising - "unknown is
better than wrong" applies to parsing failures too, not just diagnoses.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from ipa_diagnose.evidence.model import EvidenceBundle, Finding, Provenance, Severity

_SEVERITY_ALIASES = {s.value: s for s in Severity}


def _parse_severity(raw: Any) -> Severity:
    if isinstance(raw, str) and raw.upper() in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[raw.upper()]
    return Severity.WARNING


_TRACEBACK_LAST_LINE_RE = re.compile(r"([^\n]+)\s*$")


def _extract_message(kw: Dict[str, Any]) -> str:
    """`kw.msg` is the normal case, but real ipa-healthcheck output also
    emits CRITICAL results with NO `msg` key at all when a check plugin
    itself raises an uncaught exception - only `kw.exception`/`kw.traceback`
    are present. Confirmed against a real FreeIPA server capture (a
    CRITICAL `IPAauthzdatapacCheck` result with an `AttributeError: ldap2 is
    not connected` traceback and no `msg` key) - without this fallback, that
    finding's message silently became an empty string, discarding the only
    diagnostic content a CRITICAL result had."""

    if kw.get("msg"):
        return str(kw["msg"])
    if kw.get("exception"):
        return str(kw["exception"])
    traceback_text = kw.get("traceback")
    if traceback_text:
        m = _TRACEBACK_LAST_LINE_RE.search(str(traceback_text).rstrip())
        if m:
            return m.group(1).strip()
    return ""


def parse_healthcheck_results(
    raw_results: List[Dict[str, Any]],
    *,
    command: str,
    live: bool,
    host: str = "",
) -> List[Finding]:
    findings: List[Finding] = []
    for idx, entry in enumerate(raw_results):
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("source", "unknown"))
        check = str(entry.get("check", "unknown"))
        severity = _parse_severity(entry.get("result"))
        kw = entry.get("kw") or {}
        message = _extract_message(kw) if isinstance(kw, dict) else ""
        finding_id = str(entry.get("uuid") or f"{source}.{check}.{idx}")
        findings.append(
            Finding(
                finding_id=finding_id,
                source=source,
                check=check,
                severity=severity,
                message=message,
                keywords=kw if isinstance(kw, dict) else {},
                provenance=Provenance(
                    source="ipa-healthcheck",
                    command=command,
                    host=host or None,
                    collected_at=str(entry.get("when", "")) or None,
                    live=live,
                ),
                raw=entry,
            )
        )
    return findings


def load_healthcheck_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "results" in data:
        data = data["results"]
    if not isinstance(data, list):
        raise ValueError(f"expected a JSON array of healthcheck results in {path}")
    return data


def parse_healthcheck_json_text(text: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    if isinstance(data, dict) and "results" in data:
        data = data["results"]
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of healthcheck results")
    return data


def merge_into_bundle(bundle: EvidenceBundle, findings: List[Finding]) -> None:
    bundle.findings.extend(findings)
