"""Certmonger tracking-request collector.

Wraps ``getcert list`` (read-only - never ``getcert start-tracking``/``resubmit``/
``stop-tracking``) and normalizes each tracking request block into one
EvidenceItem of kind ``"certmonger_request"``.

``getcert list`` prints one un-indented ``Request ID '<id>':`` header per
tracking request, followed by indented ``key: value`` lines, e.g.::

    Number of certificates and requests being tracked: 2.
    Request ID '20260101120000':
        status: MONITORING
        stuck: no
        key pair storage: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='Server-Cert',token='NSS Certificate DB'
        certificate: type=NSSDB,location='/etc/pki/pki-tomcat/alias',nickname='Server-Cert',token='NSS Certificate DB'
        CA: IPA
        issuer: CN=Certificate Authority,O=EXAMPLE.TEST
        subject: CN=ipa01.example.test,O=EXAMPLE.TEST
        expires: 2026-12-01 00:00:00 UTC
        eku: id-kp-serverAuth,id-kp-clientAuth
        pre-save command:
        post-save command: /usr/libexec/ipa/certmonger/restart_httpd
        track: yes
        auto-renew: yes

and, for a request stuck talking to the CA, an additional line such as::

        ca-error: Server at https://ipa01.example.test/ca/agent/ca/profileSubmitSSLClient failed request, giving up: Unable to communicate with CMS.

EvidenceItem.data for each request is a dict with these normalized keys
(all optional except ``request_id`` and ``state``, since real output is not
guaranteed to include every field, and a request may not need a
``serial``/``ca_error``):

    {
      "request_id": str,
      "nickname": str | None,
      "ca": str | None,
      "state": str,              # e.g. "MONITORING", "CA_UNREACHABLE", ...
      "stuck": str | None,       # "yes"/"no" as reported by getcert
      "ca_error": str | None,    # verbatim ca-error text, or "" / None if absent
      "serial": str | None,
      "subject": str | None,
      "issuer": str | None,
      "not_valid_after": str | None,  # verbatim "expires" text, best-effort parse
    }

Fixture format (``<fixture_dir>/certmonger.json``): a JSON array where each
element is a dict using the same keys as above (any subset; missing keys are
treated as absent/None). This lets tests express tracking requests directly
without re-deriving the ``getcert list`` text format.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

GETCERT_LIST_COMMAND = ["getcert", "list"]

FAILURE_STATES = {"CA_REJECTED", "CA_UNREACHABLE", "CA_UNCONFIGURED", "NEED_GUIDANCE"}
HAPPY_STATE = "MONITORING"

_REQUEST_HEADER_RE = re.compile(r"^Request ID '(?P<request_id>.+)':\s*$")
_FIELD_RE = re.compile(r"^\s+([A-Za-z][A-Za-z0-9 _-]*):\s?(.*)$")
_NICKNAME_RE = re.compile(r"nickname='([^']*)'")


def _parse_getcert_list(text: str) -> List[Dict[str, Any]]:
    """Parses ``getcert list`` stdout into a list of normalized request dicts."""

    requests: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for raw_line in text.splitlines():
        header = _REQUEST_HEADER_RE.match(raw_line)
        if header:
            if current is not None:
                requests.append(current)
            current = {"request_id": header.group("request_id")}
            continue
        if current is None:
            continue
        field = _FIELD_RE.match(raw_line)
        if not field:
            continue
        key = field.group(1).strip().lower()
        value = field.group(2).strip()
        if key == "status":
            current["state"] = value
        elif key == "ca-error":
            current["ca_error"] = value
        elif key == "expires":
            current["not_valid_after"] = value
        elif key == "ca":
            current["ca"] = value
        elif key == "stuck":
            current["stuck"] = value
        elif key == "serial number":
            current["serial"] = value
        elif key == "subject":
            current["subject"] = value
        elif key == "issuer":
            current["issuer"] = value
        elif key == "post-save command":
            current["post_save"] = value
        elif key in ("certificate", "key pair storage") and "nickname" not in current:
            nick = _NICKNAME_RE.search(value)
            if nick:
                current["nickname"] = nick.group(1)
    if current is not None:
        requests.append(current)
    return requests


def _severity_for_state(state: str) -> Optional[Severity]:
    upper = (state or "").upper()
    if upper in FAILURE_STATES:
        return Severity.ERROR
    if upper == HAPPY_STATE:
        return Severity.SUCCESS
    if upper:
        # Transitional states (NEWLY_ADDED, GENERATING_KEY_PAIR, GENERATING_CSR,
        # SUBMITTING, CA_WORKING, SAVING_CERT) or an unrecognized future state -
        # not evidence of a problem by itself, but worth a mild flag if seen in
        # a point-in-time snapshot (a real run should catch these mid-flight
        # only rarely).
        return Severity.WARNING
    return None


class CertmongerCollector(Collector):
    name = "certmonger"
    timeout_seconds = 15.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("getcert") is None:
            raise CollectorError("getcert is not installed or not on PATH")
        try:
            proc = subprocess.run(
                GETCERT_LIST_COMMAND,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(f"failed to run 'getcert list': {e}") from e
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            permission_related = "permission" in stderr.lower() or "must be run as root" in stderr.lower()
            raise CollectorError(
                f"'getcert list' exited {proc.returncode}: {stderr[:300]}",
                permission_related=permission_related,
            )
        parsed = _parse_getcert_list(proc.stdout)
        command = " ".join(GETCERT_LIST_COMMAND)
        return [self._to_item(entry, provenance=Provenance(source="certmonger", command=command, live=True)) for entry in parsed]

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "certmonger.json"
        if not fixture_file.exists():
            return []
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(data, list):
            raise CollectorError(f"fixture {fixture_file} must be a JSON array of tracking-request objects")
        provenance = Provenance(source="certmonger", command=f"--replay {fixture_file}", live=False)
        return [self._to_item(entry, provenance=provenance) for entry in data if isinstance(entry, dict)]

    @staticmethod
    def _to_item(entry: Dict[str, Any], *, provenance: Provenance) -> EvidenceItem:
        request_id = str(entry.get("request_id") or "unknown")
        state = str(entry.get("state") or "")
        nickname = entry.get("nickname")
        data = {
            "request_id": request_id,
            "nickname": nickname,
            "ca": entry.get("ca"),
            "state": state,
            "stuck": entry.get("stuck"),
            "ca_error": entry.get("ca_error"),
            "serial": entry.get("serial"),
            "subject": entry.get("subject"),
            "issuer": entry.get("issuer"),
            "not_valid_after": entry.get("not_valid_after"),
        }
        summary = f"certmonger request {request_id} (nickname={nickname or '?'}) state={state or 'UNKNOWN'}"
        if entry.get("not_valid_after"):
            summary += f", expires {entry['not_valid_after']}"
        return EvidenceItem(
            item_id=f"certmonger.{request_id}",
            kind="certmonger_request",
            summary=summary,
            data=data,
            severity=_severity_for_state(state),
            provenance=provenance,
        )


register(CertmongerCollector())
