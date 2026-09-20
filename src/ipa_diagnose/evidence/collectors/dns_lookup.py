"""Read-only DNS resolution probes for the DNS diagnostic pack.

ipa-healthcheck's only DNS check (``ipahealthcheck.ipa.idns``,
``IPADNSSystemRecordsCheck``) resolves against a single resolver (the first
entry in ``/etc/resolv.conf`` on the host it runs on) and only checks the
handful of "system records" ``ipa dns-update-system-records --dry-run`` would
also check. This collector fills part of that gap by independently resolving,
via ``dig``, the records most commonly implicated in IPA client discovery
failures:

  - ``_kerberos._udp.<realm>`` and ``_kerberos._tcp.<realm>`` SRV records
    (KDC discovery)
  - ``_ldap._tcp.<domain>`` SRV records (LDAP server discovery)
  - A/AAAA records for ``ipa-ca.<domain>`` (CA chain retrieval) and for the
    host's own FQDN

LIMITATION (documented, not fixed by this collector): like
IPADNSSystemRecordsCheck, this collector only queries resolvers reachable
from *this* host. In a multi-server IPA DNS topology a clean result here
does NOT prove every DNS server in the fleet serves correct records - see
freeipa.org's own DNS troubleshooting page. Callers (dns.py rules) must
surface this same limitation to the administrator, not just rely on this
docstring.

This collector is strictly read-only: it only ever shells out to ``dig``.

Fixture format (tests/fixtures/dns/<scenario>/dns_lookup.json): a JSON array
of objects shaped like::

    {
      "item_id": "dns_lookup.srv_kerberos_udp",
      "kind": "dns_srv_record",            # or "dns_address_record" for A/AAAA
      "summary": "human-readable one-liner",
      "data": {
        "query": "_kerberos._udp.example.test",
        "qtype": "SRV",
        "resolver": "127.0.0.1",
        "rcode": "NOERROR",                # or "NXDOMAIN", "SERVFAIL", "TIMEOUT", ...
        "answers": ["0 100 88 ipa01.example.test."]   # empty list if none
      },
      "severity": "SUCCESS"                # SUCCESS | WARNING | ERROR | CRITICAL | null
    }
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

_SEVERITY_ALIASES = {s.value: s for s in Severity}

_IPA_DEFAULT_CONF = pathlib.Path("/etc/ipa/default.conf")

# (label, name-template, qtype, kind)
_QUERY_PLAN: List[Tuple[str, str, str, str]] = [
    ("srv_kerberos_udp", "_kerberos._udp.{realm_dns}", "SRV", "dns_srv_record"),
    ("srv_kerberos_tcp", "_kerberos._tcp.{realm_dns}", "SRV", "dns_srv_record"),
    ("srv_ldap_tcp", "_ldap._tcp.{domain}", "SRV", "dns_srv_record"),
    ("a_ipa_ca", "ipa-ca.{domain}", "A", "dns_address_record"),
    ("aaaa_ipa_ca", "ipa-ca.{domain}", "AAAA", "dns_address_record"),
    ("a_fqdn", "{fqdn}", "A", "dns_address_record"),
    ("aaaa_fqdn", "{fqdn}", "AAAA", "dns_address_record"),
]


def _parse_severity(raw: Any) -> Optional[Severity]:
    if isinstance(raw, str) and raw.upper() in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[raw.upper()]
    return None


def _discover_domain_realm_fqdn() -> Tuple[str, str, str]:
    """Best-effort, read-only discovery of the IPA domain/realm/FQDN.

    Prefers /etc/ipa/default.conf (present on any enrolled/server host) and
    falls back to deriving domain/realm from the host's own FQDN - the
    standard FreeIPA convention (realm == domain.upper()) when installed
    with defaults. This is a heuristic, not a guarantee, for hosts where the
    realm was customized; it only affects which names we probe, not any
    diagnostic conclusion (rules cite the actual query string used).
    """

    domain = ""
    realm = ""
    if _IPA_DEFAULT_CONF.exists():
        try:
            text = _IPA_DEFAULT_CONF.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^\s*domain\s*=\s*(\S+)", text, re.MULTILINE)
            if m:
                domain = m.group(1).strip().lower()
            m = re.search(r"^\s*realm\s*=\s*(\S+)", text, re.MULTILINE)
            if m:
                realm = m.group(1).strip()
        except OSError:
            pass

    fqdn = socket.getfqdn()
    if not domain:
        parts = fqdn.split(".", 1)
        domain = parts[1].lower() if len(parts) == 2 else fqdn.lower()
    if not realm:
        realm = domain.upper()
    return domain, realm, fqdn


def _run_dig(qname: str, qtype: str, timeout: float) -> Dict[str, Any]:
    cmd = ["dig", "+time=2", "+tries=1", qtype, qname]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"rcode": "TIMEOUT", "answers": [], "resolver": None, "raw": "", "command": " ".join(cmd)}
    except (OSError, subprocess.SubprocessError) as e:
        raise CollectorError(f"failed to run dig: {e}") from e

    text = proc.stdout
    rcode_match = re.search(r"status:\s*([A-Z]+)", text)
    rcode = rcode_match.group(1) if rcode_match else ("NOERROR" if proc.returncode == 0 else "UNKNOWN")
    resolver_match = re.search(r"SERVER:\s*([^\s#]+)", text)
    resolver = resolver_match.group(1) if resolver_match else None

    answers: List[str] = []
    in_answer = False
    for line in text.splitlines():
        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        if in_answer:
            if not line.strip() or line.startswith(";;"):
                break
            fields = line.split(None, 4)
            if len(fields) >= 5:
                answers.append(fields[4])
    return {"rcode": rcode, "answers": answers, "resolver": resolver, "raw": text, "command": " ".join(cmd)}


class DNSLookupCollector(Collector):
    name = "dns_lookup"
    timeout_seconds = 5.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("dig") is None:
            raise CollectorError("dig is not installed or not on PATH")

        domain, realm, fqdn = _discover_domain_realm_fqdn()
        realm_dns = realm.lower()

        items: List[EvidenceItem] = []
        for label, name_template, qtype, kind in _QUERY_PLAN:
            qname = name_template.format(domain=domain, realm_dns=realm_dns, fqdn=fqdn)
            result = _run_dig(qname, qtype, self.timeout_seconds)
            answered = bool(result["answers"]) and result["rcode"] == "NOERROR"
            severity = Severity.SUCCESS if answered else Severity.ERROR
            if qtype == "AAAA" and result["rcode"] == "NOERROR" and not result["answers"]:
                # An IPv4-only deployment legitimately has no AAAA record (and the
                # matching freeipa-healthcheck #270 warning is known to be spurious).
                severity = Severity.SUCCESS
            summary = (
                f"{qname} {qtype}: {result['rcode']}, {len(result['answers'])} record(s)"
                if result["rcode"] != "TIMEOUT"
                else f"{qname} {qtype}: query timed out (no response from resolver)"
            )
            items.append(
                EvidenceItem(
                    item_id=f"dns_lookup.{label}",
                    kind=kind,
                    summary=summary,
                    data={
                        "query": qname,
                        "qtype": qtype,
                        "resolver": result["resolver"],
                        "rcode": result["rcode"],
                        "answers": result["answers"],
                    },
                    severity=severity,
                    provenance=Provenance(
                        source="dns_lookup", command=result["command"], live=True
                    ),
                )
            )
        return items

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "dns_lookup.json"
        if not fixture_file.exists():
            raise CollectorError(
                f"no dns_lookup fixture at {fixture_file} "
                "(simulating the collector being unable to run, e.g. permission denied)",
                permission_related=True,
            )
        try:
            raw = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(raw, list):
            raise CollectorError(f"fixture {fixture_file} is not a JSON array")

        items: List[EvidenceItem] = []
        for idx, entry in enumerate(raw):
            if not isinstance(entry, dict):
                continue
            items.append(
                EvidenceItem(
                    item_id=str(entry.get("item_id") or f"dns_lookup.{idx}"),
                    kind=str(entry.get("kind", "dns_srv_record")),
                    summary=str(entry.get("summary", "")),
                    data=dict(entry.get("data") or {}),
                    severity=_parse_severity(entry.get("severity")),
                    provenance=Provenance(
                        source="dns_lookup", command=f"--replay {fixture_file}", live=False
                    ),
                )
            )
        return items


register(DNSLookupCollector())
