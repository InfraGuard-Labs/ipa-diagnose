"""DNS diagnostic pack.

ipa-healthcheck's DNS coverage is thin by design: the only check is
``ipahealthcheck.ipa.idns`` / ``IPADNSSystemRecordsCheck`` (equivalent to
``ipa dns-update-system-records --dry-run``), resolved against a single
resolver on a single host. There is no bind-dyndb-ldap health check, no
forwarder-reachability check, and no DNSSEC check anywhere in
ipa-healthcheck. This pack's two targeted collectors
(``evidence.collectors.dns_lookup``, ``evidence.collectors.journal_named``)
exist specifically to fill that gap with independent, read-only evidence.

Three rules, matching the three well-documented DNS root-cause clusters for
FreeIPA/IdM (see module-level rule docstrings for sourcing):

  A. NamedServiceDownRule    - named/bind-dyndb-ldap not running or crashed,
                               with a special case for the documented
                               missing-LDAP-ACI-after-restore failure mode.
  B. ForwardZoneConflictRule - a configured forward zone auto-unloaded
                               because it collides with a BIND automatic
                               empty zone (RFC1918 etc.) - looks identical to
                               "forwarders are just down" from the outside,
                               so this rule is deliberately conservative.
  C. SrvAutodiscoveryRule    - IPADNSSystemRecordsCheck flags a broken
                               SRV/A/AAAA record needed for Kerberos/LDAP
                               autodiscovery or CA chain retrieval, with the
                               two documented caveats (single-resolver blind
                               spot; WARNING-only false positives per
                               freeipa-healthcheck issue #270) explicitly
                               encoded rather than trusted blindly.

Per the documented causality chain (DNS -> Kerberos -> Replication ->
Certificates, Directory Server foundational under all), DNS sits at the top
of the chain: none of these rules normally have upstream_candidates, with
one specific, narrowly-scoped exception in NamedServiceDownRule where the
evidence points at a directory-server ACI regression as the true root cause.
"""

from __future__ import annotations

import re
from typing import List, Optional

from ipa_diagnose.engine.model import (
    Action,
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    EvidenceRef,
    RiskLevel,
    VerificationCondition,
)
from ipa_diagnose.engine.packs.base import DiagnosticPack, DiagnosticRule
from ipa_diagnose.evidence.model import EvidenceBundle, EvidenceItem, Finding, Severity

PACK_ID = "dns"

_IDNS_SOURCE = "ipahealthcheck.ipa.idns"
_IDNS_CHECK = "IPADNSSystemRecordsCheck"

_SINGLE_RESOLVER_LIMITATION = (
    "ipahealthcheck's IPADNSSystemRecordsCheck (and this pack's own dns_lookup "
    "collector) only resolve against resolver(s) reachable from this one host. "
    "In a multi-server IPA DNS topology, a clean result here does not confirm "
    "every IPA DNS server serves correct records - freeipa.org's DNS "
    "troubleshooting page documents this as a known blind spot. Spot-check "
    "`dig` against every known IPA DNS server before considering DNS fully "
    "verified."
)


def _ref_item(item: EvidenceItem, why: str) -> EvidenceRef:
    return EvidenceRef(evidence_id=item.item_id, kind="item", why_relevant=why)


def _ref_finding(f: Finding, why: str) -> EvidenceRef:
    return EvidenceRef(evidence_id=f.finding_id, kind="finding", why_relevant=why)


def _journal_lines(bundle: EvidenceBundle) -> List[EvidenceItem]:
    # "named_journal_line", not the generic "journal_line" some other packs'
    # journal collectors use - kept distinct so this never picks up another
    # pack's unrelated journal evidence (e.g. dirsrv's) from the shared bundle.
    return bundle.items_by_kind("named_journal_line")


def _dns_lookup_items(bundle: EvidenceBundle) -> List[EvidenceItem]:
    return [i for i in bundle.items if i.kind in ("dns_srv_record", "dns_address_record")]


# ---------------------------------------------------------------------------
# Rule A: named / bind-dyndb-ldap startup or sync failure
# ---------------------------------------------------------------------------
#
# Sourcing: [HIGH] freeipa.org/page/Troubleshooting/DNS and bind-dyndb-ldap's
# own "NamedCannotStart" troubleshooting doc both describe named failing to
# start, and specifically call out a missing LDAP ACI for the
# DNS/<fqdn>@REALM principal (typically after an LDIF restore or upgrade) as
# a documented, specific root cause that surfaces as an LDAP
# permission-denied error in the journal at startup. A generic crash/failed
# start without that specific signature is still diagnosable ("named is not
# running") but must NOT be attributed to the ACI cause without the matching
# evidence.

_ACI_ERROR_KEYWORDS = ("insufficient access", "permission denied", "no permission", "err=50")
_ACI_CONTEXT_KEYWORDS = ("ldap", "cn=dns", "aci", "bind-dyndb-ldap")

_STRONG_CRASH_KEYWORDS = (
    "failed to start",
    "exiting (due to fatal error",
    "could not configure any dns",
    "entered failed state",
    "named service failed",
    "fatal error",
    "shutting down due to fatal",
)

# Matched by the journal_named relevance filter but not clearly a crash -
# e.g. a transient/retry message. Not enough on its own to diagnose.
_AMBIGUOUS_NAMED_KEYWORDS = ("error", "denied", "cannot", "can't")


def _is_aci_error(item: EvidenceItem) -> bool:
    text = f"{item.summary} {item.data.get('raw_line', '')}".lower()
    return any(k in text for k in _ACI_ERROR_KEYWORDS) and any(k in text for k in _ACI_CONTEXT_KEYWORDS)


def _is_strong_crash(item: EvidenceItem) -> bool:
    text = f"{item.summary} {item.data.get('raw_line', '')}".lower()
    return any(k in text for k in _STRONG_CRASH_KEYWORDS)


def _is_ambiguous_named_trouble(item: EvidenceItem) -> bool:
    text = f"{item.summary} {item.data.get('raw_line', '')}".lower()
    return any(k in text for k in _AMBIGUOUS_NAMED_KEYWORDS)


def _service_down_findings(bundle: EvidenceBundle) -> List[Finding]:
    results = []
    for f in bundle.findings:
        if f.severity.rank < Severity.ERROR.rank:
            continue
        # Only the exact "<service>: not running" result of the service checks, for named itself.
        if not f.source.endswith("meta.services"):
            continue
        if re.fullmatch(r"\s*named(-pkcs11)?\s*:\s*not running\s*", f.message or "", re.IGNORECASE):
            results.append(f)
    return results


class NamedServiceDownRule(DiagnosticRule):
    rule_id = "named-service-down"
    summary = "named/bind-dyndb-ldap is not running or failed to start"

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        journal_lines = _journal_lines(bundle)
        aci_lines = [i for i in journal_lines if _is_aci_error(i)]
        crash_lines = [i for i in journal_lines if _is_strong_crash(i)]
        ambiguous_lines = [
            i for i in journal_lines if i not in aci_lines and i not in crash_lines and _is_ambiguous_named_trouble(i)
        ]
        service_findings = _service_down_findings(bundle)

        if not aci_lines and not crash_lines and not service_findings and not ambiguous_lines:
            return None  # no evidence at all that named is unhealthy

        if aci_lines or crash_lines or service_findings:
            evidence_for = (
                [_ref_item(i, "journal shows named/bind-dyndb-ldap failed to start with a permission/ACI error") for i in aci_lines]
                + [_ref_item(i, "journal shows named/bind-dyndb-ldap crashing or failing to start") for i in crash_lines]
                + [_ref_finding(f, "service health check reports named is not running") for f in service_findings]
            )

            if aci_lines:
                return Diagnosis(
                    pack_id=PACK_ID,
                    rule_id=self.rule_id,
                    status=DiagnosisStatus.DIAGNOSED,
                    title="named failed to start: missing LDAP ACI for the DNS service principal",
                    why=(
                        "named/bind-dyndb-ldap logged an LDAP permission-denied error while starting "
                        "up. This matches the documented failure mode where ACIs for the "
                        "DNS/<fqdn>@REALM principal under cn=dns are missing or incorrect - most "
                        "commonly after an LDIF restore or an upgrade that didn't reapply DNS ACIs. "
                        "Without those ACIs, bind-dyndb-ldap cannot read the DNS zone data it needs "
                        "to start named."
                    ),
                    confidence=Confidence(
                        level=ConfidenceLevel.HIGH,
                        rationale=(
                            "[HIGH: freeipa.org/page/Troubleshooting/DNS + bind-dyndb-ldap's "
                            "'NamedCannotStart' doc] the journal shows the specific LDAP "
                            "permission-denied signature this failure mode is documented to produce, "
                            "not just a generic crash."
                        ),
                        corroborating_evidence_count=len(aci_lines) + len(service_findings),
                    ),
                    severity=Severity.CRITICAL,
                    evidence_for=evidence_for,
                    impact=(
                        "named is down: all DNS resolution this server is authoritative for "
                        "(SRV/A/AAAA lookups clients depend on for Kerberos and LDAP discovery) "
                        "fails for clients pointed at this server."
                    ),
                    actions=[
                        Action(
                            description="Confirm the DNS service ACIs under cn=dns,<suffix> for the DNS/<fqdn>@REALM principal are actually missing before changing anything",
                            risk=RiskLevel.SAFE,
                            command="ldapsearch -Y GSSAPI -b 'cn=dns,$(ipa env basedn -o tsv 2>/dev/null || echo dc=example,dc=test)' aci",
                            rationale="Verifies the specific documented cause before any remediation is attempted.",
                        ),
                        Action(
                            description="Restore the standard DNS ACIs (compare against a known-good IPA DNS server, or reapply via the DNS update LDIF shipped with ipa-server-dns)",
                            risk=RiskLevel.CAUTION,
                            rationale="Documented fix for ACIs lost during an LDIF restore or upgrade.",
                            reference="https://www.freeipa.org/page/Troubleshooting/DNS",
                        ),
                        Action(
                            description="Restart named-pkcs11 once the ACIs are confirmed restored",
                            risk=RiskLevel.CAUTION,
                            command="systemctl restart named-pkcs11",
                            rationale="named/bind-dyndb-ldap only re-reads ACIs at (re)start.",
                        ),
                    ],
                    verification=[
                        VerificationCondition(
                            description="named-pkcs11 is active and no longer logs the ACI/permission-denied error on startup",
                            recheck=lambda b: not any(_is_aci_error(i) for i in _journal_lines(b)),
                        )
                    ],
                    limitations=(
                        "Diagnosis is based on text pattern matching for the documented "
                        "ACI-permission-denied signature; if bind-dyndb-ldap's exact wording "
                        "differs across versions, confirm by reading the full journal excerpt "
                        "manually before applying the ACI fix."
                    ),
                    upstream_candidates=["directory-server"],
                )

            # Generic named-down: crash and/or service-check evidence, but no
            # ACI-specific signature - do not guess at the ACI cause.
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="named/bind-dyndb-ldap is not running",
                why=(
                    "named/bind-dyndb-ldap appears to be down or crashed (journal and/or service "
                    "health evidence below), but the journal does not show the specific "
                    "LDAP-ACI-permission-denied signature associated with the documented "
                    "post-restore ACI regression, so that specific root cause is not being "
                    "assumed here."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.MEDIUM if not (crash_lines and service_findings) else ConfidenceLevel.HIGH,
                    rationale=(
                        "[HIGH: freeipa.org/page/Troubleshooting/DNS documents named-down as a "
                        "root cause of DNS resolution failure] evidence directly shows the service "
                        "down/crashed; confidence is capped below HIGH when only one of "
                        "journal/service-check evidence is available."
                    ),
                    corroborating_evidence_count=len(crash_lines) + len(service_findings),
                ),
                severity=Severity.CRITICAL,
                evidence_for=evidence_for,
                impact=(
                    "named is down: DNS resolution this server is authoritative for fails for "
                    "any client pointed at it, including this server's own Kerberos/LDAP discovery."
                ),
                actions=[
                    Action(
                        description="Check named-pkcs11 service status and the full recent journal for the actual failure reason",
                        risk=RiskLevel.SAFE,
                        command="systemctl status named-pkcs11 named; journalctl -u named-pkcs11 -u named --since -30min --no-pager",
                    ),
                    Action(
                        description="Restart named-pkcs11 once the underlying cause from the journal is understood and addressed",
                        risk=RiskLevel.CAUTION,
                        command="systemctl restart named-pkcs11",
                        rationale="Restarting without understanding the cause risks an immediate repeat crash.",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="named-pkcs11 is active and no new crash-signature lines appear in the journal",
                        recheck=lambda b: not any(_is_strong_crash(i) for i in _journal_lines(b)),
                    )
                ],
                limitations=(
                    "No ACI-specific error signature was found, so a directory-server ACI root "
                    "cause is not being claimed; if the generic remediation doesn't hold, check "
                    "cn=dns ACIs manually as a next step."
                ),
                upstream_candidates=[],
            )

        # Only ambiguous journal lines matched the relevance filter - not
        # enough to say named is actually down.
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="Possible named/bind-dyndb-ldap trouble - not clearly a service failure",
            why=(
                "The journal contains lines mentioning named/bind-dyndb-ldap errors, but none "
                "match a clear startup-failure or crash signature, so it's unclear whether named "
                "is actually down or this is a transient/retried condition."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale="Only ambiguous keyword matches in the journal; no clear crash or service-down signal.",
                corroborating_evidence_count=len(ambiguous_lines),
            ),
            severity=Severity.WARNING,
            evidence_for=[_ref_item(i, "journal line mentions a named/bind-dyndb-ldap error, but not clearly a crash") for i in ambiguous_lines],
            next_diagnostic_step=(
                "Run `systemctl status named-pkcs11 named` and re-check "
                "`journalctl -u named-pkcs11 -u named --since -30min` for a clear startup failure "
                "or crash signature before concluding named is down."
            ),
            limitations="Journal keyword matching is a heuristic; treat this as a prompt to look closer, not a conclusion.",
            upstream_candidates=[],
        )


# ---------------------------------------------------------------------------
# Rule B: forward-zone / empty-zone collision
# ---------------------------------------------------------------------------
#
# Sourcing: [HIGH] freeipa.org/page/V4/Forward_zones documents that BIND's
# automatic empty zones (RFC1918 reverse zones, etc.) take priority over a
# configured IPA forward zone when the names collide/overlap, causing
# bind-dyndb-ldap to auto-unload the forward zone. From the client's point of
# view this looks identical to "the forwarders are just unreachable" - a
# documented trap - so this rule only diagnoses the collision-specific cause
# when journal_named shows bind-dyndb-ldap explicitly logging the
# unload/skip due to an empty-zone conflict; a generic "forwarding isn't
# working" signal alone must not be assumed to be this cause (or ruled out
# as it, either).

_EMPTY_ZONE_KEYWORDS = ("empty zone", "auto-empty-zone", "empty-zone")
_ZONE_UNLOAD_KEYWORDS = ("unload", "skip", "not loaded", "overlap")
_FORWARD_ZONE_KEYWORDS = ("forward zone", "forwarders", "forwarding")
_GENERIC_FORWARDING_FAILURE_KEYWORDS = ("servfail", "timed out", "timeout", "unreachable", "connection refused")


def _is_zone_collision(item: EvidenceItem) -> bool:
    text = f"{item.summary} {item.data.get('raw_line', '')}".lower()
    return (
        any(k in text for k in _EMPTY_ZONE_KEYWORDS)
        and any(k in text for k in _ZONE_UNLOAD_KEYWORDS)
        and "forward" in text
    )


def _is_generic_forwarding_trouble(item: EvidenceItem) -> bool:
    text = f"{item.summary} {item.data.get('raw_line', '')}".lower()
    if any(k in text for k in _FORWARD_ZONE_KEYWORDS):
        return True
    return any(k in text for k in _GENERIC_FORWARDING_FAILURE_KEYWORDS) and "forward" in text


class ForwardZoneConflictRule(DiagnosticRule):
    rule_id = "forward-zone-conflict"
    summary = "Configured forward zone auto-unloaded due to an empty-zone collision"

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        journal_lines = _journal_lines(bundle)
        collision_lines = [i for i in journal_lines if _is_zone_collision(i)]
        generic_lines = [
            i for i in journal_lines if i not in collision_lines and _is_generic_forwarding_trouble(i)
        ]

        if not collision_lines and not generic_lines:
            return None  # no forwarding-related evidence at all

        if collision_lines:
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Forward zone auto-unloaded due to a BIND empty-zone collision",
                why=(
                    "bind-dyndb-ldap explicitly logged that a configured forward zone was "
                    "skipped/unloaded because it overlaps one of BIND's automatic empty zones "
                    "(e.g. an RFC1918 reverse zone). This is a documented FreeIPA forward-zone "
                    "gotcha, distinct from the forwarders simply being unreachable: the forward "
                    "zone is configured correctly but never actually loaded, so queries for names "
                    "under it are answered (or NXDOMAIN'd) by the empty zone instead of being "
                    "forwarded."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.HIGH,
                    rationale=(
                        "[HIGH: freeipa.org/page/V4/Forward_zones] the journal shows the specific "
                        "documented unload/collision log line, not just a generic resolution failure."
                    ),
                    corroborating_evidence_count=len(collision_lines),
                ),
                severity=Severity.ERROR,
                evidence_for=[_ref_item(i, "bind-dyndb-ldap log line shows the forward zone was unloaded due to an empty-zone collision") for i in collision_lines],
                impact=(
                    "Names under the affected forward zone fail to resolve (or resolve "
                    "incorrectly via the empty zone) for every client using this DNS server, "
                    "even though the forward zone configuration itself is correct."
                ),
                actions=[
                    Action(
                        description="Identify exactly which forward zone and which built-in empty zone collided, from the log line cited above",
                        risk=RiskLevel.SAFE,
                        command="journalctl -u named-pkcs11 -u named --since -30min --no-pager | grep -i 'empty zone'",
                    ),
                    Action(
                        description="Either exempt the specific overlapping prefix from BIND's automatic empty zones, or re-scope/rename the forward zone so it no longer overlaps an RFC1918/automatic empty zone",
                        risk=RiskLevel.CAUTION,
                        rationale="Documented fix for the forward-zone/empty-zone collision.",
                        reference="https://www.freeipa.org/page/V4/Forward_zones",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="A name under the forward zone now resolves via the forwarder, and the journal no longer shows the zone being unloaded",
                        recheck=lambda b: not any(_is_zone_collision(i) for i in _journal_lines(b)),
                    )
                ],
                limitations=_SINGLE_RESOLVER_LIMITATION,
                upstream_candidates=[],
            )

        # Generic forwarding trouble without the specific collision signature -
        # this is exactly the documented trap: it could be the empty-zone
        # collision, or it could just be an unreachable forwarder. Don't guess.
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="Forwarded DNS resolution appears broken - cause not yet distinguished",
            why=(
                "There is evidence of forwarding trouble (forwarder-related errors in the "
                "journal), but nothing confirms whether this is the documented forward-zone / "
                "empty-zone collision (freeipa.org/page/V4/Forward_zones) or simply an "
                "unreachable/misconfigured forwarder - these look identical from the outside but "
                "have completely different fixes."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale=(
                    "[HIGH-documented trap, but MED/LOW confidence in which side of it we're on] "
                    "generic forwarding-failure text was found without the specific "
                    "empty-zone-unload log signature that would confirm the collision cause."
                ),
                corroborating_evidence_count=len(generic_lines),
            ),
            severity=Severity.ERROR,
            evidence_for=[_ref_item(i, "journal shows forwarding-related trouble, but not the specific empty-zone-collision signature") for i in generic_lines],
            next_diagnostic_step=(
                "Check specifically for an RFC1918/automatic-empty-zone overlap with the "
                "configured forward zone (`journalctl -u named-pkcs11 | grep -i 'empty zone'`), "
                "and separately test raw forwarder reachability with "
                "`dig @<forwarder-ip> <name-under-forward-zone>` - do not assume either cause "
                "without one of these confirming it."
            ),
            limitations=_SINGLE_RESOLVER_LIMITATION,
            upstream_candidates=[],
        )


# ---------------------------------------------------------------------------
# Rule C: SRV/autodiscovery breakage (IPADNSSystemRecordsCheck)
# ---------------------------------------------------------------------------
#
# Sourcing: [HIGH] Red Hat's "Checking DNS records using IdM Healthcheck"
# docs. Two documented caveats are encoded rather than trusted blindly:
#   1. freeipa.org's DNS wiki page: this check only tests ONE DNS server's
#      view in a multi-server topology.
#   2. freeipa-healthcheck GitHub issue #270: this check produces spurious
#      WARNINGs (IPv6/ipa-ca AAAA record count) even on healthy systems, so a
#      WARNING-only result is not, by itself, trustworthy evidence of a real
#      problem.


def _looks_broken(item: EvidenceItem) -> bool:
    if str(item.data.get("rcode", "")).upper() == "TIMEOUT":
        return False  # no response at all does not confirm a missing record
    if item.severity is not None and item.severity.rank >= Severity.ERROR.rank:
        return True
    rcode = str(item.data.get("rcode", "")).upper()
    if rcode and rcode != "NOERROR":
        return True
    answers = item.data.get("answers")
    if answers is not None and len(answers) == 0:
        # No AAAA answer is normal on an IPv4-only deployment (and is the
        # known-spurious freeipa-healthcheck #270 shape): never "broken" alone.
        if "aaaa" in str(item.item_id).lower() or str(item.data.get("rtype", "")).upper() == "AAAA":
            return False
        return True
    return False


class SrvAutodiscoveryRule(DiagnosticRule):
    rule_id = "srv-autodiscovery"
    summary = "SRV/A/AAAA record correctness for Kerberos/LDAP autodiscovery"

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        idns_findings = [f for f in bundle.findings if f.source == _IDNS_SOURCE and f.check == _IDNS_CHECK]
        # "Unexpected SRV/URI entry" and "Unexpected ipa-ca address" report EXTRA records (for example a
        # stale replica's), not a missing/broken one - not autodiscovery breakage, so left undiagnosed.
        bad = [
            f
            for f in idns_findings
            if f.severity.rank >= Severity.WARNING.rank and not (f.message or "").lstrip().lower().startswith("unexpected")
        ]
        if not bad:
            return None

        worst = max(bad, key=lambda f: f.severity.rank)
        dns_items = _dns_lookup_items(bundle)
        broken_items = [i for i in dns_items if _looks_broken(i)]
        healthy_items = [i for i in dns_items if not _looks_broken(i)]

        if worst.severity == Severity.WARNING:
            # freeipa-healthcheck issue #270: WARNING-only results from this
            # specific check are a documented false-positive source. Do not
            # diagnose from the healthcheck WARNING alone.
            if not broken_items:
                return None
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="DNS record(s) required for Kerberos/LDAP autodiscovery are broken",
                why=(
                    f"IPADNSSystemRecordsCheck reported a WARNING ({worst.message or 'no message'}). "
                    "This specific check is documented (freeipa-healthcheck issue #270) to WARN on "
                    "healthy systems for IPv6/ipa-ca AAAA record counts, so the WARNING alone would "
                    "not be trusted - but an independent live `dig` lookup below confirms at least "
                    "one of the same records is actually missing or wrong."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.MEDIUM,
                    rationale=(
                        "[MED] healthcheck WARNING alone is a known false-positive source for this "
                        "specific check (issue #270); confidence comes from independent corroboration "
                        "via a live dig result, not the healthcheck WARNING itself."
                    ),
                    corroborating_evidence_count=len(broken_items),
                ),
                severity=Severity.ERROR,
                evidence_for=[_ref_finding(worst, "IPADNSSystemRecordsCheck flagged a system DNS record")]
                + [_ref_item(i, "live dig lookup independently confirms this record is missing or wrong") for i in broken_items],
                impact=(
                    "Clients may fail Kerberos/LDAP server autodiscovery (SRV lookups) or CA chain "
                    "retrieval (ipa-ca A/AAAA), causing intermittent authentication or enrollment "
                    "failures."
                ),
                actions=[
                    Action(
                        description="Diff live DNS records against the expected IPA system records",
                        risk=RiskLevel.SAFE,
                        command="ipa dns-update-system-records --dry-run",
                    ),
                    Action(
                        description="Add or correct the specific record identified above",
                        risk=RiskLevel.CAUTION,
                        command="ipa dnsrecord-add <zone> <name> --srv-rec='<priority> <weight> <port> <target>'  # or --a-rec/--aaaa-rec as appropriate",
                        rationale="Directly repairs the record confirmed broken by both healthcheck and a live dig.",
                        reference="https://access.redhat.com/documentation - Checking DNS records using IdM Healthcheck",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="Re-run IPADNSSystemRecordsCheck for SUCCESS and re-confirm via a fresh dig that the record now resolves correctly",
                        recheck=lambda b: not any(
                            f.source == _IDNS_SOURCE and f.check == _IDNS_CHECK and f.severity.rank >= Severity.ERROR.rank
                            for f in b.findings
                        ),
                        healthcheck_sources=[_IDNS_SOURCE],
                    )
                ],
                limitations=_SINGLE_RESOLVER_LIMITATION
                + " If the original symptom was a downstream Kerberos discovery failure, re-run "
                "the kerberos pack's checks after this fix for true end-to-end verification - "
                "resolving on this server (possibly from cache) does not prove client-facing "
                "resolution works.",
                upstream_candidates=[],
            )

        # ERROR/CRITICAL - not the documented WARNING-only false-positive band.
        if broken_items:
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="DNS record(s) required for Kerberos/LDAP autodiscovery are broken",
                why=(
                    f"IPADNSSystemRecordsCheck reported {worst.severity.value} "
                    f"({worst.message or 'no message'}), and an independent live `dig` lookup "
                    "confirms the affected record is actually missing or resolving incorrectly."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.HIGH,
                    rationale=(
                        "[HIGH: Red Hat 'Checking DNS records using IdM Healthcheck'] "
                        f"{worst.severity.value}-level healthcheck result corroborated by an "
                        "independent live dig lookup showing the same record is broken."
                    ),
                    corroborating_evidence_count=len(broken_items),
                ),
                severity=Severity.ERROR if worst.severity == Severity.ERROR else Severity.CRITICAL,
                evidence_for=[_ref_finding(worst, "IPADNSSystemRecordsCheck flagged a system DNS record")]
                + [_ref_item(i, "live dig lookup independently confirms this record is missing or wrong") for i in broken_items],
                impact=(
                    "Clients may fail Kerberos/LDAP server autodiscovery (SRV lookups) or CA chain "
                    "retrieval (ipa-ca A/AAAA), causing authentication or enrollment failures."
                ),
                actions=[
                    Action(
                        description="Diff live DNS records against the expected IPA system records",
                        risk=RiskLevel.SAFE,
                        command="ipa dns-update-system-records --dry-run",
                    ),
                    Action(
                        description="Add or correct the specific record identified above",
                        risk=RiskLevel.CAUTION,
                        command="ipa dnsrecord-add <zone> <name> --srv-rec='<priority> <weight> <port> <target>'  # or --a-rec/--aaaa-rec as appropriate",
                        rationale="Directly repairs the record confirmed broken by both healthcheck and a live dig.",
                        reference="https://access.redhat.com/documentation - Checking DNS records using IdM Healthcheck",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="Re-run IPADNSSystemRecordsCheck for SUCCESS and re-confirm via a fresh dig that the record now resolves correctly",
                        recheck=lambda b: not any(
                            f.source == _IDNS_SOURCE and f.check == _IDNS_CHECK and f.severity.rank >= Severity.ERROR.rank
                            for f in b.findings
                        ),
                        healthcheck_sources=[_IDNS_SOURCE],
                    )
                ],
                limitations=_SINGLE_RESOLVER_LIMITATION
                + " If the original symptom was a downstream Kerberos discovery failure, re-run "
                "the kerberos pack's checks after this fix for true end-to-end verification.",
                upstream_candidates=[],
            )

        if healthy_items and not broken_items:
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.UNKNOWN_CONFLICTING_EVIDENCE,
                title="IPADNSSystemRecordsCheck reports a broken record, but live dig disagrees",
                why=(
                    f"IPADNSSystemRecordsCheck reported {worst.severity.value} "
                    f"({worst.message or 'no message'}), but this pack's own live `dig` lookups "
                    "for the related SRV/A/AAAA records all resolved successfully, so the two "
                    "pieces of evidence conflict."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.LOW,
                    rationale="Healthcheck and an independent live dig disagree; unsafe to pick one without more information.",
                    corroborating_evidence_count=0,
                    contradicting_evidence_count=len(healthy_items),
                ),
                severity=Severity.ERROR,
                evidence_for=[_ref_finding(worst, "IPADNSSystemRecordsCheck flagged a system DNS record")],
                evidence_against=[_ref_item(i, "live dig lookup for a related record resolved successfully") for i in healthy_items],
                next_diagnostic_step=(
                    "Re-run `ipa dns-update-system-records --dry-run` and compare its exact output "
                    "to the specific record(s) this dig confirmed resolve, to see whether the "
                    "healthcheck result is stale, resolver-specific, or the dig target didn't match "
                    "the flagged record."
                ),
                limitations=_SINGLE_RESOLVER_LIMITATION,
                upstream_candidates=[],
            )

        # No dns_lookup evidence at all (collector didn't run / fixture missing).
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="IPADNSSystemRecordsCheck reports a broken record - not independently confirmed",
            why=(
                f"IPADNSSystemRecordsCheck reported {worst.severity.value} "
                f"({worst.message or 'no message'}), but no independent dig-based evidence is "
                "available to confirm which record is actually broken or corroborate the result."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale="Only the single-resolver healthcheck result is available; no independent corroboration.",
                corroborating_evidence_count=0,
            ),
            severity=Severity.ERROR,
            evidence_for=[_ref_finding(worst, "IPADNSSystemRecordsCheck flagged a system DNS record")],
            next_diagnostic_step=(
                "Run `dig SRV _ldap._tcp.<domain>` and `dig SRV _kerberos._udp.<realm>` against "
                "every IPA DNS server in the topology (not just this host) and check "
                "`journalctl -u named-pkcs11` as root."
            ),
            limitations=_SINGLE_RESOLVER_LIMITATION,
            upstream_candidates=[],
        )


PACK = DiagnosticPack(
    pack_id=PACK_ID,
    version="1",
    display_name="DNS",
    rules=[NamedServiceDownRule(), ForwardZoneConflictRule(), SrvAutodiscoveryRule()],
    healthcheck_sources=["ipahealthcheck.ipa.idns"],
    additional_collectors=["dns_lookup", "journal_named"],
)
