"""Kerberos diagnostic pack.

ipa-healthcheck's own Kerberos coverage is documented but thin:
``ipahealthcheck.ipa.host``'s ``IPAHostKeytab`` check just runs ``kinit -kt
/etc/krb5.keytab`` and reports pass/fail with whatever error kinit produced;
``ipahealthcheck.ipa.kdc``'s ``KDCWorkersCheck`` only compares KDC worker
count against CPU count; ``ipahealthcheck.meta.services`` only reports
whether the ``krb5kdc``/``kadmin`` processes are up. None of these do log
analysis or a KVNO/clock comparison - that gap is exactly what this pack's
targeted collectors (``kerberos_client``, ``journal_krb5kdc``) fill.

Three root-cause clusters are covered, matching the researched, documented
failure modes for Kerberos auth in FreeIPA/IdM:

  A. Clock skew (ClockSkewRule) - [HIGH, MIT Kerberos "Clock Skew" doc:
     the default 300s/5min rejection window]. Checked first/cheaply because
     its symptom (generic auth failure) superficially resembles the other
     two clusters.
  B. Keytab/KVNO mismatch (KeytabKvnoMismatchRule) - [HIGH, Red Hat KCS
     5576461 & 3380341]. Deliberately does NOT treat the generic
     "Preauthentication failed" string as sufficient evidence by itself -
     only a direct ``kvno`` vs ``klist -kte`` mismatch counts.
  C. DNS-caused KDC discovery failure (KdcDiscoveryFailureRule) - [HIGH,
     freeipa.org + Red Hat Bugzilla 1508053]. The one clearest cross-pack
     causality link in the product: always cites
     ``upstream_candidates=["dns"]``.

Every rule returns ``None`` (silence) when its own specific trigger evidence
isn't present at all - a healthy system produces zero kerberos diagnoses.
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

_KEYTAB_SOURCE = "ipahealthcheck.ipa.host"
_KEYTAB_CHECK = "IPAHostKeytab"

_DNS_RESOLVE_RE = re.compile(r"cannot resolve network address", re.IGNORECASE)
_DNS_CONTACT_RE = re.compile(r"cannot contact any kdc", re.IGNORECASE)
_CLOCK_TEXT_RE = re.compile(r"clock skew|time skew", re.IGNORECASE)

_DESYNC_OFFSET_THRESHOLD_SECONDS = 5.0
"""Local-NTP-offset threshold we treat as "worth flagging". Much smaller
than MIT Kerberos's 300s auth-rejection window - this collector observes
only this host's side, so we flag well before that window to catch drift
before it becomes an outage."""


def _keytab_findings(bundle: EvidenceBundle) -> List[Finding]:
    return [
        f
        for f in bundle.findings
        if f.source == _KEYTAB_SOURCE
        and f.check == _KEYTAB_CHECK
        and f.severity.rank >= Severity.WARNING.rank
    ]


def _is_dns_style(message: str) -> bool:
    return bool(_DNS_RESOLVE_RE.search(message) or _DNS_CONTACT_RE.search(message))


def _is_clock_style(message: str) -> bool:
    return bool(_CLOCK_TEXT_RE.search(message))


def _journal_items(bundle: EvidenceBundle, pattern: str) -> List[EvidenceItem]:
    # "krb5kdc_journal_line", not the generic "journal_line" some other
    # packs' journal collectors use - kept distinct so this never picks up
    # another pack's unrelated journal evidence from the shared bundle.
    return [i for i in bundle.items_by_kind("krb5kdc_journal_line") if i.data.get("matched_pattern") == pattern]


def _desynced_clock_items(bundle: EvidenceBundle) -> List[EvidenceItem]:
    hits = []
    for item in bundle.items_by_kind("clock_sync"):
        if item.data.get("ntp_synchronized") is False:
            hits.append(item)
            continue
        offset = item.data.get("offset_seconds")
        if isinstance(offset, (int, float)) and abs(offset) >= _DESYNC_OFFSET_THRESHOLD_SECONDS:
            hits.append(item)
    return hits


def _kvno_items(bundle: EvidenceBundle) -> List[EvidenceItem]:
    return bundle.items_by_kind("kvno_comparison")


class ClockSkewRule(DiagnosticRule):
    rule_id = "clock-skew"
    summary = "Kerberos auth failing because this host's (or the KDC's) clock is out of sync."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        journal_hits = _journal_items(bundle, "clock_skew")
        desync_hits = _desynced_clock_items(bundle)
        if not journal_hits and not desync_hits:
            return None  # no clock-related evidence at all - not applicable

        keytab_findings = _keytab_findings(bundle)
        evidence_for: List[EvidenceRef] = [
            EvidenceRef(
                f.finding_id,
                "finding",
                "IPAHostKeytab's kinit -kt attempt failed around the same time as the clock evidence below.",
            )
            for f in keytab_findings
        ]

        if journal_hits:
            for item in journal_hits[:3]:
                evidence_for.append(
                    EvidenceRef(
                        item.item_id,
                        "item",
                        "krb5kdc journal line explicitly rejects a request for clock skew, matching MIT "
                        "Kerberos's documented default 300-second skew window.",
                    )
                )
            confidence = Confidence(
                level=ConfidenceLevel.HIGH,
                rationale=(
                    "[HIGH, MIT Kerberos 'Clock Skew' docs] The krb5kdc journal contains an explicit "
                    "clock-skew rejection line - this is direct KDC-side evidence, not an inference."
                ),
                corroborating_evidence_count=len(journal_hits) + len(keytab_findings),
            )
        else:
            for item in desync_hits:
                evidence_for.append(
                    EvidenceRef(
                        item.item_id,
                        "item",
                        "This host's own NTP sync check shows it is not synchronized or has a large offset.",
                    )
                )
            confidence = Confidence(
                level=ConfidenceLevel.MEDIUM,
                rationale=(
                    "[MED, corroborated by MIT Kerberos docs on the skew window] No direct KDC-side "
                    "rejection line was captured; inferred from this host's own NTP desync correlated "
                    "with an IPAHostKeytab kinit failure. True skew confirmation needs the KDC's own "
                    "clock too, which this collector cannot see."
                ),
                corroborating_evidence_count=len(desync_hits) + len(keytab_findings),
            )

        actions = [
            Action(
                description=(
                    "Run `chronyc tracking` (or `date -u`) on this host AND on the KDC to confirm the "
                    "exact skew magnitude before changing anything."
                ),
                risk=RiskLevel.SAFE,
                command="chronyc tracking",
                rationale="Read-only diagnostic step; confirms scope before any remediation.",
                reference="https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-admin/Clock-Skew.html",
            ),
            Action(
                description="Ensure chronyd/ntpd is enabled and force an immediate resync.",
                risk=RiskLevel.CAUTION,
                command="systemctl enable --now chronyd && chronyc makestep",
                rationale=(
                    "Reversible service/state change, not read-only: stepping the clock can disrupt any "
                    "process sensitive to sudden time jumps (cron, TLS validity windows, other auth "
                    "protocols), so this is CAUTION rather than SAFE."
                ),
            ),
        ]

        verification = [
            VerificationCondition(
                description=(
                    "From a FRESH process (not a cached ticket/session), both `kinit` (password) and "
                    "`kinit -kt /etc/krb5.keytab` succeed, `klist` shows a validly-timed ticket, and no "
                    "new clock-skew line appears in the krb5kdc journal. A stale cached TGT can make a "
                    "fix look successful when it isn't - always test from a fresh session."
                ),
                recheck=lambda b: not _journal_items(b, "clock_skew") and not _desynced_clock_items(b),
                healthcheck_sources=["ipahealthcheck.ipa.host"],
            )
        ]

        return Diagnosis(
            pack_id="kerberos",
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Kerberos authentication failing due to clock skew",
            why=(
                "Kerberos rejects authentication attempts when the client and KDC clocks differ by more "
                "than a default 5-minute window. The evidence below shows a clock-skew signal coinciding "
                "with a Kerberos authentication failure on this host."
            ),
            confidence=confidence,
            severity=Severity.ERROR,
            evidence_for=evidence_for,
            impact=(
                "Kerberos authentication (kinit, service tickets, SSO) fails intermittently or "
                "completely for this host until the clocks are back within the skew window."
            ),
            actions=actions,
            verification=verification,
            limitations=(
                "This pack can only directly observe this host's own NTP sync state (via chronyc/date), "
                "not the KDC's clock. A direct krb5kdc-journal clock-skew rejection line is treated as "
                "strong direct evidence (HIGH); a local desync alone is treated as indirect evidence "
                "(MEDIUM) because it does not by itself prove the *relative* skew against the KDC."
            ),
            upstream_candidates=[],
        )


class KeytabKvnoMismatchRule(DiagnosticRule):
    rule_id = "keytab-kvno-mismatch"
    summary = "Kerberos auth failing because the on-disk keytab's KVNO is stale relative to the KDC."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        keytab_findings = _keytab_findings(bundle)
        kvno_items = _kvno_items(bundle)
        if not keytab_findings and not kvno_items:
            return None  # nothing at all suggesting a keytab problem

        mismatches = [i for i in kvno_items if i.data.get("match") is False]

        if mismatches:
            evidence_for: List[EvidenceRef] = []
            for item in mismatches:
                evidence_for.append(
                    EvidenceRef(
                        item.item_id,
                        "item",
                        (
                            f"Direct KVNO comparison for {item.data.get('principal')}: KDC kvno="
                            f"{item.data.get('kdc_kvno')} vs keytab kvno={item.data.get('keytab_kvno')} "
                            "- a real numeric mismatch, not just the generic error string."
                        ),
                    )
                )
            for f in keytab_findings:
                evidence_for.append(
                    EvidenceRef(
                        f.finding_id,
                        "finding",
                        "IPAHostKeytab's kinit -kt attempt failed, consistent with an out-of-date keytab.",
                    )
                )

            return Diagnosis(
                pack_id="kerberos",
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Kerberos authentication failing due to a stale host/service keytab (KVNO mismatch)",
                why=(
                    "`kvno <principal>` (what the KDC currently has) does not match the key version "
                    "recorded in `klist -kte /etc/krb5.keytab` (what this host has on disk). This is the "
                    "direct disambiguating evidence for a keytab problem specifically - the generic "
                    "'Preauthentication failed' error alone was NOT used to reach this conclusion, "
                    "since that message is also produced by clock skew and salt mismatches."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.HIGH,
                    rationale=(
                        "[HIGH, Red Hat KCS 5576461 & 3380341] kvno-vs-keytab comparison is a direct, "
                        "deterministic numeric check, not an inference from an ambiguous error string."
                    ),
                    corroborating_evidence_count=len(mismatches) + len(keytab_findings),
                ),
                severity=Severity.ERROR,
                evidence_for=evidence_for,
                impact="This host cannot authenticate as its host/service principal until the keytab is refreshed.",
                actions=[
                    Action(
                        description=(
                            "Re-run `kvno <principal>` and `klist -kte /etc/krb5.keytab` to reconfirm the "
                            "KVNO numbers before changing anything."
                        ),
                        risk=RiskLevel.SAFE,
                        command="kvno <principal> && klist -kte /etc/krb5.keytab",
                        rationale="Read-only; confirms the mismatch is still current before remediating.",
                    ),
                    Action(
                        description="Regenerate the keytab properly via `ipa-getkeytab`.",
                        risk=RiskLevel.CAUTION,
                        command="ipa-getkeytab -s <ipa-server> -p <principal> -k /etc/krb5.keytab",
                        rationale=(
                            "Reversible but disruptive: this immediately invalidates the OLD keytab. Any "
                            "process or host still holding a copy of the old keytab file will start "
                            "failing kinit until it also receives the new one. Do NOT manually rebuild a "
                            "keytab with `ktutil` - Red Hat/community reports document that as a common "
                            "CAUSE of salt mismatches, not a fix, so it is intentionally not offered here."
                        ),
                        reference="Red Hat KCS 5576461",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description=(
                            "From a FRESH process (not a cached ticket/session), `kinit -kt "
                            "/etc/krb5.keytab` succeeds, a fresh `kvno <principal>` now matches the "
                            "keytab's KVNO, and ipahealthcheck.ipa.host's IPAHostKeytab check reports "
                            "SUCCESS. Do not rely on an already-cached ticket to judge success."
                        ),
                        recheck=lambda b: not any(i.data.get("match") is False for i in _kvno_items(b)),
                        healthcheck_sources=["ipahealthcheck.ipa.host"],
                    )
                ],
                limitations=(
                    "Manually rebuilding a keytab with `ktutil` is deliberately not offered as an action: "
                    "it is a documented cause of salt mismatches, not a remediation for one."
                ),
                upstream_candidates=[],
            )

        if not kvno_items:
            generic = [f for f in keytab_findings if not _is_dns_style(f.message) and not _is_clock_style(f.message)]
            if generic:
                return Diagnosis(
                    pack_id="kerberos",
                    rule_id=self.rule_id,
                    status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                    title="Kerberos authentication failing (kinit) - cause not yet disambiguated",
                    why=(
                        "IPAHostKeytab's kinit -kt attempt failed with a generic error, but the "
                        "kerberos_client collector's KVNO comparison could not be obtained this run "
                        "(missing/failed collection). 'Preauthentication failed' and similar generic "
                        "kinit errors are produced by clock skew, a wrong keytab/password, AND a salt "
                        "mismatch alike - without the direct KVNO comparison, this cannot be safely "
                        "attributed to a keytab problem specifically."
                    ),
                    confidence=Confidence(
                        level=ConfidenceLevel.LOW,
                        rationale=(
                            "[HIGH per Red Hat KCS that the error text alone is a generic bucket] The "
                            "generic kinit failure message is, by itself, LOW-confidence evidence for any "
                            "single specific cause - clock skew, keytab/KVNO mismatch, and salt mismatch "
                            "all produce the same text."
                        ),
                        contradicting_evidence_count=0,
                    ),
                    severity=Severity.ERROR,
                    evidence_for=[
                        EvidenceRef(
                            f.finding_id,
                            "finding",
                            "IPAHostKeytab kinit failure - generic error text, not diagnostic by itself.",
                        )
                        for f in generic
                    ],
                    impact="Kerberos authentication is failing for this host; the specific cause is not yet known.",
                    actions=[
                        Action(
                            description=(
                                "As root, compare `kvno <principal>` against `klist -kte /etc/krb5.keytab`, "
                                "and check `chronyc tracking`/`date` against the KDC's clock, to distinguish "
                                "clock skew from a keytab problem."
                            ),
                            risk=RiskLevel.SAFE,
                            command="kvno <principal>; klist -kte /etc/krb5.keytab; chronyc tracking",
                            rationale="Read-only; this is exactly the missing disambiguating evidence.",
                        )
                    ],
                    limitations=(
                        "The kerberos_client collector did not produce a KVNO comparison for this run "
                        "(fixture/collection unavailable), which is the one piece of evidence that could "
                        "safely distinguish a keytab mismatch from clock skew or a salt mismatch."
                    ),
                    next_diagnostic_step=(
                        "As root, compare `kvno <principal>` against `klist -kte /etc/krb5.keytab`, and "
                        "check `chronyc tracking`/`date` against the KDC's clock, to distinguish clock "
                        "skew from a keytab problem."
                    ),
                    upstream_candidates=[],
                )

        return None


class KdcDiscoveryFailureRule(DiagnosticRule):
    rule_id = "kdc-discovery-failure"
    summary = "Kerberos auth failing because this host cannot find/reach a KDC (likely DNS-caused)."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        keytab_findings = _keytab_findings(bundle)
        dns_style = [f for f in keytab_findings if _is_dns_style(f.message)]
        if not dns_style:
            return None  # no discovery/reachability-shaped error at all

        # A more specific, already-diagnosable cause takes precedence over
        # this hypothesis rather than letting two rules fight over the same
        # symptom.
        if _journal_items(bundle, "clock_skew") or _desynced_clock_items(bundle):
            return None
        if any(i.data.get("match") is False for i in _kvno_items(bundle)):
            return None

        resolve_hits = [f for f in dns_style if _DNS_RESOLVE_RE.search(f.message)]
        contact_hits = [f for f in dns_style if _DNS_CONTACT_RE.search(f.message) and f not in resolve_hits]

        if resolve_hits:
            confidence = Confidence(
                level=ConfidenceLevel.HIGH,
                rationale=(
                    "[HIGH, freeipa.org + Red Hat Bugzilla 1508053] 'Cannot resolve network address for "
                    "KDC' means DNS resolution itself is failing at the client's resolver - unambiguously "
                    "a DNS-layer failure regardless of whether the underlying cause is a missing record "
                    "or a resolver misconfiguration."
                ),
                corroborating_evidence_count=len(resolve_hits),
            )
            error_kind = "DNS resolution of the KDC itself is failing"
        else:
            confidence = Confidence(
                level=ConfidenceLevel.MEDIUM,
                rationale=(
                    "[MED, Red Hat Bugzilla 1508053] 'Cannot contact any KDC for realm' can mean either "
                    "missing/wrong _kerberos._udp/_tcp SRV records (a DNS problem) OR that a correctly "
                    "resolved KDC is genuinely network-unreachable (firewall/routing) - these are NOT the "
                    "same problem, and this pack's own collectors cannot fully distinguish them without "
                    "the DNS pack's SRV record check."
                ),
                corroborating_evidence_count=len(contact_hits),
            )
            error_kind = "no KDC could be contacted for the realm"

        evidence_for = [
            EvidenceRef(
                f.finding_id,
                "finding",
                f"IPAHostKeytab's kinit -kt attempt failed because {error_kind}.",
            )
            for f in dns_style
        ]

        return Diagnosis(
            pack_id="kerberos",
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Kerberos authentication failing because no KDC could be found or reached",
            why=(
                f"kinit failed because {error_kind}, with no clock-skew or KVNO-mismatch evidence "
                "present to explain the failure instead. The most commonly documented root cause for "
                "this pattern is missing or incorrect DNS SRV records for the Kerberos realm."
            ),
            confidence=confidence,
            severity=Severity.CRITICAL,
            evidence_for=evidence_for,
            impact=(
                "Kerberos authentication cannot succeed at all for this host (and potentially others "
                "relying on the same DNS data) until KDC discovery/reachability is restored."
            ),
            actions=[
                Action(
                    description=(
                        "Check the Kerberos SRV records: `dig _kerberos._udp.<domain> SRV` and "
                        "`dig _kerberos._tcp.<domain> SRV`, confirming they resolve to the expected KDC(s)."
                    ),
                    risk=RiskLevel.SAFE,
                    command="dig _kerberos._udp.<domain> SRV; dig _kerberos._tcp.<domain> SRV",
                    rationale="Read-only; this is the DNS pack's own evidence needed to fully confirm this cause.",
                    reference="Red Hat Bugzilla 1508053",
                ),
                Action(
                    description="Verify network reachability to the resolved KDC(s) on port 88 (tcp/udp).",
                    risk=RiskLevel.SAFE,
                    command="nc -vz <kdc-host> 88",
                    rationale="Read-only; distinguishes a DNS-only problem from a genuine network/firewall outage.",
                ),
            ],
            verification=[
                VerificationCondition(
                    description=(
                        "From a FRESH process (not a cached ticket/session), both password-based `kinit` "
                        "and `kinit -kt /etc/krb5.keytab` succeed and `klist` shows a valid ticket; "
                        "IPAHostKeytab reports SUCCESS. A cached ticket cannot be used to judge this."
                    ),
                    recheck=lambda b: not any(_is_dns_style(f.message) for f in _keytab_findings(b)),
                    healthcheck_sources=["ipahealthcheck.ipa.host"],
                )
            ],
            limitations=(
                "Fully confirming this as a DNS root cause (vs. a genuine network/firewall outage to an "
                "otherwise-correctly-resolved KDC) requires checking the `_kerberos._udp`/`_tcp` SRV "
                "records via the dns pack's own collector, which this pack does not have direct access "
                "to. This diagnosis is linked to a concurrently-firing DNS-pack diagnosis, if any, via "
                "upstream_candidates."
            ),
            upstream_candidates=["dns"],
        )


PACK = DiagnosticPack(
    pack_id="kerberos",
    version="1",
    display_name="Kerberos",
    rules=[
        ClockSkewRule(),
        KeytabKvnoMismatchRule(),
        KdcDiscoveryFailureRule(),
    ],
    healthcheck_sources=["ipahealthcheck.ipa.host", "ipahealthcheck.ipa.kdc", "ipahealthcheck.meta.services"],
    additional_collectors=["kerberos_client", "journal_krb5kdc"],
)
