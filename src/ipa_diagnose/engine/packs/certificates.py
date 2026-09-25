"""Certificates/CA diagnostic pack.

Covers ipa-healthcheck's ``ipahealthcheck.ipa.certs`` and
``ipahealthcheck.dogtag.ca`` sources plus the ``certmonger``/``journal_pki``
targeted collectors (see evidence/collectors/certmonger.py and journal_pki.py).

Four rules, one per researched root-cause cluster:

  A. CertmongerTrackingStuckRule   - a tracking request is stuck in a CA
     failure state (CA_REJECTED/CA_UNREACHABLE/CA_UNCONFIGURED/NEED_GUIDANCE).
     CA_UNREACHABLE in particular has at least three distinct root causes
     that all produce the same state name (network/DNS outage to the CA, an
     expired CA certificate, or a missing/broken local trust anchor) - this
     rule only DIAGNOSEs when the reported ca-error text is specific enough
     to point at one of them, and otherwise stays UNKNOWN_INSUFFICIENT_EVIDENCE.
  B. CertificateExpiredRule        - ipa-healthcheck's own expiration checks
     report a certificate at (ERROR/CRITICAL) or approaching (WARNING) its
     expiry threshold. This is a direct reading of the cert's notAfter date,
     not an inference, so it is HIGH confidence either way; only the ERROR/
     CRITICAL case is treated as a real (CRITICAL-severity) problem, the
     WARNING case is a low-severity heads-up.
  C. RaAgentDesyncRule             - Dogtag/RA-agent connectivity or auth
     failures (including HTTP 4301-class errors) suggesting the RA agent
     certificate is out of sync with o=ipaca. A full confirmation needs an
     LDAP read this pack does not perform, so confidence is capped at MEDIUM
     unless corroborated by more than one independent signal.
  D. RenewalMasterUnreachableRule  - a certificate is aging toward expiry
     with certmonger reporting a clean MONITORING state (no error at all) on
     this host - the documented signature of the CA renewal master itself
     being the problem, not this host. Inherently unconfirmable from a
     single host, so this always stays UNKNOWN_INSUFFICIENT_EVIDENCE.

Per the documented causality chain (DNS -> Kerberos -> Replication ->
Certificates), rules A and D cite upstream_candidates=["replication"] (a
broken replication topology is a well-documented reason
dogtag-ipa-*-renew-agent can't read/write the CA renewal state in LDAP), and
rule C cites upstream_candidates=["directory-server"] (LDAP/o=ipaca
connectivity could be the true cause of an RA-agent desync). Rule B does not
carry an upstream candidate: an authoritative "this certificate's notAfter
date has passed" reading isn't explained away by an upstream pack firing.
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

PACK_ID = "certificates"

FAILURE_STATES = {"CA_REJECTED", "CA_UNREACHABLE", "CA_UNCONFIGURED", "NEED_GUIDANCE"}
_EXPIRY_CHECKS = {"IPACertmongerExpirationCheck", "IPACertfileExpirationCheck"}
# Only the RA agent's own check and the Dogtag connectivity check (a weak, shared-cause signal) are RA-desync
# evidence. DogtagCertsConfigCheck (CS.cfg vs NSS DB) and IPAKRAAgent (a different agent) are not, and stay
# undiagnosed rather than being folded into an RA-agent diagnosis.
_RA_HEALTHCHECK_CHECKS = {"DogtagCertsConnectivityCheck", "IPARAAgent"}
_RA_NICKNAMES = {"ipacert", "ipara"}
# "4301" is deliberately NOT a hint: IPA error 4301 is the generic CertificateOperationError (also raised
# when the CA is simply down), not an authorization failure. Bare "unauthorized" is any HTTP 401.
_AUTH_HINTS = ("authorization error", "not authorized")
# IPARAAgent results that state the agent's certificate/description and its LDAP entry disagree.
_RA_DESYNC_KEYS = {"description_mismatch", "ldap_mismatch", "agent_missing_description"}


_EXPIRY_TEXT_RE = re.compile(r"\bexpires in \d+ days?\b|\bexpired on\b|\bhas expired\b|\bis expired\b")


def _is_external_cert_message(f: Finding) -> bool:
    return "not an ipa-issued" in (f.message or "").lower()


def _is_expiry_result(f: Finding) -> bool:
    """A result that is actually about a notAfter date. The expiry checks also ERROR for 'no
    not-valid-after date yet', unreadable NSS DB/cert file and unknown storage - not expiry."""

    kw = f.keywords if isinstance(f.keywords, dict) else {}
    text = (f.message or "").lower()
    if _is_external_cert_message(f):
        return False  # user-provided certificate: certmonger will not renew it; different remedy
    return bool(kw.get("expiration_date")) or bool(_EXPIRY_TEXT_RE.search(text))

_NETWORK_HINTS = (
    "could not resolve",
    "name or service not known",
    "no route to host",
    "connection refused",
    "network is unreachable",
    "could not connect",
    "couldn't connect to server",
    "couldn't resolve host",
    "timed out connecting",
    "nodename nor servname",
)
_TRUST_HINTS = (
    "certificate has expired",
    "certificate verify failed",
    "unable to get local issuer certificate",
    "unable to get issuer certificate",
    "self signed certificate",
    "ssl handshake",
    "certificate is not yet valid",
    "x509",
)


def _cm_items(bundle: EvidenceBundle) -> List[EvidenceItem]:
    return bundle.items_by_kind("certmonger_request")


def _journal_items(bundle: EvidenceBundle) -> List[EvidenceItem]:
    return bundle.items_by_kind("pki_journal_line")


def _cert_findings(bundle: EvidenceBundle, *, sources: tuple, checks: Optional[set] = None) -> List[Finding]:
    results = [f for f in bundle.findings if any(f.source.startswith(s) for s in sources)]
    if checks is not None:
        results = [f for f in results if f.check in checks]
    return results


def _no_failure_states_remain(bundle: EvidenceBundle) -> bool:
    return not any(str(i.data.get("state", "")).upper() in FAILURE_STATES for i in _cm_items(bundle))


def _expiry_cleared(bundle: EvidenceBundle) -> bool:
    return not any(
        f.severity.rank >= Severity.WARNING.rank
        for f in _cert_findings(bundle, sources=("ipahealthcheck.ipa.certs",), checks=_EXPIRY_CHECKS)
    )


def _ra_agent_cleared(bundle: EvidenceBundle) -> bool:
    hc_clear = not any(
        f.severity.rank >= Severity.WARNING.rank
        for f in _cert_findings(bundle, sources=("ipahealthcheck.dogtag.ca", "ipahealthcheck.ipa.certs"), checks=_RA_HEALTHCHECK_CHECKS)
    )
    cm_clear = not any(
        str(i.data.get("nickname", "")).lower() in _RA_NICKNAMES and str(i.data.get("state", "")).upper() in FAILURE_STATES
        for i in _cm_items(bundle)
    )
    return hc_clear and cm_clear


def _local_ca_service_stopped(bundle: EvidenceBundle) -> bool:
    """ipa-healthcheck's service check reports this server's own CA (pki-tomcatd) as not running."""

    for f in bundle.findings:
        if (f.source.endswith("meta.services") and f.check in ("pki_tomcatd", "pki-tomcatd")
                and f.severity.rank >= Severity.ERROR.rank):
            return True
    return False


class CertmongerTrackingStuckRule(DiagnosticRule):
    rule_id = "certmonger-tracking-stuck"
    summary = "A certmonger tracking request is stuck in a CA failure state (renewal will not happen)."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        failing = [i for i in _cm_items(bundle) if str(i.data.get("state", "")).upper() in FAILURE_STATES]
        if not failing:
            return None

        evidence_for: List[EvidenceRef] = []
        local_ca_stopped = _local_ca_service_stopped(bundle)
        network_hit = False
        trust_hit = False
        informative_error = None
        for item in failing:
            evidence_for.append(
                EvidenceRef(
                    evidence_id=item.item_id,
                    kind="item",
                    why_relevant=(
                        f"certmonger request {item.data.get('request_id', '?')} "
                        f"(nickname={item.data.get('nickname', '?')}) is in failure state {item.data.get('state')}"
                    ),
                )
            )
            err = str(item.data.get("ca_error") or "").strip().lower()
            if not err:
                continue
            # Both are evaluated independently: text matching both families supports neither.
            # "Unable to communicate with CMS (Connection refused)": the CA's own service refusing, not a network path.
            # A local CA service reported stopped explains "couldn't connect" on its own: that is not a network path.
            if any(h in err for h in _NETWORK_HINTS) and "cms" not in err and not local_ca_stopped:
                network_hit = True
                informative_error = item.data.get("ca_error")
            if any(h in err for h in _TRUST_HINTS):
                trust_hit = True
                informative_error = item.data.get("ca_error")

        for jitem in _journal_items(bundle):
            line = str(jitem.data.get("line", "")).lower()
            if any(state.lower().replace("_", " ") in line or state.lower() in line for state in FAILURE_STATES) or "ca-error" in line:
                evidence_for.append(
                    EvidenceRef(
                        evidence_id=jitem.item_id,
                        kind="item",
                        why_relevant="journal line from the same window corroborates a CA/certmonger error",
                    )
                )

        actions_diagnostic = [
            Action(
                description="Confirm reachability to the CA host over the network before changing anything.",
                risk=RiskLevel.SAFE,
                command="dig <ca-host>; curl -kv https://<ca-host>:8443/ca/admin/ca/getStatus",
                rationale="Read-only reachability check to rule the network path in or out first.",
            ),
        ]

        if network_hit and not trust_hit:
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Certmonger cannot reach the CA over the network",
                why=(
                    "One or more certmonger tracking requests are stuck in a CA failure state, and the "
                    f"reported ca-error text specifically points at a network/DNS problem reaching the CA: "
                    f'"{informative_error}".'
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.MEDIUM,
                    rationale=(
                        "[MED] CA_UNREACHABLE-family states have several distinct root causes that share the "
                        "same state name (mankier getcert-list(1); freeipa.org/page/Troubleshooting/PKI); "
                        "confidence here rests on the ca-error text itself naming a specific network/DNS "
                        "failure rather than being generic, which narrows it to this cause."
                    ),
                    corroborating_evidence_count=len(evidence_for),
                ),
                severity=Severity.ERROR,
                evidence_for=evidence_for,
                impact=(
                    "Automated certificate renewal will not happen until connectivity to the CA is restored; "
                    "the certificate(s) behind this request will eventually expire."
                ),
                actions=actions_diagnostic
                + [
                    Action(
                        description="Once connectivity is confirmed restored, resubmit the stuck request.",
                        risk=RiskLevel.CAUTION,
                        command="getcert resubmit -i <request-id>",
                        rationale="Standard, reversible certmonger operation to retry the CA handshake.",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="Re-run `getcert list` and confirm the request has moved to MONITORING with a future expiry.",
                        recheck=_no_failure_states_remain,
                        healthcheck_sources=["ipahealthcheck.ipa.certs", "ipahealthcheck.dogtag.ca"],
                    )
                ],
                limitations=(
                    "If restoring replication is what actually fixed connectivity (see the documented "
                    "replication-breaks-then-certs-cant-renew cascade), resubmit any remaining stuck requests "
                    "on other CA masters afterward - fixing one master does not fix the others automatically."
                ),
                upstream_candidates=["replication"],
            )

        if trust_hit and not network_hit:
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Certmonger cannot validate the CA's certificate chain",
                why=(
                    "One or more certmonger tracking requests are stuck in a CA failure state, and the "
                    f"reported ca-error text specifically points at a TLS/certificate validation problem: "
                    f'"{informative_error}".'
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.MEDIUM,
                    rationale=(
                        "[MED] As with the network case, this is one of several distinct causes behind the same "
                        "CA_UNREACHABLE-family state name; confidence rests on the ca-error text explicitly "
                        "naming a certificate/trust validation failure rather than being generic."
                    ),
                    corroborating_evidence_count=len(evidence_for),
                ),
                severity=Severity.ERROR,
                evidence_for=evidence_for,
                impact=(
                    "Automated certificate renewal will not happen until the CA's certificate chain validates "
                    "correctly again on this host."
                ),
                actions=[
                    Action(
                        description="Inspect the exact TLS error and the CA certificate's own validity window.",
                        risk=RiskLevel.SAFE,
                        command="openssl s_client -connect <ca-host>:443 -showcerts </dev/null; getcert list -c <nickname>",
                        rationale="Read-only - confirms whether the CA's own certificate expired or the local trust store is missing it.",
                    ),
                    Action(
                        description="Refresh the local copy of the IPA CA certificate(s) in the trust store.",
                        risk=RiskLevel.CAUTION,
                        command="ipa-certupdate",
                        rationale="Standard, reversible, documented operation to resync local trust anchors with the CA.",
                        reference="https://www.freeipa.org/page/Troubleshooting/PKI",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="Re-run `getcert list` and confirm the request has moved to MONITORING with a future expiry.",
                        recheck=_no_failure_states_remain,
                        healthcheck_sources=["ipahealthcheck.ipa.certs", "ipahealthcheck.dogtag.ca"],
                    )
                ],
                upstream_candidates=["replication"],
            )

        if network_hit and trust_hit:
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.UNKNOWN_CONFLICTING_EVIDENCE,
                title="Certmonger tracking is stuck, but requests disagree on why",
                why=(
                    "Multiple certmonger tracking requests are in a CA failure state, but their ca-error text "
                    "points at different causes (network/DNS on some, certificate/trust validation on others) - "
                    "treating this as one root cause would be guessing."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.LOW,
                    rationale="Conflicting ca-error signals across requests; each needs its own investigation.",
                    corroborating_evidence_count=len(evidence_for),
                    contradicting_evidence_count=1,
                ),
                severity=Severity.ERROR,
                evidence_for=evidence_for,
                next_diagnostic_step=(
                    "Run `getcert list -v` and read each stuck request's ca-error individually rather than "
                    "assuming a single shared root cause - resolve each one on its own evidence."
                ),
                upstream_candidates=["replication"],
            )

        # Generic/empty ca-error: the documented CA_UNREACHABLE trap. Do not
        # guess between the network/expired-CA-cert/missing-trust-anchor
        # causes without more specific text to go on.
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="Certmonger tracking is stuck talking to the CA - cause unclear",
            why=(
                "One or more certmonger tracking requests are stuck in a CA failure state, but the reported "
                "ca-error text is empty or too generic to tell apart the (at least) three distinct root causes "
                "that all produce this same state: a network/DNS outage to the CA, the CA's own certificate "
                "having expired, or this host's trust store missing the IPA CA root."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale=(
                    "[HIGH per mankier getcert-list(1) and freeipa.org/page/Troubleshooting/PKI that "
                    "CA_UNREACHABLE has multiple unrelated root causes sharing one state name; LOW here "
                    "specifically because the ca-error text available in this run is not specific enough to "
                    "pick one - forcing a guess would violate 'unknown is better than wrong'.]"
                ),
                corroborating_evidence_count=len(evidence_for),
            ),
            severity=Severity.ERROR,
            evidence_for=evidence_for,
            impact=(
                "Automated certificate renewal will not happen while this request is stuck; the certificate(s) "
                "behind it will eventually expire."
            ),
            next_diagnostic_step=(
                "Check DNS/network reachability to the CA host AND independently verify the CA certificate "
                "chain and local trust store - e.g. `dig`/`curl -kv` to the CA's HTTPS port for reachability, "
                "and `openssl s_client -connect <ca-host>:443 -showcerts` plus confirming the IPA CA root is "
                "present and unexpired in the local NSS/system trust store. Either failure mode produces the "
                "identical CA_UNREACHABLE state, so both must be checked before assuming which one it is."
            ),
            actions=actions_diagnostic,
            verification=[
                VerificationCondition(
                    description="Re-run `getcert list` and confirm the request has moved to MONITORING with a future expiry.",
                    recheck=_no_failure_states_remain,
                    healthcheck_sources=["ipahealthcheck.ipa.certs", "ipahealthcheck.dogtag.ca"],
                )
            ],
            upstream_candidates=["replication"],
        )


class CertificateExpiredRule(DiagnosticRule):
    rule_id = "cert-expired"
    summary = "ipa-healthcheck reports a tracked certificate at or approaching its expiration threshold."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        findings = [
            f
            for f in _cert_findings(bundle, sources=("ipahealthcheck.ipa.certs",), checks=_EXPIRY_CHECKS)
            if f.severity.rank >= Severity.WARNING.rank and _is_expiry_result(f)
        ]
        if not findings:
            return None

        worst = max(findings, key=lambda f: f.severity.rank)
        evidence_for = [
            EvidenceRef(evidence_id=f.finding_id, kind="finding", why_relevant=f"{f.check} reported {f.severity.value}: {f.message}")
            for f in findings
        ]

        if worst.severity.rank >= Severity.ERROR.rank:
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Tracked certificate has passed its expiration threshold",
                why=(
                    f"{worst.check} reports {worst.severity.value} for this certificate: {worst.message}. Per Red "
                    "Hat KCS 7007191 and freeipa.org/page/V4/CA_certificate_renewal, an ERROR/CRITICAL result "
                    "here means the certificate is at or past expiry and effectively already service-impacting."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.HIGH,
                    rationale=(
                        "[HIGH] Directly reported by ipa-healthcheck's own IPACertmongerExpirationCheck/"
                        "IPACertfileExpirationCheck, which reads the certificate's notAfter date - a direct "
                        "measurement, not an inference."
                    ),
                    corroborating_evidence_count=len(evidence_for),
                ),
                severity=Severity.CRITICAL,
                evidence_for=evidence_for,
                impact=(
                    "Services relying on this certificate (LDAPS, HTTPS/Apache, or CA/KRA agent TLS) will fail "
                    "TLS negotiation until it is renewed."
                ),
                actions=[
                    Action(
                        description="Confirm the current certmonger tracking state for this request before acting.",
                        risk=RiskLevel.SAFE,
                        command="getcert list",
                        rationale="Read-only - establishes whether certmonger already has a renewal in flight before intervening manually.",
                    ),
                    Action(
                        description="Ask certmonger to resubmit the renewal now.",
                        risk=RiskLevel.CAUTION,
                        command="getcert resubmit -i <request-id>",
                        rationale="Standard, reversible certmonger renewal path - try this before any destructive recovery step.",
                    ),
                    Action(
                        description="Run ipa-cert-fix to recover from expired IPA system certificates.",
                        risk=RiskLevel.HIGH_RISK,
                        command="ipa-cert-fix",
                        rationale=(
                            "recovery-only per official guidance (freeipa.org/page/Troubleshooting/PKI, Fraser "
                            "Tweedale's ipa-cert-fix writeup) - back up certs/keys first, use only when expired "
                            "certs are actively blocking normal operation, and expect to need `getcert resubmit` "
                            "on remaining CA masters afterward."
                        ),
                        reference="https://www.freeipa.org/page/Troubleshooting/PKI",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="Re-run ipa-healthcheck's certs source fresh (not cached) and confirm SUCCESS for this check.",
                        recheck=_expiry_cleared,
                        healthcheck_sources=["ipahealthcheck.ipa.certs"],
                    )
                ],
                limitations=(
                    "Confirming the fix fully also requires checking that dependent services (httpd/dirsrv) "
                    "actually reloaded the new certificate, not just that certmonger wrote a new file to disk; "
                    "this pack's collectors do not check service-side TLS reload."
                ),
            )

        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Tracked certificate is approaching its expiration window",
            why=(
                f"{worst.check} reports WARNING: {worst.message}. This is inside ipa-healthcheck's configurable "
                "pre-expiry warning window (default 28 days, /etc/ipahealthcheck/ipahealthcheck.conf) - not yet "
                "broken, but worth confirming automated renewal is on track."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.HIGH,
                rationale=(
                    "[HIGH] Directly reported by ipa-healthcheck's own expiration check reading the cert's "
                    "notAfter date against its configured warning threshold - a direct measurement, not an "
                    "inference."
                ),
                corroborating_evidence_count=len(evidence_for),
            ),
            severity=Severity.WARNING,
            evidence_for=evidence_for,
            impact="No current service impact; becomes service-impacting only if automated renewal fails to complete before actual expiry.",
            actions=[
                Action(
                    description="Confirm certmonger auto-renewal is tracking this certificate on the happy path.",
                    risk=RiskLevel.SAFE,
                    command="getcert list",
                    rationale="Read-only - confirms the request is in MONITORING/CA_WORKING rather than a failure state.",
                ),
            ],
            verification=[
                VerificationCondition(
                    description="Re-run ipa-healthcheck's certs source fresh (not cached) and confirm SUCCESS for this check.",
                    recheck=_expiry_cleared,
                    healthcheck_sources=["ipahealthcheck.ipa.certs"],
                )
            ],
        )


class RaAgentDesyncRule(DiagnosticRule):
    rule_id = "ra-agent-desync"
    summary = "Dogtag/RA-agent connectivity or auth failures suggesting the RA agent certificate is out of sync with o=ipaca."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        hc_findings = [
            f
            for f in _cert_findings(bundle, sources=("ipahealthcheck.dogtag.ca", "ipahealthcheck.ipa.certs"), checks=_RA_HEALTHCHECK_CHECKS)
            if f.severity.rank >= Severity.WARNING.rank
        ]
        ra_cm_items = [
            i
            for i in _cm_items(bundle)
            if str(i.data.get("nickname", "")).lower() in _RA_NICKNAMES and str(i.data.get("state", "")).upper() in FAILURE_STATES
        ]
        auth_journal_items = [i for i in _journal_items(bundle) if any(h in str(i.data.get("line", "")).lower() for h in _AUTH_HINTS)]

        if not hc_findings and not ra_cm_items and not auth_journal_items:
            return None

        evidence_for: List[EvidenceRef] = []
        for f in hc_findings:
            evidence_for.append(EvidenceRef(evidence_id=f.finding_id, kind="finding", why_relevant=f"{f.check} reported {f.severity.value}: {f.message}"))
        for i in ra_cm_items:
            evidence_for.append(
                EvidenceRef(
                    evidence_id=i.item_id,
                    kind="item",
                    why_relevant=f"RA agent certmonger request {i.data.get('request_id', '?')} is in failure state {i.data.get('state')}",
                )
            )
        for i in auth_journal_items:
            evidence_for.append(EvidenceRef(evidence_id=i.item_id, kind="item", why_relevant="journal line shows a CA agent authorization error"))

        signal_types = sum([bool(hc_findings), bool(ra_cm_items), bool(auth_journal_items)])
        max_hc_severity = max((f.severity for f in hc_findings), default=Severity.WARNING)

        # A Dogtag CONNECTIVITY/config ERROR alone looks identical to a stopped
        # pki-tomcatd or an unreachable CA: only an RA-agent-specific ERROR, a failing
        # RA-agent certmonger request, or two independent signals support this cause.
        ra_specific_error = any(
            f.check == "IPARAAgent"
            and f.severity.rank >= Severity.ERROR.rank
            and isinstance(f.keywords, dict)
            and str(f.keywords.get("key", "")) in _RA_DESYNC_KEYS
            for f in hc_findings
        )
        # A stopped/unreachable CA produces the same connectivity errors, CA_UNREACHABLE states and generic LDAP
        # access errors, so those are never enough. Confident only with the RA agent's own desync result, or its
        # own ERROR corroborated by an explicit authorization failure in the journal.
        ra_own_error = any(f.check == "IPARAAgent" and f.severity.rank >= Severity.ERROR.rank for f in hc_findings)
        if ra_specific_error or (ra_own_error and auth_journal_items):
            confidence_level = ConfidenceLevel.HIGH if signal_types >= 2 else ConfidenceLevel.MEDIUM
            severity = Severity.ERROR
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="RA agent certificate appears out of sync with the CA agent database",
                why=(
                    "Dogtag/RA-agent connectivity or authorization is failing (Dogtag/RA-agent healthcheck "
                    "findings, a failing RA-agent certmonger tracking request, and/or CA-agent authorization "
                    "errors in the journal) - the well-documented signature of the RA agent certificate being "
                    "out of sync with its o=ipaca LDAP entry (freeipa.org/page/Troubleshooting/PKI)."
                ),
                confidence=Confidence(
                    level=confidence_level,
                    rationale=(
                        "[HIGH per freeipa.org/page/Troubleshooting/PKI for the RA-agent/Dogtag desync pattern "
                        "itself; capped at MEDIUM unless corroborated by more than one independent signal here, "
                        "since a full confirmation would require comparing against the o=ipaca LDAP RA agent "
                        "entry, which this pack does not query.]"
                    ),
                    corroborating_evidence_count=len(evidence_for),
                ),
                severity=severity,
                evidence_for=evidence_for,
                impact=(
                    "CA (and KRA, if configured) operations authenticated as the RA agent - including "
                    "certificate issuance and renewal for the whole deployment - can fail until the RA agent "
                    "certificate is back in sync."
                ),
                actions=[
                    Action(
                        description="Inspect the RA agent certmonger tracking entry together with recent CA/certmonger journal errors.",
                        risk=RiskLevel.SAFE,
                        command="getcert list -c ipaCert; journalctl -u pki-tomcatd -u certmonger --since -30min",
                        rationale="Read-only - narrows down whether this is a certificate mismatch vs. a transient connectivity blip.",
                    ),
                    Action(
                        description="Follow the documented RA agent certificate recovery procedure.",
                        risk=RiskLevel.CAUTION,
                        command="ipa-certupdate",
                        rationale="Reversible, standard recovery step documented at freeipa.org/page/Troubleshooting/PKI; run only after confirming the mismatch.",
                        reference="https://www.freeipa.org/page/Troubleshooting/PKI",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description="Re-run ipa-healthcheck's dogtag.ca source fresh and confirm DogtagCertsConnectivityCheck/DogtagCertsConfigCheck are SUCCESS.",
                        recheck=_ra_agent_cleared,
                        healthcheck_sources=["ipahealthcheck.dogtag.ca", "ipahealthcheck.ipa.certs"],
                    )
                ],
                limitations=(
                    "A full confirmation would require comparing this host's RA agent certificate serial "
                    "against the uid=ipara,ou=People,o=ipaca LDAP entry directly; that LDAP read is out of this "
                    "pack's scope (see the directory-server/replication packs)."
                ),
                upstream_candidates=["directory-server"],
            )

        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="Possible RA agent / Dogtag connectivity issue - insufficient corroboration",
            why=(
                "There is a single, thin signal (a WARNING-level Dogtag/RA-agent healthcheck finding) with no "
                "corroborating RA-agent certmonger failure or CA-agent authorization error in the journal - not "
                "enough to confidently call this an RA-agent/o=ipaca desync versus a transient blip."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale="Only one weak signal present; forcing a diagnosis here would be a guess, not a finding.",
                corroborating_evidence_count=len(evidence_for),
            ),
            severity=Severity.WARNING,
            evidence_for=evidence_for,
            next_diagnostic_step=(
                "Compare the RA agent certificate serial (`getcert list -c ipaCert`) against the "
                "uid=ipara,ou=People,o=ipaca LDAP entry with a read-only ldapsearch, and re-check "
                "`journalctl -u pki-tomcatd -u certmonger` for a repeat of the connectivity/auth error before "
                "concluding this is a real desync rather than a transient blip."
            ),
            limitations=(
                "A full confirmation would require comparing against the uid=ipara,ou=People,o=ipaca LDAP entry "
                "directly, which this pack does not query."
            ),
            upstream_candidates=["directory-server"],
        )


class RenewalMasterUnreachableRule(DiagnosticRule):
    rule_id = "renewal-master-unreachable"
    summary = "A certificate is approaching expiry with certmonger reporting no local error - possibly the CA renewal master is down."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        warning_findings = [
            f
            for f in _cert_findings(bundle, sources=("ipahealthcheck.ipa.certs",), checks=_EXPIRY_CHECKS)
            if f.severity == Severity.WARNING and _is_expiry_result(f)
        ]
        if not warning_findings:
            return None

        cm_items = _cm_items(bundle)
        if any(str(i.data.get("state", "")).upper() in FAILURE_STATES for i in cm_items):
            # Cluster A (an active local failure state) already explains a
            # stalled renewal on this host; don't also float the
            # renewal-master theory on top of a known local cause.
            return None

        monitoring_no_error = [
            i for i in cm_items if str(i.data.get("state", "")).upper() == "MONITORING" and not str(i.data.get("ca_error") or "").strip()
        ]
        if not monitoring_no_error:
            return None

        evidence_for = [
            EvidenceRef(evidence_id=f.finding_id, kind="finding", why_relevant=f"{f.check} reports WARNING (approaching expiry): {f.message}")
            for f in warning_findings
        ]
        evidence_for += [
            EvidenceRef(
                evidence_id=i.item_id,
                kind="item",
                why_relevant=(
                    f"certmonger request {i.data.get('request_id', '?')} shows state MONITORING with no ca-error "
                    "- this host sees no local failure that would explain the lack of renewal"
                ),
            )
            for i in monitoring_no_error
        ]

        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="Certificate nearing expiry with no local certmonger error - possible CA renewal master issue",
            evidence_severity=Severity.WARNING,  # built only from WARNING "approaching expiry" results
            why=(
                "This certificate is inside ipa-healthcheck's pre-expiry warning window, and certmonger on this "
                "host reports no error at all (state MONITORING, no ca-error) - it is not stuck locally. In "
                "IPA's CA renewal architecture only the current CA renewal master replica actually performs "
                "renewals; other CA replicas just read the renewed certificate back from LDAP "
                "(freeipa.org/page/Howto/Promote_CA_to_Renewal_and_CRL_Master; Fraser Tweedale's CA renewal "
                "master writeup). A certificate that keeps aging with a clean local certmonger state is the "
                "documented signature of the renewal master itself being unreachable or down, not a local "
                "problem on this host."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale=(
                    "[HIGH per freeipa.org/page/Howto/Promote_CA_to_Renewal_and_CRL_Master and Fraser Tweedale's "
                    "CA-renewal-master writeup for the architecture itself; LOW for confirming it applies here, "
                    "since a single host cannot see which replica is the current renewal master or whether it "
                    "is online.]"
                ),
                corroborating_evidence_count=len(evidence_for),
            ),
            severity=Severity.ERROR,
            evidence_for=evidence_for,
            impact=(
                "If the renewal master really is down, this certificate will continue aging toward outright "
                "expiry with no visible local error until someone checks the renewal master directly."
            ),
            next_diagnostic_step=(
                "Confirm which host is the current CA renewal master (check the CA renewal/CRL master role in "
                "the topology) and verify it is online and that its dogtag-ipa-ca-renew-agent / certmonger "
                "renewal helper completed successfully in its own journal."
            ),
            actions=[
                Action(
                    description="Identify and check the current CA renewal master's own certmonger/journal state.",
                    risk=RiskLevel.SAFE,
                    command="ssh <renewal-master> 'getcert list; journalctl -u certmonger --since -1day'",
                    rationale="Read-only topology and journal check on the host that actually performs renewals.",
                ),
            ],
            verification=[
                VerificationCondition(
                    description=(
                        "Once the renewal master is confirmed healthy, re-run ipa-healthcheck's certs source "
                        "fresh and confirm the WARNING clears because the certificate was actually renewed, not "
                        "just that the warning threshold changed."
                    ),
                    recheck=_expiry_cleared,
                    healthcheck_sources=["ipahealthcheck.ipa.certs"],
                )
            ],
            limitations=(
                "This is inherently a topology-wide fact (which replica is the renewal master, and whether it's "
                "healthy) that a single host's evidence cannot fully confirm."
            ),
            upstream_candidates=["replication"],
        )


PACK = DiagnosticPack(
    pack_id=PACK_ID,
    version="1",
    display_name="Certificates / CA",
    rules=[
        CertmongerTrackingStuckRule(),
        CertificateExpiredRule(),
        RaAgentDesyncRule(),
        RenewalMasterUnreachableRule(),
    ],
    healthcheck_sources=["ipahealthcheck.ipa.certs", "ipahealthcheck.dogtag.ca"],
    additional_collectors=["certmonger", "journal_pki"],
)
