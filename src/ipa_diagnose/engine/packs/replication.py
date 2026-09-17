"""Replication diagnostic pack.

Encodes four root-cause clusters for FreeIPA multi-supplier replication
problems, each backed by ipa-healthcheck findings plus two targeted,
read-only collectors (``replication_agreements``, ``ldap_query``):

  - ``peer-connectivity-break``: a replication agreement has stalled because
    the peer is unreachable or the replication keytab/GSSAPI bind is
    broken. [HIGH, freeipa.org/page/Troubleshooting/Directory_Server]
  - ``replication-conflicts``: LDAP conflict entries exist. Their presence
    means replication *is* transmitting writes between suppliers - it is a
    reconciliation-model artifact, not proof of a broken link. [HIGH,
    port389.org "Managing Replication Conflict Entries"; Red Hat Directory
    Server admin guide "Solving Common Replication Conflicts"]
  - ``stale-ruv``: a Replica Update Vector entry has no corresponding live
    server in this snapshot. A single host's RUV list cannot, by itself,
    distinguish a genuinely retired replica from one that is merely slow to
    converge, so this rule is deliberately conservative about confidence.
    [HIGH mechanism, port389.org CSN design; MED for any clock-skew causal
    narrative]
  - ``topology-disconnected``: ``IPATopologyDomainCheck`` reports a topology
    suffix is not fully connected. [HIGH, Red Hat "Checking IdM replication
    using Healthcheck"]

Every rule follows "unknown is better than wrong": it only reaches
``DIAGNOSED`` when it has HIGH/MEDIUM-confidence corroborating evidence, and
otherwise returns an ``UNKNOWN_*`` diagnosis with a concrete, safe
``next_diagnostic_step``.
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
from ipa_diagnose.evidence.model import EvidenceBundle, Finding, Severity

REPLICATION_SOURCE = "ipahealthcheck.ds.replication"
TOPOLOGY_SOURCE = "ipahealthcheck.ipa.topology"
DISK_SPACE_SOURCES = ("ipahealthcheck.ds.disk_space", "ipahealthcheck.system.filesystemspace")

_PEER_FROM_AGREEMENT_RE = re.compile(r"cn=meTo([\w.-]+),", re.IGNORECASE)
_PEER_FROM_MSG_RE = re.compile(r"\breplica\s+([\w.-]+)", re.IGNORECASE)


def _trigger_peer(trigger: Finding) -> "str | None":
    """Best-effort extraction of which peer a ReplicationCheck error is
    actually about, from the agreement DN or the message text. Used to make
    sure bind/agreement-status evidence is only treated as corroborating
    when it's about the SAME peer the healthcheck error named - found in
    adversarial review: without this, a broken bind to peer B could
    corroborate a ReplicationCheck error about peer A in a 3+-replica
    topology. Returns None (no filtering applied) when no peer name can be
    extracted, since the historical fixtures/behavior shouldn't regress for
    messages that don't mention a specific peer."""

    agreement_dn = str(trigger.keywords.get("agreement", ""))
    m = _PEER_FROM_AGREEMENT_RE.search(agreement_dn)
    if m:
        return m.group(1).lower()
    m = _PEER_FROM_MSG_RE.search(trigger.message)
    if m:
        return m.group(1).rstrip(":.,").lower()
    return None


def _disk_space_signal(bundle: EvidenceBundle) -> bool:
    return any(
        f.severity.rank >= Severity.WARNING.rank and any(f.source.startswith(s) for s in DISK_SPACE_SOURCES)
        for f in bundle.findings
    )


class PeerConnectivityBreakRule(DiagnosticRule):
    rule_id = "peer-connectivity-break"
    summary = "Replication agreement stalled due to peer unreachability or a broken keytab/GSSAPI bind."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        trigger_findings = [
            f
            for f in bundle.findings
            if f.source == REPLICATION_SOURCE
            and f.check == "ReplicationCheck"
            and f.severity.rank >= Severity.ERROR.rank
        ]
        if not trigger_findings:
            return None
        trigger = max(trigger_findings, key=lambda f: f.severity.rank)

        bind_items = bundle.items_by_kind("keytab_bind_check")
        agreement_items = bundle.items_by_kind("replication_agreement")
        conflict_items = bundle.items_by_kind("replication_conflict")

        bind_failures = [i for i in bind_items if not i.data.get("bind_ok", True)]
        agreement_failures = [i for i in agreement_items if i.data.get("status") == "red"]

        peer_ambiguous = False
        trigger_peer = _trigger_peer(trigger)
        if trigger_peer:
            bind_failures = [i for i in bind_failures if str(i.data.get("target", "")).lower() == trigger_peer]
            agreement_failures = [
                i for i in agreement_failures if str(i.data.get("peer", "")).lower() == trigger_peer
            ]
        else:
            # No peer name could be extracted from this trigger finding at
            # all (e.g. a future ipa-healthcheck renamed the `kw.agreement`
            # field and the message text doesn't name a host either). If
            # there is only ONE failing candidate, there is nothing to
            # misattribute - keep it. If there is more than one distinct
            # failing peer, we cannot tell which one this specific
            # healthcheck error is actually about, and blanket-using all of
            # them risks citing an unrelated peer's evidence as "confirming"
            # this one (the exact false-diagnosis mechanism found in
            # adversarial review). Prefer UNKNOWN over a guess: discard the
            # candidates so this falls through to the not-corroborated path
            # below instead of a confident DIAGNOSED citing the wrong peer.
            candidate_peers = {str(i.data.get("target", "")).lower() for i in bind_failures if i.data.get("target")}
            candidate_peers |= {str(i.data.get("peer", "")).lower() for i in agreement_failures if i.data.get("peer")}
            if len(candidate_peers) > 1:
                bind_failures = []
                agreement_failures = []
                peer_ambiguous = True

        upstream = ["dns", "kerberos"]
        if _disk_space_signal(bundle):
            upstream.append("directory-server")

        base_evidence_for = [
            EvidenceRef(
                evidence_id=trigger.finding_id,
                kind="finding",
                why_relevant="ipa-healthcheck ReplicationCheck reported ERROR/CRITICAL for a replication agreement.",
            )
        ]

        if not bind_items and not agreement_items:
            # additional_collectors were triggered (a WARNING+ finding from
            # this pack's healthcheck_sources is present) but produced
            # nothing - either they weren't able to run, or the fixture/host
            # simply has no corroborating data yet. Either way we cannot
            # safely tell "broken link" from "conflict-resolution artifact"
            # from the healthcheck finding alone.
            return Diagnosis(
                pack_id="replication",
                rule_id=self.rule_id,
                status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                title="Replication agreement error - cause not yet corroborated",
                why=(
                    "ipa-healthcheck's ReplicationCheck reports an error on a replication agreement, "
                    "but neither the replication-agreement/RUV collector nor the LDAP keytab/bind and "
                    "conflict-search collector produced any corroborating evidence. A connectivity/keytab "
                    "break and a conflict-resolution artifact look identical from this single healthcheck "
                    "finding alone."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.LOW,
                    rationale=(
                        "[HIGH mechanism, MED applicability] The freeipa.org troubleshooting guide "
                        "documents connectivity/keytab breaks as a primary cause of this error, but "
                        "without the corroborating collectors we cannot distinguish it from a conflict "
                        "artifact or a transient blip."
                    ),
                    corroborating_evidence_count=1,
                ),
                severity=trigger.severity,
                evidence_for=base_evidence_for,
                impact="Unknown until corroborated - could range from a stalled agreement to a benign, already-resolving artifact.",
                actions=[
                    Action(
                        description="List replication agreements and check for conflict entries as root.",
                        risk=RiskLevel.SAFE,
                        command="ipa-replica-manage list <host>",
                        rationale="Distinguishes a stalled/errored agreement from a healthy one with unrelated conflicts.",
                        reference="https://www.freeipa.org/page/Troubleshooting/Directory_Server",
                    ),
                ],
                verification=[_verification_condition()],
                limitations=(
                    "RUVCheck/KnownRUVCheck itself documents that full replication-health analysis is not "
                    "possible from a single host - it requires collecting the RUV from all masters."
                ),
                next_diagnostic_step=(
                    "Run `ipa-replica-manage list <host>` and check for replication conflict entries as "
                    "root to determine whether this is a connectivity break or a conflict-resolution artifact."
                ),
                upstream_candidates=upstream,
            )

        if bind_failures or agreement_failures:
            evidence_for = list(base_evidence_for)
            for item in bind_failures:
                evidence_for.append(
                    EvidenceRef(
                        evidence_id=item.item_id,
                        kind="item",
                        why_relevant="GSSAPI bind to the peer failed, matching the documented keytab/DNS prerequisite failure mode.",
                    )
                )
            for item in agreement_failures:
                evidence_for.append(
                    EvidenceRef(
                        evidence_id=item.item_id,
                        kind="item",
                        why_relevant="ipa-replica-manage reports this agreement's last update as failed.",
                    )
                )

            if conflict_items:
                # Contradictory: conflicts prove writes ARE reaching the peer,
                # which is at odds with "the link is broken". Don't force a
                # DIAGNOSED status - "unknown is better than wrong".
                evidence_against = [
                    EvidenceRef(
                        evidence_id=item.item_id,
                        kind="item",
                        why_relevant="A replication conflict entry implies writes from both suppliers reached each other at some point.",
                    )
                    for item in conflict_items
                ]
                return Diagnosis(
                    pack_id="replication",
                    rule_id=self.rule_id,
                    status=DiagnosisStatus.UNKNOWN_CONFLICTING_EVIDENCE,
                    title="Replication agreement error alongside conflict entries - cause ambiguous",
                    why=(
                        "Both a peer connectivity/bind failure signal and replication conflict entries are "
                        "present. Conflict entries normally indicate replication traffic IS reaching both "
                        "suppliers, which conflicts with a currently-broken link; this could mean the link "
                        "broke only recently (after the conflicting writes already replicated) or that the "
                        "bind-check target differs from the agreement that is actually failing."
                    ),
                    confidence=Confidence(
                        level=ConfidenceLevel.LOW,
                        rationale=(
                            "[HIGH, port389.org] conflicts are strong evidence replication has been "
                            "working; this directly contradicts a simple 'link is down' read of the "
                            "connectivity signal, so confidence in either single story is capped."
                        ),
                        corroborating_evidence_count=len(bind_failures) + len(agreement_failures),
                        contradicting_evidence_count=len(conflict_items),
                    ),
                    severity=trigger.severity,
                    evidence_for=evidence_for,
                    evidence_against=evidence_against,
                    impact="Replication health is uncertain; could be an active break, a stale bind-check target, or a recovering agreement.",
                    actions=[
                        Action(
                            description="Check the specific failing agreement's status directly.",
                            risk=RiskLevel.SAFE,
                            command="dsconf -D \"cn=Directory Manager\" ldap://<host> repl-agmt status --suffix=<suffix> <agreement>",
                            rationale="Confirms whether the errored agreement is the same one the bind check probed.",
                            reference="https://access.redhat.com/solutions/6096751",
                        ),
                        Action(
                            description="Re-run the GSSAPI bind check against the peer named in the errored agreement.",
                            risk=RiskLevel.SAFE,
                            command="kinit -kt /etc/dirsrv/ds.keytab ldap/<host> && klist && ldapsearch -Y GSSAPI -H ldap://<peer> -b '' -s base",
                        ),
                    ],
                    verification=[_verification_condition()],
                    limitations=(
                        "Single-host RUV/conflict snapshots cannot fully confirm current link state; "
                        "a live write-and-observe test is the gold-standard verification step."
                    ),
                    next_diagnostic_step=(
                        "Confirm which specific agreement is failing and re-run the bind check against "
                        "that exact peer before concluding whether the link is actually down."
                    ),
                    upstream_candidates=upstream,
                )

            return Diagnosis(
                pack_id="replication",
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Replication agreement broken - peer unreachable or keytab/GSSAPI bind failing",
                why=(
                    "ipa-healthcheck's ReplicationCheck reports an agreement error, corroborated by a "
                    "failed GSSAPI bind and/or a failed 'last update status' to the peer, with no "
                    "conflict entries present to suggest this is merely a reconciliation artifact."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.HIGH if bind_failures else ConfidenceLevel.MEDIUM,
                    rationale=(
                        "[HIGH, freeipa.org/page/Troubleshooting/Directory_Server] documents the GSSAPI "
                        "bind/keytab check as the primary prerequisite verification for a stalled "
                        "agreement; a direct bind failure is as close to ground truth as this pack gets."
                        if bind_failures
                        else "[HIGH mechanism, MED here] agreement status alone (without a direct bind-check "
                        "failure) is corroborating but slightly less direct evidence of a connectivity break."
                    ),
                    corroborating_evidence_count=len(bind_failures) + len(agreement_failures),
                ),
                severity=trigger.severity,
                evidence_for=evidence_for,
                impact="Multi-supplier convergence has stopped for this agreement; changes will not propagate to/from the affected peer until resolved.",
                actions=[
                    Action(
                        description="List replication agreements for this host and confirm which one is failing.",
                        risk=RiskLevel.SAFE,
                        command="ipa-replica-manage list <host>",
                    ),
                    Action(
                        description="Check the specific agreement's live status.",
                        risk=RiskLevel.SAFE,
                        command="dsconf -D \"cn=Directory Manager\" ldap://<host> repl-agmt status --suffix=<suffix> <agreement>",
                        reference="https://access.redhat.com/solutions/6096751",
                    ),
                    Action(
                        description="Verify DNS resolves the peer in both directions.",
                        risk=RiskLevel.SAFE,
                        command="dig +short <peer-fqdn>",
                    ),
                    Action(
                        description="Verify the replication keytab produces a valid GSSAPI bind to the peer.",
                        risk=RiskLevel.SAFE,
                        command="kinit -kt /etc/dirsrv/ds.keytab ldap/<host> && klist && ldapsearch -Y GSSAPI -H ldap://<peer> -b '' -s base",
                    ),
                ],
                verification=[_verification_condition()],
                limitations=(
                    "True convergence requires pulling RUVs from ALL servers, which a single-host tool "
                    "cannot fully do (RUVCheck documents this same limitation). A live write-and-observe "
                    "test on both suppliers is the gold-standard verification step."
                ),
                upstream_candidates=upstream,
            )

        if peer_ambiguous:
            # Real bind/agreement failures exist, but for more than one
            # distinct peer, and this trigger finding didn't name which one
            # it's actually about - attributing any single one of them would
            # risk citing the wrong peer's evidence (see the comment where
            # peer_ambiguous is set). This is a distinct case from "nothing
            # failed": failures ARE present, we just cannot safely say which
            # one this specific healthcheck error corroborates.
            return Diagnosis(
                pack_id="replication",
                rule_id=self.rule_id,
                status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                title="Replication agreement error - failing peer could not be confirmed",
                why=(
                    "ipa-healthcheck's ReplicationCheck reports an agreement error, and more than one "
                    "peer independently shows a bind or agreement failure, but this specific healthcheck "
                    "finding does not name which peer it is actually about. Attributing any single one of "
                    "those failures to this finding would risk citing the wrong peer's evidence."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.LOW,
                    rationale=(
                        "[MED] multiple candidate peers are failing, which is real signal, but without a "
                        "way to match this specific healthcheck finding to one of them, confidently "
                        "naming a cause risks being about the wrong replica entirely."
                    ),
                    corroborating_evidence_count=len(candidate_peers),
                ),
                severity=trigger.severity,
                evidence_for=base_evidence_for,
                impact="One or more replication agreements are failing; scope is uncertain until the specific failing agreement is confirmed.",
                actions=[
                    Action(
                        description="List replication agreements for this host to see which ones are actually failing.",
                        risk=RiskLevel.SAFE,
                        command="ipa-replica-manage list <host>",
                        rationale="Confirms exactly which agreement(s) this healthcheck error corresponds to before acting on any one of them.",
                    ),
                ],
                verification=[_verification_condition()],
                limitations="Cannot confirm which of the multiple failing peers this specific ReplicationCheck finding is about.",
                next_diagnostic_step="Run `ipa-replica-manage list <host>` as root and compare the failing agreement(s) against this healthcheck finding's timing/details to confirm which peer it actually names.",
                upstream_candidates=upstream,
            )

        # Collectors ran but found nothing wrong on their end, and there are
        # no conflicts either - the healthcheck signal isn't corroborated.
        return Diagnosis(
            pack_id="replication",
            rule_id=self.rule_id,
            status=DiagnosisStatus.TRANSIENT_SUSPECTED,
            title="Replication agreement error not corroborated by connectivity/bind checks",
            why=(
                "ipa-healthcheck flagged a ReplicationCheck error, but the keytab/bind check succeeded "
                "and no agreement was found in a failed state. This pattern matches a transient blip "
                "(e.g. a momentary timeout during a busy update window) more than a persistent break."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale=(
                    "[MED] absence of a corroborating failure is suggestive but not conclusive - "
                    "ipa-healthcheck may have caught a state that already self-resolved."
                ),
            ),
            severity=Severity.WARNING,
            evidence_for=base_evidence_for,
            impact="Likely already recovering, but should be re-checked to confirm it does not recur.",
            actions=[
                Action(
                    description="Re-run ipa-healthcheck's replication source to see if the error persists.",
                    risk=RiskLevel.SAFE,
                    command="ipa-healthcheck --source ipahealthcheck.ds.replication --output-type json",
                )
            ],
            verification=[_verification_condition()],
            next_diagnostic_step="Re-run ipa-healthcheck's replication check after a few minutes to confirm the error has cleared, not just moved.",
            upstream_candidates=upstream,
        )


class ReplicationConflictsRule(DiagnosticRule):
    rule_id = "replication-conflicts"
    summary = "LDAP replication conflict entries present (reconciliation artifact, not a broken link)."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        conflict_findings = [
            f
            for f in bundle.findings
            if f.source == REPLICATION_SOURCE and f.check == "ReplicationConflictCheck" and f.severity.rank >= Severity.WARNING.rank
        ]
        conflict_items = bundle.items_by_kind("replication_conflict")

        if not conflict_findings and not conflict_items:
            return None

        evidence_for: List[EvidenceRef] = []
        for f in conflict_findings:
            evidence_for.append(
                EvidenceRef(
                    evidence_id=f.finding_id,
                    kind="finding",
                    why_relevant="ipa-healthcheck ReplicationConflictCheck reported conflict entries.",
                )
            )
        for item in conflict_items:
            evidence_for.append(
                EvidenceRef(
                    evidence_id=item.item_id,
                    kind="item",
                    why_relevant="Direct LDAP search for (nsds5ReplConflict=*) returned this entry.",
                )
            )

        if not conflict_items:
            # healthcheck flagged it but the direct LDAP search didn't
            # corroborate with specific entries.
            return Diagnosis(
                pack_id="replication",
                rule_id=self.rule_id,
                status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                title="Possible replication conflicts reported, not yet enumerated",
                why="ipa-healthcheck's ReplicationConflictCheck reported conflicts, but the direct LDAP conflict search returned no entries to corroborate which ones.",
                confidence=Confidence(
                    level=ConfidenceLevel.LOW,
                    rationale="[HIGH mechanism, MED here] the check itself is a reliable signal, but without the enumerated entries we cannot confirm scope or which entries are involved.",
                ),
                severity=Severity.WARNING,
                evidence_for=evidence_for,
                impact="Unknown scope until the specific conflict entries are enumerated.",
                actions=[
                    Action(
                        description="Enumerate conflict entries directly.",
                        risk=RiskLevel.SAFE,
                        command='ldapsearch -Y GSSAPI -H ldap://localhost -b <suffix> "(nsds5ReplConflict=*)" dn nsds5ReplConflict',
                        reference="https://www.port389.org/docs/389ds/howto/howto-repl-conflict.html",
                    )
                ],
                verification=[_verification_condition()],
                next_diagnostic_step='Run `ldapsearch -Y GSSAPI ... "(nsds5ReplConflict=*)"` under the domain suffix as root to enumerate the actual conflict entries.',
            )

        return Diagnosis(
            pack_id="replication",
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Replication conflict entries present",
            why=(
                f"Direct LDAP search found {len(conflict_items)} entrie(s) matching (nsds5ReplConflict=*). "
                "This means writes from multiple suppliers reached each other and the reconciliation "
                "model created conflict entries - it is evidence replication IS working, not that it is "
                "broken, but the conflicts themselves need administrator review and resolution."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.HIGH,
                rationale="[HIGH, port389.org 'Managing Replication Conflict Entries'; Red Hat Directory Server admin guide] presence of nsds5ReplConflict entries via a direct LDAP filter is an unambiguous fact, not an inference.",
                corroborating_evidence_count=len(conflict_items),
            ),
            severity=Severity.WARNING,
            evidence_for=evidence_for,
            impact="Affected entries have diverged data that will not self-resolve; left alone, conflict entries accumulate and complicate future maintenance.",
            actions=[
                Action(
                    description="Enumerate all conflict entries to assess scope.",
                    risk=RiskLevel.SAFE,
                    command='ldapsearch -Y GSSAPI -H ldap://localhost -b <suffix> "(nsds5ReplConflict=*)" dn nsds5ReplConflict',
                    reference="https://www.port389.org/docs/389ds/howto/howto-repl-conflict.html",
                ),
                Action(
                    description="Resolve a specific conflict entry (choose which side wins, then strip the conflict marker).",
                    risk=RiskLevel.CAUTION,
                    command="ldapmodify (modrdn to drop the nsuniqueid suffix; remove nsds5ReplConflict/glue objectclass)",
                    rationale="Requires human judgment about which side's data should win - never resolved automatically.",
                    reference="https://access.redhat.com/documentation/en-us/red_hat_directory_server/11/html/administration_guide/managing_replication-solving_common_replication_conflicts",
                ),
            ],
            verification=[_verification_condition()],
            limitations="A conflict count alone does not indicate whether the underlying agreements are otherwise healthy - see the peer-connectivity-break rule for that.",
        )


class StaleRuvRule(DiagnosticRule):
    rule_id = "stale-ruv"
    summary = "A Replica Update Vector entry has no corresponding live server in this snapshot."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        ruv_items = bundle.items_by_kind("replication_ruv")
        stale_items = [i for i in ruv_items if i.data.get("alive") is False]
        if not stale_items:
            return None

        evidence_for = [
            EvidenceRef(
                evidence_id=item.item_id,
                kind="item",
                why_relevant="ipa-replica-manage list-ruv reports this replica ID with no corresponding live server in this snapshot.",
            )
            for item in stale_items
        ]

        explicit_findings = [
            f
            for f in bundle.findings
            if f.source.startswith("ipahealthcheck.ds.ruv") and f.severity.rank >= Severity.ERROR.rank
        ]

        if not explicit_findings:
            return Diagnosis(
                pack_id="replication",
                rule_id=self.rule_id,
                status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                title="Possible stale/orphaned RUV entry",
                why=(
                    f"{len(stale_items)} RUV entrie(s) have no corresponding live server in this single-host "
                    "snapshot. This can mean a replica was retired without cleanup, or simply that it is "
                    "slow to converge - a single snapshot cannot distinguish the two."
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.LOW,
                    rationale=(
                        "[HIGH mechanism, port389.org CSN design; MED for any specific causal story] RUVCheck's "
                        "own documentation states local analysis is not possible since it requires collecting "
                        "the RUV from all masters, which this single-host collector cannot do."
                    ),
                    corroborating_evidence_count=len(stale_items),
                ),
                severity=Severity.WARNING,
                evidence_for=evidence_for,
                impact="If genuinely dead, this RID's changelog data lingers indefinitely; if not, treating it as dead risks data loss.",
                actions=[
                    Action(
                        description="Cross-check the RID against the current live server/topology list before concluding it is dead.",
                        risk=RiskLevel.SAFE,
                        command="ipa-replica-manage list",
                    ),
                    Action(
                        description="Re-run list-ruv again after a delay to rule out a slow-to-converge replica.",
                        risk=RiskLevel.SAFE,
                        command="ipa-replica-manage list-ruv",
                    ),
                ],
                verification=[_verification_condition()],
                limitations="A single host's RUV snapshot cannot confirm a replica is permanently gone; cross-referencing all masters' RUVs is the only conclusive method.",
                next_diagnostic_step=(
                    "Re-run `ipa-replica-manage list-ruv` after roughly 15 minutes and cross-check the RID "
                    "against `ipa-replica-manage list` / a live topology query on ALL masters before "
                    "concluding it is dead."
                ),
            )

        evidence_for.extend(
            EvidenceRef(
                evidence_id=f.finding_id,
                kind="finding",
                why_relevant="ipa-healthcheck explicitly flagged this stale RID as an error.",
            )
            for f in explicit_findings
        )
        return Diagnosis(
            pack_id="replication",
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Stale/orphaned RUV entry confirmed by ipa-healthcheck",
            why=(
                "ipa-healthcheck explicitly flags a stale replica ID, corroborated by this host's own "
                "list-ruv snapshot showing no corresponding live server for that RID."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.MEDIUM,
                rationale=(
                    "[HIGH mechanism, port389.org; MED overall] capped at MEDIUM (not HIGH) because "
                    "RUVCheck's own documentation notes full confirmation still requires cross-checking "
                    "RUVs from all masters, which this run has not done."
                ),
                corroborating_evidence_count=len(stale_items) + len(explicit_findings),
            ),
            severity=Severity.WARNING,
            evidence_for=evidence_for,
            impact="Stale changelog/RUV state for a retired replica; left alone it is mostly a maintenance nuisance, but cleanup is destructive if the replica is not actually gone.",
            actions=[
                Action(
                    description="Confirm the replica no longer exists in the topology.",
                    risk=RiskLevel.SAFE,
                    command="ipa-replica-manage list",
                ),
                Action(
                    description="Remove the stale RUV for a confirmed-dead replica ID. Last resort only.",
                    risk=RiskLevel.HIGH_RISK,
                    command="ipa-replica-manage clean-ruv <replica_id>",
                    rationale="Community reports (freeipa-users) that running this against a RID that is not actually dead, or mid-topology-transition, can cause further data loss/desync.",
                ),
            ],
            verification=[_verification_condition()],
            limitations="Full confirmation requires collecting RUVs from every master, not just this host.",
        )


class TopologyDisconnectedRule(DiagnosticRule):
    rule_id = "topology-disconnected"
    summary = "A topology suffix is not fully connected (IPATopologyDomainCheck)."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        trigger_findings = [
            f
            for f in bundle.findings
            if f.source == TOPOLOGY_SOURCE
            and f.check == "IPATopologyDomainCheck"
            and f.severity.rank >= Severity.ERROR.rank
            and "not connected" in f.message.lower()
        ]
        if not trigger_findings:
            return None
        trigger = max(trigger_findings, key=lambda f: f.severity.rank)

        upstream = ["dns", "kerberos"]
        if _disk_space_signal(bundle):
            upstream.append("directory-server")

        suffix = trigger.keywords.get("suffix") if isinstance(trigger.keywords, dict) else None
        suffix_hint = suffix or "<suffix>"

        return Diagnosis(
            pack_id="replication",
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Topology suffix is not fully connected",
            why=(
                f"ipa-healthcheck's IPATopologyDomainCheck reports the topology suffix is not connected: "
                f"{trigger.message}"
            ),
            confidence=Confidence(
                level=ConfidenceLevel.HIGH,
                rationale="[HIGH, Red Hat 'Checking IdM replication using Healthcheck'] IPATopologyDomainCheck wraps `ipa topologysuffix-verify`, a direct, authoritative topology-graph check, not an inference.",
                corroborating_evidence_count=1,
            ),
            severity=trigger.severity,
            evidence_for=[
                EvidenceRef(
                    evidence_id=trigger.finding_id,
                    kind="finding",
                    why_relevant="IPATopologyDomainCheck directly reports this suffix as not connected.",
                )
            ],
            impact="Servers on the disconnected side of the topology graph will not receive updates from the rest of the domain at all, not just from one peer.",
            actions=[
                Action(
                    description="List topology segments for the affected suffix.",
                    risk=RiskLevel.SAFE,
                    command=f"ipa topologysegment-find {suffix_hint}",
                ),
                Action(
                    description="Re-verify the domain (and, if this host is a CA, the ca) suffix.",
                    risk=RiskLevel.SAFE,
                    command=f"ipa topologysuffix-verify {suffix_hint}",
                    reference="https://access.redhat.com/articles/checking-idm-replication-using-healthcheck",
                ),
            ],
            verification=[_verification_condition()],
            limitations="Confirms the topology graph is disconnected, not the specific underlying network/DNS/keytab cause - pair with the peer-connectivity-break rule's actions to find that.",
            upstream_candidates=upstream,
        )


def _recheck_replication_healthy(bundle: EvidenceBundle) -> bool:
    """Shared recheck: no ERROR+ ReplicationCheck, no failed bind, and no
    disconnected topology suffix remain. Necessary but not sufficient - see
    each rule's `limitations` for why full convergence needs all-master RUVs.
    """

    has_replication_error = any(
        f.source == REPLICATION_SOURCE and f.check == "ReplicationCheck" and f.severity.rank >= Severity.ERROR.rank
        for f in bundle.findings
    )
    has_topology_break = any(
        f.source == TOPOLOGY_SOURCE
        and f.check == "IPATopologyDomainCheck"
        and f.severity.rank >= Severity.ERROR.rank
        and "not connected" in f.message.lower()
        for f in bundle.findings
    )
    has_bind_failure = any(not i.data.get("bind_ok", True) for i in bundle.items_by_kind("keytab_bind_check"))
    return not has_replication_error and not has_topology_break and not has_bind_failure


def _verification_condition() -> VerificationCondition:
    return VerificationCondition(
        description=(
            "Re-run ReplicationCheck and IPATopologyDomainCheck and confirm SUCCESS, plus a clean GSSAPI "
            "bind check. This is necessary but not sufficient: true convergence requires pulling RUVs from "
            "ALL servers, which this single-host tool cannot fully do (matching RUVCheck's own documented "
            "limitation) - a live write-and-observe test across suppliers is the gold-standard check."
        ),
        recheck=_recheck_replication_healthy,
        healthcheck_sources=[REPLICATION_SOURCE, TOPOLOGY_SOURCE],
    )


PACK = DiagnosticPack(
    pack_id="replication",
    version="1",
    display_name="Replication",
    rules=[
        PeerConnectivityBreakRule(),
        ReplicationConflictsRule(),
        StaleRuvRule(),
        TopologyDisconnectedRule(),
    ],
    healthcheck_sources=["ipahealthcheck.ds.replication", "ipahealthcheck.ipa.topology"],
    # ldap_query (conflict search + GSSAPI bind check) stays trigger-gated:
    # it only matters once ReplicationCheck/topology already looks broken.
    additional_collectors=["ldap_query"],
    # replication_agreements runs on every invocation, not just when
    # something else already looks broken - see
    # DiagnosticPack.unconditional_collectors and StaleRuvRule's docstring.
    # A stale RUV from a decommissioned replica does not, by itself, make
    # RUVCheck/KnownRUVCheck report anything worse than SUCCESS, so gating
    # this collector behind another replication/topology finding meant that
    # exact real-world scenario (old replica removed, everything else
    # healthy) was silently invisible.
    unconditional_collectors=["replication_agreements"],
)
