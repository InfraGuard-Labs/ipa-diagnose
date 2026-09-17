"""Tests for the replication diagnostic pack.

The first group runs the full pipeline (collect_evidence -> run_diagnosis)
against the fixtures under tests/fixtures/replication/, matching outcomes
recorded in each fixture's meta.json. The second group exercises the
stale-ruv and topology-disconnected rules directly against hand-built
EvidenceBundle objects, since those two clusters aren't covered by the four
required fixture directories (healthy/peer-unreachable/ambiguous/conflicting)
but are still part of the pack's rule set and must not regress silently.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ipa_diagnose.engine.model import (
    Confidence,
    ConfidenceLevel,
    DiagnosisStatus,
    PriorityBucket,
)
from ipa_diagnose.engine.packs.replication import PACK
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.evidence.model import EvidenceBundle, EvidenceItem, Finding, Provenance, Severity

FIXTURES_DIR = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "replication"


def _load_meta(fixture_name: str) -> dict:
    return json.loads((FIXTURES_DIR / fixture_name / "meta.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "fixture_name", ["healthy", "peer-unreachable", "ambiguous", "conflicting", "stale-ruv-removed-replica"]
)
def test_fixture_matches_expected_outcome(fixture_name):
    meta = _load_meta(fixture_name)
    fixture_dir = FIXTURES_DIR / fixture_name

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    assert report.overall_status.value == meta["expected_overall_status"], (
        f"{fixture_name}: expected overall_status={meta['expected_overall_status']!r}, "
        f"got {report.overall_status.value!r} (diagnoses: {[d.diagnosis_id for d in report.diagnoses]})"
    )

    actual_by_id = {d.diagnosis_id: d for d in report.diagnoses}
    expected_ids = {e["diagnosis_id"] for e in meta["expected_diagnoses"]}

    # Only assert on replication-pack diagnoses; other (currently-stub) packs
    # contribute nothing today, but this keeps the test from being brittle if
    # that changes.
    replication_diagnoses = {k: v for k, v in actual_by_id.items() if k.startswith("replication.")}
    assert set(replication_diagnoses.keys()) == expected_ids, (
        f"{fixture_name}: expected diagnosis ids {expected_ids}, got {set(replication_diagnoses.keys())}"
    )

    for expected in meta["expected_diagnoses"]:
        actual = replication_diagnoses[expected["diagnosis_id"]]
        assert actual.status.value == expected["status"], (
            f"{fixture_name}/{expected['diagnosis_id']}: expected status={expected['status']!r}, "
            f"got {actual.status.value!r}"
        )
        assert actual.priority.value == expected["priority"], (
            f"{fixture_name}/{expected['diagnosis_id']}: expected priority={expected['priority']!r}, "
            f"got {actual.priority.value!r}"
        )
        # Every diagnosis must ground its claims in evidence that is really
        # present in the bundle (the core "never invent evidence" contract).
        _assert_evidence_refs_are_real(actual, bundle)
        if actual.status != DiagnosisStatus.DIAGNOSED:
            assert actual.next_diagnostic_step, (
                f"{fixture_name}/{expected['diagnosis_id']}: non-DIAGNOSED status must set next_diagnostic_step"
            )


def _assert_evidence_refs_are_real(diagnosis, bundle: EvidenceBundle) -> None:
    finding_ids = {f.finding_id for f in bundle.findings}
    item_ids = {i.item_id for i in bundle.items}
    for ref in list(diagnosis.evidence_for) + list(diagnosis.evidence_against):
        if ref.kind == "finding":
            assert ref.evidence_id in finding_ids, f"evidence_for cites unknown finding_id {ref.evidence_id!r}"
        elif ref.kind == "item":
            assert ref.evidence_id in item_ids, f"evidence_for cites unknown item_id {ref.evidence_id!r}"
        else:
            pytest.fail(f"unexpected EvidenceRef.kind {ref.kind!r}")


def test_peer_unreachable_cites_bind_failure_and_no_conflicts():
    bundle = collect_evidence(replay_dir=str(FIXTURES_DIR / "peer-unreachable"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "replication.peer-connectivity-break")

    assert diag.confidence.level == ConfidenceLevel.HIGH
    assert not diag.evidence_against
    assert any(ref.evidence_id == "keytab-bind-check" for ref in diag.evidence_for)
    assert diag.actions[0].risk.value == "SAFE"
    assert all(a.risk.value != "HIGH_RISK" for a in diag.actions)


def test_conflicting_does_not_trigger_peer_connectivity_rule():
    bundle = collect_evidence(replay_dir=str(FIXTURES_DIR / "conflicting"))
    report = run_diagnosis(bundle)
    ids = {d.diagnosis_id for d in report.diagnoses}
    assert "replication.peer-connectivity-break" not in ids
    assert "replication.replication-conflicts" in ids


def test_conflicting_conflict_diagnosis_has_a_caution_resolution_action_not_automatic():
    bundle = collect_evidence(replay_dir=str(FIXTURES_DIR / "conflicting"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "replication.replication-conflicts")
    resolution_actions = [a for a in diag.actions if a.risk.value == "CAUTION"]
    assert resolution_actions, "expected a CAUTION-risk manual resolution action"
    assert "human" in resolution_actions[0].rationale.lower() or "judgment" in resolution_actions[0].rationale.lower()


def _bundle(findings=None, items=None) -> EvidenceBundle:
    return EvidenceBundle(
        hostname="ipa01.example.test",
        collected_at=EvidenceBundle.now(),
        findings=findings or [],
        items=items or [],
    )


def _finding(source, check, severity, message="", finding_id=None, keywords=None) -> Finding:
    return Finding(
        finding_id=finding_id or f"{source}.{check}",
        source=source,
        check=check,
        severity=severity,
        message=message,
        keywords=keywords or {},
        provenance=Provenance(source="ipa-healthcheck"),
    )


def _ruv_item(replica_id, alive, item_id=None) -> EvidenceItem:
    return EvidenceItem(
        item_id=item_id or f"replication-ruv:{replica_id}",
        kind="replication_ruv",
        summary=f"RUV entry replica_id={replica_id}",
        data={"replica_id": replica_id, "ldap_url": f"ldap://gone{replica_id}.example.test:389", "csn": None, "alive": alive},
    )


def test_stale_ruv_without_healthcheck_corroboration_is_insufficient_evidence():
    bundle = _bundle(items=[_ruv_item(9, alive=False)])
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "stale-ruv")
    assert diag.status == DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE
    assert diag.confidence.level == ConfidenceLevel.LOW
    assert diag.next_diagnostic_step
    _assert_evidence_refs_are_real(diag, bundle)


def test_stale_ruv_with_explicit_healthcheck_error_is_diagnosed_but_capped_at_medium():
    findings = [
        _finding(
            "ipahealthcheck.ds.ruv",
            "KnownRUVCheck",
            Severity.ERROR,
            message="Replica ID 9 has no corresponding live server",
        )
    ]
    bundle = _bundle(findings=findings, items=[_ruv_item(9, alive=False)])
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "stale-ruv")
    assert diag.status == DiagnosisStatus.DIAGNOSED
    # Never HIGH: RUVCheck's own documented limitation (needs all-master RUVs)
    # caps this rule's ceiling at MEDIUM even with explicit corroboration.
    assert diag.confidence.level == ConfidenceLevel.MEDIUM
    assert any(a.risk.value == "HIGH_RISK" for a in diag.actions)
    # Safest step ("do this first") must come before the high-risk cleanup.
    assert diag.actions[0].risk.value == "SAFE"
    _assert_evidence_refs_are_real(diag, bundle)


def test_stale_ruv_all_alive_does_not_fire():
    bundle = _bundle(items=[_ruv_item(4, alive=True), _ruv_item(5, alive=True)])
    diagnoses = PACK.evaluate(bundle)
    assert not any(d.rule_id == "stale-ruv" for d in diagnoses)


def test_topology_disconnected_fires_on_not_connected_message():
    findings = [
        _finding(
            "ipahealthcheck.ipa.topology",
            "IPATopologyDomainCheck",
            Severity.ERROR,
            message="Topology domain for suffix domain is not connected: ipa03.example.test",
            keywords={"suffix": "domain"},
        )
    ]
    bundle = _bundle(findings=findings)
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "topology-disconnected")
    assert diag.status == DiagnosisStatus.DIAGNOSED
    assert diag.confidence.level == ConfidenceLevel.HIGH
    assert all(a.risk.value == "SAFE" for a in diag.actions)
    assert "dns" in diag.upstream_candidates and "kerberos" in diag.upstream_candidates
    _assert_evidence_refs_are_real(diag, bundle)


def test_topology_success_does_not_fire():
    findings = [_finding("ipahealthcheck.ipa.topology", "IPATopologyDomainCheck", Severity.SUCCESS)]
    bundle = _bundle(findings=findings)
    diagnoses = PACK.evaluate(bundle)
    assert not any(d.rule_id == "topology-disconnected" for d in diagnoses)


def test_no_evidence_at_all_produces_no_diagnoses():
    bundle = _bundle()
    diagnoses = PACK.evaluate(bundle)
    assert diagnoses == []


def test_bind_failure_for_a_different_peer_does_not_corroborate_the_trigger():
    """Found in adversarial review: in a 3+-replica topology, a
    ReplicationCheck error naming peer A must not be treated as corroborated
    by a broken bind/agreement to an unrelated peer B - that's evidence for
    a *different* problem, not this one."""

    trigger = _finding(
        "ipahealthcheck.ds.replication",
        "ReplicationCheck",
        Severity.ERROR,
        message="Unable to communicate with replica ipa02.example.test: sasl_io_recv failed to decode packet",
        keywords={"agreement": "cn=meToipa02.example.test,cn=replica,cn=dc=example,dc=test,cn=mapping tree,cn=config"},
    )
    unrelated_bind_failure = EvidenceItem(
        item_id="ldap-query:keytab-bind",
        kind="keytab_bind_check",
        summary="GSSAPI bind to ipa03 failed",
        data={"target": "ipa03.example.test", "bind_ok": False},
    )
    unrelated_agreement_failure = EvidenceItem(
        item_id="replication-agreements:ipa03",
        kind="replication_agreement",
        summary="agreement to ipa03 is red",
        data={"peer": "ipa03.example.test", "status": "red"},
    )
    bundle = _bundle(findings=[trigger], items=[unrelated_bind_failure, unrelated_agreement_failure])
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "peer-connectivity-break")

    # Must NOT be the confident DIAGNOSED result - the only corroborating
    # evidence collected is about a different peer entirely.
    assert diag.status != DiagnosisStatus.DIAGNOSED
    for ref in diag.evidence_for:
        assert ref.evidence_id not in {"ldap-query:keytab-bind", "replication-agreements:ipa03"}


def test_stale_ruv_removed_replica_no_longer_silently_reports_healthy():
    """The critical regression this release fixes: a decommissioned replica
    leaves a stale RUV entry while every other replication/topology check
    (including RUVCheck/KnownRUVCheck themselves, which real ipa-healthcheck
    never reports above SUCCESS for this - confirmed against upstream
    source) looks completely healthy. Before the fix, the RUV collector
    never even ran in this scenario, so this reported 'Overall: HEALTHY'.
    Prove it no longer does."""

    bundle = collect_evidence(replay_dir=str(FIXTURES_DIR / "stale-ruv-removed-replica"))
    report = run_diagnosis(bundle)

    assert report.overall_status.value != "HEALTHY"
    stale = next(d for d in report.diagnoses if d.diagnosis_id == "replication.stale-ruv")
    assert stale.status == DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE
    assert stale.status != DiagnosisStatus.DIAGNOSED  # must not guess "decommissioned" without corroboration
    assert stale.next_diagnostic_step
    _assert_evidence_refs_are_real(stale, bundle)
    # The collector must actually have run unconditionally - not merely
    # "no error", but real RUV items present in the bundle.
    ruv_items = bundle.items_by_kind("replication_ruv")
    assert any(i.data.get("replica_id") == 6 and i.data.get("alive") is False for i in ruv_items)


def test_multiple_active_replicas_with_one_stale_only_flags_the_stale_one():
    bundle = _bundle(
        items=[
            _ruv_item(4, alive=True),
            _ruv_item(5, alive=True),
            _ruv_item(6, alive=True),
            _ruv_item(9, alive=False),
        ]
    )
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "stale-ruv")
    stale_ids = {ref.evidence_id for ref in diag.evidence_for}
    assert "replication-ruv:9" in stale_ids
    for alive_id in ("replication-ruv:4", "replication-ruv:5", "replication-ruv:6"):
        assert alive_id not in stale_ids


def test_stale_ruv_and_real_replication_failure_both_fire_independently():
    """A genuinely broken agreement and an unrelated stale RUV happening at
    the same time must both be reported, not merged or have one mask the
    other."""

    trigger = _finding(
        "ipahealthcheck.ds.replication",
        "ReplicationCheck",
        Severity.ERROR,
        message="Unable to communicate with replica ipa02.example.test: sasl_io_recv failed to decode packet",
        keywords={"agreement": "cn=meToipa02.example.test,cn=replica,..."},
    )
    bind_failure = EvidenceItem(
        item_id="ldap-query:keytab-bind",
        kind="keytab_bind_check",
        summary="GSSAPI bind to ipa02 failed",
        data={"target": "ipa02.example.test", "bind_ok": False},
    )
    bundle = _bundle(findings=[trigger], items=[bind_failure, _ruv_item(9, alive=False)])
    diagnoses = {d.rule_id: d for d in PACK.evaluate(bundle)}
    assert diagnoses["peer-connectivity-break"].status == DiagnosisStatus.DIAGNOSED
    assert diagnoses["stale-ruv"].status == DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE
    # Neither rule's evidence should bleed into the other's.
    assert "replication-ruv:9" not in {r.evidence_id for r in diagnoses["peer-connectivity-break"].evidence_for}


def test_peer_correlation_prefers_unknown_over_guessing_with_two_ambiguous_failing_peers():
    """Hardening: if the trigger finding names no specific peer (a renamed
    kw.agreement field, or message text without a hostname) AND more than
    one distinct peer is independently failing, the rule must not guess -
    it must not cite either peer's evidence as confirming this finding."""

    trigger = _finding(
        "ipahealthcheck.ds.replication",
        "ReplicationCheck",
        Severity.ERROR,
        message="A replication agreement is failing",  # no hostname, no "agreement" keyword at all
    )
    bind_failure_b = EvidenceItem(
        item_id="ldap-query:keytab-bind-b",
        kind="keytab_bind_check",
        summary="GSSAPI bind to ipa02 failed",
        data={"target": "ipa02.example.test", "bind_ok": False},
    )
    agreement_failure_c = EvidenceItem(
        item_id="replication-agreements:ipa03",
        kind="replication_agreement",
        summary="agreement to ipa03 is red",
        data={"peer": "ipa03.example.test", "status": "red"},
    )
    bundle = _bundle(findings=[trigger], items=[bind_failure_b, agreement_failure_c])
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "peer-connectivity-break")

    assert diag.status != DiagnosisStatus.DIAGNOSED
    cited_ids = {ref.evidence_id for ref in diag.evidence_for}
    assert "ldap-query:keytab-bind-b" not in cited_ids
    assert "replication-agreements:ipa03" not in cited_ids


def test_peer_correlation_keeps_single_unambiguous_candidate_even_without_a_named_peer():
    """When exactly one peer is failing, there is nothing to misattribute -
    the rule should still use it even though the trigger finding names no
    specific peer."""

    trigger = _finding(
        "ipahealthcheck.ds.replication",
        "ReplicationCheck",
        Severity.ERROR,
        message="A replication agreement is failing",
    )
    only_failure = EvidenceItem(
        item_id="ldap-query:keytab-bind",
        kind="keytab_bind_check",
        summary="GSSAPI bind to ipa02 failed",
        data={"target": "ipa02.example.test", "bind_ok": False},
    )
    bundle = _bundle(findings=[trigger], items=[only_failure])
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "peer-connectivity-break")
    assert diag.status == DiagnosisStatus.DIAGNOSED
    assert any(ref.evidence_id == "ldap-query:keytab-bind" for ref in diag.evidence_for)


def test_unrecognized_severity_still_triggers_the_rule_instead_of_being_silently_dropped():
    """Reproduces the severity-fallback bug: a real, fully-corroborated
    problem reported with a future/unrecognized severity value must not
    silently fail to trigger the rule's >= ERROR gate."""

    trigger = _finding(
        "ipahealthcheck.ds.replication",
        "ReplicationCheck",
        Severity.UNKNOWN,  # what _parse_severity now returns for e.g. "FATAL"
        message="Unable to communicate with replica ipa02.example.test",
        keywords={"agreement": "cn=meToipa02.example.test,cn=replica,..."},
    )
    bind_failure = EvidenceItem(
        item_id="ldap-query:keytab-bind",
        kind="keytab_bind_check",
        summary="GSSAPI bind to ipa02 failed",
        data={"target": "ipa02.example.test", "bind_ok": False},
    )
    bundle = _bundle(findings=[trigger], items=[bind_failure])
    diagnoses = PACK.evaluate(bundle)
    diag = next((d for d in diagnoses if d.rule_id == "peer-connectivity-break"), None)
    assert diag is not None, "an UNKNOWN-severity ERROR-equivalent finding must still trigger the rule"
    assert diag.status == DiagnosisStatus.DIAGNOSED


def test_confidence_object_is_reused_correctly_when_low():
    # Sanity-check that a LOW-confidence UNKNOWN diagnosis never accidentally
    # claims DIAGNOSED (the engine's own __post_init__ would raise if a rule
    # got this wrong, but assert explicitly here for this pack too).
    bundle = _bundle(items=[_ruv_item(9, alive=False)])
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "stale-ruv")
    assert diag.confidence == Confidence(
        level=ConfidenceLevel.LOW,
        rationale=diag.confidence.rationale,
        corroborating_evidence_count=diag.confidence.corroborating_evidence_count,
        contradicting_evidence_count=0,
    )
    assert diag.status != DiagnosisStatus.DIAGNOSED
