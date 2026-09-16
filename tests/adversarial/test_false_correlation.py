"""Adversarial correlation tests: does the engine ever invent a causal link
that isn't real, and does it correctly recognize a link that IS documented?

These merge evidence from two *independently built* pack fixtures into one
bundle (each pack's fixtures were authored by a different agent with no
knowledge of the others), which is a more honest test of correlate.py's real
behavior than hand-rolled synthetic Diagnosis objects (see
tests/unit/test_correlate.py for those).
"""

import pathlib

import pytest

from ipa_diagnose.engine.model import PriorityBucket
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.evidence.model import EvidenceBundle

FIXTURES_ROOT = pathlib.Path(__file__).parent.parent / "fixtures"


def _merged_bundle(*fixture_dirs: str) -> EvidenceBundle:
    merged = EvidenceBundle(hostname="merged-adversarial-test", collected_at=EvidenceBundle.now())
    for rel in fixture_dirs:
        sub = collect_evidence(replay_dir=str(FIXTURES_ROOT / rel))
        merged.findings.extend(sub.findings)
        merged.items.extend(sub.items)
        merged.collection_errors.extend(sub.collection_errors)
    return merged


def test_unrelated_simultaneous_failures_stay_independent():
    """certificates/expired and directory-server/disk-space have no
    documented causal relationship. Both firing at once must NOT be merged
    into one story, and neither's `why` text should reference the other."""

    bundle = _merged_bundle("certificates/expired", "directory-server/disk-space")
    report = run_diagnosis(bundle)

    cert = next(d for d in report.diagnoses if d.pack_id == "certificates")
    ds = next(d for d in report.diagnoses if d.pack_id == "directory-server")

    priorities = {cert.priority, ds.priority}
    assert PriorityBucket.RELATED_SYMPTOM not in priorities, (
        "an unrelated pack pair must never be demoted to RELATED_SYMPTOM of each other"
    )
    assert "directory-server" not in cert.why.lower()
    assert "certificates" not in ds.why.lower()
    # Both are real, independent problems - both must be surfaced, not dropped.
    assert cert.priority in (PriorityBucket.PRIMARY, PriorityBucket.SECONDARY_INDEPENDENT)
    assert ds.priority in (PriorityBucket.PRIMARY, PriorityBucket.SECONDARY_INDEPENDENT)


def test_documented_causal_link_is_recognized():
    """dns/named-down and kerberos/dns-discovery both firing together is
    exactly the documented DNS -> Kerberos causal chain: the kerberos
    diagnosis must be demoted to RELATED_SYMPTOM, not treated as a second,
    independent primary problem."""

    bundle = _merged_bundle("dns/named-down", "kerberos/dns-discovery")
    report = run_diagnosis(bundle)

    dns_diag = next(d for d in report.diagnoses if d.pack_id == "dns" and d.rule_id == "named-service-down")
    kerberos_diag = next(d for d in report.diagnoses if d.pack_id == "kerberos")

    assert dns_diag.priority == PriorityBucket.PRIMARY
    assert kerberos_diag.priority == PriorityBucket.RELATED_SYMPTOM
    assert "dns" in kerberos_diag.why.lower()


def test_benign_upstream_diagnosis_does_not_cause_a_demotion():
    """Found in adversarial review: correlate.py used to demote a diagnosis
    whenever ANY diagnosis existed in an upstream pack, even a benign,
    WARNING-severity one (e.g. replication conflicts, which the pack's own
    docs say mean replication IS working). certificates/ambiguous declares
    upstream_candidates=["replication"], so merging it with
    replication/conflicting (a low-severity, non-problem finding) must NOT
    demote the certificate diagnosis to RELATED_SYMPTOM."""

    bundle = _merged_bundle("certificates/ambiguous", "replication/conflicting")
    report = run_diagnosis(bundle)

    cert_diagnoses = [d for d in report.diagnoses if d.pack_id == "certificates"]
    assert cert_diagnoses, "expected at least one certificates diagnosis from the ambiguous fixture"
    for d in cert_diagnoses:
        assert d.priority != PriorityBucket.RELATED_SYMPTOM, (
            f"{d.diagnosis_id} was wrongly demoted by a benign replication-conflicts finding"
        )


def test_merging_two_healthy_packs_stays_healthy():
    bundle = _merged_bundle("replication/healthy", "certificates/healthy")
    report = run_diagnosis(bundle)
    assert report.diagnoses == []
    assert report.overall_status.value == "HEALTHY"


@pytest.mark.parametrize(
    "fixture_a,fixture_b",
    [
        ("replication/peer-unreachable", "dns/srv-missing"),
        ("directory-server/permissions", "certificates/ambiguous"),
    ],
)
def test_every_evidence_ref_traces_to_the_merged_bundle(fixture_a, fixture_b):
    """No rule may cite evidence that doesn't actually exist in the bundle it
    was given - this is re-checked against a merged, cross-pack bundle
    specifically because that's the scenario most likely to expose a rule
    that accidentally grabbed evidence via a too-broad query."""

    bundle = _merged_bundle(fixture_a, fixture_b)
    report = run_diagnosis(bundle)

    finding_ids = {f.finding_id for f in bundle.findings}
    item_ids = {i.item_id for i in bundle.items}

    for diagnosis in report.diagnoses:
        for ref in list(diagnosis.evidence_for) + list(diagnosis.evidence_against):
            valid_ids = finding_ids if ref.kind == "finding" else item_ids
            assert ref.evidence_id in valid_ids, (
                f"{diagnosis.diagnosis_id} cites {ref.kind}={ref.evidence_id!r} which is not in the bundle"
            )
