"""Runs the real pipeline against real ipa-healthcheck output captured from
an actual FreeIPA server (see tests/fixtures/real-freeipa-capture/README.md
for exactly how). This is a genuinely different validation tier from the
hand-authored fixtures used everywhere else: those encode researched,
documented failure signatures; these are unedited real output. Assertions
here are deliberately loose (no crash, sane shape, the one known-correct
finding) rather than pinned to every diagnosis, since real server output
will legitimately vary run to run - the value of this test is "the real
pipeline survives real input," not "this exact snapshot is permanent."
"""

import pathlib

from ipa_diagnose.engine.model import DiagnosisStatus
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

FIXTURES_ROOT = pathlib.Path(__file__).parent.parent / "fixtures" / "real-freeipa-capture"


def test_real_healthy_capture_parses_and_diagnoses_without_crashing():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "healthy"))
    assert len(bundle.findings) > 200  # sanity: the real capture actually loaded
    # This real capture's WARNING-level DNS findings (no --setup-dns was
    # used) correctly stage the dns pack's targeted collectors - which then
    # correctly report a CollectionError since no dns_lookup/journal_named
    # fixture file exists for this real-capture directory. That's the
    # staged-collection design working as intended, not a pipeline failure.

    report = run_diagnosis(bundle)
    assert report is not None
    # Real, un-doctored output must never trip the DIAGNOSED+low-confidence
    # guardrail (Diagnosis.__post_init__ would already raise if it did).
    for d in report.diagnoses:
        if d.status == DiagnosisStatus.DIAGNOSED:
            assert d.confidence.level.value in ("HIGH", "MEDIUM")


def test_real_dirsrv_down_capture_parses_and_diagnoses_without_crashing():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "dirsrv-down"))
    assert len(bundle.findings) > 100
    assert bundle.collection_errors == []

    report = run_diagnosis(bundle)
    assert report is not None
    for d in report.diagnoses:
        if d.status == DiagnosisStatus.DIAGNOSED:
            assert d.confidence.level.value in ("HIGH", "MEDIUM")


def test_critical_finding_with_no_msg_key_is_not_silently_empty():
    """The specific real-world entry that surfaced the kw.msg-vs-exception
    parsing gap: confirm the CRITICAL IPAauthzdatapacCheck finding from the
    real capture keeps its exception text as its message, end to end
    through collect_evidence (not just the unit-level healthcheck.py test)."""

    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "dirsrv-down"))
    critical_trust_findings = [
        f for f in bundle.findings if f.check == "IPAauthzdatapacCheck" and f.severity.value == "CRITICAL"
    ]
    assert critical_trust_findings, "expected the real capture to still contain this CRITICAL finding"
    assert critical_trust_findings[0].message, "message must not be silently empty for a CRITICAL result"
    assert "ldap2 is not connected" in critical_trust_findings[0].message
