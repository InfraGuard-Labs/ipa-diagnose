"""Malformed/hostile/oversized-input robustness: none of these should crash
the engine, and none should produce a confident false DIAGNOSED result -
"unknown is better than wrong" applies to garbage input too, not just
genuinely ambiguous evidence.
"""

import json
import pathlib

from ipa_diagnose.engine.model import DiagnosisStatus
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_json_text, parse_healthcheck_results


def test_unknown_future_check_id_is_ignored_not_crashed():
    raw = parse_healthcheck_json_text(
        json.dumps(
            [
                {
                    "source": "ipahealthcheck.future.quantumcheck",
                    "check": "QuantumEntanglementCheck",
                    "result": "CRITICAL",
                    "uuid": "x",
                    "kw": {"msg": "a check that does not exist yet in 2026"},
                }
            ]
        )
    )
    findings = parse_healthcheck_results(raw, command="test", live=False)
    assert len(findings) == 1

    from ipa_diagnose.evidence.model import EvidenceBundle

    bundle = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=findings)
    report = run_diagnosis(bundle)
    # No pack claims this source: no crash and definitely no guessed
    # diagnosis from an unrelated pack. But a CRITICAL finding must never
    # VANISH either (live-discovered: a stopped Directory Server's ERROR/
    # CRITICAL findings were dropped) - it surfaces as ONE honest UNKNOWN
    # that quotes the raw finding and claims no root cause.
    from ipa_diagnose.engine.model import DiagnosisStatus

    assert [d.rule_id for d in report.diagnoses] == ["unexplained-findings"]
    only = report.diagnoses[0]
    assert only.pack_id == "healthcheck"
    assert only.status == DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE
    assert "QuantumEntanglementCheck" in only.why


def test_huge_healthcheck_output_does_not_crash_or_hang(tmp_path):
    huge = [
        {
            "source": "ipahealthcheck.ds.replication",
            "check": "ReplicationCheck",
            "result": "SUCCESS",
            "uuid": f"id-{i}",
            "kw": {},
        }
        for i in range(5000)
    ]
    fixture_dir = tmp_path / "huge"
    fixture_dir.mkdir()
    (fixture_dir / "healthcheck.json").write_text(json.dumps(huge), encoding="utf-8")

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    assert len(bundle.findings) == 5000
    report = run_diagnosis(bundle)
    assert report.overall_status.value == "HEALTHY"


def test_malformed_json_fixture_becomes_collection_error_not_crash(tmp_path):
    fixture_dir = tmp_path / "malformed"
    fixture_dir.mkdir()
    (fixture_dir / "healthcheck.json").write_text("{not valid json", encoding="utf-8")

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    assert bundle.findings == []
    assert any("ipa-healthcheck" in e.collector for e in bundle.collection_errors)
    report = run_diagnosis(bundle)
    assert report.diagnoses == []  # garbage evidence -> no diagnoses, not a guess


def test_non_array_json_fixture_is_a_collection_error():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        fixture_dir = pathlib.Path(tmp)
        (fixture_dir / "healthcheck.json").write_text('{"oops": "not an array"}', encoding="utf-8")
        bundle = collect_evidence(replay_dir=str(fixture_dir))
        assert bundle.findings == []
        assert bundle.collection_errors


def test_malformed_collector_fixture_is_a_collection_error_not_crash(tmp_path):
    fixture_dir = tmp_path / "bad-collector"
    fixture_dir.mkdir()
    (fixture_dir / "healthcheck.json").write_text(
        json.dumps(
            [
                {
                    "source": "ipahealthcheck.ipa.certs",
                    "check": "IPACertmongerExpirationCheck",
                    "result": "ERROR",
                    "uuid": "x",
                    "kw": {"msg": "expired"},
                }
            ]
        ),
        encoding="utf-8",
    )
    (fixture_dir / "certmonger.json").write_text("[this is not json", encoding="utf-8")

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    assert any(e.collector == "certmonger" for e in bundle.collection_errors)
    # Must still complete a full diagnosis run despite the broken collector.
    report = run_diagnosis(bundle)
    assert report is not None


def test_hostile_unicode_and_control_characters_do_not_crash_rendering():
    from ipa_diagnose.evidence.model import EvidenceBundle, Finding, Provenance, Severity
    from ipa_diagnose.privacy.redact import redact_text

    hostile = "replication error \x00\x1b[31m‮﻿" + "A" * 10000
    result = redact_text(hostile)
    assert isinstance(result.redacted_text, str)

    finding = Finding(
        finding_id="f1",
        source="ipahealthcheck.ds.replication",
        check="ReplicationCheck",
        severity=Severity.CRITICAL,
        message=hostile,
        provenance=Provenance(source="ipa-healthcheck"),
    )
    bundle = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=[finding])
    report = run_diagnosis(bundle)
    assert report is not None  # must not raise


def test_diagnosed_status_never_appears_without_high_or_medium_confidence_across_full_engine():
    """A blanket, engine-wide sweep (not just the constructor unit test):
    run every pack against every existing fixture and confirm the invariant
    holds everywhere, not just in hand-written examples."""

    fixtures_root = pathlib.Path(__file__).parent.parent / "fixtures"
    checked = 0
    for meta_file in fixtures_root.rglob("meta.json"):
        fixture_dir = meta_file.parent
        bundle = collect_evidence(replay_dir=str(fixture_dir))
        report = run_diagnosis(bundle)
        for d in report.diagnoses:
            checked += 1
            if d.status == DiagnosisStatus.DIAGNOSED:
                assert d.confidence.level.value in ("HIGH", "MEDIUM"), (
                    f"{fixture_dir}: {d.diagnosis_id} is DIAGNOSED with {d.confidence.level.value} confidence"
                )
    assert checked > 0
