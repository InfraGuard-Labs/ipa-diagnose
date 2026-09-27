"""Support bundle content: fixed members, honest labels, no commands, canaries never survive, bounded, stable."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import tarfile

import pytest

from ipa_diagnose.bundle import archive, selftest
from ipa_diagnose.bundle.build import MEMBERS, TOP_DIR, build
from ipa_diagnose.engine.model import Action, RiskLevel
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.model import (
    CollectionError, EnvironmentInfo, EvidenceBundle, EvidenceItem, Finding, Provenance, Severity)
from ipa_diagnose.resolution.checks import ReplayRunner
from ipa_diagnose.resolution.engine import resolve_report

from tests.bundle.helpers import CANARIES, ROOT, all_text, canary_fixture, diagnose_replay

T0 = "2026-09-26T12:00:00Z"


def _json(built, name):
    return json.loads(built.members[name])


def _check(built, forbidden=()):
    selftest.check(built.members, built.sanitizer.originals(), forbidden)


def _live_bundle(findings, items=(), errors=(), host="ipa01.example.test"):
    ev = EvidenceBundle(hostname=host, collected_at=T0, findings=list(findings), items=list(items),
                        collection_errors=list(errors),
                        environment=EnvironmentInfo(distro="fedora", distro_version="43", freeipa_version="4.13.3-2.fc43"))
    report = run_diagnosis(ev)
    resolve_report(report, ReplayRunner(None))
    return ev, report


def _f(source, check, sev, msg="", fid=None, **kw):
    return Finding(finding_id=fid or f"{source}.{check}", source=source, check=check, severity=Severity(sev),
                   message=msg, keywords=dict(kw, msg=msg), provenance=Provenance(source="ipa-healthcheck", live=True),
                   raw={"result": sev, "when": "20260926120000Z"})


def test_fixed_members_manifest_and_checksums_agree():
    ev, report = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    b = build(ev, report, created_at=T0)
    _check(b)
    assert list(b.members) == list(MEMBERS)
    m = _json(b, "manifest.json")
    assert m["bundle_format"] == "ipa-diagnose-support-bundle" and m["bundle_schema_version"] == 1
    assert [e["name"] for e in m["members"]] == [n for n in MEMBERS if n not in ("manifest.json", "SHA256SUMS")]
    for e in m["members"]:
        assert e["sha256"] == hashlib.sha256(b.members[e["name"]]).hexdigest() and e["bytes"] == len(b.members[e["name"]])
    sums = dict(reversed(line.split("  ")) for line in b.members["SHA256SUMS"].decode().splitlines())
    assert set(sums) == set(MEMBERS) - {"SHA256SUMS"}
    assert all(hashlib.sha256(b.members[n]).hexdigest() == h for n, h in sums.items())
    assert "not a signature" in m["integrity"]


def test_replay_is_labelled_replay_everywhere_and_the_path_is_not_included(tmp_path):
    fx = canary_fixture(tmp_path)
    ev, report = diagnose_replay(fx)
    b = build(ev, report, created_at=T0)
    _check(b, [str(fx)])
    for name in MEMBERS:
        if name.endswith(".json"):
            assert _json(b, name)["source_mode"] == "REPLAY", name
    assert "REPLAY" in b.members["README.txt"].decode() and "LIVE -" not in b.members["README.txt"].decode()
    assert str(fx) not in all_text(b.members) and "canary-fixture" not in all_text(b.members)
    assert "<replay-fixture>" in b.members["evidence.json"].decode()


def test_live_evidence_is_labelled_live():
    ev, report = _live_bundle([_f("ipahealthcheck.meta.services", "dirsrv", "SUCCESS")])
    b = build(ev, report, created_at=T0)
    _check(b)
    assert _json(b, "manifest.json")["source_mode"] == "LIVE"
    assert all(_json(b, n)["source_mode"] == "LIVE" for n in MEMBERS if n.endswith(".json"))


def test_canary_secrets_and_identities_never_survive(tmp_path):
    fx = canary_fixture(tmp_path)
    ev, report = diagnose_replay(fx)
    b = build(ev, report, created_at=T0)
    _check(b, [str(fx)])
    text = all_text(b.members)
    for canary in CANARIES:
        assert canary.lower() not in text.lower(), canary
    red = _json(b, "redaction-report.json")
    assert red["secret_named_fields_removed"] >= 1 and sum(red["redacted_values"].values()) >= 8
    assert {"HOST", "DOMAIN", "REALM", "SUFFIX", "USER", "IP"} <= set(red["pseudonymized_identifiers"])
    # relationships kept: the agreement and the peer are the same pseudonym everywhere
    topo = _json(b, "topology.json")
    assert topo["local_host"] == "HOST-001" and topo["agreements"][0]["to"] == "HOST-002"
    assert "meToHOST-002" in b.members["healthcheck.json"].decode()
    assert "\x1b" not in text and "‮" not in text


def test_the_archive_itself_carries_no_canary(tmp_path):
    fx = canary_fixture(tmp_path)
    ev, report = diagnose_replay(fx)
    b = build(ev, report, created_at=T0)
    data = archive.make_archive(b.members, T0)
    raw = gzip.decompress(data)
    for canary in CANARIES:
        assert canary.encode().lower() not in raw.lower()


def test_fix_commands_are_omitted_and_never_presented_as_safe_to_run():
    ev, report = diagnose_replay(ROOT / "resolution" / "service-not-running")
    b = build(ev, report, created_at=T0)
    _check(b)
    rep = _json(b, "report.json")
    r = rep["resolutions"][0]
    assert r["status"] == "OFFERED" and r["procedure_id"] == "proc.service.start-stopped-service"
    assert r["tier"] == "BUILT_IN_VERIFIED" and r["commands_omitted"] is True
    assert all(set(s) == {"id", "text", "risk", "run_on"} for s in r["steps"])
    assert r["evaluated_against"] == "RECORDED EVIDENCE"
    assert "systemctl start" not in all_text(b.members)
    assert "Re-run ipa-diagnose on the machine you intend to change" in rep["note"]
    assert "never a fix for another machine" in b.members["README.txt"].decode()


def test_withheld_and_no_procedure_resolutions_keep_their_reasons():
    ev, report = diagnose_replay(ROOT / "resolution" / "ds-certificate-expiring")
    b = build(ev, report, created_at=T0)
    ids = {r["status"] for r in _json(b, "report.json")["resolutions"]}
    assert ids  # the resolution record is carried whatever its status
    for r in _json(b, "report.json")["resolutions"]:
        if r["status"] != "OFFERED":
            assert r["reasons"], r


def test_only_read_only_pack_actions_keep_their_command():
    ev, report = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    d = report.diagnoses[0]
    d.actions = [Action("look", RiskLevel.SAFE, command="ipa-replica-manage list <host>"),
                 Action("change", RiskLevel.CAUTION, command="ipa-replica-manage re-initialize --from <peer>"),
                 Action("destroy", RiskLevel.HIGH_RISK, command="ipa-replica-manage del <peer> --force")]
    b = build(ev, report, created_at=T0)
    acts = _json(b, "report.json")["diagnoses"][0]["actions"]
    assert acts[0]["command"] == "ipa-replica-manage list <host>" and not acts[0]["command_omitted"]
    assert acts[1]["command"] is None and acts[1]["command_omitted"] and acts[2]["command_omitted"]
    assert "re-initialize" not in all_text(b.members) and "--force" not in all_text(b.members)


def test_ai_text_is_never_part_of_a_bundle():
    ev, report = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    b = build(ev, report, created_at=T0)
    assert "ai_explanation" not in b.members["report.json"].decode()


def test_undiagnosed_and_future_checks_stay_visible():
    ev, report = _live_bundle([
        _f("ipahealthcheck.zzz.future", "FutureError", "ERROR", "something new failed", fid="f1"),
        _f("ipahealthcheck.zzz.future", "FutureWarning", "WARNING", "something new looks odd", fid="f2"),
        _f("ipahealthcheck.ds.replication", "ReplicationCheck", "SUCCESS"),
        _f("ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", "SUCCESS")])
    b = build(ev, report, created_at=T0)
    hc = {f["finding_id"]: f for f in _json(b, "healthcheck.json")["findings"]}
    # an unknown ERROR is claimed by the "unexplained findings" diagnosis; an unknown WARNING is listed as undiagnosed
    assert hc["f1"]["check_known_to_this_build"] is False and hc["f1"]["severity"] == "ERROR"
    assert hc["f1"]["diagnosed_by"] == ["healthcheck.unexplained-findings"]
    assert hc["f2"]["undiagnosed"] is True and hc["f2"]["check_known_to_this_build"] is False
    assert [f["severity"] for f in _json(b, "healthcheck.json")["findings"]][:2] != ["SUCCESS", "SUCCESS"]
    rep = _json(b, "report.json")
    assert rep["undiagnosed_count"] == 1 and rep["undiagnosed_findings"][0]["finding_id"] == "f2"
    assert "healthcheck.unexplained-findings" in [d["diagnosis_id"] for d in rep["diagnoses"]]
    assert rep["overall_status"] != "HEALTHY"


def test_unknown_status_and_collection_errors_are_explained():
    ev, report = _live_bundle([], errors=[
        CollectionError(collector="ipa-healthcheck", message="ipa-healthcheck is not installed or not on PATH"),
        CollectionError(collector="journal_dirsrv", message="journalctl: Permission denied", permission_related=True)])
    b = build(ev, report, created_at=T0)
    _check(b)
    assert _json(b, "manifest.json")["overall_status"] == "UNKNOWN"
    ce = _json(b, "collection-errors.json")
    cats = {e["collector"]: e for e in ce["errors"]}
    assert cats["ipa-healthcheck"]["category"] == "not_available" and cats["ipa-healthcheck"]["leaves_unverified"]
    assert cats["journal_dirsrv"]["category"] == "permission"
    assert ce["completeness"] == "insufficient"


def test_not_fully_verified_is_carried_not_upgraded():
    ev, report = _live_bundle([_f("ipahealthcheck.meta.services", "dirsrv", "SUCCESS")],
                              errors=[CollectionError(collector="journal_dirsrv", message="journalctl timed out")])
    b = build(ev, report, created_at=T0)
    assert report.overall_status.value == "NOT_FULLY_VERIFIED"  # nothing wrong found, but not everything collected
    assert _json(b, "manifest.json")["overall_status"] == "NOT_FULLY_VERIFIED"
    assert _json(b, "report.json")["fully_verified"] is False


def test_structured_items_drop_raw_output_tickets_and_serials():
    items = [
        EvidenceItem("kerberos_client.klist", "klist_ticket", "klist ticket cache for admin@EXAMPLE.TEST (1 ticket(s))",
                     data={"principal": "admin@EXAMPLE.TEST", "tickets": ["09/26/26 krbtgt/EXAMPLE.TEST@EXAMPLE.TEST"],
                           "raw": "Ticket cache: KCM:0\nDefault principal: admin@EXAMPLE.TEST"}),
        EvidenceItem("kerberos_client.clock_sync", "clock_sync", "clock", data={"method": "chronyc", "offset_seconds": 0.1,
                                                                              "raw": "Reference ID: 10.1.1.1 (ntp.corp.internal)"}),
        EvidenceItem("certmonger.1", "certmonger_request", "req", data={"request_id": "1", "serial": 123456789,
                                                                      "subject": "CN=ipa01.example.test,O=EXAMPLE.TEST"}),
    ]
    ev, report = _live_bundle([_f("ipahealthcheck.meta.services", "dirsrv", "SUCCESS")], items=items)
    b = build(ev, report, created_at=T0)
    _check(b)
    ev_json = {i["kind"]: i["data"] for i in _json(b, "evidence.json")["items"]}
    assert ev_json["klist_ticket"] == {"principal": "admin@REALM-001", "ticket_count": 1}
    assert "raw" not in ev_json["clock_sync"] and "serial" not in ev_json["certmonger_request"]
    assert ev_json["certmonger_request"]["subject"] == "CN=HOST-001,O=REALM-001"
    assert "10.1.1.1" not in all_text(b.members) and "ntp.corp" not in all_text(b.members)


def test_resource_limits_truncate_honestly_and_keep_failures_first():
    findings = [_f("ipahealthcheck.ipa.files", "IPAFileCheck", "SUCCESS", fid=f"s{i}") for i in range(600)]
    findings += [_f("ipahealthcheck.zzz.x", f"C{i}", "ERROR", "m" * 3000, fid=f"e{i}") for i in range(700)]
    ev, report = _live_bundle(findings)
    b = build(ev, report, created_at=T0)
    _check(b)
    hc = _json(b, "healthcheck.json")
    assert len(hc["findings"]) == 1000
    assert sum(1 for f in hc["findings"] if f["severity"] == "ERROR") == 700  # every failure kept
    m = _json(b, "manifest.json")
    assert m["content_complete"] is False and m["truncation"]["entries_dropped_by_limits"]["findings"] == 300
    assert m["truncation"]["strings_truncated"] >= 700
    assert all(len(f.get("message", "")) <= 2000 for f in hc["findings"])


def test_same_input_gives_the_same_bundle():
    ev, report = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    a, b = build(ev, report, created_at=T0), build(ev, report, created_at=T0)
    assert a.members == b.members
    assert archive.make_archive(a.members, T0) == archive.make_archive(b.members, T0)
    # two independent runs differ only in the declared volatile fields
    ev2, report2 = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    c = build(ev2, report2, created_at="2026-09-27T00:00:00Z")
    for name in ("environment.json", "topology.json", "evidence.json", "healthcheck.json", "redaction-report.json"):
        assert a.members[name] == c.members[name], name
    ra, rc = _json(a, "report.json"), _json(c, "report.json")
    ra.pop("generated_at"), rc.pop("generated_at")
    assert ra == rc


def test_archive_metadata_is_fixed_and_anonymous():
    ev, report = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    b = build(ev, report, created_at=T0)
    data = archive.make_archive(b.members, T0)
    assert data[:2] == b"\x1f\x8b" and data[3] & 0x08 == 0 and data[4:8] == b"\x00\x00\x00\x00"  # no name, mtime 0
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode="r:") as tar:
        infos = tar.getmembers()
    assert [ti.name for ti in infos] == [f"{TOP_DIR}/{n}" for n in MEMBERS]
    for ti in infos:
        assert ti.isreg() and ti.mode == 0o644 and ti.uid == ti.gid == 0 and ti.uname == ti.gname == ""
        assert ti.mtime == 1790424000 and not ti.pax_headers


def test_verification_context_is_context_only():
    ev, report = diagnose_replay(ROOT / "resolution" / "service-not-running")
    previous = {"generated_at": "2026-09-25T10:00:00Z", "hostname": "ipa01.lab.test", "overall_status": "CRITICAL",
                "diagnoses": [{"diagnosis_id": "healthcheck.service-not-running-dirsrv", "status": "DIAGNOSED",
                               "priority": "PRIMARY_PROBLEM"}],
                "v2": {"verify_baseline": {"schema": 1, "fixes": [
                    {"diagnosis_id": "healthcheck.service-not-running-dirsrv",
                     "procedure_id": "proc.service.start-stopped-service", "bindings": {"unit": "dirsrv@LAB-TEST.service"},
                     "procedure_digest": "d" * 64, "criteria_digest": "c" * 64}]}, "carried_diagnoses": []}}
    b = build(ev, report, previous=previous, created_at=T0)
    _check(b)
    v = _json(b, "verification.json")
    assert v["context_only"] is True and v["baseline_present"] is True and v["baseline_host"] == "HOST-001"
    assert v["fixes_awaiting_verify"] == [{"diagnosis_id": "healthcheck.service-not-running-dirsrv",
                                           "procedure_id": "proc.service.start-stopped-service"}]
    text = b.members["verification.json"].decode()
    assert "bindings" not in text and "digest" not in text and "LAB-TEST" not in text


def test_hostile_text_is_neutralised_and_the_bundle_still_builds():
    evil = "\x1b]0;pwned\x07\x1b[2J‮gnp.exe​\x00\x07 ok " + "\ud800".encode("utf-8", "surrogatepass").decode(
        "utf-8", "replace")
    ev, report = _live_bundle([_f("ipahealthcheck.zzz.evil", "Evil", "ERROR", evil, fid="x"),
                               _f("ipahealthcheck.ds.replication", "ReplicationCheck", "SUCCESS"),
                               _f("ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", "SUCCESS")])
    b = build(ev, report, created_at=T0)
    _check(b)
    text = all_text(b.members)
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f​‮]", text)


@pytest.mark.parametrize("fixture", [
    "real-freeipa-capture/healthy", "real-freeipa-capture/dirsrv-down", "real-freeipa-capture/certmonger-stopped",
    "resolution/file-permissions", "resolution/clock-skew", "replication/stale-ruv-removed-replica",
])
def test_real_and_resolution_fixtures_build_and_pass_the_self_test(fixture):
    ev, report = diagnose_replay(ROOT / fixture)
    b = build(ev, report, created_at=T0)
    _check(b, [str(ROOT / fixture)])
    assert _json(b, "manifest.json")["overall_status"] == report.overall_status.value
