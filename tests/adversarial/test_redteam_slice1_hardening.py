"""Slice 1 hardening: the fresh false-diagnosis red team's reproductions (fixtures under tests/fixtures/redteam,
CONSTRUCTED). Each asserts the outcome that is true, not merely "not what it was"."""

from __future__ import annotations

import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence, healthcheck_coverage_gap
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_results

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "redteam"


def run(name):
    return run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))


def by_title(report, needle):
    return [d for d in report.diagnoses if needle in d.title]


def primary(report):
    return next(d for d in report.diagnoses if d.priority.value == "PRIMARY_PROBLEM")


@pytest.mark.parametrize("name,root", [
    ("p1r-real-healthy-plus-named-aci", "named failed to start"),
    ("p1-named-aci-plus-cscfg", "named failed to start"),
    ("p2r-real-healthy-plus-ra-desync", "RA agent certificate"),
    ("p2-ra-desync-plus-cscfg", "RA agent certificate"),
    ("p12-repl-peer-down-plus-tmp-and-cscfg", "Replication agreement broken"),
])
def test_a_tomcat_file_mode_warning_never_outranks_or_demotes_a_real_root_cause(name, root):
    report = run(name)
    assert root in primary(report).title
    for d in by_title(report, root):
        assert d.priority.value != "RELATED_SYMPTOM"
    for d in by_title(report, "File ownership/mode mismatch"):
        assert d.priority.value != "PRIMARY_PROBLEM"


def test_an_undiagnosed_critical_finding_outranks_a_warning_level_file_mode():
    report = run("p3-ca-chain-expired-plus-cscfg")
    assert primary(report).status.value != "DIAGNOSED"  # the expired CA chain is not explained by any rule
    assert by_title(report, "File ownership/mode mismatch")[0].priority.value == "SECONDARY_INDEPENDENT_PROBLEM"


@pytest.mark.parametrize("name", ["p4c-clock-skew-keytab-ok", "p4-clock-skew-other-client"])
def test_another_clients_kdc_skew_line_is_not_this_hosts_clock_skew(name):
    report = run(name)
    assert not [d for d in by_title(report, "clock skew") if d.status.value == "DIAGNOSED"]


@pytest.mark.parametrize("name", ["p6-named-stopped-srv-error", "p6-named-stopped-srv-warning"])
def test_stopped_named_is_the_cause_and_records_are_its_symptom(name):
    report = run(name)
    assert "named" in primary(report).title and "not running" in primary(report).title
    for d in by_title(report, "DNS record(s)"):
        assert d.priority.value == "RELATED_SYMPTOM"


@pytest.mark.parametrize("name", ["p5c-pki-down-certmonger", "p5d-pki-down-certmonger-hyphen", "p5-pki-down-certmonger-connect"])
def test_stopped_local_ca_is_not_blamed_on_the_network(name):
    report = run(name)
    assert "not running" in primary(report).title and "tomcatd" in primary(report).title
    assert not by_title(report, "over the network")
    assert primary(report).severity.value == "CRITICAL"  # pki_tomcatd is a core service (both spellings)


def test_kdc_unreachable_with_dirsrv_down_is_a_symptom_of_dirsrv():
    report = run("p16-dirsrv-down-kdc-unreach")
    assert "dirsrv" in primary(report).title
    for d in by_title(report, "no KDC could be found"):
        assert d.priority.value == "RELATED_SYMPTOM"


def test_services_only_live_output_is_not_full_coverage():
    only_services = parse_healthcheck_results(
        [{"source": "ipahealthcheck.meta.services", "check": "dirsrv", "result": "SUCCESS", "kw": {}}], command="t", live=True)
    assert healthcheck_coverage_gap(only_services)
    full = parse_healthcheck_results(
        [{"source": s, "check": "C", "result": "SUCCESS", "kw": {}} for s in
         ("ipahealthcheck.meta.services", "ipahealthcheck.ds.replication", "ipahealthcheck.ipa.certs")], command="t", live=True)
    assert healthcheck_coverage_gap(full) is None


def test_services_only_replay_fixture_is_documented_limitation():
    # Replay fixtures are CONSTRUCTED and often minimal: the coverage rule applies to live runs only
    # (docs/limitations). This pins the current replay behaviour so any change is deliberate.
    assert run("p15-only-meta-services").overall_status.value == "HEALTHY"


def test_live_services_only_output_is_never_healthy(monkeypatch):
    import json

    from tests.adversarial import test_false_reassurance as fr

    only_services = json.dumps([fr._entry("ipahealthcheck.meta.services", "dirsrv", "SUCCESS")])
    fr._install(monkeypatch, healthcheck=(0, only_services, ""))
    report = fr._diagnose()
    assert report.overall_status.value != "HEALTHY"
    assert report.evidence_completeness.level != "complete"
    assert any(u.collector == "ipa-healthcheck-coverage" for u in report.evidence_completeness.unverified)


def test_when_healthcheck_gives_nothing_ipa_diagnose_names_stopped_units_itself(monkeypatch):
    import io
    import subprocess

    from rich.console import Console

    from ipa_diagnose.render.console import render_report
    from tests.adversarial import test_false_reassurance as fr

    def systemctl(args):
        unit = args[-1]
        if unit == "named-pkcs11.service":  # does not exist on this system: never listed
            return (0, "LoadState=not-found\nActiveState=inactive\n", "")
        return (0, f"LoadState=loaded\nActiveState={'inactive' if unit == 'named.service' else 'active'}\n", "")

    fr._install(monkeypatch, healthcheck=subprocess.TimeoutExpired(["ipa-healthcheck"], 120), extra={"systemctl": systemctl})
    report = fr._diagnose()
    assert report.overall_status.value == "UNKNOWN"
    assert report.service_states.get("named.service") == "inactive"
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=200, color_system=None))
    text = buf.getvalue()
    assert "named.service: inactive" in text and "NOT a healthy result" in text and "No problem was observed" not in text
    assert "named-pkcs11" not in text


def test_certmonger_started_by_healthcheck_is_disclosed(monkeypatch):
    import io

    from rich.console import Console

    from ipa_diagnose.render.console import render_report
    from tests.adversarial import test_false_reassurance as fr

    calls = []

    def systemctl(args):
        calls.append(args[-1])
        # stopped before ipa-healthcheck ran, running afterwards (ipalib starts it)
        state = "inactive" if calls.count("certmonger.service") == 1 else "active"
        return (0, f"LoadState=loaded\nActiveState={state}\n", "")

    fr._install(monkeypatch, extra={"systemctl": systemctl})
    report = fr._diagnose()
    assert any("certmonger was not running" in s for s in report.side_effects)
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=200, color_system=None))
    assert "ipa-diagnose itself changed nothing" in " ".join(buf.getvalue().split())


def test_certmonger_restarted_by_healthcheck_is_not_reported_as_a_current_outage(monkeypatch):
    from tests.adversarial import test_false_reassurance as fr

    calls = []

    def systemctl(args):
        calls.append(args[-1])
        state = "inactive" if calls.count("certmonger.service") == 1 else "active"
        return (0, f"LoadState=loaded\nActiveState={state}\n", "")

    hc = __import__("json").dumps([fr._entry("ipahealthcheck.meta.services", "certmonger", "ERROR", "certmonger: not running"),
                                   fr._entry("ipahealthcheck.ds.replication", "ReplicationCheck", "SUCCESS"),
                                   fr._entry("ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", "SUCCESS")])
    fr._install(monkeypatch, healthcheck=(0, hc, ""), extra={"systemctl": systemctl})
    report = fr._diagnose()
    d = next(x for x in report.diagnoses if "certmonger" in x.title)
    assert d.severity.value == "WARNING" and "running now" in d.why
