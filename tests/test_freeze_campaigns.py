"""Integrated freeze campaign: product-wide invariants swept over EVERY recorded scenario of every surface.

The per-slice tests pin each scenario to its own expected answer. These sweeps add what only holds across the whole
product: whatever the scenario, no surface offers a fix for a symptom, an unknown or a non-local cause; every offered
fix is complete (steps with expected results, rollback, verification); nothing that could not be checked is
reported as healthy, passed or resolved; recorded evidence never passes as live.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ipa_diagnose.cli import main
from tests.client import helpers as CH
from tests.client import scenarios as CS
from tests.replication import helpers as RH
from tests.replication import scenarios as RS
from tests.replication.scenarios import IPA01, IPA02, IPA03, Lab

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SERVER_FIXTURES = sorted(p.parent for p in FIXTURES.rglob("healthcheck.json"))
SERVER_PROGRAMS = {"systemctl", "chmod", "chown", "chgrp", "chronyc", "getcert"}
CLIENT_PROGRAMS = {"systemctl", "sss_cache", "sssctl"}


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))


def test_the_server_sweep_is_not_empty():
    assert len(SERVER_FIXTURES) >= 100


@pytest.mark.parametrize("fx", SERVER_FIXTURES, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_server_diagnosis_invariants_over_every_recorded_fixture(capsys, fx):
    code = main(["--replay", str(fx), "--json", "--no-ai"])
    doc = json.loads(capsys.readouterr().out)
    diags = {d["diagnosis_id"]: d for d in doc["diagnoses"]}
    status = doc["overall_status"]
    assert code == {"HEALTHY": 0, "DEGRADED": 1, "CRITICAL": 2, "UNKNOWN": 3, "NOT_FULLY_VERIFIED": 4}[status]
    if status == "HEALTHY":  # nothing claimed healthy while anything is diagnosed, undiagnosed or missing
        assert not doc["diagnoses"] and not doc.get("undiagnosed_findings")
    for r in (doc.get("v2") or {}).get("resolutions") or []:
        if r["status"] != "OFFERED":
            assert not r.get("steps"), f"{r['diagnosis_id']}: a withheld/absent fix must carry no commands"
            continue
        d = diags[r["diagnosis_id"]]
        assert d["status"] == "DIAGNOSED", f"fix offered for a {d['status']} diagnosis"
        assert d["priority"] != "RELATED_SYMPTOM", "fix offered for a symptom of another problem"
        assert r["steps"] and r["risk"] and r["verify"] and r["rollback"] and r["what_changes"]
        for s in r["steps"]:
            assert s["argv"][0] in SERVER_PROGRAMS and s["expected"] and s["run_on"] == "local"
            assert s["argv"][0] != "systemctl" or s["argv"][1] == "start"
            assert "ipactl" not in s["argv"]
        for c in r.get("checked") or []:  # recorded evidence never passes as a check run now
            assert c["source"] == "recorded"


@pytest.mark.parametrize("fx", SERVER_FIXTURES, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_no_ungated_state_changing_command_reaches_the_console(capsys, monkeypatch, fx):
    """Freeze SME + resolution-safety reviews: v0.1.3 pack actions that are not SAFE (ipa-getkeytab, ipa-cert-fix,
    certutil -A, systemctl restart named-pkcs11, ...) were printed for diagnoses no procedure covers. Whatever the
    fixture, a non-SAFE legacy command appears in the console only if it is also an offered, gated fix step."""

    monkeypatch.setenv("COLUMNS", "400")  # no wrapping inside a command
    main(["--replay", str(fx), "--json", "--no-ai"])
    doc = json.loads(capsys.readouterr().out)
    gated = {s["command"] for r in (doc.get("v2") or {}).get("resolutions") or [] if r["status"] == "OFFERED"
             for s in r.get("steps") or []}
    risky = {a["command"] for d in doc["diagnoses"] for a in d.get("actions") or []
             if a.get("command") and a.get("risk") != "SAFE"} - gated
    for extra in ([], ["--details"]):
        main(["--replay", str(fx), "--no-ai", *extra])
        out = " ".join(capsys.readouterr().out.split())
        leaked = [c for c in risky if " ".join(c.split()) in out]
        assert not leaked, (extra, leaked)


CLIENT_CASES = [(n, root) for n in sorted(CS.SCENARIOS) for root in (True, False)]


@pytest.mark.parametrize("name,root", CLIENT_CASES, ids=[f"{n}-{'root' if r else 'nonroot'}" for n, r in CLIENT_CASES])
def test_client_invariants_over_every_scenario(name, root):
    def as_run(d):  # a real non-root run records that it is not root (the procedure prerequisite reads it)
        if not root:
            d[CS.key("host.privilege")]["fields"].update(is_root=False)

    r = CH.run(name, is_root=root, mutate=as_run)
    roles = {d.code: d.role for d in r.diagnoses}
    assert r.authentication.state != "PASS" and r.runtime.state != "PASS"  # no credential, no login is ever tried
    for code, res in CH.offered(r).items():
        assert root, "a fix is never offered without root (its checks could not run)"
        assert roles.get(code) in ("PRIMARY", "INDEPENDENT"), f"{code}: fix offered for a {roles.get(code)}"
        for s in res.steps:
            assert s.argv[0] in CLIENT_PROGRAMS and s.expected and s.run_on == "local"
            assert not any("/var/lib/sss" in a for a in s.argv) and "initctl" not in s.argv[0]
        assert res.rollback or res.risk == "LOW"
    if r.status in ("HEALTHY", "HEALTHY_WITH_WARNINGS"):
        assert not [d for d in r.diagnoses if d.role in ("PRIMARY", "INDEPENDENT", "UNDIAGNOSED", "CONTRADICTING")]
    # a check that could not run (UNKNOWN) is never, on its own, a cause
    unknown_steps = {rec.step_id for rec in r.trace.records if rec.outcome.value == "UNKNOWN"}
    for d in r.diagnoses:
        if d.role in ("PRIMARY", "INDEPENDENT") and d.confidence == "HIGH":
            assert set(d.evidence) - unknown_steps, f"{d.code} rests only on checks that could not run"


def _labs():
    yield "healthy", Lab()
    yield "local-kdc-stopped", Lab().local_kdc_stopped()
    yield "local-kdc-stopped-agreements-green", Lab().local_kdc_stopped(affect_agreements=False)
    yield "local-ds-stopped", Lab().unit("dirsrv")
    yield "local-ds-and-kdc-stopped", Lab().unit("dirsrv").unit("krb5kdc")
    yield "peer-ds-stopped", Lab().peer_ds_stopped(IPA02)
    yield "peer-unreachable", Lab().peer_unreachable(IPA02)
    yield "dns-broken", Lab().dns_broken(IPA02)
    yield "clock-skew", Lab().clock_skew(IPA02, 900)
    yield "clock-skew-small", Lab().clock_skew(IPA02, 12)
    yield "kerberos-clock", Lab().kerberos_failure(IPA02, bind_ok=False, bind_error_class="GSSAPI_CLOCK_SKEW")
    yield "server-not-found", Lab().kerberos_failure(IPA02, bind_ok=False, bind_error_class="GSSAPI_SERVER_NOT_FOUND")
    yield "ldap-49", Lab().kerberos_failure(IPA02, RS.INVALID_TEXT, bind_ok=False,
                                            bind_error_class="INVALID_CREDENTIALS")
    yield "reverse-local-error", Lab().set_reverse(IPA02, RS.LOCAL_ERROR_TEXT, suffix="domain")
    yield "reverse-invisible", Lab().set_reverse(IPA02, visible=False)
    yield "generation-mismatch", Lab().set_status(IPA02, RS.GENERATION_TEXT)
    yield "ca-only-generation", Lab().set_status(IPA02, RS.GENERATION_TEXT, suffix="ca")
    yield "access-denied", Lab().set_status(IPA02, RS.DENIED_TEXT, suffix="domain")
    yield "transport", Lab().set_status(IPA02, RS.TRANSPORT_TEXT)
    yield "unrecognized-status", Lab().set_status(IPA02, RS.WEIRD_TEXT)
    yield "keytab-unreadable", Lab(me=IPA03).keytab(owner="root", group="root", dirsrv_can_read=False)
    yield "ruv-candidate", Lab().ruv("domain", 9, "old.lab.test")
    yield "budget", Lab().many_agreements(9)
    yield "middle-two-causes", Lab(me=IPA02).local_kdc_stopped(affect_agreements=False).peer_ds_stopped(IPA03)
    yield "middle-two-peers", Lab(me=IPA02).peer_ds_stopped(IPA01).peer_unreachable(IPA03)


REPL_CASES = list(_labs())


def test_the_replication_sweep_is_not_empty():
    assert len(REPL_CASES) >= 10


def test_the_sweeps_reach_offered_fixes(capsys):
    """Guard against a vacuous sweep: each surface's sweep contains scenarios where a fix IS offered."""

    assert sum(bool(RH.offered(RH.run(lab, live=True))) for _n, lab in REPL_CASES) >= 4
    assert sum(bool(CH.offered(CH.run(n))) for n in CS.SCENARIOS) >= 3
    offered = 0
    for fx in SERVER_FIXTURES:
        main(["--replay", str(fx), "--json", "--no-ai"])
        doc = json.loads(capsys.readouterr().out)
        offered += any(r["status"] == "OFFERED" for r in (doc.get("v2") or {}).get("resolutions") or [])
    assert offered >= 5


@pytest.mark.parametrize("name,lab", REPL_CASES, ids=[n for n, _ in REPL_CASES])
def test_replication_invariants_over_every_scenario(name, lab):
    replay = RH.run(lab)
    assert not RH.offered(replay), "recorded (REPLAY) evidence never offers a replication fix"
    live = RH.run(lab, live=True)
    me = live.environment.get("host") if isinstance(live.environment, dict) else None
    roles = {d.key: d.role for d in live.diagnoses}
    for key, res in RH.offered(live).items():
        assert roles.get(key) in ("PRIMARY", "INDEPENDENT")
        assert me is None or key.endswith(f"server:{me}"), "a fix is printed only for THIS server"
        for s in res.steps:
            assert s.argv[:2] == ["systemctl", "start"] and len(s.argv) == 3 and s.expected
    for d in live.diagnoses:  # an unreachable peer is never called dead
        assert "dead" not in (d.title or "").lower().split()
