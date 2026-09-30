"""Whole-product consistency checks from the integrated freeze campaign (Slices 1-5 as one product).

- An offered fix shows each step's expected result in the default view of every surface that prints fixes (server
  diagnosis, client mode; replication mode already did): a printed procedure without its expected result (and, where
  the procedure states it, what a failure looks like) is not complete enough to follow without looking elsewhere.
- Every command's --help states its exit codes, including the ones only some paths produce (access --runtime: 5).
"""

from __future__ import annotations

import pathlib
import re

import pytest

from ipa_diagnose.cli import main
from tests.client import helpers as CH

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("COLUMNS", "200")


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_server_offered_fix_shows_the_expected_result_without_details(capsys):
    code = main(["--replay", str(FIXTURES / "resolution" / "service-not-running")])
    out = _flat(capsys.readouterr().out)
    assert code == 2
    assert "systemctl start dirsrv@LAB-TEST.service" in out
    assert "expected: the command returns without an error and dirsrv@LAB-TEST.service is active. If it fails, it " \
           "stays stopped and systemctl status shows why" in out
    assert "| risk MEDIUM" not in out  # the per-step risk stays a --details item (RISK is its own section)


def test_server_details_still_show_the_step_risk(capsys):
    main(["--replay", str(FIXTURES / "resolution" / "service-not-running"), "--details"])
    out = _flat(capsys.readouterr().out)
    assert "is active. If it fails, it stays stopped and systemctl status shows why | risk MEDIUM" in out


def test_client_offered_fix_shows_the_expected_result(capsys, tmp_path):
    fx = CH.write_checks(CH.scenario("sssd-stopped"), directory=tmp_path / "fx")
    code = main(["client", "--replay", str(fx), "--user", "alice", "--service", "sshd"])
    out = _flat(capsys.readouterr().out)
    assert code == 1
    assert "systemctl start sssd.service" in out
    assert "Expected: the command returns without an error and sssd.service is active. If it fails, it stays " \
           "stopped and 'systemctl status sssd' shows why." in out


def test_access_runtime_fix_shows_the_expected_result_and_the_replay_warning(capsys, tmp_path):
    from tests.access.helpers import World
    from tests.client import scenarios as CS

    d = tmp_path / "rt"
    CH.write_checks(CH.scenario("sssd-stopped"), directory=d)
    World().user("alice").host(CS.HOST).service("sshd").rule(
        "r1", users=["alice"], hosts=[CS.HOST], services=["sshd"]).write(d, "alice", CS.HOST, "sshd")
    code = main(["access", "alice", CS.HOST, "sshd", "--replay", str(d), "--runtime"])
    out = _flat(capsys.readouterr().out)
    assert code == 5
    assert "systemctl start sssd.service Expected: the command returns without an error" in out
    assert "Recorded evidence (--replay): these commands describe the recorded system, not this host." in out


def test_a_policy_allow_points_to_the_runtime_check_and_runtime_does_not_repeat_it(capsys, tmp_path):
    import json

    from tests.access.helpers import World
    from tests.client import scenarios as CS

    d = tmp_path / "allow"
    CH.write_checks(CH.scenario("healthy"), directory=d)
    World().user("alice").host(CS.HOST).service("sshd").rule(
        "r1", users=["alice"], hosts=[CS.HOST], services=["sshd"]).write(d, "alice", CS.HOST, "sshd")
    main(["access", "alice", CS.HOST, "sshd", "--replay", str(d), "--json"])
    verify = json.loads(capsys.readouterr().out)["verify"]
    assert any(f"ipa-diagnose access alice {CS.HOST} sshd --runtime" in v for v in verify)
    main(["access", "alice", CS.HOST, "sshd", "--replay", str(d), "--json", "--runtime"])
    verify = json.loads(capsys.readouterr().out)["verify"]
    assert not any("--runtime" in v or "sssctl user-checks" in v for v in verify)


def test_replayed_server_and_client_fixes_say_not_to_run_them_here(capsys, tmp_path):
    main(["--replay", str(FIXTURES / "resolution" / "service-not-running")])
    assert "Do not run them here." in _flat(capsys.readouterr().out)
    fx = CH.write_checks(CH.scenario("sssd-stopped"), directory=tmp_path / "c")
    main(["client", "--replay", str(fx)])
    assert "Do not run them here." in _flat(capsys.readouterr().out)


def test_a_tampered_recorded_unit_never_becomes_a_command_target(capsys, tmp_path):
    """Freeze resolution-safety review: a replay fixture whose recorded unit for 'dirsrv' was emergency.service
    printed 'systemctl start emergency.service', labelled definitive."""

    import json
    import shutil

    fx = tmp_path / "tampered"
    shutil.copytree(FIXTURES / "resolution" / "service-not-running", fx)
    p = fx / "resolution_checks.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    k = next(k for k in data if k.startswith("systemd.unit|"))
    data[k]["fields"]["unit"] = "emergency.service"
    p.write_text(json.dumps(data), encoding="utf-8")
    main(["--replay", str(fx), "--json", "--no-ai"])
    res = json.loads(capsys.readouterr().out)["v2"]["resolutions"]
    assert all(r["status"] != "OFFERED" for r in res)
    assert "emergency.service" not in json.dumps([r.get("steps") for r in res])


def test_a_replayed_fix_is_never_definitive_and_says_it_is_recorded(capsys):
    import json

    main(["--replay", str(FIXTURES / "resolution" / "service-not-running"), "--json", "--no-ai"])
    r = next(x for x in json.loads(capsys.readouterr().out)["v2"]["resolutions"] if x["status"] == "OFFERED")
    assert r["definitive"] is False and r["source"] == "recorded"
    assert r["verification_label"].startswith("Recorded evidence (--replay)")


def test_services_that_need_the_directory_server_are_its_symptoms_while_it_is_down(capsys, tmp_path):
    """Freeze SME review: dirsrv, krb5kdc and httpd stopped (the state after 'ipactl stop' or a failed boot) gave a
    PRIMARY dirsrv plus two INDEPENDENT problems, each with its own start command. Now only dirsrv gets a fix."""

    import json
    import shutil

    fx = tmp_path / "all-down"
    shutil.copytree(FIXTURES / "resolution" / "service-not-running", fx)
    hc = json.loads((fx / "healthcheck.json").read_text(encoding="utf-8"))
    base = next(x for x in hc if x["check"] == "dirsrv")
    for svc in ("krb5kdc", "httpd"):
        hc.append(dict(base, check=svc, uuid=f"res-svc-{svc}", kw={"status": False, "msg": f"{svc}: not running"}))
    (fx / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    rc = json.loads((fx / "resolution_checks.json").read_text(encoding="utf-8"))
    unit = rc["systemd.unit|service=dirsrv"]
    for svc in ("krb5kdc", "httpd"):
        rc[f"systemd.unit|service={svc}"] = dict(unit, fields=dict(unit["fields"], unit=f"{svc}.service"))
    (fx / "resolution_checks.json").write_text(json.dumps(rc), encoding="utf-8")
    main(["--replay", str(fx), "--json", "--no-ai"])
    doc = json.loads(capsys.readouterr().out)
    pri = {d["diagnosis_id"]: d["priority"] for d in doc["diagnoses"]}
    assert pri["healthcheck.service-not-running-dirsrv"] == "PRIMARY_PROBLEM"
    assert pri["healthcheck.service-not-running-krb5kdc"] == "RELATED_SYMPTOM"
    assert pri["healthcheck.service-not-running-httpd"] == "RELATED_SYMPTOM"
    offered = [r["diagnosis_id"] for r in doc["v2"]["resolutions"] if r["status"] == "OFFERED"]
    assert offered == ["healthcheck.service-not-running-dirsrv"]


def test_a_stopped_kdc_alone_still_gets_its_own_fix(capsys, tmp_path):
    import json
    import shutil

    fx = tmp_path / "kdc"
    shutil.copytree(FIXTURES / "resolution" / "service-not-running", fx)
    hc = json.loads((fx / "healthcheck.json").read_text(encoding="utf-8"))
    for x in hc:
        if x["check"] == "dirsrv":
            x.update(check="krb5kdc", kw={"status": False, "msg": "krb5kdc: not running"})
    (fx / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    rc = json.loads((fx / "resolution_checks.json").read_text(encoding="utf-8"))
    u = rc.pop("systemd.unit|service=dirsrv")
    rc["systemd.unit|service=krb5kdc"] = dict(u, fields=dict(u["fields"], unit="krb5kdc.service"))
    (fx / "resolution_checks.json").write_text(json.dumps(rc), encoding="utf-8")
    main(["--replay", str(fx), "--json", "--no-ai"])
    doc = json.loads(capsys.readouterr().out)
    assert [r["diagnosis_id"] for r in doc["v2"]["resolutions"] if r["status"] == "OFFERED"] == \
        ["healthcheck.service-not-running-krb5kdc"]


@pytest.mark.parametrize("module", ["pam_faillock.so", "pam_tally2.so"])
def test_the_pam_account_phase_is_never_run_when_it_would_reset_failed_login_counters(module):
    """Freeze SME review: 'sssctl user-checks -a acct' runs the service's PAM account phase; pam_faillock's account
    phase resets the user's failed-login records, so running it could unlock a locked account."""

    from tests.client import scenarios as CS

    def with_counter_module(d):
        d[CS.key("pam.stack", service=CS.SERVICE)]["fields"]["account_modules"] = ["pam_unix.so", module, "pam_sss.so"]

    r = CH.run("healthy", mutate=with_counter_module)
    rec = r.trace.get("pam.acct")
    assert rec is not None and rec.outcome.value == "SKIPPED" and "failed-login counter" in rec.skip_reason
    assert r.runtime.state != "PASS"
    # the skipped account check is a GAP: never HEALTHY or 'complete' without it (freeze re-review)
    assert rec.skip_reason.startswith("not applicable:")
    assert r.status == "NOT_FULLY_VERIFIED" and r.completeness["level"] != "complete"
    # and a host that refuses the user (pam_denied) is never reported healthy just because the check was skipped
    rd = CH.run("pam-denied", mutate=with_counter_module, hbac="PASS")
    assert rd.status != "HEALTHY" and rd.runtime.state != "PASS"
    r2 = CH.run("healthy")
    assert r2.trace.get("pam.acct").outcome.value == "PASS"


def test_a_pam_stack_read_only_in_part_is_unknown_for_the_counter_gate():
    from tests.client import scenarios as CS

    def cut_short(d):
        d[CS.key("pam.stack", service=CS.SERVICE)]["fields"]["account_modules"] = None

    r = CH.run("healthy", mutate=cut_short)
    assert r.trace.get("pam.acct").skip_reason.startswith("not applicable: not run on purpose")
    assert r.status == "NOT_FULLY_VERIFIED"


def _help(capsys, argv):
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 0
    return _flat(capsys.readouterr().out)


@pytest.mark.parametrize("argv,codes", [
    (["--help"], ["0 HEALTHY", "1 DEGRADED", "2 CRITICAL", "3 UNKNOWN", "4 NOT_FULLY_VERIFIED", "70", "130"]),
    (["access", "--help"], ["0 authorized", "1 not authorized", "3 unknown", "4 authorized but", "5 (only with --runtime)",
                            "2 usage error"]),
    (["client", "--help"], ["0 healthy", "1 problem found", "4 not everything", "2 usage error"]),
    (["replication", "--help"], ["0 healthy", "1 problem found", "4 not everything", "3 pending", "2 usage error"]),
    (["bundle", "--help"], ["0 done", "5 the bundle was not created", "2 usage error"]),
])
def test_every_command_help_states_its_exit_codes(capsys, argv, codes):
    out = _help(capsys, argv)
    assert "Exit codes" in out
    for c in codes:
        assert c in out, (argv, c)
