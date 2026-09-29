"""Regressions for the focused re-review of the round-1/2 fixes (one BLOCKER, three MINOR)."""

from __future__ import annotations

import json

from ipa_diagnose.cli import main
from tests.access.helpers import not_found
from tests.access.test_access import base, run


def _timeout():
    return {"transport_error": {"kind": "timeout", "message": "simulated"}}


def test_trusted_user_on_a_missing_host_is_never_sent_to_hbactest(tmp_path, capsys):
    """BLOCKER: the trusted-domain path printed ipa hbactest for a host that does not exist."""

    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("host_show", ("typo.lab.test",))] = {"response": not_found("typo.lab.test")}
    d = w.write(tmp_path / "fx", "john", "typo.lab.test", "sshd")
    code = main(["access", "alice@ad.example.com", "typo.lab.test", "sshd", "--replay", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    blob = " ".join(doc["verify"]) + doc["resolution"]["reason"] + json.dumps(doc["diagnosis"]["findings"])
    assert code == 3
    assert "ipa hbactest --user" not in blob
    assert any(s.startswith("ipa host-show typo.lab.test") for s in doc["verify"])
    assert any("do not use ipa hbactest" in s for s in doc["verify"])


def test_trusted_user_on_an_existing_host_gets_freeipas_own_evaluation(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    d = w.write(tmp_path / "fx", "john", "app03.lab.test", "sshd")
    main(["access", "alice@ad.example.com", "app03.lab.test", "sshd", "--replay", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["verify"][0].startswith("ipa hbactest --user=alice@ad.example.com --host=app03.lab.test")


def test_unreadable_host_or_user_never_suggests_hbactest(tmp_path, capsys):
    for override in (("host_show", ("app03.lab.test",)), ("user_show", ("john",))):
        w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
        w.overrides[override] = _timeout()
        code, doc = run(tmp_path, capsys, w)
        assert code == 3
        steps = " ".join(doc["verify"])
        assert "ipa hbactest --user" not in steps and "do not use ipa hbactest" in steps


def test_ticket_refused_during_the_run_is_the_operators_problem(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("user_show", ("john",))] = {"transport_error": {"kind": "auth", "message": "HTTP 401: run kinit"}}
    code, doc = run(tmp_path, capsys, w)
    codes = {f["code"] for f in doc["diagnosis"]["findings"]}
    assert code == 3
    assert "EVALUATOR_UNAVAILABLE" in codes and "OBJECT_UNREADABLE" not in codes
    assert doc["answer"].startswith("ipa-diagnose could not query FreeIPA")
    assert doc["verify"][0].startswith("klist")
    assert doc["completeness"]["api_calls"] == 1  # nothing more was sent after the refusal


def test_deny_says_rules_for_all_users_are_not_listed(tmp_path, capsys):
    w = base().rule("r_all_users_elsewhere", usercat=True, hosts=["secret-db.lab.test"], servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 1
    assert any("Rules that apply to all users" in x for x in doc["diagnosis"]["why"])
    assert "secret-db" not in json.dumps(doc)
