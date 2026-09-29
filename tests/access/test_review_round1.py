"""Regressions for the first fresh reviews of access diagnosis (decisions/explanations, fresh-user/support)."""

from __future__ import annotations

import json

from ipa_diagnose.cli import main
from tests.access.helpers import World, not_found
from tests.access.test_access import base, run, text


def _timeout():
    return {"transport_error": {"kind": "timeout", "message": "simulated"}}


# ---------------------------------------------------------------- fresh-user BLOCKER B1


def test_missing_user_verify_never_suggests_hbactest(tmp_path, capsys):
    w = World().host("app03.lab.test").service("sshd").rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("user_show", ("jhon",))] = {"response": not_found("jhon")}
    code, doc = run(tmp_path, capsys, w, user="jhon")
    steps = " ".join(doc["verify"])
    assert "ipa hbactest --user" not in steps and "ipa-diagnose access" not in steps
    assert "ipa user-show jhon" in steps and "do not use ipa hbactest" in steps


def test_missing_host_verify_never_suggests_hbactest(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("host_show", ("app04.lab.test",))] = {"response": not_found("app04.lab.test")}
    code, doc = run(tmp_path, capsys, w, host="app04.lab.test")
    steps = " ".join(doc["verify"])
    assert "ipa hbactest --user" not in steps and "ipa host-show app04.lab.test" in steps
    assert doc["answer"] == "app04.lab.test is not an IPA host, so FreeIPA HBAC policy has no decision about it."


# ---------------------------------------------------------------- the operator's ticket is not the user's


def test_no_ticket_is_about_the_operator_not_the_user(tmp_path, capsys):
    w = base()
    w.meta["unavailable"] = "no valid Kerberos ticket: run kinit"
    code, doc = run(tmp_path, capsys, w)
    assert code == 3
    assert doc["answer"].startswith("ipa-diagnose could not query FreeIPA")
    assert "account was not read" in doc["authentication"]["summary"]
    assert "kinit" in doc["resolution"]["reason"] and any(s.startswith("klist") for s in doc["verify"])


# ---------------------------------------------------------------- account-state wording


def test_expired_principal_impact_is_limited_to_kerberos_logins(tmp_path, capsys):
    w = base().user("john", ["ipausers"], krbprincipalexpiration="20200101000000Z").rule(
        "allow_all", usercat=True, hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert "Kerberos-based logins" in doc["diagnosis"]["impact"]
    assert "regardless of HBAC" in doc["diagnosis"]["impact"]
    assert any("ipa user-show john --all" in s for s in doc["verify"])


def test_allow_does_not_claim_the_account_state_is_fully_checked(tmp_path, capsys):
    code, doc = run(tmp_path, capsys, base().rule("allow_all", usercat=True, hostcat=True, servicecat=True))
    assert "lockout" in doc["diagnosis"]["no_blocker"] and "Not checked" in doc["diagnosis"]["no_blocker"]
    assert any("ipa user-status john" in s for s in doc["verify"])
    checks = " ".join(c["summary"] for c in doc["evidence"]["checks"])
    assert "no principal expiration set or readable" in checks  # absent is not "not expired"


def test_preserved_user_cannot_authenticate_and_is_not_evaluated(tmp_path, capsys):
    w = base().user("john", ["ipausers"], preserved=True).rule("r", users=["john"], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 1
    assert doc["authentication"]["state"] == "FAIL" and doc["authorization"]["state"] == "UNKNOWN"
    assert "USER_PRESERVED" in {f["code"] for f in doc["diagnosis"]["findings"]}
    assert doc["authoritative_evaluation"]["ran"] is False


# ---------------------------------------------------------------- explanation honesty (review 1 findings 1-3)


def test_disabled_rule_that_also_misses_a_side_says_so(tmp_path, capsys):
    w = base().rule("r_off", enabled=False, users=["john"], hosts=["other.lab.test"], services=["sshd"])
    code, doc = run(tmp_path, capsys, w)
    line = next(x for x in doc["diagnosis"]["why"] if "r_off" in x)
    assert "the rule is disabled" in line and "also does not cover the host" in line


def test_unreadable_matched_rule_makes_the_explanation_incomplete(tmp_path, capsys):
    w = (base().rule("r_a", users=["john"], hostcat=True, servicecat=True)
         .rule("r_b", users=["john"], hostcat=True, servicecat=True))
    w.overrides[("hbacrule_show", ("r_b",))] = _timeout()
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["authorization"]["state"] == "PASS"
    assert doc["explanation_status"] == "INCOMPLETE"


def test_unreadable_related_rule_makes_a_deny_explanation_incomplete(tmp_path, capsys):
    w = base().rule("r_x", users=["john"], hosts=["other.lab.test"], services=["sshd"])
    w.overrides[("hbacrule_show", ("r_x",))] = _timeout()
    code, doc = run(tmp_path, capsys, w)
    assert code == 1 and doc["explanation_status"] == "INCOMPLETE"


def test_too_many_matched_rules_is_incomplete(tmp_path, capsys):
    w = base()
    for i in range(12):
        w.rule(f"r{i:02d}", users=["john"], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["explanation_status"] == "INCOMPLETE"


def test_unread_service_groups_are_not_called_uncovered(tmp_path, capsys):
    w = (base().service("sshd", ["remote"]).rule("r_svc", users=["john"], hosts=["other.lab.test"],
                                                svcgroups=["remote"]))
    w.overrides[("hbacsvc_show", ("sshd",))] = _timeout()
    code, doc = run(tmp_path, capsys, w)
    line = next(x for x in doc["diagnosis"]["why"] if "r_svc" in x)
    assert "does not cover the host" in line and "service could not be determined" in line
    assert doc["explanation_status"] == "INCOMPLETE"


def test_contradicting_deny_says_so_and_suggests_no_policy_change(tmp_path, capsys):
    w = base().rule("r_open", users=["john"], hostcat=True, servicecat=True)
    w.hbactest_override = {"value": False, "matched": None, "notmatched": ["r_open"], "error": None}
    code, doc = run(tmp_path, capsys, w)
    assert code == 1 and doc["explanation_status"] == "CONTRADICTING"
    line = next(x for x in doc["diagnosis"]["why"] if "r_open" in x)
    assert "FreeIPA did not match it" in line
    assert "No policy change is suggested" in doc["resolution"]["reason"]


def test_contradiction_is_shown_before_resolution_in_text(tmp_path, capsys):
    w = base().rule("r_open", users=["john"], hostcat=True, servicecat=True)
    w.hbactest_override = {"value": False, "matched": None, "notmatched": ["r_open"], "error": None}
    code, out = text(tmp_path, capsys, w)
    assert out.index("ALSO NOTED") < out.index("RESOLUTION")


# ---------------------------------------------------------------- failure labels and bounds (findings 4-6, 8)


def test_node_bound_during_chain_expansion_is_not_a_crash(tmp_path, capsys):
    groups = [f"g{i}" for i in range(2100)] + ["backend"]
    w = (base().user("john", groups).group("backend", ["devs"]).group("devs")
         .rule("r", groups=["devs"], hostcat=True, servicecat=True))
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["authorization"]["state"] == "PASS"
    assert doc["explanation_status"] in ("INCOMPLETE", "COMPLETE")


def test_unreadable_user_is_labelled_as_such_not_as_an_evaluator_failure(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("user_show", ("john",))] = _timeout()
    code, doc = run(tmp_path, capsys, w)
    codes = {f["code"] for f in doc["diagnosis"]["findings"]}
    assert code == 3 and "OBJECT_UNREADABLE" in codes and "EVALUATOR_FAILED" not in codes


def test_sid_is_a_trusted_identity(tmp_path, capsys):
    w = base()
    d = w.write(tmp_path / "fx", "john", "app03.lab.test", "sshd")
    code = main(["access", "S-1-5-21-1111111111-2222222222-3333333333-1104", "app03.lab.test", "sshd",
                 "--replay", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 3
    assert "TRUSTED_IDENTITY_UNSUPPORTED" in {f["code"] for f in doc["diagnosis"]["findings"]}
    assert "@" not in doc["query"]["user_display"]


def test_replay_cannot_answer_a_different_hbactest_request(tmp_path, capsys):
    from ipa_diagnose.access.api import ReplayApi

    d = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True).write(
        tmp_path / "fx", "john", "app03.lab.test", "sshd")
    api = ReplayApi(str(d))
    ok_req = {"user": "john", "targethost": "app03.lab.test", "service": "sshd", "nodetail": False}
    assert api.call("hbactest", [], ok_req).ok
    bad = dict(ok_req, targethost="APP03")
    assert api.call("hbactest", [], bad).error.kind == "not_recorded"


def test_json_keeps_rule_names_and_rule_objects_apart(tmp_path, capsys):
    code, doc = run(tmp_path, capsys, base().rule("allow_all", usercat=True, hostcat=True, servicecat=True))
    assert doc["authoritative_evaluation"]["matched_rule_names"] == ["allow_all"]
    assert doc["matched_rules"][0]["rule"] == "allow_all"
