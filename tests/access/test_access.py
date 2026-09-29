"""ipa-diagnose access: decisions, explanations, failure modes and output (REPLAY of SYNTHETIC API answers)."""

from __future__ import annotations

import json
import re

import pytest

from ipa_diagnose.cli import main
from tests.access.helpers import World, not_found, ok

GRANT_WORDS = re.compile(r"\b(user-mod|user-enable|group-add-member|hostgroup-add-member|hbacrule-add|"
                         r"hbacrule-enable|hbacrule-mod|add-user|add-host|add_member)\b", re.I)


def run(tmp_path, capsys, world: World, user="john", host="app03.lab.test", svc="sshd", extra=()):
    d = world.write(tmp_path / "fx", user, host, svc)
    code = main(["access", user, host, svc, "--replay", str(d), "--json", *extra])
    out = capsys.readouterr().out
    return code, json.loads(out)


def text(tmp_path, capsys, world: World, user="john", host="app03.lab.test", svc="sshd", details=False):
    d = world.write(tmp_path / "fxt", user, host, svc)
    code = main(["access", user, host, svc, "--replay", str(d)] + (["--details"] if details else []))
    return code, capsys.readouterr().out


def base() -> World:
    return (World().user("john", ["ipausers"]).group("ipausers").host("app03.lab.test").service("sshd"))


def calls_made(doc):
    return [c["call"] for c in doc["evidence"]["checks"]]


# ---------------------------------------------------------------- ALLOW paths


def test_direct_user_allow(tmp_path, capsys):
    code, doc = run(tmp_path, capsys, base().rule("r_direct", users=["john"], hosts=["app03.lab.test"],
                                                  services=["sshd"]))
    assert code == 0
    assert doc["authorization"]["state"] == "PASS"
    assert doc["authorization"]["decided_by"] == "FreeIPA hbactest"
    assert doc["authentication"]["state"] == "NOT_VERIFIED"
    assert doc["runtime_access"]["state"] == "NOT_VERIFIED"
    assert doc["source_mode"] == "REPLAY"
    (m,) = doc["matched_rules"]
    assert m["rule"] == "r_direct" and m["explanation_status"] == "COMPLETE"
    assert [s["how"] for s in m["sides"]["user"]] == ["direct"]
    assert [s["how"] for s in m["sides"]["host"]] == ["direct"]
    assert doc["explanation_status"] == "COMPLETE"
    assert doc["resolution"]["status"] == "NONE" and doc["resolution"]["commands"] == []


def test_group_allow(tmp_path, capsys):
    w = base().user("john", ["ipausers", "devs"]).group("devs").rule("r_grp", groups=["devs"], hostcat=True,
                                                                     services=["sshd"])
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    s = doc["matched_rules"][0]["sides"]
    assert s["user"][0] == {"side": "user", "how": "group", "via": "devs", "chain": ["john", "devs"], "count": 0,
                            "chain_complete": True}
    assert s["host"][0]["how"] == "all"


def test_nested_group_allow_shows_the_chain(tmp_path, capsys):
    w = (base().user("john", ["ipausers", "backend"]).group("backend", ["eng"]).group("eng", ["devs"]).group("devs")
         .rule("r_nested", groups=["devs"], hosts=["app03.lab.test"], services=["sshd"]))
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    u = doc["matched_rules"][0]["sides"]["user"][0]
    assert u["how"] == "nested_group" and u["chain"] == ["john", "backend", "eng", "devs"] and u["chain_complete"]
    assert any(p["how"] == "nested_group" for p in doc["relationship_paths"])
    assert doc["objects"]["user"]["nested_groups"] == ["devs", "eng"]


def test_hostgroup_and_nested_hostgroup_allow(tmp_path, capsys):
    w = (base().host("app03.lab.test", ["web"]).hostgroup("web", ["prod"]).hostgroup("prod")
         .rule("r_hg", usercat=True, hostgroups=["prod"], services=["sshd"]))
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    h = doc["matched_rules"][0]["sides"]["host"][0]
    assert h["how"] == "nested_group" and h["chain"] == ["app03.lab.test", "web", "prod"]


def test_service_group_allow(tmp_path, capsys):
    w = base().service("sshd", ["remote-login"]).rule("r_svcgrp", usercat=True, hostcat=True,
                                                      svcgroups=["remote-login"])
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    assert doc["matched_rules"][0]["sides"]["service"][0]["how"] == "group"


def test_allow_all_is_category_all_on_every_side(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    sides = doc["matched_rules"][0]["sides"]
    assert all(sides[k][0]["how"] == "all" for k in ("user", "host", "service"))


def test_disabled_rule_is_not_the_explanation_when_another_allows(tmp_path, capsys):
    w = (base().rule("r_disabled", enabled=False, users=["john"], hosts=["app03.lab.test"], services=["sshd"])
         .rule("r_enabled", users=["john"], hostcat=True, services=["sshd"]))
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    assert [m["rule"] for m in doc["matched_rules"]] == ["r_enabled"]
    assert "r_disabled" not in json.dumps(doc["matched_rules"])


# ---------------------------------------------------------------- DENY: policy, not a fault


def test_deny_is_policy_not_misconfiguration_and_no_grant_is_suggested(tmp_path, capsys):
    w = base().rule("r_other_host", users=["john"], hosts=["db01.lab.test"], services=["sshd"])
    w.host("db01.lab.test")
    code, doc = run(tmp_path, capsys, w)
    assert code == 1
    assert doc["authorization"]["state"] == "FAIL"
    assert doc["answer"].startswith("FreeIPA HBAC policy does not authorize")
    blob = json.dumps(doc).lower()
    for word in ("misconfig", "broken", "incorrect", "wrong"):
        assert word not in blob
    assert not GRANT_WORDS.search(json.dumps(doc))
    assert doc["resolution"] == {"status": "NONE", "procedure": None, "commands": [], "reason": doc["resolution"]["reason"]}
    assert "business decision" in doc["resolution"]["reason"]
    rel = {r["rule"]: r for r in doc["related_rules"]}
    assert "r_other_host" in rel
    assert rel["r_other_host"]["sides"]["host"][0]["how"] == "none"


def test_deny_text_output_has_all_sections_and_no_grant_command(tmp_path, capsys):
    w = base().rule("r_other", users=["mary"], hostcat=True, servicecat=True).user("mary")
    code, out = text(tmp_path, capsys, w)
    assert code == 1
    for section in ("AUTHENTICATION", "AUTHORIZATION", "RUNTIME ACCESS", "ROOT CAUSE", "WHY", "CHECKED FOR YOU",
                    "IMPACT", "RESOLUTION", "RISK", "VERIFY", "LIMITATIONS"):
        assert section in out
    assert "FreeIPA HBAC policy does not authorize john" in out
    assert not GRANT_WORDS.search(out)


def test_only_disabled_rule_would_match_deny_names_it_as_disabled_without_suggesting_enable(tmp_path, capsys):
    w = base().rule("r_off", enabled=False, users=["john"], hosts=["app03.lab.test"], services=["sshd"])
    code, doc = run(tmp_path, capsys, w)
    assert code == 1 and doc["authorization"]["state"] == "FAIL"
    assert any("r_off: the rule is disabled" in line for line in doc["diagnosis"]["why"])
    assert "enable" not in doc["resolution"]["reason"].lower().replace("enabling a rule, just to turn", "")


# ---------------------------------------------------------------- account state (AUTHENTICATION)


def test_disabled_user_with_allowing_policy_is_authn_fail_authz_pass(tmp_path, capsys):
    w = base().user("john", ["ipausers"], disabled=True).rule("allow_all", usercat=True, hostcat=True,
                                                               servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 1
    assert doc["authentication"]["state"] == "FAIL"
    assert doc["authorization"]["state"] == "PASS"
    assert "cannot authenticate" in doc["answer"]
    assert "USER_DISABLED" in {f["code"] for f in doc["diagnosis"]["findings"]}
    assert not GRANT_WORDS.search(json.dumps(doc))


def test_expired_principal_is_authn_fail(tmp_path, capsys):
    w = base().user("john", ["ipausers"], krbprincipalexpiration="20200101000000Z").rule(
        "allow_all", usercat=True, hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 1 and doc["authentication"]["state"] == "FAIL"
    assert doc["authentication"]["account"]["principal_expired"] is True


def test_expired_password_is_not_authn_fail(tmp_path, capsys):
    w = base().user("john", ["ipausers"], krbpasswordexpiration="20200101000000Z").rule(
        "allow_all", usercat=True, hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["authentication"]["state"] == "NOT_VERIFIED"
    assert doc["authentication"]["account"]["password_expired"] is True


def test_unreadable_account_state_is_unknown_and_exit_4_when_policy_allows(tmp_path, capsys):
    w = base().user("john", ["ipausers"], nsaccountlock_absent=True).rule("allow_all", usercat=True, hostcat=True,
                                                                          servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 4
    assert doc["authentication"]["state"] == "UNKNOWN" and doc["authorization"]["state"] == "PASS"


def test_user_exists_is_never_authentication_pass(tmp_path, capsys):
    code, doc = run(tmp_path, capsys, base().rule("allow_all", usercat=True, hostcat=True, servicecat=True))
    assert doc["authentication"]["state"] != "PASS"


# ---------------------------------------------------------------- missing objects


def test_missing_user_is_not_evaluated_even_if_allow_all_would_grant_a_bare_name(tmp_path, capsys):
    w = World().host("app03.lab.test").service("sshd").rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("user_show", ("ghost",))] = {"response": not_found("ghost")}
    code, doc = run(tmp_path, capsys, w, user="ghost")
    assert code == 1
    assert doc["authentication"]["state"] == "FAIL"
    assert doc["authorization"]["state"] == "UNKNOWN"  # never PASS for a name with no IPA identity
    assert doc["authoritative_evaluation"]["ran"] is False
    assert "hbactest" not in calls_made(doc)


def test_missing_host_is_unknown(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("host_show", ("nohost.lab.test",))] = {"response": not_found("nohost.lab.test")}
    code, doc = run(tmp_path, capsys, w, host="nohost.lab.test")
    assert code == 3
    assert doc["authorization"]["state"] == "UNKNOWN"
    assert "HOST_NOT_FOUND" in {f["code"] for f in doc["diagnosis"]["findings"]}


def test_missing_service_is_evaluated_only_category_all_can_match(tmp_path, capsys):
    w = base().rule("r_sshd", users=["john"], hostcat=True, services=["sshd"])
    w.overrides[("hbacsvc_show", ("custom-app",))] = {"response": not_found("custom-app")}
    code, doc = run(tmp_path, capsys, w, svc="custom-app")
    assert code == 1 and doc["authorization"]["state"] == "FAIL"
    assert doc["authoritative_evaluation"]["request"]["service"] == "custom-app"
    assert "SERVICE_NOT_DEFINED" in {f["code"] for f in doc["diagnosis"]["findings"]}


# ---------------------------------------------------------------- evaluator failures never become decisions


def test_evaluator_unavailable_is_unknown(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.meta["unavailable"] = "no valid Kerberos ticket: run kinit"
    code, doc = run(tmp_path, capsys, w)
    assert code == 3
    assert doc["authorization"]["state"] == "UNKNOWN" and doc["authentication"]["state"] == "UNKNOWN"
    assert doc["authorization"]["decided_by"] is None


@pytest.mark.parametrize("kind", ["auth", "unavailable", "timeout", "malformed"])
def test_hbactest_transport_failure_is_unknown(tmp_path, capsys, kind):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("hbactest", ())] = {"transport_error": {"kind": kind, "message": "simulated"}}
    code, doc = run(tmp_path, capsys, w)
    assert code == 3 and doc["authorization"]["state"] == "UNKNOWN"


@pytest.mark.parametrize("answer", [
    {"value": "True", "matched": ["x"]},  # not a boolean
    {"value": True, "matched": None},  # granted without a rule
    {"value": False, "matched": ["x"]},  # denied with a matched rule
    {},
])
def test_malformed_verdict_is_unknown(tmp_path, capsys, answer):
    w = base()
    w.hbactest_override = answer
    code, doc = run(tmp_path, capsys, w)
    assert code == 3 and doc["authorization"]["state"] == "UNKNOWN"


def test_hbactest_api_error_is_unknown(tmp_path, capsys):
    w = base()
    w.overrides[("hbactest", ())] = {"response": {"error": {"code": 2100, "name": "ACIError", "message": "no"},
                                                  "result": None}}
    code, doc = run(tmp_path, capsys, w)
    assert code == 3 and doc["authorization"]["state"] == "UNKNOWN"


def test_truncated_rule_list_is_unknown_even_when_granted(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    ans = w.hbactest("john", "app03.lab.test", "sshd")
    ans["messages"] = [{"type": "warning", "name": "SearchResultTruncated", "code": 13017,
                        "message": "Search result has been truncated"}]
    w.hbactest_override = ans
    code, doc = run(tmp_path, capsys, w)
    assert code == 3 and doc["authorization"]["state"] == "UNKNOWN"
    assert doc["authoritative_evaluation"]["rule_list_truncated"] is True


def test_rule_errors_make_the_answer_unknown(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    ans = w.hbactest("john", "app03.lab.test", "sshd")
    ans["error"] = ["broken_rule"]
    w.hbactest_override = ans
    code, doc = run(tmp_path, capsys, w)
    assert code == 3 and doc["authorization"]["state"] == "UNKNOWN"


def test_missing_replay_file_is_unknown(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    code = main(["access", "john", "app03.lab.test", "sshd", "--replay", str(tmp_path / "empty"), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 3 and doc["authorization"]["state"] == "UNKNOWN"


def test_unrecorded_call_is_never_an_empty_success(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    d = w.write(tmp_path / "fx", "john", "app03.lab.test", "sshd")
    code = main(["access", "mary", "app03.lab.test", "sshd", "--replay", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 3
    assert doc["authentication"]["state"] == "UNKNOWN" and doc["authorization"]["state"] == "UNKNOWN"


# ---------------------------------------------------------------- decision vs explanation conflicts


def test_allow_with_unexplained_rule_stays_pass_and_says_contradicting(tmp_path, capsys):
    w = base().rule("r_mystery", users=["someoneelse"], hosts=["app03.lab.test"], services=["sshd"])
    w.hbactest_override = {"value": True, "matched": ["r_mystery"], "notmatched": None, "error": None}
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["authorization"]["state"] == "PASS"
    assert doc["explanation_status"] == "CONTRADICTING"
    assert "EXPLANATION_CONTRADICTS" in {f["code"] for f in doc["diagnosis"]["findings"]}


def test_deny_is_never_turned_into_allow_by_a_permissive_looking_rule(tmp_path, capsys):
    w = base().rule("r_looks_open", usercat=True, hostcat=True, servicecat=True)
    w.hbactest_override = {"value": False, "matched": None, "notmatched": ["r_looks_open"], "error": None}
    w.users["john"] = {}
    # make the rule visible as "related": list john directly too
    w.rules[0]["users"] = ["john"]
    w.rules[0]["usercat"] = False
    code, doc = run(tmp_path, capsys, w)
    assert code == 1 and doc["authorization"]["state"] == "FAIL"
    assert doc["explanation_status"] == "CONTRADICTING"


def test_partial_group_data_is_incomplete_not_a_decision_change(tmp_path, capsys):
    w = (base().user("john", ["ipausers", "backend"]).group("backend", ["devs"]).group("devs")
         .rule("r_nested", groups=["devs"], hostcat=True, servicecat=True))
    w.overrides[("group_show", ("devs",))] = {"response": {"error": {"code": 903, "name": "InternalError",
                                                                        "message": "boom"}, "result": None}}
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["authorization"]["state"] == "PASS"
    assert doc["explanation_status"] == "INCOMPLETE"
    u = doc["matched_rules"][0]["sides"]["user"][0]
    assert u["how"] == "nested_group" and u["chain_complete"] is False


# ---------------------------------------------------------------- graph safety and bounds


def test_group_cycle_terminates_and_explains(tmp_path, capsys):
    w = (base().user("john", ["a"]).group("a", ["b"]).group("b", ["c"]).group("c", ["a", "target"])
         .group("target").rule("r_cycle", groups=["target"], hostcat=True, servicecat=True))
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    u = doc["matched_rules"][0]["sides"]["user"][0]
    assert u["chain"] == ["john", "a", "b", "c", "target"]


def test_duplicate_paths_are_deduplicated(tmp_path, capsys):
    w = (base().user("john", ["a", "b"]).group("a", ["t"]).group("b", ["t"]).group("t")
         .rule("r", groups=["t"], hostcat=True, servicecat=True))
    code, doc = run(tmp_path, capsys, w)
    rels = doc["evidence"]["relationships"]
    keys = [(r["from"]["name"], r["to"]["name"], r["kind"], r["side"]) for r in rels]
    assert len(keys) == len(set(keys))
    assert len(doc["matched_rules"][0]["sides"]["user"]) == 1  # one listed group, one explanation


def test_deep_nesting_is_bounded_and_marked_incomplete(tmp_path, capsys):
    w = base()
    chain = [f"g{i}" for i in range(60)]
    w.user("john", [chain[0]])
    for a, b in zip(chain, chain[1:]):
        w.group(a, [b])
    w.group(chain[-1]).rule("r_deep", groups=[chain[-1]], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["authorization"]["state"] == "PASS"  # FreeIPA decided; bounds only limit the why
    assert doc["explanation_status"] == "INCOMPLETE"
    assert doc["completeness"]["api_calls"] <= doc["completeness"]["api_call_budget"]


def test_large_membership_does_not_fetch_every_group(tmp_path, capsys):
    groups = [f"team{i}" for i in range(3000)]
    w = base().user("john", groups).rule("r_direct", users=["john"], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    assert not any(c.startswith("group_show") for c in calls_made(doc))


# ---------------------------------------------------------------- canonical names and trusted identities


def test_canonical_names_are_what_freeipa_evaluates(tmp_path, capsys):
    w = base().rule("r_direct", users=["john"], hosts=["app03.lab.test"], services=["sshd"])
    d = w.write(tmp_path / "fx", "john", "app03.lab.test", "sshd")
    code = main(["access", "JOHN", "APP03", "sshd", "--replay", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert doc["authoritative_evaluation"]["request"] == {"user": "john", "targethost": "app03.lab.test",
                                                          "service": "sshd"}
    assert doc["query"]["host_completed_with_ipa_domain"] is True


def test_trusted_identity_is_recognized_and_unknown(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    d = w.write(tmp_path / "fx", "john", "app03.lab.test", "sshd")
    code = main(["access", "jsmith@ad.example.com", "app03.lab.test", "sshd", "--replay", str(d), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 3
    assert doc["authorization"]["state"] == "UNKNOWN" and doc["authentication"]["state"] == "UNKNOWN"
    assert "TRUSTED_IDENTITY_UNSUPPORTED" in {f["code"] for f in doc["diagnosis"]["findings"]}
    assert "hbactest" not in calls_made(doc)


def test_own_realm_suffix_is_an_ordinary_user(tmp_path, capsys):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    d = w.write(tmp_path / "fx", "john", "app03.lab.test", "sshd")
    code = main(["access", "john@LAB.TEST", "app03.lab.test", "sshd", "--replay", str(d), "--json"])
    assert code == 0


# ---------------------------------------------------------------- hostile input and output safety


@pytest.mark.parametrize("args", [
    ["all", "app03.lab.test", "sshd"], ["john", "all", "sshd"], ["john", "app03.lab.test", "all"],
    ["john;id", "app03.lab.test", "sshd"], ["$(id)", "h", "sshd"], ["john", "app03.lab.test", "host/app03"],
    ["john", "app03 lab", "sshd"], ["john", "-x.lab.test", "sshd"], ["j" * 300, "h.lab.test", "sshd"],
    ["john", "app03.lab.test", "ss\x1b[31mhd"], ["jo‮hn", "app03.lab.test", "sshd"],
    ["john", "app03.lab.test", "sshd\nx"], ["john", "a..b", "sshd"], ["john@", "h.lab.test", "sshd"],
])
def test_hostile_or_malformed_targets_are_refused_as_usage_errors(tmp_path, capsys, args):
    (tmp_path / "e").mkdir()
    with pytest.raises(SystemExit) as e:
        main(["access", *args, "--replay", str(tmp_path / "e")])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "\x1b" not in err and "‮" not in err


def test_hostile_names_from_the_directory_are_sanitized_in_json_and_text(tmp_path, capsys):
    evil = "evil\x1b]0;pwned\x07‮rule​"
    w = base().rule(evil, users=["john"], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    blob = json.dumps(doc, ensure_ascii=False)
    assert "\x1b" not in blob and "‮" not in blob and "​" not in blob and "\x07" not in blob
    code, out = text(tmp_path, capsys, w, details=True)
    assert "\x1b" not in out and "‮" not in out


def test_printed_commands_are_quoted_and_read_only(tmp_path, capsys):
    w = World().user("svc$", ["ipausers"]).group("ipausers").host("app03.lab.test").service("sshd").rule(
        "allow_all", usercat=True, hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w, user="svc$")
    assert code == 0
    assert any("'svc$'" in v for v in doc["verify"])
    for v in doc["verify"]:
        assert not GRANT_WORDS.search(v)


def test_access_never_accepts_an_ai_provider(tmp_path, capsys):
    (tmp_path / "e").mkdir()
    with pytest.raises(SystemExit) as e:
        main(["access", "john", "h.lab.test", "sshd", "--ai-provider", "openai", "--replay", str(tmp_path / "e")])
    assert e.value.code == 2


def test_access_without_targets_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as e:
        main(["access"])
    assert e.value.code == 2


def test_access_does_not_write_the_verify_baseline(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    run(tmp_path, capsys, base().rule("allow_all", usercat=True, hostcat=True, servicecat=True))
    assert not list(tmp_path.rglob("last_report*.json"))


# ---------------------------------------------------------------- privacy: only what the question needs


def test_deny_does_not_list_unrelated_rule_names(tmp_path, capsys):
    w = base().user("mary").rule("secret_finance_rule", users=["mary"], hosts=["fin01.lab.test"],
                                 services=["sshd"]).host("fin01.lab.test")
    code, doc = run(tmp_path, capsys, w)
    assert code == 1
    assert "secret_finance_rule" not in json.dumps(doc)
    assert doc["authoritative_evaluation"]["not_matched_rule_count"] == 1


def test_only_the_users_own_groups_are_fetched(tmp_path, capsys):
    w = (base().user("john", ["backend"]).group("backend", ["devs"]).group("devs").group("unrelated_team")
         .rule("r", groups=["devs"], hostcat=True, servicecat=True))
    code, doc = run(tmp_path, capsys, w)
    assert "group_show unrelated_team" not in calls_made(doc)


# ---------------------------------------------------------------- JSON contract


def test_json_contract(tmp_path, capsys):
    code, doc = run(tmp_path, capsys, base().rule("allow_all", usercat=True, hostcat=True, servicecat=True))
    assert doc["kind"] == "ipa-diagnose.access" and doc["access_schema_version"] == "1.0"
    for key in ("query", "authentication", "authorization", "runtime_access", "authoritative_evaluation",
                "matched_rules", "relationship_paths", "evidence", "completeness", "diagnosis", "resolution",
                "limitations"):
        assert key in doc
    for key in ("authentication", "authorization", "runtime_access"):
        assert doc[key]["state"] in ("PASS", "FAIL", "UNKNOWN", "NOT_VERIFIED")
    assert isinstance(doc["authoritative_evaluation"]["granted"], bool)
    assert doc["evidence"]["provenance"]["read_only"] is True
    assert "report_schema_version" not in doc  # the v1 diagnosis report is a different document


def test_prose_is_not_truncated(tmp_path, capsys):
    w = base().rule("r_other", users=["mary"], hostcat=True, servicecat=True).user("mary")
    code, doc = run(tmp_path, capsys, w)
    for text in [doc["resolution"]["reason"], doc["risk"], doc["diagnosis"]["impact"], *doc["limitations"]]:
        assert not text.endswith("..."), text


def test_time_budget_starts_with_the_first_call_not_at_construction(tmp_path):
    """Live lab A21 (run 36483967139): `bundle --access` built the API client before its minutes-long diagnosis,
    so the whole access time budget was gone before the first call and the answer became UNKNOWN."""

    import time

    from ipa_diagnose.access.api import ReplayApi

    d = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True).write(tmp_path / "fx", "john",
                                                                                     "app03.lab.test", "sshd")
    api = ReplayApi(str(d), deadline_seconds=0.05)
    time.sleep(0.1)
    assert api.call("user_show", ["john"]).ok
    time.sleep(0.1)
    assert api.call("host_show", ["app03.lab.test"]).error.kind == "budget"


def test_only_allowlisted_read_only_methods_can_be_sent(tmp_path):
    from ipa_diagnose.access.api import ReplayApi

    api = ReplayApi(str(tmp_path))
    for method in ("user_mod", "hbacrule_enable", "group_add_member", "user_enable", "batch"):
        with pytest.raises(ValueError):
            api.call(method, ["x"])
