"""Regressions for the focused review of round 3 (one BLOCKER on the trusted-domain path, four MINOR)."""

from __future__ import annotations

import json

import pytest

from ipa_diagnose.cli import main
from tests.access.helpers import not_found
from tests.access.test_access import base, run

EVALUATOR_HINTS = ("hbactest", "own evaluat", "evaluator can answer")


def _trusted(tmp_path, capsys, user, host_override=None):
    w = base().rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    if host_override is not None:
        w.overrides[("host_show", ("app03.lab.test",))] = host_override
    d = w.write(tmp_path / "fx", "john", "app03.lab.test", "sshd")
    code = main(["access", user, "app03.lab.test", "sshd", "--replay", str(d), "--json"])
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("user", ["alice@ad.example.com", "AD\\alice", "S-1-5-21-1111111111-2222222222-3333333333-1104"])
@pytest.mark.parametrize("host_override", [
    {"response": not_found("app03.lab.test")},
    {"transport_error": {"kind": "timeout", "message": "x"}},
    {"response": {"error": {"code": 2100, "name": "ACIError", "message": "no"}, "result": None}},
    {"transport_error": {"kind": "auth", "message": "HTTP 401"}},
])
def test_trusted_user_without_a_known_host_is_never_pointed_at_the_evaluator(tmp_path, capsys, user, host_override):
    """BLOCKER: RESOLUTION and the finding still said 'use FreeIPA's own evaluation' for a missing/unreadable host."""

    code, doc = _trusted(tmp_path, capsys, user, host_override)
    assert code == 3
    text = " ".join([doc["resolution"]["reason"], *doc["verify"], *doc["diagnosis"]["why"],
                     *[f["detail"] for f in doc["diagnosis"]["findings"]]]).lower()
    positive = [s for s in doc["verify"] if "hbactest" in s.lower() and "do not use" not in s.lower()]
    assert not positive
    assert "own evaluat" not in text and "evaluator can answer" not in text


def test_trusted_user_on_existing_host_confirms_the_identity_first(tmp_path, capsys):
    code, doc = _trusted(tmp_path, capsys, "alice@ad.example.com")
    assert doc["verify"][0].startswith("id alice@ad.example.com")
    assert doc["verify"][1].startswith("only if it does: ipa hbactest")


def test_domain_backslash_form_is_printed_as_typed(tmp_path, capsys):
    """MINOR 2: DOMAIN\\name was redisplayed as name@DOMAIN, which the tool itself refuses."""

    code, doc = _trusted(tmp_path, capsys, "AD\\alice")
    assert doc["query"]["user_display"] == "AD\\alice"
    assert "alice@AD" not in json.dumps(doc)


def test_401_after_the_decision_keeps_the_decision(tmp_path, capsys):
    """MINOR 1: a 401 on hbacrule_show after hbactest granted threw the decision away."""

    w = base().rule("r_ops", users=["john"], hostcat=True, servicecat=True)
    w.overrides[("hbacrule_show", ("r_ops",))] = {"transport_error": {"kind": "auth", "message": "HTTP 401"}}
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["authorization"]["state"] == "PASS"
    assert doc["explanation_status"] == "INCOMPLETE"
    assert not doc["answer"].startswith("ipa-diagnose could not query")


def test_401_after_the_account_was_read_keeps_its_state(tmp_path, capsys):
    w = base().user("john", ["ipausers"], disabled=True).rule("allow_all", usercat=True, hostcat=True, servicecat=True)
    w.overrides[("host_show", ("app03.lab.test",))] = {"transport_error": {"kind": "auth", "message": "HTTP 401"}}
    code, doc = run(tmp_path, capsys, w)
    assert code == 1 and doc["authentication"]["state"] == "FAIL"
    assert doc["authorization"]["state"] == "UNKNOWN"


def test_chain_search_stops_when_the_path_is_known(tmp_path, capsys):
    """MINOR 4a: a whole level of groups was read after the path was already complete."""

    w = base().user("john", [f"f{i}" for i in range(60)])
    for i in range(60):
        w.group(f"f{i}", [f"m{i}"]).group(f"m{i}", ["top"])
    w.group("top").rule("r_top", groups=["top"], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["explanation_status"] == "COMPLETE"
    reads = [c for c in doc["evidence"]["checks"] if c["call"].startswith("group_show")]
    assert len(reads) <= 3


def test_chain_longer_than_twelve_is_found(tmp_path, capsys):
    """MINOR 4c: all 15 groups were read, but a depth-12 path search could not find the chain."""

    chain = [f"d{i}" for i in range(15)]
    w = base().user("john", [chain[0]])
    for a, b in zip(chain, chain[1:]):
        w.group(a, [b])
    w.group(chain[-1]).rule("r", groups=[chain[-1]], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert doc["explanation_status"] == "COMPLETE"
    assert doc["matched_rules"][0]["sides"]["user"][0]["chain"] == ["john"] + chain


# ---------------------------------------------------------------- round-4 review (no blocker), MINOR 1-4


def test_deny_with_an_unreadable_rule_does_not_claim_no_rule_names_the_user(tmp_path, capsys):
    w = base().user("john", ["ops"]).group("ops").rule("r_ops", groups=["ops"], hosts=["other.lab.test"],
                                                       servicecat=True)
    w.overrides[("hbacrule_show", ("r_ops",))] = {"transport_error": {"kind": "timeout", "message": "x"}}
    code, doc = run(tmp_path, capsys, w)
    assert code == 1
    why = " ".join(doc["diagnosis"]["why"])
    assert "No HBAC rule names" not in why and "could not be read" in why and "r_ops" in why


def test_diamond_with_two_wanted_groups_is_complete(tmp_path, capsys):
    w = (base().user("john", ["t1"]).group("t1", ["x", "y"]).group("x", ["a"]).group("y", ["b"]).group("b", ["a"])
         .group("a").rule("r_a", groups=["a"], hostcat=True, servicecat=True)
         .rule("r_b", groups=["b"], hostcat=True, servicecat=True))
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["explanation_status"] == "COMPLETE"
    chains = {m["rule"]: m["sides"]["user"][0]["chain"] for m in doc["matched_rules"]}
    assert chains["r_b"] == ["john", "t1", "y", "b"]


def test_shared_chain_budget_note_names_the_shared_budget(tmp_path, capsys):
    chain = [f"d{i}" for i in range(45)]
    w = base().user("john", [chain[0]]).host("app03.lab.test", ["h0"]).hostgroup("h0", ["h1"]).hostgroup("h1")
    for a, b in zip(chain, chain[1:]):
        w.group(a, [b])
    w.group(chain[-1]).rule("r", groups=[chain[-1]], hostgroups=["h1"], servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    notes = " ".join(doc["completeness"]["notes"])
    assert "share a budget" in notes and "followed for at most" not in notes


def test_missing_user_then_401_keeps_the_missing_user(tmp_path, capsys):
    w = base()
    w.overrides[("user_show", ("ghost",))] = {"response": not_found("ghost")}
    w.overrides[("host_show", ("app03.lab.test",))] = {"transport_error": {"kind": "auth", "message": "HTTP 401"}}
    code, doc = run(tmp_path, capsys, w, user="ghost")
    assert code == 1 and doc["authentication"]["state"] == "FAIL"
    assert not doc["answer"].startswith("ipa-diagnose could not query")


def test_sid_on_existing_host_is_checked_with_trust_resolve(tmp_path, capsys):
    code, doc = _trusted(tmp_path, capsys, "s-1-5-21-1111111111-2222222222-3333333333-1104")
    assert doc["verify"][0].startswith("ipa trust-resolve --sids=S-1-5-21-1111111111-2222222222-3333333333-1104")
    assert doc["query"]["user_display"] == "S-1-5-21-1111111111-2222222222-3333333333-1104"
