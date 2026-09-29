"""`ipa-diagnose client --verify`: fresh evidence only; never a false RESOLVED (false-RESOLVED gate)."""

from __future__ import annotations

import json

import pytest

from ipa_diagnose.client import verify as V
from ipa_diagnose.cli import main
from tests.client import helpers as H
from tests.client import scenarios as S
from tests.client.scenarios import DOMAIN, USER, key


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def _fx(tmp_path, name, mutate=None):
    return H.write_checks(H.scenario(name, mutate), directory=tmp_path / f"fx-{name}-{id(mutate)}")


def _verify(capsys, fx):
    code = main(["client", "--verify", "--json", "--replay", str(fx)])
    doc = json.loads(capsys.readouterr().out)
    return code, {i["code"]: i["outcome"] for i in doc["items"]}, doc


def _first(capsys, fx):
    code = main(["client", "--user", USER, "--service", "sshd", "--json", "--replay", str(fx)])
    capsys.readouterr()
    return code


def test_resolved_after_the_fix(state, capsys):
    assert _first(capsys, _fx(state, "sssd-stopped")) == 1
    code, items, doc = _verify(capsys, _fx(state, "healthy"))
    assert items == {"SSSD_NOT_RUNNING": "RESOLVED"} and code == 0
    assert doc["current"]["input"]["user"] == USER  # the same question is asked again


def test_still_present_when_nothing_changed(state, capsys):
    fx = _fx(state, "sssd-stopped")
    _first(capsys, fx)
    code, items, _ = _verify(capsys, fx)
    assert items == {"SSSD_NOT_RUNNING": "STILL_PRESENT"} and code == 1


def test_collector_failure_is_never_resolved(state, capsys):
    _first(capsys, _fx(state, "sssd-stopped"))

    def broken(d):
        d[key("systemd.unit", service="sssd")] = S.ok({}, "systemctl: timed out", status="NOT_RUN")

    code, items, _ = _verify(capsys, _fx(state, "healthy", broken))
    assert items == {"SSSD_NOT_RUNNING": "UNABLE_TO_VERIFY"} and code == 4


def test_symptom_changed_is_not_resolved(state, capsys):
    _first(capsys, _fx(state, "sssd-stopped"))

    def activating(d):
        d[key("systemd.unit", service="sssd")]["fields"].update(active_state="activating")

    code, items, _ = _verify(capsys, _fx(state, "healthy", activating))
    assert items["SSSD_NOT_RUNNING"] == "UNABLE_TO_VERIFY" and code == 4


def test_partial_recovery_with_an_independent_cause_remaining(state, capsys):
    _first(capsys, _fx(state, "dns-and-config"))
    code, items, doc = _verify(capsys, _fx(state, "dns-failure"))
    assert items["SSSD_CONFIG_INVALID"] == "RESOLVED"
    assert items["DNS_RESOLVER_NOT_ANSWERING"] == "STILL_PRESENT"
    assert code == 1


def test_fix_criteria_failing_makes_it_partial(state, capsys):
    _first(capsys, _fx(state, "stale-cache"))

    def still_broken_for_the_fix(d):
        # the lookup passes (the planner's symptom) ...
        pass

    code, items, _ = _verify(capsys, _fx(state, "healthy", still_broken_for_the_fix))
    assert items == {"SSSD_CACHE_INCONSISTENT": "RESOLVED"} and code == 0

    _first(capsys, _fx(state, "stale-cache"))

    def unit_down(d):  # ... but the fresh check behind a fix criterion cannot run: never RESOLVED
        d[key("nss.user_sss", user=USER)] = S.ok({}, "getent: timed out", status="NOT_RUN")

    code, items, _ = _verify(capsys, _fx(state, "healthy", unit_down))
    assert items["SSSD_CACHE_INCONSISTENT"] == "UNABLE_TO_VERIFY" and code == 4


def test_new_problem_blocks_a_clean_verify(state, capsys):
    _first(capsys, _fx(state, "sssd-stopped"))
    code, items, doc = _verify(capsys, _fx(state, "time-skew"))
    assert items["SSSD_NOT_RUNNING"] == "RESOLVED"
    assert "This host's clock is too far from the IPA server's" in doc["new_conditions"] and code == 1


def test_tampered_state_is_refused(state, capsys):
    _first(capsys, _fx(state, "sssd-stopped"))
    path = V.state_path(True)
    doc = json.loads(path.read_text())
    doc["diagnoses"][0]["code"] = "rm -rf /"
    path.write_text(json.dumps(doc))
    code = main(["client", "--verify", "--json", "--replay", str(_fx(state, "healthy"))])
    assert code == 4 and json.loads(capsys.readouterr().out)["baseline_unreadable"] is True


def test_tampered_fix_record_cannot_pass(state, capsys):
    _first(capsys, _fx(state, "stale-cache"))
    path = V.state_path(True)
    doc = json.loads(path.read_text())
    fix = doc["fixes"]["SSSD_CACHE_INCONSISTENT"]
    fix["bindings"]["user"] = "someone-else"
    path.write_text(json.dumps(doc))
    code, items, _ = _verify(capsys, _fx(state, "healthy"))
    assert items["SSSD_CACHE_INCONSISTENT"] == "UNABLE_TO_VERIFY" and code == 4


def test_no_baseline_is_a_plain_run(state, capsys):
    code, items, doc = _verify(capsys, _fx(state, "healthy"))
    assert items == {} and doc["previous_generated_at"] is None and code == 0


def test_replay_state_never_touches_the_live_baseline(state, capsys):
    _first(capsys, _fx(state, "sssd-stopped"))
    assert V.state_path(True).exists() and not V.state_path(False).exists()


# ---- red-team round 1 (F1): a different --user/--service is never a RESOLVED
@pytest.mark.parametrize("scenario,first,second", [
    ("user-missing-in-ipa", ["--user", "alice", "--service", "sshd"], ["--user", "bob", "--service", "sshd"]),
    ("pam-not-integrated", ["--user", "alice", "--service", "sshd"], ["--user", "alice", "--service", "login"]),
    ("pam-denied", ["--user", "alice", "--service", "sshd"], ["--user", "bob", "--service", "sshd"]),
])
def test_verify_with_other_inputs_is_unable_not_resolved(state, capsys, scenario, first, second):
    fx = _fx(state, scenario)
    main(["client", *first, "--json", "--replay", str(fx)])
    capsys.readouterr()
    healthy = H.write_checks(H.scenario("healthy"), directory=state / f"any-{scenario}")
    code = main(["client", "--verify", *second, "--json", "--replay", str(healthy)])
    doc = json.loads(capsys.readouterr().out)
    assert {i["outcome"] for i in doc["items"]} == {"UNABLE_TO_VERIFY"} and code == 4
