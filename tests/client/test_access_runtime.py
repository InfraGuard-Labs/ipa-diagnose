"""`ipa-diagnose access ... --runtime` (Slice 3 + 4 boundary): HBAC stays FreeIPA's decision; runtime is separate."""

from __future__ import annotations

import json

import pytest

from ipa_diagnose.cli import main
from tests.access.helpers import World
from tests.client import helpers as H
from tests.client import scenarios as S


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))


def _fx(tmp_path, client_scenario, allow=True, host=S.HOST, mutate=None):
    d = tmp_path / f"{client_scenario}-{allow}-{host}"
    H.write_checks(H.scenario(client_scenario, mutate), directory=d)
    w = World().user("alice").host(host).service("sshd")
    if allow:
        w.rule("r1", users=["alice"], hosts=[host], services=["sshd"])
    else:
        w.rule("r_other", users=["alice"], hosts=["other.lab.test"], services=["sshd"])
        w.host("other.lab.test")
    w.write(d, "alice", host, "sshd")
    return d


def _access(capsys, fx, *extra, host=S.HOST):
    code = main(["access", "alice", host, "sshd", "--replay", str(fx), "--json", *extra])
    return code, json.loads(capsys.readouterr().out)


def test_hbac_pass_and_client_side_failure(tmp_path, capsys):
    code, doc = _access(capsys, _fx(tmp_path, "sssd-stopped"), "--runtime")
    assert doc["authorization"]["state"] == "PASS" and doc["authorization"]["decided_by"] == "FreeIPA hbactest"
    assert doc["runtime_access"]["state"] == "FAIL" and doc["runtime_access"]["investigated"] is True
    assert doc["access_schema_version"] == "1.1" and code == 5
    assert any("SSSD is not running" in x for x in doc["diagnosis"]["root_cause"])
    assert "login is expected to fail" in doc["answer"]


def test_runtime_never_rewrites_the_hbac_decision(tmp_path, capsys):
    code, doc = _access(capsys, _fx(tmp_path, "pam-denied"), "--runtime")
    assert doc["authorization"]["state"] == "PASS"
    diags = {d["code"]: d["role"] for d in doc["runtime_access"]["client"]["diagnoses"]}
    assert diags == {"RUNTIME_DENIED_HBAC_ALLOWS": "CONTRADICTING"}
    assert doc["runtime_access"]["state"] == "FAIL" and code == 5


def test_healthy_runtime_stays_not_verified(tmp_path, capsys):
    code, doc = _access(capsys, _fx(tmp_path, "healthy"), "--runtime")
    assert doc["runtime_access"]["state"] == "NOT_VERIFIED" and code == 0
    assert "checked on" in doc["runtime_access"]["summary"]
    assert not any("sssctl user-checks" in v for v in doc["verify"])


def test_deny_is_not_investigated_further(tmp_path, capsys):
    code, doc = _access(capsys, _fx(tmp_path, "sssd-stopped", allow=False), "--runtime")
    assert doc["authorization"]["state"] == "FAIL" and code == 1
    assert doc["runtime_access"]["investigated"] is False and "already refuses" in doc["runtime_access"]["note"]


def test_not_on_the_target_host_prints_the_command_instead(tmp_path, capsys):
    host = "app07.lab.test"
    code, doc = _access(capsys, _fx(tmp_path, "sssd-stopped", host=host), "--runtime", host=host)
    rt = doc["runtime_access"]
    assert rt["state"] == "NOT_VERIFIED" and rt["investigated"] is False and code == 0
    assert "ipa-diagnose client --user alice --service sshd" in rt["note"] and "never runs checks on another host" \
        in rt["note"]


def test_without_runtime_the_slice3_answer_is_unchanged(tmp_path, capsys):
    code, doc = _access(capsys, _fx(tmp_path, "sssd-stopped"))
    assert doc["access_schema_version"] == "1.0" and "investigated" not in doc["runtime_access"]
    assert doc["runtime_access"]["state"] == "NOT_VERIFIED" and code == 0


def test_console_runtime_section(tmp_path, capsys):
    fx = _fx(tmp_path, "stale-cache")
    main(["access", "alice", S.HOST, "sshd", "--replay", str(fx), "--runtime"])
    out = capsys.readouterr().out
    assert "RUNTIME (--runtime)" in out and "sss_cache -u alice" in out
    assert "AUTHORIZATION   PASS" in out and "RUNTIME ACCESS  FAIL" in out
