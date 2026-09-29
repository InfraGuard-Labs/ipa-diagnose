"""`ipa-diagnose client` command line: exit codes, JSON contract, output safety, usage errors."""

from __future__ import annotations

import json
import re

import pytest

from ipa_diagnose.cli import main
from tests.client import helpers as H


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))


def _run(capsys, tmp_path, name, *extra):
    fx = H.write_checks(H.scenario(name), directory=tmp_path / name)
    code = main(["client", "--replay", str(fx), *extra])
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.parametrize("name,code", [("healthy", 0), ("srv-missing-fixed-fallback", 0), ("sssd-stopped", 1),
                                       ("dns-and-config", 1), ("collector-timeout", 4), ("not-enrolled", 1)])
def test_exit_codes(capsys, tmp_path, name, code):
    assert _run(capsys, tmp_path, name, "--user", "alice", "--service", "sshd")[0] == code


def test_json_contract(capsys, tmp_path):
    code, out, _ = _run(capsys, tmp_path, "stale-cache", "--user", "alice", "--service", "sshd", "--json")
    doc = json.loads(out)
    assert doc["kind"] == "ipa-diagnose.client" and doc["client_schema_version"] == "1.0"
    for k in ("environment", "planner_summary", "steps", "authentication", "authorization", "runtime_access",
              "diagnoses", "ruled_out", "resolution", "verification", "completeness", "limitations", "evidence"):
        assert k in doc
    assert doc["source_mode"] == "REPLAY" and "REPLAY" in doc["evidence"]["provenance"]["via"]
    assert doc["runtime_access"]["state"] == "FAIL" and doc["authentication"]["state"] != "PASS"
    step = doc["steps"][0]
    for k in ("step", "capability", "check", "outcome", "why_in_plan", "command", "privilege", "side_effects",
              "collected_at", "source"):
        assert k in step
    fix = doc["resolution"]["SSSD_CACHE_INCONSISTENT"]
    assert fix["status"] == "OFFERED" and fix["steps"][0]["argv"] == ["sss_cache", "-u", "alice"]
    assert doc["verification"]["criteria"]["SSSD_CACHE_INCONSISTENT"]


def test_console_shows_checked_for_you_and_ruled_out(capsys, tmp_path):
    _, out, _ = _run(capsys, tmp_path, "sssd-stopped", "--user", "alice", "--service", "sshd")
    assert "CHECKED FOR YOU" in out and "✓ IPA server name resolves" in out and "✗ SSSD service running" in out
    assert "RULED OUT" in out and "systemctl start sssd.service" in out
    assert "why now:" not in out  # planner detail only with --details


def test_details_explain_why_each_check_ran_or_not(capsys, tmp_path):
    _, out, _ = _run(capsys, tmp_path, "stale-cache", "--user", "alice", "--service", "sshd", "--details")
    assert "why now:" in out and "Not run:" in out and "note:" in out


_BAD = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")


def test_hostile_recorded_output_is_neutralised(capsys, tmp_path):
    for fmt in ((), ("--json",), ("--details",)):
        _, out, _ = _run(capsys, tmp_path, "hostile-output", "--user", "alice", *fmt)
        assert not _BAD.search(out), fmt
        assert "Secret123" not in out


@pytest.mark.parametrize("args", [["--user", "-rf"], ["--user", "1000"], ["--user", "all"], ["--user", "a;b"],
                                  ["--service", "sshd"], ["--user", "alice", "--service", "../x"],
                                  ["--ai-provider", "openai"]])
def test_usage_errors(capsys, tmp_path, args):
    fx = H.write_checks(H.scenario("healthy"), directory=tmp_path / "fx")
    with pytest.raises(SystemExit) as e:
        main(["client", "--replay", str(fx), *args])
    assert e.value.code == 2


def test_no_ai_is_accepted_and_ignored(capsys, tmp_path):
    assert _run(capsys, tmp_path, "healthy", "--no-ai")[0] == 0


def test_replay_directory_must_exist(capsys, tmp_path):
    with pytest.raises(SystemExit):
        main(["client", "--replay", str(tmp_path / "nope")])


def test_top_level_help_lists_client(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "client:" in capsys.readouterr().out
