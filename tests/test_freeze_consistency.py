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


def test_replayed_server_and_client_fixes_say_not_to_run_them_here(capsys, tmp_path):
    main(["--replay", str(FIXTURES / "resolution" / "service-not-running")])
    assert "Do not run them here." in _flat(capsys.readouterr().out)
    fx = CH.write_checks(CH.scenario("sssd-stopped"), directory=tmp_path / "c")
    main(["client", "--replay", str(fx)])
    assert "Do not run them here." in _flat(capsys.readouterr().out)


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
