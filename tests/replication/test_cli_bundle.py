"""`ipa-diagnose replication` CLI, JSON contract, and `bundle --replication`."""

from __future__ import annotations

import io
import json
import pathlib
import shutil
import tarfile

import pytest

from ipa_diagnose import cli as main_cli
from tests.replication import helpers as H
from tests.replication import scenarios as S
from tests.replication.scenarios import IPA01, IPA02, Lab

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def state_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    import ipa_diagnose.verify as V

    monkeypatch.setattr(V, "default_state_path", lambda: tmp_path / "state" / "last_report.json")


def run_cli(argv, capsys):
    rc = main_cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def fx(lab) -> str:
    return str(H.write(lab.build()))


def test_json_contract_and_exit_codes(capsys):
    rc, out, _ = run_cli(["replication", "--replay", fx(Lab()), "--json"], capsys)
    doc = json.loads(out)
    assert rc == 0 and doc["status"] == "HEALTHY" and doc["source_mode"] == "REPLAY"
    for k in ("kind", "replication_schema_version", "subjects", "relationships", "trace", "cause_chains", "diagnoses",
              "resolutions", "completeness", "topology", "environment_graph", "verification", "limitations",
              "handoffs"):
        assert k in doc, k
    assert doc["kind"] == "ipa-diagnose.replication" and doc["replication_schema_version"] == "1.0"
    rc, out, _ = run_cli(["replication", "--replay", fx(Lab().peer_ds_stopped(IPA02)), "--json"], capsys)
    assert rc == 1 and json.loads(out)["status"] == "PROBLEM_FOUND"
    rc, _o, _e = run_cli(["replication", "--replay", fx(Lab().set_reverse(IPA02, status="NOT_RUN"))], capsys)
    assert rc == 4


def test_the_json_is_deterministic_apart_from_timestamps(capsys):
    d = fx(Lab().peer_ds_stopped(IPA02))
    docs = []
    for _ in range(2):
        _rc, out, _ = run_cli(["replication", "--replay", d, "--json"], capsys)
        doc = json.loads(out)
        for k in ("generated_at", "planner_summary"):
            doc.pop(k)
        doc["trace"] = [{k: v for k, v in s.items() if k not in ("collected_at", "seconds")} for s in doc["trace"]]
        doc["environment_graph"]["facts"] = [{k: v for k, v in f.items() if k != "collected_at"}
                                             for f in doc["environment_graph"]["facts"]]
        doc["completeness"].pop("planner")
        docs.append(json.dumps(doc, sort_keys=True))
    assert docs[0] == docs[1]


def test_console_output_names_direction_suffix_handoff(capsys):
    rc, out, _ = run_cli(["replication", "--replay", fx(Lab().peer_ds_stopped(IPA02))], capsys)
    assert f"domain  {IPA01} -> {IPA02}" in out and f"ca      {IPA01} -> {IPA02}" in out
    assert "HANDOFF" in out and f"sudo ipa-diagnose replication --peer {IPA01}" in out
    assert "Stops here:" in out


@pytest.mark.parametrize("argv", [["--peer", "not a host"], ["--peer", "-x"], ["--ai-provider", "openai"],
                                  ["--replay", "/nonexistent-dir"], ["--bogus"]])
def test_usage_errors(argv, capsys):
    with pytest.raises(SystemExit) as e:
        main_cli.main(["replication"] + argv)
    assert e.value.code == 2


def test_hostile_peer_argument_is_sanitized_in_the_error(capsys):
    with pytest.raises(SystemExit):
        main_cli.main(["replication", "--peer", "\x1b]52;c;evil\x07"])
    assert "\x1b" not in capsys.readouterr().err


def test_not_an_ipa_server_exits_4_and_saves_nothing(capsys, tmp_path):
    lab = Lab()
    lab.data[S.key("repl.server", {})]["fields"]["is_ipa_server"] = False
    rc, out, _ = run_cli(["replication", "--replay", fx(lab), "--json"], capsys)
    assert rc == 4 and json.loads(out)["status"] == "NOT_AN_IPA_SERVER"
    assert not list((tmp_path / "state").glob("replication_last*")) if (tmp_path / "state").exists() else True


def test_verify_flow_uses_the_saved_state_and_pending_exits_3(capsys, tmp_path):
    rc, _o, _e = run_cli(["replication", "--replay", fx(Lab().local_kdc_stopped())], capsys)
    assert rc == 1
    import datetime

    old = Lab(now=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5))
    rc, out, _ = run_cli(["replication", "--replay", fx(old), "--verify", "--json"], capsys)
    doc = json.loads(out)
    assert rc == 3 and {i["outcome"] for i in doc["items"]} == {"PENDING"}
    assert doc["ruv_equality_required"] is False
    later = Lab(now=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
    rc, out, _ = run_cli(["replication", "--replay", fx(later), "--verify", "--json"], capsys)
    doc = json.loads(out)
    assert rc == 0 and {i["outcome"] for i in doc["items"]} == {"RESOLVED"}


def test_verify_with_a_damaged_state_exits_4(capsys, tmp_path):
    run_cli(["replication", "--replay", fx(Lab().local_kdc_stopped())], capsys)
    for p in (tmp_path / "state").glob("replication_last*.json"):
        p.write_text("{damaged", encoding="utf-8")
    rc, _o, err = run_cli(["replication", "--replay", fx(Lab()), "--verify"], capsys)
    assert rc == 4 and "cannot be read" in err


def test_output_never_contains_credentials_or_key_material(capsys):
    lab = Lab().local_kdc_stopped()
    lab.data[S.key("repl.agreements", {})]["fields"]["agreements"][0]["status_text"] += \
        " password=hunter2 nsDS5ReplicaCredentials: {AES}c2VjcmV0"
    rc, out, _ = run_cli(["replication", "--replay", fx(lab), "--json", "--details"], capsys)
    assert "hunter2" not in out and "c2VjcmV0" not in out


def test_output_strips_terminal_escapes_from_evidence(capsys):
    lab = Lab().set_status(IPA02, "Error (77) \x1b[2J\x1b]0;owned\x07 bidi‮ text")
    _rc, out, _ = run_cli(["replication", "--replay", fx(lab)], capsys)
    assert "\x1b" not in out and "‮" not in out


# ---------------------------------------------------------------- bundle --replication


def _bundle_fixture(tmp_path, lab) -> str:
    d = tmp_path / "fx"
    shutil.copytree(FIXTURES / "real-freeipa-capture" / "healthy", d)
    (d / "replication_checks.json").write_text(json.dumps(lab.build()), encoding="utf-8")
    return str(d)


def _members(path):
    with tarfile.open(path, "r:gz") as t:
        return {m.name.split("/", 1)[1]: t.extractfile(m).read().decode("utf-8") for m in t.getmembers() if m.isfile()}


def test_bundle_with_replication_is_pseudonymized_structure_only(tmp_path, capsys):
    out = tmp_path / "b.tar.gz"
    d = _bundle_fixture(tmp_path, Lab().peer_ds_stopped(IPA02))
    rc, stdout, err = run_cli(["bundle", "--replay", d, "--replication", "--output", str(out), "--json"], capsys)
    assert rc == 0, stdout + err
    m = _members(out)
    assert "replication.json" in m
    doc = json.loads(m["replication.json"])
    blob = "\n".join(m.values())
    for raw in ("ipa01.lab.test", "ipa02.lab.test", "lab.test", "LAB.TEST", "Can't contact LDAP server",
                "sudo ipa-diagnose", "systemctl"):
        assert raw not in m["replication.json"], raw
    assert "ipa02.lab.test" not in blob
    assert doc["diagnoses"] and all(x["subject"] is None or "HOST-" in x["subject"] or x["subject"].startswith(
        ("ruv:", "group:")) for x in doc["diagnoses"])
    assert {r["direction"] for r in doc["relationships"]} == {"outbound", "inbound"}
    assert all(c["links"][0]["discriminator"] == "agreement-status" for c in doc["cause_chains"])
    assert all(h["commands_included"] is False for h in doc["handoffs"])
    rc, vout, _ = run_cli(["bundle", "validate", str(out), "--json"], capsys)
    assert rc == 0


def test_bundle_peer_needs_replication_and_a_valid_name(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main_cli.main(["bundle", "--peer", IPA02])
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        main_cli.main(["bundle", "--replication", "--peer", "bad name"])
    assert e.value.code == 2


def test_bundles_without_replication_do_not_change(tmp_path, capsys):
    out = tmp_path / "plain.tar.gz"
    rc, _o, _e = run_cli(["bundle", "--replay", str(FIXTURES / "real-freeipa-capture" / "healthy"), "--output",
                          str(out)], capsys)
    assert rc == 0 and "replication.json" not in _members(out)
