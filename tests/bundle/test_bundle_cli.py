"""`ipa-diagnose bundle`: preview writes nothing, creation is fail-closed, nothing else in the CLI changes."""

from __future__ import annotations

import json
import os
import pathlib

import pytest

from ipa_diagnose import cli
from ipa_diagnose.bundle import selftest

from tests.bundle.helpers import CANARIES, ROOT, canary_fixture, members_of

FX = str(ROOT / "replication" / "peer-unreachable")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


def _files(path):
    return sorted(p.name for p in pathlib.Path(path).iterdir())


def test_preview_writes_nothing_and_says_what_would_be_included(capsys, tmp_path):
    assert cli.main(["bundle", "--preview", "--replay", FX]) == 0
    out = capsys.readouterr().out
    assert "nothing was written" in out and "report.json" in out and "Pseudonymized: host 2" in out
    assert "Never included:" in out and "Leak self-test: passed" in out and "REPLAY" in out
    assert _files(tmp_path / "work") == [] and not (tmp_path / "state").exists()
    assert "example.test" not in out and "ipa02" not in out


def test_preview_json_is_machine_readable(capsys):
    assert cli.main(["bundle", "--preview", "--json", "--replay", FX]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["preview"] is True and data["written"] is False and data["source_mode"] == "REPLAY"
    assert data["estimated_bytes"] > 0 and {m["name"] for m in data["members"]} >= {"manifest.json", "SHA256SUMS"}


def test_create_then_validate(capsys, tmp_path):
    assert cli.main(["bundle", "--replay", FX]) == 0
    out = capsys.readouterr().out
    [name] = _files(tmp_path / "work")
    assert name.startswith("ipa-diagnose-bundle-") and name.endswith(".tar.gz")
    assert "Support bundle written" in out and "Nothing was uploaded" in out and "bundle validate" in out
    assert cli.main(["bundle", "validate", name]) == 0
    assert "VALID" in capsys.readouterr().out
    assert cli.main(["bundle", "validate", name, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_output_directory_and_no_overwrite(capsys, tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    assert cli.main(["bundle", "--replay", FX, "--output", str(out_dir / "b.tar.gz"), "--json"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["created"] is True and pathlib.Path(first["path"]).exists()
    before = (out_dir / "b.tar.gz").read_bytes()
    assert cli.main(["bundle", "--replay", FX, "-o", str(out_dir / "b.tar.gz")]) == 5
    assert "already exists" in capsys.readouterr().out and (out_dir / "b.tar.gz").read_bytes() == before
    assert cli.main(["bundle", "--replay", FX, "-o", str(out_dir)]) == 0
    assert len(_files(out_dir)) == 2


def test_leak_self_test_failure_writes_nothing(capsys, tmp_path, monkeypatch):
    def leak(members, originals, forbidden=()):
        raise selftest.LeakDetected([("report.json", "real identifier (HOST)")])

    monkeypatch.setattr(selftest, "check", leak)
    assert cli.main(["bundle", "--replay", FX, "-o", str(tmp_path / "work")]) == 5
    out = capsys.readouterr().out
    assert "No bundle was created" in out and "report.json: real identifier (HOST)" in out
    assert _files(tmp_path / "work") == []
    assert cli.main(["bundle", "--replay", FX, "--json"]) == 5
    assert json.loads(capsys.readouterr().out)["created"] is False


def test_the_real_self_test_catches_a_broken_redactor(capsys, tmp_path, monkeypatch):
    """Fail closed: if redaction and pseudonymization stopped working, no canary may reach a file."""

    from ipa_diagnose.bundle import sanitize

    monkeypatch.setattr(sanitize, "redact", lambda text, counts=None: text)
    monkeypatch.setattr(sanitize.Sanitizer, "pseudonymize", lambda self, text: text)
    fx = canary_fixture(tmp_path)
    assert cli.main(["bundle", "--replay", str(fx), "--json"]) == 5
    result = json.loads(capsys.readouterr().out)
    cats = " ".join(result["problems"])
    assert "credential pattern" in cats and "real identifier" in cats
    assert not any(c.lower() in cats.lower() for c in CANARIES)  # problems never echo the value
    assert _files(tmp_path / "work") == []


def test_canaries_do_not_reach_the_written_file(tmp_path):
    fx = canary_fixture(tmp_path)
    assert cli.main(["bundle", "--replay", str(fx), "-o", str(tmp_path / "c.tar.gz")]) == 0
    data = (tmp_path / "c.tar.gz").read_bytes()
    text = "\n".join(m.decode() for m in members_of(data).values()).lower()
    assert not [c for c in CANARIES if c.lower() in text]


def test_bundle_never_changes_the_verify_baseline(capsys, tmp_path):
    state = tmp_path / "state" / "last_report.replay.json"
    assert cli.main(["--replay", FX, "--json"]) in (0, 1, 2, 3, 4)
    capsys.readouterr()
    before = state.read_bytes()
    assert cli.main(["bundle", "--replay", FX, "-o", str(tmp_path / "b.tar.gz")]) == 0
    assert state.read_bytes() == before
    verification = json.loads(members_of((tmp_path / "b.tar.gz").read_bytes())["verification.json"])
    assert verification["baseline_present"] is True and verification["context_only"] is True


def test_bundle_never_contacts_an_ai_provider(capsys, monkeypatch):
    import ipa_diagnose.cli as c

    monkeypatch.setenv("IPA_DIAGNOSE_AI_PROVIDER", "openai")
    monkeypatch.setattr(c, "build_provider", lambda *a, **k: (_ for _ in ()).throw(AssertionError("AI contacted")))
    assert cli.main(["bundle", "--preview", "--replay", FX]) == 0
    with pytest.raises(SystemExit) as e:
        cli.main(["bundle", "--preview", "--ai-provider", "openai", "--replay", FX])
    assert e.value.code == 2


def test_live_mode_bundle_is_labelled_live(capsys, tmp_path, monkeypatch):
    from tests.adversarial import test_false_reassurance as fr

    fr._install(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert cli.main(["bundle", "-o", str(tmp_path / "live.tar.gz")]) == 0
    capsys.readouterr()
    m = members_of((tmp_path / "live.tar.gz").read_bytes())
    manifest = json.loads(m["manifest.json"])
    assert manifest["source_mode"] == "LIVE" and "LIVE -" in m["README.txt"].decode()
    assert "ipa01" not in "".join(x.decode() for x in m.values())


@pytest.mark.parametrize("argv", [
    ["bundle", "validate"], ["bundle", "validate", "x", "--replay", "y"], ["bundle", "somefile"],
    ["bundle", "--preview", "--output", "x"], ["bundle", "validate", "a", "b"],
])
def test_usage_errors(argv):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2


def test_validate_reports_problems_without_echoing_hostile_names(capsys, tmp_path):
    bad = tmp_path / "\x1b[31mevil.tar.gz"
    bad.write_bytes(b"not a bundle")
    assert cli.main(["bundle", "validate", str(bad)]) == 5
    out = capsys.readouterr().out
    assert "NOT VALID" in out and "\x1b" not in out


def test_other_commands_are_unchanged(capsys):
    assert cli._first_positional(["--replay", "bundle", "--json"]) is None
    assert cli._first_positional(["--replay", "x", "bundle"]) == "bundle"
    assert cli._first_positional(["--json", "verify"]) == "verify"
    assert cli._first_positional(["--", "bundle"]) is None
    code = cli.main(["--replay", FX, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1 and data["overall_status"] == "DEGRADED" and data["report_schema_version"] == 2
    with pytest.raises(SystemExit) as e:
        cli.main(["nonsense"])
    assert e.value.code == 2


def test_a_missing_replay_directory_is_refused(capsys, tmp_path):
    assert cli.main(["bundle", "--replay", str(tmp_path / "nope")]) == 5
    assert "does not exist" in capsys.readouterr().out and _files(tmp_path / "work") == []
