import json

from ipa_diagnose.cli import main


def test_diagnose_replay_healthy_json(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    exit_code = main(["--replay", "tests/fixtures/replication/healthy", "diagnose", "--json"])
    assert exit_code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["overall_status"] == "HEALTHY"
    assert data["diagnoses"] == []


def test_diagnose_replay_healthy_text(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    exit_code = main(["--replay", "tests/fixtures/replication/healthy", "diagnose"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "HEALTHY" in out
    assert "No problems detected" in out


def test_verify_with_no_prior_state(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    exit_code = main(["--replay", "tests/fixtures/replication/healthy", "verify"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No previous diagnosis found" in out


def test_ai_preview_with_no_problems(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    exit_code = main(["--replay", "tests/fixtures/replication/healthy", "ai-preview"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "No primary or independent problems" in out


def test_missing_fixture_dir_reports_collection_error_not_crash(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    exit_code = main(["--replay", str(tmp_path / "does-not-exist"), "diagnose", "--json"])
    # A --replay of a directory that does not exist must never look healthy:
    # it is a visible collection error and UNKNOWN (exit 3), not a crash.
    assert exit_code == 3
    data = json.loads(capsys.readouterr().out)
    assert data["overall_status"] == "UNKNOWN"
    assert any("replay directory not found" in e for e in data["collection_errors"])


def test_replay_runs_never_overwrite_the_real_verify_baseline(tmp_path, monkeypatch):
    """Release-candidate review finding: a README demo (`--replay ... diagnose`) used to
    overwrite the real server's baseline, so the next `verify` compared against fixture data."""
    state = tmp_path / "state"
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(state))
    main(["--replay", "tests/fixtures/replication/healthy", "diagnose"])
    assert (state / "last_report.replay.json").exists()
    assert not (state / "last_report.json").exists()
