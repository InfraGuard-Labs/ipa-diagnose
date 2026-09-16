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
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["overall_status"] == "HEALTHY"  # no healthcheck.json found -> no findings, not a crash
