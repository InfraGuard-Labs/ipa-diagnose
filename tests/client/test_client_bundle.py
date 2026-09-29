"""`ipa-diagnose bundle --client`: client.json is structure only, pseudonymized, and passes the leak self-test."""

from __future__ import annotations

import json
import pathlib
import shutil
import tarfile

import pytest

from ipa_diagnose.cli import main
from tests.client import helpers as H

ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))


def _bundle(tmp_path, scenario, *extra):
    fx = tmp_path / f"fx-{scenario}"
    shutil.copytree(ROOT / "tests" / "fixtures" / "real-freeipa-capture" / "healthy", fx)
    H.write_checks(H.scenario(scenario), directory=fx)
    out = tmp_path / f"{scenario}.tar.gz"
    code = main(["bundle", "--client", "--user", "alice", "--service", "sshd", "--replay", str(fx), "--output",
                 str(out), *extra])
    return code, out


def _member(path, name):
    with tarfile.open(path) as t:
        return t.extractfile(f"ipa-diagnose-bundle/{name}").read().decode()


@pytest.mark.parametrize("scenario", ["cache-db-error", "hostile-output", "healthy", "keytab-mismatch"])
def test_client_json_is_structural_and_pseudonymized(tmp_path, capsys, scenario):
    code, out = _bundle(tmp_path, scenario)
    assert code == 0, capsys.readouterr()
    text = _member(out, "client.json")
    doc = json.loads(text)
    assert doc["source_mode"] == "REPLAY" and doc["client_schema_version"] == "1.0"
    for raw in ("alice", "client1", "lab.test", "LAB.TEST", "ipa01", "EVIL", "Secret123", "sss_cache",
                "sssctl cache-remove", "Input/output", "host/"):
        assert raw not in text, raw
    assert all(r["commands_included"] is False for r in doc["resolution"])
    assert main(["bundle", "validate", str(out)]) == 0


def test_client_member_is_optional_and_listed_in_the_manifest(tmp_path, capsys):
    code, out = _bundle(tmp_path, "sssd-stopped")
    manifest = json.loads(_member(out, "manifest.json"))
    assert "client.json" in [m["name"] for m in manifest["members"]]


@pytest.mark.parametrize("args", [["--user", "alice"], ["--client", "--service", "sshd"], ["--client", "--user", "-x"]])
def test_bundle_client_usage_errors(tmp_path, args):
    with pytest.raises(SystemExit) as e:
        main(["bundle", "--preview", *args])
    assert e.value.code == 2
