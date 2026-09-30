"""The committed replication replay fixtures are generated (scripts/make_replication_fixtures.py) and stay in sync."""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

from ipa_diagnose.replication.run import REPLAY_FIELD_LIMIT, investigate
from ipa_diagnose.resolution.checks import ReplayRunner

ROOT = pathlib.Path(__file__).resolve().parents[2]
FX = ROOT / "tests" / "fixtures" / "replication-mode"


def test_committed_fixtures_are_up_to_date():
    spec = importlib.util.spec_from_file_location("mk", ROOT / "scripts" / "make_replication_fixtures.py")
    mk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mk)
    assert mk.main(check=True) == 0


@pytest.mark.parametrize("name,status,primary", [
    ("healthy", "HEALTHY", None),
    ("peer-ds-stopped", "PROBLEM_FOUND", "PEER_DS_NOT_ACCEPTING"),
    ("peer-unreachable", "PROBLEM_FOUND", "PEER_UNREACHABLE"),
    ("local-kdc-stopped", "PROBLEM_FOUND", "LOCAL_KDC_NOT_RUNNING"),
    ("clock-skew", "PROBLEM_FOUND", "PAIR_CLOCK_SKEW"),
    ("ca-suffix-generation-mismatch", "PROBLEM_FOUND", "REPLICA_NEEDS_ADMIN_ACTION"),
    ("reverse-not-observable", "NOT_FULLY_VERIFIED", None),
    ("middle-server-two-causes", "PROBLEM_FOUND", "PEER_UNREACHABLE"),  # + PEER_DS_NOT_ACCEPTING INDEPENDENT
])
def test_committed_fixture_answers(name, status, primary):
    r = investigate(ReplayRunner(str(FX / name), filename="replication_checks.json", field_limit=REPLAY_FIELD_LIMIT),
                    is_root=True)
    assert r.status == status
    p = next((d.code for d in r.diagnoses if d.role == "PRIMARY"), None)
    assert p == primary
    assert r.mode == "REPLAY" and not any(v.status == "OFFERED" for k, v in r.resolutions.items()
                                          if not k.startswith("_"))
