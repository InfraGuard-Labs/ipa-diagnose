"""Test helpers: run `ipa-diagnose replication` on SYNTHETIC scenarios (tests/replication/scenarios.py)."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any, Dict, Optional

from ipa_diagnose.replication.run import REPLAY_FIELD_LIMIT, ReplicationResult, investigate
from ipa_diagnose.resolution.checks import ReplayRunner
from tests.replication.scenarios import Lab


def write(data: Dict[str, Any], is_root: bool = True, directory: Optional[pathlib.Path] = None) -> pathlib.Path:
    d = directory or pathlib.Path(tempfile.mkdtemp(prefix="repl-fx-"))
    d.mkdir(parents=True, exist_ok=True)
    (d / "replication_checks.json").write_text(json.dumps(data), encoding="utf-8")
    (d / "meta.json").write_text(json.dumps({"is_root": is_root}), encoding="utf-8")
    return d


class LiveLikeRunner(ReplayRunner):
    """Answers from synthetic data but presents itself as LIVE: exercises the live-only gates (fresh revalidation,
    evidence age) in unit tests. `overrides` change answers for FRESH re-runs (a target that changed after the
    diagnosis)."""

    replay = False

    def __init__(self, data: Dict[str, Any], fresh_overrides: Optional[Dict[str, Any]] = None):
        d = write(data)
        super().__init__(str(d), filename="replication_checks.json", field_limit=REPLAY_FIELD_LIMIT)
        self.fresh_overrides = fresh_overrides or {}
        self.fresh_calls = []

    def run(self, check_id, params, fresh=False):
        if fresh:
            self.fresh_calls.append((check_id, dict(params)))
            k = check_id + "|" + ",".join(f"{a}={params[a]}" for a in sorted(params))
            if k in self.fresh_overrides:
                self._data[k] = self.fresh_overrides[k]
        return super().run(check_id, params, fresh=fresh)


def run(lab: Optional[Lab] = None, data: Optional[Dict[str, Any]] = None, peer: Optional[str] = None,
        is_root: bool = True, live: bool = False, runner: Any = None) -> ReplicationResult:
    data = data if data is not None else (lab or Lab()).build()
    if runner is None:
        runner = LiveLikeRunner(data) if live else ReplayRunner(
            str(write(data, is_root)), filename="replication_checks.json", field_limit=REPLAY_FIELD_LIMIT)
    return investigate(runner, peer=peer, is_root=is_root)


def by_code(r: ReplicationResult) -> Dict[str, str]:
    return {d.key: d.role for d in r.diagnoses}


def roles(r: ReplicationResult, role: str):
    return [d for d in r.diagnoses if d.role == role]


def primary(r: ReplicationResult):
    return next((d for d in r.diagnoses if d.role == "PRIMARY"), None)


def offered(r: ReplicationResult) -> Dict[str, Any]:
    return {k: v for k, v in r.resolutions.items() if not k.startswith("_") and v.status == "OFFERED"}


def rel(r: ReplicationResult, subject: str) -> Optional[Dict[str, Any]]:
    return next((x for x in r.relationships if x["subject"] == subject), None)
