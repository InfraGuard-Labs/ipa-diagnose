"""Test helpers: run the client planner on a SYNTHETIC replay scenario (tests/client/scenarios.py)."""

from __future__ import annotations

import json
import pathlib
import tempfile
from typing import Any, Callable, Dict, Optional

from ipa_diagnose.client.run import ClientResult, investigate
from ipa_diagnose.resolution.checks import ReplayRunner
from tests.client import scenarios as S


def write_checks(data: Dict[str, Any], is_root: bool = True, directory: Optional[pathlib.Path] = None) -> pathlib.Path:
    d = directory or pathlib.Path(tempfile.mkdtemp(prefix="client-fx-"))
    d.mkdir(parents=True, exist_ok=True)
    (d / "client_checks.json").write_text(json.dumps(data), encoding="utf-8")
    (d / "meta.json").write_text(json.dumps({"is_root": is_root}), encoding="utf-8")
    return d


def scenario(name: str, mutate: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    d = S.build(name)
    if mutate:
        mutate(d)
    return d


def run(name: str = "healthy", user: Optional[str] = S.USER, service: Optional[str] = S.SERVICE,
        is_root: bool = True, hbac: Optional[str] = None,
        mutate: Optional[Callable[[Dict[str, Any]], None]] = None, data: Optional[Dict[str, Any]] = None
        ) -> ClientResult:
    d = write_checks(data if data is not None else scenario(name, mutate), is_root)
    return investigate(ReplayRunner(str(d), filename="client_checks.json"), user=user, service=service,
                       hbac_state=hbac, is_root=is_root)


def codes(r: ClientResult) -> Dict[str, str]:
    return {d.code: d.role for d in r.diagnoses}


def primary(r: ClientResult) -> Optional[str]:
    return next((d.code for d in r.diagnoses if d.role == "PRIMARY"), None)


def outcome(r: ClientResult, step: str) -> str:
    rec = r.trace.get(step)
    return rec.outcome.value if rec else "MISSING"


def offered(r: ClientResult) -> Dict[str, Any]:
    return {k: v for k, v in r.resolutions.items() if not k.startswith("_") and v.status == "OFFERED"}
