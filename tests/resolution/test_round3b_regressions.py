"""Regressions for the second round-3 independent review (verify, replay, knowledge loader, journal redaction)."""

from __future__ import annotations

import copy
import io
import json

import pytest
from rich.console import Console

from ipa_diagnose.render.console import render_report, render_verify
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.resolution import checks as C
from ipa_diagnose.resolution import knowledge as K
from ipa_diagnose.resolution.engine import stored_verify_matches
from ipa_diagnose.verify import VerifyOutcome, compare, load_previous_report

from tests.resolution.test_procedures import (
    CS, ROOT_OK, FakeRunner, perm, report_for, stat,
)


def _prev_with_fix():
    before, _ = report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat()})
    prev = json.loads(json.dumps(report_to_dict(before)))
    res = next(r for r in prev["v2"]["resolutions"] if r["status"] == "OFFERED")
    return prev, res


def _verify(prev, fresh_stat):
    after, _ = report_for([], {**ROOT_OK})
    return compare(prev, after, runner=FakeRunner({f"file.stat|path={CS}": fresh_stat}))


def test_untampered_criteria_match_the_catalogue():
    _, res = _prev_with_fix()
    assert stored_verify_matches(res["procedure_id"], res["verify"])


@pytest.mark.parametrize("tamper", [
    lambda r: r["verify"][0]["when"].update(op="ne"),
    lambda r: r["verify"][0]["when"].update(right="0664"),  # still a mode, but see below: type-valid values pass shape
    lambda r: r["verify"][0].update(check="host.privilege"),
    lambda r: r["verify"][0]["when"].update(right="no-such-mode"),
    lambda r: r["verify"].clear(),
    lambda r: r.update(procedure_id="proc.unknown"),
    lambda r: r["verify"][0].update(extra=1),
])
def test_tampered_criteria_are_not_run(tamper):
    prev, res = _prev_with_fix()
    tamper(res)
    out = _verify(prev, stat(mode="0664"))
    item = out.items[0]
    if item.outcome == VerifyOutcome.RESOLVED:
        # only a type-valid value of the same criterion can survive the shape check; the fresh mode must equal it
        assert res["verify"][0]["when"]["right"] == "0664"
    else:
        assert item.outcome in (VerifyOutcome.UNABLE_TO_VERIFY, VerifyOutcome.PARTIALLY_RESOLVED)


def test_op_tamper_that_used_to_pass_is_unable_to_verify():
    prev, res = _prev_with_fix()
    res["verify"][0]["when"] = {"left": {"ref": "this", "field": "mode"}, "op": "ne", "right": "no-such-mode"}
    item = _verify(prev, stat(mode="0664")).items[0]
    assert item.outcome == VerifyOutcome.UNABLE_TO_VERIFY and "do not match" in item.detail


def test_replay_verify_says_the_checks_were_recorded():
    prev, _ = _prev_with_fix()
    after, _ = report_for([], {**ROOT_OK})
    runner = FakeRunner({f"file.stat|path={CS}": stat(mode="0660")})
    runner.replay = True
    item = compare(prev, after, runner=runner).items[0]
    assert item.outcome == VerifyOutcome.RESOLVED and "recorded in the replay fixture, not run now" in item.detail
    after.replay_source = "tests/fixtures/x"
    buf = io.StringIO()
    render_verify(compare(prev, after, runner=runner), Console(file=buf, width=200, color_system=None))
    assert "nothing was checked on this host now" in buf.getvalue()


def test_hand_edited_state_file_cannot_fake_lines_or_crash(tmp_path):
    prev, _ = _prev_with_fix()
    prev["diagnoses"][0]["title"] = "x\n✓ RESOLVED  Kerberos KDC certificate expired" + "y" * 5000
    prev["diagnoses"][0]["pack_id"] = ["list"]
    prev["diagnoses"][0]["priority"] = {"a": 1}
    del prev["generated_at"]
    p = tmp_path / "last_report.json"
    p.write_text(json.dumps(prev), encoding="utf-8")
    loaded = load_previous_report(p)
    out = _verify(loaded, stat(mode="0664"))
    assert out.previous_generated_at == "an unknown time"
    assert "\n" not in out.items[0].title and len(out.items[0].title) <= 160
    assert out.items[0].outcome == VerifyOutcome.PARTIALLY_RESOLVED


@pytest.mark.parametrize("line,secret", [
    ("ldap bind failed password=Hunter2Secret! for cn=admin", "Hunter2Secret!"),
    ("GET /ipa Authorization: Basic YWRtaW46U2VjcmV0MTIz", "YWRtaW46U2VjcmV0MTIz"),
    ("x" * 180 + " token " + "A" * 60, "A" * 30),
    ('pin: "1234 5678"', "1234 5678"),
])
def test_journal_line_is_redacted_before_truncation(monkeypatch, line, secret):
    monkeypatch.setattr(C, "_run", lambda argv: (0, "start\n" + line + "\n", ""))
    res = C._journal_tail({"unit": "dirsrv@LAB-TEST.service"})
    assert secret not in res.fields["last_line"] and secret not in res.display


@pytest.mark.parametrize("doc", [
    '{"schema": 1, "procedures": [42]}',
    '{"schema": 1, "procedures": ' + "[" * 5000 + "]" * 5000 + "}",
])
def test_any_malformed_catalogue_disables_fixes_without_crashing(monkeypatch, doc):
    class _Res:
        def joinpath(self, _):
            return self

        def read_text(self, encoding):
            return doc

    monkeypatch.setattr(K.resources, "files", lambda _pkg: _Res())
    K.reset_cache()
    try:
        cat, err = K.load_catalogue()
        assert cat == [] and err
    finally:
        K.reset_cache()


def test_deeply_nested_replay_checks_file_is_ignored(tmp_path):
    (tmp_path / "resolution_checks.json").write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
    runner = C.ReplayRunner(str(tmp_path))
    assert runner.run("host.privilege", {}).status == C.NOT_RUN


def _catalogue_with(mutate):
    cat = json.loads(K.resources.files("ipa_diagnose.resolution").joinpath("procedures.json").read_text(encoding="utf-8"))
    proc = next(p for p in cat["procedures"] if p["id"] == "proc.service.start-stopped-service")
    prov = proc["provenance"]
    prov["tier"] = "BUILT_IN_VERIFIED"
    proc["applies_to"]["freeipa_min"] = "4.9"
    prov["verified_on"] = [{"freeipa": "4.13.3", "os": "fedora-43", "tier": "LIVE",
                            "evidence": "https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36055264033"}]
    prov["reviews"] = [{"by": "fresh reviewer", "date": "2026-09-24", "scope": "procedure", "independent": True}]
    mutate(proc)
    return cat


def test_complete_built_in_verified_provenance_is_accepted():
    K.validate_catalogue(_catalogue_with(lambda p: None))


@pytest.mark.parametrize("mutate", [
    lambda p: p["provenance"]["sources"][0].update(ref=""),
    lambda p: p["provenance"]["reviews"][0].update(by=""),
    lambda p: p["provenance"]["reviews"][0].update(date=""),
    lambda p: p["provenance"].update(tests=["nope"]),
    lambda p: p["provenance"]["verified_on"][0].update(evidence="."),
    lambda p: p["applies_to"].update(freeipa_min="0"),
    lambda p: p["applies_to"].update(freeipa_min="not-a-version"),
    lambda p: p["provenance"]["verified_on"][0].update(freeipa="latest"),
])
def test_empty_or_fake_provenance_is_rejected(mutate):
    with pytest.raises(K.KnowledgeError):
        K.validate_catalogue(_catalogue_with(mutate))


def test_withheld_fix_keeps_v013_confidence_limitations_and_verify_hint_in_details():
    report, _ = report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat(mode="0660")})  # already fixed -> withheld
    d = next(x for x in report.diagnoses if x.resolution_key == "directory-server.ipa-file-permissions")
    assert report.resolutions[d.diagnosis_id].status == "WITHHELD"
    buf = io.StringIO()
    render_report(copy.copy(report), Console(file=buf, width=200, color_system=None), details=True)
    text = buf.getvalue()
    assert "CONFIDENCE" in text and "sudo ipa-diagnose verify" in text
    if d.limitations:
        assert "LIMITATIONS" in text
