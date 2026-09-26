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
from ipa_diagnose.resolution.engine import criteria_digest, rebuild_verify
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


def _fix(prev):
    return prev["v2"]["verify_baseline"]["fixes"][0]


def test_untampered_baseline_rebuilds_the_same_criteria():
    prev, res = _prev_with_fix()
    criteria, problem, _ = rebuild_verify(_fix(prev), FakeRunner({f"file.stat|path={CS}": stat()}))
    assert problem == "" and criteria_digest(criteria) == criteria_digest(res["verify"])


@pytest.mark.parametrize("tamper", [
    lambda r: r["verify"][0]["when"].update(op="ne"),
    lambda r: r["verify"][0]["when"].update(right="0664"),
    lambda r: r["verify"][0].update(check="host.privilege"),
    lambda r: r["verify"].clear(),
    lambda r: r.update(status="WITHHELD", procedure_id="proc.unknown", steps=[], risk="LOW"),
])
def test_display_copy_of_the_fix_is_never_used_by_verify(tamper):
    """v2.resolutions (criteria, status, commands, risk) is display data only: tampering it changes nothing."""
    prev, res = _prev_with_fix()
    tamper(res)
    assert _verify(prev, stat(mode="0664")).items[0].outcome == VerifyOutcome.PARTIALLY_RESOLVED
    assert _verify(prev, stat(mode="0660")).items[0].outcome == VerifyOutcome.RESOLVED


@pytest.mark.parametrize("tamper,expected", [
    (lambda f: f.update(procedure_id="proc.unknown"), VerifyOutcome.UNABLE_TO_VERIFY),
    (lambda f: f.update(procedure_digest="0" * 64), VerifyOutcome.UNABLE_TO_VERIFY),
    (lambda f: f.update(bindings="x"), VerifyOutcome.UNABLE_TO_VERIFY),
    (lambda f: f["bindings"]["targets_mode"][0].update(expected="0777; reboot"), VerifyOutcome.UNABLE_TO_VERIFY),
    (lambda f: f["bindings"]["targets_mode"].clear(), VerifyOutcome.UNABLE_TO_VERIFY),
    (lambda f: f["bindings"]["targets_mode"][0].update(expected="0664"), VerifyOutcome.CHANGED),  # valid, but not what was shown
    (lambda f: f.update(criteria_digest="0" * 64), VerifyOutcome.CHANGED),
    (lambda f: f.clear(), VerifyOutcome.UNABLE_TO_VERIFY),  # record unusable, but the fix was listed as shown
])
def test_tampered_or_corrupt_baseline_never_gives_resolved(tamper, expected):
    prev, _ = _prev_with_fix()
    tamper(_fix(prev))
    assert _verify(prev, stat(mode="0664")).items[0].outcome == expected


def test_fix_target_moved_since_the_fix_was_shown_is_changed_not_resolved():
    prev, _ = _prev_with_fix()
    # after the "fix" the reported path now resolves to another (already correct) file
    moved = stat(mode="0660", real="/etc/pki/pki-tomcat/other/CS.cfg")
    after, _ = report_for([], {**ROOT_OK})
    out = compare(prev, after, runner=FakeRunner({f"file.stat|path={CS}": moved,
                                                  "file.stat|path=/etc/pki/pki-tomcat/other/CS.cfg": moved}))
    assert out.items[0].outcome == VerifyOutcome.CHANGED


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


@pytest.mark.parametrize("tamper", [
    lambda p: p["v2"].pop("verify_baseline"),
    lambda p: p.pop("v2"),
    lambda p: p["v2"]["verify_baseline"].update(fixes="x"),
    lambda p: p["v2"]["verify_baseline"].update(schema=9),
])
def test_schema2_report_without_a_valid_baseline_is_damaged(tamper):
    prev, _ = _prev_with_fix()
    tamper(prev)
    assert _verify(prev, stat(mode="0664")).items[0].outcome == VerifyOutcome.UNABLE_TO_VERIFY
    assert _verify(prev, stat(mode="0660")).items[0].outcome == VerifyOutcome.UNABLE_TO_VERIFY


def test_other_host_or_mode_or_unknown_diagnosis_is_unable_to_verify():
    prev, _ = _prev_with_fix()
    other = copy.deepcopy(prev)
    other["hostname"] = "ipa99.elsewhere.test"
    assert _verify(other, stat(mode="0660")).items[0].outcome == VerifyOutcome.UNABLE_TO_VERIFY
    replayed = copy.deepcopy(prev)
    replayed["replay_source"] = "tests/fixtures/x"
    assert _verify(replayed, stat(mode="0660")).items[0].outcome == VerifyOutcome.UNABLE_TO_VERIFY
    bogus = copy.deepcopy(prev)
    bogus["diagnoses"][0]["diagnosis_id"] = "directory-server.renamed-in-a-later-version"
    assert _verify(bogus, stat(mode="0660")).items[0].outcome == VerifyOutcome.UNABLE_TO_VERIFY


def test_v013_report_without_v2_is_compared_as_before():
    prev, _ = _prev_with_fix()
    prev.pop("v2")
    prev.pop("report_schema_version")
    assert _verify(prev, stat(mode="0664")).items[0].outcome == VerifyOutcome.RESOLVED  # v0.1.3 semantics
