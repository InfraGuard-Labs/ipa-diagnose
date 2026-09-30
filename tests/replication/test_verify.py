"""`ipa-diagnose replication --verify`: the false-RESOLVED campaign and bounded PENDING."""

from __future__ import annotations

import datetime
import json

import pytest

from ipa_diagnose.replication import verify as V
from tests.replication import helpers as H
from tests.replication import scenarios as S
from tests.replication.scenarios import IPA01, IPA02, IPA03, Lab

NOW = datetime.datetime.now(datetime.timezone.utc)
LATER = NOW + datetime.timedelta(minutes=5)
KDC = f"LOCAL_KDC_NOT_RUNNING@server:{IPA01}"
SYM_D = f"REPLICATION_FAILING@domain:{IPA01}>{IPA02}"


@pytest.fixture(autouse=True)
def _fresh_clock():
    """NOW/LATER per test, not per import: a baseline is stamped with the real time when a test runs, so on a slow
    full-suite run (this module reached more than 5 minutes after collection) an import-time LATER fell before the
    baseline and a RESOLVED case read as PENDING (freeze campaign: failed locally at 8m53s)."""

    global NOW, LATER
    NOW = datetime.datetime.now(datetime.timezone.utc)
    LATER = NOW + datetime.timedelta(minutes=5)
    yield


def baseline(lab, **kw):
    r = H.run(lab, **kw)
    doc = V.to_state(r)
    return r, _load(doc)


def _load(doc, tmp=None):
    import pathlib
    import tempfile

    p = pathlib.Path(tempfile.mkdtemp()) / "replication_last.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return V.load(p)


def verify(prev, lab, now=None, **kw):
    fresh = H.run(lab, **kw)
    cmp = V.compare(prev, fresh, None, now=now or LATER)
    return cmp, {i.key: i.outcome for i in cmp["items"]}, V.exit_code(cmp, 0)


def fixed_later():
    return Lab(now=LATER)


# ---------------------------------------------------------------- RESOLVED only when the incident is gone


def test_resolved_needs_a_fresh_successful_session_after_the_baseline():
    _r, prev = baseline(Lab().local_kdc_stopped())
    cmp, out, code = verify(prev, fixed_later())
    assert out[SYM_D] == "RESOLVED" and out[KDC] == "RESOLVED" and code == 0


def test_no_fresh_session_yet_is_pending_with_a_recheck_time_and_never_exit_zero():
    _r, prev = baseline(Lab().local_kdc_stopped())
    cmp, out, code = verify(prev, Lab(now=NOW - datetime.timedelta(minutes=2)))  # green, but the session is OLD
    assert out[SYM_D] == "PENDING" and out[KDC] == "PENDING"
    assert code == 3
    it = next(i for i in cmp["items"] if i.key == SYM_D)
    assert it.recheck_after and it.pending_since and SYM_D in cmp["pending"]


def test_pending_is_time_bounded():
    _r, prev = baseline(Lab().local_kdc_stopped())
    since = LATER - datetime.timedelta(seconds=V.CONVERGENCE_WINDOW + 1)
    stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    prev["pending"] = {SYM_D: stamp}
    cmp, out, code = verify(prev, Lab(now=NOW - datetime.timedelta(minutes=2)))
    assert out[SYM_D] == "UNABLE_TO_VERIFY" and "convergence window" in next(
        i.detail for i in cmp["items"] if i.key == SYM_D)
    assert out[f"REPLICATION_FAILING@ca:{IPA01}>{IPA02}"] == "PENDING" and code == 3  # its own window is still open
    prev["pending"] = {k: stamp for k in out}
    _c, out, code = verify(prev, Lab(now=NOW - datetime.timedelta(minutes=2)))
    assert "PENDING" not in out.values() and code == 4


def test_update_in_progress_is_not_resolved():
    _r, prev = baseline(Lab().local_kdc_stopped())
    _c, out, code = verify(prev, fixed_later().set_status(IPA02, S.OK_TEXT, update_in_progress=True))
    assert out[SYM_D] == "PENDING" and code == 3


@pytest.mark.parametrize("text", [S.NO_SESSIONS_TEXT, S.BUSY_TEXT])
def test_a_transient_state_after_the_fix_is_never_green(text):
    _r, prev = baseline(Lab().local_kdc_stopped())
    _c, out, code = verify(prev, fixed_later().set_status(IPA02, text, suffix="domain"))
    assert out[SYM_D] == "PENDING" and code == 3


def test_a_recorded_failure_that_is_not_reproduced_now_is_pending_not_still_present():
    """Freeze live run 36729641548 (R02d): the peer's Directory Server was started again and answered from ipa01, but
    389-DS on ipa01 had not retried yet, so the agreement still recorded 'Can't contact LDAP server'. The fresh run
    itself classifies that as not reproduced (transient); verify must answer PENDING (exit 3), not STILL_PRESENT."""

    peer_down = Lab().peer_ds_stopped(IPA02)
    _r, prev = baseline(peer_down)
    peer = f"PEER_DS_NOT_ACCEPTING@server:{IPA02}"
    stale = fixed_later().set_status(IPA02, S.TRANSPORT_TEXT, suffix="domain")  # peer answers; old status kept
    cmp, out, code = verify(prev, stale)
    assert out[SYM_D] == "PENDING" and code == 3, out
    assert out.get(peer) in (None, "PENDING"), out
    # a failure the fresh checks DO reproduce stays STILL_PRESENT
    _c, out2, code2 = verify(prev, Lab(now=LATER).peer_ds_stopped(IPA02))
    assert out2[SYM_D] == "STILL_PRESENT" and code2 == 1
    # and PENDING is bounded as before: after the window it becomes STILL_PRESENT, never RESOLVED
    since = LATER - datetime.timedelta(seconds=V.CONVERGENCE_WINDOW + 1)
    prev["pending"] = {SYM_D: since.strftime("%Y-%m-%dT%H:%M:%SZ")}
    _c, out3, _code3 = verify(prev, stale)
    assert out3[SYM_D] == "STILL_PRESENT"


def test_a_peer_cause_that_only_changed_shape_is_changed_not_resolved():
    """Freeze review probe: the peer's port went from refused to timing out. PEER_DS_NOT_ACCEPTING@server:peer is gone
    but PEER_DS_NOT_ANSWERING/PEER_UNREACHABLE for the same peer appears: CHANGED, never RESOLVED."""

    peer = f"PEER_DS_NOT_ACCEPTING@server:{IPA02}"
    _r, prev = baseline(Lab().peer_ds_stopped(IPA02, recorded=False))
    later = Lab(now=LATER).peer_ds_stopped(IPA02, recorded=False)
    later.data[S.key("net.tcp", {"host": IPA02, "port": "389"})] = S.ok(
        {"state": "timeout", "open": False, "seconds": 5.0}, f"TCP {IPA02}:389: timeout")
    _c, out, code = verify(prev, later)
    assert out[peer] == "CHANGED", out
    assert code != 0
    # and from unreachable to refused
    unreach = next(k for k in baseline(Lab().peer_unreachable(IPA02, recorded=False))[0].diagnoses
                   if k.code == "PEER_UNREACHABLE").key
    _r2, prev2 = baseline(Lab().peer_unreachable(IPA02, recorded=False))
    _c, out2, _code2 = verify(prev2, Lab(now=LATER).peer_ds_stopped(IPA02, recorded=False))
    assert out2[unreach] == "CHANGED", out2


def test_still_failing_is_still_present():
    _r, prev = baseline(Lab().local_kdc_stopped())
    _c, out, code = verify(prev, Lab(now=LATER).local_kdc_stopped())
    assert out[KDC] == "STILL_PRESENT" and out[SYM_D] == "STILL_PRESENT" and code == 1


def test_a_different_failure_on_the_same_agreement_is_changed_not_resolved():
    _r, prev = baseline(Lab().local_kdc_stopped())
    _c, out, code = verify(prev, fixed_later().peer_ds_stopped(IPA02))
    assert out[SYM_D] in ("CHANGED", "STILL_PRESENT") and code == 1  # new PEER_DS cause is a new condition


def test_an_unrelated_new_failure_blocks_exit_zero():
    _r, prev = baseline(Lab(me=IPA02).peer_ds_stopped(IPA01))
    cmp, out, code = verify(prev, Lab(me=IPA02, now=LATER).peer_unreachable(IPA03))
    assert out[f"REPLICATION_FAILING@domain:{IPA02}>{IPA01}"] == "RESOLVED"
    assert cmp["new_conditions"] and code == 1


# ---------------------------------------------------------------- UNABLE_TO_VERIFY, never RESOLVED


def test_collector_failure_is_unable_to_verify():
    _r, prev = baseline(Lab().local_kdc_stopped())
    _c, out, code = verify(prev, Lab(now=LATER).unit("dirsrv"))  # agreements cannot be read now
    assert out[SYM_D] == "UNABLE_TO_VERIFY" and out[KDC] in ("UNABLE_TO_VERIFY", "RESOLVED", "PENDING")
    assert code != 0


def test_a_baseline_from_another_host_or_scope_is_unable_to_verify():
    _r, prev = baseline(Lab().local_kdc_stopped())
    _c, out, _ = verify(prev, Lab(me=IPA02, now=LATER))
    assert set(out.values()) == {"UNABLE_TO_VERIFY"}
    _r, prev = baseline(Lab().local_kdc_stopped(), peer=IPA02)
    _c, out, _ = verify(prev, fixed_later())
    assert set(out.values()) == {"UNABLE_TO_VERIFY"}


def test_the_agreement_disappearing_is_not_resolved():
    _r, prev = baseline(Lab().local_kdc_stopped())
    lab = fixed_later()
    lab.data[S.key("repl.agreements", {})]["fields"]["agreements"] = [
        a for a in lab.data[S.key("repl.agreements", {})]["fields"]["agreements"] if a["suffix_kind"] != "domain"]
    _c, out, code = verify(prev, lab)
    assert out[SYM_D] == "UNABLE_TO_VERIFY" and code != 0


def test_a_failing_reverse_direction_that_cannot_be_observed_now_is_unable_to_verify():
    key = f"REVERSE_REPLICATION_FAILING@domain:{IPA02}>{IPA01}"
    _r, prev = baseline(Lab().set_reverse(IPA02, S.LOCAL_ERROR_TEXT, suffix="domain"))
    assert key in {d["key"] for d in prev["diagnoses"]}
    cmp, out, code = verify(prev, fixed_later().set_reverse(IPA02, status="NOT_RUN"))
    assert out[key] == "UNABLE_TO_VERIFY" and code != 0
    assert f"domain:{IPA02}>{IPA01}" in cmp["reverse_not_verified"]


def test_reverse_direction_resolved_only_with_a_fresh_session_read_from_the_peer():
    key = f"REVERSE_REPLICATION_FAILING@domain:{IPA02}>{IPA01}"
    _r, prev = baseline(Lab().set_reverse(IPA02, S.LOCAL_ERROR_TEXT, suffix="domain"))
    _c, out, _ = verify(prev, fixed_later())
    assert out[key] == "RESOLVED"
    _c, out, _ = verify(prev, Lab(now=NOW - datetime.timedelta(minutes=1)))
    assert out[key] == "PENDING"


def test_cause_is_only_resolved_when_everything_it_explained_is():
    _r, prev = baseline(Lab().local_kdc_stopped())
    lab = fixed_later().set_status(IPA02, S.OK_TEXT, suffix="ca", last_update_end=S.iso(NOW - datetime.timedelta(
        minutes=10)))
    _c, out, code = verify(prev, lab)
    assert out[SYM_D] == "RESOLVED" and out[f"REPLICATION_FAILING@ca:{IPA01}>{IPA02}"] == "PENDING"
    assert out[KDC] == "PENDING" and code == 3


def test_clock_skew_is_not_resolved_without_measuring_the_clock_again():
    key = f"PAIR_CLOCK_SKEW@pair:{IPA01}>{IPA02}"
    lab = Lab()
    lab.data[S.key("repl.peer_rootdse", {"host": IPA02, "port": "389", "transport": "LDAP"})]["fields"][
        "offset_seconds"] = 900.0
    _r, prev = baseline(lab)
    assert key in {d["key"] for d in prev["diagnoses"]}
    _c, out, _ = verify(prev, fixed_later().rootdse_without_clock(IPA02))
    assert out[key] == "UNABLE_TO_VERIFY"
    _c, out, _ = verify(prev, fixed_later())
    assert out[key] == "RESOLVED"


def test_exact_ruv_equality_is_not_required():
    _r, prev = baseline(Lab().local_kdc_stopped())
    lab = fixed_later()
    lab.data[S.key("repl.agreements", {})]["fields"]["ruv"]["domain"][1]["max_csn"] = "changed-since"
    cmp, out, code = verify(prev, lab)
    assert code == 0 and cmp["ruv_equality_required"] is False


# ---------------------------------------------------------------- the saved state is untrusted


def test_tampered_or_foreign_state_is_refused(tmp_path):
    good = V.to_state(H.run(Lab().local_kdc_stopped()))
    p = tmp_path / "replication_last.json"
    for bad in ({**good, "state_version": 99}, {**good, "kind": "ipa-diagnose.client.state"},
                {**good, "generated_at": "yesterday"},
                {**good, "diagnoses": [{"code": "rm -rf /", "subject": "server:x"}]},
                {**good, "diagnoses": [{"code": "X", "subject": "$(reboot)"}]}):
        p.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(V.UnreadableState):
            V.load(p)
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(V.UnreadableState):
        V.load(p)


def test_state_behind_a_symlink_is_refused(tmp_path):
    import os

    if not hasattr(os, "symlink") or os.name == "nt":
        pytest.skip("symlinks")
    target = tmp_path / "real.json"
    target.write_text(json.dumps(V.to_state(H.run(Lab()))), encoding="utf-8")
    link = tmp_path / "replication_last.json"
    link.symlink_to(target)
    with pytest.raises(V.UnreadableState):
        V.load(link)


def test_the_state_keeps_subjects_and_no_secret_material():
    r = H.run(Lab().local_kdc_stopped(), live=True)
    doc = V.to_state(r)
    text = json.dumps(doc).lower()
    assert "nsds5replicacredentials" not in text and "password" not in text
    assert {d["subject"] for d in doc["diagnoses"]} >= {f"server:{IPA01}", f"domain:{IPA01}>{IPA02}"}
    assert KDC in doc["fixes"] and doc["fixes"][KDC]["diagnosis_id"] == f"replication.{KDC}"
