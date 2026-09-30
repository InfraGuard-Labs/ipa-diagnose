"""Resolution Safety gate and No-Google gate: red-team cases per procedure."""

from __future__ import annotations

import dataclasses
import datetime
import inspect
import re

import pytest

from ipa_diagnose.replication import diagnose as D
from ipa_diagnose.replication import safety as G
from ipa_diagnose.resolution.engine import Resolution, Step
from ipa_diagnose.resolution.knowledge import load_catalogue
from tests.replication import helpers as H
from tests.replication import scenarios as S
from tests.replication.scenarios import IPA01, IPA02, Lab

KDC_KEY = f"LOCAL_KDC_NOT_RUNNING@server:{IPA01}"
DS_KEY = f"LOCAL_DS_NOT_RUNNING@server:{IPA01}"


def kdc_live(lab=None, **kw):
    return H.run(lab or Lab().local_kdc_stopped(), live=True, **kw)


# ---------------------------------------------------------------- the validated local procedures


LIVE_REC = ({"tier": "LIVE", "freeipa": "4.13.3", "os": "fedora-43", "date": "2026-09-30",
             "evidence": "lab run (test record)"},)


@pytest.fixture
def replication_live(monkeypatch):
    meta = dict(G.SLICE5_PROCEDURES["proc.service.start-stopped-service"], replication_live=LIVE_REC)
    monkeypatch.setitem(G.SLICE5_PROCEDURES, "proc.service.start-stopped-service", meta)


def test_no_google_needs_a_live_record_in_a_replication_incident():
    """The command's live record from the single-server service scenarios does not count for replication."""

    r = kdc_live()
    ng = r.gates[KDC_KEY]["no_google"]
    assert r.resolutions[KDC_KEY].status == "OFFERED"
    assert not ng["claimed"] and ng["missing"] == ["live_verified_here"]


def test_local_kdc_fix_is_exact_complete_and_no_google(replication_live):
    r = kdc_live()
    res = r.resolutions[KDC_KEY]
    assert res.status == "OFFERED" and res.procedure_id == "proc.service.start-stopped-service"
    assert [s.argv for s in res.steps] == [["systemctl", "start", "krb5kdc.service"]]
    assert [x["argv"] for x in res.rollback] == [["systemctl", "stop", "krb5kdc.service"]]
    assert all(p.state == "met" for p in res.prerequisites)
    ng = r.gates[KDC_KEY]["no_google"]
    assert ng["claimed"] and all(ng["checklist"].values())
    assert "krb5kdc.service" in ng["on_failure"] and "ipactl start" in ng["on_failure"]
    assert any("reports success for a session that ended after this diagnosis" in c for c in ng["incident_criteria"])
    assert res.baseline["criteria_digest"]  # verify can rebuild it


def test_local_ds_fix_targets_this_servers_instance_only():
    r = H.run(Lab().unit("dirsrv"), live=True)
    res = r.resolutions[DS_KEY]
    assert [s.argv for s in res.steps] == [["systemctl", "start", "dirsrv@LAB-TEST.service"]]


def test_only_one_fix_when_the_kdc_is_down_because_the_ds_is_down():
    r = H.run(Lab().unit("dirsrv").unit("krb5kdc"), live=True)
    assert list(H.offered(r)) == [DS_KEY]


def test_no_google_is_not_claimed_on_a_version_without_a_live_record(replication_live):
    r = kdc_live(Lab(freeipa="4.13.4").local_kdc_stopped())
    res = r.resolutions[KDC_KEY]
    assert res.status == "OFFERED"
    ng = r.gates[KDC_KEY]["no_google"]
    assert not ng["claimed"] and ng["missing"] == ["live_verified_here"]


@pytest.mark.parametrize("version,why", [("5.1.0", "5.0 or later"), ("4.8.10", "4.9 or later")])
def test_unsupported_versions_withhold(version, why):
    r = kdc_live(Lab(freeipa=version).local_kdc_stopped())
    res = r.resolutions[KDC_KEY]
    assert res.status == "WITHHELD" and any(why in x for x in res.reasons)


def test_unknown_version_withholds():
    lab = Lab().local_kdc_stopped()
    lab.data[S.key("repl.server", {})]["fields"]["freeipa"] = None
    assert kdc_live(lab).resolutions[KDC_KEY].status == "WITHHELD"


def test_not_root_withholds_by_prerequisite():
    lab = Lab().local_kdc_stopped()
    lab.data[S.key("host.privilege", {})]["fields"]["is_root"] = False
    res = kdc_live(lab).resolutions[KDC_KEY]
    assert res.status == "WITHHELD" and any(p.state == "unmet" for p in res.prerequisites)


def test_masked_unit_withholds():
    lab = Lab().local_kdc_stopped()
    lab.data[S.key("systemd.unit", {"service": "krb5kdc"})]["fields"]["load_state"] = "masked"
    r = kdc_live(lab)
    assert not H.offered(r)


# ---------------------------------------------------------------- red team: host, subject, change, age, replay


def test_target_changed_after_the_diagnosis_withholds_with_a_fresh_check():
    lab = Lab().local_kdc_stopped()
    data = lab.build()
    k = S.key("systemd.unit", {"service": "krb5kdc"})
    fixed = {"status": "OK", "fields": dict(data[k]["fields"], active_state="active", sub_state="running"),
             "display": "active"}
    runner = H.LiveLikeRunner(data, fresh_overrides={k: fixed})
    r = H.run(runner=runner)
    res = r.resolutions[KDC_KEY]
    assert res.status == "WITHHELD" and any("running now" in x for x in res.reasons)
    assert ("systemd.unit", {"service": "krb5kdc"}) in runner.fresh_calls


def test_replay_evidence_never_offers_but_keeps_parity_with_live():
    live = kdc_live()
    replay = H.run(Lab().local_kdc_stopped())
    res = replay.resolutions[KDC_KEY]
    assert res.status == "WITHHELD" and any("REPLAY" in x for x in res.reasons)
    prev = replay.gates[KDC_KEY]["replay_preview"]
    assert prev["procedure_id"] == live.resolutions[KDC_KEY].procedure_id
    assert prev["steps"] == [s.argv for s in live.resolutions[KDC_KEY].steps]
    assert replay.gates[KDC_KEY]["no_google"] is None


def _ctx(r, **kw):
    base = dict(me=IPA01, replay=False, trace=r.trace, diagnoses=r.diagnoses,
                chains={c.chain_id: c for c in r.chains}, topology=r.topology, runner=None)
    base.update(kw)
    return G.GateContext(**base)


def test_stale_evidence_withholds():
    r = kdc_live()
    d = next(x for x in r.diagnoses if x.key == KDC_KEY)
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=G.MAX_EVIDENCE_AGE + 60)
    reasons = G.resolution_gate(d, _ctx(r, now=later), "proc.service.start-stopped-service")
    assert any("older than" in x for x in reasons)


def test_wrong_host_and_wrong_subject_withhold():
    r = kdc_live()
    d = next(x for x in r.diagnoses if x.key == KDC_KEY)
    assert "not on this server" in G.resolution_gate(d, _ctx(r, me=IPA02), "proc.service.start-stopped-service")[0]
    other = dataclasses.replace(d, subject=f"pair:{IPA01}>{IPA02}")
    assert "not on this server" in G.resolution_gate(other, _ctx(r), "proc.service.start-stopped-service")[0]
    peer = dataclasses.replace(d, subject=f"server:{IPA02}", scope="peer")
    assert "not on this server" in G.resolution_gate(peer, _ctx(r), "proc.service.start-stopped-service")[0]


@pytest.mark.parametrize("change,why", [
    ({"role": "RELATED"}, "RELATED"), ({"role": "WARNING"}, "WARNING"), ({"confidence": "MEDIUM"}, "medium"),
    ({"kind": "UNDIAGNOSED"}, "UNDIAGNOSED"), ({"kind": "TRANSIENT"}, "TRANSIENT"), ({"chain_ids": []}, "chain"),
    ({"chain_ids": ["nope"]}, "deepest proven link")])
def test_role_confidence_kind_and_chain_are_machine_checked(change, why):
    r = kdc_live()
    d = dataclasses.replace(next(x for x in r.diagnoses if x.key == KDC_KEY), **change)
    reasons = G.resolution_gate(d, _ctx(r), "proc.service.start-stopped-service")
    assert any(why in x for x in reasons), reasons


def test_a_procedure_outside_the_slice5_allowlist_is_withheld():
    r = kdc_live()
    d = next(x for x in r.diagnoses if x.key == KDC_KEY)
    assert any("may print" in x for x in G.resolution_gate(d, _ctx(r), "proc.files.restore-expected-permissions"))


# ---------------------------------------------------------------- topology predicates (sole roles, articulation)


TOPO = {"complete": True, "roles": {IPA01: ["CA", "DNS"], IPA02: ["CA"]}, "renewal_master": IPA01,
        "dnssec_key_master": None,
        "suffixes": {"domain": {"articulation_points": [IPA02]}, "ca": {"articulation_points": []}}}


@pytest.mark.parametrize("pred,me,expect", [
    ("not_sole_ca", IPA01, True), ("not_sole_dns", IPA01, False), ("not_sole_dns", IPA02, True),
    ("not_sole_kra", IPA01, None), ("not_renewal_master", IPA01, False), ("not_renewal_master", IPA02, True),
    ("not_dnssec_key_master", IPA01, None), ("not_articulation_point", IPA02, False),
    ("not_articulation_point", IPA01, True)])
def test_topology_predicates(pred, me, expect):
    assert G.topology_predicate(pred, me, TOPO) is expect


def test_role_predicates_need_exactly_one_established_holder():
    two = dict(TOPO, renewal_master=None)  # the summary keeps it only when exactly one server carries the flag
    assert G.topology_predicate("not_renewal_master", IPA01, two) is None
    assert G.topology_predicate("not_sole_ca", IPA01, dict(TOPO, roles={})) is None


def test_a_link_of_another_capability_on_the_same_subject_is_not_this_diagnosis():
    r = kdc_live()
    d = next(x for x in r.diagnoses if x.key == KDC_KEY)
    wrong = dataclasses.replace(d, capability="LOCAL_DS")
    assert any("deepest proven link" in x for x in G.resolution_gate(wrong, _ctx(r), "proc.service.start-stopped-service"))


def test_a_diagnosis_without_evidence_fails_the_age_gate():
    r = kdc_live()
    d = dataclasses.replace(next(x for x in r.diagnoses if x.key == KDC_KEY), evidence=[])
    assert any("names no evidence" in x for x in G.resolution_gate(d, _ctx(r), "proc.service.start-stopped-service"))


def test_stop_is_allowed_only_as_a_rollback():
    assert G.check_offered(_res([["systemctl", "stop", "krb5kdc.service"]]))


def test_the_replay_preview_is_labelled_never_to_be_run():
    prev = H.run(Lab().local_kdc_stopped()).gates[KDC_KEY]["replay_preview"]
    assert "not a command to run" in prev["do_not_run"]


def test_unknown_storage_under_a_stopped_ds_withholds_the_start():
    lab = Lab().unit("dirsrv")
    lab.data[S.key("repl.storage", {})] = {"status": "FAILED", "fields": {}, "display": "statvfs failed"}
    r = H.run(lab, live=True)
    ds = next(d for d in r.diagnoses if d.code == "LOCAL_DS_NOT_RUNNING")
    assert ds.resolution_key is None and not H.offered(r)


def test_topology_predicates_are_never_true_from_a_partial_read():
    for pred in G.TOPOLOGY_PREDICATES:
        assert G.topology_predicate(pred, IPA01, dict(TOPO, complete=False)) is None


def test_a_topology_sensitive_procedure_is_withheld_when_a_predicate_fails(monkeypatch):
    meta = dict(G.SLICE5_PROCEDURES["proc.service.start-stopped-service"], topology=("not_sole_dns",))
    monkeypatch.setitem(G.SLICE5_PROCEDURES, "proc.service.start-stopped-service", meta)
    r = kdc_live()
    res = r.resolutions[KDC_KEY]
    assert res.status == "WITHHELD" and any("not sole dns" in x for x in res.reasons)


# ---------------------------------------------------------------- what may never be printed


def _res(argvs, risk="MEDIUM", rollback=True, confirm=False):
    r = Resolution(diagnosis_id="x", status="OFFERED", risk=risk)
    r.steps = [Step("s", "t", a, risk, ["service-start"], "e", "local") for a in argvs]
    r.rollback = [{"text": "r", "argv": ["systemctl", "stop", "x.service"]}] if rollback else []
    r.confirm_first = [{"argv": ["stat", "x"]}] if confirm else []
    return r


@pytest.mark.parametrize("argv", [
    ["ipa-replica-manage", "re-initialize", "--from", "ipa02.lab.test"], ["ipa-replica-manage", "force-sync"],
    ["ipa-replica-manage", "clean-ruv", "9"], ["ipa", "server-del", "ipa02.lab.test"],
    ["ipa", "topologysegment-del", "domain", "x"], ["ipa-getkeytab", "-s", "x", "-p", "ldap/x", "-k", "/etc/x"],
    ["ldapmodify", "-Y", "EXTERNAL"], ["chronyc", "makestep"], ["date", "-s", "yesterday"],
    ["systemctl", "restart", "dirsrv@X.service"], ["systemctl", "disable", "x.service"], ["rm", "-rf", "/var/lib/sss"],
    ["ipa", "config-mod", "--ca-renewal-master-server", "x"], ["ipa-server-install", "--uninstall"],
])
def test_forbidden_operations_are_refused(argv):
    assert G.check_offered(_res([argv]))


def test_the_allowed_shape_passes_and_high_risk_needs_rollback_and_backup():
    assert not G.check_offered(_res([["systemctl", "start", "krb5kdc.service"]]))
    assert G.check_offered(_res([["systemctl", "start", "krb5kdc.service"]], risk="HIGH", rollback=False))
    assert G.check_offered(_res([["systemctl", "start", "krb5kdc.service"]], risk="HIGH"))  # no backup step
    bad = _res([["systemctl", "start", "krb5kdc.service"]])
    bad.steps[0].run_on = "ipa02.lab.test"
    assert G.check_offered(bad)


def test_every_procedure_a_replication_diagnosis_can_reach_is_allowlisted_or_no_procedure():
    src = inspect.getsource(D)
    keys = set(re.findall(r'resolution_key=(?:None if [^"]+ else )?"([a-z.-]+)"', src))
    assert keys >= {"healthcheck.service-not-running", "replication.ds-keytab-problem", "replication.pair-clock-skew"}
    cat, err = load_catalogue()
    assert not err
    for k in keys:
        procs = [p for p in cat if p["resolves"]["diagnosis"] == k]
        assert procs, k
        for p in procs:
            assert p["kind"] == "no_procedure" or p["id"] in G.SLICE5_PROCEDURES, (k, p["id"])


def test_peer_side_causes_never_get_a_command():
    for lab in (Lab().peer_ds_stopped(IPA02), Lab().peer_unreachable(IPA02), Lab().clock_skew(IPA02),
                Lab().set_reverse(IPA02, S.LOCAL_ERROR_TEXT)):
        r = H.run(lab, live=True)
        assert not H.offered(r)
        for d in r.diagnoses:
            if d.scope != "local":
                res = r.resolutions.get(d.key)
                assert res is None or res.status != "OFFERED"


def test_withheld_results_never_carry_steps_and_the_json_has_no_commands_for_them():
    import json

    from ipa_diagnose.replication.output import to_dict

    r = H.run(Lab().local_kdc_stopped())  # replay: withheld
    doc = to_dict(r)
    assert doc["resolutions"][KDC_KEY]["status"] == "WITHHELD"
    assert doc["resolutions"][KDC_KEY]["steps"] == []
    assert "systemctl start" not in json.dumps(doc["resolutions"][KDC_KEY]["steps"])
