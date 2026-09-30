"""Replication diagnosis on synthetic scenarios: direction, suffix, cause chains, roles, handoffs, honesty."""

from __future__ import annotations

import re

import pytest

from ipa_diagnose.replication.causal import check_chain
from tests.replication import helpers as H
from tests.replication import scenarios as S
from tests.replication.scenarios import IPA01, IPA02, IPA03, Lab


def codes(r):
    return {d.code for d in r.diagnoses}


def keys(r):
    return {d.key: d.role for d in r.diagnoses}


# ---------------------------------------------------------------- healthy, scope, not a server


def test_healthy_line_topology_is_healthy_in_both_directions_and_suffixes():
    r = H.run(Lab())
    assert r.status == "HEALTHY", [g for g in r.completeness["not_verified"]]
    assert not r.diagnoses and not r.chains and not r.handoffs
    subjects = {x["subject"]: x for x in r.relationships}
    assert set(subjects) == {f"domain:{IPA01}>{IPA02}", f"domain:{IPA02}>{IPA01}", f"ca:{IPA01}>{IPA02}",
                             f"ca:{IPA02}>{IPA01}"}
    assert subjects[f"ca:{IPA02}>{IPA01}"]["direction"] == "inbound"
    assert all(x["observed_from"] == IPA01 for x in r.relationships)
    # a healthy agreement is not probed further (no GSSAPI test bind)
    assert r.trace.get("gssapi", subject=f"domain:{IPA02}").skip_reason.startswith("not needed")


def test_the_middle_server_sees_both_neighbours_and_no_ca_agreement_to_a_ca_less_replica():
    r = H.run(Lab(me=IPA02))
    outbound = sorted(x["subject"] for x in r.relationships if x["direction"] == "outbound")
    assert outbound == [f"ca:{IPA02}>{IPA01}", f"domain:{IPA02}>{IPA01}", f"domain:{IPA02}>{IPA03}"]
    assert r.status == "HEALTHY"
    assert r.topology["suffixes"]["domain"]["articulation_points"] == [IPA02]


def test_not_an_ipa_server_stops_honestly_without_guessing():
    lab = Lab()
    lab.data[S.key("repl.server", {})]["fields"].update(is_ipa_server=False)
    r = H.run(lab)
    assert r.status == "NOT_AN_IPA_SERVER"
    assert not r.diagnoses and not r.relationships
    assert all(x.outcome.value == "SKIPPED" for x in r.trace.records[1:])
    assert "not an IPA server" in r.trace.stop_reason


def test_peer_scope_investigates_only_that_peer_and_says_so():
    r = H.run(Lab(me=IPA02).peer_ds_stopped(IPA03), peer=IPA01)
    assert r.status == "HEALTHY"
    assert "towards ipa01.lab.test" in r.completeness["scope"]
    assert {x["consumer"] for x in r.relationships if x["direction"] == "outbound"} == {IPA01}


def test_peer_scope_to_a_server_without_agreement_is_not_reported_healthy():
    r = H.run(Lab(), peer=IPA03)
    assert r.status != "HEALTHY"
    assert any("no outbound agreement towards ipa03" in n for n in r.notes)


# ---------------------------------------------------------------- transport: peer DS, unreachable, DNS


def test_peer_ds_refused_with_host_up_is_a_peer_side_cause_with_a_handoff():
    r = H.run(Lab().peer_ds_stopped(IPA02))
    p = H.primary(r)
    assert (p.code, p.subject, p.scope) == ("PEER_DS_NOT_ACCEPTING", f"server:{IPA02}", "peer")
    assert "stopped" not in p.title.lower()  # never claimed from here
    related = {d.key for d in r.diagnoses if d.role == "RELATED"}
    assert related == {f"REPLICATION_FAILING@domain:{IPA01}>{IPA02}", f"REPLICATION_FAILING@ca:{IPA01}>{IPA02}"}
    assert r.handoffs[0]["host"] == IPA02 and r.handoffs[0]["command"] == f"sudo ipa-diagnose replication --peer {IPA01}"
    assert not H.offered(r)
    assert r.status == "PROBLEM_FOUND"
    # the reverse direction was not observable: it is never reported as healthy
    assert H.rel(r, f"domain:{IPA02}>{IPA01}")["state"] == "UNKNOWN"


@pytest.mark.parametrize("fault,code", [("peer_ds_stopped", "PEER_DS_NOT_ACCEPTING"),
                                        ("peer_unreachable", "PEER_UNREACHABLE")])
def test_a_peer_that_does_not_answer_now_is_found_even_while_the_status_is_still_green(fault, code):
    """Live finding (run 36654176983): the agreement status kept its last success after the peer went away."""

    r = H.run(getattr(Lab(), fault)(IPA02, recorded=False))
    p = H.primary(r)
    assert p.code == code and "has not recorded this yet" in p.detail
    # the sentence names the agreement it is about (freeze: CA and domain statuses can differ for one peer finding)
    assert re.search(r"The (domain|ca) agreement \S+ -> \S+ still shows its last session", p.detail)
    assert H.rel(r, f"domain:{IPA01}>{IPA02}")["state"] == "OK"  # the recorded state is shown as it is
    assert r.status == "PROBLEM_FOUND" and r.handoffs and not H.offered(r)
    assert all(c.links[0].discriminator.endswith("-now") for c in r.chains)


def test_a_reverse_49_explained_by_this_servers_own_keytab_is_not_a_second_root():
    """Live finding (run 36654176983, R06): the peer's agreement towards a replica whose Directory Server cannot
    read its keytab fails with LDAP 49; that is the replica's own keytab problem, not an independent peer cause."""

    lab = Lab(me=IPA03).keytab(owner="root", group="root", dirsrv_can_read=False).set_reverse(
        IPA02, S.INVALID_TEXT, suffix="domain")
    r = H.run(lab)
    roots = [d for d in r.diagnoses if d.role in ("PRIMARY", "INDEPENDENT")]
    assert [d.code for d in roots] == ["DS_KEYTAB_PROBLEM"]
    rev = next(d for d in r.diagnoses if d.code == "REVERSE_REPLICATION_FAILING")
    assert rev.role == "RELATED" and rev.related_to == roots[0].key


@pytest.mark.parametrize("text", [S.NO_KDC_TEXT, S.SKEW_TEXT, S.NOT_FOUND_TEXT, S.CREDS_TEXT])
def test_peer_side_kerberos_failures_are_not_blamed_on_this_servers_keytab(text):
    """Re-review blocker: these classes happen on the peer's own side before this server accepts anything."""

    r = H.run(Lab(me=IPA03).keytab(owner="root", group="root", dirsrv_can_read=False).set_reverse(
        IPA02, text, suffix="domain"))
    rev = next(d for d in r.diagnoses if d.code == "REVERSE_REPLICATION_FAILING")
    assert rev.related_to is None and rev.role == "INDEPENDENT" and rev.handoff["host"] == IPA02


def test_a_reverse_49_with_a_measured_skew_is_not_this_servers_keytab():
    lab = Lab(me=IPA03).keytab(owner="root", group="root", dirsrv_can_read=False).set_reverse(
        IPA02, S.INVALID_TEXT, suffix="domain")
    lab.data[S.key("repl.peer_rootdse", {"host": IPA02, "port": "389", "transport": "LDAP"})]["fields"][
        "offset_seconds"] = 900.0
    rev = next(d for d in H.run(lab).diagnoses if d.code == "REVERSE_REPLICATION_FAILING")
    assert rev.related_to is None


@pytest.mark.parametrize("fault", ["peer_ds_stopped", "peer_unreachable"])
def test_a_failing_non_transport_status_still_uses_what_the_peer_shows_now(fault):
    r = H.run(getattr(Lab(), fault)(IPA02, recorded=False).set_status(IPA02, S.LOCAL_ERROR_TEXT))
    assert any(d.code in ("PEER_DS_NOT_ACCEPTING", "PEER_UNREACHABLE") and d.role in ("PRIMARY", "INDEPENDENT")
               for d in r.diagnoses)
    assert r.handoffs


@pytest.mark.parametrize("fault", ["peer_ds_stopped", "peer_unreachable"])
def test_the_peer_finding_never_calls_a_failing_status_successful(fault):
    r = H.run(getattr(Lab(), fault)(IPA02, recorded=False).set_status(IPA02, S.LOCAL_ERROR_TEXT))
    root = next(d for d in r.diagnoses if d.code in ("PEER_DS_NOT_ACCEPTING", "PEER_UNREACHABLE"))
    assert "still shows its last session as successful" not in root.detail
    assert re.search(r"last recorded status of the (domain|ca) agreement \S+ -> \S+ is:", root.detail)
    assert root.role == "PRIMARY"  # a real root outranks the unlinked symptoms
    sym = next(d for d in r.diagnoses if d.code == "REPLICATION_FAILING")
    assert any("reported separately" in c.boundary for c in r.chains if c.chain_id in sym.chain_ids)


def test_a_generic_local_error_towards_this_server_keeps_the_peer_handoff():
    r = H.run(Lab(me=IPA03).keytab(owner="root", group="root", dirsrv_can_read=False).set_reverse(
        IPA02, S.LOCAL_ERROR_TEXT, suffix="domain"))
    rev = next(d for d in r.diagnoses if d.code == "REVERSE_REPLICATION_FAILING")
    assert rev.role == "RELATED" and rev.confidence == "MEDIUM" and rev.handoff["host"] == IPA02


def test_an_unsynchronized_local_ntp_in_a_clock_question_is_reported():
    lab = Lab().kerberos_failure(IPA02, kinit_ok=False, kinit_class="clock_skew", bind_attempted=False,
                                 bind_ok=False)
    lab.data[S.key("chrony.tracking", {})]["fields"].update(synchronized=False, leap_status="Not synchronised")
    r = H.run(lab)
    d = next(x for x in r.diagnoses if x.code == "LOCAL_NTP_NOT_SYNCHRONIZED")
    assert d.severity == "WARN" and "PAIR_CLOCK_SKEW" not in {x.code for x in r.diagnoses}


def test_a_kinit_clock_skew_is_not_the_pairs_clock():
    lab = Lab().kerberos_failure(IPA02, kinit_ok=False, kinit_class="clock_skew", bind_attempted=False,
                                 bind_ok=False)
    lab.data[S.key("repl.peer_rootdse", {"host": IPA02, "port": "389", "transport": "LDAP"})]["fields"][
        "offset_seconds"] = 400.0
    r = H.run(lab)
    assert not any(ln.discriminator == "kerberos-clock-skew" for c in r.chains for ln in c.links)
    assert r.trace.get("time.local").outcome.value != "SKIPPED"


def test_both_ports_refused_is_a_pair_level_finding():
    lab = Lab().peer_ds_stopped(IPA02)
    lab.data[S.key("net.tcp", {"host": IPA02, "port": "443"})]["fields"].update(state="refused", open=False)
    d = H.primary(H.run(lab))
    assert d.code == "PEER_DS_NOT_ANSWERING" and d.scope == "pair" and "filter on the path" in d.detail


def test_unreachable_peer_is_never_called_dead_and_says_from_where_and_when():
    r = H.run(Lab().peer_unreachable(IPA02))
    p = H.primary(r)
    assert p.code == "PEER_UNREACHABLE" and p.subject == f"pair:{IPA01}>{IPA02}"
    text = (p.title + p.detail + " ".join(c.boundary for c in r.chains)).lower()
    assert "unreachable from ipa01" in text and "dead" not in text and "decommission" not in text
    assert "gone for good" in text  # the boundary says it is NOT established
    chain = next(c for c in r.chains if c.subject == f"domain:{IPA01}>{IPA02}")
    assert [x.capability for x in chain.links] == ["REPLICATION", "PEER_DS", "NETWORK"]


def test_replay_never_invents_the_time_of_an_observation():
    r = H.run(Lab().peer_unreachable(IPA02))
    assert "unrecorded time (recorded evidence)" in H.primary(r).detail


def test_an_articulation_point_that_loses_both_neighbours_says_so():
    lab = Lab(me=IPA02).peer_unreachable(IPA01).peer_ds_stopped(IPA03)
    r = H.run(lab)
    assert any("articulation point of the domain topology" in n for n in r.notes)


def test_missing_reverse_direction_says_how_to_read_it():
    r = H.run(Lab().set_reverse(IPA02, status="NOT_RUN"))
    gap = next(g for g in r.completeness["not_verified"] if g["step"].startswith("reverse@"))
    assert "kinit admin" in gap["reason"] and "sudo does not pass" in gap["reason"]


def test_dns_failure_is_observer_relative_and_stops_at_the_name():
    r = H.run(Lab().dns_broken(IPA02))
    p = H.primary(r)
    assert p.code == "PEER_NAME_UNRESOLVED" and "observed from ipa01" in p.detail
    assert r.trace.get("peer.port", subject=f"domain:{IPA02}").blocked_by == f"peer.dns@domain:{IPA02}"


def test_transport_error_that_the_peer_no_longer_shows_is_transient_not_a_root_cause():
    r = H.run(Lab().set_status(IPA02, S.TRANSPORT_TEXT))
    assert codes(r) == {"REPLICATION_NOT_REPRODUCED"}
    assert all(d.role == "WARNING" for d in r.diagnoses)
    assert r.status == "NOT_FULLY_VERIFIED"


# ---------------------------------------------------------------- Kerberos: KDC, clock, principal, keytab, 49


def test_local_kdc_stopped_explains_both_suffixes_as_one_shared_root_with_a_local_fix(monkeypatch):
    from ipa_diagnose.replication import safety as G

    meta = dict(G.SLICE5_PROCEDURES["proc.service.start-stopped-service"], replication_live=(
        {"tier": "LIVE", "freeipa": "4.13.3", "os": "fedora-43"},))
    monkeypatch.setitem(G.SLICE5_PROCEDURES, "proc.service.start-stopped-service", meta)
    r = H.run(Lab().local_kdc_stopped(), live=True)
    p = H.primary(r)
    assert p.code == "LOCAL_KDC_NOT_RUNNING" and p.subject == f"server:{IPA01}"
    assert sorted(p.explains) == [f"REPLICATION_FAILING@ca:{IPA01}>{IPA02}",
                                  f"REPLICATION_FAILING@domain:{IPA01}>{IPA02}"]
    chains = [c for c in r.chains if c.root.subject == p.subject]
    assert len(chains) == 3  # its own, and one per suffix (shared downstream link, not collapsed)
    res = H.offered(r)[p.key]
    assert [s.argv for s in res.steps] == [["systemctl", "start", "krb5kdc.service"]]
    ng = r.gates[p.key]["no_google"]
    assert ng["claimed"] is True and not ng["missing"]


def test_local_kdc_stopped_while_agreements_still_green_is_found_without_blaming_replication():
    r = H.run(Lab().local_kdc_stopped(affect_agreements=False))
    assert codes(r) == {"LOCAL_KDC_NOT_RUNNING"}
    assert "once the Directory Server's current tickets expire" in H.primary(r).impact


def test_no_kdc_error_with_the_local_kdc_running_goes_no_deeper():
    lab = Lab().kerberos_failure(IPA02, kinit_ok=False, kinit_class="kdc_unreachable", bind_attempted=False,
                                 bind_ok=False)
    r = H.run(lab)
    assert H.primary(r) is None
    d = next(d for d in r.diagnoses if d.code == "REPLICATION_FAILING")
    assert d.role == "UNDIAGNOSED" and "LOCAL_KDC_NOT_RUNNING" not in codes(r)
    c = r.chains[0]
    assert c.links[-1].capability == "KERBEROS" and "krb5kdc is running" in c.boundary


def test_clock_skew_stops_at_the_measured_difference_and_never_claims_the_peers_ntp_state():
    r = H.run(Lab().clock_skew(IPA02, 900))
    p = H.primary(r)
    assert p.code == "PAIR_CLOCK_SKEW" and "900 s" in p.title
    blob = " ".join([p.detail] + [c.boundary for c in r.chains]).lower()
    assert "chronyd" not in blob and "stopped" not in blob
    assert "which clock is wrong is not established" in blob
    assert r.resolutions[p.key].status == "NONE"  # no clock step is ever printed


def test_clock_skew_status_with_a_small_measured_offset_is_not_promoted_to_time():
    lab = Lab().clock_skew(IPA02, 12)
    r = H.run(lab)
    assert "PAIR_CLOCK_SKEW" not in codes(r)
    assert any("under the Kerberos tolerance" in c.boundary for c in r.chains)


def test_pair_skew_on_a_green_agreement_is_still_reported():
    lab = Lab()
    lab.data[S.key("repl.peer_rootdse", {"host": IPA02, "port": "389", "transport": "LDAP"})]["fields"][
        "offset_seconds"] = -420.0
    r = H.run(lab)
    assert H.primary(r).code == "PAIR_CLOCK_SKEW" and "behind" in H.primary(r).detail


def test_peer_clock_falls_back_to_the_https_date_header_when_the_root_dse_has_none():
    lab = Lab().kerberos_failure(IPA02, bind_ok=False, bind_error_class="GSSAPI_CLOCK_SKEW").rootdse_without_clock(
        IPA02, https_offset=-700.0)
    r = H.run(lab)
    p = H.primary(r)
    assert p.code == "PAIR_CLOCK_SKEW" and "HTTPS Date header" in p.detail and "behind" in p.detail
    assert r.trace.get("peer.time", subject=f"domain:{IPA02}").outcome.value == "WARN"


def test_no_peer_clock_at_all_stops_the_skew_chain_at_kerberos():
    lab = Lab().kerberos_failure(IPA02, bind_ok=False, bind_error_class="GSSAPI_CLOCK_SKEW").rootdse_without_clock(
        IPA02)
    r = H.run(lab)
    assert "PAIR_CLOCK_SKEW" not in codes(r)
    assert any(c.links[-1].capability == "KERBEROS" and "could not be read" in c.boundary for c in r.chains)


def test_the_https_clock_is_not_read_when_the_root_dse_gives_it():
    r = H.run(Lab())
    assert r.trace.get("peer.time", subject=f"domain:{IPA02}").skip_reason.startswith("not needed")


def test_server_not_found_is_taken_to_the_missing_principal_only_when_the_list_is_complete():
    lab = Lab().kerberos_failure(IPA02, bind_ok=False, bind_error_class="GSSAPI_SERVER_NOT_FOUND")
    lab.data[S.key("repl.principals", {})]["fields"]["ldap_principals"] = [IPA01, IPA03]
    r = H.run(lab)
    assert H.primary(r).code == "PEER_LDAP_PRINCIPAL_MISSING"
    lab.data[S.key("repl.principals", {})]["fields"]["complete"] = False
    r2 = H.run(lab)
    assert "PEER_LDAP_PRINCIPAL_MISSING" not in codes(r2)


def test_unreadable_ds_keytab_is_the_local_root_even_though_root_can_read_it():
    lab = Lab().set_status(IPA02, S.LOCAL_ERROR_TEXT).keytab(owner="root", group="root", dirsrv_can_read=False)
    lab.gssapi(IPA02, bind_ok=False, bind_error_class="GSSAPI_CREDENTIALS")  # (root can read it; dirsrv cannot)
    r = H.run(lab)
    p = H.primary(r)
    assert p.code == "DS_KEYTAB_PROBLEM" and "dirsrv" in p.title
    assert r.resolutions[p.key].status == "NONE"  # no keytab/ownership fix printed in Slice 5


def test_the_real_389ds_status_shape_still_reaches_the_local_kdc(tmp_path=None):
    """389-DS records only 'Local error (connection error)': the KDC cause comes from the reproduction."""

    r = H.run(Lab().local_kdc_stopped(), live=True)
    assert r.trace.get("agreements").facts["subjects"][0]["status_class"] == "GSSAPI_OTHER"
    assert H.primary(r).code == "LOCAL_KDC_NOT_RUNNING"
    assert any("shown by reproduction (kinit)" in c.links[1].claim for c in r.chains if len(c.links) > 1)
    assert H.offered(r)


def test_ldap_49_with_a_measured_skew_is_the_clock_not_the_peers_keytab():
    lab = Lab().kerberos_failure(IPA02, S.INVALID_TEXT, bind_ok=False, bind_error_class="INVALID_CREDENTIALS")
    lab.data[S.key("repl.peer_rootdse", {"host": IPA02, "port": "389", "transport": "LDAP"})]["fields"][
        "offset_seconds"] = 900.0
    r = H.run(lab)
    assert H.primary(r).code == "PAIR_CLOCK_SKEW"
    assert "PEER_REJECTS_GSSAPI" not in codes(r)
    assert any(ln.discriminator == "kerberos-49-with-measured-skew" for c in r.chains for ln in c.links)


def test_ldap_49_with_a_kinit_that_cannot_reach_a_kdc_is_not_called_a_credential_problem():
    lab = Lab().local_kdc_stopped(affect_agreements=False).kerberos_failure(
        IPA02, S.INVALID_TEXT, kinit_ok=False, kinit_class="kdc_unreachable", bind_attempted=False, bind_ok=False)
    r = H.run(lab)
    assert H.primary(r).code == "LOCAL_KDC_NOT_RUNNING"
    assert not any("obtained its own ticket" in c.boundary for c in r.chains)
    assert not any("no usable Kerberos credentials" in ln.claim for c in r.chains for ln in c.links)
    # freeze review: a recorded LDAP 49 (ticket obtained, then refused) is NOT explained by a KDC that is down now
    sym = next(d for d in r.diagnoses if d.key == f"REPLICATION_FAILING@domain:{IPA01}>{IPA02}")
    assert sym.related_to is None and sym.key not in H.primary(r).explains
    assert sym.role == "UNDIAGNOSED" and any(f"on {IPA02}:" in s for s in sym.next_steps)


def test_a_tls_failure_is_not_called_a_directory_server_that_does_not_answer():
    lab = Lab().set_status(IPA02, "Error (-11) Problem connecting to replica - LDAP error: Connect error "
                                  "(connection error)")
    rd = lab.data[S.key("repl.peer_rootdse", {"host": IPA02, "port": "389", "transport": "LDAP"})]["fields"]
    rd.update(answered=False, ok=False, error_class="TLS", offset_seconds=None)
    r = H.run(lab)
    assert H.primary(r).code == "PEER_TLS_FAILED"
    assert "PEER_DS_NOT_ANSWERING" not in codes(r)


def test_a_failing_agreement_dropped_by_the_budget_is_still_reported():
    lab = Lab().many_agreements(9)
    lab.set_status("extra08.lab.test", S.TRANSPORT_TEXT)
    r = H.run(lab)
    d = next(x for x in r.diagnoses if x.subject.endswith(">extra08.lab.test"))
    assert d.code == "REPLICATION_FAILING" and d.role == "UNDIAGNOSED" and "not investigated" in d.title
    assert r.status == "PROBLEM_FOUND"


def test_ldap_49_is_not_jumped_to_a_keytab_mismatch():
    r = H.run(Lab().set_status(IPA02, S.INVALID_TEXT, suffix="domain"))
    assert not {"DS_KEY_REJECTED", "DS_KEYTAB_PROBLEM"} & codes(r)
    assert "REPLICATION_NOT_REPRODUCED" in codes(r)  # the fresh reproduction succeeds


def test_ldap_49_reproduced_with_a_valid_ticket_is_a_peer_side_rejection():
    lab = Lab().set_status(IPA02, S.INVALID_TEXT, suffix="domain").gssapi(IPA02, bind_ok=False,
                                                                         bind_error_class="INVALID_CREDENTIALS")
    r = H.run(lab)
    p = H.primary(r)
    assert p.code == "PEER_REJECTS_GSSAPI" and p.scope == "peer" and p.confidence == "MEDIUM"
    assert r.handoffs and r.handoffs[0]["host"] == IPA02


def test_ldap_49_with_a_rejected_local_key_is_the_local_key():
    lab = Lab().set_status(IPA02, S.INVALID_TEXT, suffix="domain").gssapi(
        IPA02, kinit_ok=False, kinit_class="key_rejected", bind_attempted=False, bind_ok=False)
    r = H.run(lab)
    assert H.primary(r).code == "DS_KEY_REJECTED"
    assert r.resolutions[H.primary(r).key].status == "NONE"
    # the recorded 49 is not claimed as explained by the local key (freeze review): undiagnosed, pointing to the peer
    sym = next(d for d in r.diagnoses if d.key == f"REPLICATION_FAILING@domain:{IPA01}>{IPA02}")
    assert sym.related_to is None and sym.role == "UNDIAGNOSED"


def test_a_local_kdc_fix_is_not_claimed_to_resolve_a_recorded_49():
    """Freeze review probe: KDC stopped + a recorded LDAP 49. After the KDC is started while the 49 remains, verify
    must not say the KDC diagnosis is STILL_PRESENT (it is running) - and the 49 is not RESOLVED either."""

    from tests.replication import test_verify as TV

    lab = Lab().unit("krb5kdc").kerberos_failure(IPA02, S.INVALID_TEXT, kinit_ok=False, kinit_class="kdc_unreachable",
                                                 bind_attempted=False, bind_ok=False)
    r = H.run(lab, live=True)
    assert not H.offered(r) or all(k.startswith("LOCAL_KDC") for k in H.offered(r))
    _r, prev = TV.baseline(lab)
    later = TV.fixed_later().kerberos_failure(IPA02, S.INVALID_TEXT, kinit_ok=True,
                                              bind_error_class="INVALID_CREDENTIALS")
    _c, out, _code = TV.verify(prev, later)
    assert out[f"LOCAL_KDC_NOT_RUNNING@server:{IPA01}"] == "RESOLVED", out
    assert out[f"REPLICATION_FAILING@domain:{IPA01}>{IPA02}"] != "RESOLVED", out


# ---------------------------------------------------------------- authorization, data, CA suffix


def test_insufficient_access_with_this_server_missing_from_managers():
    lab = Lab().set_status(IPA02, S.DENIED_TEXT, suffix="domain")
    lab.data[S.key("repl.principals", {})]["fields"]["replication_managers"] = [IPA02, IPA03]
    r = H.run(lab)
    assert H.primary(r).code == "NOT_A_REPLICATION_MANAGER"
    assert H.primary(r).confidence == "MEDIUM"


def test_ca_suffix_only_failure_leaves_the_domain_suffix_green():
    r = H.run(Lab().set_status(IPA02, S.GENERATION_TEXT, suffix="ca"))
    p = H.primary(r)
    assert p.code == "REPLICA_NEEDS_ADMIN_ACTION" and p.subject == f"ca:{IPA01}>{IPA02}"
    assert H.rel(r, f"domain:{IPA01}>{IPA02}")["state"] == "OK"
    assert r.resolutions[p.key].status == "NONE"
    reason = r.resolutions[p.key].reasons[0].lower()
    assert "never prints re-initialization" in reason


def test_suffixes_with_the_same_peer_are_separate_subjects():
    r = H.run(Lab().set_status(IPA02, S.WEIRD_TEXT, suffix="ca"))
    subjects = {d.subject for d in r.diagnoses}
    assert subjects == {f"ca:{IPA01}>{IPA02}"}
    assert H.rel(r, f"domain:{IPA01}>{IPA02}")["state"] == "OK"


def test_unrecognized_status_is_undiagnosed_not_forced_into_a_story():
    r = H.run(Lab().set_status(IPA02, S.WEIRD_TEXT))
    assert {d.role for d in r.diagnoses} == {"UNDIAGNOSED"}
    assert r.status == "PROBLEM_FOUND" and not H.offered(r)


@pytest.mark.parametrize("text", [S.BUSY_TEXT, S.NO_SESSIONS_TEXT])
def test_transient_states_are_never_green_and_never_a_root(text):
    r = H.run(Lab().set_status(IPA02, text, suffix="domain"))
    assert {d.code for d in r.diagnoses} == {"REPLICATION_TRANSIENT"}
    assert r.status == "NOT_FULLY_VERIFIED"
    assert H.rel(r, f"domain:{IPA01}>{IPA02}")["state"] != "OK"


def test_disabled_agreement_is_reported_and_not_probed():
    r = H.run(Lab().set_status(IPA02, S.OK_TEXT, suffix="domain", enabled=False))
    assert "AGREEMENT_DISABLED" in codes(r)


# ---------------------------------------------------------------- reverse direction


def test_reverse_direction_failure_read_from_the_peer_is_handed_off_to_the_peer():
    r = H.run(Lab().set_reverse(IPA02, S.LOCAL_ERROR_TEXT, suffix="domain"))
    d = next(x for x in r.diagnoses if x.code == "REVERSE_REPLICATION_FAILING")
    assert d.subject == f"domain:{IPA02}>{IPA01}" and d.scope == "peer"
    assert d.handoff["host"] == IPA02
    assert not any(x.code == "LOCAL_KDC_NOT_RUNNING" for x in r.diagnoses)  # the PEER's KDC, not ours
    assert H.rel(r, f"ca:{IPA02}>{IPA01}")["state"] == "OK"


def test_a_reverse_transport_failure_while_this_ds_runs_is_transient_not_a_failure():
    r = H.run(Lab().set_reverse(IPA02, S.TRANSPORT_TEXT, suffix="domain"))
    d = next(x for x in r.diagnoses if x.subject == f"domain:{IPA02}>{IPA01}")
    assert d.kind == "TRANSIENT" and d.severity == "WARN" and r.status == "NOT_FULLY_VERIFIED"
    assert H.rel(r, f"domain:{IPA02}>{IPA01}")["state"] == "TRANSIENT"


def test_reverse_direction_without_a_ticket_is_unknown_and_never_inferred():
    r = H.run(Lab().set_reverse(IPA02, status="NOT_RUN"))
    assert r.status == "NOT_FULLY_VERIFIED"
    assert H.rel(r, f"domain:{IPA02}>{IPA01}")["state"] == "UNKNOWN"
    assert any(h["host"] == IPA02 for h in r.handoffs)


def test_an_empty_reverse_answer_is_not_visible_not_absent():
    r = H.run(Lab().set_reverse(IPA02, visible=False))
    assert H.rel(r, f"domain:{IPA02}>{IPA01}")["state"] == "UNKNOWN"
    assert r.status == "NOT_FULLY_VERIFIED"


# ---------------------------------------------------------------- local prerequisites and multiple roots


def test_local_ds_stopped_blocks_everything_that_needs_it_and_is_the_only_root():
    r = H.run(Lab().unit("dirsrv"))
    assert H.primary(r).code == "LOCAL_DS_NOT_RUNNING"
    assert r.trace.get("agreements").blocked_by == "local.ds"
    assert r.status == "PROBLEM_FOUND"
    assert any(g["step"] == "agreements" for g in r.completeness["not_verified"]) is False  # explained, not a gap


def test_kdc_down_because_ds_down_is_related_to_the_ds():
    r = H.run(Lab().unit("dirsrv").unit("krb5kdc"))
    kdc = next(d for d in r.diagnoses if d.code == "LOCAL_KDC_NOT_RUNNING")
    assert kdc.role == "RELATED" and kdc.related_to == f"LOCAL_DS_NOT_RUNNING@server:{IPA01}"


def test_storage_under_a_stopped_ds_is_the_deeper_cause_and_the_ds_start_is_not_offered():
    lab = Lab().unit("dirsrv")
    lab.data[S.key("repl.storage", {})]["fields"].update(read_only=True)
    r = H.run(lab, live=True)
    assert H.primary(r).code == "DS_STORAGE_PROBLEM"
    ds = next(d for d in r.diagnoses if d.code == "LOCAL_DS_NOT_RUNNING")
    assert ds.role == "RELATED" and ds.resolution_key is None
    assert not H.offered(r)


def test_two_independent_causes_on_two_peers_are_two_chains():
    lab = Lab(me=IPA02).peer_ds_stopped(IPA01).peer_unreachable(IPA03)
    r = H.run(lab)
    roots = {d.code: d.role for d in r.diagnoses if d.role in ("PRIMARY", "INDEPENDENT")}
    assert set(roots) == {"PEER_DS_NOT_ACCEPTING", "PEER_UNREACHABLE"}
    assert sorted(roots.values()) == ["INDEPENDENT", "PRIMARY"]
    assert {h["host"] for h in r.handoffs} >= {IPA01, IPA03}


def test_local_and_peer_causes_together_keep_the_local_one_primary():
    lab = Lab(me=IPA02).local_kdc_stopped(affect_agreements=False).peer_ds_stopped(IPA03)
    r = H.run(lab)
    assert H.primary(r).code == "LOCAL_KDC_NOT_RUNNING"
    assert any(d.code == "PEER_DS_NOT_ACCEPTING" and d.role == "INDEPENDENT" for d in r.diagnoses)


def test_every_chain_passes_the_discriminator_and_dag_check():
    for lab in (Lab().peer_ds_stopped(IPA02), Lab().peer_unreachable(IPA02), Lab().dns_broken(IPA02),
                Lab().local_kdc_stopped(), Lab().clock_skew(IPA02), Lab().set_status(IPA02, S.GENERATION_TEXT),
                Lab(me=IPA02).peer_ds_stopped(IPA01).peer_unreachable(IPA03), Lab().unit("dirsrv").unit("krb5kdc")):
        for c in H.run(lab).chains:
            check_chain(c)


# ---------------------------------------------------------------- bounds, topology, RUV


def test_budget_drops_are_named_partial_and_never_healthy():
    r = H.run(Lab().many_agreements(9))
    e = r.trace.enumerations["agreement"]
    assert e["status"] == "PARTIAL" and len(e["subjects"]) == 8 and len(e["dropped"]) == 3
    assert r.status == "NOT_FULLY_VERIFIED"
    gap = next(g for g in r.completeness["not_verified"] if g["step"] == "agreement")
    assert all(x in gap["reason"] for x in e["dropped"])
    dropped = [x for x in r.relationships if x["direction"] == "outbound" and not x["investigated"]]
    assert len(dropped) == 3


def test_topology_and_agreements_that_disagree_are_contradicting_and_withhold_fixes():
    lab = Lab().local_kdc_stopped(affect_agreements=False)
    lab.data[S.key("repl.topology", {})]["fields"]["segments"].append(
        {"suffix": "domain", "left": IPA01, "right": IPA03, "name": "x", "direction": "both"})
    r = H.run(lab, live=True)
    assert any(d.code == "SEGMENT_WITHOUT_AGREEMENT" and d.role == "CONTRADICTING" for d in r.diagnoses)
    kdc = H.primary(r)
    assert r.resolutions[kdc.key].status == "WITHHELD"
    assert any("Contradicting" in x for x in r.resolutions[kdc.key].reasons)


def test_ruv_element_without_server_is_a_candidate_never_a_cleanup():
    r = H.run(Lab().ruv("domain", 9, "old.lab.test"))
    d = next(x for x in r.diagnoses if x.code == "RUV_ELEMENT_WITHOUT_SERVER")
    assert d.severity == "WARN" and "candidate" in d.detail.lower()
    assert r.resolutions[d.key].status == "NONE"
    assert "clean" not in " ".join(d.next_steps).replace("clean-up", "").lower() or "ipa-healthcheck" in d.next_steps[0]


def test_ruv_is_not_classified_while_a_clean_task_runs_or_the_topology_is_partial():
    lab = Lab().ruv("domain", 9, "old.lab.test")
    lab.data[S.key("repl.agreements", {})]["fields"]["clean_tasks"] = 1
    r = H.run(lab)
    assert "RUV_ELEMENT_WITHOUT_SERVER" not in codes(r)
    assert any("clean task" in n for n in r.notes)
    lab2 = Lab().ruv("domain", 9, "old.lab.test")
    lab2.data[S.key("repl.topology", {})]["fields"]["complete"] = False
    assert "RUV_ELEMENT_WITHOUT_SERVER" not in codes(H.run(lab2))


def test_without_root_nothing_is_claimed_about_what_needs_root():
    r = H.run(Lab().peer_ds_stopped(IPA02), is_root=False)
    assert r.status == "NOT_FULLY_VERIFIED"
    assert not r.diagnoses
    assert any("needs root" in g["reason"] for g in r.completeness["not_verified"])


def test_unexpected_evidence_types_are_never_interpreted():
    lab = Lab()
    lab.data[S.key("repl.agreements", {})]["fields"]["agreements"] = "not a list"
    r = H.run(lab)
    assert r.status != "HEALTHY"
