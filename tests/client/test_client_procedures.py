"""Client fix procedures (Slice 4): offered only when every gate passes; withheld otherwise. False-resolution gate."""

from __future__ import annotations

import json

import pytest

from ipa_diagnose.resolution.knowledge import FIX_PROGRAMS, KnowledgeError, load_catalogue, validate_catalogue
from tests.client import helpers as H
from tests.client import scenarios as S
from tests.client.scenarios import DOMAIN, USER, key

ALL = sorted(S.SCENARIOS)


def _every_command(r):
    out = []
    for code, res in r.resolutions.items():
        if code.startswith("_"):
            continue
        out += [s.argv for s in res.steps] + [x["argv"] for x in res.rollback if x.get("argv")]
    for d in r.diagnoses:
        out += [[s] for s in d.next_steps]
    return out


@pytest.mark.parametrize("name", ALL)
def test_no_destructive_generic_command_in_any_scenario(name):
    r = H.run(name, hbac="PASS" if name == "contradicting" else None)
    text = json.dumps(_every_command(r))
    for bad in ("rm ", "/var/lib/sss/db/*", "initctl", "ipa-client-install", "ipa-getkeytab", "--uninstall",
                "ipa-join", "kdestroy", "resolv.conf >", "nmcli", "chronyc makestep", "date -s", "sed -i"):
        assert bad not in text, (name, bad)


@pytest.mark.parametrize("name", ALL)
def test_offered_steps_use_only_allowlisted_programs(name):
    r = H.run(name)
    for res in H.offered(r).values():
        for st in res.steps:
            assert st.argv[0] in FIX_PROGRAMS
            if st.argv[0] == "sssctl":
                assert st.argv[1] == "cache-remove"


def test_only_expected_fixes_are_offered():
    expected = {"sssd-stopped": {"SSSD_NOT_RUNNING": "proc.client.start-sssd"},
                "stale-cache": {"SSSD_CACHE_INCONSISTENT": "proc.client.expire-sssd-user-entry"},
                "cache-db-error": {"SSSD_CACHE_DB_ERROR": "proc.client.remove-sssd-cache"}}
    for name in ALL:
        got = {k: v.procedure_id for k, v in H.offered(H.run(name)).items()}
        assert got == expected.get(name, {}), name


def test_restart_is_withheld_when_the_config_is_invalid():
    r = H.run("sssd-config-invalid")
    res = r.resolutions["SSSD_NOT_RUNNING"]
    assert res.status == "WITHHELD" and not res.steps


def test_start_is_withheld_when_config_check_says_invalid_even_if_diagnosis_is_primary():
    def m(d):
        S.sssd_stopped(d)
        d[key("sssd.config_check")]["fields"].update(valid=False, issues=1)

    # the diagnosis layer sees the invalid config too; force the procedure path by recording the check invalid only
    r = H.run("healthy", mutate=m)
    res = r.resolutions["SSSD_NOT_RUNNING"]
    assert res.status == "WITHHELD"


def test_start_is_withheld_without_systemd_and_never_prints_initctl():
    def m(d):
        S.sssd_stopped(d)
        d[key("client.versions")]["fields"].update(systemd=False)

    r = H.run("healthy", mutate=m)
    res = r.resolutions["SSSD_NOT_RUNNING"]
    assert res.status == "WITHHELD" and any("initctl" in x and "obsolete" in x for x in res.reasons)
    assert not res.steps


def test_start_is_withheld_when_masked_disabled_or_not_root():
    for fields in ({"load_state": "masked"}, {"unit_file_state": "disabled"}):
        def m(d, f=fields):
            S.sssd_stopped(d)
            d[key("systemd.unit", service="sssd")]["fields"].update(f)

        assert H.run("healthy", mutate=m).resolutions["SSSD_NOT_RUNNING"].status == "WITHHELD"

    def m(d):
        S.sssd_stopped(d)
        d[key("host.privilege")]["fields"].update(is_root=False)

    assert H.run("healthy", mutate=m).resolutions["SSSD_NOT_RUNNING"].status == "WITHHELD"


def test_start_fix_is_withheld_on_an_unknown_client_version():
    def m(d):
        S.sssd_stopped(d)
        d[key("client.versions")]["fields"].update(ipa_client=None)

    res = H.run("healthy", mutate=m).resolutions["SSSD_NOT_RUNNING"]
    assert res.status == "WITHHELD" and any("IPA client version" in x for x in res.reasons)


def test_start_fix_is_withheld_on_an_unsupported_client_version():
    def m(d):
        S.sssd_stopped(d)
        d[key("client.versions")]["fields"].update(ipa_client="4.6.8")

    res = H.run("healthy", mutate=m).resolutions["SSSD_NOT_RUNNING"]
    assert res.status == "WITHHELD" and any("4.9 or later" in x for x in res.reasons)


def test_cache_expire_is_withheld_when_offline_or_no_entry():
    def offline(d):
        S.stale_cache(d)
        d[key("sssd.domain_status", domain=DOMAIN)]["fields"].update(online=False)

    assert not H.offered(H.run("healthy", mutate=offline))

    def no_entry_now(d):
        S.stale_cache(d)
        # the planner saw an entry, the fresh check made for the procedure sees none: withheld (same key: simulate
        # by a different recorded answer is impossible in one replay, so the planner itself sees none)
        d[key("sssd.cache_user", user=USER)]["fields"].update(present=False)

    r = H.run("healthy", mutate=no_entry_now)
    assert "SSSD_CACHE_INCONSISTENT" not in H.codes(r) and not H.offered(r)


def test_cache_removal_needs_strong_evidence_and_admin_confirmation():
    r = H.run("cache-db-error")
    res = r.resolutions["SSSD_CACHE_DB_ERROR"]
    assert res.status == "OFFERED" and res.risk == "HIGH"
    assert [s.argv for s in res.steps] == [["sssctl", "cache-remove", "--stop", "--start"]]
    assert any(p.state == "confirm" and "cached passwords" in p.text for p in res.prerequisites)
    assert "cached password" in res.impact_note.lower() or "cached password" in " ".join(res.what_changes).lower()


def test_cache_removal_is_not_offered_on_a_suspicion():
    def m(d):
        S.cache_db_error(d)
        d[key("sssd.log_signals", domain=DOMAIN)]["fields"].update(counts={})  # only the cache read failed

    r = H.run("healthy", mutate=m)
    d = next(x for x in r.diagnoses if x.code == "SSSD_CACHE_DB_ERROR")
    assert d.confidence == "MEDIUM" and d.variant == "suspected"
    assert r.resolutions["SSSD_CACHE_DB_ERROR"].status == "NONE"


def test_no_clock_step_on_a_client_and_no_keytab_replacement_or_reenrollment():
    for name, code in (("time-skew", "CLOCK_SKEW"), ("keytab-mismatch", "HOST_KEY_REJECTED"),
                       ("keytab-missing", "HOST_KEYTAB_MISSING"), ("host-entry-missing", "HOST_PRINCIPAL_UNKNOWN"),
                       ("not-enrolled", "CLIENT_NOT_ENROLLED")):
        res = H.run(name).resolutions[code]
        assert res.status == "NONE" and not res.steps, name


def test_no_fix_for_undiagnosed_contradicting_or_related():
    r = H.run("contradicting", hbac="PASS")
    assert not r.resolutions
    r = H.run("sssd-config-invalid")
    assert r.resolutions["SSSD_NOT_RUNNING"].status == "WITHHELD"


def test_catalogue_rejects_other_sssctl_commands_and_unknown_programs():
    cat, err = load_catalogue()
    assert err is None
    proc = json.loads(json.dumps(next(p for p in cat if p["id"] == "proc.client.remove-sssd-cache")))
    proc["steps"][0]["command"] = ["sssctl", "logs-remove"]
    with pytest.raises(KnowledgeError, match="sssctl"):
        validate_catalogue({"schema": 1, "procedures": [proc]})
    proc["steps"][0]["command"] = ["rm", "-rf", "/var/lib/sss/db"]
    with pytest.raises(KnowledgeError):
        validate_catalogue({"schema": 1, "procedures": [proc]})


def test_client_procedures_are_client_role_only_and_server_ones_unchanged():
    cat, _ = load_catalogue()
    client = [p for p in cat if p["id"].startswith("proc.client.")]
    assert client and all(p["applies_to"]["roles"] == ["ipa-client"] for p in client)
    assert all(p["provenance"]["tier"] == "FIXTURE_ONLY" or p["provenance"]["verified_on"] for p in client)
    server = [p for p in cat if p.get("kind") == "procedure" and not p["id"].startswith("proc.client.")]
    assert all(p["applies_to"]["roles"] == ["ipa-server"] for p in server)


def test_sssd_failing_on_its_cache_database_gets_no_start_and_no_removal():
    r = H.run("sssd-fails-cache-db")
    assert H.codes(r) == {"SSSD_CACHE_DB_ERROR": "PRIMARY", "SSSD_NOT_RUNNING": "RELATED"}
    assert not H.offered(r)
    assert r.resolutions["SSSD_CACHE_DB_ERROR"].status == "NONE"


def test_one_log_line_and_an_absent_entry_do_not_justify_cache_removal():
    """Red-team round 1 (F2): an absent cache entry is ordinary; one cache_db log line is not proof."""

    def m(d):
        S.stale_cache(d)
        d[key("sssd.cache_user", user=USER)]["fields"].update(present=False)
        d[key("sssd.log_signals", domain=DOMAIN)]["fields"].update(counts={"cache_db": 1})

    r = H.run("healthy", mutate=m)
    d = next(x for x in r.diagnoses if x.code == "SSSD_CACHE_DB_ERROR")
    assert d.confidence == "MEDIUM" and d.variant == "suspected" and not H.offered(r)
