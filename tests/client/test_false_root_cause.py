"""False-root-cause gate: the planner must not confidently blame the wrong layer (owner's Slice 4 list)."""

from __future__ import annotations

from tests.client import helpers as H
from tests.client import scenarios as S
from tests.client.scenarios import DOMAIN, PRINCIPAL, SERVER, USER, key


def _confident(r):
    return {d.code for d in r.diagnoses if d.role in ("PRIMARY", "INDEPENDENT") and d.confidence in ("HIGH", "MEDIUM")}


def test_dns_is_not_blamed_when_sssd_is_broken():
    r = H.run("sssd-stopped")
    assert not {c for c in _confident(r) if c.startswith("DNS")}


def test_sssd_is_not_blamed_when_dns_is_broken():
    r = H.run("dns-failure")
    assert H.primary(r).startswith("DNS")
    assert H.codes(r).get("SSSD_OFFLINE") == "RELATED"
    assert not {c for c in _confident(r) if c.startswith("SSSD")}


def test_kerberos_or_keytab_is_not_blamed_when_time_is_broken():
    r = H.run("time-skew")
    assert H.primary(r) == "CLOCK_SKEW"
    assert not {"HOST_KEY_REJECTED", "KDC_UNREACHABLE", "HOST_PRINCIPAL_UNKNOWN"} & set(H.codes(r))


def test_kdc_reported_skew_without_a_measured_skew_is_medium_and_names_the_other_clock():
    def m(d):
        d[key("krb.host_kinit", principal=PRINCIPAL)]["fields"].update(ok=False, error_class="clock_skew")

    r = H.run("healthy", mutate=m)
    d = next(x for x in r.diagnoses if x.code == "CLOCK_SKEW")
    assert d.confidence == "MEDIUM" and "another server" in d.detail


def test_keytab_is_not_blamed_when_the_kdc_is_unavailable():
    r = H.run("kdc-unreachable")
    assert H.primary(r) == "KDC_UNREACHABLE"
    assert not {"HOST_KEY_REJECTED", "HOST_KEYTAB_MISSING", "HOST_PRINCIPAL_UNKNOWN"} & set(H.codes(r))


def test_cache_is_not_blamed_when_the_backend_is_offline():
    def m(d):
        S.stale_cache(d)
        d[key("sssd.domain_status", domain=DOMAIN)]["fields"].update(online=False)

    r = H.run("healthy", mutate=m)
    assert not {"SSSD_CACHE_INCONSISTENT", "SSSD_CACHE_DB_ERROR"} & set(H.codes(r))
    assert H.outcome(r, "cache.entry") == "SKIPPED"
    assert not H.offered(r)


def test_cache_is_not_blamed_when_ipa_lacks_the_user():
    def m(d):
        S.stale_cache(d)
        d[key("ipa.api_user", principal=PRINCIPAL, user=USER)]["fields"].update(exists=False)

    r = H.run("healthy", mutate=m)
    assert H.primary(r) == "USER_NOT_IN_IPA" and not H.offered(r)


def test_cache_is_not_blamed_when_ipa_could_not_be_asked():
    def m(d):
        S.stale_cache(d)
        d[key("ipa.api_user", principal=PRINCIPAL, user=USER)] = S.ok({}, "no answer", status="NOT_RUN")

    r = H.run("healthy", mutate=m)
    assert not {"SSSD_CACHE_INCONSISTENT", "SSSD_CACHE_DB_ERROR"} & set(H.codes(r))
    assert H.codes(r).get("IDENTITY_LOOKUP_FAILS") == "UNDIAGNOSED"
    assert not H.offered(r)


def test_enrollment_is_not_blamed_when_a_host_lookup_merely_failed():
    # the server name does not resolve: the KDC never answered, so "principal unknown" must not appear
    r = H.run("dns-failure")
    assert "HOST_PRINCIPAL_UNKNOWN" not in H.codes(r) and "CLIENT_NOT_ENROLLED" not in H.codes(r)
    # a kinit timeout is not "host deleted"
    def m(d):
        d[key("krb.host_kinit", principal=PRINCIPAL)] = S.ok({}, "timed out after 25s", status="NOT_RUN")

    r = H.run("healthy", mutate=m)
    assert "HOST_PRINCIPAL_UNKNOWN" not in H.codes(r)


def test_pam_is_not_blamed_when_nss_already_fails():
    def m(d):
        S.nss_not_integrated(d)
        S.pam_denied(d)
        d[key("nss.user_sss", user=USER)]["fields"].update(found=False)
        d[key("ipa.api_user", principal=PRINCIPAL, user=USER)]["fields"].update(exists=False)

    r = H.run("healthy", mutate=m)
    assert H.outcome(r, "pam.acct") == "SKIPPED"
    assert not {"RUNTIME_ACCOUNT_DENIED", "PAM_SERVICE_WITHOUT_SSSD"} & set(H.codes(r))


def test_srv_records_are_not_blamed_when_sssd_uses_fixed_servers():
    r = H.run("fixed-servers-no-srv")
    assert "DNS_SRV_MISSING" not in H.codes(r)
    assert H.outcome(r, "dns.srv_ldap") == "SKIPPED"


def test_missing_srv_with_a_fixed_fallback_is_only_a_warning():
    r = H.run("srv-missing-fixed-fallback")
    assert H.codes(r) == {"DNS_SRV_MISSING": "WARNING"} and r.runtime.state == "NOT_VERIFIED"


def test_contradicting_evidence_is_never_a_confident_primary():
    r = H.run("contradicting", hbac="PASS")
    assert H.primary(r) is None and not _confident(r)


def test_offline_with_only_the_offline_signal_is_not_explained_by_the_log():
    r = H.run("sssd-offline-unexplained")
    assert H.codes(r)["SSSD_OFFLINE"] == "UNDIAGNOSED"


def test_hostile_text_cannot_steer_the_diagnosis():
    r = H.run("hostile-output")
    assert H.primary(r) is None
    assert all(d.confidence != "HIGH" or d.role == "RELATED" for d in r.diagnoses)


def test_server_unreachable_is_the_cause_not_the_kdc():
    r = H.run("server-unreachable")
    assert H.primary(r) == "SERVER_UNREACHABLE" and H.codes(r)["KDC_UNREACHABLE"] == "RELATED"


def test_https_only_problem_is_not_blamed_on_ldap():
    def m(d):
        d[key("net.tcp", host=SERVER, port="443")]["fields"].update(state="refused", open=False)

    r = H.run("healthy", mutate=m)
    assert "SERVER_UNREACHABLE" not in H.codes(r) and "LDAP_UNREACHABLE" not in H.codes(r)
    assert H.codes(r).get("HTTPS_UNREACHABLE") == "WARNING" and r.runtime.state == "NOT_VERIFIED"
