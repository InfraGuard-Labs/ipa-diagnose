"""Client mode against every SYNTHETIC replay scenario: root cause, role, states and completeness."""

from __future__ import annotations

import pytest

from tests.client import helpers as H

# scenario -> (primary code or None, status, runtime state, authentication state)
EXPECT = {
    "healthy": (None, "HEALTHY", "NOT_VERIFIED", "NOT_VERIFIED"),
    "sssd-stopped": ("SSSD_NOT_RUNNING", "PROBLEM_FOUND", "FAIL", "FAIL"),
    "dns-failure": ("DNS_RESOLVER_NOT_ANSWERING", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "time-skew": ("CLOCK_SKEW", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "server-unreachable": ("SERVER_UNREACHABLE", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "kdc-unreachable": ("KDC_UNREACHABLE", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "host-entry-missing": ("HOST_PRINCIPAL_UNKNOWN", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "keytab-missing": ("HOST_KEYTAB_MISSING", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "keytab-mismatch": ("HOST_KEY_REJECTED", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "keytab-wrong-principal": ("HOST_KEYTAB_WRONG_PRINCIPAL", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "sssd-config-invalid": ("SSSD_CONFIG_INVALID", "PROBLEM_FOUND", "FAIL", "FAIL"),
    "sssd-fails-cache-db": ("SSSD_CACHE_DB_ERROR", "PROBLEM_FOUND", "FAIL", "FAIL"),
    "user-missing-in-ipa": ("USER_NOT_IN_IPA", "PROBLEM_FOUND", "FAIL", "NOT_VERIFIED"),
    "stale-cache": ("SSSD_CACHE_INCONSISTENT", "PROBLEM_FOUND", "FAIL", "NOT_VERIFIED"),
    "cache-db-error": ("SSSD_CACHE_DB_ERROR", "PROBLEM_FOUND", "FAIL", "NOT_VERIFIED"),
    "nss-not-integrated": ("NSS_NOT_USING_SSSD", "PROBLEM_FOUND", "FAIL", "NOT_VERIFIED"),
    "pam-not-integrated": ("PAM_SERVICE_WITHOUT_SSSD", "PROBLEM_FOUND", "FAIL", "NOT_VERIFIED"),
    "pam-denied": ("RUNTIME_ACCOUNT_DENIED", "PROBLEM_FOUND", "FAIL", "NOT_VERIFIED"),
    "ca-untrusted": ("CA_TRUST_FAILED", "PROBLEM_FOUND", "NOT_VERIFIED", "FAIL"),
    "not-enrolled": ("CLIENT_NOT_ENROLLED", "PROBLEM_FOUND", "FAIL", "FAIL"),
    "collector-timeout": (None, "NOT_FULLY_VERIFIED", "NOT_VERIFIED", "NOT_VERIFIED"),
    "unsupported-sssd": (None, "NOT_FULLY_VERIFIED", "NOT_VERIFIED", "NOT_VERIFIED"),
    "unknown-sssd": (None, "NOT_FULLY_VERIFIED", "NOT_VERIFIED", "NOT_VERIFIED"),
    "srv-missing-fixed-fallback": (None, "HEALTHY_WITH_WARNINGS", "NOT_VERIFIED", "NOT_VERIFIED"),
    "fixed-servers-no-srv": (None, "HEALTHY", "NOT_VERIFIED", "NOT_VERIFIED"),
}


@pytest.mark.parametrize("name", sorted(EXPECT))
def test_scenario(name):
    prim, status, runtime, authn = EXPECT[name]
    r = H.run(name)
    assert H.primary(r) == prim, H.codes(r)
    assert r.status == status
    assert r.runtime.state == runtime
    assert r.authentication.state == authn
    assert r.runtime.state != "PASS" and r.authentication.state != "PASS"
    assert r.mode == "REPLAY"


def test_every_scenario_in_the_fixture_set_is_covered():
    from tests.client.scenarios import SCENARIOS

    assert set(SCENARIOS) - set(EXPECT) <= {"dns-and-config", "hostile-output", "contradicting",
                                             "sssd-offline-unexplained"}


def test_simultaneous_failures_are_primary_plus_independent_not_one_story():
    r = H.run("dns-and-config")
    c = H.codes(r)
    assert c["SSSD_CONFIG_INVALID"] == "PRIMARY"
    assert c["DNS_RESOLVER_NOT_ANSWERING"] == "INDEPENDENT"
    assert c["SSSD_NOT_RUNNING"] == "RELATED"
    assert c["KDC_NOT_RESOLVABLE"] == "RELATED"


def test_offline_with_healthy_upstream_is_undiagnosed_not_guessed():
    r = H.run("sssd-offline-unexplained")
    c = H.codes(r)
    assert c["SSSD_OFFLINE"] == "UNDIAGNOSED" and H.primary(r) is None
    assert c["IDENTITY_LOOKUP_FAILS"] == "RELATED"
    assert r.status == "PROBLEM_FOUND"


def test_hbac_pass_with_runtime_denial_is_contradicting():
    r = H.run("contradicting", hbac="PASS")
    assert H.codes(r) == {"RUNTIME_DENIED_HBAC_ALLOWS": "CONTRADICTING"}
    assert r.authorization.state == "PASS"  # never rewritten by runtime evidence
    assert r.runtime.state == "FAIL"
    assert not H.offered(r)


def test_client_mode_alone_never_claims_an_authorization_decision():
    r = H.run("healthy")
    assert r.authorization.state == "NOT_VERIFIED"


def test_without_root_the_run_is_not_fully_verified_and_says_why():
    r = H.run("healthy", is_root=False)
    assert r.status == "NOT_FULLY_VERIFIED"
    gaps = {g["step"] for g in r.completeness["not_verified"]}
    assert {"keytab", "krb", "sssd", "sssd.domain"} <= gaps
    assert all("blocked" in g["reason"] for g in r.completeness["not_verified"] if g["step"] == "krb")


def test_without_user_the_group_probe_tests_identity_lookup():
    r = H.run("healthy", user=None, service=None)
    assert H.outcome(r, "id.group") == "PASS" and H.outcome(r, "id.user") == "SKIPPED"
    assert r.status == "HEALTHY"


def test_user_lookup_failure_triggers_the_group_probe_and_the_ipa_lookup():
    r = H.run("user-missing-in-ipa")
    assert H.outcome(r, "id.group") == "PASS"
    assert H.outcome(r, "ipa.user") == "FAIL"
    assert H.outcome(r, "cache.entry") == "SKIPPED"  # IPA does not have the user: the cache is not suspected


def test_unsupported_sssd_skips_every_sssctl_check():
    r = H.run("unsupported-sssd")
    for step in ("sssd.config", "sssd.domain", "pam.acct"):
        assert r.trace.get(step).skip_reason.startswith("not applicable"), step
