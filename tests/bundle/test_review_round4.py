"""Reproductions from the fourth fresh security review of the support bundle (credential shapes, URL hosts)."""

from __future__ import annotations

import pytest

from ipa_diagnose.bundle.sanitize import Sanitizer, find_secrets


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


@pytest.mark.parametrize("text,secret", [
    ("ldap_default_authtok = ZqCanary40", "ZqCanary40"),
    ("ldapsearch -LLL -xw ZqCanary1 -b cn=config", "ZqCanary1"),
    ("ldapsearch -Y GSSAPI -xLLLw ZqCanary48", "ZqCanary48"),
    ("bindpw ZqCanary42", "ZqCanary42"),
    ("rootpw ZqCanary43", "ZqCanary43"),
    ("PASSWORD\tZqCanary24", "ZqCanary24"),
    ("reports: PASSWORD ZqCanary24 (collapsed upstream)", "ZqCanary24"),
    ("curl --user admin:ZqCanary2 https://x/ipa", "ZqCanary2"),
    ("ldap://cn=Directory Manager:ZqCanary18@ipa.corp.test", "ZqCanary18"),
    ("net ads join -U Administrator%ZqCanary3", "ZqCanary3"),
    ("The password for admin is ZqCanary4", "ZqCanary4"),
    ("PIN for token 'NSS Certificate DB': ZqCanary34", "ZqCanary34"),
    ("Client secret [REF-1]: ZqCanary6", "ZqCanary6"),
    ("password agent: ZqCanary7", "ZqCanary7"),
    ("sshpass -p ZqCanary8 ssh root@h", "ZqCanary8"),
    ("kinit admin <<< ZqCanary9", "ZqCanary9"),
    ("echo ZqCanary10 | kinit admin", "ZqCanary10"),
    ("Cookie ipa_session=MagBearerToken%3DZqCanary16abcdef", "ZqCanary16"),
    ("pass word=ZqCanary38", "ZqCanary38"),  # a zero-width space turned into a space by upstream text cleaning
])
def test_credential_shapes_from_round_four_are_redacted(text, secret):
    out = _san(text).text(text)
    assert secret not in out
    assert "[REDACTED:[REDACTED" not in out  # never a marker inside a marker


def test_sssd_authtok_field_is_removed():
    assert _san().transform({"ldap_default_authtok": "ZqCanary41"}) == {"ldap_default_authtok": "[REMOVED]"}


@pytest.mark.parametrize("text", ["Enter password for cn=Directory Manager: ZqCanary35",
                                  "The password for admin is ZqCanary4"])
def test_redacted_prompts_do_not_trip_the_self_test_detectors(text):
    out = _san(text).text(text)
    assert "ZqCanary" not in out and not find_secrets(out)


@pytest.mark.parametrize("text", ["Password expired for user admin", "ldap_default_authtok_type = password",
                                  "Directory Manager password required", "password policy: default"])
def test_config_rules_leave_prose_and_metadata_alone(text):
    assert _san().text(text) == text


def test_the_host_of_a_url_with_a_spaced_user_part_is_pseudonymized():
    text = "ldap://cn=Directory Manager:ZqCanary18@ipa.corp.test"
    out = _san(text).text(text)
    assert "corp.test" not in out and "ipa.corp" not in out


def test_a_host_in_the_ipa_domain_before_a_file_extension_is_pseudonymized():
    text = "copied replica07.example.test.pem to the replica"
    out = _san(text).text(text)
    assert "replica07" not in out and "example.test" not in out
