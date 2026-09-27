"""Support bundle sanitization: redaction before truncation, consistent pseudonyms, relationships kept."""

from __future__ import annotations

import pytest

from ipa_diagnose.bundle.sanitize import Sanitizer, clean, find_secrets, redact


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host)
    if "." in host:
        s.add_domain(host.split(".", 1)[1])
        s.add_realm(host.split(".", 1)[1].upper())
    for t in texts:
        s.discover(t)
    return s


# --- secrets -------------------------------------------------------------------------------------------------------
SECRETS = [
    ("password=Hunter2xyz", "Hunter2xyz"),
    ("PASSWORD: Hunter2xyz", "Hunter2xyz"),
    ("dm_password = 'Secret Pass 1'", "Secret Pass 1"),
    ('{"bind_pw": "Hunter2xyz"}', "Hunter2xyz"),
    ("pwd=Hunter2xyz", "Hunter2xyz"),
    ("pw: Hunter2xyz", "Hunter2xyz"),
    ("pin=4821", "4821"),
    ("the password is Hunter2xyz", "Hunter2xyz"),
    ("Password was reset to Hunter2xyz today", "Hunter2xyz"),
    ("ipa-server-install --ds-password Hunter2xyz -U", "Hunter2xyz"),
    ("ipa-server-install --admin-password=Hunter2xyz", "Hunter2xyz"),
    ("ldapsearch -x -D 'cn=Directory Manager' -w Hunter2xyz -b cn=config", "Hunter2xyz"),
    ("pk12util -i x.p12 -W Hunter2xyz", "Hunter2xyz"),
    ("Authorization: Negotiate YIIGhgYGKwYBBQUCoIIGejCCBnagMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAg", "YIIGhgYGKwYBBQUCoIIG"),
    ("authorization=Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
    ("got header Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij", "eyJzdWIiOiIxIn0"),
    ("Cookie: ipa_session=MagBearerToken=abcdef0123456789", "abcdef0123456789"),
    ("connect ldaps://admin:Hunter2xyz@ipa02.example.test:636", "Hunter2xyz"),
    ("https://user:Hunter2xyz@proxy.example.com/", "Hunter2xyz"),
    ("key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
    ("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx"),
    ("using sk-ant-api03-abcdefghijklmnopqrstuv", "abcdefghijklmnopqrstuv"),
    ("token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghij"),
    ("xoxb-1234567890-abcdefghij", "1234567890-abcdefghij"),
    ("AIzaSyA-abcdefghijklmnopqrstuvwxyz012345", "AIzaSyA-abcdef"),
    ("keytab: 0123456789abcdef0123456789abcdef01234567", "0123456789abcdef0123456789abcdef"),
    ("blob 3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB9xyz0", "3q2+7wAAAAAAAAAAAAAA"),
    ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGd2Zm9vYmFyYmF6 user@host", "AAAAC3NzaC1lZDI1NTE5"),
]


@pytest.mark.parametrize("text,secret", SECRETS)
def test_known_secret_shapes_are_redacted(text, secret):
    out = redact(clean(text))
    assert secret not in out and "[REDACTED:" in out


@pytest.mark.parametrize("text,secret", [
    ("ＰＡＳＳＷＯＲＤ＝Ｈｕｎｔｅｒ２ｘｙｚ", "Hunter2xyz"),              # fullwidth (NFKC)
    ("pass​word=Hunter2xyz", "Hunter2xyz"),                    # zero-width space inside the keyword
    ("pass‮word=Hunter2xyz", "Hunter2xyz"),                    # bidi override inside the keyword
    ("pаssword=Hunter2xyz", "Hunter2xyz"),                          # Cyrillic 'а'
    ("PaSsWoRd=Hunter2xyz", "Hunter2xyz"),                          # mixed case
    ("\x1b[31mpassword=Hunter2xyz\x1b[0m", "Hunter2xyz"),           # terminal escapes around it
])
def test_unicode_and_terminal_tricks_do_not_hide_a_secret(text, secret):
    s = _san()
    out = s.text(text)
    assert secret not in out and "[REDACTED:" in out
    assert "\x1b" not in out and "​" not in out and "‮" not in out


def test_pem_blocks_complete_truncated_and_headless():
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n4lgOEePzNm0tRgeLezV6ffAt0gunVTLw\n-----END RSA PRIVATE KEY-----"
    cert = "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG\n-----END CERTIFICATE-----"
    cut = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"          # END was cut off upstream
    headless = "kiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----"   # BEGIN was cut off upstream
    for text, frag in ((key, "MIIEowIBAAKC"), (cert, "MIIDdzCCAl"), (cut, "MIIEvQIBADAN"), (headless, "kiG9w0BAQEFAASCBKcw")):
        out = _san().text("x " + text + " y")
        assert frag not in out and "[REDACTED:" in out


def test_redaction_runs_before_truncation():
    """A secret past the length limit is never exposed by the cut, and one straddling it is gone entirely."""

    s = _san()
    long_text = "a " * 300 + "password=Hunter2xyz " + "b " * 300
    out = s.text(long_text, limit=500)
    assert "Hunter2" not in out and s.truncated == 1
    straddle = "x" * 480 + " password=Hunter2xyzHunter2xyz"
    out = s.text(straddle, limit=500)
    assert "Hunter2" not in out


def test_oversized_text_is_omitted_not_cut_then_scanned():
    s = _san()
    out = s.text("password=" + "A" * 70000)
    assert out.startswith("[OMITTED:") and s.omitted == 1


@pytest.mark.parametrize("text", [
    "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg too permissive: 0664 and should be 0660",
    "_var_log_dirsrv_slapd-EXAMPLE-TEST_access_mode",
    "33333333-3333-3333-3333-333333333333",
    "csn 5f0a1b2c000000040000",
    "password_expiration=20260101000000Z",
    "krbPasswordExpiration: never",
    "ipahealthcheck.ipa.certs.IPACertmongerExpirationCheck",
    "Password expired for the Directory Manager",
    "https://freeipa.org/page/Troubleshooting/Directory_Server",
])
def test_ordinary_diagnostic_text_is_not_redacted(text):
    assert not [f for f in find_secrets(clean(text)) if f[0] != "password_prose"], find_secrets(text)


def test_secret_named_fields_are_removed_and_raw_output_dropped():
    s = _san()
    out = s.transform({"bind_password": "x", "api_token": ["a", "b"], "Cookie": {"k": "v"}, "keytab_kvno": 3,
                       "raw": "full stdout", "stderr": "e", "principal": "admin@EXAMPLE.TEST"})
    assert out["bind_password"] == out["api_token"] == out["Cookie"] == "[REMOVED]"
    assert out["keytab_kvno"] == 3 and "raw" not in out and "stderr" not in out
    assert out["principal"] == "admin@REALM-001"  # the built-in admin account keeps its meaning
    assert s.removed_fields == 3 and s.raw_fields_dropped == 2


# --- pseudonymization ----------------------------------------------------------------------------------------------
def test_relationships_survive_pseudonymization():
    agreement = r"cn=meToipa02.example.test,cn=replica,cn=dc\3Dexample\2Cdc\3Dtest,cn=mapping tree,cn=config"
    texts = ["Unable to communicate with replica ipa02.example.test", agreement, "ldap/ipa01.example.test@EXAMPLE.TEST",
             "ldap://ipa02.example.test:389", "dirsrv@EXAMPLE-TEST.service failed",
             "/etc/dirsrv/slapd-EXAMPLE-TEST/dse.ldif", "uid=admin,cn=users,cn=accounts,dc=example,dc=test",
             "_kerberos._udp.example.test SRV", "ipa-ca.example.test A record", "IPA01.EXAMPLE.TEST", "ipa01 is up"]
    s = _san(*texts)
    out = [s.text(t) for t in texts]
    assert out[0] == "Unable to communicate with replica HOST-002"
    assert out[1] == "cn=meToHOST-002,cn=replica,cn=SUFFIX-001,cn=mapping tree,cn=config"
    assert out[2] == "ldap/HOST-001@REALM-001"
    assert out[3] == "ldap://HOST-002:389"
    assert out[4] == "dirsrv@INSTANCE-001.service failed"
    assert out[5] == "/etc/dirsrv/slapd-INSTANCE-001/dse.ldif"
    assert out[6] == "uid=admin,cn=users,cn=accounts,SUFFIX-001"
    assert out[7] == "_kerberos._udp.DOMAIN-001 SRV"
    assert out[8] == "ipa-ca.DOMAIN-001 A record"
    assert out[9] == "HOST-001" and out[10] == "HOST-001 is up"


def test_similar_names_never_collide():
    texts = ["ipa1.example.test", "xipa1.example.test", "ipa1.example.test.other.com", "ipa1.example.testing.com"]
    s = _san(*texts, host="ipa1.example.test")
    out = [s.text(t) for t in texts]
    assert len(set(out)) == 4, out
    assert out[0] == "HOST-001"
    assert all("ipa1" not in o.lower() and "example.test" not in o.lower() for o in out)


def test_pseudonym_shaped_input_never_merges_with_an_assigned_pseudonym():
    s = _san("HOST-002 is a literal string in a message", "peer ipa02.example.test")
    assert s.text("peer ipa02.example.test") == "peer HOST-003"
    assert s.pseudonym_shaped_input == 1


def test_users_groups_services_ips_and_emails():
    texts = ["jsmith@EXAMPLE.TEST failed preauth", "uid=jsmith,cn=users,cn=accounts,dc=example,dc=test",
             "cn=ops-team,cn=groups,cn=accounts,dc=example,dc=test", "cn=web-servers,cn=hostgroups,cn=accounts",
             "payroll/app1.example.test@EXAMPLE.TEST", "HTTP/ipa01.example.test@EXAMPLE.TEST",
             "from 10.20.30.40 and 2001:db8::7 and 127.0.0.1", "mail to ops@corp.com", "/home/jsmith/.cache/x",
             "user jsmith logged in"]
    s = _san(*texts)
    out = [s.text(t) for t in texts]
    assert out[0] == "USER-001@REALM-001 failed preauth"
    assert out[1].startswith("uid=USER-001,")
    assert out[2].startswith("cn=GROUP-001,cn=groups")
    assert out[3].startswith("cn=HOSTGROUP-001,cn=hostgroups")
    assert out[4] == "SERVICE-001/HOST-002@REALM-001"
    assert out[5] == "HTTP/HOST-001@REALM-001"
    assert out[6] == "from IP-001 and IP-002 and 127.0.0.1"
    assert out[7] == "mail to EMAIL-001"
    assert out[8] == "/home/USER-001/.cache/x"
    assert out[9] == "user USER-001 logged in"


def test_constants_keep_their_technical_meaning():
    texts = ["dirsrv@EXAMPLE-TEST.service", "ipahealthcheck.dogtag.ca.DogtagCertsConfigCheck",
             "owner root group dirsrv", "https://access.redhat.com/solutions/6096751", "localhost:389",
             "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST", "java.lang.NullPointerException in com.netscape.cms.servlet"]
    s = _san(*texts)
    out = [s.text(t) for t in texts]
    assert out[1] == texts[1] and out[2] == texts[2] and out[3] == texts[3] and out[4] == texts[4]
    assert out[5] == "krbtgt/REALM-001@REALM-001" and out[6] == texts[6]
    assert "EMAIL" not in "".join(out)  # a unit name is not an address


def test_unknown_fqdn_in_another_domain_is_pseudonymized():
    s = _san("forwarder dns1.corp.internal unreachable", "trust with ad.acme.com")
    assert s.text("forwarder dns1.corp.internal unreachable") == "forwarder HOST-002 unreachable"
    assert "acme" not in s.text("trust with ad.acme.com")
    assert s.heuristic_hosts == 2


def test_pseudonyms_are_sequential_and_not_derived_from_the_value():
    a = _san("peer ipa02.example.test")
    b = _san("peer zz-secret-name.example.test")
    assert a.text("peer ipa02.example.test") == b.text("peer zz-secret-name.example.test") == "peer HOST-002"


def test_mapping_keys_are_transformed_too():
    s = _san("dirsrv@EXAMPLE-TEST.service")
    assert s.transform({"dirsrv@EXAMPLE-TEST.service": "inactive"}) == {"dirsrv@INSTANCE-001.service": "inactive"}


def test_structure_is_bounded():
    s = _san()
    rec = {"l": list(range(1000)), "d": {str(i): i for i in range(500)}, "n": [[[[[[[[[["deep"]]]]]]]]]]}
    out = s.transform({"records": list(range(1500)), "rec": rec})
    # a member's own record lists are capped (and reported) by build.LIMITS, never silently here
    assert len(out["records"]) == 1500
    assert len(out["rec"]["l"]) == 200 and len(out["rec"]["d"]) == 60 and s.structure_trimmed >= 3
    assert "OMITTED" in str(out["rec"]["n"])
