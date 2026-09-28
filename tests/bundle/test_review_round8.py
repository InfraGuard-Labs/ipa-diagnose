"""Reproductions from the eighth fresh privacy review of the support bundle."""

from __future__ import annotations

import base64
import os
import secrets

import pytest

from ipa_diagnose.bundle.sanitize import Sanitizer


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


@pytest.mark.parametrize("token", [
    "/ZqCanary1xXDWxlWmb1lZIAbcuxXb7A1tiLvWOgYE/aI89yI=",
    "zq_live_51HZqCanary2abcdef0123456789abcdef0123456789",
    "ya29.a0ARrdaMZqCanary3abcdefghijklmnopqrstuvwxyz0123456789",
    "Wxy8Q~ZqCanary4abcdefghijklmnopqrstuvwxyz0123456789ABCD",
    "IEcpS8dds83b-nk-Vw-V4SBpK2SgfQ6p7j_FENOPPTA",
])
def test_long_random_tokens_of_every_shape_are_redacted(token):
    out = _san().text(f"got {token} from server")
    assert token not in out and "[REDACTED:high_entropy_token]" in out


def test_random_base64_secrets_are_redacted_almost_always():
    """Statistical detection: a sample of random 32-byte secrets in both base64 alphabets."""

    s = _san()
    escaped = 0
    for _ in range(2000):
        for tok in (base64.b64encode(os.urandom(32)).decode(), secrets.token_urlsafe(32)):
            if tok in s.text(f"got {tok} from server"):
                escaped += 1
    assert escaped <= 2, escaped  # documented: a small fraction of letters-only tokens can pass


@pytest.mark.parametrize("text", ["ipahealthcheck.ipa.certs.IPACertmongerExpirationCheck",
                                  "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg too permissive",
                                  "_var_log_dirsrv_slapd-INSTANCE-001_access_mode"])
def test_identifiers_and_paths_are_not_mistaken_for_tokens(text):
    assert "REDACTED" not in _san().text(text)


@pytest.mark.parametrize("text,leaked", [
    ("CA agreement cloneAgreement1-zqpeer03.zqother.lan-pki-tomcat also failing", "zqpeer03"),
    ("zqpeer06.zqother.lan_389 down", "zqpeer06"),
    ("zqpeer03.zqother.lan-cert.pem missing", "zqpeer03"),
    ("adminpw=ZqCanary1", "ZqCanary1"),
    ("ADMINPW: ZqCanary1", "ZqCanary1"),
    ("printf '%s\\n' ZqCanary1 | kinit admin", "ZqCanary1"),
    ("ipa passwd alice ZqCanary1", "ZqCanary1"),
    ("api_key ZqCanary1abcdef", "ZqCanary1abcdef"),
    ("access_token ZqCanary1abcdef", "ZqCanary1abcdef"),
    ("X-Api-Key ZqCanary1abcdef", "ZqCanary1abcdef"),
    ("Bearer: ZqCanary1abcdefgh", "ZqCanary1abcdefgh"),
    ("pki -c ZqCanary1 -n caadmin ca-user-find", "ZqCanary1"),
    ("pass phrase is ZqCanary1", "ZqCanary1"),
    ("userPassword: {SSHA512}ZqCanary1abcdefghijklmnopqrstuvwx", "ZqCanary1"),
    ("hash {SSHA512}ZqCanary1abcdefghijklmnopqrstuvwx stored", "ZqCanary1"),
])
def test_round_eight_shapes(text, leaked):
    out = _san(text).text(text)
    assert leaked.lower() not in out.lower(), out


def test_master_agreement_names_keep_the_peer_relationship():
    texts = ["masterAgreement1-ipa02.example.test-pki-tomcat failing", "peer ipa02.example.test"]
    s = _san(*texts)
    assert s.text(texts[0]) == "masterAgreement1-HOST-002-pki-tomcat failing"
    assert s.text(texts[1]) == "peer HOST-002"
