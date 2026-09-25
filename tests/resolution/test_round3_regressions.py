"""Regressions for the round-3 independent adversarial review of Slice 1 (each case was reproduced first)."""

from __future__ import annotations

import pytest

from ipa_diagnose.ai.prompt import sanitize_explanation
from ipa_diagnose.engine.model import Action, Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, RiskLevel
from ipa_diagnose.evidence.model import EvidenceItem
from ipa_diagnose.resolution import checks as C
from ipa_diagnose.resolution import types as T
from ipa_diagnose.resolution.engine import NONE, OFFERED, WITHHELD

from tests.resolution.test_procedures import (
    CHRONY_OK, KEYTAB_SKEW, ROOT_OK, ok, perm, report_for, res_of, stat,
)

FP = "directory-server.ipa-file-permissions"


# --- blocker 1: a service account swaps one of its directories for a link into another component ---------------

def _fs(monkeypatch, links):
    """Fake filesystem: `links` maps a symlink path to its final real location."""

    def realpath(p):
        cur = ""
        for part in [x for x in p.split("/") if x]:
            cur = f"{cur}/{part}"
            if cur in links:
                cur = realpath(links[cur])
        return cur or "/"

    def islink(p):
        parent, _, base = p.rpartition("/")
        return f"{realpath(parent or '/').rstrip('/')}/{base}" in links

    monkeypatch.setattr(C.os.path, "realpath", realpath)
    monkeypatch.setattr(C.os.path, "islink", islink)


def test_swapped_alias_directory_into_directory_server_is_refused(monkeypatch):
    _fs(monkeypatch, {"/etc/pki/pki-tomcat/alias": "/etc/dirsrv/slapd-LAB-TEST"})
    assert C._layout_ok("/etc/pki/pki-tomcat/alias/cert9.db") is False


def test_standard_pki_layout_link_is_accepted(monkeypatch):
    _fs(monkeypatch, {"/var/lib/pki/pki-tomcat/conf": "/etc/pki/pki-tomcat"})
    assert C._layout_ok("/var/lib/pki/pki-tomcat/conf/ca/CS.cfg") is True


def test_known_link_name_pointing_somewhere_else_is_refused(monkeypatch):
    _fs(monkeypatch, {"/var/lib/pki/pki-tomcat/conf": "/etc/dirsrv/slapd-LAB-TEST"})
    assert C._layout_ok("/var/lib/pki/pki-tomcat/conf/cert9.db") is False


def test_link_inside_the_real_directory_is_refused(monkeypatch):
    # the PKI link is fine, but a directory inside its target was swapped
    _fs(monkeypatch, {"/var/lib/pki/pki-tomcat/conf": "/etc/pki/pki-tomcat", "/etc/pki/pki-tomcat/ca": "/etc/dirsrv/slapd-LAB-TEST"})
    assert C._layout_ok("/var/lib/pki/pki-tomcat/conf/ca/CS.cfg") is False


def test_container_data_mirror_and_pki_link_together_are_accepted(monkeypatch):
    # freeipa-container: /etc/pki -> /data/etc/pki, plus the PKI link
    _fs(monkeypatch, {"/etc/pki": "/data/etc/pki", "/var/lib/pki": "/data/var/lib/pki",
                      "/data/var/lib/pki/pki-tomcat/conf": "/etc/pki/pki-tomcat"})
    assert C._layout_ok("/var/lib/pki/pki-tomcat/conf/ca/CS.cfg") is True


def test_link_into_data_that_is_not_a_mirror_is_refused(monkeypatch):
    _fs(monkeypatch, {"/etc/pki/pki-tomcat/alias": "/data/etc/dirsrv/slapd-LAB-TEST"})
    assert C._layout_ok("/etc/pki/pki-tomcat/alias/cert9.db") is False


def test_every_known_layout_link_stays_inside_ipa_locations():
    for link, dest in T.IPA_LAYOUT_LINKS.items():
        assert T.validate("ipa_path", link + "/x") and T.validate("ipa_path", dest + "/x"), link


# --- blocker 2: two names for one file with different expectations --------------------------------------------

P1, P2 = "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg", "/etc/pki/pki-tomcat/ca/CS.cfg"


def test_two_paths_to_one_file_with_conflicting_owner_withhold_everything():
    entries = [perm(path=P1, kind="owner", expected="pkiuser", got="dirsrv", check="TomcatFileCheck"),
               perm(path=P2, kind="owner", expected="root", got="dirsrv", check="IPAFileCheck")]
    results = {**ROOT_OK, f"file.stat|path={P1}": stat(owner="dirsrv", real=P2), f"file.stat|path={P2}": stat(owner="dirsrv", real=P2),
               "account.user|name=pkiuser": ok({"exists": True}), "account.user|name=root": ok({"exists": True})}
    r = res_of(report_for(entries, results)[0], FP)
    assert r.status == WITHHELD and not r.steps and any("different values for the same file" in x for x in r.reasons)


def test_two_paths_to_one_file_with_conflicting_mode_withhold_everything():
    entries = [perm(path=P1, expected="0660", got="0666"), perm(path=P2, expected="0640", got="0666", check="IPAFileCheck")]
    results = {**ROOT_OK, f"file.stat|path={P1}": stat(mode="0666", real=P2), f"file.stat|path={P2}": stat(mode="0666", real=P2)}
    r = res_of(report_for(entries, results)[0], FP)
    assert r.status == WITHHELD and not r.steps


def test_two_paths_to_one_file_that_agree_give_one_step():
    entries = [perm(path=P1, expected="0660", got="0664"), perm(path=P2, expected="0660", got="0664", check="IPAFileCheck")]
    results = {**ROOT_OK, f"file.stat|path={P1}": stat(mode="0664", real=P2), f"file.stat|path={P2}": stat(mode="0664", real=P2)}
    r = res_of(report_for(entries, results)[0], FP)
    assert r.status == OFFERED and [s.argv for s in r.steps] == [["chmod", "o-r", P2]]
    assert len(r.rollback) == len(r.verify) == 1


# --- should-fix 1: secrets inside allowed locations are never re-owned ----------------------------------------

@pytest.mark.parametrize("path,expected,got", [
    ("/etc/ipa/dnssec/softhsm_pin", "apache", "ods"),
    ("/etc/ipa/dnssec/softhsm_pin_so", "apache", "ods"),
    ("/var/lib/ipa/dnssec/tokens/abc/generation", "apache", "ods"),
    ("/etc/ipa/.dns_ccache", "apache", "named"),
    ("/etc/dirsrv/slapd-LAB-TEST/dse.ldif", "apache", "dirsrv"),
    ("/var/lib/ipa/backup/ipa-full-2026-09-01/ipa-full.tar", "apache", "root"),
])
def test_secrets_are_never_re_owned(path, expected, got):
    entry = perm(path=path, kind="owner", expected=expected, got=got, check="IPAFileCheck")
    results = {**ROOT_OK, f"file.stat|path={path}": stat(owner=got, real=path), f"account.user|name={expected}": ok({"exists": True})}
    r = res_of(report_for([entry], results)[0], FP)
    assert r.status == WITHHELD and not r.steps


# --- should-fix 2: an AI explanation cannot bring back a state-changing command --------------------------------

def _diag(*actions):
    return Diagnosis(pack_id="kerberos", rule_id="clock-skew", status=DiagnosisStatus.DIAGNOSED, title="t", why="t",
                     confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="t"),
                     actions=[Action(description="a", risk=risk, command=cmd) for risk, cmd in actions])


@pytest.mark.parametrize("text", [
    "Fix it: `systemctl enable --now chronyd && chronyc makestep`.",
    "Just run systemctl stop krb5kdc and it will be fine.",
    "Run chmod 0777 /etc/ipa and chown nobody /var/lib/ipa/ra-agent.key to fix this.",
    "Step the clock with chronyc makestep now.",
    "Run `systemctl status chronyd; systemctl stop krb5kdc`.",
])
def test_ai_text_with_non_approved_commands_is_rejected(text):
    d = _diag((RiskLevel.SAFE, "systemctl status chronyd"), (RiskLevel.CAUTION, "systemctl enable --now chronyd"),
              (RiskLevel.CAUTION, "chronyc makestep"))
    assert sanitize_explanation(text, d) is None


def test_ai_text_quoting_a_safe_command_is_still_allowed():
    d = _diag((RiskLevel.SAFE, "systemctl status chronyd"))
    for text in ("Check `systemctl status chronyd` to see whether chronyd runs.",
                 "Running systemctl status chronyd shows whether it is active."):
        assert sanitize_explanation(text, d) == text
    # A bare program name followed by more words is treated as a command ("`chronyc` makestep" has the same
    # shape), so such an explanation falls back to the deterministic text.
    assert sanitize_explanation("The `systemctl` output will tell you.", d) is None


def test_ai_text_for_the_real_withheld_clock_diagnosis_is_rejected():
    journal = [EvidenceItem(item_id="kj", kind="krb5kdc_journal_line", summary="skew",
                            data={"matched_pattern": "clock_skew", "message": "CLOCK_SKEW"})]
    report, _ = report_for(KEYTAB_SKEW, CHRONY_OK, items=journal)
    d = next(x for x in report.diagnoses if x.resolution_key == "kerberos.clock-skew")
    assert report.resolutions[d.diagnosis_id].status == NONE
    assert sanitize_explanation("Fix it: `systemctl enable --now chronyd && chronyc makestep`.", d) is None


# --- nits ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/var/log/ipabogus/x", "/var/log/ipa_secret", "/var/log/secure", "/var/log/messages"])
def test_log_prefix_needs_the_directory_boundary(path):
    assert T.validate("ipa_path", path) is None


def test_ipa_log_directory_and_install_logs_are_ipa_paths():
    assert T.validate("ipa_path", "/var/log/ipa/healthcheck/healthcheck.log")
    assert T.validate("ipa_path", "/var/log/ipaserver-install.log")


@pytest.mark.parametrize("off", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_clock_offset_is_never_offered(off):
    from tests.resolution.test_procedures import DESYNC

    res = {**CHRONY_OK, "chrony.tracking|": ok({"offset_seconds": off, "offset_abs": abs(off), "direction": "ahead of",
                                                "leap_status": "Normal", "synchronized": True, "reference": "10.0.0.5"})}
    r = res_of(report_for(KEYTAB_SKEW, res, items=DESYNC)[0], "kerberos.clock-skew")
    assert r.status != OFFERED and not r.steps
