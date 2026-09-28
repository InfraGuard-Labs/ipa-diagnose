"""The CA journal collector (journal_pki) and its evidence in a support bundle.

FreeIPA runs the CA as the Dogtag instance unit pki-tomcatd@pki-tomcat.service. The collector used to ask for
`-u pki-tomcatd`, which journalctl reads as pki-tomcatd.service - a unit that does not exist - so no CA line was ever
collected. Once CA lines are collected, a Tomcat digester warning can echo a server.xml attribute value such as the
AJP connector secret; it must be redacted before it reaches a bundle, and the self-test must refuse it otherwise.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.build import build
from ipa_diagnose.evidence.collectors import journal_pki
from ipa_diagnose.evidence.collectors.registry import get as get_collector

from tests.bundle.helpers import ROOT, all_text, diagnose_replay

# a letters-only canary: the random-token rule alone would not catch it, only the digester rule does
AJP = "ZqCanaryAjpSecretOnlyLettersAbcdefgh"

LIVE_OUTPUT = "\n".join([
    "Sep 28 10:00:01 ipa01.lab.test server[2345]: 28-Sep-2026 10:00:01.123 WARNING [main] "
    "org.apache.tomcat.util.digester.SetPropertiesRule.begin Match [Server/Service/Connector] failed to set "
    f"property [requiredSecret] to [{AJP}]",
    "Sep 28 10:00:02 ipa01.lab.test server[2345]: INFO: Starting ProtocolHandler [\"https-jsse-nio-8443\"]",
    "Sep 28 10:00:05 ipa01.lab.test server[2345]: SEVERE: Unable to connect to LDAP server ipa01.lab.test:636",
    "Sep 28 10:00:07 ipa01.lab.test certmonger[812]: Server at https://ipa01.lab.test/ipa/xml failed request, "
    "will retry: 4301 (RPC failed at server.  Certificate operation cannot be completed: Unable to communicate "
    "with CMS (503)).",
    "Sep 28 10:00:09 ipa01.lab.test systemd[1]: pki-tomcatd@pki-tomcat.service: Failed with result 'exit-code'.",
])


def test_the_collector_asks_for_the_dogtag_instance_unit():
    cmd = journal_pki.JOURNALCTL_COMMAND
    units = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-u"]
    assert units == ["pki-tomcatd@pki-tomcat.service", "certmonger"]


def test_live_ca_lines_are_collected_and_labelled(monkeypatch):
    seen = {}

    def run(args, *a, **k):
        seen["args"] = args
        return subprocess.CompletedProcess(args, 0, stdout=LIVE_OUTPUT, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    items = get_collector("journal_pki").collect_live()
    assert "pki-tomcatd@pki-tomcat.service" in seen["args"]
    units = [(i.data["unit"], i.data["line"].split("]: ", 1)[0].rsplit(" ", 1)[-1]) for i in items]
    # the INFO line is not an issue line; every other line is kept, the CA's own lines as pki-tomcatd
    assert units == [("pki-tomcatd", "server[2345"), ("pki-tomcatd", "server[2345"), ("certmonger", "certmonger[812"),
                     ("pki-tomcatd", "systemd[1")]
    assert items[0].provenance.command.startswith("journalctl -u pki-tomcatd@pki-tomcat.service")


@pytest.mark.parametrize("line,value", [
    ("WARNING [main] org.apache.tomcat.util.digester.SetPropertiesRule.begin Match [Server/Service/Connector] "
     f"failed to set property [requiredSecret] to [{AJP}]", AJP),
    ("WARNING: [SetPropertiesRule]{Server/Service/Connector} Setting property 'secret' to 'ZqCanaryOldAjpAbc' did "
     "not find a matching property.", "ZqCanaryOldAjpAbc"),
    ("Match [Server/Service/Connector/SSLHostConfig/Certificate] failed to set property [certificateKeystorePassword]"
     " to [ZqCanaryKsPw]", "ZqCanaryKsPw"),
    ("Match [Server/Service/Connector] failed to set property [keystorePass] to [ZqCanaryKsPass]", "ZqCanaryKsPass"),
])
def test_a_digester_warning_does_not_carry_the_attribute_value_into_a_bundle(tmp_path, line, value):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "certificates" / "ambiguous", d)
    (d / "journal_pki.json").write_text(json.dumps([
        {"unit": "pki-tomcatd", "line": "ipa01.example.test server[2345]: " + line},
        {"unit": "pki-tomcatd", "line": "ipa01.example.test server[2345]: SEVERE: Unable to connect to LDAP server "
                                        "ipa01.example.test:636"},
    ]), encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-28T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    text = all_text(b.members)
    assert value not in text
    lines = [i["data"]["line"] for i in json.loads(b.members["evidence.json"])["items"] if i["kind"] == "pki_journal_line"]
    # still useful: which attribute Tomcat rejected, and the CA's LDAP error, with the host pseudonymized
    assert any("failed to set property" in x or "Setting property" in x for x in lines)
    assert any("Unable to connect to LDAP server HOST-" in x for x in lines)
    assert "ipa01" not in text
    assert json.loads(b.members["redaction-report.json"])["redacted_values"].get("tomcat_property_secret", 0) >= 1


def test_the_self_test_refuses_an_unredacted_digester_warning():
    raw = f"failed to set property [requiredSecret] to [{AJP}]"
    assert "credential pattern (tomcat_property_secret)" in selftest.scan_text(raw)


@pytest.mark.parametrize("line", [
    "Match [Server/Service/Connector] failed to set property [maxThreads] to [150]",
    "Match [Server/Service/Engine/Host] failed to set property [appBase] to [webapps]",
])
def test_a_non_secret_attribute_stays_readable(line):
    assert selftest.scan_text(line) == []
