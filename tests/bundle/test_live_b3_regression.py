"""Live B3 (KDC stopped) regression: ipa-healthcheck's DNA check crashed with a traceback quoting api.env.host.

The host-name heuristic took `api.env.host` for a host (.host is a real TLD), in-domain discovery then registered its
short name `api`, and the leak self-test refused every bundle because the bundle's own generated text says "API".
"""

from __future__ import annotations

import json
import shutil

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.build import build
from ipa_diagnose.bundle.sanitize import Sanitizer

from tests.bundle.helpers import ROOT, all_text, diagnose_replay

TRACEBACK = ('Traceback (most recent call last):\n  File "/usr/lib/python3.14/site-packages/ipahealthcheck/ipa/dna.py", '
             'line 41, in check\n    (range_start, range_max) = agmt.get_DNA_range(api.env.host)\n    ^^^^^\n'
             "UnboundLocalError: cannot access local variable 'agmt' where it is not associated with a value")


def _san(*texts):
    s = Sanitizer()
    s.add_host("ipa01.lab.test", force=True)
    s.add_domain("lab.test", force=True)
    s.add_realm("LAB.TEST", force=True)
    for t in texts:
        s.discover(t)
    return s


def test_freeipa_api_env_attributes_are_code_not_hosts():
    s = _san(TRACEBACK)
    assert not [f for c, f in s.originals() if c == "HOST" and "api" in f]
    assert "api.env.host" in s.text(TRACEBACK, limit=2000)


def test_only_the_three_label_api_env_attribute_is_code():
    text = "peer api.env.zqacme.com unreachable"
    assert "zqacme" not in _san(text).text(text)


def test_a_host_named_api_does_not_make_the_word_api_an_identifier():
    s = _san("proxy to api.zqacme.io failed")
    assert ("HOST", "api") not in s.originals()
    assert "zqacme" not in s.text("proxy to api.zqacme.io failed")


def test_a_bundle_with_the_dna_traceback_is_written(tmp_path):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "kerberos" / "keytab-mismatch", d)
    hc = json.loads((d / "healthcheck.json").read_text(encoding="utf-8"))
    hc.append({"source": "ipahealthcheck.ipa.dna", "check": "IPADNARangeCheck", "result": "CRITICAL",
               "uuid": "dna1", "when": "20260101120000Z", "duration": "0.1",
               "kw": {"exception": TRACEBACK, "msg": "{exception}"}})
    (d / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-28T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)  # must not refuse
    assert "API, bearer and cloud tokens" in all_text(b.members)
