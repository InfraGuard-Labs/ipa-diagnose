"""Regressions for the security/privacy review of access diagnosis (no blocker; one MAJOR, five MINOR)."""

from __future__ import annotations

import json
import shutil

from ipa_diagnose.cli import main
from tests.access.helpers import World
from tests.access.test_access import base, run, text
from tests.bundle.helpers import ROOT, members_of

OTHERS = ("carol_ceo", "dave_cfo", "secret-db.lab.test", "payroll", "finance_admins", "db_servers")


def test_rules_never_expose_other_members_in_any_output(tmp_path, capsys):
    """MAJOR M1: a rule naming this user also lists other users, groups, hosts and services."""

    w = (base().user("carol_ceo").user("dave_cfo").host("secret-db.lab.test").service("payroll")
         .rule("r_mixed", users=["john", "carol_ceo", "dave_cfo"], groups=["finance_admins"],
               hosts=["secret-db.lab.test"], hostgroups=["db_servers"], services=["sshd", "payroll"]))
    code, doc = run(tmp_path, capsys, w)
    assert code == 1  # the rule does not cover app03
    blob = json.dumps(doc)
    for name in OTHERS:
        assert name not in blob, name
    code, out = text(tmp_path, capsys, w, details=True)
    for name in OTHERS:
        assert name not in out, name


def test_error_rule_names_are_counted_not_listed_unless_they_name_the_user(tmp_path, capsys):
    w = base().rule("mine", users=["john"], hosts=["x.lab.test"], services=["sshd"])
    ans = w.hbactest("john", "app03.lab.test", "sshd")
    ans["error"] = ["someone_elses_rule", "mine"]
    w.hbactest_override = ans
    code, doc = run(tmp_path, capsys, w)
    assert code == 3
    assert "someone_elses_rule" not in json.dumps(doc)
    assert doc["authoritative_evaluation"]["error_rule_count"] == 2
    assert doc["authoritative_evaluation"]["error_rules_naming_this_user"] == ["mine"]


def test_deeply_nested_replay_is_unknown_not_an_internal_error(tmp_path, capsys):
    """MINOR 1."""

    d = tmp_path / "deep"
    d.mkdir()
    (d / "access_api.json").write_text("[" * 100000, encoding="utf-8")
    code = main(["access", "john", "app03.lab.test", "sshd", "--replay", str(d), "--json"])
    assert code == 3


def test_emoji_shortcodes_in_names_are_printed_literally(tmp_path, capsys):
    """MINOR 2."""

    w = base().rule("ok :warning: :white_check_mark:", users=["john"], hostcat=True, servicecat=True)
    code, out = text(tmp_path, capsys, w)
    assert ":warning:" in out and "⚠" not in out and "✅" not in out


def test_side_explanations_and_group_lists_are_bounded(tmp_path, capsys):
    """MINOR 3: a user in thousands of groups, a rule listing all of them."""

    groups = [f"team{i}" for i in range(3000)]
    w = base().user("john", groups).rule("r_many", groups=groups, hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0
    side = doc["matched_rules"][0]["sides"]["user"]
    assert len(side) == 21 and side[-1]["how"] == "more" and side[-1]["count"] == 2980
    assert len(doc["objects"]["user"]["direct_groups"]) == 200 and doc["objects"]["user"]["group_count"] == 3000
    assert len(json.dumps(doc)) < 2_000_000


def test_curl_never_reads_curlrc_and_is_https_only(monkeypatch, tmp_path):
    """MINOR 4: the argv, without running curl."""

    import subprocess

    from ipa_diagnose.access import api as api_mod

    seen = {}

    class P:
        returncode, stdout, stderr = 0, b'{"result": {"result": {}}, "error": null}\n200', b""

    def fake_run(argv, **kw):
        seen["argv"], seen["input"] = argv, kw.get("input")
        return P()

    live = api_mod.LiveApi.__new__(api_mod.LiveApi)
    api_mod.Api.__init__(live, api_mod.ApiContext(mode="LIVE", server="ipa01.lab.test"))
    live._curl, live._ca = "/usr/bin/curl", "/etc/ipa/ca.crt"
    monkeypatch.setattr(subprocess, "run", fake_run)
    live.call("user_show", ["john;id"], {"all": True})
    argv = seen["argv"]
    assert argv[1] == "-q" and "--proto" in argv and argv[argv.index("--proto") + 1] == "=https"
    assert "--max-filesize" in argv
    assert not any("john" in a for a in argv)  # targets travel only in the JSON body on stdin
    assert b'"john;id"' in seen["input"]


def test_bundle_accepts_targets_named_like_common_words(tmp_path, capsys):
    """MINOR 5: `bundle --access` refused 'backup'/'support' because the name matched the bundle's own README."""

    d = tmp_path / "fx"
    shutil.copytree(ROOT / "replication" / "peer-unreachable", d)
    w = (World().user("backup", ["ipausers"]).group("ipausers").host("support.example.test").service("sshd")
         .rule("allow_all", usercat=True, hostcat=True, servicecat=True))
    w.meta.update(domain="example.test", realm="EXAMPLE.TEST")
    w.write(d, "backup", "support.example.test", "sshd")
    out = tmp_path / "b.tar.gz"
    code = main(["bundle", "--replay", str(d), "--output", str(out), "--access", "backup", "support.example.test",
                 "sshd"])
    assert code == 0, capsys.readouterr().out
    acc = json.loads(members_of(out.read_bytes())["access.json"])
    assert acc["query"]["user"].startswith("USER-") and acc["query"]["host"].startswith("HOST-")


def test_nested_chain_reads_only_groups_on_the_path(tmp_path, capsys):
    """Live run 36500100173 (A-perf): a user in 150 flat groups plus a 12-deep chain made the upward search hit its
    40-read bound (45 API calls, explanation INCOMPLETE). The search now walks down from the rule's group."""

    chain = [f"deep{i}" for i in range(12)]
    w = base().user("john", [chain[0]] + [f"flat{i}" for i in range(150)])
    for a, b in zip(chain, chain[1:]):
        w.group(a, [b])
    w.group(chain[-1])
    for i in range(150):
        w.group(f"flat{i}")
    w.rule("r_deep", groups=[chain[-1]], hostcat=True, servicecat=True)
    code, doc = run(tmp_path, capsys, w)
    assert code == 0 and doc["explanation_status"] == "COMPLETE"
    side = doc["matched_rules"][0]["sides"]["user"][0]
    assert side["chain"] == ["john"] + chain
    group_reads = [c for c in doc["evidence"]["checks"] if c["call"].startswith("group_show")]
    assert len(group_reads) <= 12 and not any("flat" in c["call"] for c in group_reads)
