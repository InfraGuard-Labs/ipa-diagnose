#!/usr/bin/env python3
"""Live access-diagnosis lab (Slice 3), run on the CI host against a throwaway FreeIPA container `ipa-s`.

    python3 scripts/lab_access.py setup          # seed a known HBAC policy (the lab plays the administrator)
    python3 scripts/lab_access.py run            # every scenario: independent hbactest, then ipa-diagnose blind
    python3 scripts/lab_access.py summary        # fail when a scenario failed OR has no result row

For every scenario the EXPECTED answer comes from the policy this script created, and is independently confirmed by
FreeIPA's own `ipa hbactest` run directly (not through ipa-diagnose). ipa-diagnose then answers blind, and the row
records both, plus whether the answer was a false allow, a false deny or a wrong explanation. Only fake lab data is
used. ipa-diagnose itself never changes anything; only this script does, on the throwaway server.

Rows: out/truth/access-results.jsonl. Compact rows are also printed as GitHub annotations (public check-run data).
"""

from __future__ import annotations

import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

C = "ipa-s"
TOOL = "/root/.local/bin/ipa-diagnose"
PW = os.environ.get("IPA_PASSWORD", "")
USER_PW = "LabUserPass1!"
OUT = pathlib.Path("out")
ROWS = OUT / "truth" / "access-results.jsonl"
ADMIN_CC = "FILE:/root/admin.ccache"
DOMAIN = "lab.test"
APP01, APP02 = f"app01.{DOMAIN}", f"app02.{DOMAIN}"

REQUIRED = [
    "A01-direct-user-allow", "A02-group-hostgroup-allow", "A03-nested-group-allow", "A04-nested-hostgroup-allow",
    "A05-servicegroup-allow", "A06-no-rule-deny", "A07-only-disabled-rule-deny", "A08-disabled-user",
    "A09-missing-user", "A10-missing-host", "A11-undefined-service", "A12-no-ticket", "A13-non-admin-caller",
    "A14-allow-all-missing-user", "A15-short-host-and-case", "A16-evaluator-unreachable", "A17-trusted-form",
    "A18-hostile-rule-name", "A19-group-cycle", "A20-disabled-rule-plus-allowing-rule", "A21-bundle-access",
    "A22-expired-principal",
]


def dx(cmd: str, cc: str = ADMIN_CC, user: str = "root", timeout: int = 180, stdin: str = None):
    env = f"KRB5CCNAME={cc} " if cc else ""
    argv = ["docker", "exec", "-i", "-u", user, C, "bash", "-c", env + cmd]
    start = time.monotonic()
    p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr, round(time.monotonic() - start, 3)


def ipa(cmd: str, check: bool = False) -> str:
    rc, out, err, _ = dx("ipa " + cmd)
    line = f"$ ipa {cmd}\n{out}{err}"
    with open(OUT / "access-setup.log", "a", encoding="utf-8") as f:
        f.write(line + f"[rc={rc}]\n")
    if check and rc != 0:
        raise SystemExit(f"setup failed: ipa {cmd}: {err.strip()[:300]}")
    return out + err


def kinit_admin() -> None:
    rc, _, err, _ = dx("kinit admin >/dev/null", stdin=PW + "\n")
    if rc != 0:
        raise SystemExit(f"kinit admin failed: {err[:200]}")


def setup() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "truth").mkdir(exist_ok=True)
    kinit_admin()
    ipa("hbacrule-disable allow_all", check=True)
    for u in ("alice", "bob", "carol", "dave", "erin", "frank", "gina", "henry", "ivan", "hostile", "judy",
              "cyc", "perf"):
        ipa(f"user-add {u} --first={u} --last=Lab")
    # alice gets a password (first login changes it) so she can be a non-admin caller in A13
    dx("ipa passwd alice >/dev/null", stdin=f"{USER_PW}\n{USER_PW}\n")
    dx("kinit alice >/dev/null", cc="FILE:/root/alice.ccache", stdin=f"{USER_PW}\n{USER_PW}x\n{USER_PW}x\n")
    for g in ("ops", "backend", "devs", "perfdeep0"):
        ipa(f"group-add {g}")
    ipa("group-add-member ops --users=bob", check=True)
    ipa("group-add-member backend --users=carol", check=True)
    ipa("group-add-member devs --groups=backend", check=True)
    for h in (APP01, APP02):
        ipa(f"host-add {h} --force", check=True)
    for hg in ("web", "prod"):
        ipa(f"hostgroup-add {hg}")
    ipa(f"hostgroup-add-member web --hosts={APP02}", check=True)
    ipa("hostgroup-add-member prod --hostgroups=web", check=True)
    rules = [
        ("r_direct", "--users=alice", f"--hosts={APP01}", "--hbacsvcs=sshd"),
        ("r_group", "--groups=ops", "--hostgroups=web", "--hbacsvcs=sshd"),
        ("r_nested", "--groups=devs", f"--hosts={APP01}", "--hbacsvcs=sshd"),
        ("r_hg_nested", "--users=henry", "--hostgroups=prod", "--hbacsvcs=sshd"),
        ("r_svcgroup", "--users=gina", f"--hosts={APP01}", "--hbacsvcgroups=Sudo"),
        ("r_frank_off", "--users=frank", f"--hosts={APP01}", "--hbacsvcs=sshd"),
        ("r_erin", "--users=erin", f"--hosts={APP01}", "--hbacsvcs=sshd"),
        ("r_ivan_off", "--users=ivan", f"--hosts={APP01}", "--hbacsvcs=sshd"),
        ("r_ivan_on", "--users=ivan", f"--hosts={APP01}", "--hbacsvcs=sshd"),
        ("r_judy", "--users=judy", f"--hosts={APP01}", "--hbacsvcs=sshd"),
    ]
    for name, u, h, s in rules:
        ipa(f"hbacrule-add {name}", check=True)
        ipa(f"hbacrule-add-user {name} {u}", check=True)
        ipa(f"hbacrule-add-host {name} {h}", check=True)
        ipa(f"hbacrule-add-service {name} {s}", check=True)
    ipa("hbacrule-disable r_frank_off", check=True)
    ipa("hbacrule-disable r_ivan_off", check=True)
    ipa("user-disable erin", check=True)
    ipa("user-mod judy --principal-expiration=20200101000000Z", check=True)
    # a hostile rule name (bidi override + escape-like text); FreeIPA may refuse it - that is recorded too
    out = ipa("hbacrule-add " + shlex.quote("zz‮evil\x1b[31m rule"))
    ok = "Added HBAC rule" in out
    if ok:
        ipa("hbacrule-add-user " + shlex.quote("zz‮evil\x1b[31m rule") + " --users=hostile")
        ipa("hbacrule-mod " + shlex.quote("zz‮evil\x1b[31m rule") + " --hostcat=all --servicecat=all")
    (OUT / "access-hostile-rule.txt").write_text("accepted" if ok else "refused by FreeIPA", encoding="utf-8")
    # a membership cycle attempt: FreeIPA may refuse it; recorded
    ipa("group-add cyc1")
    ipa("group-add cyc2")
    ipa("group-add-member cyc1 --users=cyc")
    ipa("group-add-member cyc2 --groups=cyc1")
    cyc = ipa("group-add-member cyc1 --groups=cyc2")
    (OUT / "access-cycle.txt").write_text(("accepted: " if "Number of members added 1" in cyc else "refused: ")
                                           + " ".join(cyc.split())[:300], encoding="utf-8")
    ipa("hbacrule-add r_cycle --hostcat=all --servicecat=all")
    ipa("hbacrule-add-user r_cycle --groups=cyc2")
    # performance: perf is in 150 flat groups and a 12-deep chain; the rule names the top of the chain
    for i in range(1, 12):
        ipa(f"group-add perfdeep{i}")
        ipa(f"group-add-member perfdeep{i} --groups=perfdeep{i - 1}")
    ipa("group-add-member perfdeep0 --users=perf")
    dx("for i in $(seq 1 150); do ipa group-add perfflat$i >/dev/null 2>&1; ipa group-add-member perfflat$i "
       "--users=perf >/dev/null 2>&1; done", timeout=1800)
    ipa("hbacrule-add r_perf --hostcat=all --servicecat=all")
    ipa("hbacrule-add-user r_perf --groups=perfdeep11")
    print("setup done")


# ---------------------------------------------------------------- scenarios


def hbactest(user: str, host: str, svc: str, cc: str = ADMIN_CC):
    rc, out, err, _ = dx(f"ipa hbactest --user={shlex.quote(user)} --host={shlex.quote(host)} "
                         f"--service={shlex.quote(svc)}", cc=cc)
    granted = None
    if "Access granted: True" in out:
        granted = True
    elif "Access granted: False" in out:
        granted = False
    matched = []
    section = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Matched rules:"):
            section, rest = "m", s.split(":", 1)[1].strip()
            if rest:
                matched.append(rest)
        elif s.startswith(("Not matched rules:", "Non-existent", "Access granted")) or s.startswith("-"):
            section = None
        elif section == "m" and s:
            matched.append(s)
    return {"granted": granted, "matched": matched, "rc": rc, "error": err.strip()[:200] or None}


def access(user: str, host: str, svc: str, cc: str = ADMIN_CC, extra: str = ""):
    rc, out, err, secs = dx(f"{TOOL} access {shlex.quote(user)} {shlex.quote(host)} {shlex.quote(svc)} --json "
                            f"{extra}", cc=cc)
    try:
        doc = json.loads(out)
    except ValueError:
        doc = None
    rc2, text, _, _ = dx(f"{TOOL} access {shlex.quote(user)} {shlex.quote(host)} {shlex.quote(svc)} --details",
                         cc=cc)
    return rc, doc, err.strip()[:300], secs, text


def _find(doc, code):
    return code in {f["code"] for f in (doc or {}).get("diagnosis", {}).get("findings", [])}


def row(sid: str, query, expected: dict, independent, rc, doc, err, secs, text, checks: dict) -> dict:
    obs = {"exit": rc}
    if doc:
        obs.update(authentication=doc["authentication"]["state"], authorization=doc["authorization"]["state"],
                   runtime=doc["runtime_access"]["state"], matched=doc["authoritative_evaluation"]["matched_rules"],
                   explanation=doc["explanation_status"], answer=doc["answer"],
                   findings=[f["code"] for f in doc["diagnosis"]["findings"]],
                   resolution=doc["resolution"]["status"], api_calls=doc["completeness"]["api_calls"])
    problems = []
    for k, v in expected.items():
        if obs.get(k) != v:
            problems.append(f"{k}: expected {v!r}, got {obs.get(k)!r}")
    for name, ok in checks.items():
        if not ok:
            problems.append(f"check failed: {name}")
    authz = obs.get("authorization")
    ind = independent.get("granted") if independent else None
    false_allow = authz == "PASS" and ind is not True
    false_deny = authz == "FAIL" and ind is not False
    if false_allow:
        problems.append("FALSE ALLOW")
    if false_deny:
        problems.append("FALSE DENY")
    for bad in ("\x1b", "‮", "​"):
        if bad in (text or "") or (doc and bad in json.dumps(doc, ensure_ascii=False)):
            problems.append("unsanitized control/bidi character in output")
    if doc and not text:
        problems.append("text output missing")
    r = {"scenario": sid, "query": query, "expected": expected, "independent_hbactest": independent,
         "observed": obs, "stderr": err or None, "seconds": secs, "false_allow": false_allow,
         "false_deny": false_deny, "result": "PASS" if not problems else "FAIL", "problems": problems}
    with open(ROWS, "a", encoding="utf-8") as f:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
    (OUT / f"access-{sid}.txt").write_text(text or "", encoding="utf-8")
    if doc:
        (OUT / f"access-{sid}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{r['result']:4}  {sid}  {'; '.join(problems)}")
    return r


def side_how(doc, rule, side):
    for m in (doc or {}).get("matched_rules", []):
        if m["rule"] == rule:
            return [(s["how"], s["via"], s["chain"]) for s in m["sides"][side]]
    return None


def scenario(sid, user, host, svc, expected, checks=lambda doc, text: {}, cc=ADMIN_CC, ind_user=None,
             ind_host=None, independent=True):
    ind = hbactest(ind_user or user, ind_host or host, svc) if independent else None
    rc, doc, err, secs, text = access(user, host, svc, cc=cc)
    return row(sid, [user, host, svc], expected, ind, rc, doc, err, secs, text, checks(doc, text))


def run() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "truth").mkdir(exist_ok=True)
    kinit_admin()
    dx(f"{TOOL} --version > /dev/null")
    PASS, FAIL, UNK, NV = "PASS", "FAIL", "UNKNOWN", "NOT_VERIFIED"
    no_grant = lambda doc: not any(w in json.dumps(doc or {}) for w in (  # noqa: E731
        "hbacrule-add", "hbacrule-enable", "group-add-member", "hostgroup-add-member", "user-enable", "hbacrule-mod"))

    scenario("A01-direct-user-allow", "alice", APP01, "sshd",
             {"exit": 0, "authentication": NV, "authorization": PASS, "runtime": NV, "explanation": "COMPLETE"},
             lambda d, t: {"matched r_direct": "r_direct" in (d or {}).get("authoritative_evaluation", {}).get(
                 "matched_rules", []), "user side direct": (side_how(d, "r_direct", "user") or [("",)])[0][0] == "direct"})
    scenario("A02-group-hostgroup-allow", "bob", APP02, "sshd",
             {"exit": 0, "authorization": PASS, "explanation": "COMPLETE"},
             lambda d, t: {"via ops": (side_how(d, "r_group", "user") or [("", "")])[0][:2] == ("group", "ops"),
                           "via web": (side_how(d, "r_group", "host") or [("", "")])[0][:2] == ("group", "web")})
    scenario("A03-nested-group-allow", "carol", APP01, "sshd",
             {"exit": 0, "authorization": PASS, "explanation": "COMPLETE"},
             lambda d, t: {"chain carol>backend>devs": (side_how(d, "r_nested", "user") or [("", "", [])])[0]
                           == ("nested_group", "devs", ["carol", "backend", "devs"])})
    scenario("A04-nested-hostgroup-allow", "henry", APP02, "sshd",
             {"exit": 0, "authorization": PASS, "explanation": "COMPLETE"},
             lambda d, t: {"chain app02>web>prod": (side_how(d, "r_hg_nested", "host") or [("", "", [])])[0]
                           == ("nested_group", "prod", [APP02, "web", "prod"])})
    scenario("A05-servicegroup-allow", "gina", APP01, "sudo",
             {"exit": 0, "authorization": PASS, "explanation": "COMPLETE"},
             lambda d, t: {"via Sudo service group": (side_how(d, "r_svcgroup", "service") or [("", "")])[0][:2]
                           == ("group", "Sudo")})
    scenario("A06-no-rule-deny", "dave", APP01, "sshd",
             {"exit": 1, "authentication": NV, "authorization": FAIL, "resolution": "NONE"},
             lambda d, t: {"no grant suggestion": no_grant(d),
                           "not called broken": not any(w in json.dumps(d or {}).lower()
                                                        for w in ("misconfig", "broken"))})
    scenario("A07-only-disabled-rule-deny", "frank", APP01, "sshd",
             {"exit": 1, "authorization": FAIL, "resolution": "NONE"},
             lambda d, t: {"names disabled rule": any("r_frank_off: the rule is disabled" in w
                                                      for w in (d or {}).get("diagnosis", {}).get("why", [])),
                           "no enable suggestion": no_grant(d)})
    scenario("A08-disabled-user", "erin", APP01, "sshd",
             {"exit": 1, "authentication": FAIL, "authorization": PASS},
             lambda d, t: {"USER_DISABLED": _find(d, "USER_DISABLED"), "no user-enable": no_grant(d)})
    scenario("A09-missing-user", "nosuchuser", APP01, "sshd",
             {"exit": 1, "authentication": FAIL, "authorization": UNK}, independent=False)
    scenario("A10-missing-host", "alice", f"nohost.{DOMAIN}", "sshd",
             {"exit": 3, "authorization": UNK}, lambda d, t: {"HOST_NOT_FOUND": _find(d, "HOST_NOT_FOUND")},
             independent=False)
    scenario("A11-undefined-service", "alice", APP01, "nosuchsvc",
             {"exit": 1, "authorization": FAIL},
             lambda d, t: {"SERVICE_NOT_DEFINED": _find(d, "SERVICE_NOT_DEFINED")})
    scenario("A12-no-ticket", "alice", APP01, "sshd", {"exit": 3, "authorization": UNK, "authentication": UNK},
             cc="FILE:/root/none.ccache", independent=False)
    scenario("A13-non-admin-caller", "bob", APP02, "sshd", {"authorization": PASS},
             cc="FILE:/root/alice.ccache")
    # A14: re-enable allow_all; FreeIPA's own hbactest grants a user that does not exist - ipa-diagnose must not
    ipa("hbacrule-enable allow_all")
    ind = hbactest("nosuchuser", APP01, "sshd")
    rc, doc, err, secs, text = access("nosuchuser", APP01, "sshd")
    row("A14-allow-all-missing-user", ["nosuchuser", APP01, "sshd"],
        {"exit": 1, "authentication": FAIL, "authorization": UNK}, None, rc, doc, err, secs, text,
        {"raw hbactest grants a missing user (recorded fact)": ind.get("granted") is True})
    with open(OUT / "access-A14-raw-hbactest.json", "w", encoding="utf-8") as f:
        json.dump(ind, f)
    ipa("hbacrule-disable allow_all")
    scenario("A15-short-host-and-case", "ALICE", "APP01", "sshd", {"exit": 0, "authorization": PASS},
             lambda d, t: {"canonical request": (d or {}).get("authoritative_evaluation", {}).get("request")
                           == {"user": "alice", "targethost": APP01, "service": "sshd"}},
             ind_user="alice", ind_host=APP01)
    dx("systemctl stop httpd.service")
    scenario("A16-evaluator-unreachable", "alice", APP01, "sshd", {"exit": 3, "authorization": UNK},
             independent=False)
    dx("systemctl start httpd.service; sleep 5")
    scenario("A17-trusted-form", "someone@ad.example.com", APP01, "sshd", {"exit": 3, "authorization": UNK},
             lambda d, t: {"TRUSTED_IDENTITY_UNSUPPORTED": _find(d, "TRUSTED_IDENTITY_UNSUPPORTED")},
             independent=False)
    hostile_ok = (OUT / "access-hostile-rule.txt").read_text() == "accepted"
    scenario("A18-hostile-rule-name", "hostile", APP01, "sshd",
             {"exit": 0 if hostile_ok else 1, "authorization": PASS if hostile_ok else FAIL})
    scenario("A19-group-cycle", "cyc", APP01, "sshd", {"authorization": PASS},
             lambda d, t: {"terminates with an explanation": (d or {}).get("explanation_status") in (
                 "COMPLETE", "INCOMPLETE")})
    scenario("A20-disabled-rule-plus-allowing-rule", "ivan", APP01, "sshd", {"exit": 0, "authorization": PASS},
             lambda d, t: {"only the enabled rule explains": (d or {}).get("authoritative_evaluation", {}).get(
                 "matched_rules") == ["r_ivan_on"] and "r_ivan_off" not in json.dumps(
                 (d or {}).get("matched_rules", []))})
    scenario("A22-expired-principal", "judy", APP01, "sshd", {"exit": 1, "authentication": FAIL,
                                                             "authorization": PASS},
             lambda d, t: {"USER_PRINCIPAL_EXPIRED": _find(d, "USER_PRINCIPAL_EXPIRED")})
    bundle()
    timing()


def bundle() -> None:
    rc, out, err, secs = dx(f"rm -f /root/acc.tar.gz; {TOOL} bundle --access alice {APP01} sshd --output "
                            "/root/acc.tar.gz --json")
    vrc, vout, _, _ = dx(f"{TOOL} bundle validate /root/acc.tar.gz --json")
    _, acc, _, _ = dx("tar -xzOf /root/acc.tar.gz ipa-diagnose-bundle/access.json")
    _, allm, _, _ = dx("tar -xzOf /root/acc.tar.gz")
    leaked = [n for n in ("alice", "app01", "lab.test", "LAB.TEST", "r_direct") if n.lower() in allm.lower()]
    try:
        a = json.loads(acc)
    except ValueError:
        a = {}
    problems = []
    if rc != 0:
        problems.append(f"bundle exit {rc}: {err.strip()[:200]}")
    if vrc != 0:
        problems.append("bundle validate failed")
    if leaked:
        problems.append(f"identifiers in bundle: {leaked}")
    if a.get("hbac_policy_decision", {}).get("state") != "PASS":
        problems.append(f"access findings {[f.get('code') for f in a.get('findings', [])]} checks "
                        f"{[(c.get('call'), c.get('outcome')) for c in a.get('checks', [])]}")
        problems.append("access.json decision is not PASS")
    r = {"scenario": "A21-bundle-access", "query": ["alice", APP01, "sshd"], "expected": {"valid": True},
         "observed": {"exit": rc, "validate_exit": vrc, "decision": a.get("hbac_policy_decision"),
                      "leaked": leaked}, "seconds": secs, "false_allow": False, "false_deny": False,
         "result": "PASS" if not problems else "FAIL", "problems": problems}
    with open(ROWS, "a", encoding="utf-8") as f:
        f.write(json.dumps(r) + "\n")
    (OUT / "access-A21-access.json").write_text(acc, encoding="utf-8")
    print(f"{r['result']:4}  A21-bundle-access  {'; '.join(problems)}")


def timing() -> None:
    lines = []
    for label, user in (("direct (alice)", "alice"), ("nested 12 deep + 150 groups (perf)", "perf"),
                        ("deny (dave)", "dave")):
        for n in range(1, 4):
            rc, doc, err, secs, _ = access(user, APP01, "sshd")
            calls = (doc or {}).get("completeness", {}).get("api_calls")
            lines.append(f"{label} run {n}: {secs} s, exit {rc}, {calls} API calls, "
                         f"explanation {(doc or {}).get('explanation_status')}")
    dx("systemctl stop httpd.service")
    rc, doc, err, secs, _ = access("alice", APP01, "sshd")
    lines.append(f"API unreachable: {secs} s, exit {rc}")
    dx("systemctl start httpd.service; sleep 5")
    (OUT / "access-timing.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


def shapes() -> None:
    """Which keys the real API answers carry (for the replay fixtures): key names and value types only."""

    kinit_admin()
    out = {}
    for method, args, opts in (("user_show", ["carol"], {"all": True}), ("host_show", [APP02], {}),
                               ("hbacsvc_show", ["sudo"], {}), ("hbacrule_show", ["r_nested"], {}),
                               ("group_show", ["backend"], {}), ("hostgroup_show", ["web"], {}),
                               ("hbactest", [], {"user": "carol", "targethost": APP01, "service": "sshd",
                                                 "nodetail": False})):
        body = json.dumps({"method": method, "params": [args, opts], "id": 0})
        rc, raw, err, _ = dx("curl -s --negotiate -u : --cacert /etc/ipa/ca.crt -H 'Content-Type: application/json' "
                             "-H 'Referer: https://ipa01.lab.test/ipa' --data-binary @- https://ipa01.lab.test/ipa/json",
                             stdin=body)
        try:
            doc = json.loads(raw)
            res = doc.get("result") or {}
            inner = res.get("result") if isinstance(res.get("result"), dict) else res
            out[method] = {"top": sorted(doc), "result_keys": sorted(res),
                           "entry": {k: type(v).__name__ + (f"[{type(v[0]).__name__}]" if isinstance(v, list) and v
                                                            else "") for k, v in sorted(inner.items())
                                     if not k.startswith(("krbextradata", "ipantsecurityidentifier"))},
                           "sample": {k: inner[k] for k in ("nsaccountlock", "ipaenabledflag", "value", "matched",
                                                            "has_keytab", "krbprincipalexpiration")
                                      if k in inner}}
        except ValueError:
            out[method] = {"error": raw[:200]}
    (OUT / "access-api-shapes.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    compact = json.dumps({m: {"entry_keys": sorted(v.get("entry", {})), "sample": v.get("sample"),
                              "error": v.get("error")} for m, v in out.items()}, separators=(",", ":"))
    for i in range(0, min(len(compact), 9 * 3500), 3500):
        print(f"::notice title=api shapes {i // 3500 + 1}::" + compact[i:i + 3500].replace("%", "%25"))


def summary() -> int:
    rows = [json.loads(line) for line in ROWS.read_text(encoding="utf-8").splitlines() if line.strip()] \
        if ROWS.exists() else []
    seen = {r["scenario"]: r for r in rows}
    bad = 0
    compact = []
    for sid in REQUIRED:
        r = seen.get(sid)
        if r is None:
            print(f"FAIL  {sid} (no result row)")
            bad += 1
            compact.append(f"{sid}=MISSING")
            continue
        o = r.get("observed", {})
        compact.append(f"{sid}={r['result']}(x{o.get('exit')},{str(o.get('authentication', ''))[:4]}/"
                       f"{str(o.get('authorization', o.get('decision', '')))[:4]},{o.get('explanation', '')}"
                       f"{',FA' if r.get('false_allow') else ''}{',FD' if r.get('false_deny') else ''}"
                       f"{';' + '|'.join(r['problems'])[:160] if r['problems'] else ''})")
        if r["result"] != "PASS":
            bad += 1
    # public annotations (at most 10 notices per step): pack rows
    for i in range(0, len(compact), 4):
        print("::notice title=access truth " + str(i // 4 + 1) + "::" + " ".join(compact[i:i + 4]).replace(
            "%", "%25").replace("\n", " "))
    facts = []
    for name, f in (("group cycle", "access-cycle.txt"), ("hostile rule name", "access-hostile-rule.txt")):
        p = OUT / f
        facts.append(f"{name}: {p.read_text(encoding='utf-8')[:200] if p.exists() else 'not recorded'}")
    raw14 = OUT / "access-A14-raw-hbactest.json"
    facts.append("A14 raw ipa hbactest for a missing user under allow_all: "
                 + (raw14.read_text(encoding="utf-8")[:200] if raw14.exists() else "not recorded"))
    print("::notice title=access lab facts::" + " | ".join(facts).replace("%", "%25").replace("\n", " "))
    print(f"{len(REQUIRED) - bad}/{len(REQUIRED)} scenarios PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "setup":
        setup()
    elif cmd == "run":
        run()
    elif cmd == "shapes":
        shapes()
    elif cmd == "summary":
        sys.exit(summary())
    else:
        sys.exit(__doc__)
