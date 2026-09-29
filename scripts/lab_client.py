#!/usr/bin/env python3
"""Live client-diagnosis lab (Slice 4), run on the CI host against two throwaway containers on a private network:
`ipa-s` (FreeIPA server, 172.30.0.10) and `ipa-c` (Fedora 43, enrolled client client1.lab.test, 172.30.0.20).

    python3 scripts/lab_client.py enroll     # enroll the client and PROVE the enrollment (row E00)
    python3 scripts/lab_client.py setup      # seed users and a known HBAC policy (the lab plays the administrator)
    python3 scripts/lab_client.py run        # every scenario: inject, confirm independently, run ipa-diagnose blind
    python3 scripts/lab_client.py summary    # fail when a scenario failed OR has no result row

Every fault is injected by this script on the disposable client and confirmed with an independent command
(systemctl, getent, kinit, ipa hbactest, ...) BEFORE ipa-diagnose runs; ipa-diagnose is never told what was broken.
Only fake lab identities and fake canaries are used. ipa-diagnose itself never changes anything; when a scenario
applies a fix, it is the exact argv ipa-diagnose printed, run by this script (as the administrator would).

Rows: out/truth/client-results.jsonl; compact rows are also printed as GitHub annotations (public check-run data).
"""

from __future__ import annotations

import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

S, C = "ipa-s", "ipa-c"
TOOL = "/opt/ipd/bin/ipa-diagnose"
PW = os.environ.get("IPA_PASSWORD", "")
USER_PW = "LabUserPass1!"
OUT = pathlib.Path("out")
ROWS = OUT / "truth" / "client-results.jsonl"
HOST, SERVER, DOMAIN, REALM = "client1.lab.test", "ipa01.lab.test", "lab.test", "LAB.TEST"
SERVER_IP = "172.30.0.10"
ADMIN_CC = "FILE:/root/admin.ccache"
CANARY = "CANARY-C14-7f3a9b2e"

REQUIRED = [
    "E00-enrollment-proven", "C00-healthy-baseline", "C00b-healthy-no-user", "C01-sssd-stopped",
    "C02-sssd-recovered-verify", "C03-dns-discovery-failure", "C04-kdc-unreachable", "C05-time-skew-simulated",
    "C06-host-keytab-missing", "C07-identity-lookup-failure", "C07b-user-not-in-ipa", "C08-sssd-offline",
    "C09-hbac-pass-sssd-stopped", "C09b-hbac-pass-host-denies", "C10-recovery-verify-resolved",
    "C11-cache-database-damaged", "C12-insufficient-privilege", "C13-multiple-failures", "C14-support-bundle",
]


def dx(container: str, cmd: str, user: str = "root", timeout: int = 300, stdin: str = None, cc: str = None):
    env = f"export KRB5CCNAME={cc}; " if cc else ""
    argv = ["docker", "exec", "-i", "-u", user, container, "bash", "-c", env + cmd]
    start = time.monotonic()
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, round(time.monotonic() - start, 3)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout", round(time.monotonic() - start, 3)


def log(name: str, text: str) -> None:
    OUT.mkdir(exist_ok=True)
    with open(OUT / f"{name}.log", "a", encoding="utf-8") as f:
        f.write(text + "\n")


def sh(container: str, cmd: str, check: bool = False, **kw) -> str:
    rc, out, err, _ = dx(container, cmd, **kw)
    log("lab-commands", f"[{container}] $ {cmd}\n{out}{err}[rc={rc}]")
    if check and rc != 0:
        raise SystemExit(f"lab step failed on {container}: {cmd}: {err.strip()[:300]}")
    return out + err


# ---------------------------------------------------------------- enrollment and policy


def enroll() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "truth").mkdir(exist_ok=True)
    sh(C, f"cp /etc/resolv.conf /root/resolv.conf.docker; printf 'search {DOMAIN}\\nnameserver {SERVER_IP}\\n' "
          "> /etc/resolv.conf", check=True)
    for _ in range(12):
        if "has SRV record" in sh(C, f"host -t SRV _ldap._tcp.{DOMAIN}"):
            break
        time.sleep(10)
    sh(C, f"ipa-client-install -U --domain {DOMAIN} --realm {REALM} --hostname {HOST} --principal admin "
          f"--password {shlex.quote(PW)} --no-ntp --force-join", check=True, timeout=900)
    sh(C, "systemctl enable --now sshd", check=False)
    sh(C, "cp /etc/resolv.conf /root/resolv.conf.ipa; cp /etc/sssd/sssd.conf /root/sssd.conf.enrolled", check=True)
    proof = {
        "keytab": sh(C, "klist -k /etc/krb5.keytab | grep -c host/" + HOST).strip(),
        "sssd_online": "Online" in sh(C, f"sssctl domain-status {DOMAIN} -o"),
        "getent_admin": sh(C, "getent passwd admin").startswith("admin:"),
        "host_entry": "Host name: " + HOST in sh(S, f"echo {shlex.quote(PW)} | kinit admin >/dev/null && "
                                                    f"ipa host-show {HOST}"),
    }
    ok = proof["keytab"] not in ("", "0") and proof["sssd_online"] and proof["getent_admin"] and proof["host_entry"]
    _write({"scenario": "E00-enrollment-proven", "result": "PASS" if ok else "FAIL", "proof": proof})
    if not ok:
        raise SystemExit(f"enrollment not proven: {proof}")
    print("enrolled and proven:", proof)


def setup() -> None:
    sh(S, f"echo {shlex.quote(PW)} | kinit admin >/dev/null", check=True)
    sh(S, "ipa hbacrule-disable allow_all", check=True)
    for u in ("alice", "bob", "ghost"):
        sh(S, f"ipa user-add {u} --first={u} --last=Lab")
    sh(S, "ipa passwd alice >/dev/null", stdin=f"{USER_PW}\n{USER_PW}\n")
    sh(S, "ipa hbacrule-add r_client", check=True)
    sh(S, "ipa hbacrule-add-user r_client --users=alice", check=True)
    sh(S, f"ipa hbacrule-add-host r_client --hosts={HOST}", check=True)
    sh(S, "ipa hbacrule-add-service r_client --hbacsvcs=sshd", check=True)
    # the client's operator ticket for access --runtime (the admin identity, in its own cache)
    sh(C, f"echo {shlex.quote(PW)} | kinit admin >/dev/null", cc=ADMIN_CC, check=True)
    sh(C, "sss_cache -E; systemctl restart sssd; sleep 3; getent passwd alice >/dev/null", check=False)
    print("setup done")


# ---------------------------------------------------------------- helpers


def client(args: str, user: str = "root", env: str = "", cc: str = None):
    cmd = f"{env} {TOOL} {args}".strip()
    if user != "root":
        cmd = f"cd /tmp && {cmd}"
    rc, out, err, secs = dx(C, cmd, user=user, cc=cc, timeout=400)
    try:
        doc = json.loads(out)
    except ValueError:
        doc = None
    log("tool-runs", f"$ {cmd}\n[rc={rc} {secs}s]\n{out[:20000]}\n{err[:2000]}")
    return rc, doc, err.strip()[:300], secs


def details(args: str, name: str, cc: str = None) -> str:
    rc, out, err, _ = dx(C, f"{TOOL} {args} --details", cc=cc, timeout=400)
    (OUT / "details").mkdir(exist_ok=True, parents=True)
    (OUT / "details" / f"{name}.txt").write_text(out + err, encoding="utf-8")
    return out


def diag(doc) -> dict:
    return {d["code"]: d["role"] for d in (doc or {}).get("diagnoses", [])}


def primary(doc):
    return next((d["code"] for d in (doc or {}).get("diagnoses", []) if d["role"] == "PRIMARY"), None)


def offered(doc) -> dict:
    return {k: v for k, v in ((doc or {}).get("resolution") or {}).items() if v["status"] == "OFFERED"}


def planner(doc) -> dict:
    ps = (doc or {}).get("planner_summary") or {}
    return {k: ps.get(k) for k in ("steps_in_plan", "steps_run", "steps_skipped", "wall_seconds", "stop_reason")}


FORBIDDEN_ALWAYS = ("rm ", "/var/lib/sss/db/*", "initctl", "ipa-client-install", "ipa-getkeytab", "kdestroy")


def _commands(doc) -> str:
    out = []
    for v in ((doc or {}).get("resolution") or {}).values():
        out += [s["command"] for s in v.get("steps", [])] + [r.get("command") or "" for r in v.get("rollback", [])]
    for d in (doc or {}).get("diagnoses", []):
        out += d.get("next_steps") or []
    return "\n".join(out)


def row(sid: str, expect: dict, rc: int, doc, secs: float, independent: dict, extra: dict = None) -> dict:
    problems = []
    extra = dict(extra or {}, debug=_debug(doc))
    got = diag(doc)
    prim = primary(doc)
    if doc is None:
        problems.append("no JSON answer")
    if "exit" in expect and rc != expect["exit"]:
        problems.append(f"exit {rc} != {expect['exit']}")
    if "status" in expect and (doc or {}).get("status") not in (expect["status"] if isinstance(expect["status"], tuple)
                                                                  else (expect["status"],)):
        problems.append(f"status {(doc or {}).get('status')} != {expect['status']}")
    if "primary" in expect and prim not in expect["primary"]:
        problems.append(f"primary {prim} not in {expect['primary']}")
    for code, role in (expect.get("roles") or {}).items():
        if got.get(code) != role:
            problems.append(f"{code} is {got.get(code)}, expected {role}")
    false_root = [c for c in got if got[c] in ("PRIMARY", "INDEPENDENT") and c in (expect.get("forbidden") or ())]
    if false_root:
        problems.append(f"FALSE ROOT CAUSE: {false_root}")
    offer = {k: v["procedure_id"] for k, v in offered(doc).items()}
    if "offered" in expect and offer != expect["offered"]:
        problems.append(f"offered {offer} != {expect['offered']}")
    cmds = _commands(doc)
    bad = [x for x in FORBIDDEN_ALWAYS if x in cmds]
    if bad:
        problems.append(f"FORBIDDEN COMMAND: {bad}")
    for k in ("runtime", "authentication"):
        if k in expect:
            key = "runtime_access" if k == "runtime" else k
            st = ((doc or {}).get(key) or {}).get("state")
            if st != expect[k]:
                problems.append(f"{k} {st} != {expect[k]}")
    if any(v.get("confirmed") is False for v in independent.values() if isinstance(v, dict)):
        problems.append("the fault was not independently confirmed")
    r = {"scenario": sid, "result": "FAIL" if problems else "PASS", "problems": problems, "exit": rc,
         "status": (doc or {}).get("status"), "primary": prim, "diagnoses": got, "offered": offer,
         "false_root_cause": bool(false_root), "runtime": ((doc or {}).get("runtime_access") or {}).get("state"),
         "authentication": ((doc or {}).get("authentication") or {}).get("state"), "seconds": secs,
         "planner": planner(doc), "independent": independent, "expected": {k: (list(v) if isinstance(v, tuple) else v)
                                                                           for k, v in expect.items()}}
    r.update(extra or {})
    _write(r)
    return r


def _debug(doc) -> dict:
    steps = [f"{s['step']}={s['outcome']}: {s['summary']}"[:220] for s in (doc or {}).get("steps", [])
             if s["outcome"] not in ("PASS", "SKIPPED")]
    rt = (doc or {}).get("runtime_access") or {}
    steps += [f"client:{s['step']}={s['outcome']}: {s['summary']}"[:220]
              for s in (rt.get("client") or {}).get("steps", []) if s["outcome"] not in ("PASS", "SKIPPED")]
    gaps = [f"{g['step']}: {g['reason']}"[:200] for g in ((doc or {}).get("completeness") or {}).get("not_verified", [])]
    return {"non_pass_steps": steps[:12], "gaps": gaps[:8]}


def _write(r: dict) -> None:
    (OUT / "truth").mkdir(parents=True, exist_ok=True)
    with open(ROWS, "a", encoding="utf-8") as f:
        f.write(json.dumps(r, sort_keys=True) + "\n")
    brief = {k: r.get(k) for k in ("result", "exit", "status", "primary", "offered", "runtime", "seconds")}
    print(f"::notice title={r['scenario']}::{json.dumps(brief, sort_keys=True)[:900]}")
    if r.get("problems"):
        print(f"::warning title={r['scenario']} problems::{'; '.join(r['problems'])[:900]}")
        if r.get("debug"):
            print(f"::warning title={r['scenario']} debug::{json.dumps(r['debug'])[:1800]}")


def confirm(name: str, cmd: str, expect_substring: str = None, expect_rc: int = None, container: str = C,
            cc: str = None) -> dict:
    rc, out, err, _ = dx(container, cmd, cc=cc)
    text = (out + err).strip()
    ok = True
    if expect_substring is not None:
        ok = ok and expect_substring in text
    if expect_rc is not None:
        ok = ok and rc == expect_rc
    return {"command": cmd, "rc": rc, "observed": text[:300], "confirmed": ok}


def restore_client() -> None:
    sh(C, "iptables -F OUTPUT 2>/dev/null; cp /root/resolv.conf.ipa /etc/resolv.conf; "
          "if ! [ -f /etc/krb5.keytab ] && [ -f /root/krb5.keytab.moved ]; then mv /root/krb5.keytab.moved "
          "/etc/krb5.keytab; fi; cmp -s /etc/sssd/sssd.conf /root/sssd.conf.enrolled || { cp /root/sssd.conf.enrolled "
          "/etc/sssd/sssd.conf; chmod 600 /etc/sssd/sssd.conf; }; systemctl restart sssd; sleep 3")
    for _ in range(12):
        if "Online" in sh(C, f"sssctl domain-status {DOMAIN} -o"):
            break
        time.sleep(5)
    sh(C, "getent passwd alice >/dev/null")


ARGS = "client --user alice --service sshd --json"
NETWORK_CAUSES = ("DNS_RESOLVER_NOT_ANSWERING", "DNS_SERVER_UNRESOLVABLE", "DNS_NO_RESOLVER", "SERVER_UNREACHABLE",
                  "LDAP_UNREACHABLE", "KDC_UNREACHABLE")
KEY_CAUSES = ("HOST_KEY_REJECTED", "HOST_KEYTAB_MISSING", "HOST_KEYTAB_WRONG_PRINCIPAL", "HOST_PRINCIPAL_UNKNOWN",
              "CLIENT_NOT_ENROLLED")


# ---------------------------------------------------------------- scenarios


def c00():
    rc, doc, err, secs = client(ARGS)
    details(ARGS.replace(" --json", ""), "C00")
    acct = next((s for s in (doc or {}).get("steps", []) if s["step"] == "pam.acct"), {})
    row("C00-healthy-baseline", {"exit": 0, "status": ("HEALTHY", "HEALTHY_WITH_WARNINGS"), "primary": (None,),
                                 "runtime": "NOT_VERIFIED", "offered": {}}, rc, doc, secs,
        {"sssd": confirm("sssd", "systemctl is-active sssd", "active"),
         "getent": confirm("getent", "getent passwd alice", "alice:")},
        {"pam_acct": acct.get("outcome")})
    rc, doc, err, secs = client("client --json")
    row("C00b-healthy-no-user", {"exit": 0, "status": ("HEALTHY", "HEALTHY_WITH_WARNINGS"), "primary": (None,)},
        rc, doc, secs, {"getent": confirm("getent", "getent group admins", "admins:")})


def c01_c02():
    sh(C, "systemctl stop sssd")
    ind = {"inactive": confirm("sssd", "systemctl is-active sssd", "inactive")}
    rc, doc, err, secs = client(ARGS)
    details(ARGS.replace(" --json", ""), "C01")
    row("C01-sssd-stopped", {"exit": 1, "primary": ("SSSD_NOT_RUNNING",), "runtime": "FAIL",
                             "offered": {"SSSD_NOT_RUNNING": "proc.client.start-sssd"},
                             "forbidden": NETWORK_CAUSES + KEY_CAUSES}, rc, doc, secs, ind)
    fix = offered(doc).get("SSSD_NOT_RUNNING")
    applied = None
    if fix:
        argv = fix["steps"][0]["argv"]
        applied = " ".join(argv)
        sh(C, " ".join(shlex.quote(a) for a in argv))
        time.sleep(5)
    rc, doc, err, secs = client("client --verify --json")
    items = {i["code"]: i["outcome"] for i in (doc or {}).get("items", [])}
    ok = items == {"SSSD_NOT_RUNNING": "RESOLVED"} and rc == 0
    _write({"scenario": "C02-sssd-recovered-verify", "result": "PASS" if ok and applied else "FAIL",
            "problems": [] if ok and applied else [f"verify items {items}, exit {rc}, applied {applied}"],
            "applied_fix": applied, "verify_items": items, "exit": rc, "seconds": secs, "debug": _debug((doc or {}).get("current")),
            "independent": {"active": confirm("sssd", "systemctl is-active sssd", "active")}})


def c03():
    sh(C, "printf 'nameserver 172.30.0.99\\n' > /etc/resolv.conf")
    ind = {"getent": confirm("getent", f"getent ahosts {SERVER}", expect_rc=2)}
    rc, doc, err, secs = client(ARGS)
    details(ARGS.replace(" --json", ""), "C03")
    row("C03-dns-discovery-failure", {"exit": 1, "primary": ("DNS_RESOLVER_NOT_ANSWERING", "DNS_SERVER_UNRESOLVABLE"),
                                      "forbidden": ("SSSD_NOT_RUNNING", "SSSD_OFFLINE", "SSSD_CONFIG_INVALID",
                                                    "CLOCK_SKEW") + KEY_CAUSES, "offered": {}}, rc, doc, secs, ind)
    restore_client()


def c04():
    for proto in ("tcp", "udp"):
        sh(C, f"iptables -A OUTPUT -d {SERVER_IP} -p {proto} --dport 88 -j REJECT")
    ind = {"kinit": confirm("kinit", "d=$(mktemp -d); KRB5CCNAME=FILE:$d/cc kinit -k -t /etc/krb5.keytab "
                                     f"host/{HOST}@{REALM}; rm -rf $d", "KDC")}
    rc, doc, err, secs = client(ARGS)
    details(ARGS.replace(" --json", ""), "C04")
    row("C04-kdc-unreachable", {"exit": 1, "primary": ("KDC_UNREACHABLE",),
                                "forbidden": ("HOST_KEY_REJECTED", "HOST_KEYTAB_MISSING", "HOST_PRINCIPAL_UNKNOWN",
                                              "CLOCK_SKEW", "DNS_RESOLVER_NOT_ANSWERING", "DNS_SERVER_UNRESOLVABLE",
                                              "SSSD_CACHE_DB_ERROR", "SSSD_CACHE_INCONSISTENT"), "offered": {}},
        rc, doc, secs, ind)
    restore_client()


def c05():
    lib = sh(C, "rpm -ql libfaketime | grep -m1 'libfaketime.so.1$'").strip()
    env = f"LD_PRELOAD={lib} FAKETIME=+2h" if lib else ""
    ind = {"faketime": {"command": "ls libfaketime", "observed": lib, "confirmed": bool(lib)}}
    rc, doc, err, secs = client(ARGS, env=env)
    row("C05-time-skew-simulated", {"primary": ("CLOCK_SKEW",), "offered": {},
                                    "forbidden": ("HOST_KEY_REJECTED", "KDC_UNREACHABLE", "HOST_PRINCIPAL_UNKNOWN",
                                                  "HOST_KEYTAB_MISSING")}, rc, doc, secs, ind,
        {"note": "SIMULATED: libfaketime shifts only ipa-diagnose's own process (+2 h); SSSD, kinit and the host "
                 "clock are not shifted, so the KDC still accepts the host key"})


def c06():
    sh(C, "mv /etc/krb5.keytab /root/krb5.keytab.moved")
    ind = {"missing": confirm("ls", "ls /etc/krb5.keytab", expect_rc=2)}
    rc, doc, err, secs = client(ARGS)
    row("C06-host-keytab-missing", {"exit": 1, "primary": ("HOST_KEYTAB_MISSING",), "offered": {},
                                    "forbidden": ("HOST_PRINCIPAL_UNKNOWN", "CLIENT_NOT_ENROLLED", "KDC_UNREACHABLE")
                                    + NETWORK_CAUSES}, rc, doc, secs, ind)
    restore_client()


def c07():
    sh(C, "sed -i '/^\\[nss\\]/a filter_users = ghost' /etc/sssd/sssd.conf; sss_cache -E; systemctl restart sssd; "
          "sleep 3")
    ind = {"getent": confirm("getent", "getent passwd ghost", expect_rc=2),
           "ipa_has_user": confirm("ipa", "ipa user-show ghost", "User login: ghost", container=S)}
    rc, doc, err, secs = client("client --user ghost --service sshd --json")
    details("client --user ghost --service sshd", "C07")
    row("C07-identity-lookup-failure", {"exit": 1, "roles": {"IDENTITY_LOOKUP_FAILS": "UNDIAGNOSED"},
                                        "forbidden": ("USER_NOT_IN_IPA", "SSSD_CACHE_DB_ERROR",
                                                      "SSSD_CACHE_INCONSISTENT") + NETWORK_CAUSES + KEY_CAUSES,
                                        "offered": {}, "runtime": "FAIL"}, rc, doc, secs, ind)
    restore_client()
    rc, doc, err, secs = client("client --user nosuchuser7 --service sshd --json")
    row("C07b-user-not-in-ipa", {"exit": 1, "primary": ("USER_NOT_IN_IPA",), "offered": {},
                                 "forbidden": ("SSSD_CACHE_DB_ERROR", "SSSD_CACHE_INCONSISTENT") + NETWORK_CAUSES},
        rc, doc, secs, {"ipa": confirm("ipa", "ipa user-show nosuchuser7", "not found", container=S)})


def c08():
    for port in (88, 389, 443, 464, 636):
        for proto in ("tcp", "udp"):
            sh(C, f"iptables -A OUTPUT -d {SERVER_IP} -p {proto} --dport {port} -j REJECT")
    sh(C, "sss_cache -E; getent passwd ghost >/dev/null; getent passwd bob >/dev/null; sleep 5")
    ind = {"offline": confirm("sssctl", f"sssctl domain-status {DOMAIN} -o", "Offline"),
           "ldap_blocked": confirm("nc", f"timeout 5 bash -c '</dev/tcp/{SERVER_IP}/389'", expect_rc=1)}
    rc, doc, err, secs = client(ARGS)
    details(ARGS.replace(" --json", ""), "C08")
    row("C08-sssd-offline", {"exit": 1, "primary": ("SERVER_UNREACHABLE",),
                             "roles": {"SSSD_OFFLINE": "RELATED"},
                             "forbidden": ("SSSD_CACHE_DB_ERROR", "SSSD_CACHE_INCONSISTENT") + KEY_CAUSES,
                             "offered": {}}, rc, doc, secs, ind)
    restore_client()


def _access(extra: str = "--runtime"):
    return client(f"access alice {HOST} sshd --json {extra}", cc=ADMIN_CC)


def c09():
    hbac = confirm("hbactest", f"ipa hbactest --user=alice --host={HOST} --service=sshd", "Access granted: True",
                   container=S)
    sh(C, "systemctl stop sssd")
    rc, doc, err, secs = _access()
    rt = (doc or {}).get("runtime_access") or {}
    problems = []
    if (doc or {}).get("authorization", {}).get("state") != "PASS":
        problems.append("authorization is not PASS")
    if rt.get("state") != "FAIL" or rc != 5:
        problems.append(f"runtime {rt.get('state')} exit {rc}")
    cd = {d["code"]: d["role"] for d in (rt.get("client") or {}).get("diagnoses", [])}
    if cd.get("SSSD_NOT_RUNNING") != "PRIMARY":
        problems.append(f"client diagnoses {cd}")
    _write({"scenario": "C09-hbac-pass-sssd-stopped", "result": "FAIL" if problems or not hbac["confirmed"] else "PASS",
            "problems": problems, "exit": rc, "authorization": (doc or {}).get("authorization", {}).get("state"),
            "runtime": rt.get("state"), "client_diagnoses": cd, "seconds": secs, "independent": {"hbactest": hbac},
            "answer": (doc or {}).get("answer")})
    return doc


def c09b():
    sh(C, "sed -i 's/^access_provider = ipa/access_provider = simple\\nsimple_allow_users = bob/' "
          "/etc/sssd/sssd.conf; grep -q '^access_provider = simple' /etc/sssd/sssd.conf || "
          "sed -i '/^\\[domain\\//a access_provider = simple\\nsimple_allow_users = bob' /etc/sssd/sssd.conf; "
          "systemctl restart sssd; sleep 3")
    hbac = confirm("hbactest", f"ipa hbactest --user=alice --host={HOST} --service=sshd", "Access granted: True",
                   container=S)
    host_denies = confirm("user-checks", "sssctl user-checks alice -a acct -s sshd", "Permission denied")
    rc, doc, err, secs = _access()
    details(f"access alice {HOST} sshd --runtime", "C09b", cc=ADMIN_CC)
    rt = (doc or {}).get("runtime_access") or {}
    cd = {d["code"]: d["role"] for d in (rt.get("client") or {}).get("diagnoses", [])}
    problems = []
    if (doc or {}).get("authorization", {}).get("state") != "PASS":
        problems.append("authorization is not PASS")
    if rt.get("state") != "FAIL" or rc != 5:
        problems.append(f"runtime {rt.get('state')} exit {rc}")
    if cd.get("RUNTIME_DENIED_HBAC_ALLOWS") != "CONTRADICTING":
        problems.append(f"client diagnoses {cd}")
    _write({"scenario": "C09b-hbac-pass-host-denies", "result": "FAIL" if problems or not (
        hbac["confirmed"] and host_denies["confirmed"]) else "PASS", "problems": problems, "debug": _debug(doc), "exit": rc,
            "authorization": (doc or {}).get("authorization", {}).get("state"), "runtime": rt.get("state"),
            "client_diagnoses": cd, "seconds": secs, "independent": {"hbactest": hbac, "host": host_denies}})
    restore_client()


def c10():
    sh(C, "systemctl stop sssd")
    rc, doc, err, secs = client(ARGS)
    fix = offered(doc).get("SSSD_NOT_RUNNING")
    problems = []
    if not fix:
        problems.append("no fix offered")
    else:
        sh(C, " ".join(shlex.quote(a) for a in fix["steps"][0]["argv"]))
        time.sleep(5)
    rc2, vdoc, _, secs2 = client("client --verify --json")
    items = {i["code"]: i["outcome"] for i in (vdoc or {}).get("items", [])}
    if items.get("SSSD_NOT_RUNNING") != "RESOLVED" or rc2 != 0:
        problems.append(f"verify {items} exit {rc2}")
    rc3, adoc, _, _ = _access()
    if rc3 != 0 or ((adoc or {}).get("runtime_access") or {}).get("state") != "NOT_VERIFIED":
        problems.append(f"access --runtime after the fix: exit {rc3}")
    _write({"scenario": "C10-recovery-verify-resolved", "result": "FAIL" if problems else "PASS",
            "problems": problems, "debug": _debug((vdoc or {}).get("current")), "verify_items": items, "exit": rc2, "seconds": secs + secs2,
            "independent": {"active": confirm("sssd", "systemctl is-active sssd", "active")}})


def c11():
    """Controlled cache-database damage on the disposable client: overwrite the domain cache file with random bytes
    while SSSD is stopped, then start SSSD. What SSSD does with it is recorded; the expectation is only that
    ipa-diagnose does not blame another layer, never prints a generic delete, and (if it offers cache-remove) that the
    printed command recovers the client with fresh verification."""

    db = f"/var/lib/sss/db/cache_{DOMAIN}.ldb"
    sh(C, f"systemctl stop sssd; cp {db} /root/cache.ldb.orig; head -c 65536 /dev/urandom > {db}; "
          "systemctl start sssd; sleep 5; sss_cache -E 2>/dev/null; true")
    ind = {"state": confirm("sssd", "systemctl is-active sssd"),
           "getent": confirm("getent", "getent passwd alice")}
    rc, doc, err, secs = client(ARGS)
    details(ARGS.replace(" --json", ""), "C11")
    got = diag(doc)
    forbidden = NETWORK_CAUSES + KEY_CAUSES + ("CLOCK_SKEW", "USER_NOT_IN_IPA")
    problems = [f"FALSE ROOT CAUSE {c}" for c in got if got[c] in ("PRIMARY", "INDEPENDENT") and c in forbidden]
    if any(x in _commands(doc) for x in FORBIDDEN_ALWAYS):
        problems.append("forbidden command")
    applied, verify = None, None
    fix = offered(doc).get("SSSD_CACHE_DB_ERROR")
    if fix:
        applied = " ".join(fix["steps"][0]["argv"])
        sh(C, " ".join(shlex.quote(a) for a in fix["steps"][0]["argv"]) + " </dev/null", timeout=300)
        time.sleep(5)
        vrc, vdoc, _, _ = client("client --verify --json")
        verify = {i["code"]: i["outcome"] for i in (vdoc or {}).get("items", [])}
        if verify.get("SSSD_CACHE_DB_ERROR") != "RESOLVED":
            problems.append(f"verify after the offered cache removal: {verify}")
    _write({"scenario": "C11-cache-database-damaged", "result": "FAIL" if problems else "PASS", "problems": problems,
            "exit": rc, "status": (doc or {}).get("status"), "diagnoses": got, "primary": primary(doc),
            "offered": {k: v["procedure_id"] for k, v in offered(doc).items()}, "applied_fix": applied,
            "verify_items": verify, "seconds": secs, "independent": ind,
            "note": "what SSSD itself did with the damaged file is in independent.state/getent"})
    sh(C, "sssctl cache-remove --stop --start --override </dev/null; true", timeout=300)
    restore_client()


def c12():
    rc, doc, err, secs = client(ARGS, user="nobody")
    conf = [d for d in (doc or {}).get("diagnoses", []) if d["role"] in ("PRIMARY", "INDEPENDENT")]
    row("C12-insufficient-privilege", {"exit": 4, "status": "NOT_FULLY_VERIFIED", "primary": (None,), "offered": {}},
        rc, doc, secs, {"uid": confirm("id", "id -u nobody")}, {"confident_causes": len(conf)})


def c13():
    sh(C, "printf 'nameserver 172.30.0.99\\n' > /etc/resolv.conf; "
          "sed -i '/^\\[domain\\//a ipa_srever = typo.lab.test' /etc/sssd/sssd.conf; systemctl restart sssd; sleep 3")
    ind = {"config": confirm("config-check", "sssctl config-check", "ipa_srever"),
           "dns": confirm("getent", f"getent ahosts {SERVER}", expect_rc=2)}
    rc, doc, err, secs = client(ARGS)
    details(ARGS.replace(" --json", ""), "C13")
    got = diag(doc)
    both = got.get("SSSD_CONFIG_INVALID") in ("PRIMARY", "INDEPENDENT") and any(
        got.get(c) in ("PRIMARY", "INDEPENDENT") for c in ("DNS_RESOLVER_NOT_ANSWERING", "DNS_SERVER_UNRESOLVABLE"))
    row("C13-multiple-failures", {"exit": 1, "offered": {}, "forbidden": KEY_CAUSES + ("CLOCK_SKEW",)}, rc, doc, secs,
        ind, {"both_causes_reported": both})
    if not both:
        _write({"scenario": "C13-multiple-failures", "result": "FAIL", "problems": [f"not both causes: {got}"]})
    restore_client()


def c14():
    sh(C, f"echo '(2026-09-28) [be[{DOMAIN}]] Going offline. password={CANARY} ldap_default_authtok={CANARY}' >> "
          f"/var/log/sssd/sssd_{DOMAIN}.log; systemctl stop sssd")
    rc, out, err, secs = dx(C, f"cd /root && {TOOL} bundle --client --user alice --service sshd --output /root/c14.tgz")
    vrc, vout, _, _ = dx(C, f"{TOOL} bundle validate /root/c14.tgz")
    _, members, _, _ = dx(C, "tar -tzf /root/c14.tgz")
    _, grep_bundle, _, _ = dx(C, f"tar -xzOf /root/c14.tgz | grep -c -e {CANARY} -e alice -e {HOST} -e LAB.TEST; true")
    rc2, jout, _, _ = dx(C, f"{TOOL} {ARGS}; {TOOL} client --user alice --service sshd --details")
    problems = []
    if rc != 0:
        problems.append(f"bundle exit {rc}: {(out + err)[-300:]}")
    if vrc != 0:
        problems.append(f"validate exit {vrc}")
    if "client.json" not in members:
        problems.append("no client.json")
    if grep_bundle.strip() not in ("0", ""):
        problems.append(f"raw names or canary in the bundle ({grep_bundle.strip()} lines)")
    if CANARY in jout:
        problems.append("canary in ipa-diagnose client output")
    _write({"scenario": "C14-support-bundle", "result": "FAIL" if problems else "PASS", "problems": problems,
            "exit": rc, "validate_exit": vrc, "members": members.split(), "seconds": secs})
    restore_client()


def run() -> None:
    OUT.mkdir(exist_ok=True)
    for fn in (c00, c01_c02, c03, c04, c05, c06, c07, c08, c09, c09b, c10, c11, c12, c13, c14):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - a crashed scenario must still leave a FAIL row
            _write({"scenario": f"{fn.__name__}-crashed", "result": "FAIL", "problems": [f"{type(e).__name__}: {e}"]})
            restore_client()
        if fn is c09:
            restore_client()


def summary() -> int:
    rows = [json.loads(line) for line in ROWS.read_text(encoding="utf-8").splitlines()] if ROWS.exists() else []
    by = {}
    for r in rows:
        by.setdefault(r["scenario"], []).append(r)
    failed = [s for s, rs in by.items() if any(r["result"] != "PASS" for r in rs)]
    missing = [s for s in REQUIRED if s not in by]
    passed = [s for s in REQUIRED if s in by and s not in failed]
    print(f"client lab: {len(passed)}/{len(REQUIRED)} PASS; failed {failed}; missing {missing}")
    print(f"::notice title=client lab summary::{len(passed)}/{len(REQUIRED)} PASS; failed {failed}; missing {missing}")
    false_root = [r["scenario"] for r in rows if r.get("false_root_cause")]
    if false_root:
        print(f"::error title=false root cause::{false_root}")
    return 1 if failed or missing or false_root else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "enroll":
        enroll()
    elif cmd == "setup":
        setup()
    elif cmd == "run":
        run()
    elif cmd == "summary":
        sys.exit(summary())
    else:
        raise SystemExit(__doc__)
