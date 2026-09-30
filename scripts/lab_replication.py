#!/usr/bin/env python3
"""Live replication-diagnosis lab (Slice 5), run on the CI host against three throwaway FreeIPA servers on a private
Docker network: ipa01 (172.31.0.11, CA + DNS), ipa02 (172.31.0.12, CA replica of ipa01), ipa03 (172.31.0.13, replica
of ipa02 without CA). Line topology: domain segments ipa01-ipa02, ipa02-ipa03; CA segment ipa01-ipa02.

    python3 scripts/lab_replication.py replica NAME FROM [--ca]   # install a replica (the lab plays the admin)
    python3 scripts/lab_replication.py setup                     # prove topology and healthy replication (R00)
    python3 scripts/lab_replication.py run                       # every scenario
    python3 scripts/lab_replication.py summary                   # fail on a FAIL, a missing row, a false root cause

Every fault is injected by this script, ONE at a time, and confirmed with an independent command (systemctl, getent,
a TCP connect, the agreement's own status read with ldapsearch) BEFORE ipa-diagnose runs; ipa-diagnose is never told
what was broken. When a scenario applies a fix, it runs exactly the argv ipa-diagnose printed. After each scenario
the lab is restored and every agreement must be green again (a fresh successful session) before the next one.

Rows: out/truth/replication-results.jsonl; compact rows are also printed as GitHub annotations.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

PW = os.environ.get("IPA_PASSWORD", "")
OUT = pathlib.Path("out")
ROWS = OUT / "truth" / "replication-results.jsonl"
TOOL = "/root/.local/bin/ipa-diagnose"
ADMIN_CC = "FILE:/root/admin.ccache"
DOMAIN, REALM, BASEDN, INST = "lab.test", "LAB.TEST", "dc=lab,dc=test", "LAB-TEST"
SERVERS = {"ipa01": "172.31.0.11", "ipa02": "172.31.0.12", "ipa03": "172.31.0.13"}
FQ = {n: f"{n}.{DOMAIN}" for n in SERVERS}
LDAPI = "ldapi://%2Frun%2Fslapd-LAB-TEST.socket"
FORBIDDEN = ("ipa-replica-manage", "ipa-csreplica-manage", "clean-ruv", "cleanallruv", "re-initialize", "force-sync",
             "server-del", "topologysegment-", "ipa-getkeytab", "ldapmodify", "makestep", "date -s", "--uninstall")

REQUIRED = [
    "R00-topology-and-healthy-replication-proven", "R01-healthy-with-ticket-ipa01", "R01-healthy-with-ticket-ipa02",
    "R01-healthy-with-ticket-ipa03", "R01b-reverse-not-observable-without-ticket", "R02-peer-ds-stopped-supplier-view",
    "R02b-peer-ds-stopped-local-view-and-fix", "R02c-verify-after-fix-local", "R02d-verify-after-fix-supplier",
    "R03-peer-unreachable", "R04-local-dns-break-for-peer", "R05-local-kdc-stopped-and-fix", "R05b-verify-after-fix",
    "R06-ds-keytab-unreadable-disposable-replica", "R07-peer-kdc-stopped-reverse-direction",
    "R08-multi-cause-middle-server", "R09-budget-scope-peer", "R10-non-root", "R11-support-bundle",
    "R12-simulated-clock-offset",
]


# ---------------------------------------------------------------- docker helpers


def dx(c: str, cmd: str, timeout: int = 300, stdin: str = None, cc: str = None, user: str = "root"):
    env = f"export KRB5CCNAME={cc}; " if cc else ""
    argv = ["docker", "exec", "-i", "-u", user, c, "bash", "-c", env + cmd]
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


def sh(c: str, cmd: str, check: bool = False, **kw) -> str:
    rc, out, err, _ = dx(c, cmd, **kw)
    log("lab-commands", f"[{c}] $ {cmd}\n{out[-4000:]}{err[-2000:]}[rc={rc}]")
    if check and rc != 0:
        raise SystemExit(f"lab step failed on {c}: {cmd}: {(out + err).strip()[-400:]}")
    return out + err


def admin(c: str) -> None:
    sh(c, f"echo {shlex.quote(PW)} | kinit admin >/dev/null", cc=ADMIN_CC, check=True)


def ipa(c: str, cmd: str, check: bool = False) -> str:
    return sh(c, "ipa " + cmd, cc=ADMIN_CC, check=check)


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- replica installation


def replica(name: str, master: str, ca: bool) -> None:
    OUT.mkdir(exist_ok=True)
    ip = SERVERS[name]
    admin("ipa01")
    ipa("ipa01", f"dnsrecord-add {DOMAIN} {name} --a-rec {ip}")
    existing = [n for n in SERVERS if n != name and subprocess.run(
        ["docker", "inspect", n], capture_output=True).returncode == 0]
    for n in existing:  # the installer's connection checks need names both ways (lesson of the earlier 2-node lab)
        sh(n, f"grep -q {FQ[name]} /etc/hosts || echo '{ip} {FQ[name]} {name}' >> /etc/hosts")
    hosts = []
    for n in existing:
        hosts += ["--add-host", f"{FQ[n]}:{SERVERS[n]}"]
    argv = (["docker", "run", "-d", "--name", name, "--privileged", "--cgroupns=host", "-v",
             "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-v", f"{name}-data:/data", "--network", "ipanet", "--ip", ip,
             "--dns", SERVERS["ipa01"], "-h", FQ[name]] + hosts +
            ["-e", f"PASSWORD={PW}", f"freeipa/freeipa-server:{os.environ.get('IMAGE', 'fedora-43')}",
             "ipa-replica-install", "-U", "--no-host-dns", f"--server={FQ[master]}", f"--domain={DOMAIN}",
             f"--realm={REALM}", "--principal=admin", f"--admin-password={PW}", "--no-ntp", "--skip-mem-check",
             f"--ip-address={ip}"] + (["--setup-ca"] if ca else []))
    subprocess.run(argv, check=True, capture_output=True)
    for i in range(150):
        time.sleep(10)
        running = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True,
                                 text=True).stdout.strip()
        if running != "true":
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            print((logs.stdout + logs.stderr)[-4000:])
            raise SystemExit(f"{name} exited during replica install")
        rc, out, _e, _s = dx(name, "systemctl is-active ipa.service")
        if out.strip() == "active":
            print(f"{name} active after ~{(i + 1) * 10}s")
            time.sleep(20)
            break
    else:
        raise SystemExit(f"{name} never became ready")
    for n in existing:
        sh(name, f"grep -q {FQ[n]} /etc/hosts || echo '{SERVERS[n]} {FQ[n]} {n}' >> /etc/hosts")
    print(sh(name, "ipactl status"))


# ---------------------------------------------------------------- independent evidence (not through ipa-diagnose)


def agreements(c: str) -> list:
    """The agreements of server c, read directly with ldapsearch over its LDAPI socket (the lab's own read)."""

    out = sh(c, f"ldapsearch -LLL -o ldif-wrap=no -Q -Y EXTERNAL -H {LDAPI} -b 'cn=mapping tree,cn=config' "
                "'(objectClass=nsds5replicationagreement)' nsDS5ReplicaHost nsDS5ReplicaRoot "
                "nsds5replicaLastUpdateStatus nsds5replicaLastUpdateEnd nsds5replicaUpdateInProgress "
                "nsDS5ReplicaTransportInfo nsDS5ReplicaBindMethod nsDS5ReplicaPort")
    res, cur = [], {}
    for line in out.splitlines() + [""]:
        if not line.strip():
            if cur.get("nsds5replicahost"):
                res.append(cur)
            cur = {}
            continue
        k, _, v = line.partition(": ")
        cur[k.lower()] = v
    for a in res:
        a["suffix"] = "ca" if a.get("nsds5replicaroot", "").lower() == "o=ipaca" else "domain"
    return res


def status_of(c: str, peer: str, suffix: str) -> dict:
    return next((a for a in agreements(c) if a.get("nsds5replicahost") == FQ[peer] and a["suffix"] == suffix), {})


def _end(a: dict):
    v = a.get("nsds5replicalastupdateend", "")
    try:
        return datetime.datetime.strptime(v, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


_probe = [0]


def trigger(c: str, suffix: str = "domain") -> None:
    """Make a change on server c so its agreements start a session. The lab writes through c's LDAPI socket as root
    (SASL EXTERNAL), which needs no Kerberos: with c's own KDC stopped, kinit on c fails (run 36657552130 - an IPA
    server's Kerberos library uses its own KDC). Domain suffix: the description of a lab-only entry; CA suffix
    (o=ipaca): the description of ou=people,o=ipaca."""

    _probe[0] += 1
    dn = (f"uid=admin,cn=users,cn=accounts,{BASEDN}" if suffix == "domain" else "ou=people,o=ipaca")
    ldif = f"dn: {dn}\nchangetype: modify\nreplace: description\ndescription: lab probe {_probe[0]} from {c}\n"
    rc, out, err, _ = dx(c, f"ldapmodify -Q -Y EXTERNAL -H {LDAPI}", stdin=ldif)
    log("triggers", f"{iso(now())} {c} {suffix} change: {'made' if rc == 0 else 'FAILED: ' + (out + err)[-200:]}")


def wait_agreement(c: str, peer: str, suffix: str, want_ok: bool, since: datetime.datetime, timeout: int = 240) -> dict:
    deadline = time.monotonic() + timeout
    a = {}
    while time.monotonic() < deadline:
        a = status_of(c, peer, suffix)
        st = a.get("nsds5replicalastupdatestatus", "")
        end = _end(a)
        ok = st.startswith("Error (0) Replica acquired successfully")
        fresh = end is not None and end > since
        if want_ok and ok and fresh and a.get("nsds5replicaupdateinprogress", "").upper() != "TRUE":
            return a
        if not want_ok and st and not ok and "No replication sessions" not in st:
            return a
        time.sleep(8)
        if want_ok:
            trigger(c, suffix)
    return a


LAST_PENDING: list = []


def wait_green(timeout: int = 900) -> bool:
    """Every agreement of every server is green: its last session succeeded (a domain agreement: a session that
    ended after this wait began) and none is in progress. A CA agreement that had no session since its server
    started is accepted only while nothing else fails (the lab's CA changes are rare)."""

    start = now()
    time.sleep(2)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pending = []
        for c in SERVERS:
            for a in agreements(c):
                st = a.get("nsds5replicalastupdatestatus", "")
                end = _end(a)
                ok = st.startswith("Error (0) Replica acquired successfully")
                if a["suffix"] == "domain":
                    ok = ok and end is not None and end > start
                else:
                    ok = ok or "No replication sessions started" in st
                if not ok or a.get("nsds5replicaupdateinprogress", "").upper() == "TRUE":
                    pending.append(f"{c}->{a.get('nsds5replicahost')}/{a['suffix']}: {st[:90]}")
        LAST_PENDING[:] = pending
        if not pending:
            return True
        log("wait-green", f"{iso(now())} pending: {pending}")
        for c in SERVERS:
            trigger(c, "domain")
        for c in ("ipa01", "ipa02"):
            trigger(c, "ca")
        time.sleep(20)
    return False


def confirm(c: str, cmd: str, expect_substring: str = None, expect_rc: int = None, not_substring: str = None) -> dict:
    rc, out, err, _ = dx(c, cmd)
    text = (out + err).strip()
    ok = True
    if expect_substring is not None:
        ok = ok and expect_substring in text
    if not_substring is not None:
        ok = ok and not_substring not in text
    if expect_rc is not None:
        ok = ok and rc == expect_rc
    return {"on": c, "command": cmd, "rc": rc, "observed": text[:300], "confirmed": ok}


# ---------------------------------------------------------------- running ipa-diagnose blind


def tool(c: str, args: str = "", ticket: bool = True, user: str = "root", prefix: str = ""):
    cmd = f"{prefix}{TOOL} replication {args} --json".strip()
    if user != "root":
        cmd = f"cd /tmp && {cmd}"
    rc, out, err, secs = dx(c, cmd, cc=ADMIN_CC if ticket else "FILE:/nonexistent-lab-cache", user=user, timeout=500)
    try:
        doc = json.loads(out)
    except ValueError:
        doc = None
    log("tool-runs", f"[{c}] $ {cmd}\n[rc={rc} {secs}s]\n{out[:30000]}\n{err[:3000]}")
    return rc, doc, secs


def details(c: str, name: str, args: str = "", ticket: bool = True) -> None:
    rc, out, err, _ = dx(c, f"{TOOL} replication {args} --details", cc=ADMIN_CC if ticket else None, timeout=500)
    (OUT / "details").mkdir(exist_ok=True, parents=True)
    (OUT / "details" / f"{name}.txt").write_text(out + err, encoding="utf-8")


def roots(doc) -> dict:
    return {d["key"]: d["role"] for d in (doc or {}).get("diagnoses", []) if d["role"] in ("PRIMARY", "INDEPENDENT")}


def primary(doc):
    return next((d["key"] for d in (doc or {}).get("diagnoses", []) if d["role"] == "PRIMARY"), None)


def offered(doc) -> dict:
    return {k: v for k, v in ((doc or {}).get("resolutions") or {}).items() if v.get("status") == "OFFERED"}


def _commands(doc) -> str:
    out = []
    for v in ((doc or {}).get("resolutions") or {}).values():
        out += [s["command"] for s in v.get("steps", [])] + [r.get("command") or "" for r in v.get("rollback", [])]
    for d in (doc or {}).get("diagnoses", []):
        out += d.get("next_steps") or []
    return "\n".join(out)


def row(sid: str, expect: dict, rc: int, doc, secs: float, independent: dict, extra: dict = None) -> dict:
    problems = []
    got_roots = roots(doc)
    prim = primary(doc)
    if doc is None:
        problems.append("no JSON answer")
    if "status" in expect and (doc or {}).get("status") not in expect["status"]:
        problems.append(f"status {(doc or {}).get('status')} not in {expect['status']}")
    if "primary" in expect and prim not in expect["primary"]:
        problems.append(f"primary {prim} not in {expect['primary']}")
    allowed = set(expect.get("roots", [])) | set(expect.get("primary", []) or [])
    false_root = [k for k in got_roots if "roots" in expect and k not in allowed]
    missed = [k for k in expect.get("roots", []) if k not in got_roots]
    if false_root:
        problems.append(f"FALSE ROOT CAUSE: {false_root}")
    if missed:
        problems.append(f"MISSED EXPECTED CAUSE: {missed}")
    for code in expect.get("present", []):
        if not any(d["key"].startswith(code) for d in (doc or {}).get("diagnoses", [])):
            problems.append(f"{code} not reported")
    for code in expect.get("absent", []):
        if any(d["key"].startswith(code) for d in (doc or {}).get("diagnoses", [])):
            problems.append(f"{code} reported but must not be")
    off = offered(doc)
    offer = {k: [s["argv"] for s in v.get("steps", [])] for k, v in off.items()}
    if "offered" in expect and offer != expect["offered"]:
        problems.append(f"offered {offer} != {expect['offered']}")
    unsafe = [k for k, v in off.items() if not k.endswith(f"server:{(doc or {}).get('environment', {}).get('host')}")
              or any(s["argv"][0] != "systemctl" for s in v.get("steps", []))]
    if unsafe:
        problems.append(f"UNSAFE RESOLUTION: {unsafe}")
    bad = [x for x in FORBIDDEN if x in _commands(doc)]
    if bad:
        problems.append(f"FORBIDDEN COMMAND: {bad}")
    for host in expect.get("handoff_to", []):
        if not any(h["host"] == FQ[host] for h in (doc or {}).get("handoffs", [])):
            problems.append(f"no handoff to {host}")
    for subj, state in (expect.get("relationships") or {}).items():
        x = next((r for r in (doc or {}).get("relationships", []) if r["subject"] == subj), None)
        if (x or {}).get("state") not in (state if isinstance(state, (list, tuple)) else [state]):
            problems.append(f"relationship {subj} is {(x or {}).get('state')}, expected {state}")
    if "no_google" in expect:
        ng = [((v.get("safety_gate") or {}).get("no_google") or {}) for v in off.values()]
        if not ng or any(bool(x.get("claimed")) != expect["no_google"] for x in ng):
            problems.append(f"no_google {[x.get('claimed') for x in ng]} != {expect['no_google']} "
                            f"(missing {[x.get('missing') for x in ng]})")
    if any(v.get("confirmed") is False for v in independent.values() if isinstance(v, dict)):
        problems.append("the fault was not independently confirmed")
    r = {"scenario": sid, "result": "FAIL" if problems else "PASS", "problems": problems, "exit": rc,
         "status": (doc or {}).get("status"), "primary": prim, "roots": got_roots, "offered": offer,
         "false_root_cause": bool(false_root), "missed_cause": bool(missed), "unsafe_resolution": bool(unsafe or bad),
         "seconds": secs, "planner": (doc or {}).get("planner_summary", {}).get("steps_run"),
         "independent": independent, "expected": expect,
         "chains": [[x["claim"][:160] for x in c["links"]] + [f"STOP: {c['boundary'][:160]}"]
                    for c in (doc or {}).get("cause_chains", [])][:6],
         "no_google": {k: ((v.get("safety_gate") or {}).get("no_google") or {}).get("claimed") for k, v in off.items()},
         "freeipa": (doc or {}).get("environment", {}).get("freeipa"),
         "debug": {"gaps": [f"{g['step']}: {g['reason']}"[:200]
                            for g in ((doc or {}).get("completeness") or {}).get("not_verified", [])][:8],
                   "diagnoses": [f"{d['role']} {d['key']}"[:160] for d in (doc or {}).get("diagnoses", [])][:12],
                   "relationships": [f"{x['subject']}={x.get('state')}" for x in (doc or {}).get("relationships", [])],
                   "status_texts": [f"{x['subject']}: {(x.get('status_text') or '')[:200]}"
                                    for x in (doc or {}).get("relationships", []) if x.get("state") not in ("OK",)]}}
    r.update(extra or {})
    _write(r)
    return r


def _write(r: dict) -> None:
    (OUT / "truth").mkdir(parents=True, exist_ok=True)
    with open(ROWS, "a", encoding="utf-8") as f:
        f.write(json.dumps(r, sort_keys=True, default=str) + "\n")
    brief = {k: r.get(k) for k in ("result", "exit", "status", "primary", "seconds")}
    print(f"::notice title={r['scenario']}::{json.dumps(brief, sort_keys=True)[:900]}")
    if r.get("problems"):
        print(f"::warning title={r['scenario']} problems::{'; '.join(r['problems'])[:900]}")
        print(f"::warning title={r['scenario']} debug::{json.dumps(r.get('debug'))[:3000]}")


def apply_printed(c: str, doc, key: str) -> dict:
    """Run EXACTLY the argv ipa-diagnose printed (no shell), as the administrator would."""

    res = ((doc or {}).get("resolutions") or {}).get(key) or {}
    done = []
    for s in res.get("steps", []):
        argv = s["argv"]
        p = subprocess.run(["docker", "exec", c] + argv, capture_output=True, text=True, timeout=300)
        done.append({"argv": argv, "rc": p.returncode, "out": (p.stdout + p.stderr)[-300:]})
        log("applied-fixes", f"[{c}] {argv} -> rc={p.returncode} {(p.stdout + p.stderr)[-500:]}")
    return {"applied": done, "all_ok": bool(done) and all(x["rc"] == 0 for x in done)}


def verify_until(c: str, args: str = "", ticket: bool = True, rounds: int = 20, pause: int = 30):
    """--verify, repeated while it answers PENDING (exit 3), as its recheck time says. Returns the last answer."""

    hist = []
    rc = doc = secs = None
    for _ in range(rounds):
        rc, doc, secs = tool(c, f"--verify {args}".strip(), ticket=ticket)
        items = {i["key"]: i["outcome"] for i in (doc or {}).get("items", [])}
        hist.append({"exit": rc, "items": items,
                     "new": [n.get("key") for n in (doc or {}).get("new_conditions", [])]})
        if rc != 3:
            break
        for n in SERVERS:  # give the suppliers something to replicate
            trigger(n, "domain")
        time.sleep(pause)
    return rc, doc, secs, hist


def restore(tag: str) -> None:
    for c in SERVERS:
        sh(c, "systemctl start dirsrv@LAB-TEST krb5kdc; ipactl start >/dev/null 2>&1; true", timeout=600)
    if not wait_green():
        _write({"scenario": f"restore-after-{tag}", "result": "FAIL",
                "problems": [f"the lab did not return to green: {LAST_PENDING}"]})
        raise SystemExit(f"lab not green after {tag}")


# ---------------------------------------------------------------- setup (R00)


def setup() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "truth").mkdir(exist_ok=True)
    for c in SERVERS:
        admin(c)
    seg_d = ipa("ipa01", "topologysegment-find domain")
    seg_c = ipa("ipa01", "topologysegment-find ca")
    roles = ipa("ipa01", "server-role-find --status=enabled")
    krb = {c: sh(c, "grep -E '^\\s*(kdc|master_kdc)\\s*=' /etc/krb5.conf; grep -E 'dns_lookup_kdc' /etc/krb5.conf")
           for c in SERVERS}
    kt = {c: sh(c, "stat -c '%U:%G %a' /etc/dirsrv/ds.keytab; grep KRB5_KTNAME /etc/sysconfig/dirsrv-LAB-TEST "
                   "/etc/sysconfig/dirsrv 2>/dev/null") for c in SERVERS}
    green = wait_green()
    probe = f"proofuser{int(time.time()) % 100000}"
    ipa("ipa01", f"user-add {probe} --first=Proof --last=Lab")
    seen = {}
    for _ in range(30):
        seen = {c: probe in sh(c, f"ldapsearch -LLL -Q -Y EXTERNAL -H {LDAPI} -b cn=users,cn=accounts,{BASEDN} "
                                  f"uid={probe} uid") for c in SERVERS}
        if all(seen.values()):
            break
        time.sleep(5)
    proof = {"segments_domain": seg_d.count("Left node"), "segments_ca": seg_c.count("Left node"),
             "ca_servers": roles.count("CA server"), "all_green": green, "change_replicated_to": seen,
             "krb5_conf": {c: " ".join(v.split())[:300] for c, v in krb.items()},
             "ds_keytab": {c: " ".join(v.split())[:200] for c, v in kt.items()},
             "agreements": {c: [f"{a.get('nsds5replicahost')}/{a['suffix']} {a.get('nsds5replicatransportinfo')} "
                                f"{a.get('nsds5replicabindmethod')} {a.get('nsds5replicaport')}" for a in agreements(c)]
                            for c in SERVERS}}
    proof["not_green"] = list(LAST_PENDING)
    ok = proof["segments_domain"] == 2 and proof["segments_ca"] == 1 and green and all(seen.values())
    _write({"scenario": "R00-topology-and-healthy-replication-proven", "result": "PASS" if ok else "FAIL",
            "problems": [] if ok else [f"topology/replication not as designed: {proof}"], "proof": proof})
    print(json.dumps(proof, indent=1))
    if not ok:
        raise SystemExit("lab topology not proven")


# ---------------------------------------------------------------- scenarios


def r01() -> None:
    for c in SERVERS:
        rc, doc, secs = tool(c)
        details(c, f"r01-healthy-{c}")
        row(f"R01-healthy-with-ticket-{c}", {"status": ["HEALTHY"], "roots": [], "offered": {}}, rc, doc, secs,
            {"all_agreements_green": {"confirmed": all(a.get("nsds5replicalastupdatestatus", "").startswith(
                "Error (0) Replica acquired") for a in agreements(c))}})
    rc, doc, secs = tool("ipa01", ticket=False)
    details("ipa01", "r01b-no-ticket", ticket=False)
    row("R01b-reverse-not-observable-without-ticket",
        {"status": ["NOT_FULLY_VERIFIED"], "roots": [], "offered": {}, "handoff_to": ["ipa02"],
         "relationships": {f"domain:{FQ['ipa02']}>{FQ['ipa01']}": "UNKNOWN",
                           f"domain:{FQ['ipa01']}>{FQ['ipa02']}": "OK"}}, rc, doc, secs, {})


def r02() -> None:
    sh("ipa02", f"systemctl stop dirsrv@{INST}")
    ind = {"ds_stopped_on_ipa02": confirm("ipa02", f"systemctl is-active dirsrv@{INST}", "inactive"),
           "ldap_refused_from_ipa01": confirm("ipa01", f"timeout 5 bash -c '</dev/tcp/{FQ['ipa02']}/389' "
                                                       "&& echo OPEN || echo CLOSED", "CLOSED")}
    t0 = now()
    trigger("ipa01", "domain")
    a = wait_agreement("ipa01", "ipa02", "domain", want_ok=False, since=t0)
    ind["agreement_status_observed"] = {"recorded_failure": "Error (0)" not in a.get(
        "nsds5replicalastupdatestatus", "Error (0)"), "observed": a.get("nsds5replicalastupdatestatus", "")[:200]}
    rc, doc, secs = tool("ipa01")
    details("ipa01", "r02-supplier")
    row("R02-peer-ds-stopped-supplier-view",
        {"status": ["PROBLEM_FOUND"], "primary": [f"PEER_DS_NOT_ACCEPTING@server:{FQ['ipa02']}"],
         "roots": [f"PEER_DS_NOT_ACCEPTING@server:{FQ['ipa02']}"], "offered": {}, "handoff_to": ["ipa02"],
         "absent": ["LOCAL_"]}, rc, doc, secs, ind)
    rc2, doc2, secs2 = tool("ipa02")
    details("ipa02", "r02b-local")
    ind2 = {"ds_stopped_on_ipa02": ind["ds_stopped_on_ipa02"]}
    key = f"LOCAL_DS_NOT_RUNNING@server:{FQ['ipa02']}"
    r = row("R02b-peer-ds-stopped-local-view-and-fix",
            {"status": ["PROBLEM_FOUND"], "primary": [key], "roots": [key],
             "offered": {key: [["systemctl", "start", f"dirsrv@{INST}.service"]]}}, rc2, doc2, secs2, ind2)
    applied = apply_printed("ipa02", doc2, key) if r["result"] == "PASS" else {"applied": [], "all_ok": False}
    rc3, doc3, secs3, hist = verify_until("ipa02")
    items = {i["key"]: i["outcome"] for i in (doc3 or {}).get("items", [])}
    ok = applied["all_ok"] and items.get(key) == "RESOLVED" and rc3 in (0, 4)
    _write({"scenario": "R02c-verify-after-fix-local", "result": "PASS" if ok else "FAIL",
            "problems": [] if ok else [f"verify on ipa02: exit {rc3}, items {items}, applied {applied}, "
                                       f"history {hist}"],
            "exit": rc3, "verify_items": items, "applied": applied, "history": hist, "seconds": secs3})
    rc4, doc4, secs4, hist4 = verify_until("ipa01")
    items4 = {i["key"]: i["outcome"] for i in (doc4 or {}).get("items", [])}
    sym = f"REPLICATION_FAILING@domain:{FQ['ipa01']}>{FQ['ipa02']}"
    # the agreement's recorded status may never have shown the failure (389-DS lag): then the peer-side root is
    # the only item; either way every item must be RESOLVED
    ok4 = bool(items4) and set(items4.values()) == {"RESOLVED"} and (sym in items4 or any(
        k.startswith("PEER_DS_NOT_ACCEPTING@") for k in items4)) and rc4 in (0, 4)
    _write({"scenario": "R02d-verify-after-fix-supplier", "result": "PASS" if ok4 else "FAIL",
            "problems": [] if ok4 else [f"verify on ipa01: exit {rc4}, items {items4}"], "exit": rc4,
            "verify_items": items4, "history": hist4, "pending_seen": any(h["exit"] == 3 for h in hist4),
            "seconds": secs4})
    restore("r02")


def r03() -> None:
    subprocess.run(["docker", "network", "disconnect", "ipanet", "ipa02"], capture_output=True)
    try:
        ind = {"ipa02_unreachable_from_ipa01": confirm(
            "ipa01", f"timeout 8 bash -c '</dev/tcp/{FQ['ipa02']}/389' && echo OPEN || echo CLOSED", "CLOSED")}
        t0 = now()
        trigger("ipa01", "domain")
        a = wait_agreement("ipa01", "ipa02", "domain", want_ok=False, since=t0, timeout=300)
        ind["agreement_status_observed"] = {"recorded_failure": "Error (0)" not in a.get(
            "nsds5replicalastupdatestatus", "Error (0)"), "observed": a.get("nsds5replicalastupdatestatus", "")[:200]}
        rc, doc, secs = tool("ipa01")
        details("ipa01", "r03-unreachable")
        text = json.dumps(doc or {}).lower()
        row("R03-peer-unreachable",
            {"status": ["PROBLEM_FOUND"], "primary": [f"PEER_UNREACHABLE@pair:{FQ['ipa01']}>{FQ['ipa02']}"],
             "roots": [f"PEER_UNREACHABLE@pair:{FQ['ipa01']}>{FQ['ipa02']}"], "offered": {}, "absent": ["LOCAL_"]},
            rc, doc, secs, ind, {"says_dead": " dead" in text or "decommission" in text})
    finally:
        subprocess.run(["docker", "network", "connect", "--ip", SERVERS["ipa02"], "ipanet", "ipa02"],
                       capture_output=True)
    restore("r03")


def r04() -> None:
    sh("ipa01", "cp /etc/hosts /root/hosts.lab; cp /etc/resolv.conf /root/resolv.lab; "
                f"grep -v {FQ['ipa02']} /root/hosts.lab > /etc/hosts; printf 'nameserver 127.0.0.2\\n' > /etc/resolv.conf")
    try:
        ind = {"ipa02_does_not_resolve_on_ipa01": confirm("ipa01", f"getent ahosts {FQ['ipa02']}; echo rc=$?", "rc=2")}
        t0 = now()
        trigger("ipa01", "domain")
        a = wait_agreement("ipa01", "ipa02", "domain", want_ok=False, since=t0, timeout=300)
        ind["agreement_status_observed"] = {"recorded_failure": "Error (0)" not in a.get(
            "nsds5replicalastupdatestatus", "Error (0)"), "observed": a.get("nsds5replicalastupdatestatus", "")[:200]}
        rc, doc, secs = tool("ipa01")
        details("ipa01", "r04-dns")
        row("R04-local-dns-break-for-peer",
            {"status": ["PROBLEM_FOUND"], "primary": [f"PEER_NAME_UNRESOLVED@pair:{FQ['ipa01']}>{FQ['ipa02']}"],
             "offered": {}, "absent": ["PEER_DS", "PEER_UNREACHABLE"]}, rc, doc, secs, ind)
    finally:
        sh("ipa01", "cp /root/hosts.lab /etc/hosts; cp /root/resolv.lab /etc/resolv.conf")
    restore("r04")


def r05() -> None:
    sh("ipa01", "systemctl stop krb5kdc")
    ind = {"kdc_stopped_on_ipa01": confirm("ipa01", "systemctl is-active krb5kdc", "inactive")}
    key = f"LOCAL_KDC_NOT_RUNNING@server:{FQ['ipa01']}"
    rc, doc, secs = tool("ipa01")
    details("ipa01", "r05-kdc")
    r = row("R05-local-kdc-stopped-and-fix",
            {"status": ["PROBLEM_FOUND"], "primary": [key], "roots": [key],
             "offered": {key: [["systemctl", "start", "krb5kdc.service"]]}, "no_google": True}, rc, doc, secs, ind,
            {"agreement_states": [f"{x['subject']}={x.get('state')}" for x in (doc or {}).get("relationships", [])]})
    applied = apply_printed("ipa01", doc, key) if r["result"] == "PASS" else {"applied": [], "all_ok": False}
    rc2, doc2, secs2, hist = verify_until("ipa01")
    items = {i["key"]: i["outcome"] for i in (doc2 or {}).get("items", [])}
    ok = applied["all_ok"] and items.get(key) == "RESOLVED" and "STILL_PRESENT" not in items.values() \
        and rc2 in (0, 4)
    _write({"scenario": "R05b-verify-after-fix", "result": "PASS" if ok else "FAIL",
            "problems": [] if ok else [f"verify: exit {rc2}, items {items}, applied {applied}"], "exit": rc2,
            "verify_items": items, "applied": applied, "history": hist, "seconds": secs2})
    restore("r05")


def r06() -> None:
    orig = sh("ipa03", "stat -c '%U:%G' /etc/dirsrv/ds.keytab").strip().splitlines()[-1]
    sh("ipa03", "chown root:root /etc/dirsrv/ds.keytab; chmod 0600 /etc/dirsrv/ds.keytab; "
                f"systemctl restart dirsrv@{INST}")
    try:
        ind = {"dirsrv_cannot_read_keytab": confirm("ipa03", "runuser -u dirsrv -- test -r /etc/dirsrv/ds.keytab; "
                                                             "echo rc=$?", "rc=1"),
               "original_owner": {"observed": orig, "confirmed": ":" in orig}}
        t0 = now()
        trigger("ipa03", "domain")
        a = wait_agreement("ipa03", "ipa02", "domain", want_ok=False, since=t0, timeout=300)
        ind["agreement_status_observed"] = {"recorded_failure": "Error (0)" not in a.get(
            "nsds5replicalastupdatestatus", "Error (0)"), "observed": a.get("nsds5replicalastupdatestatus", "")[:300]}
        rc, doc, secs = tool("ipa03")
        details("ipa03", "r06-keytab")
        key = f"DS_KEYTAB_PROBLEM@server:{FQ['ipa03']}"
        row("R06-ds-keytab-unreadable-disposable-replica",
            {"status": ["PROBLEM_FOUND"], "primary": [key], "roots": [key], "offered": {}}, rc, doc, secs, ind)
    finally:
        sh("ipa03", f"chown {shlex.quote(orig)} /etc/dirsrv/ds.keytab; systemctl restart dirsrv@{INST}")
    restore("r06")


def r07() -> None:
    sh("ipa02", "systemctl stop krb5kdc")
    try:
        ind = {"kdc_stopped_on_ipa02": confirm("ipa02", "systemctl is-active krb5kdc", "inactive")}
        sh("ipa02", f"systemctl restart dirsrv@{INST}")  # drop its cached tickets: it needs its (stopped) KDC now
        t0 = now()
        trigger("ipa02", "domain")
        a = wait_agreement("ipa02", "ipa01", "domain", want_ok=False, since=t0, timeout=300)
        ind["ipa02_to_ipa01_reports_error"] = {
            "confirmed": "Error (0)" not in a.get("nsds5replicalastupdatestatus", "Error (0)"),
            "observed": a.get("nsds5replicalastupdatestatus", "")[:300]}
        t1 = now()
        trigger("ipa01", "domain")
        b = wait_agreement("ipa01", "ipa02", "domain", want_ok=True, since=t1, timeout=240)
        ind["ipa01_to_ipa02_still_ok"] = {"confirmed": b.get("nsds5replicalastupdatestatus", "").startswith(
            "Error (0) Replica acquired"), "observed": b.get("nsds5replicalastupdatestatus", "")[:200]}
        rc, doc, secs = tool("ipa01")
        details("ipa01", "r07-peer-kdc")
        row("R07-peer-kdc-stopped-reverse-direction",
            {"status": ["PROBLEM_FOUND"], "present": ["REVERSE_REPLICATION_FAILING"], "offered": {},
             "absent": ["LOCAL_KDC", "PEER_DS"], "handoff_to": ["ipa02"],
             "relationships": {f"domain:{FQ['ipa01']}>{FQ['ipa02']}": "OK",
                               f"domain:{FQ['ipa02']}>{FQ['ipa01']}": "FAILING"}}, rc, doc, secs, ind)
    finally:
        sh("ipa02", "systemctl start krb5kdc")
    restore("r07")


def r08() -> None:
    sh("ipa02", "systemctl stop krb5kdc")
    sh("ipa03", f"systemctl stop dirsrv@{INST}")
    try:
        ind = {"kdc_stopped_on_ipa02": confirm("ipa02", "systemctl is-active krb5kdc", "inactive"),
               "ds_stopped_on_ipa03": confirm("ipa03", f"systemctl is-active dirsrv@{INST}", "inactive")}
        t0 = now()
        trigger("ipa02", "domain")
        a = wait_agreement("ipa02", "ipa03", "domain", want_ok=False, since=t0, timeout=240)
        ind["ipa02_to_ipa03_reports_error"] = {"confirmed": "Error (0)" not in a.get(
            "nsds5replicalastupdatestatus", "Error (0)"), "observed": a.get("nsds5replicalastupdatestatus", "")[:200]}
        rc, doc, secs = tool("ipa02")
        details("ipa02", "r08-multi")
        k1 = f"LOCAL_KDC_NOT_RUNNING@server:{FQ['ipa02']}"
        k2 = f"PEER_DS_NOT_ACCEPTING@server:{FQ['ipa03']}"
        row("R08-multi-cause-middle-server",
            {"status": ["PROBLEM_FOUND"], "primary": [k1], "roots": [k1, k2],
             "offered": {k1: [["systemctl", "start", "krb5kdc.service"]]}, "handoff_to": ["ipa03"]},
            rc, doc, secs, ind)
    finally:
        sh("ipa02", "systemctl start krb5kdc")
        sh("ipa03", f"systemctl start dirsrv@{INST}")
    restore("r08")


def r09() -> None:
    rc, doc, secs = tool("ipa02", f"--peer {FQ['ipa03']}")
    subjects = {x["subject"] for x in (doc or {}).get("relationships", [])}
    ok_scope = subjects == {f"domain:{FQ['ipa02']}>{FQ['ipa03']}", f"domain:{FQ['ipa03']}>{FQ['ipa02']}"}
    # a natural backoff of an agreement in scope is NOT_FULLY_VERIFIED (never green); anything else must be HEALTHY
    transient = [d["key"] for d in (doc or {}).get("diagnoses", []) if d.get("kind") == "TRANSIENT"]
    row("R09-budget-scope-peer", {"status": ["HEALTHY"] + (["NOT_FULLY_VERIFIED"] if transient else []), "roots": [],
                                  "offered": {}}, rc, doc, secs,
        {"scope_only_ipa03": {"confirmed": ok_scope, "observed": sorted(subjects)}},
        {"transient_seen": transient})


def r10() -> None:
    sh("ipa01", "id labuser >/dev/null 2>&1 || useradd -m labuser; chmod o+x /root; chmod -R o+rX /root/.local")
    rc, doc, secs = tool("ipa01", ticket=False, user="labuser")
    row("R10-non-root", {"status": ["NOT_FULLY_VERIFIED"], "roots": [], "offered": {}}, rc, doc, secs, {})


def r11() -> None:
    rc, out, err, secs = dx("ipa01", f"cd /root && rm -f repl-bundle.tar.gz && {TOOL} bundle --replication "
                                     "--output /root/repl-bundle.tar.gz", cc=ADMIN_CC, timeout=600)
    vrc, vout, verr, _ = dx("ipa01", f"{TOOL} bundle validate /root/repl-bundle.tar.gz")
    members = sh("ipa01", "tar -tzf /root/repl-bundle.tar.gz")
    leak = sh("ipa01", "mkdir -p /root/rb && tar -xzf /root/repl-bundle.tar.gz -C /root/rb && "
                       f"grep -rIl -e {FQ['ipa02']} -e {DOMAIN} -e {REALM} -e 172.31.0. /root/rb | wc -l")
    problems = []
    if rc != 0:
        problems.append(f"bundle exit {rc}: {(out + err)[-300:]}")
    if vrc != 0:
        problems.append(f"validate exit {vrc}")
    if "replication.json" not in members:
        problems.append("no replication.json")
    if leak.strip().splitlines()[-1:] != ["0"]:
        problems.append(f"raw lab names in the bundle ({leak.strip()[-50:]} files)")
    _write({"scenario": "R11-support-bundle", "result": "FAIL" if problems else "PASS", "problems": problems,
            "exit": rc, "validate_exit": vrc, "members": members.split(), "seconds": secs})


def r12() -> None:
    """SIMULATED: only ipa-diagnose's own process tree runs 15 minutes ahead (libfaketime); the servers' clocks
    are untouched (containers share the host's kernel clock, so a real skew cannot be made here)."""

    lib = sh("ipa01", "rpm -ql libfaketime 2>/dev/null | grep -E '/libfaketime\\.so\\.1$' | head -1").strip()
    if not lib:
        _write({"scenario": "R12-simulated-clock-offset", "result": "FAIL", "problems": ["libfaketime missing"]})
        return
    prefix = f"FAKETIME=+15m LD_PRELOAD={lib} "
    ind = {"process_clock_shifted": confirm("ipa01", f"{prefix}date -u +%s; date -u +%s")}
    rc, doc, secs = tool("ipa01", prefix=prefix)
    key = f"PAIR_CLOCK_SKEW@pair:{FQ['ipa01']}>{FQ['ipa02']}"
    text = json.dumps(doc or {}).lower()
    row("R12-simulated-clock-offset",
        {"status": ["PROBLEM_FOUND"], "primary": [key], "offered": {}, "absent": ["LOCAL_"]},
        rc, doc, secs, ind, {"simulated": "libfaketime +15m on ipa-diagnose only",
                             "claims_ntp_state_of_peer": "chronyd" in text and "stopped" in text})


def run() -> None:
    OUT.mkdir(exist_ok=True)
    for c in SERVERS:
        admin(c)
    for fn in (r01, r02, r03, r04, r05, r06, r07, r08, r09, r10, r11, r12):
        try:
            fn()
        except SystemExit as e:
            _write({"scenario": f"{fn.__name__}-aborted", "result": "FAIL", "problems": [str(e)]})
            break
        except Exception as e:  # noqa: BLE001 - a crashed scenario must still leave a FAIL row
            _write({"scenario": f"{fn.__name__}-crashed", "result": "FAIL", "problems": [f"{type(e).__name__}: {e}"]})
            try:
                restore(fn.__name__)
            except SystemExit:
                break


def summary() -> int:
    rows = [json.loads(line) for line in ROWS.read_text(encoding="utf-8").splitlines()] if ROWS.exists() else []
    by = {}
    for r in rows:
        by.setdefault(r["scenario"], []).append(r)
    failed = [s for s, rs in by.items() if any(r["result"] != "PASS" for r in rs)]
    missing = [s for s in REQUIRED if s not in by]
    passed = [s for s in REQUIRED if s in by and s not in failed]
    false_root = [r["scenario"] for r in rows if r.get("false_root_cause")]
    missed = [r["scenario"] for r in rows if r.get("missed_cause")]
    unsafe = [r["scenario"] for r in rows if r.get("unsafe_resolution")]
    print(f"replication lab: {len(passed)}/{len(REQUIRED)} PASS; failed {failed}; missing {missing}; "
          f"false root causes {false_root}; missed {missed}; unsafe {unsafe}")
    print(f"::notice title=replication lab summary::{len(passed)}/{len(REQUIRED)} PASS; failed {failed}; "
          f"missing {missing}; false root {false_root}; missed {missed}; unsafe {unsafe}")
    compact = [f"{r['scenario']}={r['result']} exit={r.get('exit')} primary={r.get('primary')} "
               f"offered={list((r.get('offered') or {}).keys())} ng={r.get('no_google')} t={r.get('seconds')}s "
               f"v={r.get('verify_items')} ipa={r.get('freeipa')}"
               + (f" PROBLEMS={r.get('problems')} DEBUG={r.get('debug')}" if r.get("problems") else "")
               + (f" OBS={ {k: v.get('observed', '')[:120] for k, v in (r.get('independent') or {}).items() if isinstance(v, dict)} }"
                  if r.get("result") != "PASS" or "agreement_status_observed" in (r.get("independent") or {}) else "")
               for r in rows]
    for i in range(0, len(compact), 2):
        print(f"::notice title=rows {i + 1}-{min(i + 2, len(compact))}::{' || '.join(compact[i:i + 2])[:3990]}")
    for r in rows:
        if r.get("chains"):
            print(f"::notice title=chains {r['scenario']}::{json.dumps(r['chains'])[:3900]}")
    return 1 if failed or missing or false_root or missed or unsafe else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "replica":
        replica(sys.argv[2], sys.argv[3], "--ca" in sys.argv[4:])
    elif cmd == "setup":
        setup()
    elif cmd == "run":
        run()
    elif cmd == "summary":
        sys.exit(summary())
    else:
        raise SystemExit(__doc__)
