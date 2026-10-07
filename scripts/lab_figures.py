#!/usr/bin/env python3
"""Terminal-session captures from disposable FreeIPA labs, for documentation figures (run on the CI host).

    python3 scripts/lab_figures.py wronggroup    # single server: wrong group on /etc/ipa/ca.crt
    python3 scripts/lab_figures.py certmask      # single server: certmonger masked and stopped
    python3 scripts/lab_figures.py alice         # server + enrolled client: SSSD stopped on the client
    python3 scripts/lab_figures.py replication   # three servers: Directory Server stopped on ipa02
    python3 scripts/lab_figures.py replay        # one plain container: --replay of a recorded fixture

Each job runs in its own fresh lab. The lab script plays the administrator: it injects one fault, confirms it with
an independent command, and then records a typed interactive session (scripts/pty_record.py) in which
ipa-diagnose runs blind, on a real pseudo-terminal. ipa-diagnose is the version installed from the pinned commit.
The lab never changes the tool. Only fake lab identities exist (lab.test, LAB.TEST).

Output: out/rec/NAME.raw/.json (the exact terminal bytes) and out/captures/NAME.txt/.json (the same bytes, base64,
for scripts/lab_captures.py emit, which publishes them as public annotations).
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

OUT = pathlib.Path("out")
REC = OUT / "rec"
CAP = OUT / "captures"
PW = os.environ.get("IPA_PASSWORD", "")
PIN = os.environ.get("PIN_COMMIT", "")
RUN_ID = os.environ.get("GITHUB_RUN_ID", "")
S, C = "ipa-s", "ipa-c"
INST = "LAB-TEST"
ADMIN_CC = "FILE:/root/admin.ccache"
USER_PW1, USER_PW2 = "LabUserPass1!", "LabUserPass2!"
CS_CFG = "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg"
SETUP_LOG = OUT / "lab-setup.log"


def _mask(text: str) -> str:
    return text.replace(PW, "***") if PW else text


def dx(c: str, cmd: str, user: str = "root", timeout: int = 300, stdin: str = None, cc: str = None):
    env = f"export KRB5CCNAME={cc}; " if cc else ""
    argv = ["docker", "exec", "-i", "-u", user, c, "bash", "-c", env + cmd]
    start = time.monotonic()
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, round(time.monotonic() - start, 3)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout", round(time.monotonic() - start, 3)


def sh(c: str, cmd: str, check: bool = False, **kw) -> str:
    rc, out, err, _ = dx(c, cmd, **kw)
    OUT.mkdir(exist_ok=True)
    with open(SETUP_LOG, "a", encoding="utf-8") as f:
        f.write(_mask(f"[{c}] $ {cmd}\n{out[-3000:]}{err[-1500:]}[rc={rc}]\n"))
    if check and rc != 0:
        raise SystemExit(f"lab step failed on {c}: {_mask(cmd)}: {_mask((out + err).strip()[-400:])}")
    return out + err


def confirm(c: str, cmd: str, expect: str, cc: str = None) -> dict:
    rc, out, err, _ = dx(c, cmd, cc=cc)
    text = (out + err).strip()
    ok = expect in text
    with open(SETUP_LOG, "a", encoding="utf-8") as f:
        f.write(_mask(f"[confirm {'OK' if ok else 'FAILED'}] [{c}] $ {cmd} -> {text[:300]}\n"))
    if not ok:
        raise SystemExit(f"the fault was not confirmed on {c}: {cmd!r} gave {_mask(text[:300])!r}, expected {expect!r}")
    return {"command": cmd, "observed": _mask(text[:300]), "confirmed": ok}


def record(c: str, name: str, scenario: str, host: str, cmds: list, env: tuple = (), cols: int = 100,
           cwd: str = "/root", prompt: str = None) -> dict:
    """One recorded terminal session inside container c, published through out/captures."""

    REC.mkdir(parents=True, exist_ok=True)
    CAP.mkdir(parents=True, exist_ok=True)
    subprocess.run(["docker", "cp", "scripts/pty_record.py", f"{c}:/tmp/pty_record.py"], check=True)
    argv = ["python3", "/tmp/pty_record.py", name, "--host", host, "--cols", str(cols), "--cwd", cwd]
    if prompt:
        argv += ["--prompt", prompt]
    for e in env:
        argv += ["--env", e]
    for cmd in cmds:
        argv += ["--cmd", cmd]
    rc, out, err, secs = dx(c, " ".join(shlex.quote(x) for x in argv), timeout=1500)
    print(out.strip() or err.strip())
    for ext in ("raw", "json"):
        subprocess.run(["docker", "cp", f"{c}:/tmp/rec/{name}.{ext}", str(REC / f"{name}.{ext}")], check=True)
    raw = (REC / f"{name}.raw").read_bytes()
    for bad in [x for x in (PW, "zqlivecanary") if len(x) >= 6]:
        if bad.encode().lower() in raw.lower():
            raise SystemExit(f"REFUSED: a forbidden value is in the recording {name}")
    meta = json.loads((REC / f"{name}.json").read_text())
    meta.update({"scenario": scenario, "container": c, "run_id": RUN_ID, "pin_commit": PIN,
                 "branch_head": os.environ.get("GITHUB_SHA", ""), "recorder_rc": rc,
                 "encoding": "txt = base64 of the raw terminal bytes", "raw_sha256": __import__("hashlib").sha256(raw).hexdigest()})
    (CAP / f"{name}.txt").write_text(base64.b64encode(raw).decode("ascii"), encoding="ascii")
    (CAP / f"{name}.json").write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    if rc != 0 or not meta.get("all_prompts_returned"):
        raise SystemExit(f"recording {name} did not complete cleanly: rc={rc} {meta}")
    return meta


# ---------------------------------------------------------------- story B and certificates: one server each


def wronggroup() -> None:
    sh(S, f"chmod 0660 {CS_CFG}", check=True)  # lab setup: the Fedora image ships CS.cfg as 0664, a separate finding
    sh(S, "chgrp apache /etc/ipa/ca.crt", check=True)
    ind = confirm(S, "stat -c '%a %U:%G' /etc/ipa/ca.crt", "root:apache")
    rc, out, err, _ = dx(S, "ipa-healthcheck --failures-only --output-type json")
    if "/etc/ipa/ca.crt" not in out:
        raise SystemExit("ipa-healthcheck does not report /etc/ipa/ca.crt on this image; stopping")
    record(S, "fig-wronggroup", "wrong group on /etc/ipa/ca.crt (apache instead of root), fresh single-server lab",
           "ipa01", ["ipa-diagnose"])
    print(json.dumps(ind))


def certmask() -> None:
    sh(S, f"chmod 0660 {CS_CFG}", check=True)  # lab setup: keep the CS.cfg quirk of the image out of this scenario
    sh(S, "systemctl mask --runtime certmonger.service; systemctl stop certmonger.service", check=True)
    confirm(S, "systemctl is-active certmonger.service", "inactive")
    confirm(S, "systemctl show -p LoadState --value certmonger.service", "masked")
    record(S, "fig-certmonger-masked", "certmonger masked and stopped, fresh single-server lab", "ipa01",
           ["ipa-diagnose"])


# ---------------------------------------------------------------- story A: server + enrolled client


def alice() -> None:
    sh(S, f"echo {shlex.quote(PW)} | kinit admin >/dev/null", check=True)
    sh(S, "ipa hbacrule-disable allow_all", check=True)
    sh(S, "ipa user-add alice --first=alice --last=Lab", check=True)
    sh(S, "ipa passwd alice >/dev/null", stdin=f"{USER_PW1}\n{USER_PW1}\n", check=True)
    sh(S, "ipa hbacrule-add r_client", check=True)
    sh(S, "ipa hbacrule-add-user r_client --users=alice", check=True)
    sh(S, "ipa hbacrule-add-host r_client --hosts=client1.lab.test", check=True)
    sh(S, "ipa hbacrule-add-service r_client --hbacsvcs=sshd", check=True)
    sh(C, f"echo {shlex.quote(PW)} | kinit admin >/dev/null", cc=ADMIN_CC, check=True)
    # lab setup: the demo user gets a valid password (an administrator-set password is expired until first use)
    sh(C, f"printf '{USER_PW1}\\n{USER_PW2}\\n{USER_PW2}\\n' | kinit alice", cc="FILE:/tmp/alice-pw.ccache", check=True)
    sh(C, "kdestroy -c /tmp/alice-pw.ccache", check=False)
    exp = sh(S, "ipa user-show alice --all --raw | grep -i krbpasswordexpiration")
    print("alice password expiration after the change:", exp.strip())
    sh(C, "sss_cache -E; systemctl restart sssd; sleep 5; getent passwd alice >/dev/null", check=False)
    confirm(C, "getent passwd alice", "alice:")
    ind0 = confirm(C, "systemctl is-active sssd", "active")
    sh(C, "systemctl stop sssd", check=True)
    confirm(C, "systemctl is-active sssd", "inactive")
    cmd = "ipa-diagnose client --user alice --service sshd"
    scen = "SSSD stopped on enrolled client1, alice has a valid password, fresh client lab"
    record(C, "fig-alice-client-w100", scen, "client1", [cmd], cols=100)
    record(C, "fig-alice-client-w130", scen + " (same state, wider terminal)", "client1", [cmd], cols=130)
    record(C, "fig-alice-access-runtime", scen + " (access --runtime, admin ticket)", "client1",
           ["ipa-diagnose access alice client1.lab.test sshd --runtime"], env=(f"KRB5CCNAME={ADMIN_CC}",), cols=100)
    record(C, "alice-fix-verify", scen + " (the printed fix, then verify)", "client1",
           ["systemctl start sssd.service", "@sleep 6", "ipa-diagnose client --verify --user alice --service sshd"],
           cols=100)
    print(json.dumps(ind0))


# ---------------------------------------------------------------- story R: three servers


def replication() -> None:
    import lab_replication as LR  # the existing lab helpers (agreement reads, triggers); imported, not changed

    for c in ("ipa01", "ipa02"):
        LR.admin(c)
    if not LR.wait_green(600):
        raise SystemExit(f"replication is not green before the fault: {LR.LAST_PENDING}")
    LR.sh("ipa02", f"systemctl stop dirsrv@{INST}", check=True)
    if not LR.confirm("ipa02", f"systemctl is-active dirsrv@{INST}", "inactive")["confirmed"]:
        raise SystemExit("dirsrv on ipa02 is not stopped")
    c1 = LR.confirm("ipa01", "timeout 5 bash -c '</dev/tcp/ipa02.lab.test/389' && echo OPEN || echo CLOSED", "CLOSED")
    if not c1["confirmed"]:
        raise SystemExit("port 389 on ipa02 is not refused from ipa01")
    t0 = LR.now()
    LR.trigger("ipa01", "domain")
    a = LR.wait_agreement("ipa01", "ipa02", "domain", want_ok=False, since=t0)
    print("agreement status seen by the lab:", a.get("nsds5replicalastupdatestatus", "")[:160])
    env = (f"KRB5CCNAME={ADMIN_CC}",)
    scen = "Directory Server stopped on ipa02, three-server lab"
    record("ipa01", "fig-repl-1-ipa01", scen + ", seen from ipa01", "ipa01", ["ipa-diagnose replication"], env=env)
    record("ipa02", "fig-repl-2-ipa02", scen + ", seen on ipa02", "ipa02",
           ["ipa-diagnose replication --peer ipa01.lab.test"], env=env)
    record("ipa02", "fig-repl-3-verify", scen + ", the printed fix, then verify", "ipa02",
           [f"systemctl start dirsrv@{INST}.service", "@sleep 3", "ipa-diagnose replication --verify"], env=env)
    print(json.dumps(c1))


# ---------------------------------------------------------------- certificates, replay (no FreeIPA lab)


def replay() -> None:
    sh("rp", f"cd /root/ipa-diagnose && git rev-parse HEAD", check=True)
    confirm("rp", "cd /root/ipa-diagnose && git rev-parse HEAD", PIN)
    record("rp", "fig-ds-cert-replay", "REPLAY of a constructed fixture: Directory Server certificate expires in 12 days",
           "lab", ["ipa-diagnose --replay tests/fixtures/resolution/ds-certificate-expiring"],
           cwd="/root/ipa-diagnose", prompt="[root@lab ipa-diagnose]# ")


JOBS = {"wronggroup": wronggroup, "certmask": certmask, "alice": alice, "replication": replication, "replay": replay}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in JOBS:
        print(__doc__)
        sys.exit(2)
    OUT.mkdir(exist_ok=True)
    JOBS[sys.argv[1]]()
