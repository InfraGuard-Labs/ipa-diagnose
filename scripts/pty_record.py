#!/usr/bin/env python3
"""Record a typed interactive bash session in a real pseudo-terminal. Run INSIDE a lab container (standard library
only). The shell echoes the typed commands and prints its real prompt; ipa-diagnose sees a terminal, so it prints
whatever it prints on a terminal (colours included). Nothing is added to or removed from the byte stream.

    python3 pty_record.py NAME --host ipa01 --cmd 'ipa-diagnose' [--cmd '...'] [--cols 100] [--env K=V ...]
                          [--cwd /root] [--prompt '[root@ipa01 ~]# '] [--out /tmp/rec]

Writes OUT/NAME.raw (the exact bytes the terminal received) and OUT/NAME.json (commands, exit codes, size, times).
Each command is typed character by character; the next one is typed once the prompt is back.
"""

from __future__ import annotations

import argparse
import datetime
import fcntl
import json
import os
import pathlib
import pty
import select
import signal
import struct
import sys
import termios
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--host", required=True, help="short host name shown in the prompt")
    ap.add_argument("--cmd", action="append", required=True)
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--rows", type=int, default=50)
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument("--cwd", default="/root")
    ap.add_argument("--prompt", default=None)
    ap.add_argument("--out", default="/tmp/rec")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--keystroke-delay", type=float, default=0.02)
    a = ap.parse_args()

    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rc_file = out / f"{a.name}.rc"
    rc_file.write_text("")
    prompt = a.prompt or f"[root@{a.host} ~]# "
    rcfile = out / f"{a.name}.bashrc"
    rcfile.write_text(
        "bind 'set enable-bracketed-paste off'\n"
        "export HISTFILE=/dev/null\n"
        "PS1='[\\u@\\h \\W]\\$ '\n"
        f"PROMPT_COMMAND='echo $? >> {rc_file}'\n"
    )
    env = {"TERM": "xterm-256color", "LANG": "C.UTF-8", "HOME": "/root", "USER": "root", "LOGNAME": "root",
           "PATH": "/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    for kv in a.env:
        k, _, v = kv.partition("=")
        env[k] = v

    started = datetime.datetime.now(datetime.timezone.utc)
    pid, fd = pty.fork()
    if pid == 0:  # child: the terminal size is set before the shell starts, so it (and rich) see it from the start
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", a.rows, a.cols, 0, 0))
        os.chdir(a.cwd)
        os.execvpe("bash", ["bash", "--noprofile", "--rcfile", str(rcfile), "-i"], env)
    data = bytearray()
    want = prompt.encode()

    def pump(wait: float) -> None:
        r, _, _ = select.select([fd], [], [], wait)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            data.extend(chunk)

    def wait_prompt(after: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pump(0.2)
            if len(data) > after and bytes(data[-len(want):]) == want:
                time.sleep(0.4)  # let any trailing output arrive
                pump(0.1)
                return bytes(data[-len(want):]) == want
        return False

    ok = wait_prompt(-1, 30)
    typed = []
    for cmd in a.cmd:
        if not ok:
            break
        if cmd.startswith("@sleep "):  # a pause between commands (the administrator reads the screen); nothing typed
            time.sleep(float(cmd.split()[1]))
            continue
        time.sleep(0.6)
        mark = len(data)
        for ch in cmd:
            os.write(fd, ch.encode())
            pump(a.keystroke_delay)
        time.sleep(0.25)
        os.write(fd, b"\r")
        typed.append(cmd)
        ok = wait_prompt(mark + len(cmd), a.timeout)
    time.sleep(0.5)
    pump(0.2)
    ended = datetime.datetime.now(datetime.timezone.utc)
    try:
        os.kill(pid, signal.SIGHUP)
        os.waitpid(pid, 0)
    except OSError:
        pass
    (out / f"{a.name}.raw").write_bytes(bytes(data))
    codes = [int(x) for x in rc_file.read_text().split() if x.lstrip("-").isdigit()]
    meta = {"name": a.name, "host": a.host, "prompt": prompt, "commands": typed, "all_prompts_returned": ok,
            "exit_codes": codes[1:], "cols": a.cols, "rows": a.rows, "term": env["TERM"], "cwd": a.cwd,
            "env_set": [kv.split("=", 1)[0] + "=" + kv.split("=", 1)[1] for kv in a.env],
            "started": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "ended": ended.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bytes": len(data)}
    (out / f"{a.name}.json").write_text(json.dumps(meta, indent=1, sort_keys=True))
    print(f"recorded {a.name}: {len(data)} bytes, exit codes {meta['exit_codes']}, prompt back: {ok}")
    return 0 if ok and len(typed) == len([c for c in a.cmd if not c.startswith("@sleep ")]) else 1


if __name__ == "__main__":
    sys.exit(main())
