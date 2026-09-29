"""A minimal, read-only DNS SRV query over UDP (standard library only).

FreeIPA clients do not always have ``dig`` (bind-utils), and glibc's ``getent`` cannot ask for SRV records. SSSD and
the Kerberos library look SRV records up through the resolvers in ``/etc/resolv.conf``; this asks the same resolvers
the same question. One question per resolver, a fixed timeout, at most three resolvers, and a strictly bounded parser
(the answer is untrusted input: every offset is checked, compression pointers may only point backwards and are
followed a bounded number of times).
"""

from __future__ import annotations

import os
import random
import socket
import struct
from typing import Dict, List, Optional, Tuple

RESOLV_CONF = "/etc/resolv.conf"
MAX_RESOLVERS = 3
MAX_ANSWERS = 32
_QTYPE_SRV = 33
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DnsError(ValueError):
    pass


def read_resolv_conf(path: str = RESOLV_CONF) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"nameservers": [], "search": []}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read(65536)
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split(";", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver" and len(out["nameservers"]) < MAX_RESOLVERS:
            addr = parts[1]
            try:
                socket.inet_pton(socket.AF_INET6 if ":" in addr else socket.AF_INET, addr.split("%", 1)[0])
            except (OSError, ValueError):
                continue
            out["nameservers"].append(addr)
        elif parts and parts[0] in ("search", "domain"):
            out["search"] = [p for p in parts[1:7] if len(p) <= 253]
    return out


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise DnsError("invalid label")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(msg: bytes, off: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumps, end, pos = 0, None, off
    while True:
        if pos >= len(msg):
            raise DnsError("truncated name")
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise DnsError("truncated pointer")
            ptr = ((n & 0x3F) << 8) | msg[pos + 1]
            if ptr >= pos or jumps >= 16:  # only backwards, bounded: no loops
                raise DnsError("bad compression pointer")
            if end is None:
                end = pos + 2
            pos, jumps = ptr, jumps + 1
            continue
        if n & 0xC0:
            raise DnsError("unsupported label type")
        if pos + 1 + n > len(msg):
            raise DnsError("truncated label")
        labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        if len(labels) > 127:
            raise DnsError("name too long")
        pos += 1 + n
    return ".".join(labels).lower(), (end if end is not None else pos)


def parse_srv_response(msg: bytes, qid: int) -> Tuple[str, List[Dict[str, object]]]:
    if len(msg) < 12:
        raise DnsError("short answer")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid or not flags & 0x8000:
        raise DnsError("not an answer to this question")
    rcode = _RCODES.get(flags & 0x000F, f"RCODE{flags & 0x000F}")
    off = 12
    for _ in range(min(qd, 4)):
        _, off = _read_name(msg, off)
        off += 4
    answers: List[Dict[str, object]] = []
    for _ in range(min(an, MAX_ANSWERS)):
        _, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise DnsError("truncated record")
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        if off + rdlen > len(msg):
            raise DnsError("truncated record data")
        if rtype == _QTYPE_SRV and rdlen >= 7:
            prio, weight, port = struct.unpack("!HHH", msg[off:off + 6])
            target, _ = _read_name(msg, off + 6)
            answers.append({"priority": prio, "weight": weight, "port": port, "target": target[:253]})
        off += rdlen
    return rcode, answers


def query_srv(name: str, nameservers: List[str], timeout: float = 3.0) -> Dict[str, object]:
    """{"rcode": NOERROR|NXDOMAIN|...|TIMEOUT|NO_RESOLVER, "resolver": addr, "answers": [...]} for the first resolver
    that answers (as the stub resolver does)."""

    if not nameservers:
        return {"rcode": "NO_RESOLVER", "resolver": None, "answers": []}
    last: Dict[str, object] = {"rcode": "TIMEOUT", "resolver": None, "answers": []}
    for ns in nameservers[:MAX_RESOLVERS]:
        qid = random.SystemRandom().randrange(0, 65536)
        packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", _QTYPE_SRV, 1)
        family = socket.AF_INET6 if ":" in ns else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((ns.split("%", 1)[0], 53))
                s.send(packet)
                data = s.recv(4096)
            rcode, answers = parse_srv_response(data, qid)
            return {"rcode": rcode, "resolver": ns, "answers": answers}
        except socket.timeout:
            last = {"rcode": "TIMEOUT", "resolver": ns, "answers": []}
        except (OSError, DnsError) as e:
            last = {"rcode": "ERROR", "resolver": ns, "answers": [], "error": type(e).__name__}
    return last


def uses_stub_resolver(nameservers: List[str]) -> bool:
    return any(ns.startswith("127.") for ns in nameservers) and os.path.exists("/run/systemd/resolve")
