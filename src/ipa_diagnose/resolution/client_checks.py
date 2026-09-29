"""Client-side checks for `ipa-diagnose client` (Slice 4), part of the ONE closed check registry
(:data:`ipa_diagnose.resolution.checks.REGISTRY`).

Every check here is a fixed argv or a fixed file read, parameters are typed and validated before they are used, output
is bounded and sanitized, and nothing secret is ever returned: the keytab is listed without keys (``klist -k``, never
``-K``), sssd.conf is reduced to a fixed set of non-secret options, log lines are reduced to known signal counts plus
one redacted example, and a ``getent`` answer keeps only the name, UID and GID.

Side effects are declared per check (``CheckSpec.side_effects``) from the documented/observed behaviour of the tool,
not from intent (the certmonger lesson: ``getcert list`` starting certmonger). The planner shows them.
"""

from __future__ import annotations

import configparser
import datetime
import email.utils
import glob
import os
import re
import shutil
import socket
import ssl
import stat as _stat
import tempfile
import time
from typing import Any, Dict, List, Optional

from ipa_diagnose.resolution.checks import (
    DENIED, FAILED, NOT_RUN, OK, CheckResult, CheckSpec, _redact_log_line, _res, _run,
)
from ipa_diagnose.textsafe import sanitize_text

IPA_CONF = "/etc/ipa/default.conf"
IPA_CA = "/etc/ipa/ca.crt"
KEYTAB = "/etc/krb5.keytab"
SSSD_CONF = "/etc/sssd/sssd.conf"
SSSD_CONF_D = "/etc/sssd/conf.d"
NSSWITCH = "/etc/nsswitch.conf"
PAM_D = "/etc/pam.d"
SSS_DB = "/var/lib/sss/db"
SSSD_LOG_DIR = "/var/log/sssd"

# sssd.conf options that may be recorded. Anything else (in particular ldap_default_authtok and every *_password /
# *authtok* / *secret* option) is never read into the result.
SSSD_KEYS = frozenset({
    "id_provider", "auth_provider", "access_provider", "chpass_provider", "ipa_server", "ipa_backup_server",
    "ipa_domain", "ipa_hostname", "krb5_realm", "krb5_server", "cache_credentials", "enumerate",
    "entry_cache_timeout", "offline_credentials_expiration", "use_fully_qualified_names", "ldap_uri",
    "dns_discovery_domain", "services", "domains", "simple_allow_users", "simple_allow_groups", "debug_level",
    "krb5_store_password_if_offline", "ipa_hbac_refresh", "ipa_hbac_support_srchost", "pam_id_timeout",
    "entry_negative_timeout", "memcache_timeout",
})
_SECRETISH = re.compile(r"(?i)pass|authtok|secret|token|pin|key")


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _c(v: Any, n: int = 120) -> str:
    return sanitize_text(v, n)


# --------------------------------------------------------------------------- enrollment / local configuration


def _read_ipa_conf() -> Dict[str, str]:
    from ipa_diagnose.access.api import read_ipa_conf

    return read_ipa_conf(IPA_CONF)


def _client_conf(params):
    exists = os.path.isfile(IPA_CONF)
    conf = _read_ipa_conf() if exists else {}
    from ipa_diagnose.access.api import _server_from_conf
    from ipa_diagnose.resolution import types as T

    fields = {
        "conf_present": exists, "conf_readable": bool(conf),
        "domain": T.validate("fqdn", conf.get("domain", "")) if conf else None,
        "server": _server_from_conf(conf) if conf else None,
        "host": T.validate("fqdn", conf.get("host", "")) if conf else None,
        "ca_present": os.path.isfile(IPA_CA),
        "kernel_hostname": _c(socket.gethostname(), 253).lower(),
        "is_ipa_server": os.path.isdir("/var/lib/ipa/sysrestore") and os.path.exists("/usr/sbin/ipactl"),
    }
    fields["realm"] = T.validate("realm", conf.get("realm", "")) if conf else None
    if fields["host"] and fields["realm"]:
        fields["host_principal"] = f"host/{fields['host']}@{fields['realm']}"
    else:
        fields["host_principal"] = None
    if not exists:
        disp = f"{IPA_CONF} does not exist"
    elif not conf:
        disp = f"{IPA_CONF} exists but is unreadable or has no [global] section"
    else:
        disp = (f"IPA client configuration: domain {fields['domain'] or '?'}, realm {fields['realm'] or '?'}, "
                f"server {fields['server'] or '?'}, this host {fields['host'] or '?'}")
    return _res("client.ipa_conf", params, OK, fields, disp, f"read {IPA_CONF}")


def _versions(params):
    def rpm(*names: str) -> Optional[str]:
        for n in names:
            rc, out, _ = _run(["rpm", "-q", "--qf", "%{VERSION}", n], timeout=10)
            if rc == 0 and re.fullmatch(r"[0-9][0-9A-Za-z._+~-]{0,40}", out.strip()):
                return out.strip()
        return None

    sssd = rpm("sssd-common", "sssd")
    if sssd is None:
        rc, out, _ = _run(["sssd", "--version"], timeout=10)
        if rc == 0 and re.fullmatch(r"[0-9][0-9A-Za-z._+~-]{0,40}", out.strip()):
            sssd = out.strip()
    client = rpm("freeipa-client", "ipa-client")
    osid = osver = None
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
            for line in f.read(65536).splitlines():
                k, _, v = line.partition("=")
                v = v.strip().strip('"')
                if k == "ID":
                    osid = _c(v, 30).lower()
                elif k == "VERSION_ID":
                    osver = _c(v, 20)
    except OSError:
        pass
    fields = {"sssd": sssd, "ipa_client": client, "os": osid, "os_version": osver,
              "systemd": os.path.isdir("/run/systemd/system")}
    return _res("client.versions", params, OK, fields,
                f"SSSD {sssd or 'unknown'}, IPA client {client or 'unknown'}, {osid or '?'} {osver or ''}".strip(),
                "rpm -q sssd-common freeipa-client; read /etc/os-release")


def _parse_sssd_conf(texts: List[str]) -> Dict[str, Dict[str, str]]:
    sections: Dict[str, Dict[str, str]] = {}
    for text in texts:
        cp = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
        cp.optionxform = str.lower  # type: ignore[assignment]
        try:
            cp.read_string(text[:262144])
        except configparser.Error:
            raise ValueError("unparsable")
        for sec in cp.sections()[:64]:
            dst = sections.setdefault(sec.strip()[:200], {})
            for k, v in cp.items(sec):
                if k in SSSD_KEYS and not _SECRETISH.search(k):
                    dst[k] = _c(v, 300)
    return sections


def _sssd_conf(params):
    try:
        st = os.stat(SSSD_CONF)
    except FileNotFoundError:
        return _res("sssd.conf", params, OK, {"present": False}, f"{SSSD_CONF} does not exist", f"read {SSSD_CONF}")
    except PermissionError:
        return _res("sssd.conf", params, DENIED, {}, f"{SSSD_CONF}: permission denied (run as root)")
    texts = []
    try:
        with open(SSSD_CONF, encoding="utf-8", errors="replace") as f:
            texts.append(f.read(262144))
        for snip in sorted(glob.glob(os.path.join(SSSD_CONF_D, "*.conf")))[:32]:
            with open(snip, encoding="utf-8", errors="replace") as f:
                texts.append(f.read(262144))
    except PermissionError:
        return _res("sssd.conf", params, DENIED, {}, f"{SSSD_CONF}: permission denied (run as root)")
    except OSError as e:
        return _res("sssd.conf", params, FAILED, {}, f"{SSSD_CONF}: {type(e).__name__}")
    try:
        sections = _parse_sssd_conf(texts)
    except ValueError:
        return _res("sssd.conf", params, OK, {"present": True, "parsable": False, "mode": "%04o" % (st.st_mode & 0o7777)},
                    f"{SSSD_CONF} cannot be parsed", f"read {SSSD_CONF}")
    domains = []
    for sec, opts in sections.items():
        if sec.lower().startswith("domain/"):
            domains.append({"name": _c(sec[len("domain/"):], 200), **{k: opts.get(k) for k in (
                "id_provider", "access_provider", "ipa_server", "ipa_domain", "ipa_hostname", "krb5_realm",
                "cache_credentials", "dns_discovery_domain", "ldap_uri", "use_fully_qualified_names")}})
    active = [d.strip() for d in (sections.get("sssd", {}).get("domains") or "").split(",") if d.strip()]
    ipa_domains = [d for d in domains if (d.get("id_provider") or "").lower() == "ipa"]
    first = next((d for d in ipa_domains if d["name"] in active), ipa_domains[0] if ipa_domains else None)
    ipa_server = [s.strip() for s in ((first or {}).get("ipa_server") or "").split(",") if s.strip()]
    fields = {
        "present": True, "parsable": True, "mode": "%04o" % (st.st_mode & 0o7777), "owner_uid": st.st_uid,
        "active_domains": [_c(d, 200) for d in active[:16]], "domains": domains[:16],
        "ipa_domain": first["name"] if first else None,
        "ipa_domain_active": bool(first and first["name"] in active),
        "access_provider": (first or {}).get("access_provider") or ("ipa" if first else None),
        "ipa_server": [_c(s, 253) for s in ipa_server[:8]],
        "uses_srv": any(s == "_srv_" for s in ipa_server) or (first is not None and not ipa_server),
        "ipa_hostname": (first or {}).get("ipa_hostname"),
        "cache_credentials": (first or {}).get("cache_credentials"),
        "fully_qualified_names": ((first or {}).get("use_fully_qualified_names") or "").lower() in ("true", "yes", "1"),
        "services": sections.get("sssd", {}).get("services"),
    }
    disp = (f"sssd.conf: IPA domain {fields['ipa_domain']}" + ("" if fields["ipa_domain_active"] else " (NOT active)")
            + f", servers {', '.join(fields['ipa_server']) or '(SRV discovery)'}, access_provider "
            f"{fields['access_provider']}") if first else "sssd.conf has no domain with id_provider = ipa"
    return _res("sssd.conf", params, OK, fields, disp, f"read {SSSD_CONF} (non-secret options only)")


# --------------------------------------------------------------------------- DNS / network / time / TLS


def _resolvers(params):
    from ipa_diagnose.client.dnsq import read_resolv_conf, uses_stub_resolver

    rc = read_resolv_conf()
    fields = {"nameservers": rc["nameservers"], "search": [_c(s, 253) for s in rc["search"]],
              "stub": uses_stub_resolver(rc["nameservers"])}
    return _res("dns.resolvers", params, OK, fields,
                f"{len(rc['nameservers'])} resolver(s) in /etc/resolv.conf"
                + (f"; search {' '.join(fields['search'])}" if fields["search"] else ""), "read /etc/resolv.conf")


def _address(params):
    name = params["name"]
    argv = ["getent", "ahosts", name]
    start = time.monotonic()
    rc, out, err = _run(argv, timeout=15)
    secs = round(time.monotonic() - start, 3)
    if rc is None:
        return _res("dns.address", params, NOT_RUN, {}, err, "getent ahosts " + name)
    addrs = []
    for line in out.splitlines():
        a = line.split()[0] if line.split() else ""
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in a else socket.AF_INET, a)
        except (OSError, ValueError):
            continue
        if a not in addrs:
            addrs.append(a)
    fields = {"resolved": bool(addrs), "addresses": addrs[:8], "seconds": secs, "exit": rc}
    return _res("dns.address", params, OK, fields,
                f"{name} resolves to {', '.join(addrs[:3])}" if addrs else f"{name} does not resolve (getent exit {rc})",
                "getent ahosts " + name)


def _srv(params):
    from ipa_diagnose.client.dnsq import query_srv, read_resolv_conf

    r = query_srv(params["name"], read_resolv_conf()["nameservers"])
    answers = [{"target": _c(a["target"], 253), "port": a["port"], "priority": a["priority"]}
               for a in r["answers"]][:16]
    fields = {"rcode": r["rcode"], "resolver": r["resolver"], "answers": answers, "found": bool(answers)}
    disp = (f"{params['name']}: {len(answers)} record(s) ({', '.join(a['target'] for a in answers[:3])})" if answers
            else f"{params['name']}: no record ({r['rcode']})")
    return _res("dns.srv", params, OK, fields, disp, f"DNS SRV query {params['name']} (resolvers of /etc/resolv.conf)")


def _tcp(params):
    host, port = params["host"], int(params["port"])
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=5):
            state = "open"
    except socket.timeout:
        state = "timeout"
    except ConnectionRefusedError:
        state = "refused"
    except socket.gaierror:
        state = "unresolvable"
    except OSError as e:
        state = "unreachable" if getattr(e, "errno", None) in (101, 113) else "error"
    fields = {"state": state, "open": state == "open", "seconds": round(time.monotonic() - start, 3)}
    return _res("net.tcp", params, OK, fields, f"TCP {host}:{port}: {state}", f"TCP connect {host}:{port} (5 s)")


def _https(params):
    """One HTTPS HEAD request to the IPA server: does TLS verify with this host's IPA CA (/etc/ipa/ca.crt), and what
    time does the server's Date header say. No credentials are sent."""

    server = params["server"]
    fields: Dict[str, Any] = {"ca_file": os.path.isfile(IPA_CA)}
    import http.client

    def head(ctx) -> "http.client.HTTPResponse":
        conn = http.client.HTTPSConnection(server, 443, timeout=10, context=ctx)
        try:
            conn.request("HEAD", "/ipa/config/ca.crt", headers={"User-Agent": "ipa-diagnose"})
            resp = conn.getresponse()
            return resp
        finally:
            conn.close()

    before = _now()
    resp = None
    if not fields["ca_file"]:
        fields.update(tls="no_ca_file", tls_ok=None)
    else:
        try:
            ctx = ssl.create_default_context(cafile=IPA_CA)
            resp = head(ctx)
            fields.update(tls="verified", tls_ok=True)
        except ssl.SSLCertVerificationError as e:
            reason = "hostname_mismatch" if "hostname" in str(e).lower() or "match" in str(e).lower() else "untrusted"
            fields.update(tls=reason, tls_ok=False, tls_detail=_c(getattr(e, "verify_message", "") or e, 160))
        except ssl.SSLError as e:
            fields.update(tls="tls_error", tls_ok=False, tls_detail=_c(type(e).__name__, 60))
        except socket.timeout:
            fields.update(tls="timeout", tls_ok=None)
        except ConnectionRefusedError:
            fields.update(tls="refused", tls_ok=None)
        except OSError as e:
            fields.update(tls="unreachable", tls_ok=None, tls_detail=_c(type(e).__name__, 60))
    date_source = "verified TLS"
    if resp is None and fields.get("tls_ok") is False:
        # read only the Date header over an unverified connection, labelled as such (for the clock comparison)
        try:
            unverified = ssl.create_default_context()
            unverified.check_hostname = False
            unverified.verify_mode = ssl.CERT_NONE
            resp = head(unverified)
            date_source = "unverified TLS (the server's identity was not proven)"
        except OSError:
            resp = None
    after = _now()
    offset = None
    if resp is not None:
        fields["http_status"] = resp.status
        date = resp.getheader("Date")
        try:
            server_time = email.utils.parsedate_to_datetime(date) if date else None
        except (TypeError, ValueError):
            server_time = None
        if server_time is not None and server_time.tzinfo is not None:
            local_mid = before + (after - before) / 2
            offset = round((local_mid - server_time).total_seconds(), 1)
    fields.update(offset_seconds=offset, offset_abs=None if offset is None else abs(offset),
                  date_source=date_source if offset is not None else None,
                  round_trip=round((after - before).total_seconds(), 3))
    disp = f"HTTPS to {server}: TLS {fields['tls']}"
    if offset is not None:
        disp += f"; this host's clock is {abs(offset):.0f} s {'ahead of' if offset >= 0 else 'behind'} the server's"
    return _res("ipa.https", params, OK, fields, disp, f"HTTPS HEAD https://{server}/ipa/config/ca.crt "
                "(CA /etc/ipa/ca.crt; no credentials)")


# --------------------------------------------------------------------------- Kerberos / keytab / IPA API


_KT_LINE = re.compile(r"^\s*(\d+)\s+(?:\S+\s+\S+\s+)?(\S+@\S+)\s*(?:\(.*\))?\s*$")


def _keytab(params):
    fields: Dict[str, Any] = {}
    try:
        st = os.lstat(KEYTAB)
    except FileNotFoundError:
        return _res("krb.keytab", params, OK, {"present": False}, f"{KEYTAB} does not exist", f"stat {KEYTAB}")
    except PermissionError:
        return _res("krb.keytab", params, DENIED, {}, f"{KEYTAB}: permission denied (run as root)")
    fields.update(present=True, mode="%04o" % (st.st_mode & 0o7777), owner_uid=st.st_uid,
                  is_regular=_stat.S_ISREG(st.st_mode), size=st.st_size,
                  world_or_group_readable=bool(st.st_mode & 0o044))
    if not _is_root() and not os.access(KEYTAB, os.R_OK):
        return _res("krb.keytab", params, DENIED, fields, f"{KEYTAB}: not readable (run as root)", f"stat {KEYTAB}")
    argv = ["klist", "-k", KEYTAB]  # principals and key versions only: never -K (key bytes)
    rc, out, err = _run(argv, timeout=10)
    if rc is None:
        return _res("krb.keytab", params, NOT_RUN, fields, err, " ".join(argv))
    entries = []
    for line in out.splitlines():
        m = _KT_LINE.match(line)
        if m:
            entries.append({"kvno": int(m.group(1)), "principal": _c(m.group(2), 300)})
    principals = sorted({e["principal"] for e in entries})
    fields.update(readable=rc == 0, entries=len(entries), principals=principals[:32],
                  kvnos={p: sorted({e["kvno"] for e in entries if e["principal"] == p})[-3:] for p in principals[:32]})
    if rc != 0:
        fields["error"] = _c(err, 160)
        return _res("krb.keytab", params, OK, fields, f"{KEYTAB}: klist -k failed ({fields['error']})", " ".join(argv))
    return _res("krb.keytab", params, OK, fields,
                f"{KEYTAB}: {len(entries)} key(s) for {len(principals)} principal(s), mode {fields['mode']}",
                " ".join(argv) + "   (principals and key versions only; never keys)")


_KINIT_ERRORS = (
    ("clock_skew", re.compile(r"(?i)clock skew too great")),
    ("kdc_unreachable", re.compile(r"(?i)cannot contact any kdc|cannot find kdc|unable to reach any kdc")),
    ("kdc_unresolvable", re.compile(r"(?i)cannot resolve network address for kdc|cannot resolve servers for kdc")),
    ("principal_unknown", re.compile(r"(?i)client .{0,300} not found in kerberos database|client not found")),
    ("keytab_no_entry", re.compile(r"(?i)keytab contains no suitable keys|no key table entry found|"
                                   r"key table entry not found|no such file or directory")),
    ("key_rejected", re.compile(r"(?i)preauthentication failed|password incorrect|decrypt integrity check failed|"
                                r"key version number for principal in key table is incorrect")),
    ("principal_revoked", re.compile(r"(?i)client'?s? credentials have been revoked|clients credentials have been revoked")),
    ("realm_unknown", re.compile(r"(?i)cannot find kdc for realm|realm not local|configuration file does not specify")),
)


def _classify_kinit(err: str) -> str:
    for name, rx in _KINIT_ERRORS:
        if rx.search(err):
            return name
    return "other"


def host_ticket(principal: str, timeout: float = 20):
    """kinit with the host keytab into a PRIVATE temporary credential cache. Returns (rc, error_class, detail,
    ccache_dir). The caller removes ccache_dir (see _drop)."""

    d = tempfile.mkdtemp(prefix="ipa-diagnose-cc-")
    os.chmod(d, 0o700)
    cc = f"FILE:{d}/cc"
    env_argv = ["kinit", "-k", "-t", KEYTAB, principal]
    from ipa_diagnose.resolution.checks import _SAFE_ENV
    import subprocess

    if shutil.which("kinit", path=_SAFE_ENV["PATH"]) is None:
        return None, "not_installed", "kinit is not installed", d
    env = dict(_SAFE_ENV, KRB5CCNAME=cc)
    try:
        p = subprocess.run(env_argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace",
                           env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, "timeout", f"no answer within {timeout:.0f} s", d
    except OSError as e:
        return None, "error", type(e).__name__, d
    if p.returncode == 0:
        return 0, "ok", "", d
    err = (p.stderr or "")[:4096]
    return p.returncode, _classify_kinit(err), _c(_redact_log_line(err), 200), d


def _drop(d: str) -> None:
    try:
        for n in os.listdir(d):
            os.unlink(os.path.join(d, n))
        os.rmdir(d)
    except OSError:
        pass


def _host_kinit(params):
    principal = params["principal"]
    if not _is_root() and not os.access(KEYTAB, os.R_OK):
        return _res("krb.host_kinit", params, DENIED, {}, f"{KEYTAB} is not readable (run as root)")
    rc, cls, detail, d = host_ticket(principal)
    _drop(d)
    if rc is None and cls in ("not_installed", "error"):
        return _res("krb.host_kinit", params, NOT_RUN, {}, detail, f"kinit -k -t {KEYTAB} {principal}")
    fields = {"ok": rc == 0, "error_class": cls if rc != 0 else None, "detail": detail or None}
    disp = (f"the KDC accepted this host's key ({principal})" if rc == 0
            else f"kinit with the host keytab failed: {cls.replace('_', ' ')}" + (f" ({detail})" if detail else ""))
    return _res("krb.host_kinit", params, OK, fields, disp,
                f"kinit -k -t {KEYTAB} {principal}   (into a private temporary cache, removed at once)")


def _api(params, method: str, arg: str, what: str):
    """One read-only IPA API call made with THIS HOST's identity (host keytab -> private temporary cache): the same
    identity SSSD uses to read the directory."""

    from ipa_diagnose.access.api import LiveApi

    check_id = f"ipa.api_{what}"
    if not _is_root() and not os.access(KEYTAB, os.R_OK):
        return _res(check_id, params, DENIED, {}, f"{KEYTAB} is not readable (run as root)")
    rc, cls, detail, d = host_ticket(params["principal"])
    try:
        if rc != 0:
            return _res(check_id, params, NOT_RUN, {"kinit_error": cls},
                        f"no host ticket, so the IPA API was not asked ({cls.replace('_', ' ')})")
        api = LiveApi(ccache=f"FILE:{d}/cc", max_calls=2, deadline_seconds=30)
        if api.context.unavailable:
            return _res(check_id, params, NOT_RUN, {}, api.context.unavailable)
        r = api.call(method, [arg], {"all": False} if method == "user_show" else None)
    finally:
        _drop(d)
    if r.ok:
        entry = r.entry
        from ipa_diagnose.access.evaluate import _bool, _first

        fields = {"exists": True, "server": api.context.server}
        if what == "user":
            fields["uid"] = _c(_first(entry.get("uid")), 255)
            fields["disabled"] = _bool(entry.get("nsaccountlock"))
            uidn = _first(entry.get("uidnumber"))
            fields["uidnumber"] = int(uidn) if isinstance(uidn, str) and uidn.isdigit() else (
                uidn if isinstance(uidn, int) and not isinstance(uidn, bool) else None)
        else:
            fields["fqdn"] = _c(_first(entry.get("fqdn")), 253)
            fields["has_keytab"] = _bool(entry.get("has_keytab"))
        return _res(check_id, params, OK, fields, f"IPA has {what} {arg}", f"IPA API {method} {arg} (host identity)")
    if r.error.kind == "not_found":
        return _res(check_id, params, OK, {"exists": False, "server": api.context.server},
                    f"IPA has no {what} named {arg}", f"IPA API {method} {arg} (host identity)")
    status = DENIED if r.error.kind in ("denied", "auth") else NOT_RUN
    return _res(check_id, params, status, {"api_error": r.error.kind}, _c(r.error.message, 200),
                f"IPA API {method} {arg} (host identity)")


def _api_user(params):
    return _api(params, "user_show", params["user"], "user")


# --------------------------------------------------------------------------- SSSD


_SSSCTL_VERSION_MIN = (2, 0)


def _sssctl(argv: List[str], check_id: str, params, timeout: float = 20):
    if not _is_root():
        return None, _res(check_id, params, DENIED, {}, "sssctl needs root")
    rc, out, err = _run(["sssctl"] + argv, timeout=timeout)
    if rc is None:
        return None, _res(check_id, params, NOT_RUN, {}, err, "sssctl " + " ".join(argv))
    return (rc, out, err), None


def _config_check(params):
    got, bad = _sssctl(["config-check"], "sssd.config_check", params)
    if bad:
        return bad
    rc, out, err = got
    m = re.search(r"Issues identified by validators:\s*(\d+)", out)
    merge = re.search(r"Messages generated during configuration merging:\s*(\d+)", out)
    issues = [_c(ln.strip(), 200) for ln in out.splitlines() if ln.strip().startswith(("[rule/", "[sssd]", "["))
              and "]" in ln][:10]
    missing = "does not exist" in out or "There is no configuration" in out
    fields = {"exit": rc, "issues": int(m.group(1)) if m else None, "merge_messages": int(merge.group(1)) if merge else None,
              "valid": rc == 0 and not missing, "missing": missing, "examples": issues}
    if m is None and rc != 0:
        fields["error"] = _c(_redact_log_line(err or out), 200)
    disp = ("sssctl config-check: no issues" if fields["valid"] else
            "sssctl config-check: no configuration" if missing else
            f"sssctl config-check: {fields['issues'] if fields['issues'] is not None else 'unknown number of'} issue(s)")
    return _res("sssd.config_check", params, OK, fields, disp, "sssctl config-check")


def _domain_status(params):
    dom = params["domain"]
    got, bad = _sssctl(["domain-status", dom, "--online", "--active-server"], "sssd.domain_status", params)
    if bad:
        return bad
    rc, out, err = got
    online = re.search(r"Online status:\s*(Online|Offline)", out)
    servers = []
    for line in out.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9 _-]{1,40}):\s*(\S{1,253})\s*$", line)
        if m and not line.startswith("Online status"):
            servers.append({"service": _c(m.group(1), 40), "server": _c(m.group(2), 253)})
    fields = {"exit": rc, "online": None if not online else online.group(1) == "Online",
              "active_servers": servers[:8], "no_active_server": "has no active servers" in out}
    if rc != 0 or online is None:
        fields["error"] = _c(_redact_log_line(err or out), 200)
        return _res("sssd.domain_status", params, FAILED, fields,
                    f"sssctl domain-status {dom}: no answer ({fields['error'] or 'exit ' + str(rc)})",
                    f"sssctl domain-status {dom} --online --active-server")
    disp = f"SSSD domain {dom} is {'online' if fields['online'] else 'OFFLINE'}"
    if servers:
        disp += "; active " + ", ".join(f"{s['service']} {s['server']}" for s in servers[:3])
    return _res("sssd.domain_status", params, OK, fields, disp, f"sssctl domain-status {dom} --online --active-server")


def _getent(db: str, name: str, sss_only: bool):
    argv = ["getent"] + (["-s", "sss"] if sss_only else []) + [db, name]
    start = time.monotonic()
    rc, out, err = _run(argv, timeout=30)
    return rc, out, err, round(time.monotonic() - start, 3), " ".join(argv)


def _nss_user(sss_only: bool):
    check_id = "nss.user_sss" if sss_only else "nss.user"

    def run(params):
        rc, out, err, secs, cmd = _getent("passwd", params["user"], sss_only)
        if rc is None:
            return _res(check_id, params, NOT_RUN, {}, err, cmd)
        line = out.splitlines()[0] if out.strip() else ""
        parts = line.split(":")
        fields: Dict[str, Any] = {"found": rc == 0 and len(parts) >= 4, "exit": rc, "seconds": secs}
        if fields["found"]:  # name, UID and GID only: never GECOS, home or shell
            fields.update(name=_c(parts[0], 255), uid=int(parts[2]) if parts[2].isdigit() else None,
                          gid=int(parts[3]) if parts[3].isdigit() else None)
        where = "SSSD (getent -s sss)" if sss_only else "the system's NSS stack (getent)"
        disp = (f"{where} resolves {params['user']} (UID {fields.get('uid')})" if fields["found"]
                else f"{where} does not resolve {params['user']} (exit {rc})")
        return _res(check_id, params, OK, fields, disp, cmd)

    return run


def _nss_group(params):
    rc, out, err, secs, cmd = _getent("group", params["group"], True)
    if rc is None:
        return _res("nss.group_sss", params, NOT_RUN, {}, err, cmd)
    parts = (out.splitlines()[0] if out.strip() else "").split(":")
    found = rc == 0 and len(parts) >= 3
    fields = {"found": found, "exit": rc, "seconds": secs,
              "gid": int(parts[2]) if found and parts[2].isdigit() else None}
    return _res("nss.group_sss", params, OK, fields,
                f"SSSD resolves group {params['group']}" if found else
                f"SSSD does not resolve group {params['group']} (exit {rc})", cmd)


def _nsswitch(params):
    try:
        with open(NSSWITCH, encoding="utf-8", errors="replace") as f:
            text = f.read(65536)
    except FileNotFoundError:
        return _res("nss.nsswitch", params, OK, {"present": False}, f"{NSSWITCH} does not exist", f"read {NSSWITCH}")
    except OSError as e:
        return _res("nss.nsswitch", params, FAILED, {}, f"{NSSWITCH}: {type(e).__name__}")
    srcs: Dict[str, List[str]] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        db, sep, rest = line.partition(":")
        if sep and db.strip() in ("passwd", "group", "shadow", "netgroup", "sudoers", "services", "automount"):
            srcs[db.strip()] = [_c(w, 30) for w in rest.split() if not w.startswith("[")][:8]
    fields = {"present": True, "passwd": srcs.get("passwd", []), "group": srcs.get("group", []),
              "passwd_has_sss": "sss" in srcs.get("passwd", []), "group_has_sss": "sss" in srcs.get("group", [])}
    return _res("nss.nsswitch", params, OK, fields,
                f"nsswitch passwd: {' '.join(fields['passwd']) or '(none)'}; group: {' '.join(fields['group']) or '(none)'}",
                f"read {NSSWITCH}")


_PAM_LINE = re.compile(r"^\s*-?(auth|account|password|session)\s+(\[[^\]]*\]|\S+)\s+(\S+)")
_PAM_INCLUDE = re.compile(r"^\s*-?(?:auth|account|password|session)?\s*(?:include|substack)\s+(\S+)|^\s*@include\s+(\S+)")
_PAM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")


def _pam_stack(params):
    svc = params["service"]
    seen: List[str] = []
    mods: Dict[str, List[str]] = {"auth": [], "account": []}

    nested: List[tuple] = []

    def walk(name: str, depth: int) -> Optional[str]:
        if depth > 5 or len(seen) >= 12 or name in seen or not _PAM_NAME.fullmatch(name):
            return None
        path = os.path.join(PAM_D, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read(65536)
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unreadable"
        seen.append(name)
        for line in text.splitlines():
            line = line.split("#", 1)[0]
            inc = _PAM_INCLUDE.match(line)
            if inc:
                target = inc.group(1) or inc.group(2)
                # "account include system-auth" includes only the account lines of system-auth; tracked as a whole
                sub = walk(target, depth + 1)
                if sub is not None:  # an included file that cannot be read leaves the stack unknown (review 3d)
                    nested.append((target, sub))
                continue
            m = _PAM_LINE.match(line)
            if m and m.group(1) in mods:
                mod = os.path.basename(m.group(3))
                if mod not in mods[m.group(1)]:
                    mods[m.group(1)].append(_c(mod, 40))
        return None

    state = walk(svc, 0)
    if state == "unreadable":
        return _res("pam.stack", params, DENIED, {}, f"{PAM_D}/{svc}: not readable")
    present = state is None
    if not present:  # PAM falls back to /etc/pam.d/other for an unconfigured service
        other = walk("other", 0)
        if other is not None:  # review round 3e: the fallback is held to the same rule as the service file
            return _res("pam.stack", params, DENIED if other == "unreadable" else FAILED, {},
                        f"{PAM_D}/{svc} does not exist and {PAM_D}/other is {other}: the stack cannot be evaluated")
    if nested:  # an include of the service file OR of the 'other' fallback that could not be read
        target, why = nested[0]
        status = DENIED if why == "unreadable" else FAILED
        return _res("pam.stack", params, status, {}, f"{PAM_D}/{_c(target, 64)} (included by "
                    f"{svc if present else 'other'}) is {why}: the stack cannot be evaluated")
    fields = {"service_file": present, "files": seen, "account_modules": mods["account"][:24],
              "auth_modules": mods["auth"][:24], "account_has_sss": "pam_sss.so" in mods["account"],
              "auth_has_sss": "pam_sss.so" in mods["auth"]}
    disp = (f"PAM service {svc}" + ("" if present else " (no file: PAM uses 'other')")
            + f": pam_sss in account {'yes' if fields['account_has_sss'] else 'NO'}, in auth "
            f"{'yes' if fields['auth_has_sss'] else 'NO'}")
    return _res("pam.stack", params, OK, fields, disp, f"read {PAM_D}/{svc} and the files it includes")


_ACCT_RESULT = re.compile(r"pam_acct_mgmt:\s*(.+)")


def _user_checks(params):
    user, svc = params["user"], params["service"]
    got, bad = _sssctl(["user-checks", user, "-a", "acct", "-s", svc], "pam.user_checks", params, timeout=45)
    if bad:
        return bad
    rc, out, err = got
    out = out + "\n" + err  # sssctl prints the PAM results on stderr (live: SSSD 2.12, Fedora 43)
    m = _ACCT_RESULT.search(out)
    result = _c(m.group(1).strip(), 120) if m else None
    low = (result or "").lower()
    cls = ("success" if low == "success" else "permission_denied" if "permission denied" in low else
           "user_unknown" if "user not known" in low or "unknown user" in low else
           "authinfo_unavail" if "authentication information" in low or "authinfo" in low else
           "system_error" if "system error" in low else "other" if result else None)
    nss_found = bool(re.search(r"SSSD nss user lookup result:\s*\n\s*-\s*user name", out))
    fields = {"exit": rc, "pam_result": result, "result_class": cls, "nss_found": nss_found}
    if result is None:
        # never the NSS lookup block (" - user name/gecos/home ..." lines)
        text = "\n".join(ln for ln in (err or out).splitlines() if not ln.lstrip().startswith("- "))
        fields["error"] = _c(_redact_log_line(text), 200)
        return _res("pam.user_checks", params, FAILED, fields,
                    f"sssctl user-checks gave no PAM account result ({fields['error'] or 'exit ' + str(rc)})",
                    f"sssctl user-checks {user} -a acct -s {svc}")
    return _res("pam.user_checks", params, OK, fields,
                f"PAM account check for {user} via {svc} on this host: {result}",
                f"sssctl user-checks {user} -a acct -s {svc}   (PAM account phase only; no password)")


_CACHE_LINE = re.compile(r"^\s*(Cache entry creation date|Cache entry last update time|Cache entry expiration time|"
                         r"Initgroups expiration time|Cached in InfoPipe)\s*:\s*(.{0,80})$")


def _cache_user(params):
    user = params["user"]
    got, bad = _sssctl(["user-show", user], "sssd.cache_user", params)
    if bad:
        return bad
    rc, out, err = got
    present = rc == 0 and "is not present in cache" not in out and "Name:" in out
    info = {}
    for line in out.splitlines():
        m = _CACHE_LINE.match(line)
        if m:
            info[m.group(1).lower().replace(" ", "_")] = _c(m.group(2).strip(), 80)
    fields = {"exit": rc, "present": present, **info,
              "expired": (info.get("cache_entry_expiration_time", "").lower() == "expired") if present else None}
    if rc != 0 and "not present" not in out:
        fields["error"] = _c(_redact_log_line(err or out), 200)
    disp = (f"SSSD cache has an entry for {user}" + (f" (expires {info.get('cache_entry_expiration_time')})"
                                                    if info.get("cache_entry_expiration_time") else "")
            if present else f"SSSD cache has no entry for {user}"
            + (f" ({fields['error']})" if fields.get("error") else ""))
    return _res("sssd.cache_user", params, OK, fields, disp, f"sssctl user-show {user}")


_SIGNALS = (
    ("offline", re.compile(r"(?i)going offline|backend is offline|marking .{0,60} as offline")),
    ("kdc_unreachable", re.compile(r"(?i)cannot contact any kdc|cannot find kdc")),
    ("clock_skew", re.compile(r"(?i)clock skew too great")),
    ("keytab", re.compile(r"(?i)keytab contains no suitable keys|no key table entry found|preauthentication failed|"
                          r"not found in kerberos database")),
    ("cache_db", re.compile(r"(?i)(ldb|sysdb|cache database|cache db|\.ldb)\S*.{0,120}"
                            r"(corrupt|i/o error|input/output error|failed to open|unable to open|cannot open|"
                            r"could not open|failed to connect|error opening|operations error|malformed)")),
    ("server_unreachable", re.compile(r"(?i)no available servers|port not working|could not connect to ldap|"
                                      r"can't contact ldap server")),
    ("tls", re.compile(r"(?i)certificate verify failed|tls.{0,40}error|unable to get local issuer")),
)


def _log_signals(params):
    dom = params["domain"]
    if not _is_root():
        return _res("sssd.log_signals", params, DENIED, {}, "SSSD logs need root")
    lines: List[str] = []
    rc, out, err = _run(["journalctl", "--no-pager", "-o", "cat", "-n", "300", "-u", "sssd.service"], timeout=15)
    if rc is not None:
        lines.extend(out.splitlines()[-300:])
    path = os.path.join(SSSD_LOG_DIR, f"sssd_{dom}.log")
    try:
        # never through a symlink, and only a regular file (the log directory may belong to the sssd user)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if _stat.S_ISREG(st.st_mode):
                f.seek(max(0, st.st_size - 262144))
                lines.extend(f.read(262144).decode("utf-8", "replace").splitlines()[-2000:])
    except OSError:
        pass
    counts: Dict[str, int] = {}
    examples: Dict[str, str] = {}
    for line in lines:
        line = line[:4096]
        for name, rx in _SIGNALS:
            if rx.search(line):
                counts[name] = counts.get(name, 0) + 1
                if name not in examples:
                    examples[name] = _c(_redact_log_line(line), 200)
    fields = {"lines_read": len(lines), "counts": counts, "examples": examples}
    disp = (f"{len(lines)} recent SSSD log line(s): " + (", ".join(f"{k} x{v}" for k, v in sorted(counts.items()))
                                                          or "no known problem signal"))
    return _res("sssd.log_signals", params, OK, fields, disp,
                f"journalctl -u sssd -n 300; tail of {path} (known signals only; one redacted example each)")


def _cache_files(params):
    dom = params["domain"]
    path = os.path.join(SSS_DB, f"cache_{dom}.ldb")
    try:
        st = os.lstat(path)  # metadata of the entry itself; a symlink is reported, never followed
        if not _stat.S_ISREG(st.st_mode):
            return _res("sssd.cache_files", params, OK, {"present": True, "size": 0, "mode": "%04o" % (st.st_mode & 0o7777),
                                                          "empty": False, "not_regular": True, "modified_seconds_ago": 0},
                        f"{path} is not a regular file", f"stat {path}")
    except FileNotFoundError:
        return _res("sssd.cache_files", params, OK, {"present": False, "dir_present": os.path.isdir(SSS_DB)},
                    f"{path} does not exist", f"stat {path}")
    except PermissionError:
        return _res("sssd.cache_files", params, DENIED, {}, f"{path}: permission denied")
    mtime = datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc)
    fields = {"present": True, "size": st.st_size, "mode": "%04o" % (st.st_mode & 0o7777), "empty": st.st_size == 0,
              "modified_seconds_ago": int((_now() - mtime).total_seconds())}
    return _res("sssd.cache_files", params, OK, fields, f"{path}: {st.st_size} bytes", f"stat {path}")


# --------------------------------------------------------------------------- registry entries

ROOT, ANY = "root", "any"
_SSSD_CACHE_TOUCH = ("SSSD may refresh its cache for this name from IPA (the same as any lookup on this host); "
                     "nothing is written to IPA")


def specs() -> List[CheckSpec]:
    return [
        CheckSpec("client.ipa_conf", {}, "IPA client configuration of this host", _client_conf, ANY,
                  evidence=("conf_present", "domain", "realm", "server", "host", "ca_present")),
        CheckSpec("client.versions", {}, "SSSD, IPA client and OS versions", _versions, ANY,
                  evidence=("sssd", "ipa_client", "os", "systemd")),
        CheckSpec("sssd.conf", {}, "SSSD configuration (non-secret options only)", _sssd_conf, ROOT,
                  evidence=("present",), secrets="options naming passwords/tokens/keys are never read"),
        CheckSpec("dns.resolvers", {}, "resolvers and search domains", _resolvers, ANY, evidence=("nameservers",)),
        CheckSpec("dns.address", {"name": "fqdn"}, "address of a name through the system resolver", _address, ANY,
                  timeout=15, evidence=("resolved", "addresses")),
        CheckSpec("dns.srv", {"name": "srv_name"}, "SRV records through the configured resolvers", _srv, ANY,
                  timeout=12, evidence=("rcode", "answers")),
        CheckSpec("net.tcp", {"host": "fqdn", "port": "ipa_port"}, "whether a TCP port of the IPA server answers",
                  _tcp, ANY, timeout=6, evidence=("state",),
                  side_effects="opens and closes one TCP connection (visible in the server's connection logs)"),
        CheckSpec("ipa.https", {"server": "fqdn"}, "TLS trust of the IPA server and its clock", _https, ANY,
                  timeout=25, evidence=("tls", "offset_seconds"),
                  side_effects="one anonymous HTTPS HEAD request to the IPA server (in its access log)"),
        CheckSpec("krb.keytab", {}, "host keytab metadata (principals and key versions, never keys)", _keytab, ROOT,
                  evidence=("present",), secrets="klist -k lists principals and key versions; keys are never read"),
        CheckSpec("krb.host_kinit", {"principal": "host_principal"}, "whether the KDC accepts this host's key",
                  _host_kinit, ROOT, timeout=25, evidence=("ok", "error_class"),
                  side_effects=("one Kerberos AS request with this host's key (as SSSD makes itself); a private "
                                "temporary credential cache is created and removed at once"),
                  secrets="the ticket stays in a private temporary cache that is deleted; it is never printed"),
        CheckSpec("ipa.api_user", {"principal": "host_principal", "user": "ipa_user"},
                  "whether IPA has the user (asked with this host's identity)", _api_user, ROOT, timeout=45,
                  evidence=("exists",),
                  side_effects="one Kerberos AS request and one read-only IPA API call (user_show) as this host",
                  secrets="the host ticket stays in a private temporary cache that is deleted"),
        CheckSpec("sssd.config_check", {}, "static check of the SSSD configuration", _config_check, ROOT,
                  timeout=20, evidence=("valid", "issues"), applies="SSSD 2.0 or later"),
        CheckSpec("sssd.domain_status", {"domain": "sssd_domain"}, "SSSD's online state and active servers",
                  _domain_status, ROOT, timeout=20, evidence=("online",), applies="SSSD 2.0 or later",
                  side_effects="asks the running SSSD over its InfoPipe; never starts SSSD (no --start)"),
        CheckSpec("nss.user_sss", {"user": "ipa_user"}, "user lookup through SSSD only", _nss_user(True), ANY,
                  timeout=30, evidence=("found",), side_effects=_SSSD_CACHE_TOUCH),
        CheckSpec("nss.user", {"user": "ipa_user"}, "user lookup through the system's NSS stack", _nss_user(False),
                  ANY, timeout=30, evidence=("found",), side_effects=_SSSD_CACHE_TOUCH),
        CheckSpec("nss.group_sss", {"group": "ipa_group"}, "group lookup through SSSD only", _nss_group, ANY,
                  timeout=30, evidence=("found",), side_effects=_SSSD_CACHE_TOUCH),
        CheckSpec("nss.nsswitch", {}, "whether NSS consults SSSD", _nsswitch, ANY, evidence=("passwd_has_sss",)),
        CheckSpec("pam.stack", {"service": "pam_service"}, "whether a PAM service reaches SSSD", _pam_stack, ANY,
                  evidence=("account_has_sss", "auth_has_sss")),
        CheckSpec("pam.user_checks", {"user": "ipa_user", "service": "pam_service"},
                  "the PAM account phase for a user through a service (no password)", _user_checks, ROOT,
                  timeout=50, evidence=("pam_result", "result_class"), applies="SSSD 2.0 or later",
                  side_effects=("runs the service's PAM ACCOUNT phase only (pam_acct_mgmt, no password, no "
                                "session): SSSD evaluates access as for a login and may refresh its cache and HBAC "
                                "rules; pam_faillock does not reset counters without an auth phase")),
        CheckSpec("sssd.cache_user", {"user": "ipa_user"}, "SSSD's cache entry for a user (timestamps)", _cache_user,
                  ROOT, timeout=20, evidence=("present",), applies="SSSD 2.0 or later"),
        CheckSpec("sssd.log_signals", {"domain": "sssd_domain"}, "known problem signals in recent SSSD logs",
                  _log_signals, ROOT, timeout=20, evidence=("counts",),
                  secrets="only signal counts and one redacted, shortened example line per signal"),
        CheckSpec("sssd.cache_files", {"domain": "sssd_domain"}, "SSSD cache database file metadata", _cache_files,
                  ROOT, evidence=("present",)),
    ]
