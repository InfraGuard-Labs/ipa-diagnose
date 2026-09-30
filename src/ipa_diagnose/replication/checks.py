"""Replication checks for `ipa-diagnose replication` (Slice 5), part of the ONE closed check registry
(:data:`ipa_diagnose.resolution.checks.REGISTRY`).

Every check is a fixed argv or a fixed file read; parameters are typed and validated before use; output is bounded,
parsed into a fixed projection and sanitized. Nothing here writes anything:

* this server's topology, roles, agreements, replica configuration and RUV are read over the LOCAL LDAPI socket with
  SASL EXTERNAL as root (the mechanism ipa-healthcheck uses; no password of any kind is involved or prompted for).
  Only fixed bases, filters and attribute lists are used - never ``nsDS5ReplicaCredentials``;
* a peer is asked only for its root DSE, anonymously (is its Directory Server answering, and what time is it there);
* the supplier's own GSSAPI bind is reproduced with the Directory Server's keytab into a PRIVATE temporary credential
  cache that is removed at once (keys are never printed or stored);
* the reverse direction (the peer's agreement towards this server) is read from the peer read-only with the
  operator's OWN Kerberos ticket, and only when one exists; an empty answer is "not visible", never "absent".

Side effects are declared per check (``CheckSpec.side_effects``): LDAP connections appear in the peer's access log,
Kerberos requests in the KDC's log.
"""

from __future__ import annotations

import datetime
import os
import re
import shlex
import shutil
import signal
import stat as _stat
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from ipa_diagnose.replication import ldif
from ipa_diagnose.replication.status import classify_bind_error
from ipa_diagnose.resolution import types as T
from ipa_diagnose.resolution.checks import (
    DENIED, FAILED, NOT_RUN, OK, CheckResult, CheckSpec, _SAFE_ENV, _redact_log_line, _res,
)
from ipa_diagnose.textsafe import sanitize_text

IPA_CONF = "/etc/ipa/default.conf"
IPA_CA = "/etc/ipa/ca.crt"
DS_KEYTAB = "/etc/dirsrv/ds.keytab"
DIRSRV_ETC = "/etc/dirsrv"
DIRSRV_VAR = "/var/lib/dirsrv"
SYSCONFIG = "/etc/sysconfig"
_MAX = 256 * 1024

AGREEMENT_ATTRS = ("cn", "objectClass", "nsDS5ReplicaHost", "nsDS5ReplicaPort", "nsDS5ReplicaTransportInfo",
                   "nsDS5ReplicaBindMethod", "nsDS5ReplicaRoot", "nsds5ReplicaEnabled",
                   "nsds5replicaLastUpdateStatus", "nsds5replicaLastUpdateStatusJSON", "nsds5replicaLastUpdateStart",
                   "nsds5replicaLastUpdateEnd", "nsds5replicaUpdateInProgress", "nsds5replicaLastInitStatus",
                   "nsds5replicaLastInitEnd")
_SECRET_ATTRS = ("nsds5replicacredentials", "userpassword", "nsds5replicabootstrapcredentials")
KNOWN_ROLES = ("CA", "KRA", "DNS", "DNSSEC", "KDC", "HTTP", "ADTRUST")
_NSDS50RUV = re.compile(r"\{replica\s+(\d{1,5})\s+ldap://([A-Za-z0-9.-]{1,253}):(\d{1,5})\}(?:\s+(\S{1,40}))?(?:\s+(\S{1,40}))?")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _c(v: Any, n: int = 200) -> str:
    return sanitize_text(v, n)


# --------------------------------------------------------------------------- process helpers


def _exec(argv: List[str], timeout: float, env_extra: Optional[Dict[str, str]] = None,
          stdin_text: Optional[str] = None) -> Tuple[Optional[int], str, str]:
    """Run argv (never a shell) from "/" with the fixed safe environment plus `env_extra`. stdin is closed (a tool
    that would prompt, for example for the Directory Manager password, gets EOF instead of hanging)."""

    if shutil.which(argv[0], path=_SAFE_ENV["PATH"]) is None:
        return None, "", f"{argv[0]}: not installed"
    env = dict(_SAFE_ENV)
    env.update(env_extra or {})
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv from a closed registry with validated parameters
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd="/",
            start_new_session=True, text=True, errors="replace")
    except OSError as e:
        return None, "", type(e).__name__
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            proc.kill()
        try:
            proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, ValueError):
            pass
        return None, "", f"timed out after {timeout:.0f}s"
    return proc.returncode, (out or "")[:_MAX], (err or "")[:_MAX]


def _gentime(v: str) -> Optional[str]:
    """LDAP GeneralizedTime (20260929123456Z) -> ISO 8601 UTC; None for empty/never (1970...)."""

    m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z", (v or "").strip())
    if not m or m.group(1) == "1970":
        return None
    try:
        dt = datetime.datetime(*(int(g) for g in m.groups()), tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(v: Optional[str]) -> Optional[datetime.datetime]:
    if not v:
        return None
    try:
        return datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# --------------------------------------------------------------------------- local IPA server context


def _read_conf() -> Dict[str, str]:
    from ipa_diagnose.access.api import read_ipa_conf

    return read_ipa_conf(IPA_CONF)


def _ds_instances() -> List[str]:
    try:
        names = sorted(p for p in os.listdir(DIRSRV_ETC) if p.startswith("slapd-") and not p.endswith(".removed"))
    except OSError:
        return []
    out = []
    for n in names:
        full = os.path.join(DIRSRV_ETC, n)
        if os.path.isdir(full) and not os.path.islink(full):
            inst = T.validate("ds_instance", n[len("slapd-"):])
            if inst:
                out.append(inst)
    return out


def _rpm_version(*names: str) -> Optional[str]:
    for n in names:
        rc, out, _ = _exec(["rpm", "-q", "--qf", "%{VERSION}", n], timeout=10)
        if rc == 0 and re.fullmatch(r"[0-9][0-9A-Za-z._+~-]{0,40}", out.strip()):
            return out.strip()
    return None


def _os_release() -> Tuple[Optional[str], Optional[str]]:
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
    return osid, osver


def _ktname(instance: Optional[str]) -> Tuple[Optional[str], str]:
    """KRB5_KTNAME the Directory Server runs with (FreeIPA writes it into /etc/sysconfig/dirsrv-INSTANCE)."""

    files = ([os.path.join(SYSCONFIG, f"dirsrv-{instance}")] if instance else []) + [os.path.join(SYSCONFIG, "dirsrv")]
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read(65536)
        except OSError:
            continue
        for line in text.splitlines():
            m = re.match(r"^\s*(?:export\s+)?KRB5_KTNAME\s*=\s*[\"']?(?:FILE:)?([^\"'\s]+)", line)
            if m:
                return _c(m.group(1), 300), path
    return None, ""


def _server(params):
    conf = _read_conf() if os.path.isfile(IPA_CONF) else {}
    inst = _ds_instances()
    realm = T.validate("realm", conf.get("realm", "")) if conf else None
    host = T.validate("fqdn", conf.get("host", "")) if conf else None
    basedn = T.validate("domain_suffix", conf.get("basedn", "")) if conf else None
    expected_inst = realm.replace(".", "-") if realm else None
    ipactl = os.path.exists("/usr/sbin/ipactl")
    is_server = bool(conf) and ipactl and bool(expected_inst) and expected_inst in inst
    osid, osver = _os_release()
    ktname, ktsrc = _ktname(expected_inst if expected_inst in inst else None)
    fields = {
        "ipa_conf_present": bool(conf), "ipactl": ipactl, "ds_instances": inst,
        "ds_instance": expected_inst if expected_inst in inst else None,
        "is_ipa_server": is_server, "host": host, "realm": realm, "basedn": basedn,
        "domain": T.validate("fqdn", conf.get("domain", "")) if conf else None,
        "ldap_principal": f"ldap/{host}@{realm}" if host and realm else None,
        "freeipa": _rpm_version("freeipa-server", "ipa-server") if is_server else None,
        "ds_version": _rpm_version("389-ds-base") if is_server else None,
        "os": osid, "os_version": osver, "systemd": os.path.isdir("/run/systemd/system"),
        "is_root": _is_root(), "krb5_ktname": ktname, "krb5_ktname_source": ktsrc,
    }
    if not conf:
        disp = f"{IPA_CONF} is missing or unreadable: this host is not an IPA server (or not configured)"
    elif not is_server:
        disp = (f"this host is not an IPA server (no Directory Server instance slapd-{expected_inst or '?'}"
                + ("" if ipactl else ", no ipactl") + ")")
    else:
        disp = (f"IPA server {host} (realm {realm}, suffix {basedn}); Directory Server slapd-{expected_inst}; "
                f"FreeIPA {fields['freeipa'] or '?'}, 389-ds {fields['ds_version'] or '?'}, {osid or '?'} "
                f"{osver or ''}").strip()
    return _res("repl.server", params, OK, fields, disp, f"read {IPA_CONF}; ls {DIRSRV_ETC}; rpm -q freeipa-server")


def _storage(params):
    try:
        st = os.statvfs(DIRSRV_VAR)
    except (OSError, AttributeError) as e:
        return _res("repl.storage", params, FAILED, {}, f"{DIRSRV_VAR}: {type(e).__name__}")
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    ro = bool(st.f_flag & getattr(os, "ST_RDONLY", 1))
    fields = {"free_bytes": free, "total_bytes": total, "free_percent": round(100.0 * free / total, 1) if total else None,
              "read_only": ro}
    disp = (f"{DIRSRV_VAR}: {free // (1024 * 1024)} MiB free ({fields['free_percent']}%)"
            + ("; the file system is READ-ONLY" if ro else ""))
    return _res("repl.storage", params, OK, fields, disp, f"statvfs {DIRSRV_VAR}")


_KT_LINE = re.compile(r"^\s*(\d+)\s+(?:\S+\s+\S+\s+)?(\S+@\S+)\s*(?:\(.*\))?\s*$")


def _ds_keytab(params):
    try:
        st = os.lstat(DS_KEYTAB)
    except FileNotFoundError:
        return _res("repl.ds_keytab", params, OK, {"present": False}, f"{DS_KEYTAB} does not exist", f"stat {DS_KEYTAB}")
    except PermissionError:
        return _res("repl.ds_keytab", params, DENIED, {}, f"{DS_KEYTAB}: permission denied (run as root)")
    import grp
    import pwd

    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = f"uid:{st.st_uid}"
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = f"gid:{st.st_gid}"
    try:
        ds = pwd.getpwnam("dirsrv")
        ds_uid, ds_gids = ds.pw_uid, {ds.pw_gid} | {g.gr_gid for g in grp.getgrall() if "dirsrv" in g.gr_mem}
    except KeyError:
        ds_uid, ds_gids = None, set()
    mode = st.st_mode & 0o7777
    readable = None
    if ds_uid is not None:
        readable = bool((st.st_uid == ds_uid and mode & 0o400) or (st.st_gid in ds_gids and mode & 0o040)
                        or mode & 0o004)
    fields: Dict[str, Any] = {
        "present": True, "is_symlink": _stat.S_ISLNK(st.st_mode), "is_regular": _stat.S_ISREG(st.st_mode),
        "links": st.st_nlink, "owner": _c(owner, 40), "group": _c(group, 40), "mode": "%04o" % mode,
        "dirsrv_can_read": readable, "world_readable": bool(mode & 0o004), "size": st.st_size,
    }
    if not fields["is_regular"] or fields["is_symlink"] or st.st_nlink > 1:
        return _res("repl.ds_keytab", params, OK, dict(fields, klist_ok=None, principals=[]),
                    f"{DS_KEYTAB} is not a plain regular file (symlink, hard link or special file): not read",
                    f"stat {DS_KEYTAB}")
    if not _is_root():
        return _res("repl.ds_keytab", params, DENIED, fields, f"{DS_KEYTAB}: listing its principals needs root")
    rc, out, err = _exec(["klist", "-k", DS_KEYTAB], timeout=10)  # principals and key versions: never -K
    if rc is None:
        return _res("repl.ds_keytab", params, NOT_RUN, fields, err, f"klist -k {DS_KEYTAB}")
    entries = []
    for line in out.splitlines():
        m = _KT_LINE.match(line)
        if m:
            entries.append((int(m.group(1)), _c(m.group(2), 300)))
    principals = sorted({p for _, p in entries})
    fields.update(klist_ok=rc == 0, principals=principals[:16],
                  kvnos={p: sorted({k for k, q in entries if q == p})[-3:] for p in principals[:16]})
    if rc != 0:
        fields["error"] = _c(_redact_log_line(err), 160)
    disp = (f"{DS_KEYTAB}: owner {owner}:{group}, mode {fields['mode']}, {len(entries)} key(s) for "
            f"{', '.join(principals[:2]) or 'no principal'}")
    return _res("repl.ds_keytab", params, OK, fields, disp,
                f"stat {DS_KEYTAB}; klist -k {DS_KEYTAB}   (principals and key versions only; never keys)")


# --------------------------------------------------------------------------- local LDAPI reads (read-only, as root)


def _ldapi() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    from ipa_diagnose.evidence.collectors.replication_agreements import _ldapi_context

    try:
        return _ldapi_context()
    except (OSError, AttributeError) as e:
        return None, None, type(e).__name__


def _ldapi_search(uri: str, base: str, scope: str, flt: str, attrs: Tuple[str, ...],
                  timeout: float = 20) -> Tuple[Optional[int], List[Dict[str, object]], str, str]:
    argv = ["ldapsearch", "-LLL", "-o", "ldif-wrap=no", "-Q", "-Y", "EXTERNAL", "-H", uri, "-b", base, "-s", scope,
            flt] + list(attrs)
    rc, out, err = _exec(argv, timeout=timeout)
    entries = ldif.parse(out) if rc == 0 else []
    for e in entries:
        for a in _SECRET_ATTRS:
            e.pop(a, None)
    cmd = " ".join(shlex.quote(a) for a in argv[:8]) + " ..."
    return rc, entries, _c(_redact_log_line(err), 200), cmd


def _whoami_dm(uri: str) -> Optional[bool]:
    rc, out, _ = _exec(["ldapwhoami", "-Q", "-Y", "EXTERNAL", "-H", uri], timeout=10)
    if rc is None:
        return None
    return rc == 0 and "cn=directory manager" in out.lower()


def _rdns(dn: str) -> List[Tuple[str, str]]:
    out = []
    for part in dn.split(","):
        k, sep, v = part.partition("=")
        if sep:
            out.append((k.strip().lower(), v.strip()))
    return out


def _topology(params):
    uri, basedn, err = _ldapi()
    if err:
        return _res("repl.topology", params, DENIED if "root" in err else NOT_RUN, {}, err)
    masters_base = f"cn=masters,cn=ipa,cn=etc,{basedn}"
    rc, entries, e1, cmd = _ldapi_search(uri, masters_base, "sub", "(objectClass=*)", ("cn", "ipaConfigString"))
    if rc != 0:
        return _res("repl.topology", params, FAILED if rc is not None else NOT_RUN, {},
                    f"reading {masters_base} failed (exit {rc}): {e1}", cmd)
    masters: List[str] = []
    roles: Dict[str, List[str]] = {}
    flags: Dict[str, List[str]] = {}
    hidden: List[str] = []
    rejected = 0
    for e in entries:
        rdns = _rdns(str(e.get("dn", "")))
        if len(rdns) >= 2 and rdns[1] == ("cn", "masters") and rdns[0][0] == "cn":
            h = T.validate("fqdn", rdns[0][1])
            if h:
                masters.append(h)
            else:
                rejected += 1
        elif len(rdns) >= 3 and rdns[2] == ("cn", "masters"):
            h = T.validate("fqdn", rdns[1][1])
            svc = rdns[0][1]
            conf = [v.strip() for v in ldif.values(e, "ipaConfigString")]
            if not h or svc not in KNOWN_ROLES:
                continue
            if "enabledService" in conf or "hiddenService" in conf:
                roles.setdefault(h, []).append(svc)
            if "hiddenService" in conf and h not in hidden:
                hidden.append(h)
            for fl in ("caRenewalMaster", "dnssecKeyMaster"):
                if fl in conf:
                    flags.setdefault(h, []).append(fl)
    topo_base = f"cn=topology,cn=ipa,cn=etc,{basedn}"
    rc2, tents, e2, _ = _ldapi_search(uri, topo_base, "sub",
                                      "(|(objectClass=iparepltopoconf)(objectClass=iparepltoposegment))",
                                      ("cn", "objectClass", "ipaReplTopoConfRoot", "ipaReplTopoSegmentLeftNode",
                                       "ipaReplTopoSegmentRightNode", "ipaReplTopoSegmentDirection"))
    suffixes: List[Dict[str, str]] = []
    segments: List[Dict[str, str]] = []
    if rc2 == 0:
        for e in tents:
            ocs = {v.lower() for v in ldif.values(e, "objectClass")}
            rdns = _rdns(str(e.get("dn", "")))
            if "iparepltopoconf" in ocs and rdns:
                root = ldif.first(e, "ipaReplTopoConfRoot").lower()
                name = rdns[0][1] if rdns[0][1] in T.SUFFIX_KINDS else "other"
                suffixes.append({"name": name, "root": _c(root, 200)})
            elif "iparepltoposegment" in ocs and len(rdns) >= 2:
                left = T.validate("fqdn", ldif.first(e, "ipaReplTopoSegmentLeftNode"))
                right = T.validate("fqdn", ldif.first(e, "ipaReplTopoSegmentRightNode"))
                suffix = rdns[1][1] if rdns[1][1] in T.SUFFIX_KINDS else "other"
                if left and right:
                    segments.append({"suffix": suffix, "left": left, "right": right, "name": _c(rdns[0][1], 120),
                                     "direction": _c(ldif.first(e, "ipaReplTopoSegmentDirection"), 30)})
                else:
                    rejected += 1
    dm = _whoami_dm(uri)
    complete = rc2 == 0 and dm is True and rejected == 0 and bool(masters)
    fields = {"masters": sorted(set(masters)), "roles": {h: sorted(set(r)) for h, r in sorted(roles.items())},
              "flags": {h: sorted(set(f)) for h, f in sorted(flags.items())}, "hidden": sorted(hidden),
              "suffixes": sorted(suffixes, key=lambda s: s["name"]),
              "segments": sorted(segments, key=lambda s: (s["suffix"], s["left"], s["right"])),
              "identity_directory_manager": dm, "complete": complete, "rejected_names": rejected,
              "topology_read": rc2 == 0}
    disp = (f"{len(fields['masters'])} IPA server(s); {len(segments)} topology segment(s) in "
            f"{', '.join(s['name'] for s in fields['suffixes']) or 'no'} suffix(es)")
    if rc2 != 0:
        disp += f"; the topology segments could not be read ({e2 or 'exit ' + str(rc2)})"
    return _res("repl.topology", params, OK, fields, disp,
                f"ldapsearch -Y EXTERNAL (LDAPI, read-only) {masters_base} and {topo_base}")


def _agreement_projection(e: Dict[str, object], basedn: str) -> Dict[str, Any]:
    root = ldif.first(e, "nsDS5ReplicaRoot").strip().lower()
    kind = "domain" if root == basedn.lower() else "ca" if root == "o=ipaca" else "other"
    consumer = T.validate("fqdn", ldif.first(e, "nsDS5ReplicaHost"))
    transport = ldif.first(e, "nsDS5ReplicaTransportInfo", "LDAP").strip().upper() or "LDAP"
    bind = ldif.first(e, "nsDS5ReplicaBindMethod", "SIMPLE").strip().upper() or "SIMPLE"
    out = {
        "subject": f"{kind}:{consumer}" if consumer and kind != "other" else None,
        "suffix_kind": kind, "suffix_root": _c(root, 200), "consumer": consumer,
        "consumer_raw": _c(ldif.first(e, "nsDS5ReplicaHost"), 120) if not consumer else None,
        "port": T.validate("ldap_port", ldif.first(e, "nsDS5ReplicaPort", "389").strip()),
        "transport": transport if transport in T.REPL_TRANSPORTS else _c(transport, 20),
        "bind_method": _c(bind, 30), "enabled": ldif.first(e, "nsds5ReplicaEnabled", "on").strip().lower() != "off",
        "status_text": _c(ldif.first(e, "nsds5replicaLastUpdateStatus"), 800),
        "status_json": ldif.first(e, "nsds5replicaLastUpdateStatusJSON")[:4096] or None,
        "last_update_start": _gentime(ldif.first(e, "nsds5replicaLastUpdateStart")),
        "last_update_end": _gentime(ldif.first(e, "nsds5replicaLastUpdateEnd")),
        "update_in_progress": ldif.first(e, "nsds5replicaUpdateInProgress").strip().upper() == "TRUE",
        "last_init_status": _c(ldif.first(e, "nsds5replicaLastInitStatus"), 400),
        "last_init_end": _gentime(ldif.first(e, "nsds5replicaLastInitEnd")),
        "name": _c(ldif.first(e, "cn"), 120),
    }
    return out


def _ruv(uri: str, base: str) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    rc, entries, err, _ = _ldapi_search(
        uri, base, "sub", "(&(nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff)(objectClass=nsTombstone))",
        ("nsds50ruv",))
    if rc == 32:
        return [], ""
    if rc != 0:
        return None, err or f"exit {rc}"
    out = []
    for e in entries:
        for v in ldif.values(e, "nsds50ruv"):
            if not v.lower().startswith("{replica "):
                continue
            m = _NSDS50RUV.match(v.strip())
            if not m:
                return None, "an RUV element could not be parsed"
            host = T.validate("fqdn", m.group(2))
            out.append({"rid": int(m.group(1)), "host": host or _c(m.group(2), 120), "port": m.group(3),
                        "max_csn": _c(m.group(5) or "", 40) or None})
    return sorted(out, key=lambda x: x["rid"]), ""


def _agreements(params):
    uri, basedn, err = _ldapi()
    if err:
        return _res("repl.agreements", params, DENIED if "root" in err else NOT_RUN, {}, err)
    rc, entries, e1, cmd = _ldapi_search(
        uri, "cn=mapping tree,cn=config", "sub",
        "(|(objectClass=nsds5replicationagreement)(objectClass=nsDSWindowsReplicationAgreement))", AGREEMENT_ATTRS)
    if rc != 0:
        return _res("repl.agreements", params, FAILED if rc is not None else NOT_RUN, {},
                    f"reading the replication agreements failed (exit {rc}): {e1}", cmd)
    agreements, other = [], []
    for e in entries:
        ocs = {v.lower() for v in ldif.values(e, "objectClass")}
        if "nsdswindowsreplicationagreement" in ocs:
            other.append({"kind": "winsync", "name": _c(ldif.first(e, "cn"), 120)})
            continue
        a = _agreement_projection(e, basedn)
        (agreements if a["subject"] else other).append(a if a["subject"] else
                                                       {"kind": a["suffix_kind"], "name": a["name"],
                                                        "suffix_root": a["suffix_root"],
                                                        "consumer": a["consumer"] or a["consumer_raw"]})
    rc2, reps, e2, _ = _ldapi_search(uri, "cn=mapping tree,cn=config", "sub", "(objectClass=nsds5replica)",
                                     ("nsDS5ReplicaRoot", "nsDS5ReplicaId", "nsDS5ReplicaType",
                                      "nsds5ReplicaBindDNGroup"))
    replicas = []
    if rc2 == 0:
        for e in reps:
            root = ldif.first(e, "nsDS5ReplicaRoot").strip().lower()
            rid = ldif.first(e, "nsDS5ReplicaId").strip()
            replicas.append({"suffix_kind": "domain" if root == basedn.lower() else "ca" if root == "o=ipaca"
                             else "other", "replica_id": int(rid) if rid.isdigit() else None,
                             "bind_dn_group": bool(ldif.first(e, "nsds5ReplicaBindDNGroup"))})
    ruv_dom, re1 = _ruv(uri, basedn)
    ruv_ca, re2 = _ruv(uri, "o=ipaca")
    rc3, tasks, _, _ = _ldapi_search(uri, "cn=cleanallruv,cn=tasks,cn=config", "one", "(objectClass=*)", ("cn",))
    clean_tasks = len(tasks) if rc3 == 0 else (0 if rc3 == 32 else None)
    dm = _whoami_dm(uri)
    complete = dm is True and rc2 == 0 and not any(o.get("kind") == "other" and o.get("consumer") is None
                                                   for o in other if isinstance(o, dict))
    agreements.sort(key=lambda a: a["subject"])
    fields = {"agreements": agreements, "other_agreements": other[:16], "replicas": replicas,
              "ruv": {"domain": ruv_dom, "ca": ruv_ca}, "ruv_error": "; ".join(x for x in (re1, re2) if x) or None,
              "clean_tasks": clean_tasks, "identity_directory_manager": dm, "complete": complete,
              "count": len(agreements)}
    disp = (f"{len(agreements)} outbound agreement(s) on this server: "
            + (", ".join(f"{a['subject']} ({a['transport']}/{a['bind_method']}, port {a['port']})"
                         for a in agreements[:4]) or "none"))
    return _res("repl.agreements", params, OK, fields, disp,
                "ldapsearch -Y EXTERNAL (LDAPI, read-only) cn=mapping tree,cn=config: agreements, replicas, RUV")


def _principals(params):
    uri, basedn, err = _ldapi()
    if err:
        return _res("repl.principals", params, DENIED if "root" in err else NOT_RUN, {}, err)
    rc, entries, e1, cmd = _ldapi_search(uri, f"cn=services,cn=accounts,{basedn}", "one",
                                         "(krbprincipalname=ldap/*)", ("krbprincipalname",))
    if rc != 0:
        return _res("repl.principals", params, FAILED if rc is not None else NOT_RUN, {},
                    f"reading the LDAP service principals failed (exit {rc}): {e1}", cmd)
    hosts = set()
    for e in entries:
        for p in ldif.values(e, "krbprincipalname"):
            m = re.fullmatch(r"ldap/([A-Za-z0-9.-]{1,253})@[A-Z0-9.-]{1,253}", p.strip())
            if m and T.validate("fqdn", m.group(1)):
                hosts.add(m.group(1).lower())
    rc2, groups, e2, _ = _ldapi_search(uri, f"cn=replication managers,cn=sysaccounts,cn=etc,{basedn}", "base",
                                       "(objectClass=*)", ("member",))
    managers = set()
    if rc2 == 0:
        for g in groups:
            for m_dn in ldif.values(g, "member"):
                m = re.match(r"(?i)krbprincipalname=ldap/([A-Za-z0-9.-]{1,253})@", m_dn.strip())
                if m and T.validate("fqdn", m.group(1)):
                    managers.add(m.group(1).lower())
    dm = _whoami_dm(uri)
    fields = {"ldap_principals": sorted(hosts), "replication_managers": sorted(managers),
              "managers_read": rc2 == 0, "complete": dm is True and rc2 == 0}
    return _res("repl.principals", params, OK, fields,
                f"{len(hosts)} ldap/ service principal(s); {len(managers)} in cn=replication managers (this server's "
                "copy of the directory)", "ldapsearch -Y EXTERNAL (LDAPI, read-only) cn=services and "
                "cn=replication managers")


# --------------------------------------------------------------------------- the peer (read-only)


def _uri(host: str, port: str, transport: str) -> Tuple[str, List[str], Dict[str, str]]:
    tls_env = {"LDAPTLS_CACERT": IPA_CA, "LDAPTLS_REQCERT": "demand"}
    if transport == "SSL":
        return f"ldaps://{host}:{port}", [], tls_env
    if transport == "TLS":
        return f"ldap://{host}:{port}", ["-ZZ"], tls_env
    return f"ldap://{host}:{port}", [], {}


def _peer_rootdse(params):
    host, port, transport = params["host"], params["port"], params["transport"]
    uri, extra, env = _uri(host, port, transport)
    argv = (["ldapsearch", "-LLL", "-o", "ldif-wrap=no", "-o", "nettimeout=5", "-l", "10", "-x", "-H", uri] + extra
            + ["-s", "base", "-b", "", "(objectClass=*)", "currentTime", "vendorVersion", "namingContexts",
               "supportedSASLMechanisms"])
    before = _now()
    t0 = time.monotonic()
    rc, out, err = _exec(argv, timeout=15, env_extra=env)
    after = _now()
    cmd = f"ldapsearch -x -H {uri}{' -ZZ' if extra else ''} -s base -b '' currentTime   (anonymous root DSE read)"
    if rc is None and "not installed" in err:
        return _res("repl.peer_rootdse", params, NOT_RUN, {}, err, cmd)
    fields: Dict[str, Any] = {"answered": False, "ok": False, "error_class": None, "exit": rc,
                              "seconds": round(time.monotonic() - t0, 3), "offset_seconds": None,
                              "peer_time": None, "naming_contexts": [], "sasl_gssapi": None, "vendor": None}
    if rc is None:
        fields["error_class"] = "TRANSPORT"
        fields["detail"] = _c(err, 120)
        return _res("repl.peer_rootdse", params, OK, fields, f"{host}:{port}: no answer ({err})", cmd)
    if rc != 0:
        fields["error_class"] = classify_bind_error(err, rc)
        fields["detail"] = _c(_redact_log_line(err.strip().splitlines()[0] if err.strip() else f"exit {rc}"), 200)
        # an LDAP result code other than "can't contact" means the peer's LDAP server DID answer
        fields["answered"] = rc not in (255, 254) and fields["error_class"] not in ("TRANSPORT", "TLS")
        return _res("repl.peer_rootdse", params, OK, fields, f"{host}:{port}: {fields['detail']}", cmd)
    entries = ldif.parse(out)
    e = entries[0] if entries else {}
    fields.update(answered=True, ok=True, vendor=_c(ldif.first(e, "vendorVersion"), 120) or None,
                  naming_contexts=[_c(v.lower(), 200) for v in ldif.values(e, "namingContexts")][:8],
                  sasl_gssapi="GSSAPI" in [v.strip().upper() for v in ldif.values(e, "supportedSASLMechanisms")])
    peer = _parse_iso(_gentime(ldif.first(e, "currentTime")))
    if peer is not None:
        mid = before + (after - before) / 2
        fields["offset_seconds"] = round((mid - peer).total_seconds(), 1)
        fields["peer_time"] = peer.strftime("%Y-%m-%dT%H:%M:%SZ")
        fields["round_trip"] = round((after - before).total_seconds(), 3)
    disp = f"{host}:{port}: the Directory Server answers" + (
        f"; this host's clock is {abs(fields['offset_seconds']):.0f} s "
        f"{'ahead of' if fields['offset_seconds'] >= 0 else 'behind'} the peer's" if peer is not None else "")
    return _res("repl.peer_rootdse", params, OK, fields, disp, cmd)


def _ccache_dir() -> str:
    d = tempfile.mkdtemp(prefix="ipa-diagnose-repl-cc-")
    os.chmod(d, 0o700)
    return d


def _drop(d: str) -> bool:
    ok = True
    try:
        for n in os.listdir(d):
            try:
                os.unlink(os.path.join(d, n))
            except OSError:
                ok = False
        os.rmdir(d)
    except OSError:
        ok = False
    return ok


def _gssapi_bind(params):
    """Reproduce the supplier's bind as closely as practical: the Directory Server authenticates with its own key
    (ldap/<this host> in /etc/dirsrv/ds.keytab), gets a service ticket for ldap/<peer> from the KDC this host's
    Kerberos configuration names, and binds with SASL GSSAPI to the agreement's host, port and transport."""

    host, port, transport, principal = params["host"], params["port"], params["transport"], params["principal"]
    if not _is_root():
        return _res("repl.gssapi_bind", params, DENIED, {}, f"{DS_KEYTAB} can only be read as root")
    try:
        st = os.lstat(DS_KEYTAB)
    except OSError:
        return _res("repl.gssapi_bind", params, NOT_RUN, {}, f"{DS_KEYTAB} cannot be read")
    if not _stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
        return _res("repl.gssapi_bind", params, NOT_RUN, {}, f"{DS_KEYTAB} is not a plain regular file: not used")
    uri, extra, env = _uri(host, port, transport)
    d = _ccache_dir()
    cc_env = {"KRB5CCNAME": f"FILE:{d}/cc"}
    fields: Dict[str, Any] = {"kinit_ok": False, "kinit_class": None, "bind_attempted": False, "bind_ok": False,
                              "bind_error_class": None, "authzid": None, "ccache_removed": None}
    cmd = (f"kinit -k -t {DS_KEYTAB} {principal}; ldapwhoami -Y GSSAPI -N -H {uri}{' -ZZ' if extra else ''}   "
           "(private temporary credential cache, removed at once)")
    try:
        rc, _out, err = _exec(["kinit", "-k", "-t", DS_KEYTAB, principal], timeout=20, env_extra=cc_env)
        if rc is None and "not installed" in err:
            return _res("repl.gssapi_bind", params, NOT_RUN, {}, err, cmd)
        if rc != 0:
            from ipa_diagnose.resolution.client_checks import _classify_kinit

            fields["kinit_class"] = "timeout" if rc is None else _classify_kinit(err)
            fields["detail"] = _c(_redact_log_line(err.strip() or "no answer"), 200)
            return _res("repl.gssapi_bind", params, OK, fields,
                        f"kinit with {principal} from {DS_KEYTAB} failed: {fields['kinit_class'].replace('_', ' ')}",
                        cmd)
        fields["kinit_ok"] = True
        fields["bind_attempted"] = True
        argv = ["ldapwhoami", "-Q", "-Y", "GSSAPI", "-N", "-o", "nettimeout=5", "-H", uri] + extra
        env2 = dict(env, **cc_env)
        rc, out, err = _exec(argv, timeout=20, env_extra=env2)
        if rc == 0:
            fields.update(bind_ok=True, authzid=_c(out.strip(), 300))
            disp = f"GSSAPI bind as {principal} to {host}:{port} succeeded ({fields['authzid']})"
        else:
            fields["bind_error_class"] = "TRANSPORT" if rc is None else classify_bind_error(err, rc)
            fields["detail"] = _c(_redact_log_line(" ".join(err.split()) or f"exit {rc}"), 300)
            disp = f"GSSAPI bind as {principal} to {host}:{port} failed: {fields['detail']}"
        return _res("repl.gssapi_bind", params, OK, fields, disp, cmd)
    finally:
        fields["ccache_removed"] = _drop(d)


def _operator_ccache() -> Dict[str, str]:
    """The operator's own credential cache, if one was named: only well-formed values are passed on."""

    v = os.environ.get("KRB5CCNAME", "")
    if re.fullmatch(r"(?:FILE:/[A-Za-z0-9._/-]{1,200}|KEYRING:[A-Za-z0-9:._%-]{1,120}|KCM:[A-Za-z0-9:._-]{0,120}|"
                    r"DIR:/[A-Za-z0-9._/-]{1,200})", v):
        return {"KRB5CCNAME": v}
    return {}


def _peer_agreement(params):
    """The peer's agreement(s) towards this server, read from the peer with the operator's OWN Kerberos ticket
    (the same read `ipa-replica-manage list -v <peer>` makes). Nothing is written; an empty answer is 'not visible
    with this identity', never 'no agreement'."""

    host, port, transport, me = params["host"], params["port"], params["transport"], params["self_host"]
    env = _operator_ccache()
    rc, _o, err = _exec(["klist", "-s"], timeout=10, env_extra=env)
    if rc is None and "not installed" in err:
        return _res("repl.peer_agreement", params, NOT_RUN, {}, err)
    if rc != 0:
        return _res("repl.peer_agreement", params, NOT_RUN, {"ticket": False},
                    "no valid Kerberos ticket in this user's credential cache: the peer's side cannot be read "
                    "(kinit as an IPA administrator to read it, or run ipa-diagnose replication on the peer)",
                    "klist -s")
    uri, extra, tls_env = _uri(host, port, transport)
    argv = (["ldapsearch", "-LLL", "-o", "ldif-wrap=no", "-o", "nettimeout=5", "-l", "15", "-Q", "-Y", "GSSAPI",
             "-N", "-H", uri] + extra + ["-b", "cn=mapping tree,cn=config", "-s", "sub",
                                         f"(&(objectClass=nsds5replicationagreement)(nsDS5ReplicaHost={me}))"]
            + list(AGREEMENT_ATTRS))
    cmd = (f"ldapsearch -Y GSSAPI -H {uri} -b 'cn=mapping tree,cn=config' '(nsDS5ReplicaHost={me})'   "
           "(read-only, with your own Kerberos ticket)")
    rc, out, err = _exec(argv, timeout=25, env_extra=dict(tls_env, **env))
    if rc is None:
        return _res("repl.peer_agreement", params, NOT_RUN, {}, err, cmd)
    if rc == 50:
        return _res("repl.peer_agreement", params, DENIED, {"error_class": "INSUFFICIENT_ACCESS"},
                    f"{host} does not let this identity read its replication agreements", cmd)
    if rc != 0:
        cls = classify_bind_error(err, rc)
        return _res("repl.peer_agreement", params, NOT_RUN, {"error_class": cls},
                    f"reading {host}'s agreements failed: {_c(_redact_log_line(' '.join(err.split())), 200)}", cmd)
    entries = [e for e in ldif.parse(out)]
    for e in entries:
        for a in _SECRET_ATTRS:
            e.pop(a, None)
    rev = []
    for e in entries:
        root = ldif.first(e, "nsDS5ReplicaRoot").strip().lower()
        kind = "ca" if root == "o=ipaca" else "domain" if T.validate("domain_suffix", root) else "other"
        a = _agreement_projection(e, root if kind == "domain" else "")
        a["suffix_kind"] = kind
        a["supplier"] = host
        rev.append(a)
    fields = {"visible": bool(rev), "agreements": sorted(rev, key=lambda a: a["suffix_kind"]), "ticket": True}
    disp = (f"{host} has {len(rev)} agreement(s) towards this server: "
            + ", ".join(f"{a['suffix_kind']} ({(a['status_text'] or '?')[:60]})" for a in rev)
            if rev else f"no agreement of {host} towards this server is visible with this identity (not proof that "
                        "none exists)")
    return _res("repl.peer_agreement", params, OK, fields, disp, cmd)


# --------------------------------------------------------------------------- registry entries

ROOT, ANY = "root", "any"
_LDAPI_READ = ("read-only LDAP searches on this server's own LDAPI socket (SASL EXTERNAL as root); visible in this "
               "server's access log")


def specs() -> List[CheckSpec]:
    return [
        CheckSpec("repl.server", {}, "whether this host is an IPA server, and its realm, suffix and versions", _server,
                  ANY, evidence=("is_ipa_server", "host", "realm", "basedn", "ds_instance")),
        CheckSpec("repl.storage", {}, "free space and read-only state of the Directory Server's file system",
                  _storage, ANY, evidence=("free_bytes", "read_only")),
        CheckSpec("repl.ds_keytab", {}, "Directory Server keytab metadata (owner, mode, principals; never keys)",
                  _ds_keytab, ROOT, evidence=("present",),
                  secrets="klist -k lists principals and key versions; keys are never read"),
        CheckSpec("repl.topology", {}, "IPA servers, their roles, and the topology segments per suffix", _topology,
                  ROOT, timeout=45, evidence=("masters", "roles", "segments", "complete"), side_effects=_LDAPI_READ),
        CheckSpec("repl.agreements", {}, "this server's outbound replication agreements, replica configuration and "
                  "RUV", _agreements, ROOT, timeout=60, evidence=("agreements", "complete", "ruv"),
                  side_effects=_LDAPI_READ, secrets="nsDS5ReplicaCredentials is never requested or kept"),
        CheckSpec("repl.principals", {}, "ldap/ service principals and the replication managers group", _principals,
                  ROOT, timeout=45, evidence=("ldap_principals", "replication_managers"), side_effects=_LDAPI_READ),
        CheckSpec("repl.peer_rootdse", {"host": "fqdn", "port": "ldap_port", "transport": "repl_transport"},
                  "whether the peer's Directory Server answers, and its clock (anonymous root DSE read)",
                  _peer_rootdse, ANY, timeout=16, evidence=("answered", "ok", "error_class", "offset_seconds"),
                  side_effects="one anonymous LDAP connection and base search of the peer's root DSE (in the peer's "
                               "access log)"),
        CheckSpec("repl.gssapi_bind", {"host": "fqdn", "port": "ldap_port", "transport": "repl_transport",
                                       "principal": "ldap_principal"},
                  "the supplier's GSSAPI bind to the peer, reproduced with the Directory Server's keytab",
                  _gssapi_bind, ROOT, timeout=45,
                  evidence=("kinit_ok", "kinit_class", "bind_attempted", "bind_ok", "bind_error_class"),
                  side_effects=("one Kerberos AS request with the Directory Server's key and one service-ticket "
                                "request (in the KDC's log); one GSSAPI bind and whoami on the peer's Directory "
                                "Server (in its access log); a private temporary credential cache is created and "
                                "removed at once"),
                  secrets="the ticket stays in a private temporary cache that is deleted; keys are never read"),
        CheckSpec("repl.peer_agreement", {"host": "fqdn", "port": "ldap_port", "transport": "repl_transport",
                                          "self_host": "fqdn"},
                  "the peer's agreement(s) towards this server (read-only, with the operator's own ticket)",
                  _peer_agreement, ANY, timeout=40, evidence=("visible", "agreements"),
                  side_effects=("one service-ticket request with YOUR Kerberos ticket and one read-only search of "
                                "the peer's cn=config (in the peer's access log)"),
                  secrets="nsDS5ReplicaCredentials is never requested; the operator's ticket is only used, never "
                          "copied"),
    ]
