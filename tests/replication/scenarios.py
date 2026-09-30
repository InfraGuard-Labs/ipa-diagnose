"""SYNTHETIC replication scenarios (replay data for `ipa-diagnose replication`), built in code.

Lab shape (the same as the live lab, docs/truth/replication-truth-matrix.md): a line topology
ipa01 -- ipa02 -- ipa03 in realm LAB.TEST. Domain suffix: segments ipa01-ipa02 and ipa02-ipa03. CA suffix (o=ipaca):
ipa01-ipa02 only (ipa03 has no CA). ipa01 is the CA renewal master and the only DNS server.

``Lab(me)`` builds what the checks would answer on server `me`; mutators inject one fault each. Status strings follow
389-DS's own formats (replication/status.py). These rows are FIXTURE evidence: nothing here was captured live.
"""

from __future__ import annotations

import copy
import datetime
from typing import Any, Dict, List, Optional

REALM, DOMAIN, BASEDN = "LAB.TEST", "lab.test", "dc=lab,dc=test"
IPA01, IPA02, IPA03 = "ipa01.lab.test", "ipa02.lab.test", "ipa03.lab.test"
SEGMENTS = [("domain", IPA01, IPA02), ("domain", IPA02, IPA03), ("ca", IPA01, IPA02)]
OK_TEXT = "Error (0) Replica acquired successfully: Incremental update succeeded"
# What 389-DS really records for a failed SASL bind (agmt_set_last_update_status): the LDAP error text plus
# "(connection error)" - the Kerberos detail is only in its errors log. The *_TEXT variants below that carry the
# Kerberos phrase test the phrase table (some versions/paths may record it); the scenarios use the real shape and
# let ipa-diagnose's own reproduction name the Kerberos cause.
LOCAL_ERROR_TEXT = "Error (-2) Problem connecting to replica - LDAP error: Local error (connection error)"
TRANSPORT_TEXT = ("Error (-1) Problem connecting to replica - LDAP error: Can't contact LDAP server (connection error)")
NO_KDC_TEXT = ("Error (-2) Problem connecting to replica - LDAP error: Local error (SASL(-1): generic failure: GSSAPI "
               "Error: Unspecified GSS failure.  Minor code may provide more information (Cannot contact any KDC for "
               "realm 'LAB.TEST'))")
SKEW_TEXT = ("Error (-2) Problem connecting to replica - LDAP error: Local error (SASL(-1): generic failure: GSSAPI "
             "Error: Unspecified GSS failure.  Minor code may provide more information (Clock skew too great))")
NOT_FOUND_TEXT = ("Error (-2) Problem connecting to replica - LDAP error: Local error (SASL(-1): generic failure: "
                  "GSSAPI Error: Unspecified GSS failure.  Minor code may provide more information (Server "
                  "ldap/ipa02.lab.test@LAB.TEST not found in Kerberos database))")
CREDS_TEXT = ("Error (-2) Problem connecting to replica - LDAP error: Local error (SASL(-1): generic failure: GSSAPI "
              "Error: No credentials were supplied, or the credentials were unavailable or inaccessible (No Kerberos "
              "credentials available (default cache: FILE:/tmp/krb5cc_389)))")
INVALID_TEXT = "Error (49) Problem connecting to replica - LDAP error: Invalid credentials (connection error)"
DENIED_TEXT = ("Error (3) Replication error acquiring replica: Unable to acquire replica: permission denied. The bind "
               "dn does not have permission to supply replication updates to the replica. Will retry later. "
               "(permission denied)")
GENERATION_TEXT = ("Error (11) Replication error acquiring replica: Unable to acquire replica: the replica has a "
                   "different data version. Replica has different database generation ID, remote replica may need "
                   "to be initialized (different data version)")
BUSY_TEXT = "Error (1) Replication error acquiring replica: Unable to acquire replica: replica busy (replica busy)"
NO_SESSIONS_TEXT = "Error (0) No replication sessions started since server startup"
WEIRD_TEXT = "Error (77) Something no one has seen before happened"


def iso(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def key(check: str, params: Dict[str, str]) -> str:
    return check + "|" + ",".join(f"{k}={params[k]}" for k in sorted(params))


def ok(fields: Dict[str, Any], display: str = "ok", command: str = "") -> Dict[str, Any]:
    return {"status": "OK", "fields": fields, "display": display, "command": command}


def res(status: str, fields: Optional[Dict[str, Any]] = None, display: str = "") -> Dict[str, Any]:
    return {"status": status, "fields": fields or {}, "display": display}


class Lab:
    def __init__(self, me: str = IPA01, now: Optional[datetime.datetime] = None, freeipa: str = "4.13.3",
                 os_id: str = "fedora", os_version: str = "43"):
        self.me = me
        self.now = now or datetime.datetime.now(datetime.timezone.utc)
        self.data: Dict[str, Any] = {}
        self.recent = iso(self.now - datetime.timedelta(seconds=30))
        self._build(freeipa, os_id, os_version)

    # ---------------------------------------------------------------- baseline (healthy)

    def neighbours(self) -> List[tuple]:
        out = []
        for suffix, a, b in SEGMENTS:
            if a == self.me:
                out.append((suffix, b))
            elif b == self.me:
                out.append((suffix, a))
        return sorted(out)

    def agreement(self, suffix: str, consumer: str, text: str = OK_TEXT, **kw) -> Dict[str, Any]:
        a = {"subject": f"{suffix}:{consumer}", "suffix_kind": suffix,
             "suffix_root": BASEDN if suffix == "domain" else "o=ipaca", "consumer": consumer, "consumer_raw": None,
             "port": "389", "transport": "LDAP", "bind_method": "SASL/GSSAPI", "enabled": True, "status_text": text,
             "status_json": None, "last_update_start": self.recent, "last_update_end": self.recent,
             "update_in_progress": False, "last_init_status": "Error (0) Total update succeeded",
             "last_init_end": None, "name": f"meTo{consumer}"}
        a.update(kw)
        return a

    def _build(self, freeipa, os_id, os_version) -> None:
        me = self.me
        d = self.data
        d[key("repl.server", {})] = ok({
            "ipa_conf_present": True, "ipactl": True, "ds_instances": ["LAB-TEST"], "ds_instance": "LAB-TEST",
            "is_ipa_server": True, "host": me, "realm": REALM, "basedn": BASEDN, "domain": DOMAIN,
            "ldap_principal": f"ldap/{me}@{REALM}", "freeipa": freeipa, "ds_version": "3.1.5", "os": os_id,
            "os_version": os_version, "systemd": True, "is_root": True, "krb5_ktname": "/etc/dirsrv/ds.keytab",
            "krb5_ktname_source": "/etc/sysconfig/dirsrv-LAB-TEST"}, f"IPA server {me}")
        for svc, unit in (("dirsrv", "dirsrv@LAB-TEST.service"), ("krb5kdc", "krb5kdc.service")):
            d[key("systemd.unit", {"service": svc})] = ok({
                "unit": unit, "start_method": "ipactl", "load_state": "loaded", "active_state": "active",
                "sub_state": "running", "unit_file_state": "enabled", "result": "success"}, f"{unit}: active (running)")
        d[key("host.privilege", {})] = ok({"is_root": True}, "running as root")
        for unit in ("dirsrv@LAB-TEST.service", "krb5kdc.service"):
            d[key("systemd.journal_tail", {"unit": unit})] = ok({"lines": 3, "last_line": "stopped"}, "last log line")
        d[key("repl.storage", {})] = ok({"free_bytes": 10 * 2 ** 30, "total_bytes": 20 * 2 ** 30, "free_percent": 50.0,
                                         "read_only": False}, "/var/lib/dirsrv: 10240 MiB free")
        d[key("repl.ds_keytab", {})] = ok({
            "present": True, "is_symlink": False, "is_regular": True, "links": 1, "owner": "dirsrv", "group": "dirsrv",
            "mode": "0600", "dirsrv_can_read": True, "world_readable": False, "size": 400, "klist_ok": True,
            "principals": [f"ldap/{me}@{REALM}"], "kvnos": {f"ldap/{me}@{REALM}": [2]}},
            "/etc/dirsrv/ds.keytab: owner dirsrv:dirsrv, mode 0600")
        d[key("repl.topology", {})] = ok({
            "masters": [IPA01, IPA02, IPA03],
            "roles": {IPA01: ["CA", "DNS", "HTTP", "KDC"], IPA02: ["CA", "HTTP", "KDC"], IPA03: ["HTTP", "KDC"]},
            "flags": {IPA01: ["caRenewalMaster"]}, "hidden": [],
            "suffixes": [{"name": "ca", "root": "o=ipaca"}, {"name": "domain", "root": BASEDN}],
            "segments": [{"suffix": s, "left": a, "right": b, "name": f"{a.split('.')[0]}-to-{b.split('.')[0]}",
                          "direction": "both"} for s, a, b in SEGMENTS],
            "identity_directory_manager": True, "complete": True, "rejected_names": 0, "topology_read": True},
            "3 IPA server(s); 3 topology segment(s)")
        agreements = [self.agreement(s, c) for s, c in self.neighbours()]
        d[key("repl.agreements", {})] = ok({
            "agreements": agreements, "other_agreements": [],
            "replicas": [{"suffix_kind": "domain", "replica_id": 4, "bind_dn_group": True}],
            "ruv": {"domain": [{"rid": 4, "host": IPA01, "port": "389", "max_csn": "abc"},
                               {"rid": 5, "host": IPA02, "port": "389", "max_csn": "def"},
                               {"rid": 6, "host": IPA03, "port": "389", "max_csn": "ghi"}],
                    "ca": [{"rid": 7, "host": IPA01, "port": "389", "max_csn": "jkl"},
                           {"rid": 8, "host": IPA02, "port": "389", "max_csn": "mno"}]},
            "ruv_error": None, "clean_tasks": 0, "identity_directory_manager": True, "complete": True,
            "count": len(agreements)}, f"{len(agreements)} outbound agreement(s)")
        d[key("repl.principals", {})] = ok({
            "ldap_principals": [IPA01, IPA02, IPA03], "replication_managers": [IPA01, IPA02, IPA03],
            "managers_read": True, "complete": True}, "3 ldap/ service principal(s)")
        d[key("chrony.tracking", {})] = ok({"offset_seconds": 0.0002, "offset_abs": 0.0002, "direction": "ahead of",
                                            "leap_status": "Normal", "synchronized": True, "reference": "x"},
                                           "clock offset +0.000 s")
        for peer in sorted({c for _, c in self.neighbours()}):
            self.peer_ok(peer)

    def peer_ok(self, peer: str) -> None:
        d = self.data
        d[key("dns.address", {"name": peer})] = ok({"resolved": True, "addresses": ["172.30.0.11"], "seconds": 0.01,
                                                    "exit": 0}, f"{peer} resolves to 172.30.0.11")
        d[key("net.tcp", {"host": peer, "port": "389"})] = ok({"state": "open", "open": True, "seconds": 0.01},
                                                             f"TCP {peer}:389: open")
        d[key("net.tcp", {"host": peer, "port": "443"})] = ok({"state": "open", "open": True, "seconds": 0.01},
                                                             f"TCP {peer}:443: open")
        d[key("repl.peer_rootdse", {"host": peer, "port": "389", "transport": "LDAP"})] = ok({
            "answered": True, "ok": True, "error_class": None, "exit": 0, "seconds": 0.02, "offset_seconds": 0.3,
            "peer_time": self.recent, "naming_contexts": [BASEDN, "o=ipaca"], "sasl_gssapi": True,
            "vendor": "389 Project"}, f"{peer}:389: the Directory Server answers")
        d[key("repl.gssapi_bind", {"host": peer, "port": "389", "transport": "LDAP",
                                   "principal": f"ldap/{self.me}@{REALM}"})] = ok({
            "kinit_ok": True, "kinit_class": None, "bind_attempted": True, "bind_ok": True, "bind_error_class": None,
            "authzid": f"dn:krbprincipalname=ldap/{self.me}@{REALM},cn=services,cn=accounts,{BASEDN}",
            "ccache_removed": True}, "GSSAPI bind succeeded")
        rev = [dict(self.agreement(s, self.me), supplier=peer) for s, c in self.neighbours() if c == peer]
        d[key("repl.peer_agreement", {"host": peer, "port": "389", "transport": "LDAP", "self_host": self.me})] = ok(
            {"visible": True, "agreements": rev, "ticket": True}, f"{peer} has agreements towards this server")

    # ---------------------------------------------------------------- mutators (one fault each)

    def _agreements(self) -> List[Dict[str, Any]]:
        return self.data[key("repl.agreements", {})]["fields"]["agreements"]

    def set_status(self, peer: str, text: str, suffix: Optional[str] = None, **kw) -> "Lab":
        for a in self._agreements():
            if a["consumer"] == peer and (suffix is None or a["suffix_kind"] == suffix):
                a["status_text"] = text
                a.update(kw)
        return self

    def set_reverse(self, peer: str, text: Optional[str] = None, visible: bool = True, status: str = "OK",
                    suffix: Optional[str] = None) -> "Lab":
        k = key("repl.peer_agreement", {"host": peer, "port": "389", "transport": "LDAP", "self_host": self.me})
        if status != "OK":
            self.data[k] = res(status, {}, "no valid Kerberos ticket in this user's credential cache")
            return self
        f = self.data[k]["fields"]
        if not visible:
            f["visible"], f["agreements"] = False, []
            return self
        for a in f["agreements"]:
            if suffix is None or a["suffix_kind"] == suffix:
                a["status_text"] = text or OK_TEXT
        return self

    def unit(self, service: str, state: str = "inactive", result: str = "success") -> "Lab":
        f = self.data[key("systemd.unit", {"service": service})]["fields"]
        f.update(active_state=state, sub_state="dead" if state == "inactive" else state, result=result)
        return self

    def peer_ds_stopped(self, peer: str, recorded: bool = True) -> "Lab":
        """recorded=False: the agreement's status still shows the last successful session (live lab, run
        36654176983: 389-DS had not recorded the failure after 4 minutes and a pending change)."""

        if recorded:
            self.set_status(peer, TRANSPORT_TEXT)
        self.data[key("net.tcp", {"host": peer, "port": "389"})] = ok({"state": "refused", "open": False,
                                                                       "seconds": 0.01}, f"TCP {peer}:389: refused")
        self.data[key("repl.peer_rootdse", {"host": peer, "port": "389", "transport": "LDAP"})] = ok({
            "answered": False, "ok": False, "error_class": "TRANSPORT", "exit": 255, "seconds": 0.01,
            "offset_seconds": None, "peer_time": None, "naming_contexts": [], "sasl_gssapi": None, "vendor": None,
            "detail": "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)"}, f"{peer}:389: Can't contact LDAP server")
        return self

    def peer_unreachable(self, peer: str, recorded: bool = True) -> "Lab":
        if recorded:
            self.set_status(peer, TRANSPORT_TEXT)
        for port in ("389", "443"):
            self.data[key("net.tcp", {"host": peer, "port": port})] = ok({"state": "timeout", "open": False,
                                                                          "seconds": 5.0}, f"TCP {peer}:{port}: timeout")
        self.data[key("repl.peer_rootdse", {"host": peer, "port": "389", "transport": "LDAP"})] = ok({
            "answered": False, "ok": False, "error_class": "TRANSPORT", "exit": None, "seconds": 15.0,
            "offset_seconds": None, "peer_time": None, "naming_contexts": [], "sasl_gssapi": None, "vendor": None,
            "detail": "timed out after 15s"}, f"{peer}:389: no answer")
        return self

    def dns_broken(self, peer: str) -> "Lab":
        self.set_status(peer, TRANSPORT_TEXT)
        self.data[key("dns.address", {"name": peer})] = ok({"resolved": False, "addresses": [], "seconds": 0.02,
                                                            "exit": 2}, f"{peer} does not resolve (getent exit 2)")
        return self

    def gssapi(self, peer: str, **fields) -> "Lab":
        k = key("repl.gssapi_bind", {"host": peer, "port": "389", "transport": "LDAP",
                                     "principal": f"ldap/{self.me}@{REALM}"})
        self.data[k]["fields"].update(fields)
        self.data[k]["display"] = "GSSAPI bind failed" if not self.data[k]["fields"].get("bind_ok") else "ok"
        return self

    def local_kdc_stopped(self, affect_agreements: bool = True) -> "Lab":
        self.unit("krb5kdc")
        if affect_agreements:
            for _s, peer in self.neighbours():
                self.set_status(peer, LOCAL_ERROR_TEXT)
                self.gssapi(peer, kinit_ok=False, kinit_class="kdc_unreachable", bind_attempted=False, bind_ok=False)
        return self

    def clock_skew(self, peer: str, offset: float = 900.0) -> "Lab":
        self.set_status(peer, LOCAL_ERROR_TEXT)
        self.data[key("repl.peer_rootdse", {"host": peer, "port": "389", "transport": "LDAP"})]["fields"][
            "offset_seconds"] = offset
        self.gssapi(peer, bind_ok=False, bind_error_class="GSSAPI_CLOCK_SKEW")
        return self

    def rootdse_without_clock(self, peer: str, https_offset: Optional[float] = None) -> "Lab":
        """389-DS may not publish currentTime in the anonymous root DSE: the clock then comes from the peer's
        HTTPS Date header (or not at all)."""

        self.data[key("repl.peer_rootdse", {"host": peer, "port": "389", "transport": "LDAP"})]["fields"][
            "offset_seconds"] = None
        if https_offset is not None:
            self.data[key("ipa.https", {"server": peer})] = ok({
                "ca_file": True, "tls": "verified", "tls_ok": True, "http_status": 200,
                "offset_seconds": https_offset, "offset_abs": abs(https_offset), "date_source": "verified TLS",
                "round_trip": 0.02}, f"HTTPS to {peer}: TLS verified")
        return self

    def kerberos_failure(self, peer: str, text: str = LOCAL_ERROR_TEXT, **gssapi) -> "Lab":
        """An agreement whose last session failed at the SASL bind, with what the reproduction shows."""

        self.set_status(peer, text)
        return self.gssapi(peer, **gssapi)

    def keytab(self, **fields) -> "Lab":
        self.data[key("repl.ds_keytab", {})]["fields"].update(fields)
        return self

    def ruv(self, suffix: str, rid: int, host: str) -> "Lab":
        self.data[key("repl.agreements", {})]["fields"]["ruv"][suffix].append({"rid": rid, "host": host, "port": "389",
                                                                               "max_csn": None})
        return self

    def many_agreements(self, n: int) -> "Lab":
        ags = self._agreements()
        for i in range(n):
            h = f"extra{i:02d}.lab.test"
            ags.append(self.agreement("domain", h))
            self.peer_ok(h)
        self.data[key("repl.topology", {})]["fields"]["masters"] += [f"extra{i:02d}.lab.test" for i in range(n)]
        seg = self.data[key("repl.topology", {})]["fields"]["segments"]
        seg += [{"suffix": "domain", "left": self.me, "right": f"extra{i:02d}.lab.test", "name": f"x{i}",
                 "direction": "both"} for i in range(n)]
        return self

    def build(self) -> Dict[str, Any]:
        return copy.deepcopy(self.data)
