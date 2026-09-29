"""Recorded (REPLAY) client check results: a healthy enrolled client plus one mutation per scenario.

These are SYNTHETIC fixtures shaped like the live lab's recorded answers (tests/fixtures/client/*/client_checks.json
are written from here by scripts/make_client_fixtures.py). They describe no live system.
"""

from __future__ import annotations

import copy
import json
import pathlib
from typing import Any, Callable, Dict

HOST, SERVER, DOMAIN, REALM = "client1.lab.test", "ipa01.lab.test", "lab.test", "LAB.TEST"
PRINCIPAL = f"host/{HOST}@{REALM}"
USER, SERVICE = "alice", "sshd"


def key(check_id: str, **params: str) -> str:
    return check_id + "|" + ",".join(f"{k}={params[k]}" for k in sorted(params))


def ok(fields: Dict[str, Any], display: str = "", command: str = "", status: str = "OK") -> Dict[str, Any]:
    return {"status": status, "fields": fields, "display": display, "command": command}


def healthy() -> Dict[str, Any]:
    d = {
        key("client.ipa_conf"): ok({"conf_present": True, "conf_readable": True, "domain": DOMAIN, "realm": REALM,
                                    "server": SERVER, "host": HOST, "ca_present": True, "kernel_hostname": HOST,
                                    "is_ipa_server": False, "host_principal": PRINCIPAL},
                                   f"IPA client configuration: domain {DOMAIN}, realm {REALM}, server {SERVER}, this "
                                   f"host {HOST}", "read /etc/ipa/default.conf"),
        key("client.versions"): ok({"sssd": "2.11.1", "ipa_client": "4.13.3", "os": "fedora", "os_version": "43",
                                    "systemd": True}, "SSSD 2.11.1, IPA client 4.13.3, fedora 43"),
        key("sssd.conf"): ok({"present": True, "parsable": True, "mode": "0600", "owner_uid": 0,
                              "active_domains": [DOMAIN], "domains": [{"name": DOMAIN, "id_provider": "ipa"}],
                              "ipa_domain": DOMAIN, "ipa_domain_active": True, "access_provider": "ipa",
                              "ipa_server": ["_srv_", SERVER], "uses_srv": True, "ipa_hostname": HOST,
                              "cache_credentials": "True", "fully_qualified_names": False, "services": "nss, pam, ssh"},
                             f"sssd.conf: IPA domain {DOMAIN}, servers _srv_, {SERVER}, access_provider ipa"),
        key("dns.resolvers"): ok({"nameservers": ["172.30.0.10"], "search": [DOMAIN], "stub": False},
                                 "1 resolver(s) in /etc/resolv.conf; search lab.test"),
        key("dns.address", name=SERVER): ok({"resolved": True, "addresses": ["172.30.0.10"], "seconds": 0.01,
                                             "exit": 0}, f"{SERVER} resolves to 172.30.0.10"),
        key("dns.srv", name=f"_ldap._tcp.{DOMAIN}"): ok({"rcode": "NOERROR", "resolver": "172.30.0.10",
                                                         "answers": [{"target": SERVER, "port": 389, "priority": 0}],
                                                         "found": True}, f"_ldap._tcp.{DOMAIN}: 1 record(s)"),
        key("dns.srv", name=f"_kerberos._tcp.{DOMAIN}"): ok({"rcode": "NOERROR", "resolver": "172.30.0.10",
                                                             "answers": [{"target": SERVER, "port": 88,
                                                                          "priority": 0}], "found": True},
                                                            f"_kerberos._tcp.{DOMAIN}: 1 record(s)"),
        key("net.tcp", host=SERVER, port="443"): ok({"state": "open", "open": True, "seconds": 0.002},
                                                    f"TCP {SERVER}:443: open"),
        key("net.tcp", host=SERVER, port="389"): ok({"state": "open", "open": True, "seconds": 0.002},
                                                    f"TCP {SERVER}:389: open"),
        key("net.tcp", host=SERVER, port="88"): ok({"state": "open", "open": True, "seconds": 0.002},
                                                   f"TCP {SERVER}:88: open"),
        key("ipa.https", server=SERVER): ok({"ca_file": True, "tls": "verified", "tls_ok": True, "http_status": 200,
                                             "offset_seconds": 0.4, "offset_abs": 0.4, "date_source": "verified TLS",
                                             "round_trip": 0.02}, f"HTTPS to {SERVER}: TLS verified"),
        key("chrony.tracking"): ok({"offset_seconds": 0.0001, "offset_abs": 0.0, "direction": "ahead of",
                                    "leap_status": "Normal", "synchronized": True, "reference": "ntp"},
                                   "clock offset +0.000 s, leap status Normal"),
        key("krb.keytab"): ok({"present": True, "mode": "0600", "owner_uid": 0, "is_regular": True, "size": 400,
                               "world_or_group_readable": False, "readable": True, "entries": 2,
                               "principals": [PRINCIPAL], "kvnos": {PRINCIPAL: [1]}},
                              "/etc/krb5.keytab: 2 key(s) for 1 principal(s), mode 0600"),
        key("krb.host_kinit", principal=PRINCIPAL): ok({"ok": True, "error_class": None, "detail": None},
                                                        f"the KDC accepted this host's key ({PRINCIPAL})"),
        key("systemd.unit", service="sssd"): ok({"unit": "sssd.service", "start_method": "systemctl",
                                                 "load_state": "loaded", "active_state": "active",
                                                 "sub_state": "running", "unit_file_state": "enabled",
                                                 "result": "success"}, "sssd.service: active (running)"),
        key("systemd.journal_tail", unit="sssd.service"): ok({"lines": 5, "last_line": "Started sssd.service"},
                                                             "last log line: Started sssd.service"),
        key("sssd.config_check"): ok({"exit": 0, "issues": 0, "merge_messages": 0, "valid": True, "missing": False,
                                      "examples": []}, "sssctl config-check: no issues"),
        key("sssd.domain_status", domain=DOMAIN): ok({"exit": 0, "online": True,
                                                      "active_servers": [{"service": "IPA", "server": SERVER}],
                                                      "no_active_server": False},
                                                     f"SSSD domain {DOMAIN} is online; active IPA {SERVER}"),
        key("nss.user_sss", user=USER): ok({"found": True, "exit": 0, "seconds": 0.03, "name": USER,
                                            "uid": 1234500001, "gid": 1234500001},
                                           f"SSSD (getent -s sss) resolves {USER} (UID 1234500001)"),
        key("nss.user", user=USER): ok({"found": True, "exit": 0, "seconds": 0.02, "name": USER, "uid": 1234500001,
                                        "gid": 1234500001},
                                       f"the system's NSS stack (getent) resolves {USER} (UID 1234500001)"),
        key("nss.group_sss", group="admins"): ok({"found": True, "exit": 0, "seconds": 0.02, "gid": 1234500000},
                                                 "SSSD resolves group admins"),
        key("nss.nsswitch"): ok({"present": True, "passwd": ["files", "sss", "systemd"], "group": ["files", "sss"],
                                 "passwd_has_sss": True, "group_has_sss": True},
                                "nsswitch passwd: files sss systemd; group: files sss"),
        key("pam.stack", service=SERVICE): ok({"service_file": True, "files": ["sshd", "password-auth"],
                                               "account_modules": ["pam_unix.so", "pam_sss.so"],
                                               "auth_modules": ["pam_unix.so", "pam_sss.so"],
                                               "account_has_sss": True, "auth_has_sss": True},
                                              f"PAM service {SERVICE}: pam_sss in account yes, in auth yes"),
        key("pam.user_checks", user=USER, service=SERVICE): ok({"exit": 0, "pam_result": "Success",
                                                                "result_class": "success", "nss_found": True},
                                                               f"PAM account check for {USER} via {SERVICE} on this "
                                                               "host: Success"),
        key("ipa.api_user", principal=PRINCIPAL, user=USER): ok({"exists": True, "server": SERVER, "uid": USER,
                                                                 "disabled": False, "uidnumber": 1234500001},
                                                                f"IPA has user {USER}"),
        key("sssd.cache_user", user=USER): ok({"exit": 0, "present": True, "expired": False},
                                              f"SSSD cache has an entry for {USER}"),
        key("sssd.log_signals", domain=DOMAIN): ok({"lines_read": 300, "counts": {}, "examples": {}},
                                                   "300 recent SSSD log line(s): no known problem signal"),
        key("sssd.cache_files", domain=DOMAIN): ok({"present": True, "size": 1581056, "mode": "0600",
                                                    "empty": False, "modified_seconds_ago": 30},
                                                   f"/var/lib/sss/db/cache_{DOMAIN}.ldb: 1581056 bytes"),
        key("host.privilege"): ok({"is_root": True}, "running as root"),
        key("binary.present", name="sss_cache"): ok({"present": True}, "sss_cache: installed"),
        key("binary.present", name="sssctl"): ok({"present": True}, "sssctl: installed"),
    }
    return d


def _set(d, k, **fields):
    d[k]["fields"].update(fields)


def _disp(d, k, text):
    d[k]["display"] = text


def sssd_stopped(d):
    _set(d, key("systemd.unit", service="sssd"), active_state="inactive", sub_state="dead", result="success")
    _disp(d, key("systemd.unit", service="sssd"), "sssd.service: inactive (dead)")
    for k in (key("nss.user_sss", user=USER), key("nss.user", user=USER)):
        _set(d, k, found=False, exit=2)
    _set(d, key("nss.group_sss", group="admins"), found=False, exit=2)
    d[key("sssd.domain_status", domain=DOMAIN)] = ok({}, "sssctl domain-status: SSSD is not running",
                                                     status="FAILED")


def dns_down(d):
    _set(d, key("dns.address", name=SERVER), resolved=False, addresses=[], exit=2)
    _disp(d, key("dns.address", name=SERVER), f"{SERVER} does not resolve (getent exit 2)")
    for n in (f"_ldap._tcp.{DOMAIN}", f"_kerberos._tcp.{DOMAIN}"):
        _set(d, key("dns.srv", name=n), rcode="TIMEOUT", answers=[], found=False)
        _disp(d, key("dns.srv", name=n), f"{n}: no record (TIMEOUT)")
    _set(d, key("krb.host_kinit", principal=PRINCIPAL), ok=False, error_class="kdc_unresolvable",
         detail="Cannot resolve network address for KDC in realm")
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False, active_servers=[])
    _disp(d, key("sssd.domain_status", domain=DOMAIN), f"SSSD domain {DOMAIN} is OFFLINE")
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 4, "server_unreachable": 3})


def time_skew(d):
    _set(d, key("ipa.https", server=SERVER), offset_seconds=3600.0, offset_abs=3600.0)
    _set(d, key("krb.host_kinit", principal=PRINCIPAL), ok=False, error_class="clock_skew",
         detail="Clock skew too great while getting initial credentials")
    _set(d, key("chrony.tracking"), synchronized=False, leap_status="Not synchronised", offset_seconds=3600.0)
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False)
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 2, "clock_skew": 5})


def server_unreachable(d):
    for port in ("443", "389", "88"):
        _set(d, key("net.tcp", host=SERVER, port=port), state="timeout", open=False)
        _disp(d, key("net.tcp", host=SERVER, port=port), f"TCP {SERVER}:{port}: timeout")
    _set(d, key("krb.host_kinit", principal=PRINCIPAL), ok=False, error_class="kdc_unreachable",
         detail="Cannot contact any KDC for realm 'LAB.TEST'")
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False)


def kdc_unreachable(d):
    _set(d, key("net.tcp", host=SERVER, port="88"), state="refused", open=False)
    _set(d, key("krb.host_kinit", principal=PRINCIPAL), ok=False, error_class="kdc_unreachable",
         detail="Cannot contact any KDC for realm 'LAB.TEST'")
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False)
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 2, "kdc_unreachable": 4})


def host_entry_missing(d):
    _set(d, key("krb.host_kinit", principal=PRINCIPAL), ok=False, error_class="principal_unknown",
         detail="Client not found in Kerberos database")
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False)
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 2, "keytab": 3})


def keytab_missing(d):
    d[key("krb.keytab")] = ok({"present": False}, "/etc/krb5.keytab does not exist")
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False)
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 2, "keytab": 3})


def keytab_mismatch(d):
    _set(d, key("krb.host_kinit", principal=PRINCIPAL), ok=False, error_class="key_rejected",
         detail="Preauthentication failed while getting initial credentials")
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False)
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 2, "keytab": 3})


def keytab_wrong_principal(d):
    other = f"host/old-name.{DOMAIN}@{REALM}"
    _set(d, key("krb.keytab"), principals=[other], kvnos={other: [1]})


def sssd_config_invalid(d):
    _set(d, key("sssd.config_check"), exit=22, issues=2, valid=False,
         examples=["[rule/allowed_domain_options]: Attribute 'ipa_srever' is not allowed in section 'domain/lab.test'"])
    _disp(d, key("sssd.config_check"), "sssctl config-check: 2 issue(s)")
    sssd_stopped(d)
    _set(d, key("systemd.unit", service="sssd"), active_state="failed", result="exit-code")


def sssd_offline_unexplained(d):
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False, active_servers=[])
    _disp(d, key("sssd.domain_status", domain=DOMAIN), f"SSSD domain {DOMAIN} is OFFLINE")
    _set(d, key("nss.user_sss", user=USER), found=False, exit=2)
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 3})


def user_missing_in_ipa(d):
    _set(d, key("nss.user_sss", user=USER), found=False, exit=2)
    _disp(d, key("nss.user_sss", user=USER), f"SSSD (getent -s sss) does not resolve {USER} (exit 2)")
    _set(d, key("nss.group_sss", group="admins"), found=True)
    d[key("ipa.api_user", principal=PRINCIPAL, user=USER)] = ok({"exists": False, "server": SERVER},
                                                                f"IPA has no user named {USER}")


def stale_cache(d):
    _set(d, key("nss.user_sss", user=USER), found=False, exit=2)
    _disp(d, key("nss.user_sss", user=USER), f"SSSD (getent -s sss) does not resolve {USER} (exit 2)")
    _set(d, key("sssd.cache_user", user=USER), present=True, expired=False)


def cache_db_error(d):
    _set(d, key("nss.user_sss", user=USER), found=False, exit=2)
    _disp(d, key("nss.user_sss", user=USER), f"SSSD (getent -s sss) does not resolve {USER} (exit 2)")
    d[key("sssd.cache_user", user=USER)] = ok({"exit": 1, "present": False,
                                               "error": "Unable to open cache ldb: Input/output error"},
                                              f"SSSD cache has no entry for {USER}")
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"cache_db": 7},
         examples={"cache_db": "sysdb_search_user_by_name: ldb error: Input/output error"})


def nss_not_integrated(d):
    _set(d, key("nss.user", user=USER), found=False, exit=2)
    _set(d, key("nss.nsswitch"), passwd=["files", "systemd"], passwd_has_sss=False)


def pam_not_integrated(d):
    _set(d, key("pam.stack", service=SERVICE), account_modules=["pam_unix.so"], auth_modules=["pam_unix.so"],
         account_has_sss=False, auth_has_sss=False)
    _disp(d, key("pam.stack", service=SERVICE), f"PAM service {SERVICE}: pam_sss in account NO, in auth NO")


def pam_denied(d):
    _set(d, key("pam.user_checks", user=USER, service=SERVICE), pam_result="Permission denied",
         result_class="permission_denied")
    _disp(d, key("pam.user_checks", user=USER, service=SERVICE),
          f"PAM account check for {USER} via {SERVICE} on this host: Permission denied")


def ca_untrusted(d):
    _set(d, key("ipa.https", server=SERVER), tls="untrusted", tls_ok=False, date_source="unverified TLS")
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False)
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 2, "tls": 4})


def sssd_fails_cache_db(d):
    sssd_stopped(d)
    _set(d, key("systemd.unit", service="sssd"), active_state="failed", result="exit-code")
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"cache_db": 3},
         examples={"cache_db": "Could not open cache database: Input/output error"})


def dns_and_config(d):
    dns_down(d)
    sssd_config_invalid(d)


def collector_timeout(d):
    d[key("krb.host_kinit", principal=PRINCIPAL)] = ok({}, "timed out after 25s", status="NOT_RUN")
    d[key("sssd.domain_status", domain=DOMAIN)] = ok({}, "timed out after 20s", status="NOT_RUN")


def unsupported_sssd(d):
    _set(d, key("client.versions"), sssd="1.16.5")


def unknown_sssd(d):
    _set(d, key("client.versions"), sssd=None)


def hostile(d):
    evil = "\x1b[31mEVIL\x1b]0;pwn\x07 ‮gnirts ldap_default_authtok=Secret123"
    _set(d, key("sssd.log_signals", domain=DOMAIN), counts={"offline": 1}, examples={"offline": evil})
    _disp(d, key("sssd.domain_status", domain=DOMAIN), evil)
    _set(d, key("sssd.domain_status", domain=DOMAIN), online=False,
         active_servers=[{"service": evil, "server": evil}])
    _disp(d, key("nss.user_sss", user=USER), evil)
    _set(d, key("nss.user_sss", user=USER), found=False)


def contradicting(d):
    """IPA's hbactest authorizes (given by access), but SSSD's account check on the host refuses."""
    pam_denied(d)


def not_enrolled(d):
    d[key("client.ipa_conf")] = ok({"conf_present": False, "conf_readable": False, "domain": None, "realm": None,
                                    "server": None, "host": None, "ca_present": False, "kernel_hostname": "box1",
                                    "is_ipa_server": False, "host_principal": None},
                                   "/etc/ipa/default.conf does not exist")


def srv_missing_fixed_fallback(d):
    for n in (f"_ldap._tcp.{DOMAIN}", f"_kerberos._tcp.{DOMAIN}"):
        _set(d, key("dns.srv", name=n), rcode="NXDOMAIN", answers=[], found=False)
        _disp(d, key("dns.srv", name=n), f"{n}: no record (NXDOMAIN)")


def fixed_servers_no_srv(d):
    _set(d, key("sssd.conf"), ipa_server=[SERVER], uses_srv=False)
    srv_missing_fixed_fallback(d)


SCENARIOS: Dict[str, Callable[[Dict[str, Any]], None]] = {
    "healthy": lambda d: None,
    "sssd-stopped": sssd_stopped,
    "dns-failure": dns_down,
    "time-skew": time_skew,
    "server-unreachable": server_unreachable,
    "kdc-unreachable": kdc_unreachable,
    "host-entry-missing": host_entry_missing,
    "keytab-missing": keytab_missing,
    "keytab-mismatch": keytab_mismatch,
    "keytab-wrong-principal": keytab_wrong_principal,
    "sssd-config-invalid": sssd_config_invalid,
    "sssd-offline-unexplained": sssd_offline_unexplained,
    "user-missing-in-ipa": user_missing_in_ipa,
    "stale-cache": stale_cache,
    "cache-db-error": cache_db_error,
    "nss-not-integrated": nss_not_integrated,
    "pam-not-integrated": pam_not_integrated,
    "pam-denied": pam_denied,
    "ca-untrusted": ca_untrusted,
    "dns-and-config": dns_and_config,
    "sssd-fails-cache-db": sssd_fails_cache_db,
    "collector-timeout": collector_timeout,
    "unsupported-sssd": unsupported_sssd,
    "unknown-sssd": unknown_sssd,
    "hostile-output": hostile,
    "contradicting": contradicting,
    "not-enrolled": not_enrolled,
    "srv-missing-fixed-fallback": srv_missing_fixed_fallback,
    "fixed-servers-no-srv": fixed_servers_no_srv,
}


def _finalize(d: Dict[str, Any]) -> None:
    """Displays follow the (mutated) fields, as the real checks produce them."""

    k = key("krb.host_kinit", principal=PRINCIPAL)
    f = d[k]["fields"]
    if d[k]["status"] == "OK":
        d[k]["display"] = (f"the KDC accepted this host's key ({PRINCIPAL})" if f.get("ok") else
                           f"kinit with the host keytab failed: {str(f.get('error_class')).replace('_', ' ')} "
                           f"({f.get('detail')})")
    k = key("sssd.log_signals", domain=DOMAIN)
    counts = d[k]["fields"].get("counts") or {}
    d[k]["display"] = "300 recent SSSD log line(s): " + (", ".join(f"{a} x{b}" for a, b in sorted(counts.items()))
                                                        or "no known problem signal")
    k = key("sssd.domain_status", domain=DOMAIN)
    if d[k]["status"] == "OK" and d[k]["fields"].get("online") is False and "OFFLINE" not in d[k]["display"] \
            and "EVIL" not in d[k]["display"]:
        d[k]["display"] = f"SSSD domain {DOMAIN} is OFFLINE"
    for k, what in ((key("nss.user_sss", user=USER), "SSSD (getent -s sss)"),
                    (key("nss.user", user=USER), "the system's NSS stack (getent)")):
        f = d[k]["fields"]
        if not f.get("found") and "EVIL" not in d[k]["display"]:
            d[k]["display"] = f"{what} does not resolve {USER} (exit {f.get('exit', 2)})"
    k = key("nss.group_sss", group="admins")
    if not d[k]["fields"].get("found"):
        d[k]["display"] = "SSSD does not resolve group admins (exit 2)"


def build(name: str) -> Dict[str, Any]:
    d = copy.deepcopy(healthy())
    SCENARIOS[name](d)
    _finalize(d)
    return d


def write(directory: pathlib.Path, name: str, is_root: bool = True) -> pathlib.Path:
    out = directory / name
    out.mkdir(parents=True, exist_ok=True)
    (out / "client_checks.json").write_text(json.dumps(build(name), indent=1, sort_keys=True, ensure_ascii=True)
                                            + "\n", encoding="utf-8")
    (out / "meta.json").write_text(json.dumps({"is_root": is_root, "source": "SYNTHETIC replay fixture (tests/client/"
                                                                             "scenarios.py); describes no live system"},
                                              indent=1) + "\n", encoding="utf-8")
    return out
