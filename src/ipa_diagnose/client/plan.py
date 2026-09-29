"""The client investigation plan: which checks exist, what each depends on, when each is worth running.

Dependency graph (from the documented client stack; see docs/client-mode.md "Why this order"):

    enrollment config ──► DNS (server name) ──► TCP 443/389/88 ──► TLS trust + server clock
          │                     └─ SRV records (only when SSSD discovers servers through DNS)
          ├─► host keytab ──► KDC accepts the host key (kinit -k)   [the KDC's answer separates clock, KDC,
          │                                                          unknown principal and stale key]
          └─► sssd.conf ─┐
    SSSD service ────────┴─► SSSD config check ─► SSSD domain online? ─► identity through SSSD
                                                                          ├─► does IPA have it? (host identity)
                                                                          ├─► system NSS stack ─► nsswitch.conf
                                                                          ├─► PAM stack of the service
                                                                          └─► PAM account phase (sssctl user-checks)
    only when an identity lookup fails although IPA has the name and SSSD is online:
          SSSD cache entry ─► SSSD log signals ─► cache database file

Local, independent checks (SSSD service, config) run even when the network side is broken, so a second,
independent cause is still found. Checks that cannot change the answer are skipped with the reason.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Tuple

from ipa_diagnose.planner.core import Classified, Context, Outcome, Req, Step

KRB_TOLERANCE = 300  # MIT Kerberos default clockskew (seconds); FreeIPA does not change it
CLOCK_WARN = 60
DEFAULT_GROUP = "admins"  # present in every IPA deployment (it cannot be deleted)

P, W, F, U = Outcome.PASS, Outcome.WARN, Outcome.FAIL, Outcome.UNKNOWN
PASSISH = (P, W)


def _ver(text: Optional[str]) -> Optional[Tuple[int, int]]:
    m = re.match(r"^(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def sssctl_applies(ctx: Context) -> Tuple[bool, str]:
    v = _ver(ctx.fact("env.sssd"))
    if v is None:
        return False, "the SSSD version is unknown, so sssctl is not used (unknown versions fail safe)"
    if v < (2, 0):
        return False, f"SSSD {ctx.fact('env.sssd')} is older than 2.0, which this version does not support"
    return True, f"SSSD {ctx.fact('env.sssd')}"


# ---------------------------------------------------------------- classifiers


def c_config(res, ctx) -> Classified:
    f = res.fields
    if not f.get("conf_present"):
        return Classified(F, "this host has no IPA client configuration (/etc/ipa/default.conf)", {"state": "absent"})
    missing = [k for k in ("domain", "realm", "server", "host") if not f.get(k)]
    if missing:
        return Classified(F, f"/etc/ipa/default.conf is incomplete or unreadable (no usable {', '.join(missing)})",
                          {"state": "incomplete"})
    return Classified(P, f"enrolled in {f['domain']} ({f['realm']}) as {f['host']}; server {f['server']}",
                      {"state": "ok", "srv_ldap": f"_ldap._tcp.{f['domain']}",
                       "srv_kerberos": f"_kerberos._tcp.{f['realm'].lower()}"})


def c_versions(res, ctx) -> Classified:
    f = res.fields
    return Classified(P, res.display, {"sssd": f.get("sssd"), "systemd": f.get("systemd")})


def c_sssd_conf(res, ctx) -> Classified:
    f = res.fields
    if not f.get("present"):
        return Classified(F, "/etc/sssd/sssd.conf does not exist", {"state": "absent"})
    if not f.get("parsable"):
        return Classified(F, "/etc/sssd/sssd.conf cannot be parsed", {"state": "unparsable"})
    if not f.get("ipa_domain"):
        return Classified(F, "sssd.conf has no domain with id_provider = ipa", {"state": "no_ipa_domain"})
    if not f.get("ipa_domain_active"):
        return Classified(F, f"the IPA domain [{f['ipa_domain']}] is not listed in 'domains =' of [sssd]",
                          {"state": "inactive", "sssd_domain": f["ipa_domain"]})
    host = ctx.fact("enroll.host")
    facts = {"state": "ok", "sssd_domain": f["ipa_domain"]}
    if f.get("ipa_hostname") and host and f["ipa_hostname"].lower() != host:
        facts["hostname_mismatch"] = True
        return Classified(W, f"sssd.conf ipa_hostname {f['ipa_hostname']} differs from /etc/ipa/default.conf host "
                          f"{host}", facts)
    return Classified(P, res.display, facts)


def c_resolvers(res, ctx) -> Classified:
    ns = res.fields.get("nameservers") or []
    if not ns:
        return Classified(F, "/etc/resolv.conf lists no resolver", {"count": 0})
    return Classified(P, res.display, {"count": len(ns)})


def c_address(res, ctx) -> Classified:
    if res.fields.get("resolved"):
        return Classified(P, res.display)
    return Classified(F, res.display)


def c_srv(res, ctx) -> Classified:
    f = res.fields
    if f.get("found"):
        return Classified(P, res.display, {"kind": "found"})
    kind = {"NXDOMAIN": "missing", "NOERROR": "missing", "TIMEOUT": "resolver_timeout", "SERVFAIL": "servfail",
            "NO_RESOLVER": "no_resolver"}.get(f.get("rcode"), "error")
    uses_srv = ctx.fact("sssd.uses_srv")
    return Classified(F if uses_srv else W, res.display, {"kind": kind})


def c_tcp(res, ctx) -> Classified:
    st = res.fields.get("state")
    return Classified(P if st == "open" else F, res.display, {"state": st})


def c_tls(res, ctx) -> Classified:
    f = res.fields
    tls = f.get("tls")
    if tls == "verified":
        return Classified(P, f"the IPA server's certificate verifies with this host's IPA CA (/etc/ipa/ca.crt)",
                          {"tls": tls})
    if tls in ("untrusted", "hostname_mismatch", "no_ca_file", "tls_error"):
        what = {"untrusted": "is not trusted by this host's IPA CA file",
                "hostname_mismatch": "does not match the server name",
                "no_ca_file": "cannot be checked: /etc/ipa/ca.crt is missing",
                "tls_error": "could not be negotiated"}[tls]
        return Classified(F, f"the IPA server's TLS certificate {what}", {"tls": tls})
    return Classified(U, res.display, {"tls": tls})


def c_time(res, ctx) -> Classified:
    off = res.fields.get("offset_seconds")
    if not isinstance(off, (int, float)):
        return Classified(U, "the server's clock could not be read", {"offset": None})
    src = res.fields.get("date_source") or "HTTPS"
    txt = f"this host's clock is {abs(off):.0f} s {'ahead of' if off >= 0 else 'behind'} the IPA server's ({src})"
    if abs(off) >= KRB_TOLERANCE:
        return Classified(F, txt + f": beyond Kerberos' {KRB_TOLERANCE} s tolerance", {"offset": off})
    if abs(off) >= CLOCK_WARN:
        return Classified(W, txt, {"offset": off})
    return Classified(P, txt, {"offset": off})


def c_chrony(res, ctx) -> Classified:
    f = res.fields
    if f.get("synchronized") and abs(f.get("offset_seconds") or 0) < 1:
        return Classified(P, res.display)
    return Classified(W, res.display + ("" if f.get("synchronized") else "; chronyd is not synchronized"))


def c_keytab(res, ctx) -> Classified:
    f = res.fields
    if not f.get("present"):
        return Classified(F, "/etc/krb5.keytab does not exist", {"state": "missing"})
    if not f.get("readable", True) or f.get("error"):
        return Classified(F, res.display, {"state": "unreadable"})
    expected = ctx.fact("enroll.host_principal")
    principals = f.get("principals") or []
    if expected and expected not in principals:
        return Classified(F, f"/etc/krb5.keytab has no key for {expected}"
                          + (f" (it has {', '.join(principals[:3])})" if principals else " (it is empty)"),
                          {"state": "principal_missing"})
    if f.get("world_or_group_readable") or f.get("owner_uid") not in (0, None):
        return Classified(W, f"/etc/krb5.keytab has keys for {expected}, but its permissions are {f.get('mode')} "
                          f"(owner uid {f.get('owner_uid')}); expected 0600 root", {"state": "permissions"})
    kv = (f.get("kvnos") or {}).get(expected) or []
    return Classified(P, f"/etc/krb5.keytab has keys for {expected}" + (f" (kvno {kv[-1]})" if kv else ""),
                      {"state": "ok"})


def c_kinit(res, ctx) -> Classified:
    f = res.fields
    if f.get("ok"):
        return Classified(P, "the KDC accepted this host's key: the host principal exists and the keytab matches",
                          {"error": None})
    return Classified(F, res.display, {"error": f.get("error_class")})


def c_unit(res, ctx) -> Classified:
    f = res.fields
    st = f.get("active_state")
    if f.get("load_state") not in (None, "", "loaded"):
        return Classified(F, f"sssd.service is not a loaded unit ({f.get('load_state')})", {"state": st})
    if st == "active":
        return Classified(P, "sssd.service is running", {"state": st})
    if st in ("activating", "reloading", "deactivating"):
        return Classified(W, f"sssd.service is {st}", {"state": st})
    return Classified(F, f"sssd.service is {st or 'not running'}"
                      + (f" (last result {f.get('result')})" if f.get("result") not in (None, "", "success") else ""),
                      {"state": st})


def c_config_check(res, ctx) -> Classified:
    f = res.fields
    if f.get("valid"):
        return Classified(P, "sssctl config-check found no issue")
    return Classified(F, res.display, {"issues": f.get("issues")})


def c_domain(res, ctx) -> Classified:
    f = res.fields
    if res.status != "OK":
        return Classified(U, res.display)
    if f.get("online"):
        return Classified(P, res.display, {"online": True})
    return Classified(F, res.display, {"online": False})


def c_found(what: str):
    def run(res, ctx) -> Classified:
        return Classified(P if res.fields.get("found") else F, res.display)

    return run


def c_ipa_user(res, ctx) -> Classified:
    ex = res.fields.get("exists")
    if ex is True:
        return Classified(P, res.display, {"exists": True})
    if ex is False:
        return Classified(F, res.display, {"exists": False})
    return Classified(U, res.display)


def c_nsswitch(res, ctx) -> Classified:
    f = res.fields
    if not f.get("present"):
        return Classified(F, "/etc/nsswitch.conf does not exist")
    if not f.get("passwd_has_sss"):
        return Classified(F, "/etc/nsswitch.conf does not list sss for passwd: the system does not ask SSSD for users",
                          {"passwd_has_sss": False})
    return Classified(P, res.display, {"passwd_has_sss": True})


def c_pam_stack(res, ctx) -> Classified:
    f = res.fields
    if not f.get("account_has_sss"):
        return Classified(F, res.display, {"account_has_sss": False, "auth_has_sss": f.get("auth_has_sss")})
    if not f.get("auth_has_sss"):
        return Classified(W, res.display, {"account_has_sss": True, "auth_has_sss": False})
    return Classified(P, res.display, {"account_has_sss": True, "auth_has_sss": True})


def c_user_checks(res, ctx) -> Classified:
    cls = res.fields.get("result_class")
    if res.status != "OK":
        return Classified(U, res.display)
    if cls == "success":
        return Classified(P, res.display, {"result": cls})
    return Classified(F, res.display, {"result": cls})


def c_cache_entry(res, ctx) -> Classified:
    f = res.fields
    if f.get("error"):
        return Classified(F, res.display, {"state": "error"})
    if f.get("present"):
        return Classified(W, res.display, {"state": "expired" if f.get("expired") else "present"})
    return Classified(P, res.display, {"state": "absent"})


def c_logs(res, ctx) -> Classified:
    counts = res.fields.get("counts") or {}
    if counts:
        return Classified(W, res.display, {"signals": sorted(counts)})
    return Classified(P, res.display, {"signals": []})


def c_cache_files(res, ctx) -> Classified:
    f = res.fields
    if not f.get("present"):
        return Classified(W, res.display, {"state": "absent"})
    if f.get("empty"):
        return Classified(F, res.display + " (empty)", {"state": "empty"})
    return Classified(P, res.display, {"state": "present"})


# ---------------------------------------------------------------- gates


def _user(ctx) -> Optional[str]:
    return ctx.input("user")


def g_srv(ctx) -> Tuple[bool, str]:
    uses = ctx.fact("sssd.uses_srv")
    if uses is True:
        return True, "SSSD discovers IPA servers through DNS SRV records (ipa_server = _srv_)"
    if uses is False:
        return False, "SSSD uses fixed servers (ipa_server lists no _srv_), so SRV records are not on its path"
    return True, "sssd.conf could not be read, so whether SSSD uses SRV discovery is unknown"


def g_chrony(ctx) -> Tuple[bool, str]:
    if ctx.fact("krb.error") == "clock_skew":
        return True, "the KDC reported clock skew: is this host's NTP working?"
    if ctx.outcome("time.server") in (F, W):
        return True, "the clock differs from the IPA server's: is this host's NTP working?"
    if ctx.outcome("time.server") != P:
        return True, "the IPA server's clock could not be read: is this host's own NTP working?"
    return False, "this host's clock agrees with the IPA server's"


def g_user(ctx) -> Tuple[bool, str]:
    return (True, f"the user {_user(ctx)} was asked about") if _user(ctx) else (False, "no --user given")


def g_group(ctx) -> Tuple[bool, str]:
    if not _user(ctx):
        return True, f"no --user given: the group {DEFAULT_GROUP}, present in every IPA domain, tests identity lookup"
    if ctx.outcome("id.user") == F:
        return True, f"the user lookup failed: does SSSD resolve anything at all (group {DEFAULT_GROUP})?"
    return False, "the user lookup already answered whether SSSD resolves identities"


def g_ipa_user(ctx) -> Tuple[bool, str]:
    if not _user(ctx):
        return False, "no --user given"
    if ctx.outcome("id.user") == F:
        return True, "SSSD does not resolve the user: does IPA itself have it?"
    return False, "SSSD resolves the user, so IPA has it"


def g_nss_system(ctx) -> Tuple[bool, str]:
    if not _user(ctx):
        return False, "no --user given"
    if ctx.outcome("id.user") == P:
        return True, "SSSD resolves the user: does the system's NSS stack (used by logins) resolve it too?"
    return False, "SSSD does not resolve the user, so the system stack cannot either"


def g_nsswitch(ctx) -> Tuple[bool, str]:
    if ctx.outcome("nss.system") == F:
        return True, "SSSD resolves the user but the system does not: is SSSD in nsswitch.conf?"
    return False, "no NSS integration symptom"


def g_service(ctx) -> Tuple[bool, str]:
    s = ctx.input("service")
    return (True, f"the PAM service {s} was asked about") if s else (False, "no --service given")


def g_user_checks(ctx) -> Tuple[bool, str]:
    if not (_user(ctx) and ctx.input("service")):
        return False, "needs --user and --service"
    if ctx.outcome("id.user") != P:
        return False, "SSSD does not resolve the user; the PAM account phase would only repeat that failure"
    return True, "the user resolves: does SSSD's account check (HBAC and account state, as at login) accept it here?"


def g_cache(ctx) -> Tuple[bool, str]:
    if ctx.outcome("id.user") != F:
        return False, "no failed user lookup to explain"
    if ctx.fact("ipa.user.exists") is not True:
        return False, "IPA itself was not shown to have the user, so the cache is not suspected"
    if ctx.outcome("sssd.domain") != P:
        return False, "SSSD is not online; an offline SSSD explains the failure before the cache does"
    return True, "IPA has the user and SSSD is online, yet SSSD does not resolve it: inspect SSSD's cache entry"


def g_logs(ctx) -> Tuple[bool, str]:
    reasons = []
    if ctx.outcome("sssd.service") == F:
        reasons.append("SSSD is not running")
    if ctx.outcome("sssd.domain") in (F, U):
        reasons.append("SSSD is offline or did not answer")
    if ctx.ran("cache.entry"):
        reasons.append("a user lookup fails although IPA has the user")
    if ctx.outcome("id.group") == F:
        reasons.append("SSSD does not resolve the group probe")
    if ctx.outcome("pam.acct") == F:
        reasons.append("SSSD's account check refused the user")
    if reasons:
        return True, "; ".join(reasons) + ": read SSSD's recent log signals"
    return False, "no SSSD symptom that its logs would explain"


def g_cache_files(ctx) -> Tuple[bool, str]:
    if "cache_db" in (ctx.fact("sssd.logs.signals") or []):
        return True, "SSSD's log reports cache database errors"
    if ctx.ran("cache.entry") and ctx.fact("cache.entry.state") in ("error",):
        return True, "reading SSSD's cache entry failed"
    return False, "no sign of a cache database problem"


def stop_not_enrolled(ctx) -> Optional[str]:
    if ctx.fact("enroll.state") == "absent":
        return "this host is not an IPA client (no /etc/ipa/default.conf): nothing client-side to investigate"
    return None


# ---------------------------------------------------------------- the plan

ROOT = True


def client_plan() -> list:
    conf = Req("enroll", PASSISH)
    return [
        Step("enroll", "ENROLLMENT", "client.ipa_conf", "IPA client configuration present",
             "Everything else needs the IPA domain, realm, server and this host's name from /etc/ipa/default.conf.",
             classify=c_config, stop=stop_not_enrolled),
        Step("env", "ENVIRONMENT", "client.versions", "SSSD and IPA client versions",
             "Version gates: sssctl is only used on SSSD versions it is known to behave on.", classify=c_versions),
        Step("sssd", "SSSD_CONFIG", "sssd.conf", "SSSD configured for the IPA domain",
             "SSSD is what resolves and authorizes IPA users on a client; its IPA domain must be configured and "
             "active.", classify=c_sssd_conf, needs_root=ROOT, after=("enroll",)),
        Step("dns.resolvers", "DNS", "dns.resolvers", "Resolvers configured",
             "Name resolution of the IPA server starts with the resolvers in /etc/resolv.conf.",
             classify=c_resolvers),
        Step("dns.server", "DNS", "dns.address", "IPA server name resolves",
             "SSSD, Kerberos and the IPA API all reach the server by name.",
             params={"name": ("fact", "enroll.server")}, requires=(conf,), classify=c_address),
        Step("dns.srv_ldap", "DNS", "dns.srv", "LDAP SRV records (_ldap._tcp)",
             "SSSD finds IPA servers through _ldap._tcp SRV records when ipa_server = _srv_.",
             params={"name": ("fact", "enroll.srv_ldap")}, requires=(conf,), after=("sssd",), when=g_srv,
             classify=c_srv),
        Step("dns.srv_kerberos", "DNS", "dns.srv", "Kerberos SRV records (_kerberos._tcp)",
             "The Kerberos library finds KDCs through _kerberos SRV records when no KDC is configured by name.",
             params={"name": ("fact", "enroll.srv_kerberos")}, requires=(conf,), after=("sssd",), when=g_srv,
             classify=c_srv),
        Step("net.https", "NETWORK", "net.tcp", "IPA server answers on 443 (HTTPS)",
             "The IPA API and the CA are served over HTTPS.",
             params={"host": ("fact", "enroll.server"), "port": "443"}, requires=(Req("dns.server"),),
             classify=c_tcp),
        Step("net.ldap", "NETWORK", "net.tcp", "IPA server answers on 389 (LDAP)",
             "SSSD reads users, groups and HBAC rules over LDAP.",
             params={"host": ("fact", "enroll.server"), "port": "389"}, requires=(Req("dns.server"),),
             classify=c_tcp),
        Step("net.kdc", "NETWORK", "net.tcp", "IPA server answers on 88 (Kerberos, TCP)",
             "Kerberos (host key, user tickets) needs the KDC; UDP 88 may work even if TCP is closed.",
             params={"host": ("fact", "enroll.server"), "port": "88"}, requires=(Req("dns.server"),),
             classify=c_tcp),
        Step("tls", "TLS", "ipa.https", "IPA server certificate trusted",
             "SSSD's LDAP (StartTLS) and the IPA API verify the server with /etc/ipa/ca.crt.",
             params={"server": ("fact", "enroll.server")}, requires=(Req("net.https"),), classify=c_tls),
        Step("time.server", "TIME", "ipa.https", "Clock agrees with the IPA server",
             "Kerberos refuses clocks more than 300 s apart; the server's own clock is read from its HTTPS Date "
             "header (the same request as the TLS check, reused).",
             params={"server": ("fact", "enroll.server")}, requires=(Req("net.https"),), after=("tls",),
             classify=c_time),
        Step("keytab", "KEYTAB", "krb.keytab", "Host keytab present with this host's key",
             "SSSD authenticates this host to IPA with /etc/krb5.keytab (metadata only; keys are never read).",
             requires=(conf,), classify=c_keytab, needs_root=ROOT),
        Step("krb", "KERBEROS", "krb.host_kinit", "KDC accepts this host's key",
             "The KDC's answer to the host key separates clock skew, an unreachable KDC, a deleted host principal "
             "and a stale keytab, which look alike from SSSD's side.",
             params={"principal": ("fact", "enroll.host_principal")}, requires=(Req("keytab", PASSISH),),
             after=("net.kdc", "time.server"), classify=c_kinit, needs_root=ROOT),
        Step("time.local", "TIME", "chrony.tracking", "This host's NTP synchronization",
             "Whether this host's own time service is working (only when a clock problem is in view).",
             after=("time.server", "krb"), when=g_chrony, classify=c_chrony),
        Step("sssd.service", "SSSD_SERVICE", "systemd.unit", "SSSD service running",
             "Without the running SSSD service no IPA identity resolves and no IPA login works.",
             params={"service": "sssd"}, classify=c_unit),
        Step("sssd.config", "SSSD_CONFIG", "sssd.config_check", "SSSD configuration valid (sssctl config-check)",
             "An invalid configuration can keep SSSD from starting or make it ignore options; restarting SSSD would "
             "not fix it.", classify=c_config_check, needs_root=ROOT, applies=sssctl_applies, after=("sssd",)),
        Step("sssd.domain", "SSSD_BACKEND", "sssd.domain_status", "SSSD online with the IPA server",
             "An offline SSSD answers only from its cache and cannot learn new users or rule changes.",
             params={"domain": ("fact", "sssd.sssd_domain")},
             requires=(Req("sssd.service"), Req("sssd", PASSISH)), classify=c_domain, needs_root=ROOT,
             applies=sssctl_applies),
        Step("id.user", "IDENTITY", "nss.user_sss", "User resolves through SSSD",
             "The first thing a login needs: SSSD must know the user.",
             params={"user": ("input", "user")}, requires=(Req("sssd.service"),), when=g_user,
             classify=c_found("user")),
        Step("id.group", "IDENTITY", "nss.group_sss", f"Group {DEFAULT_GROUP} resolves through SSSD",
             "A lookup of a name every IPA domain has shows whether SSSD resolves identities at all.",
             params={"group": ("input", "group")}, requires=(Req("sssd.service"),), after=("id.user",),
             when=g_group, classify=c_found("group")),
        Step("ipa.user", "IDENTITY", "ipa.api_user", "IPA has the user (asked as this host)",
             "Separates 'the user does not exist in IPA' from 'this client cannot see a user IPA has'. Asked with "
             "this host's own identity, as SSSD asks.",
             params={"principal": ("fact", "enroll.host_principal"), "user": ("input", "user")},
             requires=(Req("krb"), Req("tls")), after=("id.user",), when=g_ipa_user, classify=c_ipa_user,
             needs_root=ROOT),
        Step("nss.system", "NSS", "nss.user", "User resolves through the system NSS stack",
             "Logins look users up through nsswitch.conf, not through SSSD directly.",
             params={"user": ("input", "user")}, after=("id.user",), when=g_nss_system,
             classify=c_found("user")),
        Step("nss.switch", "NSS", "nss.nsswitch", "nsswitch.conf consults SSSD",
             "Only when SSSD resolves the user but the system does not.", after=("nss.system",), when=g_nsswitch,
             classify=c_nsswitch),
        Step("pam.stack", "PAM", "pam.stack", "PAM service reaches SSSD",
             "The service's PAM stack must call pam_sss for IPA users to authenticate and for HBAC to be enforced.",
             params={"service": ("input", "service")}, when=g_service, classify=c_pam_stack),
        Step("pam.acct", "PAM", "pam.user_checks", "SSSD's account check accepts the user (PAM account phase)",
             "Runs only the PAM account phase for the service, as at login, without any password: SSSD applies HBAC "
             "and account state on this host.",
             params={"user": ("input", "user"), "service": ("input", "service")},
             requires=(Req("sssd.service"),), after=("id.user", "pam.stack", "sssd.domain"), when=g_user_checks,
             classify=c_user_checks, needs_root=ROOT, applies=sssctl_applies),
        Step("cache.entry", "CACHE", "sssd.cache_user", "SSSD cache entry of the user",
             "Only when IPA has the user and SSSD is online but does not resolve it: what does SSSD's cache hold?",
             params={"user": ("input", "user")}, after=("ipa.user", "sssd.domain"), when=g_cache,
             classify=c_cache_entry, needs_root=ROOT, applies=sssctl_applies),
        Step("sssd.logs", "SSSD_LOGS", "sssd.log_signals", "SSSD log signals",
             "Only when SSSD shows a symptom: known problem signals in its recent logs (counts, one redacted "
             "example).", params={"domain": ("fact", "sssd.sssd_domain")},
             after=("sssd.service", "sssd.domain", "cache.entry", "id.group", "pam.acct"), when=g_logs,
             classify=c_logs, needs_root=ROOT),
        Step("cache.files", "CACHE", "sssd.cache_files", "SSSD cache database file",
             "Only when a cache database problem is signalled.", params={"domain": ("fact", "sssd.sssd_domain")},
             after=("sssd.logs",), when=g_cache_files, classify=c_cache_files, needs_root=ROOT),
    ]


def plan_inputs(user: Optional[str], service: Optional[str]) -> dict:
    """Inputs the plan's parameters may refer to (validated again by the registry types before any use)."""

    return {"user": user, "service": service, "group": DEFAULT_GROUP}
