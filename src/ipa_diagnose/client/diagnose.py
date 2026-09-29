"""L4 for client mode: turn the planner's trace into diagnoses, with causal roles.

Rules read step outcomes and the facts classifiers extracted. Two principles keep the root cause honest:

1. **A downstream failure is never blamed on its own layer while an upstream failure explains it.** The KDC's error
   class decides between clock, KDC, principal and key; SSSD is blamed only when DNS, network, TLS, time and the host
   key all passed; the cache is considered only when IPA has the user AND SSSD is online.
2. **No story is forced.** Independent failures (for example DNS broken and sssd.conf invalid) are reported as
   PRIMARY + INDEPENDENT; a failure nothing explains is UNDIAGNOSED; evidence that disagrees is CONTRADICTING.

Every diagnosis names the steps it rests on (evidence) and what was ruled out.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from ipa_diagnose.planner.core import Outcome, Trace

P, W, F, U, S = Outcome.PASS, Outcome.WARN, Outcome.FAIL, Outcome.UNKNOWN, Outcome.SKIPPED

LAYER = {"ENROLLMENT": 0, "SSSD_CONFIG": 1, "DNS": 2, "SSSD_SERVICE": 2, "NETWORK": 3, "TLS": 4, "TIME": 4,
         "KEYTAB": 5, "KERBEROS": 6, "SSSD_BACKEND": 7, "IDENTITY": 8, "CACHE": 8, "NSS": 9, "PAM": 10}

PRIMARY, RELATED, INDEPENDENT, UNDIAGNOSED, CONTRADICTING, WARNING = (
    "PRIMARY", "RELATED", "INDEPENDENT", "UNDIAGNOSED", "CONTRADICTING", "WARNING")


@dataclasses.dataclass
class ClientDiagnosis:
    code: str
    title: str
    capability: str
    confidence: str  # HIGH | MEDIUM | LOW
    detail: str
    impact: str
    evidence: List[str]
    severity: str = "FAIL"  # FAIL | WARN
    related_to: Optional[str] = None
    kind: Optional[str] = None  # None | UNDIAGNOSED | CONTRADICTING
    next_steps: List[str] = dataclasses.field(default_factory=list)
    resolution_key: Optional[str] = None
    variant: Optional[str] = None
    bindings: Dict[str, Any] = dataclasses.field(default_factory=dict)
    blocks_runtime: bool = False
    blocks_authentication: bool = False
    role: str = ""


class _T:
    """Read helpers over the trace."""

    def __init__(self, trace: Trace, inputs: Dict[str, Any]):
        self.trace, self.inputs = trace, inputs

    def o(self, sid: str) -> Optional[Outcome]:
        r = self.trace.get(sid)
        return r.outcome if r else None

    def f(self, sid: str, name: str, default: Any = None) -> Any:
        r = self.trace.get(sid)
        if r is None or r.outcome == S:
            return default
        return r.facts.get(name, r.fields.get(name, default))

    def s(self, sid: str) -> str:
        r = self.trace.get(sid)
        return r.summary if r else ""


def _q(v: Any) -> str:
    import shlex

    return shlex.quote(str(v))


def diagnose(trace: Trace, inputs: Dict[str, Any]) -> List[ClientDiagnosis]:
    t = _T(trace, inputs)
    out: List[ClientDiagnosis] = []
    add = out.append
    server = t.f("enroll", "server") or "the IPA server"
    host = t.f("enroll", "host") or "this host"
    user = inputs.get("user")
    service = inputs.get("service")
    principal = t.f("enroll", "host_principal") or f"host/{host}"

    def find(code: str) -> Optional[ClientDiagnosis]:
        return next((d for d in out if d.code == code), None)

    # ---------------------------------------------------------------- enrollment
    if t.o("enroll") == F:
        if t.f("enroll", "state") == "absent":
            add(ClientDiagnosis("CLIENT_NOT_ENROLLED", "This host is not an enrolled IPA client", "ENROLLMENT", "HIGH",
                                "/etc/ipa/default.conf does not exist: ipa-client-install has not been run here, or "
                                "the client was uninstalled.",
                                "No IPA user can be resolved or log in here through IPA.", ["enroll"],
                                blocks_runtime=True, blocks_authentication=True,
                                next_steps=["ls -l /etc/ipa/default.conf /etc/krb5.keytab /etc/sssd/sssd.conf   "
                                            "(read-only)"],
                                resolution_key="client.not-enrolled"))
            return _roles(out)
        add(ClientDiagnosis("CLIENT_CONFIG_INCOMPLETE", "The IPA client configuration is incomplete", "ENROLLMENT",
                            "HIGH", t.s("enroll"), "Checks that need the IPA server, domain or realm cannot run.",
                            ["enroll"], blocks_runtime=True))
    if t.o("sssd") == F:
        state = t.f("sssd", "state")
        add(ClientDiagnosis("SSSD_NOT_CONFIGURED", "SSSD is not configured for the IPA domain", "SSSD_CONFIG", "HIGH",
                            t.s("sssd") + ". The client enrollment is incomplete or was changed afterwards.",
                            "IPA users are not resolved and cannot log in through SSSD on this host.", ["sssd"],
                            blocks_runtime=True, blocks_authentication=True,
                            next_steps=["sssctl config-check   (read-only)", "sssctl domain-list   (read-only)"],
                            variant=state))
    elif t.o("sssd") == W and t.f("sssd", "hostname_mismatch"):
        add(ClientDiagnosis("HOSTNAME_MISMATCH", "SSSD and the IPA client configuration name this host differently",
                            "SSSD_CONFIG", "MEDIUM", t.s("sssd"),
                            "SSSD evaluates HBAC for the name in ipa_hostname; rules written for the other name do not "
                            "apply to logins here.", ["sssd", "enroll"], severity="WARN"))

    # ---------------------------------------------------------------- DNS / network / TLS
    dns_fail = None
    if t.o("dns.server") == F:
        srv_kinds = {t.f("dns.srv_ldap", "kind"), t.f("dns.srv_kerberos", "kind")}
        if t.o("dns.resolvers") == F:
            code, title, conf = ("DNS_NO_RESOLVER", "No DNS resolver is configured", "HIGH")
            why = "/etc/resolv.conf lists no nameserver, so the IPA server name cannot be resolved."
        elif srv_kinds & {"resolver_timeout", "no_resolver"}:
            code, title, conf = ("DNS_RESOLVER_NOT_ANSWERING", "The configured DNS resolvers do not answer", "HIGH")
            why = (f"{server} does not resolve and the resolvers in /etc/resolv.conf time out on a direct query as "
                   "well: the resolvers (or the path to them) are down, not a single missing record.")
        else:
            code, title, conf = ("DNS_SERVER_UNRESOLVABLE", f"The IPA server name {server} does not resolve", "HIGH")
            why = (f"The system resolver returns no address for {server}, the server this client is configured to "
                   "use. The record may be missing or stale in DNS, or the resolvers here are not the IPA-aware ones.")
        dns_fail = ClientDiagnosis(code, title, "DNS", conf, why,
                                   "SSSD, Kerberos and the IPA API cannot reach the server by name: IPA identities and "
                                   "logins fail once SSSD's cache no longer covers them.",
                                   ["dns.server", "dns.resolvers", "dns.srv_ldap"], blocks_runtime=True,
                                   blocks_authentication=True,
                                   next_steps=[f"getent ahosts {_q(server)}   (read-only)", "cat /etc/resolv.conf",
                                               f"dig {_q(server)}   (if bind-utils is installed; read-only)"])
        add(dns_fail)
    else:
        srv_fails = [sid for sid in ("dns.srv_ldap", "dns.srv_kerberos") if t.o(sid) == F]
        if srv_fails:
            fixed = [s for s in (t.f("sssd", "ipa_server") or []) if s != "_srv_"]
            kinds = {t.f(s, "kind") for s in srv_fails}
            add(ClientDiagnosis(
                "DNS_SRV_MISSING", "IPA SRV records are not found in DNS", "DNS", "HIGH",
                ", ".join(t.s(s) for s in srv_fails) + (". The resolvers did not answer." if
                                                         "resolver_timeout" in kinds else "."),
                ("SSSD discovers servers through these records; it falls back to the listed server(s) "
                 f"{', '.join(fixed)}, so failover to other replicas does not work." if fixed else
                 "SSSD is configured to find servers only through DNS SRV records, so it finds none."),
                srv_fails, severity="WARN" if fixed else "FAIL", blocks_runtime=not fixed,
                next_steps=[f"dig -t SRV {_q(t.f('enroll', 'srv_ldap'))}   (read-only)"]))
    net = {p: t.o(f"net.{p}") for p in ("https", "ldap", "kdc")}
    if t.o("dns.server") == P and net["https"] == F and net["ldap"] == F:
        states = {t.f(f"net.{p}", "state") for p in ("https", "ldap", "kdc") if net[p] == F}
        add(ClientDiagnosis("SERVER_UNREACHABLE", f"The IPA server {server} does not answer", "NETWORK", "HIGH",
                            f"{server} resolves, but its HTTPS and LDAP ports do not answer ({', '.join(sorted(states))})"
                            ": the server is down, or a firewall or route blocks this client.",
                            "SSSD goes offline: only cached users can log in, with cached credentials; new users, "
                            "group and HBAC changes are not seen.", ["net.https", "net.ldap", "net.kdc", "dns.server"],
                            blocks_runtime=True, blocks_authentication=True,
                            next_steps=[f"curl -sI https://{server}/ipa/config/ca.crt   (read-only)",
                                        "on the server: ipactl status   (read-only)"]))
    elif net["ldap"] == F and net["https"] == P:
        add(ClientDiagnosis("LDAP_UNREACHABLE", f"LDAP on {server} does not answer from this client", "NETWORK",
                            "HIGH", t.s("net.ldap") + "; HTTPS answers, so the server is up.",
                            "SSSD reads users, groups and HBAC rules over LDAP: it cannot refresh them.",
                            ["net.ldap", "net.https"], blocks_runtime=True,
                            next_steps=["on the server: ipactl status; firewall-cmd --list-services   (read-only)"]))
    elif net["https"] == F and net["ldap"] == P:
        add(ClientDiagnosis("HTTPS_UNREACHABLE", f"HTTPS on {server} does not answer from this client", "NETWORK",
                            "HIGH", t.s("net.https") + "; LDAP answers, so the server is up.",
                            "The IPA API and CA are not reachable from here (ipa commands, certificate requests); "
                            "SSSD's LDAP and Kerberos traffic is not affected. The server's clock and TLS "
                            "certificate could not be checked.", ["net.https", "net.ldap"], severity="WARN",
                            next_steps=["on the server: systemctl status httpd   (read-only)"]))
    if t.o("tls") == F:
        tls = t.f("tls", "tls")
        add(ClientDiagnosis("CA_TRUST_FAILED", "The IPA server's certificate is not trusted here", "TLS", "HIGH",
                            t.s("tls") + ".",
                            "SSSD's LDAP (StartTLS) and the IPA tools verify the server with /etc/ipa/ca.crt: they "
                            "cannot connect securely.", ["tls"], blocks_runtime=True, variant=tls,
                            next_steps=["openssl x509 -in /etc/ipa/ca.crt -noout -subject -enddate   (read-only)",
                                        f"openssl s_client -connect {server}:443 -CAfile /etc/ipa/ca.crt </dev/null  "
                                        " (read-only)"]))

    # ---------------------------------------------------------------- time
    krb_err = t.f("krb", "error") if t.o("krb") == F else None
    if t.o("time.server") == F:
        krb_ok = t.o("krb") == P
        add(ClientDiagnosis("CLOCK_SKEW", "This host's clock is too far from the IPA server's", "TIME",
                            "MEDIUM" if krb_ok else "HIGH",
                            t.s("time.server") + (". Yet the KDC accepted this host's key just now: the KDC that "
                                                  "answered may be another server, or a clock just changed"
                                                  if krb_ok else "."),
                            "Kerberos refuses tickets across more than 300 s: the host key, user passwords and "
                            "GSSAPI logins fail; SSSD goes offline.", ["time.server", "time.local", "krb"],
                            blocks_runtime=True, blocks_authentication=True, resolution_key="client.clock-skew",
                            next_steps=["chronyc tracking; chronyc sources   (read-only)", "timedatectl   (read-only)"]))
    elif krb_err == "clock_skew":
        add(ClientDiagnosis("CLOCK_SKEW", "The KDC reports clock skew with this host", "TIME", "MEDIUM",
                            "kinit with the host key failed with 'Clock skew too great'"
                            + (", although the IPA server's HTTPS clock agrees with this host: the KDC that answered "
                               "may be another server, whose clock is wrong" if t.o("time.server") == P else "") + ".",
                            "Kerberos authentication from this host fails until the clocks agree.",
                            ["krb", "time.server"], blocks_runtime=True, blocks_authentication=True,
                            resolution_key="client.clock-skew",
                            next_steps=["chronyc tracking   (read-only, here and on every IPA server)"]))
    elif t.o("time.server") == W:
        add(ClientDiagnosis("CLOCK_DRIFT", "This host's clock drifts from the IPA server's", "TIME", "HIGH",
                            t.s("time.server") + " (under Kerberos' 300 s tolerance).",
                            "No failure yet; Kerberos fails once the difference passes 300 s.", ["time.server"],
                            severity="WARN", next_steps=["chronyc tracking   (read-only)"]))
    if t.o("time.local") == W and not find("CLOCK_SKEW"):
        add(ClientDiagnosis("NTP_NOT_SYNCHRONIZED", "This host's time service is not synchronized", "TIME", "MEDIUM",
                            t.s("time.local") + ".", "The clock may drift until Kerberos fails.", ["time.local"],
                            severity="WARN", next_steps=["chronyc sources   (read-only)"]))

    # ---------------------------------------------------------------- keytab / Kerberos
    ks = t.f("keytab", "state")
    if t.o("keytab") == F:
        if ks == "missing":
            add(ClientDiagnosis("HOST_KEYTAB_MISSING", "The host keytab /etc/krb5.keytab is missing", "KEYTAB", "HIGH",
                                "This host has no key to authenticate itself to IPA.",
                                "SSSD cannot authenticate this host to IPA: it stays offline, and new logins "
                                "fail once cached data is not enough.", ["keytab"], blocks_runtime=True,
                                blocks_authentication=True, resolution_key="client.host-keytab-problem",
                                variant="missing",
                                next_steps=["ls -l /etc/krb5.keytab*   (read-only; a moved or renamed copy?)"]))
        elif ks == "principal_missing":
            add(ClientDiagnosis("HOST_KEYTAB_WRONG_PRINCIPAL", f"The host keytab has no key for {principal}",
                                "KEYTAB", "HIGH", t.s("keytab") + ". The keytab belongs to another name, or this "
                                "host was renamed after enrollment.",
                                "SSSD cannot authenticate this host to IPA under the configured name.", ["keytab"],
                                blocks_runtime=True, blocks_authentication=True,
                                resolution_key="client.host-keytab-problem", variant="principal-missing",
                                next_steps=["klist -k /etc/krb5.keytab   (read-only; principals only)"]))
        else:
            add(ClientDiagnosis("HOST_KEYTAB_UNREADABLE", "The host keytab cannot be read", "KEYTAB", "MEDIUM",
                                t.s("keytab"), "SSSD may not be able to use it either.", ["keytab"],
                                blocks_runtime=True))
    elif t.o("keytab") == W and ks == "permissions":
        add(ClientDiagnosis("HOST_KEYTAB_PERMISSIONS", "The host keytab is readable by more than root", "KEYTAB",
                            "HIGH", t.s("keytab") + ".",
                            "Anyone who can read it can act as this host towards IPA (a security problem, not a "
                            "login failure).", ["keytab"], severity="WARN",
                            next_steps=["ls -lZ /etc/krb5.keytab   (read-only)"]))
    if krb_err and krb_err != "clock_skew":
        upstream = dns_fail or find("SERVER_UNREACHABLE")
        if krb_err in ("kdc_unreachable", "kdc_unresolvable"):
            add(ClientDiagnosis("KDC_UNREACHABLE", "No KDC answers this host", "KERBEROS", "HIGH",
                                t.s("krb") + (". TCP 88 on the server is " + str(t.f("net.kdc", "state"))
                                              if t.o("net.kdc") in (P, F) else "") + ".",
                                "Kerberos authentication (host and users) fails; SSSD goes offline.",
                                ["krb", "net.kdc"], blocks_runtime=True, blocks_authentication=True,
                                related_to=upstream.code if upstream else None,
                                next_steps=["on the server: systemctl status krb5kdc   (read-only)",
                                            "grep -A5 '\\[realms\\]' /etc/krb5.conf   (read-only)"]))
        elif krb_err == "principal_unknown":
            add(ClientDiagnosis("HOST_PRINCIPAL_UNKNOWN", f"IPA's KDC does not know {principal}", "ENROLLMENT", "HIGH",
                                "The KDC answered that this host's principal is not in its database: the host entry was "
                                "deleted in IPA, or this host was renamed or enrolled under another name.",
                                "This host cannot authenticate to IPA at all: SSSD stays offline.", ["krb", "keytab"],
                                blocks_runtime=True, blocks_authentication=True,
                                resolution_key="client.host-principal-unknown",
                                next_steps=[f"ipa host-show {_q(host)}   (read-only, from an admin workstation)",
                                            f"ipa host-find --pkey-only {_q(host.split('.')[0])}   (read-only)"]))
        elif krb_err in ("key_rejected", "keytab_no_entry"):
            add(ClientDiagnosis("HOST_KEY_REJECTED", "IPA's KDC rejects this host's key", "KEYTAB", "HIGH",
                                "The KDC knows the host principal but the key in /etc/krb5.keytab does not match: the "
                                "keytab is out of date (for example the host was enrolled again elsewhere, or a new "
                                "keytab was retrieved for it).",
                                "This host cannot authenticate to IPA: SSSD stays offline; users' password logins "
                                "fail ticket validation.", ["krb", "keytab"], blocks_runtime=True,
                                blocks_authentication=True, resolution_key="client.host-keytab-problem",
                                variant="key-rejected",
                                next_steps=["klist -k /etc/krb5.keytab   (read-only; key versions)",
                                            f"ipa host-show {_q(host)}   (read-only; 'Keytab: True' means IPA holds a "
                                            "key)"]))
        else:
            add(ClientDiagnosis("KERBEROS_FAILED", "Kerberos with the host key failed", "KERBEROS", "LOW",
                                t.s("krb"), "SSSD may not be able to authenticate this host.", ["krb"],
                                kind=UNDIAGNOSED, blocks_runtime=True))

    # ---------------------------------------------------------------- SSSD service / configuration / backend
    cfg_bad = t.o("sssd.config") == F
    if cfg_bad:
        add(ClientDiagnosis("SSSD_CONFIG_INVALID", "The SSSD configuration has errors", "SSSD_CONFIG", "HIGH",
                            t.s("sssd.config") + ".",
                            "SSSD may refuse to start or ignore options; restarting it does not fix this.",
                            ["sssd.config"], blocks_runtime=t.o("sssd.service") == F,
                            next_steps=["sssctl config-check   (read-only; lists each issue)"]))
    db_at_start = t.o("sssd.service") == F and "cache_db" in (t.f("sssd.logs", "signals") or []) and not cfg_bad
    if db_at_start:
        add(ClientDiagnosis("SSSD_CACHE_DB_ERROR", "SSSD's log reports cache database errors while it is down",
                            "CACHE", "MEDIUM",
                            "SSSD is not running and its recent log reports errors opening or reading its cache "
                            "database. Whether the database stopped it cannot be proven while SSSD is down (the "
                            "server, the user and the cache entry cannot be checked through it).",
                            "Starting SSSD again may fail the same way.", ["sssd.service", "sssd.logs",
                                                                          "cache.files"],
                            blocks_runtime=True, resolution_key="client.sssd-cache-db-error", variant="suspected",
                            next_steps=["journalctl -u sssd -n 50   (read-only)",
                                        "ls -l /var/lib/sss/db/   (read-only)", "df -h /var/lib/sss   (read-only)"]))
    if t.o("sssd.service") == F:
        add(ClientDiagnosis("SSSD_NOT_RUNNING", "SSSD is not running", "SSSD_SERVICE", "HIGH",
                            t.s("sssd.service") + ".",
                            "No IPA user or group resolves here (apart from nscd/memory caches), and no IPA login "
                            "works.", ["sssd.service"], blocks_runtime=True, blocks_authentication=True,
                            related_to="SSSD_CONFIG_INVALID" if cfg_bad else "SSSD_CACHE_DB_ERROR" if db_at_start
                            else None,
                            resolution_key="client.sssd-not-running",
                            next_steps=["systemctl status sssd   (read-only)",
                                        "journalctl -u sssd -n 30   (read-only)"]))
    upstream_net = next((d for d in out if d.severity == "FAIL" and d.capability in (
        "DNS", "NETWORK", "TLS", "TIME", "KEYTAB", "KERBEROS", "ENROLLMENT")), None)
    offline = t.o("sssd.domain") == F
    if offline:
        signals = t.f("sssd.logs", "signals") or []
        explaining = [s for s in signals if s != "offline"]
        add(ClientDiagnosis("SSSD_OFFLINE", "SSSD is offline", "SSSD_BACKEND",
                            "HIGH" if upstream_net else "MEDIUM",
                            t.s("sssd.domain") + (f"; explained by: {upstream_net.title}" if upstream_net else
                                                  "; the server name resolves, the server answers and the KDC "
                                                  "accepts this host's key, so the reason is inside SSSD's own "
                                                  "connection") + (f". SSSD log signals: {', '.join(signals)}"
                                                                   if signals else "") + ".",
                            "Only cached users and groups resolve, and only users who logged in before can log in "
                            "(with cached credentials, if enabled). New users and policy changes are not seen.",
                            ["sssd.domain", "sssd.logs"], blocks_runtime=True,
                            related_to=upstream_net.code if upstream_net else None,
                            kind=None if upstream_net or explaining else UNDIAGNOSED,
                            next_steps=["sssctl domain-status $(sssctl domain-list | head -1) -o -a   (read-only)",
                                        "journalctl -u sssd -n 50   (read-only)"]))

    # ---------------------------------------------------------------- identity
    fq = bool(t.f("sssd", "fully_qualified_names"))
    if user and t.o("id.user") == F:
        exists = t.f("ipa.user", "exists")
        if offline or t.o("sssd.domain") == U:
            add(ClientDiagnosis("IDENTITY_LOOKUP_FAILS", f"SSSD does not resolve {user}", "IDENTITY", "HIGH",
                                t.s("id.user") + "; SSSD is not online, so it answers only from its cache, which "
                                "does not hold this user.", "This user cannot log in here.", ["id.user", "sssd.domain"],
                                blocks_runtime=True, related_to="SSSD_OFFLINE" if offline else None,
                                kind=None if offline else UNDIAGNOSED))
        elif exists is False:
            add(ClientDiagnosis("USER_NOT_IN_IPA", f"IPA has no user named {user}", "IDENTITY", "HIGH",
                                f"Asked with this host's own identity, IPA answers that {user} does not exist. SSSD "
                                "is right not to resolve it: this is not a client problem.",
                                "No IPA login for this name anywhere.", ["id.user", "ipa.user"], blocks_runtime=True,
                                next_steps=[f"ipa user-show {_q(user)}   (read-only, from an admin workstation)",
                                            f"ipa user-find --preserved=true --login={_q(user)}   (read-only)"]))
        elif exists is True and t.o("sssd.domain") == P:
            ce_state = t.f("cache.entry", "state")
            signals = t.f("sssd.logs", "signals") or []
            db_bad = "cache_db" in signals or ce_state == "error" or t.o("cache.files") == F
            if fq:
                add(ClientDiagnosis("NAME_NOT_QUALIFIED", f"SSSD expects fully qualified names ({user}@DOMAIN)",
                                    "IDENTITY", "HIGH",
                                    "sssd.conf sets use_fully_qualified_names = True for the IPA domain, so the short "
                                    f"name {user} is not looked up.",
                                    f"{user} must log in as {user}@{t.f('sssd', 'ipa_domain') or 'domain'}.",
                                    ["id.user", "sssd"], blocks_runtime=True,
                                    next_steps=[f"getent passwd {_q(user + '@' + str(t.f('sssd', 'ipa_domain')))}   "
                                                "(read-only)"]))
            elif db_bad:
                add(ClientDiagnosis("SSSD_CACHE_DB_ERROR", "SSSD's cache database is failing", "CACHE",
                                    "HIGH" if ("cache_db" in signals and ce_state in ("error", "absent")) else "MEDIUM",
                                    f"IPA has {user}, SSSD is online and the server, DNS, time and host key are fine, "
                                    f"yet SSSD does not resolve {user}"
                                    + (", and SSSD's log reports cache database errors" if "cache_db" in signals else "")
                                    + (", and reading its cache entry failed" if ce_state == "error" else "")
                                    + (", and the cache file is empty" if t.o("cache.files") == F else "") + ".",
                                    "Lookups through SSSD fail on this host even though IPA is healthy.",
                                    ["id.user", "ipa.user", "sssd.domain", "cache.entry", "sssd.logs", "cache.files"],
                                    blocks_runtime=True, resolution_key="client.sssd-cache-db-error",
                                    variant=None if ("cache_db" in signals and ce_state in ("error", "absent"))
                                    else "suspected",
                                    bindings={"user": user, "domain": t.f("sssd", "sssd_domain")}))
            elif ce_state in ("present", "expired"):
                add(ClientDiagnosis("SSSD_CACHE_INCONSISTENT", f"SSSD's cached entry for {user} is not being served",
                                    "CACHE", "MEDIUM",
                                    f"IPA has {user}, SSSD is online and holds a cache entry for it, yet a lookup "
                                    "through SSSD fails: the cached entry is inconsistent with what SSSD serves "
                                    "(for example a stale entry after a rename or UID change).",
                                    "This user cannot log in here until SSSD refreshes the entry.",
                                    ["id.user", "ipa.user", "sssd.domain", "cache.entry"], blocks_runtime=True,
                                    resolution_key="client.sssd-stale-user-entry",
                                    bindings={"user": user, "domain": t.f("sssd", "sssd_domain")}))
            else:
                add(ClientDiagnosis("IDENTITY_LOOKUP_FAILS", f"SSSD does not resolve {user} although IPA has it",
                                    "IDENTITY", "LOW",
                                    f"IPA has {user}, SSSD is online and holds no cache entry for it, and no cache "
                                    "database error is signalled. Possible reasons ipa-diagnose does not check: "
                                    "filter_users, min_id/max_id, an ID range or ID view, or a POSIX attribute missing "
                                    "on the user.", "This user cannot log in here.",
                                    ["id.user", "ipa.user", "sssd.domain", "cache.entry"], kind=UNDIAGNOSED,
                                    blocks_runtime=True,
                                    next_steps=[f"sssctl user-show {_q(user)}   (read-only)",
                                                "grep -E 'filter_users|min_id|max_id' /etc/sssd/sssd.conf   "
                                                "(read-only)"]))
        else:
            add(ClientDiagnosis("IDENTITY_LOOKUP_FAILS", f"SSSD does not resolve {user}", "IDENTITY", "LOW",
                                t.s("id.user") + "; whether IPA has the user could not be established ("
                                + (t.s("ipa.user") or "the check did not run") + ").",
                                "This user cannot log in here.", ["id.user", "ipa.user"], blocks_runtime=True,
                                related_to=upstream_net.code if upstream_net else None,
                                kind=None if upstream_net else UNDIAGNOSED))
    if t.o("id.group") == F and not find("SSSD_OFFLINE") and not find("SSSD_NOT_RUNNING"):
        add(ClientDiagnosis("IDENTITY_LOOKUP_FAILS_GENERAL", "SSSD resolves no IPA identity", "IDENTITY",
                            "MEDIUM", t.s("id.group") + ", a group every IPA domain has.",
                            "No IPA identity resolves here.", ["id.group"], blocks_runtime=True,
                            related_to=upstream_net.code if upstream_net else None,
                            kind=None if upstream_net else UNDIAGNOSED))

    # ---------------------------------------------------------------- NSS / PAM
    if t.o("nss.system") == F:
        no_sss = t.o("nss.switch") == F
        add(ClientDiagnosis("NSS_NOT_USING_SSSD", "The system does not ask SSSD for users", "NSS",
                            "HIGH" if no_sss else "MEDIUM",
                            (t.s("nss.switch") if no_sss else
                             f"SSSD resolves {user} but the system's NSS stack does not") + ".",
                            "Logins and tools use NSS: IPA users are unknown to them.", ["nss.system", "nss.switch"],
                            blocks_runtime=True, kind=None if no_sss else UNDIAGNOSED,
                            next_steps=["authselect current   (read-only)", "grep -E '^(passwd|group):' "
                                        "/etc/nsswitch.conf   (read-only)"]))
    if t.o("pam.stack") == F:
        add(ClientDiagnosis("PAM_SERVICE_WITHOUT_SSSD", f"PAM service {service} does not use SSSD", "PAM", "HIGH",
                            t.s("pam.stack") + ".",
                            f"Logins through {service} do not reach SSSD: IPA users cannot authenticate there, and "
                            "FreeIPA HBAC is not enforced by SSSD for it.", ["pam.stack"], blocks_runtime=True,
                            next_steps=["authselect current   (read-only)", f"cat /etc/pam.d/{service}   (read-only)"]))
    elif t.o("pam.stack") == W:
        add(ClientDiagnosis("PAM_AUTH_WITHOUT_SSSD", f"PAM service {service} checks accounts with SSSD but does not "
                            "authenticate with it", "PAM", "MEDIUM", t.s("pam.stack") + ".",
                            f"Password logins of IPA users through {service} fail; key-based logins may work.",
                            ["pam.stack"], severity="WARN"))
    if t.o("pam.acct") == F:
        res = t.f("pam.acct", "result")
        ap = (t.f("sssd", "access_provider") or "ipa").lower()
        hbac = inputs.get("hbac_state")
        if res == "permission_denied":
            if hbac == "PASS":
                add(ClientDiagnosis("RUNTIME_DENIED_HBAC_ALLOWS", f"This host refuses {user} although FreeIPA HBAC "
                                    "allows it", "PAM", "MEDIUM",
                                    f"FreeIPA's own hbactest authorizes {user} through {service} for this host, but "
                                    f"SSSD's account check here answers 'Permission denied' (access_provider = {ap}). "
                                    "The refusal comes from this host: another access_provider or simple_allow list, "
                                    "SSSD's cached HBAC rules not yet refreshed, a different host name "
                                    "(ipa_hostname), or another PAM module in the account phase.",
                                    "The user cannot log in here although policy allows it.", ["pam.acct", "sssd"],
                                    kind=CONTRADICTING, blocks_runtime=True,
                                    next_steps=["grep -E 'access_provider|ipa_hostname|simple_' /etc/sssd/sssd.conf  "
                                                " (read-only)", f"cat /etc/pam.d/{service}   (read-only)"]))
            else:
                add(ClientDiagnosis("RUNTIME_ACCOUNT_DENIED", f"SSSD's account check refuses {user} through {service}",
                                    "PAM", "HIGH",
                                    f"The PAM account phase answered 'Permission denied' (access_provider = {ap}). With "
                                    "access_provider = ipa this is FreeIPA HBAC (or the account state) as SSSD "
                                    "evaluates it on this host.",
                                    f"{user} cannot log in here through {service}.", ["pam.acct", "sssd"],
                                    blocks_runtime=True,
                                    next_steps=[f"ipa-diagnose access {_q(user)} {_q(host)} {_q(service)}   (why, "
                                                "from FreeIPA's own evaluation)"]))
        elif res == "authinfo_unavail":
            add(ClientDiagnosis("RUNTIME_ACCOUNT_UNAVAILABLE", "SSSD could not decide the account check", "PAM",
                                "MEDIUM", t.s("pam.acct") + ".", f"{user} cannot log in here now.", ["pam.acct"],
                                blocks_runtime=True, related_to=find("SSSD_OFFLINE").code if find("SSSD_OFFLINE")
                                else None, kind=None if find("SSSD_OFFLINE") else UNDIAGNOSED))
        else:
            add(ClientDiagnosis("RUNTIME_ACCOUNT_FAILED", "The PAM account check failed", "PAM", "LOW",
                                t.s("pam.acct") + ".", f"{user} may not be able to log in here.", ["pam.acct"],
                                kind=UNDIAGNOSED, blocks_runtime=True))
    return _roles(out)


def _roles(out: List[ClientDiagnosis]) -> List[ClientDiagnosis]:
    codes = {d.code for d in out}
    for d in out:
        if d.related_to and d.related_to not in codes:
            d.related_to = None
    primary_set = False
    for d in sorted(out, key=lambda x: (x.severity != "FAIL", LAYER.get(x.capability, 99))):
        if d.kind == CONTRADICTING:
            d.role = CONTRADICTING
        elif d.severity == "WARN":
            d.role = WARNING
        elif d.related_to:
            d.role = RELATED
        elif d.kind == UNDIAGNOSED:
            d.role = UNDIAGNOSED
        elif not primary_set:
            d.role, primary_set = PRIMARY, True
        else:
            d.role = INDEPENDENT
    order = {PRIMARY: 0, INDEPENDENT: 1, RELATED: 2, CONTRADICTING: 3, UNDIAGNOSED: 4, WARNING: 5}
    return sorted(out, key=lambda x: (order[x.role], LAYER.get(x.capability, 99)))


RULED_OUT = {
    "enroll": "enrollment configuration is present",
    "sssd": "SSSD is configured for the IPA domain",
    "dns.server": "the IPA server name resolves",
    "dns.srv_ldap": "LDAP SRV records exist",
    "dns.srv_kerberos": "Kerberos SRV records exist",
    "net.https": "the server answers on HTTPS",
    "net.ldap": "the server answers on LDAP",
    "net.kdc": "the server answers on Kerberos (TCP)",
    "tls": "the server's certificate is trusted",
    "time.server": "the clocks agree",
    "keytab": "the host keytab holds this host's key",
    "krb": "the KDC accepts this host's key",
    "sssd.service": "SSSD is running",
    "sssd.config": "the SSSD configuration is valid",
    "sssd.domain": "SSSD is online",
    "id.user": "SSSD resolves the user",
    "id.group": "SSSD resolves identities",
    "ipa.user": "IPA has the user",
    "nss.system": "the system NSS stack resolves the user",
    "pam.stack": "the PAM service uses SSSD",
    "pam.acct": "SSSD's account check accepts the user",
}


def ruled_out(trace: Trace) -> List[str]:
    return [RULED_OUT[r.step_id] for r in trace.records if r.outcome == P and r.step_id in RULED_OUT]
