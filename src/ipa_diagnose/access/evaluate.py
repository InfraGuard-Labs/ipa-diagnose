"""Answer one access question with a FIXED, bounded sequence of read-only API calls (this is not a planner):

  1. user_show USER            identity, account state, direct/indirect groups
  2. host_show HOST            canonical FQDN, direct/indirect hostgroups, whether IPA holds a key for it
  3. hbacsvc_show SERVICE      whether the HBAC service is defined, its service groups
  4. hbactest                  FreeIPA's own HBAC evaluation (the DECISION), with the canonical names from 1-3
  5. hbacrule_show RULE        matched rules (ALLOW) or the rules naming these objects (DENY), at most MAX_RULES
  6. group_show / hostgroup_show  from the rule's group DOWN to the user's/host's own groups, only to explain a
                                  nested membership chain

States (docs/access-diagnosis.md has the full contract):
- AUTHENTICATION: FAIL (FreeIPA says the account cannot authenticate: no such user, disabled, principal expired),
  NOT_VERIFIED (nothing blocks it in IPA, but no credential was tested), UNKNOWN (account state not readable).
  Never PASS: this command does not authenticate anyone.
- AUTHORIZATION: PASS / FAIL only from FreeIPA's evaluator for an existing user and host with a complete rule set and
  no rule errors; otherwise UNKNOWN. The relationship index never changes it.
- RUNTIME ACCESS: always NOT_VERIFIED in this version (no login, client SSSD, PAM, network or keytab check).
"""

from __future__ import annotations

import dataclasses
import datetime
import enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ipa_diagnose.access.api import Api, ApiResponse
from ipa_diagnose.access.relations import (
    EdgeKind, HbacRule, Membership, NodeKind, RelationshipIndex, SideExplanation, explain_side,
)
from ipa_diagnose.access.targets import Targets

MAX_RULES = 10
MAX_GROUP_FETCHES = 40


class State(enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_VERIFIED = "NOT_VERIFIED"


@dataclasses.dataclass
class Verdict:
    state: State
    summary: str
    reasons: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Check:
    name: str
    call: str
    outcome: str  # ok | problem | not_found | error | skipped
    summary: str
    seconds: float = 0.0


@dataclasses.dataclass
class AccessFinding:
    code: str
    title: str
    detail: str
    blocking: bool
    """True when it is (part of) why access is refused or undetermined; False for context only."""


@dataclasses.dataclass
class RuleExplanation:
    rule: str
    enabled: Optional[bool]
    matched_by_freeipa: bool
    sides: Dict[str, List[SideExplanation]]
    status: str
    """COMPLETE (every side explained), INCOMPLETE (a side could not be explained from the data read),
    CONTRADICTING (the data read says the rule should not match, although FreeIPA says it does - or vice versa)."""
    source: str


@dataclasses.dataclass
class Evaluation:
    """FreeIPA's own answer, as received."""

    ran: bool
    granted: Optional[bool] = None
    matched: List[str] = dataclasses.field(default_factory=list)
    not_matched_count: int = 0
    error_rules: List[str] = dataclasses.field(default_factory=list)
    error_rules_own: List[str] = dataclasses.field(default_factory=list)
    """The error rules that name this user (the only error-rule names ever shown)."""
    truncated: bool = False
    error: Optional[str] = None
    request: Dict[str, str] = dataclasses.field(default_factory=dict)
    summary: Optional[str] = None


@dataclasses.dataclass
class AccountState:
    exists: Optional[bool] = None
    canonical: Optional[str] = None
    disabled: Optional[bool] = None
    principal_expires: Optional[str] = None
    principal_expired: Optional[bool] = None
    password_expires: Optional[str] = None
    password_expired: Optional[bool] = None
    preserved: Optional[bool] = None


@dataclasses.dataclass
class HostState:
    exists: Optional[bool] = None
    canonical: Optional[str] = None
    has_keytab: Optional[bool] = None


@dataclasses.dataclass
class ServiceState:
    exists: Optional[bool] = None
    canonical: Optional[str] = None
    groups: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class AccessResult:
    targets: Targets
    raw_query: Dict[str, str]
    mode: str
    server: Optional[str]
    principal: Optional[str]
    api_version: Optional[str]
    generated_at: str
    authentication: Verdict
    authorization: Verdict
    runtime: Verdict
    evaluation: Evaluation
    account: AccountState
    host: HostState
    service: ServiceState
    user_groups: Optional[Membership]
    host_groups: Optional[Membership]
    rules: List[RuleExplanation]
    explanation_status: str
    findings: List[AccessFinding]
    checks: List[Check]
    index: RelationshipIndex
    completeness: Dict[str, Any]
    limitations: List[str]
    client: Any = None
    """Set only by `access --runtime`: the client-mode investigation of this host (Slice 4)."""
    runtime_note: Optional[str] = None
    """Set only by `access --runtime`: why the runtime side was or was not investigated."""


# ---------------------------------------------------------------- helpers


def _first(v: Any) -> Any:
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _strs(v: Any) -> List[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str) and x]
    return []


def _bool(v: Any) -> Optional[bool]:
    v = _first(v)
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.upper() in ("TRUE", "FALSE"):
        return v.upper() == "TRUE"
    return None


def _time(v: Any) -> Optional[datetime.datetime]:
    """FreeIPA returns generalized times as {"__datetime__": "20261231000000Z"} in JSON-RPC."""

    v = _first(v)
    if isinstance(v, dict):
        v = v.get("__datetime__")
    if not isinstance(v, str):
        return None
    for fmt in ("%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.datetime.strptime(v, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def _iso(t: Optional[datetime.datetime]) -> Optional[str]:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def _describe_error(resp: ApiResponse) -> str:
    e = resp.error
    if e is None:
        return ""
    return {
        "not_found": "not found",
        "denied": f"not permitted for this identity ({e.message})",
        "auth": e.message,
        "unavailable": f"IPA API unavailable: {e.message}",
        "timeout": f"timed out: {e.message}",
        "malformed": f"unusable answer: {e.message}",
        "budget": e.message,
        "not_recorded": e.message,
    }.get(e.kind, e.message)


def _is_truncated(resp: ApiResponse) -> bool:
    for m in resp.messages:
        name = m.get("name") if isinstance(m.get("name"), str) else ""
        if "truncat" in name.lower() or m.get("code") == 13017:
            return True
    return False


# ---------------------------------------------------------------- the fixed sequence


class _Run:
    def __init__(self, api: Api, targets: Targets, now: datetime.datetime):
        self.api, self.t, self.now = api, targets, now
        self.checks: List[Check] = []
        self.findings: List[AccessFinding] = []
        self.index = RelationshipIndex()
        self.limit_notes: List[str] = []
        self.rules_unread: List[str] = []
        self.rules_cut = False  # more matched/related rules than MAX_RULES
        self.chain_reads = 0  # group/hostgroup reads for nested chains, both sides together
        # the queried objects and their own groups (lower-case): the only names a rule may contribute to the output
        self.relevant: Dict[str, Set[str]] = {"user": set(), "host": set(), "service": {targets.service.lower()}}

    def call(self, name: str, method: str, args: List[str], options: Optional[Dict[str, Any]] = None) -> ApiResponse:
        resp = self.api.call(method, args, options)
        if resp.error is not None and resp.error.kind == "auth" and not self.api.context.unavailable:
            # the server refused the OPERATOR's ticket (expired, clock skew, other realm): nothing more can be read,
            # and it says nothing about the user being asked about
            self.api.context.unavailable = resp.error.message
        self._last = (name, f"{method} {' '.join(args)}".strip(), resp)
        return resp

    def check(self, outcome: str, summary: str) -> None:
        name, call, resp = self._last
        self.checks.append(Check(name, call, outcome, summary, round(resp.seconds, 3)))

    def find(self, code: str, title: str, detail: str, blocking: bool) -> None:
        if code == "OBJECT_UNREADABLE" and self.api.context.unavailable:
            return  # the object is not the problem: FreeIPA could not be queried at all (EVALUATOR_UNAVAILABLE)
        self.findings.append(AccessFinding(code, title, detail, blocking))

    # 1 ---------------------------------------------------------------- user
    def user(self) -> Tuple[AccountState, Optional[Membership]]:
        st = AccountState()
        r = self.call("user", "user_show", [self.t.user], {"all": True})
        if not r.ok:
            if r.error.kind == "not_found":
                st.exists = False
                self.check("not_found", f"no IPA user named {self.t.user}")
                self.find("USER_NOT_FOUND", f"No IPA user named {self.t.user}",
                          "FreeIPA has no user by this name (a staged user cannot log in either). Check the "
                          "spelling; the account may also be deliberately absent. A trusted-domain (AD) user must be "
                          "written as name@domain.", True)
            else:
                self.check("error", _describe_error(r))
                self.find("OBJECT_UNREADABLE", f"The user {self.t.user} could not be read",
                          _describe_error(r), True)
            return st, None
        res = r.entry
        uid = _first(res.get("uid"))
        if not isinstance(uid, str) or not uid:
            self.check("error", "the answer has no user name")
            self.find("OBJECT_UNREADABLE", f"The user {self.t.user} could not be read", "unusable answer", True)
            return st, None
        st.exists, st.canonical = True, uid
        if _bool(res.get("preserved")) is True:
            st.preserved = True
            self.check("problem", f"user {uid} is a preserved (deleted) user")
            self.find("USER_PRESERVED", f"{uid} is a preserved (deleted) user",
                      "FreeIPA keeps the deleted entry for possible restore, but a preserved user cannot "
                      "authenticate or log in. Rules may still name it; they do not apply to it.", True)
            return st, None
        st.disabled = _bool(res.get("nsaccountlock"))
        pe = _time(res.get("krbprincipalexpiration"))
        st.principal_expires, st.principal_expired = _iso(pe), (pe <= self.now) if pe else None
        pw = _time(res.get("krbpasswordexpiration"))
        st.password_expires, st.password_expired = _iso(pw), (pw <= self.now) if pw else None
        node = self.index.node(NodeKind.USER, uid)
        direct, indirect = set(_strs(res.get("memberof_group"))), set(_strs(res.get("memberofindirect_group")))
        self.index.add_memberships(node, NodeKind.GROUP, direct, indirect, f"user_show {uid}")
        self.relevant["user"] = {uid.lower()} | {g.lower() for g in direct | indirect}
        self._user_rules = set(_strs(res.get("memberof_hbacrule"))) | set(_strs(res.get("memberofindirect_hbacrule")))
        problems = []
        if st.disabled:
            problems.append("disabled")
            self.find("USER_DISABLED", f"The IPA account {uid} is disabled",
                      "FreeIPA marks the account disabled (nsAccountLock): the KDC refuses it, and SSSD's IPA access "
                      "check refuses disabled accounts too (documented SSSD behaviour, so this also applies to SSH-key "
                      "logins), whatever HBAC allows. A host answering from SSSD's offline cache may lag behind.", True)
        if st.principal_expired:
            problems.append("principal expired")
            self.find("USER_PRINCIPAL_EXPIRED", f"The Kerberos principal of {uid} expired at {st.principal_expires}",
                      "The KDC refuses an expired principal: password and Kerberos (GSSAPI) logins fail. Whether a "
                      "login that does not use the KDC (for example an SSH key) is refused depends on the host's "
                      "SSSD, which this command does not check.", True)
        if st.password_expired:
            self.find("USER_PASSWORD_EXPIRED", f"The password of {uid} expired at {st.password_expires}",
                      "A password login must change the password first; logins that do not use the password "
                      "(for example SSH keys) are not affected by this.", False)
        if st.disabled is None:
            self.check("problem", f"user {uid} exists; the disabled/enabled state is not readable by this identity")
        else:
            expiry = ("principal not expired" if st.principal_expired is False
                      else "no principal expiration set or readable")
            self.check("problem" if problems else "ok",
                       f"user {uid} exists, " + (", ".join(problems) if problems else f"enabled, {expiry}")
                       + f"; {len(direct)} direct and {len(indirect)} nested groups")
        return st, Membership(node, direct, indirect) if node else None

    # 2 ---------------------------------------------------------------- host
    def host(self) -> Tuple[HostState, Optional[Membership]]:
        st = HostState()
        r = self.call("host", "host_show", [self.t.host])
        if not r.ok:
            if r.error.kind == "not_found":
                st.exists = False
                self.check("not_found", f"no IPA host named {self.t.host}")
                self.find("HOST_NOT_FOUND", f"No IPA host named {self.t.host}",
                          "No host is enrolled in FreeIPA under this exact name, so FreeIPA has no HBAC decision about "
                          "it. Check the name: SSSD on an enrolled host uses its own full host name, which may differ "
                          "from an alias or CNAME.", True)
            else:
                self.check("error", _describe_error(r))
                self.find("OBJECT_UNREADABLE", f"The host {self.t.host} could not be read", _describe_error(r), True)
            return st, None
        res = r.entry
        fqdn = _first(res.get("fqdn"))
        if not isinstance(fqdn, str) or not fqdn:
            self.check("error", "the answer has no host name")
            self.find("OBJECT_UNREADABLE", f"The host {self.t.host} could not be read", "unusable answer", True)
            return st, None
        st.exists, st.canonical, st.has_keytab = True, fqdn, _bool(res.get("has_keytab"))
        node = self.index.node(NodeKind.HOST, fqdn)
        direct, indirect = set(_strs(res.get("memberof_hostgroup"))), set(_strs(res.get("memberofindirect_hostgroup")))
        self.index.add_memberships(node, NodeKind.HOSTGROUP, direct, indirect, f"host_show {fqdn}")
        self.relevant["host"] = {fqdn.lower()} | {g.lower() for g in direct | indirect}
        if st.has_keytab is False:
            self.find("HOST_NO_KEYTAB", f"FreeIPA holds no Kerberos key for {fqdn}",
                      "The host entry exists but has no keytab, which usually means it is not (or no longer) "
                      "enrolled: SSSD on it cannot use FreeIPA, whatever the policy says. Runtime access is not "
                      "checked by this command.", False)
        self.check("ok" if st.has_keytab is not False else "problem",
                   f"host {fqdn} exists; {len(direct)} direct and {len(indirect)} nested hostgroups"
                   + ("" if st.has_keytab is not False else "; no keytab in IPA"))
        return st, Membership(node, direct, indirect) if node else None

    # 3 ---------------------------------------------------------------- service
    def service(self) -> ServiceState:
        st = ServiceState()
        r = self.call("service", "hbacsvc_show", [self.t.service])
        if not r.ok:
            if r.error.kind == "not_found":
                st.exists = False
                self.check("not_found", f"no HBAC service named {self.t.service}")
                self.find("SERVICE_NOT_DEFINED", f"No HBAC service named {self.t.service} is defined in FreeIPA",
                          "A PAM service without an HBAC service entry can only be allowed by rules that apply to "
                          "all services; FreeIPA's evaluation below already takes this into account. Check the "
                          "spelling if this is unexpected.", False)
            else:
                self.check("error", _describe_error(r))
            return st
        res = r.entry
        cn = _first(res.get("cn"))
        if not isinstance(cn, str) or not cn:
            self.check("error", "the answer has no service name")
            return st
        st.exists, st.canonical, st.groups = True, cn, sorted(set(_strs(res.get("memberof_hbacsvcgroup"))))
        node = self.index.node(NodeKind.HBAC_SERVICE, cn)
        self.index.add_memberships(node, NodeKind.HBAC_SERVICE_GROUP, st.groups, [], f"hbacsvc_show {cn}")
        self.relevant["service"] = {cn.lower()} | {g.lower() for g in st.groups}
        self.check("ok", f"HBAC service {cn} is defined; in {len(st.groups)} service group(s)")
        return st

    # 4 ---------------------------------------------------------------- FreeIPA's decision
    def hbactest(self, user: str, host: str, service: str) -> Evaluation:
        ev = Evaluation(ran=True, request={"user": user, "targethost": host, "service": service})
        r = self.call("HBAC evaluation", "hbactest", [],
                      {"user": user, "targethost": host, "service": service, "nodetail": False})
        if not r.ok:
            ev.error = _describe_error(r)
            self.check("error", ev.error)
            return ev
        res = r.result if isinstance(r.result, dict) else None
        granted = res.get("value") if res else None
        if not isinstance(granted, bool):
            ev.error = "the evaluation answer has no boolean verdict"
            self.check("error", ev.error)
            return ev
        ev.matched = _strs(res.get("matched"))
        ev.not_matched_count = len(_strs(res.get("notmatched")))
        ev.error_rules = _strs(res.get("error"))
        own = {x.lower() for x in self._user_rules}
        ev.error_rules_own = [x for x in ev.error_rules if x.lower() in own]
        ev.truncated = _is_truncated(r)
        summary = _first(res.get("summary"))
        ev.summary = summary if isinstance(summary, str) else None
        if granted and not ev.matched:
            ev.error = "the evaluation says granted but names no matched rule"
            self.check("error", ev.error)
            return ev
        if not granted and ev.matched:
            ev.error = "the evaluation says denied but names matched rules"
            self.check("error", ev.error)
            return ev
        ev.granted = granted
        total = len(ev.matched) + ev.not_matched_count + len(ev.error_rules)
        verdict = "granted" if granted else "denied"
        if ev.error_rules or ev.truncated:
            why = (f"{len(ev.error_rules)} rule(s) could not be evaluated" if ev.error_rules
                   else "the rule list was truncated by a size limit")
            self.check("problem", f"hbactest returned {verdict}, but {why}, so the result is not trusted")
            return ev
        self.check("ok" if granted else "problem",
                   f"FreeIPA evaluated {total} enabled HBAC rule(s): access {verdict}"
                   + (f"; matched: {', '.join(ev.matched[:MAX_RULES])}" if ev.matched else ""))
        return ev

    # 5 / 6 ---------------------------------------------------------------- explanation (never the decision)
    def rule(self, name: str) -> Optional[HbacRule]:
        r = self.call(f"rule {name}", "hbacrule_show", [name])
        if not r.ok:
            self.check("error", _describe_error(r))
            self.rules_unread.append(name)
            return None
        rule = HbacRule.from_api(r.entry, f"hbacrule_show {name}")
        if rule is None:
            self.check("error", "the answer is not an HBAC rule")
            self.rules_unread.append(name)
            return None
        rn = self.index.node(NodeKind.HBAC_RULE, rule.name)
        for side, rs, obj_kind, grp_kind in (("user", rule.user, NodeKind.USER, NodeKind.GROUP),
                                             ("host", rule.host, NodeKind.HOST, NodeKind.HOSTGROUP),
                                             ("service", rule.service, NodeKind.HBAC_SERVICE,
                                              NodeKind.HBAC_SERVICE_GROUP)):
            # Privacy: a rule's other members describe other people's access. Only the objects asked about and
            # their own groups become edges; nothing else a rule names is kept or shown.
            relevant = self.relevant[side]
            for n in rs.names:
                if n.lower() in relevant:
                    self.index.add_edge(rn, self.index.node(obj_kind, n), EdgeKind.RULE_APPLIES_TO, rule.source,
                                        side)
            for g in rs.groups:
                if g.lower() in relevant:
                    self.index.add_edge(rn, self.index.node(grp_kind, g), EdgeKind.RULE_APPLIES_TO, rule.source,
                                        side)
        state = {True: "enabled", False: "disabled", None: "enabled state unknown"}[rule.enabled]
        self.check("ok", f"rule {rule.name}: {state}")
        return rule

    def expand_chain(self, member: Optional[Membership], wanted: Set[str], method: str, attr: str,
                     kind: NodeKind) -> bool:
        """Find the chain from the member to each wanted (nested) group by walking DOWN from that group through its
        member groups, keeping only groups the member itself belongs to. Only groups on a real path are read, however
        many other groups the member is in (live lab: a user in 150 flat groups plus a 12-deep chain). ``attr`` is
        the child-group attribute (``member_group`` / ``member_hostgroup``). Returns False when bounds or errors left
        a chain unknown."""

        if member is None or not wanted:
            return True

        def known(w: str) -> bool:
            target = self.index.node(kind, w)
            if target is None:  # the index is at its size bound: the chain stays unknown
                return False
            return self.index.membership_path(member.node, target) is not None

        allowed = member.all_groups()
        # children already read (by any earlier search on this side), so a group shared by two chains is read once
        # and its children are still followed for the second chain (diamonds)
        read_children: Dict[str, List[str]] = {}
        complete = True
        for w in sorted(wanted, key=str.lower):
            frontier, visited = [w], set()
            while frontier and not known(w):
                nxt: List[str] = []
                for g in frontier:
                    if g.lower() in visited:
                        continue
                    visited.add(g.lower())
                    if g.lower() not in read_children:
                        if self.chain_reads >= MAX_GROUP_FETCHES:
                            self.limit_notes.append(f"nested group and hostgroup chains share a budget of "
                                                    f"{MAX_GROUP_FETCHES} reads, which was used up before the "
                                                    f"{kind.value.lower()} chain was complete")
                            return False
                        self.chain_reads += 1
                        r = self.call(f"{kind.value.lower()} {g}", method, [g])
                        if not r.ok:
                            self.check("error", _describe_error(r))
                            read_children[g.lower()] = []
                            complete = False
                            continue
                        children = [c for c in _strs(r.entry.get(attr)) if c.lower() in allowed]
                        read_children[g.lower()] = children
                        parent = self.index.node(kind, g)
                        for c in children:
                            self.index.add_edge(self.index.node(kind, c), parent, EdgeKind.MEMBER_OF,
                                                f"{method} {g}")
                        self.check("ok", f"{kind.value.lower()} {g} contains "
                                   + (", ".join(sorted(children, key=str.lower)[:5]) if children
                                      else "none of the other groups")
                                   + " of this object's groups (read to explain the nesting)")
                    nxt.extend(c for c in read_children[g.lower()] if c.lower() not in visited)
                    if known(w):  # stop reading as soon as the chain is known
                        break
                frontier = sorted(set(nxt), key=str.lower)
        return complete and all(known(w) for w in wanted)




def _explain(run: _Run, rule: HbacRule, user_m: Optional[Membership], host_m: Optional[Membership],
             user: str, host: str, service: str, service_st: ServiceState, matched: bool) -> RuleExplanation:
    svc_member = None
    if service_st.exists and service_st.canonical:
        svc_node = run.index.node(NodeKind.HBAC_SERVICE, service_st.canonical)
        if svc_node is not None:
            svc_member = Membership(svc_node, set(service_st.groups), set())
    sides = {
        "user": explain_side(run.index, "user", rule.user, user_m, user, NodeKind.GROUP),
        "host": explain_side(run.index, "host", rule.host, host_m, host, NodeKind.HOSTGROUP),
        "service": explain_side(run.index, "service", rule.service, svc_member, service,
                                NodeKind.HBAC_SERVICE_GROUP, groups_known=service_st.exists is not None),
    }
    covered = all(any(s.how not in ("none", "unknown") for s in v) for v in sides.values())
    chains_known = all(s.chain_complete for v in sides.values() for s in v)
    data_complete = user_m is not None and host_m is not None and (service_st.exists is not None)
    if matched:
        if covered and rule.enabled is True:
            status = "COMPLETE" if chains_known else "INCOMPLETE"
        elif not data_complete or rule.enabled is None:
            status = "INCOMPLETE"
        else:
            status = "CONTRADICTING"  # FreeIPA matched it, but the data read says it should not
    else:
        # A rule FreeIPA did not match: our model must not find it enabled and covering all three sides.
        if covered and rule.enabled is True:
            status = "CONTRADICTING"
        else:
            status = "COMPLETE" if data_complete else "INCOMPLETE"
    return RuleExplanation(rule.name, rule.enabled, matched, sides, status, rule.source)


def diagnose(api: Api, targets: Targets, raw_query: Dict[str, str],
             now: Optional[datetime.datetime] = None) -> AccessResult:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    run = _Run(api, targets, now)
    run._user_rules = set()
    ctx = api.context
    evaluation = Evaluation(ran=False)
    account, host_st, svc_st = AccountState(), HostState(), ServiceState()
    user_m = host_m = None
    explanations: List[RuleExplanation] = []
    decided = False

    if ctx.unavailable:
        run.find("EVALUATOR_UNAVAILABLE", "ipa-diagnose could not query FreeIPA", ctx.unavailable, True)
    elif targets.user_domain:
        run.find("TRUSTED_IDENTITY_UNSUPPORTED",
                 f"{targets.display_user} is a trusted-domain identity",
                 "Access diagnosis of trusted-domain (for example Active Directory) users is not supported in this "
                 "version: their groups come from the trusted domain and ID views, which it does not evaluate. "
                 "Nothing about its access is concluded here.", True)
        host_st, host_m = run.host()
        svc_st = run.service()
    else:
        account, user_m = run.user()
        host_st, host_m = run.host()
        svc_st = run.service()
        if account.exists and not account.preserved and host_st.exists:
            evaluation = run.hbactest(account.canonical, host_st.canonical, svc_st.canonical or targets.service)
            decided = evaluation.error is None and evaluation.granted is not None and not ctx.unavailable
        elif account.preserved:
            evaluation.error = "not evaluated: the user is a preserved (deleted) user"
        elif account.exists is False or host_st.exists is False:
            evaluation.error = "not evaluated: the user or the host does not exist in FreeIPA"
        else:
            evaluation.error = "not evaluated: the user or the host could not be read"
        if evaluation.ran and evaluation.error is None:
            user_c, host_c = account.canonical, host_st.canonical
            svc_c = svc_st.canonical or targets.service
            if evaluation.granted:
                names = evaluation.matched[:MAX_RULES]
            else:
                # Privacy: only rules that name THIS user (directly or through the user's groups). Rules that only
                # name the host or the service describe other people's access and are not needed to answer.
                related = sorted(run._user_rules, key=str.lower)
                names = related[:MAX_RULES]
                if len(related) > MAX_RULES:
                    run.rules_cut = True
                    run.limit_notes.append(f"only {MAX_RULES} of the {len(related)} rules naming this user are "
                                           "explained")
            rules = [r for r in (run.rule(n) for n in names) if r is not None]
            want_u = {g for r in rules for g in r.user.groups if not r.user.category_all
                      and user_m is not None and g.lower() in {x.lower() for x in user_m.indirect}}
            want_h = {g for r in rules for g in r.host.groups if not r.host.category_all
                      and host_m is not None and g.lower() in {x.lower() for x in host_m.indirect}}
            run.expand_chain(user_m, want_u, "group_show", "member_group", NodeKind.GROUP)
            run.expand_chain(host_m, want_h, "hostgroup_show", "member_hostgroup", NodeKind.HOSTGROUP)
            for r in rules:
                explanations.append(_explain(run, r, user_m, host_m, user_c, host_c, svc_c, svc_st,
                                             matched=r.name.lower() in {m.lower() for m in evaluation.matched}))
            if len(evaluation.matched) > MAX_RULES:
                run.rules_cut = True
                run.limit_notes.append(f"only the first {MAX_RULES} of {len(evaluation.matched)} matched rules "
                                       "are explained")
            if run.rules_unread:
                run.limit_notes.append("rule(s) that could not be read, so their part of the explanation is missing: "
                                       + ", ".join(run.rules_unread))

    if decided and ctx.unavailable:
        # the ticket was refused only AFTER FreeIPA decided: the decision stands, only the explanation is short
        ctx.unavailable = None
        run.rules_cut = True
        run.limit_notes.append("the IPA server refused the Kerberos ticket after its decision, so the explanation "
                               "is incomplete")
    if ctx.unavailable and not any(x.code == "EVALUATOR_UNAVAILABLE" for x in run.findings):
        # the ticket was refused during the run (HTTP 401): the same answer as having no ticket at all
        run.find("EVALUATOR_UNAVAILABLE", "ipa-diagnose could not query FreeIPA", ctx.unavailable, True)
    authn = _authentication(ctx, targets, account)
    authz, expl_status = _authorization(run, ctx, targets, account, host_st, evaluation, explanations)
    runtime = _runtime(authn, authz, host_st)
    completeness = {
        "api_calls": api.calls_made,
        "api_call_budget": api.max_calls,
        "relationship_index": {"nodes": len(run.index.nodes()), "edges": len(run.index.edges()),
                               "truncated": run.index.truncated},
        "rules_explained": len(explanations),
        "rules_unread": list(run.rules_unread),
        "notes": run.limit_notes,
    }
    if run.index.truncated:
        run.limit_notes.append("the relationship index reached its size bound")
    return AccessResult(
        targets=targets, raw_query=raw_query, mode=ctx.mode, server=ctx.server, principal=ctx.principal,
        api_version=ctx.api_version, generated_at=_iso(now), authentication=authn, authorization=authz,
        runtime=runtime, evaluation=evaluation, account=account, host=host_st, service=svc_st, user_groups=user_m,
        host_groups=host_m, rules=explanations, explanation_status=expl_status, findings=run.findings,
        checks=run.checks, index=run.index, completeness=completeness, limitations=_limitations(ctx))


def _authentication(ctx, targets: Targets, account: AccountState) -> Verdict:
    if ctx.unavailable and account.exists is None:  # an account already read (or found missing) keeps its state
        return Verdict(State.UNKNOWN, f"{targets.user}'s account was not read: ipa-diagnose could not query FreeIPA",
                       [ctx.unavailable])
    if targets.user_domain:
        return Verdict(State.UNKNOWN, "trusted-domain identity: not evaluated by this version")
    if account.exists is False:
        return Verdict(State.FAIL, f"no IPA user named {targets.user}")
    if account.preserved:
        return Verdict(State.FAIL, f"{account.canonical} is a preserved (deleted) user")
    if account.exists is None:
        return Verdict(State.UNKNOWN, "the user could not be read")
    reasons = []
    if account.disabled:
        reasons.append("the account is disabled")
    if account.principal_expired:
        reasons.append(f"the Kerberos principal expired at {account.principal_expires}")
    if reasons:
        return Verdict(State.FAIL, "; ".join(reasons), reasons)
    if account.disabled is None:
        return Verdict(State.UNKNOWN, "the account's enabled/disabled state is not readable by this identity")
    note = []
    if account.password_expired:
        note.append(f"the password expired at {account.password_expires}: a password login must change it first")
    return Verdict(State.NOT_VERIFIED, "the IPA account exists and is enabled; no credential was tested", note)


def _authorization(run: _Run, ctx, targets: Targets, account: AccountState, host_st: HostState, ev: Evaluation,
                   explanations: List[RuleExplanation]) -> Tuple[Verdict, str]:
    if ctx.unavailable:
        return Verdict(State.UNKNOWN, "not evaluated: ipa-diagnose could not query FreeIPA", [ctx.unavailable]), "NONE"
    if targets.user_domain:
        return Verdict(State.UNKNOWN, "trusted-domain identity: not evaluated by this version"), "NONE"
    if account.preserved:
        return Verdict(State.UNKNOWN, "not evaluated: a preserved (deleted) user has no policy decision"), "NONE"
    if account.exists is False or host_st.exists is False:
        who = "user" if account.exists is False else "host"
        return Verdict(State.UNKNOWN, f"not evaluated: the {who} does not exist in FreeIPA, so there is no policy "
                       f"decision about it"), "NONE"
    if not ev.ran:  # the user or host could not be read (OBJECT_UNREADABLE says which)
        return Verdict(State.UNKNOWN, ev.error or "not evaluated"), "NONE"
    if ev.error:
        run.find("EVALUATOR_FAILED", "FreeIPA's HBAC evaluation gave no usable answer",
                 ev.error or "the evaluation did not run", True)
        return Verdict(State.UNKNOWN, "FreeIPA's HBAC evaluation gave no usable answer", [ev.error or ""]), "NONE"
    if ev.truncated:
        run.find("EVALUATOR_TRUNCATED", "FreeIPA evaluated a truncated rule list",
                 "The HBAC rule search hit a size limit, so some rules were not evaluated. SSSD evaluates all of "
                 "them; this answer cannot be trusted.", True)
        return Verdict(State.UNKNOWN, "FreeIPA evaluated only part of the HBAC rules (size limit)"), "NONE"
    if ev.error_rules:
        run.find("EVALUATOR_RULE_ERRORS", "Some HBAC rules could not be evaluated",
                 f"FreeIPA reported {len(ev.error_rules)} rule(s) it could not evaluate. SSSD stops at such a rule "
                 "and refuses access, depending on rule order, so the outcome on the host is not certain.", True)
        return Verdict(State.UNKNOWN, "FreeIPA reported HBAC rules it could not evaluate"), "NONE"

    contradicting = [e for e in explanations if e.status == "CONTRADICTING"]
    incomplete = [e for e in explanations if e.status == "INCOMPLETE"]
    if contradicting:
        status = "CONTRADICTING"
        run.find("EXPLANATION_CONTRADICTS", "The explanation disagrees with FreeIPA's decision",
                 "The group and rule data read by ipa-diagnose does not reproduce FreeIPA's decision for: "
                 + ", ".join(e.rule for e in contradicting) + ". FreeIPA's decision stands; the data may have changed "
                 "between calls, or this is a gap in ipa-diagnose's model (please report it).", False)
    elif incomplete or (ev.granted and not explanations) or run.rules_unread or run.rules_cut:
        status = "INCOMPLETE"
        run.find("RELATIONSHIP_INCOMPLETE", "The explanation is incomplete",
                 "Some memberships or rules could not be read, or more rules applied than are explained, so part of "
                 "the 'why' is missing. FreeIPA's decision is not affected.", False)
    else:
        status = "COMPLETE"
    rules = ", ".join(ev.matched[:MAX_RULES])
    if ev.granted:
        return Verdict(State.PASS, f"FreeIPA HBAC policy allows this request (rule{'s' if len(ev.matched) > 1 else ''}: "
                       f"{rules})"), status
    run.find("HBAC_DENIED", "FreeIPA HBAC policy does not authorize this request",
             "FreeIPA's HBAC evaluation found no enabled rule that matches this user, host and service together. "
             "This is the policy as configured, not by itself a fault.", True)
    return Verdict(State.FAIL, "FreeIPA HBAC policy does not authorize this request"), status


def _runtime(authn: Verdict, authz: Verdict, host_st: HostState) -> Verdict:
    reasons = ["no login was attempted; the host's SSSD, PAM configuration, network path and keytab were not checked"]
    if authn.state == State.FAIL or authz.state == State.FAIL:
        summary = "not tested; a login is expected to be refused where the host enforces FreeIPA through SSSD"
    elif host_st.has_keytab is False:
        summary = "not tested; the host has no keytab in FreeIPA, so it may not be enrolled"
    else:
        summary = "not tested: FreeIPA policy is only one part of a real login"
    return Verdict(State.NOT_VERIFIED, summary, reasons)


def _limitations(ctx) -> List[str]:
    return [
        "Runtime access is not tested: no login is attempted, and the host's SSSD (including its offline cache), PAM "
        "stack, access_provider setting, network path and keytab are not checked.",
        "No credential is tested; account lockout after failed logins (per-server counters) is not checked.",
        "Only HBAC is evaluated: sudo rules, SELinux user maps and local /etc/security/access.conf are not.",
        f"The answer is FreeIPA's view for the identity that asked ({ctx.principal or 'unknown'}); an identity with "
        "less read access may see less.",
        "Trusted-domain (for example Active Directory) users and ID views are not evaluated by this version.",
    ]
