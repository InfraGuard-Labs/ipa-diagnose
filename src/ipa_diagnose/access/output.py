"""JSON and console output for `ipa-diagnose access`.

Every string that came from the directory or the command line passes through ``sanitize_text`` here, at the output
boundary (terminal escapes, control and bidi/format characters removed, length bounded), in JSON as on the console.
Printed commands are read-only and built only from validated targets, shell-quoted.
"""

from __future__ import annotations

import shlex
from typing import Any, Dict, List

from rich.console import Console

from ipa_diagnose.access.evaluate import AccessResult, RuleExplanation, State
from ipa_diagnose.access.relations import SideExplanation
from ipa_diagnose.textsafe import sanitize_text

ACCESS_SCHEMA_VERSION = "1.0"


def _c(v: Any, limit: int = 1200) -> Any:
    if isinstance(v, str):
        return sanitize_text(v, limit)
    if isinstance(v, list):
        return [_c(x, limit) for x in v]
    if isinstance(v, dict):
        return {k: _c(x, limit) for k, x in v.items()}
    return v


# ---------------------------------------------------------------- the answer in words


def _codes(r: AccessResult) -> set:
    return {f.code for f in r.findings}


def headline(r: AccessResult) -> str:
    t = r.targets
    who = t.display_user
    q = f"{who} to access {t.host} through {t.service}"
    a, z = r.authentication.state, r.authorization.state
    codes = _codes(r)
    if z == State.PASS and a == State.FAIL:
        return f"FreeIPA HBAC policy authorizes {q}, but the account cannot authenticate."
    if z == State.PASS:
        return f"FreeIPA HBAC policy authorizes {q}."
    if z == State.FAIL:
        return f"FreeIPA HBAC policy does not authorize {q}."
    if "EVALUATOR_UNAVAILABLE" in codes:
        return "ipa-diagnose could not query FreeIPA, so nothing about this request is known yet."
    if r.account.exists is False:
        return f"{who} is not an IPA user, so FreeIPA HBAC policy has no decision about it."
    if r.account.preserved:
        return f"{who} is a preserved (deleted) IPA user, so FreeIPA HBAC policy has no decision about it."
    if r.host.exists is False:
        return f"{t.host} is not an IPA host, so FreeIPA HBAC policy has no decision about it."
    if a == State.FAIL:
        return f"{who} cannot authenticate, and whether FreeIPA HBAC policy authorizes it could not be determined."
    return f"Could not determine whether FreeIPA HBAC policy authorizes {q}."


def root_cause(r: AccessResult) -> List[str]:
    return [f.title for f in r.findings if f.blocking]


def no_blocker_text(r: AccessResult) -> str:
    return ("no blocker found in FreeIPA HBAC policy or in the account attributes read (disabled, principal expiry, "
            "preserved). Not checked: whether the password or other credential is valid, and lockout after failed "
            "logins.")


def _side_text(e: SideExplanation, obj: str) -> str:
    if e.how == "all":
        return {"user": "all users", "host": "all hosts", "service": "all services"}[e.side] + " (category all)"
    if e.how == "direct":
        return f"{obj} listed directly"
    if e.how == "group":
        return f"{obj} is a direct member of {e.via}"
    if e.how == "nested_group":
        chain = " -> ".join(e.chain)
        return f"{obj} is a nested member of {e.via} ({chain}{'' if e.chain_complete else ', chain not fully read'})"
    if e.how == "unknown":
        return "could not be determined (the groups of this object were not read)"
    return "no reason found in the data read"


def rule_sentence(r: AccessResult, e: RuleExplanation) -> str:
    objs = {"user": r.account.canonical or r.targets.user, "host": r.host.canonical or r.targets.host,
            "service": r.service.canonical or r.targets.service}
    parts = []
    for side in ("user", "host", "service"):
        texts = "; or ".join(_side_text(s, objs[side]) for s in e.sides[side])
        parts.append(f"{side}: {texts}")
    state = {True: "enabled", False: "disabled", None: "enabled state unknown"}[e.enabled]
    return f"rule {e.rule} ({state}) - " + " | ".join(parts)


def _unmatched_reason(e: RuleExplanation) -> str:
    missing = [s for s in ("user", "host", "service") if all(x.how == "none" for x in e.sides[s])]
    unknown = [s for s in ("user", "host", "service") if all(x.how in ("none", "unknown") for x in e.sides[s])
               and s not in missing]
    parts = []
    if e.enabled is False:
        parts.append("the rule is disabled")
    if missing:
        parts.append(("it also does not cover the " if parts else "it does not cover the ") + " or the ".join(missing))
    if unknown:
        parts.append("whether it covers the " + " or the ".join(unknown) + " could not be determined")
    if e.status == "CONTRADICTING":
        return ("the data read says this rule covers this user, host and service, but FreeIPA did not match it "
                "(explanation CONTRADICTING)")
    if e.enabled is False and not missing and not unknown:
        parts.append("it otherwise names this user, host and service")
    return "; ".join(parts) or "no reason found in the data read"


def why(r: AccessResult) -> List[str]:
    out: List[str] = []
    ev = r.evaluation
    if r.authorization.state == State.PASS:
        for e in r.rules:
            if e.matched_by_freeipa:
                out.append("Matched " + rule_sentence(r, e))
    elif r.authorization.state == State.FAIL:
        total = len(ev.matched) + ev.not_matched_count
        out.append(f"FreeIPA evaluated {total} enabled HBAC rule(s); none matches this user, host and service "
                   "together. Disabled rules are not evaluated (SSSD ignores them too).")
        related = [e for e in r.rules if not e.matched_by_freeipa]
        if related:
            out.append("Rules that name this user (directly or through its groups), and why each does not apply:")
            for e in related:
                out.append(f"  - {e.rule}: {_unmatched_reason(e)}")
        else:
            out.append(f"No HBAC rule names {r.account.canonical or r.targets.user} or any of its groups.")
    if r.explanation_status in ("INCOMPLETE", "CONTRADICTING"):
        out.append(f"Explanation {r.explanation_status}: FreeIPA's decision above stands either way (see ALSO NOTED).")
    for f in r.findings:
        if f.blocking and f.code != "HBAC_DENIED":
            out.append(f"{f.title}: {f.detail}")
    return out


def impact(r: AccessResult) -> str:
    t = r.targets
    who = r.account.canonical or t.user
    a, z = r.authentication.state, r.authorization.state
    codes = _codes(r)
    if "USER_NOT_FOUND" in codes or "USER_PRESERVED" in codes:
        return (f"{who} has no usable IPA account, so no IPA-based login is possible (a local account of that name on "
                "the host is not governed by FreeIPA).")
    if "USER_DISABLED" in codes:
        return (f"{who} cannot authenticate with FreeIPA, and SSSD's IPA access check refuses disabled accounts, so "
                "logins to IPA-joined hosts are expected to fail regardless of HBAC.")
    if "USER_PRINCIPAL_EXPIRED" in codes:
        return (f"Kerberos-based logins by {who} (password, GSSAPI) fail wherever the KDC is used, regardless of HBAC; "
                "other login methods are not decided by this command.")
    if z == State.FAIL:
        return (f"{who} is refused on {t.host} through {t.service} wherever SSSD enforces FreeIPA HBAC "
                "(access_provider = ipa, the default on enrolled hosts). Other users, hosts and services are not "
                "affected by this answer.")
    if z == State.PASS:
        return ("FreeIPA HBAC policy is not what stops this login. If the login still fails, the cause is elsewhere "
                "(credentials, lockout, the host's SSSD, PAM, network or keytab), which this command does not test.")
    return "Unknown: the HBAC policy decision could not be established."


def resolution(r: AccessResult) -> Dict[str, Any]:
    codes = _codes(r)
    if "EVALUATOR_UNAVAILABLE" in codes:
        reason = ("No fix: ipa-diagnose could not query FreeIPA (see WHY). Get a Kerberos ticket (kinit) or restore "
                  "access to the IPA server, then run the command again.")
    elif "TRUSTED_IDENTITY_UNSUPPORTED" in codes:
        reason = "No fix: trusted-domain users are not supported by this version; use FreeIPA's own evaluation (VERIFY)."
    elif "USER_NOT_FOUND" in codes or "USER_PRESERVED" in codes or "HOST_NOT_FOUND" in codes:
        reason = ("No fix is suggested. Check the name; the account or host may also be deliberately absent "
                  "(offboarded, deleted or not enrolled).")
    elif "USER_DISABLED" in codes or "USER_PRINCIPAL_EXPIRED" in codes:
        reason = ("No fix is suggested. Accounts are usually disabled or expired on purpose (offboarding, security "
                  "incidents, contract end). Whether this account should be usable is a decision for its owner's "
                  "process, not for a diagnostic tool.")
    elif "EVALUATOR_RULE_ERRORS" in codes:
        reason = ("No fix is suggested. FreeIPA could not evaluate rule(s) " + ", ".join(r.evaluation.error_rules[:5])
                  + "; inspect them with ipa hbacrule-show.")
    elif r.authorization.state == State.FAIL and r.explanation_status == "CONTRADICTING":
        reason = ("No policy change is suggested. The data read disagrees with FreeIPA's evaluation: run the command "
                  "again, and check the rule named in WHY with ipa hbactest --rules=RULE.")
    elif r.authorization.state == State.FAIL:
        reason = ("No fix is suggested. A deny is FreeIPA HBAC policy doing what it is configured to do; whether this "
                  "user should reach this host through this service is a security and business decision for the "
                  "policy owner. ipa-diagnose never proposes adding members, hosts or services to a rule, or "
                  "enabling a rule, just to turn a deny into an allow.")
    elif r.authorization.state == State.PASS:
        reason = "Nothing to fix in FreeIPA HBAC policy for this request."
    elif "OBJECT_UNREADABLE" in codes:
        reason = ("No fix: the user or host could not be read with this identity (see WHY). Run the command again, "
                  "or with an identity that may read it.")
    else:
        reason = (f"No fix: the decision is unknown (see WHY). If FreeIPA refused the evaluation for "
                  f"{r.principal or 'this identity'}, run it with an identity that may use hbactest.")
    return {"status": "NONE", "procedure": None, "commands": [], "reason": reason}


def risk(r: AccessResult) -> str:
    if r.authorization.state == State.FAIL or r.authentication.state == State.FAIL:
        return ("Changing HBAC rules, group memberships or account state changes who can log in where: it can grant "
                "more access than intended (for example through a group or hostgroup shared by other objects). "
                "Review such a change with the policy owner.")
    return "None from this command: it only reads."


def verify_steps(r: AccessResult) -> List[str]:
    t = r.targets
    q = shlex.quote
    if t.user_domain:
        return [f"ipa hbactest --user={q(t.display_user)} --host={q(t.host)} --service={q(t.service)}   "
                "(FreeIPA's own evaluation, read-only)"]
    user = r.account.canonical or t.user
    host = r.host.canonical or t.host
    svc = r.service.canonical or t.service
    codes = _codes(r)
    if r.account.exists is False or r.account.preserved or r.host.exists is False:
        steps = []
        if r.account.exists is False or r.account.preserved:
            steps += [f"ipa user-show {q(user)}   (read-only)",
                      f"ipa user-find --preserved=true --login={q(user)}   (read-only; a deleted but kept account)",
                      f"ipa stageuser-show {q(user)}   (read-only; an account not yet activated)"]
        if r.host.exists is False:
            steps.append(f"ipa host-show {q(host)}   (read-only; the host may be enrolled under another name)")
        steps.append("(do not use ipa hbactest for a name that does not exist: it evaluates such names anyway and "
                     "can report access granted through rules for all users or hosts)")
        return steps
    if "EVALUATOR_UNAVAILABLE" in codes:
        return ["klist   (is there a valid Kerberos ticket?)",
                f"ipa-diagnose access {q(user)} {q(host)} {q(svc)}   (again, after kinit or once the server is "
                "reachable)"]
    steps = [f"ipa hbactest --user={q(user)} --host={q(host)} --service={q(svc)}   "
             "(FreeIPA's own evaluation, read-only)"]
    if r.authorization.state == State.FAIL:
        steps.insert(0, f"ipa-diagnose access {q(user)} {q(host)} {q(svc)}   (again, after any change the policy "
                        "owner decides on)")
    if r.authentication.state == State.FAIL:
        steps.append(f"ipa user-show {q(user)} --all   (read-only; 'Account disabled' and 'Kerberos principal "
                     "expiration')")
    if r.authentication.state != State.FAIL:
        steps.append(f"ipa user-status {q(user)}   (read-only; failed logins and lockout on each server)")
    if r.authorization.state == State.PASS and r.authentication.state != State.FAIL:
        steps.append(f"on {host}, as root: sssctl user-checks {q(user)} -a acct -s {q(svc)}   "
                     "(the host's SSSD account check for this service; read-only; runtime evidence this command "
                     "does not collect)")
    return steps


# ---------------------------------------------------------------- JSON


def _side_dict(e: SideExplanation) -> Dict[str, Any]:
    return {"side": e.side, "how": e.how, "via": e.via, "chain": e.chain, "chain_complete": e.chain_complete}


def to_dict(r: AccessResult) -> Dict[str, Any]:
    ev = r.evaluation
    paths = []
    for e in r.rules:
        for side in ("user", "host", "service"):
            for s in e.sides[side]:
                if s.how in ("group", "nested_group"):
                    paths.append({"rule": e.rule, **_side_dict(s)})
    doc = {
        "kind": "ipa-diagnose.access",
        "access_schema_version": ACCESS_SCHEMA_VERSION,
        "source_mode": r.mode,
        "generated_at": r.generated_at,
        "query": {
            "question": "Does FreeIPA HBAC policy authorize USER to access HOST through SERVICE, and why?",
            "input": r.raw_query,
            "user": r.targets.user, "user_domain": r.targets.user_domain, "user_display": r.targets.display_user,
            "host": r.targets.host, "host_completed_with_ipa_domain": r.targets.host_completed,
            "service": r.targets.service,
            "asked_as": r.principal, "ipa_server": r.server, "ipa_api_version": r.api_version,
        },
        "answer": headline(r),
        "authentication": {"state": r.authentication.state.value, "summary": r.authentication.summary,
                           "reasons": r.authentication.reasons,
                           "account": {"exists": r.account.exists, "canonical_name": r.account.canonical,
                                       "disabled": r.account.disabled, "preserved": r.account.preserved,
                                       "principal_expires": r.account.principal_expires,
                                       "principal_expired": r.account.principal_expired,
                                       "password_expires": r.account.password_expires,
                                       "password_expired": r.account.password_expired,
                                       "lockout_checked": False}},
        "authorization": {"state": r.authorization.state.value, "summary": r.authorization.summary,
                          "reasons": r.authorization.reasons,
                          "decided_by": "FreeIPA hbactest" if r.authorization.state in (State.PASS, State.FAIL)
                          else None},
        "runtime_access": {"state": r.runtime.state.value, "summary": r.runtime.summary,
                           "reasons": r.runtime.reasons},
        "authoritative_evaluation": {
            "ran": ev.ran, "granted": ev.granted, "request": ev.request, "matched_rule_names": ev.matched,
            "not_matched_rule_count": ev.not_matched_count, "error_rules": ev.error_rules,
            "rule_list_truncated": ev.truncated, "error": ev.error, "summary": ev.summary,
            "evaluates": "enabled HBAC rules only (as SSSD)",
        },
        "objects": {
            "user": {"exists": r.account.exists, "canonical_name": r.account.canonical,
                     "direct_groups": sorted(r.user_groups.direct) if r.user_groups else None,
                     "nested_groups": sorted(r.user_groups.indirect) if r.user_groups else None},
            "host": {"exists": r.host.exists, "canonical_name": r.host.canonical, "has_keytab": r.host.has_keytab,
                     "direct_hostgroups": sorted(r.host_groups.direct) if r.host_groups else None,
                     "nested_hostgroups": sorted(r.host_groups.indirect) if r.host_groups else None},
            "service": {"exists": r.service.exists, "canonical_name": r.service.canonical,
                        "service_groups": r.service.groups},
        },
        "matched_rules": [
            {"rule": e.rule, "enabled": e.enabled, "matched_by_freeipa": e.matched_by_freeipa,
             "explanation_status": e.status, "source": e.source,
             "sides": {k: [_side_dict(s) for s in v] for k, v in e.sides.items()}}
            for e in r.rules if e.matched_by_freeipa
        ],
        "related_rules": [
            {"rule": e.rule, "enabled": e.enabled, "matched_by_freeipa": False, "explanation_status": e.status,
             "source": e.source, "sides": {k: [_side_dict(s) for s in v] for k, v in e.sides.items()}}
            for e in r.rules if not e.matched_by_freeipa
        ],
        "relationship_paths": paths,
        "explanation_status": r.explanation_status,
        "evidence": {
            "checks": [{"name": c.name, "call": c.call, "outcome": c.outcome, "summary": c.summary,
                        "seconds": c.seconds} for c in r.checks],
            "relationships": [{"from": {"kind": e.src.kind.value, "name": e.src.name},
                               "to": {"kind": e.dst.kind.value, "name": e.dst.name},
                               "kind": e.kind.value, "side": e.side, "source": e.source}
                              for e in r.index.edges()],
            "provenance": {"mode": r.mode, "via": "FreeIPA JSON-RPC API over HTTPS with the caller's Kerberos "
                           "ticket" if r.mode == "LIVE" else "recorded API answers (REPLAY; describes no live "
                           "system)", "read_only": True},
        },
        "completeness": r.completeness,
        "diagnosis": {"root_cause": root_cause(r), "no_blocker": None if root_cause(r) else no_blocker_text(r),
                      "why": why(r), "impact": impact(r),
                      "findings": [{"code": f.code, "title": f.title, "detail": f.detail, "blocking": f.blocking}
                                   for f in r.findings]},
        "resolution": resolution(r),
        "risk": risk(r),
        "verify": verify_steps(r),
        "limitations": r.limitations,
    }
    return _c(doc)


# ---------------------------------------------------------------- console

_STYLE = {"PASS": "green", "FAIL": "red", "UNKNOWN": "yellow", "NOT_VERIFIED": "cyan"}
_LABEL = {"PASS": "PASS", "FAIL": "FAIL", "UNKNOWN": "UNKNOWN", "NOT_VERIFIED": "NOT VERIFIED"}


def render(r: AccessResult, console: Console, details: bool = False) -> None:
    d = to_dict(r)  # already sanitized
    q = d["query"]
    p = lambda text="", style=None: console.print(text, markup=False, soft_wrap=True, style=style)  # noqa: E731
    src = "LIVE" if r.mode == "LIVE" else "REPLAY of recorded evidence (describes no live system)"
    p(f"ipa-diagnose access: {q['user_display']} -> "
      f"{q['host']} via {q['service']}", "bold")
    p(f"  {src}; asked FreeIPA as {q['asked_as'] or 'unknown'}"
      + (f" on {q['ipa_server']}" if q["ipa_server"] else "")
      + (f" (API {q['ipa_api_version']})" if q["ipa_api_version"] else ""))
    if q["host_completed_with_ipa_domain"]:
        p(f"  HOST was a short name; evaluated as {q['host']} (as FreeIPA's hbactest does).")
    p()
    p(d["answer"], "bold")
    p()
    for label, key in (("AUTHENTICATION", "authentication"), ("AUTHORIZATION", "authorization"),
                       ("RUNTIME ACCESS", "runtime_access")):
        st = d[key]["state"]
        console.print(f"  {label:<15} ", end="", markup=False)
        console.print(f"{_LABEL[st]:<13}", style=_STYLE[st], end="", markup=False)
        p(d[key]["summary"])
        for reason in d[key]["reasons"]:
            if reason and reason != d[key]["summary"]:
                p(f"  {'':<15} {'':<13}{reason}", "dim")
    p()
    rc = d["diagnosis"]["root_cause"]
    p("ROOT CAUSE", "bold")
    p("  " + ("; ".join(rc) if rc else d["diagnosis"]["no_blocker"]))
    p("WHY", "bold")
    for line in d["diagnosis"]["why"] or ["-"]:
        p("  " + line)
    context = [f for f in d["diagnosis"]["findings"] if not f["blocking"]]
    if context:
        p("ALSO NOTED", "bold")
        for f in context:
            p(f"  {f['title']}: {f['detail']}")
    p("CHECKED FOR YOU", "bold")
    marks = {"ok": "ok  ", "problem": "!!  ", "not_found": "--  ", "error": "ERR ", "skipped": "skip"}
    for c in d["evidence"]["checks"]:
        p(f"  [{marks.get(c['outcome'], '?   ')}] {c['summary']}")
        if details:
            p(f"         read-only API call: {c['call']} ({c['seconds']} s)", "dim")
    p("IMPACT", "bold")
    p("  " + d["diagnosis"]["impact"])
    p("RESOLUTION", "bold")
    p("  " + d["resolution"]["reason"])
    p("RISK", "bold")
    p("  " + d["risk"])
    p("VERIFY", "bold")
    for s in d["verify"]:
        p("  " + s)
    if details:
        p("RELATIONSHIPS READ (explanation only; the decision is FreeIPA's)", "bold")
        for e in d["evidence"]["relationships"]:
            p(f"  {e['from']['kind']} {e['from']['name']} -{e['kind']}{'/' + e['side'] if e['side'] else ''}-> "
              f"{e['to']['kind']} {e['to']['name']}   [{e['source']}]", "dim")
        comp = d["completeness"]
        p(f"  {comp['api_calls']} API call(s) of a budget of {comp['api_call_budget']}; index "
          f"{comp['relationship_index']['nodes']} nodes / {comp['relationship_index']['edges']} edges", "dim")
        for n in comp["notes"]:
            p(f"  {n}", "dim")
    p("LIMITATIONS", "bold")
    for lim in d["limitations"] if details else d["limitations"][:1]:
        p("  " + lim)
    if not details:
        p("  (--details lists every limitation, the API calls made and the relationships read)", "dim")
