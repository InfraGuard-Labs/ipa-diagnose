"""Run one client investigation: planner (L3) -> diagnoses (L4) -> fix procedures (L5, Slice 1 engine) -> verdicts.

States (docs/client-mode.md):
- AUTHENTICATION (path on this host): FAIL when something on this host's Kerberos/SSSD path to IPA is broken (clock,
  KDC, host key, SSSD, PAM auth stack); otherwise NOT_VERIFIED. Never PASS: no credential is tested.
- AUTHORIZATION: not decided here. Client mode reports FreeIPA's HBAC decision only when it is given one (access
  integration); SSSD's account check on this host is RUNTIME evidence, never a replacement for FreeIPA's decision.
- RUNTIME ACCESS: FAIL when a runtime prerequisite on this host is shown broken for the user/service asked (SSSD
  down, identity not resolvable, NSS/PAM not using SSSD, the PAM account phase refusing). NOT_VERIFIED otherwise,
  with what was and was not checked. Never PASS: no login is attempted.
"""

from __future__ import annotations

import dataclasses
import datetime
import os
from typing import Any, Dict, List, Optional

from ipa_diagnose.client.diagnose import (
    CONTRADICTING, INDEPENDENT, PRIMARY, RELATED, UNDIAGNOSED, WARNING, ClientDiagnosis, diagnose, ruled_out,
)
from ipa_diagnose.client.plan import client_plan, plan_inputs
from ipa_diagnose.planner.core import Outcome, Trace, run_plan

CLIENT_SCHEMA_VERSION = "1.0"

# capabilities whose checks, when not verified, leave a real gap in what the run can claim
_ESSENTIAL = ("enroll", "sssd", "dns.server", "net.ldap", "tls", "time.server", "keytab", "krb", "sssd.service",
              "sssd.config", "sssd.domain", "id.user", "id.group", "pam.stack", "pam.acct")


@dataclasses.dataclass
class Verdict:
    state: str  # PASS | FAIL | UNKNOWN | NOT_VERIFIED
    summary: str
    reasons: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ClientResult:
    mode: str
    generated_at: str
    inputs: Dict[str, Any]
    trace: Trace
    diagnoses: List[ClientDiagnosis]
    resolutions: Dict[str, Any]
    authentication: Verdict
    authorization: Verdict
    runtime: Verdict
    status: str  # HEALTHY | HEALTHY_WITH_WARNINGS | PROBLEM_FOUND | NOT_FULLY_VERIFIED
    completeness: Dict[str, Any]
    ruled_out: List[str]
    environment: Dict[str, Any]
    limitations: List[str]


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _unexplained_gap(trace: Trace, r, depth: int = 0) -> bool:
    """A check that did not answer, or was not run for a reason that is NOT an observed failure upstream (privilege,
    version, budget), is a gap. A step blocked by a failure that was observed is explained, not a gap."""

    if r.outcome == Outcome.UNKNOWN:
        return True
    if r.outcome != Outcome.SKIPPED or depth > 20:
        return False
    kind = r.skip_reason.split(":", 1)[0]
    if kind in ("privilege", "not applicable"):
        return True
    if kind == "stopped":
        return not r.skip_reason.startswith("stopped: this host is not an IPA client")
    if kind == "blocked" and r.blocked_by:
        up = trace.get(r.blocked_by)
        return up is not None and _unexplained_gap(trace, up, depth + 1)
    return False


def _completeness(trace: Trace) -> Dict[str, Any]:
    gaps = []
    for r in trace.records:
        if r.step_id in _ESSENTIAL and _unexplained_gap(trace, r):
            reason = r.summary if r.outcome == Outcome.UNKNOWN else r.skip_reason
            gaps.append({"step": r.step_id, "check": r.title, "reason": reason})
    return {"level": "complete" if not gaps else "partial", "not_verified": gaps,
            "planner": trace.summary()}


def _env(trace: Trace) -> Dict[str, Any]:
    e = trace.get("env")
    f = e.fields if e and e.outcome != Outcome.SKIPPED else {}
    c = trace.get("enroll")
    cf = c.fields if c and c.outcome != Outcome.SKIPPED else {}
    return {"sssd": f.get("sssd"), "ipa_client": f.get("ipa_client"), "os": f.get("os"),
            "os_version": f.get("os_version"), "systemd": f.get("systemd"), "host": cf.get("host"),
            "domain": cf.get("domain"), "realm": cf.get("realm"), "server": cf.get("server"),
            "is_ipa_server": cf.get("is_ipa_server")}


def _resolve(diags: List[ClientDiagnosis], env: Dict[str, Any], runner: Any) -> Dict[str, Any]:
    """Slice 1's resolution engine, unchanged in its gates: confidence, typed bindings, applicability (IPA client
    version), fresh read-only checks, withhold_if, prerequisites, typed argv."""

    from ipa_diagnose.engine.model import (
        Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, PriorityBucket,
    )
    from ipa_diagnose.evidence.model import EnvironmentInfo
    from ipa_diagnose.resolution.engine import Resolution, WITHHELD, resolve_diagnosis
    from ipa_diagnose.resolution.knowledge import load_catalogue

    catalogue, error = load_catalogue()
    info = EnvironmentInfo(distro=env.get("os"), distro_version=env.get("os_version"),
                           freeipa_version=env.get("ipa_client"), detected_live=not getattr(runner, "replay", False))
    prio = {PRIMARY: PriorityBucket.PRIMARY, INDEPENDENT: PriorityBucket.SECONDARY_INDEPENDENT,
            RELATED: PriorityBucket.RELATED_SYMPTOM, WARNING: PriorityBucket.WARNING}
    out: Dict[str, Any] = {}
    for d in diags:
        if not d.resolution_key:
            continue
        if d.role in (UNDIAGNOSED, CONTRADICTING):
            continue  # nothing is fixed on an unexplained or contradicting picture
        conf = {"HIGH": ConfidenceLevel.HIGH, "MEDIUM": ConfidenceLevel.MEDIUM}.get(d.confidence, ConfidenceLevel.LOW)
        ed = Diagnosis(pack_id="client", rule_id=d.code,
                       status=DiagnosisStatus.DIAGNOSED if conf != ConfidenceLevel.LOW
                       else DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                       title=d.title, why=d.detail, confidence=Confidence(conf, d.detail),
                       priority=prio.get(d.role, PriorityBucket.INFORMATIONAL), diagnosis_id=f"client.{d.code}",
                       related_to_titles=[x.title for x in diags if x.code == d.related_to],
                       resolution_key=d.resolution_key, variant=d.variant, bindings=dict(d.bindings))
        try:
            res = resolve_diagnosis(ed, info, runner, catalogue)
        except Exception as e:  # noqa: BLE001 - a fix must never break the diagnosis
            res = Resolution(diagnosis_id=ed.diagnosis_id, status=WITHHELD,
                             reasons=[f"Internal error while preparing the fix ({type(e).__name__}); nothing is shown."])
        if res is not None:
            out[d.code] = res
    if error:
        out["_catalogue_error"] = error
    return out


def _authentication(diags: List[ClientDiagnosis], trace: Trace) -> Verdict:
    broken = [d for d in diags if d.blocks_authentication and d.severity == "FAIL"]
    if broken:
        return Verdict("FAIL", "online authentication against IPA fails on this host: " + broken[0].title,
                       [d.title for d in broken] + ["users who logged in before may still authenticate offline with "
                                                    "cached credentials, if SSSD caches them"])
    return Verdict("NOT_VERIFIED", "nothing on this host's authentication path was found broken; no credential was "
                   "tested", ["no password or ticket of any user was used"])


def _runtime(diags: List[ClientDiagnosis], trace: Trace, inputs: Dict[str, Any]) -> Verdict:
    broken = [d for d in diags if d.blocks_runtime and d.severity == "FAIL"]
    user, service = inputs.get("user"), inputs.get("service")
    if broken:
        return Verdict("FAIL", f"a login{' by ' + user if user else ''}{' through ' + service if service else ''} "
                       f"is expected to fail on this host: {broken[0].title}", [d.title for d in broken])
    checked = []
    for sid, what in (("id.user", "the user resolves through SSSD"), ("nss.system", "the system NSS stack "
                                                                                  "resolves the user"),
                      ("pam.stack", "the PAM service uses SSSD"),
                      ("pam.acct", "SSSD's account check (PAM account phase) accepts the user")):
        r = trace.get(sid)
        if r and r.outcome == Outcome.PASS:
            checked.append(what)
    missing = []
    if not user:
        missing.append("no user was given (--user)")
    if not service:
        missing.append("no PAM service was given (--service)")
    r = trace.get("pam.acct")
    if user and service and (r is None or r.outcome != Outcome.PASS):
        missing.append("the PAM account phase was not checked" + (f" ({r.skip_reason or r.summary})" if r else ""))
    summary = ("not tested: no login was attempted" + ("; checked on this host: " + "; ".join(checked)
                                                       if checked else ""))
    return Verdict("NOT_VERIFIED", summary, missing + ["no password was used and no session was opened"])


def _status(diags: List[ClientDiagnosis], completeness: Dict[str, Any]) -> str:
    if diags and all(d.code == "EVIDENCE_UNUSABLE" for d in diags):
        return "NOT_FULLY_VERIFIED"
    if any(d.severity == "FAIL" or d.role in (UNDIAGNOSED, CONTRADICTING) for d in diags):
        return "PROBLEM_FOUND"
    if completeness["level"] != "complete":
        return "NOT_FULLY_VERIFIED"
    if diags:
        return "HEALTHY_WITH_WARNINGS"
    return "HEALTHY"


LIMITATIONS = [
    "No login is attempted and no credential is tested: RUNTIME ACCESS and AUTHENTICATION are never reported as PASS.",
    "Checks run on this host only; other clients and every IPA server are not examined (DNS answers may differ "
    "elsewhere).",
    "SSSD's account check (sssctl user-checks, PAM account phase) is runtime evidence on this host; the policy "
    "decision itself is FreeIPA's hbactest (ipa-diagnose access).",
    "Trusted-domain (AD) users, ID views, sudo rules, SELinux maps, automount and smart cards are not diagnosed.",
    "SSSD log reading is limited to known signals in recent lines; an unknown failure may not be recognized.",
    "Only SSSD 2.0 or later is examined with sssctl; on an unknown or older version those checks are skipped.",
]


def investigate(runner: Any, user: Optional[str] = None, service: Optional[str] = None,
                hbac_state: Optional[str] = None, is_root: Optional[bool] = None,
                max_seconds: Optional[float] = None) -> ClientResult:
    from ipa_diagnose.resolution.checks import REGISTRY

    root = _is_root() if is_root is None else is_root
    inputs = plan_inputs(user, service)
    kw = {"max_seconds": max_seconds} if max_seconds else {}
    trace, _ctx = run_plan(client_plan(), runner, inputs, is_root=root, registry=REGISTRY, **kw)
    try:
        diags = diagnose(trace, dict(inputs, hbac_state=hbac_state))
    except (TypeError, ValueError, AttributeError, KeyError, OverflowError, IndexError):
        # evidence of an unexpected type reached a rule: nothing is concluded from it (and nothing is fixed)
        diags = [ClientDiagnosis("EVIDENCE_UNUSABLE", "The collected evidence could not be interpreted", "ENROLLMENT",
                                 "LOW", "A check returned a value of an unexpected type, so no cause is concluded.",
                                 "Unknown.", [], kind=UNDIAGNOSED, role=UNDIAGNOSED)]
    env = _env(trace)
    resolutions = _resolve(diags, env, runner)
    completeness = _completeness(trace)
    authz = (Verdict(hbac_state, "FreeIPA HBAC policy decision (hbactest), as given by ipa-diagnose access")
             if hbac_state else
             Verdict("NOT_VERIFIED", "not evaluated by client mode: FreeIPA's own decision comes from "
                     "ipa-diagnose access USER HOST SERVICE"))
    return ClientResult(
        mode="REPLAY" if getattr(runner, "replay", False) else "LIVE", generated_at=_now(),
        inputs={"user": user, "service": service}, trace=trace, diagnoses=diags, resolutions=resolutions,
        authentication=_authentication(diags, trace), authorization=authz, runtime=_runtime(diags, trace, inputs),
        status=_status(diags, completeness), completeness=completeness, ruled_out=ruled_out(trace),
        environment=env, limitations=list(LIMITATIONS))
