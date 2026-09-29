"""`ipa-diagnose access USER HOST SERVICE --runtime`: continue past FreeIPA's HBAC decision into the runtime side.

The HBAC decision (AUTHORIZATION) is FreeIPA's hbactest and is never changed here. What changes is RUNTIME ACCESS:

- runs only ON the host asked about (this machine's enrolled name, from /etc/ipa/default.conf, must be HOST): there
  is no remote execution; elsewhere RUNTIME ACCESS stays NOT_VERIFIED and the command to run on HOST is printed;
- runs only when neither the policy nor the account already refuses (a login refused by policy needs no runtime
  investigation to be refused);
- uses client mode's bounded planner for USER and SERVICE; RUNTIME ACCESS becomes FAIL when a runtime prerequisite on
  this host is shown broken, and otherwise stays NOT_VERIFIED (no login is attempted).
"""

from __future__ import annotations

import shlex
from typing import Any, Optional

from ipa_diagnose.access.evaluate import AccessResult, State, Verdict


def local_enrolled_host(conf_path: str = "/etc/ipa/default.conf") -> Optional[str]:
    from ipa_diagnose.access.api import read_ipa_conf
    from ipa_diagnose.resolution import types as T

    return T.validate("fqdn", read_ipa_conf(conf_path).get("host", ""))


def extend(result: AccessResult, runner: Any, local_host: Optional[str], is_root: Optional[bool] = None) -> None:
    from ipa_diagnose.client.run import investigate
    from ipa_diagnose.resolution import types as T

    t = result.targets
    host = (result.host.canonical or t.host).lower()
    user = result.account.canonical or t.user
    svc = result.service.canonical or t.service
    cmd = (f"ipa-diagnose client --user {shlex.quote(user)} --service {shlex.quote(svc)}   (as root on {host})")
    if result.authorization.state == State.FAIL or result.authentication.state == State.FAIL:
        result.runtime_note = ("not investigated: FreeIPA already refuses this request (see AUTHORIZATION / "
                               "AUTHENTICATION), so a runtime check could not change the answer")
        return
    if t.user_domain or T.validate("ipa_user", user) is None or T.validate("pam_service", svc) is None:
        result.runtime_note = "not investigated: this user or service form is not supported by client mode"
        return
    if not local_host:
        result.runtime_note = (f"not investigated: this machine is not an enrolled IPA client, so it cannot check "
                               f"{host}; run on {host}: {cmd}")
        result.runtime = Verdict(State.NOT_VERIFIED, result.runtime.summary,
                                 result.runtime.reasons + [f"to check it, run on {host}: {cmd}"])
        return
    if local_host != host:
        result.runtime_note = (f"not investigated: this machine is {local_host}, not {host}; ipa-diagnose never runs "
                               f"checks on another host. Run on {host}: {cmd}")
        result.runtime = Verdict(State.NOT_VERIFIED, result.runtime.summary,
                                 result.runtime.reasons + [f"to check it, run on {host}: {cmd}"])
        return
    hbac = result.authorization.state.value if result.authorization.state in (State.PASS, State.FAIL) else None
    client = investigate(runner, user=user, service=svc, hbac_state=hbac, is_root=is_root)
    result.client = client
    if client.runtime.state == "FAIL":
        result.runtime = Verdict(State.FAIL, f"checked on {host}: {client.runtime.summary}",
                                 list(client.runtime.reasons))
        result.runtime_note = "investigated on this host with client mode's planner"
    else:
        result.runtime = Verdict(State.NOT_VERIFIED, f"checked on {host}: {client.runtime.summary}",
                                 list(client.runtime.reasons))
        result.runtime_note = "investigated on this host with client mode's planner; no login was attempted"
