"""`ipa-diagnose access USER HOST SERVICE [--json] [--details] [--replay DIR]`

Asks FreeIPA whether its policy authorizes USER to access HOST through SERVICE (a PAM/HBAC service such as sshd),
and explains why. Read-only; uses the caller's own Kerberos ticket; never changes anything; never uses AI.

Exit codes:
  0  FreeIPA policy authorizes the request and nothing in the account state blocks it
     (runtime access is still NOT VERIFIED: no login was attempted)
  1  a definite no: FreeIPA policy does not authorize it, or the account cannot authenticate
  3  unknown: no trustworthy policy decision (API unavailable, no ticket, missing user/host, evaluator errors...)
  4  FreeIPA policy authorizes it, but the account state could not be read
  5  (only with --runtime) FreeIPA policy authorizes it, but a runtime check on this host shows the login would fail
  2  usage error (including a refused USER/HOST/SERVICE); 70 internal error; 130 interrupted
Nothing is saved: `access` never touches the `verify` baseline.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List

from rich.console import Console

from ipa_diagnose.access.evaluate import AccessResult, State

USAGE_ERROR = 2


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse echoes raw arguments; never print their control characters
        from ipa_diagnose.textsafe import sanitize_text

        super().error(sanitize_text(message, 400))


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="ipa-diagnose access",
        description="Does FreeIPA policy authorize USER to access HOST through SERVICE, and why? Read-only; asks "
        "FreeIPA's own HBAC evaluator with your Kerberos ticket (kinit first).",
        epilog="Exit codes: 0 authorized by policy (login itself not tested); 1 not authorized or the account cannot "
        "authenticate; 3 unknown; 4 authorized but account state unreadable; 2 usage error.",
    )
    p.add_argument("user", metavar="USER", help="IPA user name (for example john)")
    p.add_argument("host", metavar="HOST", help="target host name (for example app03.example.com)")
    p.add_argument("service", metavar="SERVICE", help="PAM/HBAC service name (for example sshd, login, sudo)")
    p.add_argument("--json", action="store_true", help="print the answer as JSON")
    p.add_argument("--details", action="store_true", help="also show API calls, relationships and all limitations")
    p.add_argument("--replay", metavar="FIXTURE_DIR", default=None,
                   help="answer from recorded API evidence (development/testing; marked REPLAY)")
    p.add_argument("--runtime", action="store_true",
                   help="when run as root ON HOST: continue into the runtime side (SSSD, NSS, PAM account phase) with "
                   "client mode's planner; the HBAC decision itself is never changed")
    return p


def _strip_command(argv: List[str]) -> List[str]:
    out, skip, done = [], False, False
    for a in argv:
        if skip:
            skip = False
            out.append(a)
            continue
        if not done and a == "access":
            done = True
            continue
        if a in ("--replay", "--ai-provider"):
            skip = True
        out.append(a)
    return out


def exit_code(r: AccessResult) -> int:
    a, z = r.authentication.state, r.authorization.state
    if a == State.FAIL or z == State.FAIL:
        return 1
    if z == State.PASS and r.runtime.state == State.FAIL:  # only --runtime can set a runtime FAIL
        return 5
    if z == State.PASS:
        return 4 if a == State.UNKNOWN else 0
    return 3


def run(argv: List[str]) -> int:
    from ipa_diagnose.access.api import LiveApi, ReplayApi
    from ipa_diagnose.access.evaluate import diagnose
    from ipa_diagnose.access.output import render, to_dict
    from ipa_diagnose.access.targets import TargetError, parse_targets

    parser = build_parser()
    rest = _strip_command(argv)
    while "--no-ai" in rest:  # accepted everywhere else; access never uses AI
        rest.remove("--no-ai")
    if "--ai-provider" in rest:
        parser.error("access diagnosis never uses an AI provider")
    args = parser.parse_intermixed_args(rest)
    if args.replay is not None and not os.path.isdir(args.replay):
        parser.error("--replay needs a directory of recorded evidence")
    api = ReplayApi(args.replay) if args.replay else LiveApi()
    try:
        targets = parse_targets(args.user, args.host, args.service, api.context.domain, api.context.realm)
    except TargetError as e:
        parser.error(str(e))
    result = diagnose(api, targets, {"user": args.user, "host": args.host, "service": args.service})
    if args.runtime:
        from ipa_diagnose.access.runtime import extend, local_enrolled_host
        from ipa_diagnose.resolution.checks import LiveRunner, ReplayRunner

        if args.replay:
            runner = ReplayRunner(args.replay, filename="client_checks.json")
            local = runner.run("client.ipa_conf", {}).fields.get("host")
            from ipa_diagnose.client.cli import _replay_root

            extend(result, runner, local if isinstance(local, str) else None, is_root=_replay_root(args.replay))
        else:
            extend(result, LiveRunner(), local_enrolled_host())
    if args.json:
        print(json.dumps(to_dict(result), indent=2))
    else:
        render(result, Console(highlight=False, emoji=False), details=args.details)
    return exit_code(result)
