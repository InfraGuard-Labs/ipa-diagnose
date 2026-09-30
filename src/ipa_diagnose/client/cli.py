"""`ipa-diagnose client [--user USER] [--service SERVICE] [--json] [--details] [--verify] [--replay DIR]`

Is this FreeIPA client correctly enrolled and able to resolve/authenticate identities, and if not, why? A bounded,
deterministic planner picks the next relevant read-only check from what it has already seen; nothing is changed;
no AI is used. Run it as root on the client (most checks need root; without it they are reported as not verified).

Exit codes:
  0  healthy (warnings may be listed)          1  a problem was found
  4  nothing wrong found, but not everything could be checked
  2  usage error; 70 internal error; 130 interrupted
With --verify: 0 everything found last time is resolved (and nothing new), 1 something is still present or new,
4 something could not be verified.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List

from rich.console import Console

EXIT = {"HEALTHY": 0, "HEALTHY_WITH_WARNINGS": 0, "PROBLEM_FOUND": 1, "NOT_FULLY_VERIFIED": 4}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse echoes raw arguments; never print their control characters
        from ipa_diagnose.textsafe import sanitize_text

        super().error(sanitize_text(message, 400))


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="ipa-diagnose client",
                description="Is this FreeIPA client enrolled and able to resolve and authenticate IPA identities, "
                "and if not, why? Read-only; run as root on the client.",
                epilog="Exit codes: 0 healthy; 1 problem found (with --verify: still present, partial or new); 4 not "
                       "everything could be checked (with --verify: could not be verified); 2 usage error.")
    p.add_argument("--user", metavar="USER", default=None, help="an IPA user whose lookup (and login path) to check")
    p.add_argument("--service", metavar="SERVICE", default=None,
                   help="PAM service to check for that user (for example sshd); runs the PAM account phase only")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.add_argument("--details", action="store_true", help="also show why each check ran or was skipped")
    p.add_argument("--verify", action="store_true",
                   help="re-check with fresh evidence whether the problems found last time are resolved")
    p.add_argument("--replay", metavar="FIXTURE_DIR", default=None,
                   help="answer from recorded check results (development/testing; marked REPLAY)")
    return p


def _strip_command(argv: List[str]) -> List[str]:
    out, skip, done = [], False, False
    for a in argv:
        if skip:
            skip = False
            out.append(a)
            continue
        if not done and a == "client":
            done = True
            continue
        if a in ("--replay", "--user", "--service"):
            skip = True
        out.append(a)
    return out


def run(argv: List[str]) -> int:
    from ipa_diagnose.resolution import types as T
    from ipa_diagnose.resolution.checks import LiveRunner, ReplayRunner

    parser = build_parser()
    rest = _strip_command(argv)
    while "--no-ai" in rest:  # accepted everywhere else; client mode never uses AI
        rest.remove("--no-ai")
    if "--ai-provider" in rest:
        parser.error("client mode never uses an AI provider")
    args = parser.parse_args(rest)
    if args.replay is not None and not os.path.isdir(args.replay):
        parser.error("--replay needs a directory of recorded evidence")
    if args.user is not None and T.validate("ipa_user", args.user) is None:
        parser.error("--user must be an IPA user name (letters, digits, . _ -; not all digits; not 'all')")
    if args.service is not None and T.validate("pam_service", args.service) is None:
        parser.error("--service must be a PAM service name such as sshd")
    if args.service and not args.user:
        parser.error("--service needs --user")
    runner = ReplayRunner(args.replay, filename="client_checks.json") if args.replay else LiveRunner()
    is_root = None
    if args.replay:
        is_root = _replay_root(args.replay)
    from ipa_diagnose.client.run import investigate
    from ipa_diagnose.client import verify as V

    path = V.state_path(bool(args.replay))
    previous = None
    if args.verify:
        try:
            previous = V.load(path)
        except V.UnreadableState:
            msg = ("The saved client result exists but cannot be read (damaged or modified), so nothing can be "
                   "verified. Run ipa-diagnose client to create a new one.")
            if args.json:
                print(json.dumps({"kind": "ipa-diagnose.client.verify", "baseline_unreadable": True, "items": []}))
            else:
                Console(stderr=True, highlight=False).print(msg, markup=False)
            return 4
        if previous is not None and args.user is None and args.service is None:
            args.user, args.service = previous["inputs"].get("user"), previous["inputs"].get("service")
            if args.user is not None and T.validate("ipa_user", args.user) is None:
                args.user = args.service = None
            if args.service is not None and T.validate("pam_service", args.service) is None:
                args.service = None
    result = investigate(runner, user=args.user, service=args.service, is_root=is_root)
    fresh = EXIT[result.status]
    console = Console(highlight=False, emoji=False)
    from ipa_diagnose.client.output import render, to_dict

    if args.verify:
        if previous is None:
            if args.json:
                print(json.dumps({"kind": "ipa-diagnose.client.verify", "previous_generated_at": None, "items": [],
                                  "current": to_dict(result)}, indent=2))
            else:
                console.print("No saved client result to compare with: showing a fresh investigation.\n", markup=False)
                render(result, console, details=args.details)
            V.save(path, result)
            return fresh
        cmp = V.compare(previous, result, runner)
        code = V.exit_code(cmp, fresh)
        if args.json:
            from ipa_diagnose.client.output import _c

            print(json.dumps(_c({"kind": "ipa-diagnose.client.verify", "previous_generated_at":
                                 cmp["previous_generated_at"],
                                 "items": [{"code": i.code, "title": i.title, "outcome": i.outcome, "detail": i.detail}
                                           for i in cmp["items"]],
                                 "new_conditions": [d.title for d in cmp["new_conditions"]],
                                 "current": to_dict(result)}), indent=2))
        else:
            _render_verify(cmp, console)
            console.print()
            render(result, console, details=args.details)
        if not any(i.outcome in ("STILL_PRESENT", "PARTIALLY_RESOLVED", "UNABLE_TO_VERIFY", "CHANGED")
                   for i in cmp["items"]):
            V.save(path, result)
        return code
    if args.json:
        print(json.dumps(to_dict(result), indent=2))
    else:
        render(result, console, details=args.details)
    V.save(path, result)
    return fresh


def _render_verify(cmp, console: Console) -> None:
    from ipa_diagnose.client.output import _safe as sanitize_text

    p = lambda t="", s=None: console.print(t, markup=False, soft_wrap=True, style=s)  # noqa: E731
    p(f"VERIFY (compared with the client result of {sanitize_text(cmp['previous_generated_at'], 40) or 'unknown'}; "
      "every check re-run now)", "bold")
    style = {"RESOLVED": "green", "STILL_PRESENT": "red", "PARTIALLY_RESOLVED": "yellow", "CHANGED": "yellow",
             "UNABLE_TO_VERIFY": "yellow"}
    if not cmp["items"]:
        p("  Nothing was found last time.")
    for i in cmp["items"]:
        p(f"  {i.outcome:<18} {sanitize_text(i.title, 200)}: {sanitize_text(i.detail, 300)}", style.get(i.outcome))
    for d in cmp["new_conditions"]:
        p(f"  {'NEW':<18} {sanitize_text(d.title, 200)}", "red")


def _replay_root(fixture_dir: str) -> bool:
    """A replay fixture records whether it was captured as root (meta.json {"is_root": true}); default true."""

    import pathlib

    try:
        doc = json.loads((pathlib.Path(fixture_dir) / "meta.json").read_text(encoding="utf-8"))
        return doc.get("is_root") is not False if isinstance(doc, dict) else True
    except (OSError, ValueError):
        return True
