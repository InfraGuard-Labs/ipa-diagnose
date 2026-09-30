"""`ipa-diagnose replication [--peer FQDN] [--json] [--details] [--verify] [--replay DIR]`

Does replication to and from this IPA server work, per suffix (domain, o=ipaca) and per direction, and if not, what is
the deepest proven cause? Run it as root on an IPA server. Read-only; nothing is changed here or on any other server;
no AI is used.

Exit codes:
  0  every investigated agreement is green in both directions (warnings may be listed)
  1  a problem was found
  4  nothing failing was found, but not everything could be checked (or this host is not an IPA server)
  2  usage error; 70 internal error; 130 interrupted
With --verify: 0 everything found last time is resolved (and nothing new), 1 something is still present or new,
3 PENDING (not failing any more, but no fresh successful session yet: recheck later), 4 something could not be
verified.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List

from rich.console import Console

EXIT = {"HEALTHY": 0, "HEALTHY_WITH_WARNINGS": 0, "PROBLEM_FOUND": 1, "NOT_FULLY_VERIFIED": 4, "NOT_AN_IPA_SERVER": 4}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse echoes raw arguments; never print their control characters
        from ipa_diagnose.textsafe import sanitize_text

        super().error(sanitize_text(message, 400))


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="ipa-diagnose replication",
                description="Does replication to and from this IPA server work, per suffix and direction, and if "
                "not, what is the deepest proven cause? Read-only; run as root on an IPA server.",
                epilog="Exit codes: 0 healthy; 1 problem found; 4 not everything could be checked; with --verify also "
                       "3 pending; 2 usage error.")
    p.add_argument("--peer", metavar="FQDN", default=None,
                   help="investigate only this server's agreements towards this peer (both suffixes)")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.add_argument("--details", action="store_true", help="also show every check, why it ran or was skipped")
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
        if not done and a == "replication":
            done = True
            continue
        if a in ("--replay", "--peer"):
            skip = True
        out.append(a)
    return out


def run(argv: List[str]) -> int:
    from ipa_diagnose.resolution import types as T
    from ipa_diagnose.resolution.checks import LiveRunner, ReplayRunner

    parser = build_parser()
    rest = _strip_command(argv)
    while "--no-ai" in rest:  # accepted everywhere else; replication mode never uses AI
        rest.remove("--no-ai")
    if "--ai-provider" in rest:
        parser.error("replication mode never uses an AI provider")
    args = parser.parse_args(rest)
    if args.replay is not None and not os.path.isdir(args.replay):
        parser.error("--replay needs a directory of recorded evidence")
    if args.peer is not None:
        peer = T.validate("fqdn", args.peer)
        if peer is None:
            parser.error("--peer must be a fully qualified host name (for example ipa02.example.test)")
        args.peer = peer
    from ipa_diagnose.replication.run import REPLAY_FIELD_LIMIT

    runner = (ReplayRunner(args.replay, filename="replication_checks.json", field_limit=REPLAY_FIELD_LIMIT)
              if args.replay else LiveRunner())
    is_root = _replay_root(args.replay) if args.replay else None
    from ipa_diagnose.replication import verify as V
    from ipa_diagnose.replication.output import render, to_dict
    from ipa_diagnose.replication.run import investigate

    path = V.state_path(bool(args.replay))
    previous = None
    if args.verify:
        try:
            previous = V.load(path)
        except V.UnreadableState:
            msg = ("The saved replication result exists but cannot be read (damaged or modified), so nothing can be "
                   "verified. Run ipa-diagnose replication to create a new one.")
            if args.json:
                print(json.dumps({"kind": "ipa-diagnose.replication.verify", "baseline_unreadable": True,
                                  "items": []}))
            else:
                Console(stderr=True, highlight=False).print(msg, markup=False)
            return 4
        if previous is not None and args.peer is None:
            args.peer = T.validate("fqdn", previous["inputs"].get("peer")) if previous["inputs"].get("peer") else None
    result = investigate(runner, peer=args.peer, is_root=is_root)
    fresh = EXIT[result.status]
    console = Console(highlight=False, emoji=False)
    if args.verify:
        if previous is None:
            if args.json:
                print(json.dumps({"kind": "ipa-diagnose.replication.verify", "previous_generated_at": None,
                                  "items": [], "current": to_dict(result)}, indent=2))
            else:
                console.print("No saved replication result to compare with: showing a fresh investigation.\n",
                              markup=False)
                render(result, console, details=args.details)
            V.save(path, V.to_state(result))
            return fresh
        cmp = V.compare(previous, result, runner)
        code = V.exit_code(cmp, fresh)
        if args.json:
            from ipa_diagnose.client.output import _c

            print(json.dumps(_c({"kind": "ipa-diagnose.replication.verify",
                                 "previous_generated_at": cmp["previous_generated_at"],
                                 "items": [{"key": i.key, "code": i.code, "subject": i.subject, "title": i.title,
                                            "outcome": i.outcome, "detail": i.detail, "recheck_after": i.recheck_after,
                                            "pending_since": i.pending_since} for i in cmp["items"]],
                                 "new_conditions": [{"key": d.key, "title": d.title} for d in cmp["new_conditions"]],
                                 "reverse_not_verified": cmp["reverse_not_verified"],
                                 "ruv_equality_required": False, "exit_code": code,
                                 "current": to_dict(result)}), indent=2))
        else:
            _render_verify(cmp, console)
            console.print()
            render(result, console, details=args.details)
        outs = {i.outcome for i in cmp["items"]}
        if "PENDING" in outs:
            # keep the baseline (and the time PENDING started, so the window stays bounded)
            raw = dict(previous["raw"], pending=cmp["pending"])
            V.save(path, raw)
        elif not outs & {"STILL_PRESENT", "PARTIALLY_RESOLVED", "UNABLE_TO_VERIFY", "CHANGED"}:
            V.save(path, V.to_state(result))
        return code
    if args.json:
        print(json.dumps(to_dict(result), indent=2))
    else:
        render(result, console, details=args.details)
    if result.status != "NOT_AN_IPA_SERVER":
        V.save(path, V.to_state(result))
    return fresh


def _render_verify(cmp, console: Console) -> None:
    from ipa_diagnose.client.output import _safe

    p = lambda t="", s=None: console.print(t, markup=False, soft_wrap=True, style=s)  # noqa: E731
    p(f"VERIFY (compared with the replication result of {_safe(cmp['previous_generated_at'], 40) or 'unknown'}; "
      "every check re-run now)", "bold")
    style = {"RESOLVED": "green", "STILL_PRESENT": "red", "PARTIALLY_RESOLVED": "yellow", "CHANGED": "yellow",
             "UNABLE_TO_VERIFY": "yellow", "PENDING": "yellow"}
    if not cmp["items"]:
        p("  Nothing was found last time.")
    for i in cmp["items"]:
        p(f"  {i.outcome:<18} (found last time) {_safe(i.title, 200)}: {_safe(i.detail, 400)}", style.get(i.outcome))
    for d in cmp["new_conditions"]:
        p(f"  {'NEW':<18} {_safe(d.title, 200)}", "red")
    if cmp["reverse_not_verified"]:
        p("  Not verified (not observable from here): " + ", ".join(_safe(x, 200) for x in cmp["reverse_not_verified"]),
          "yellow")
    p("  Exact RUV equality is not required; a fresh successful session after the saved result is.", "dim")
    p("  The VERIFY answer above is authoritative; below is the current state from this run.", "dim")


def _replay_root(fixture_dir: str) -> bool:
    import pathlib

    try:
        doc = json.loads((pathlib.Path(fixture_dir) / "meta.json").read_text(encoding="utf-8"))
        return doc.get("is_root") is not False if isinstance(doc, dict) else True
    except (OSError, ValueError):
        return True
