"""`ipa-diagnose bundle` - create, preview or validate a support bundle.

    ipa-diagnose bundle [--output PATH] [--replay DIR] [--json]    create a bundle (nothing is uploaded)
    ipa-diagnose bundle --access USER HOST SERVICE [...]           also include one access answer (access.json)
    ipa-diagnose bundle --preview [--replay DIR] [--json]         show what a bundle would contain; write nothing
    ipa-diagnose bundle validate BUNDLE [--json]                  check a bundle without extracting it

Exit codes: 0 done; 5 the bundle was not created (leak self-test, output path or size limit) or is not valid;
2 usage error; 70 internal error; 130 interrupted. Bundle commands never change the saved verify baseline.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
from typing import Any, Dict, List

from rich.console import Console

from ipa_diagnose.textsafe import sanitize_text

REFUSED = 5
_REVIEW = ("Before sharing, review it. It is pseudonymized and credential-scanned, but it still contains operational "
           "detail (service names, versions, error text, timestamps, topology shape).")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipa-diagnose bundle",
        description="Create a sanitized, pseudonymized support bundle from a fresh diagnosis, preview one, or "
        "validate a received one. Nothing is ever uploaded.",
    )
    p.add_argument("action", nargs="?", choices=["validate"], help="validate: check a bundle file (no extraction)")
    p.add_argument("bundle", nargs="?", metavar="BUNDLE", help="the bundle file to validate")
    p.add_argument("--preview", action="store_true", help="show what the bundle would contain; write nothing")
    p.add_argument("-o", "--output", metavar="PATH",
                   help="file to create (never overwritten), or a directory for the default file name "
                   "(default: ./ipa-diagnose-bundle-<UTC time>.tar.gz)")
    p.add_argument("--replay", metavar="FIXTURE_DIR", default=None,
                   help="build from a recorded fixture directory instead of the live host (marked REPLAY)")
    p.add_argument("--access", nargs=3, metavar=("USER", "HOST", "SERVICE"), default=None,
                   help="also include the answer of ipa-diagnose access USER HOST SERVICE (pseudonymized)")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    return p


def _strip_command(argv: List[str]) -> List[str]:
    out, skip, done = [], 0, False
    for i, a in enumerate(argv):
        if skip:
            skip -= 1
            out.append(a)
            continue
        if not done and a == "bundle":
            done = True
            continue
        if a == "--access":  # USER HOST SERVICE are values even when one of them is spelled "bundle"
            skip = 3
        elif a in ("--replay", "--ai-provider", "--output", "-o"):
            skip = 1
        out.append(a)
    return out


def run(argv: List[str]) -> int:
    parser = build_parser()
    rest = _strip_command(argv)
    for flag in ("--details", "--no-ai"):  # accepted everywhere else; meaningless here but harmless
        while flag in rest:
            rest.remove(flag)
    if "--ai-provider" in rest:
        parser.error("a support bundle never uses an AI provider")
    args = parser.parse_intermixed_args(rest)
    console = Console(highlight=False)
    err = Console(stderr=True, highlight=False)
    if args.action == "validate":
        if not args.bundle:
            parser.error("validate needs the bundle file to check")
        if args.preview or args.output or args.replay or args.access:
            parser.error("validate takes only a bundle file (and --json)")
        return _validate(args, console)
    if args.bundle:
        parser.error(f"unexpected argument {args.bundle!r}")
    if args.access:
        from ipa_diagnose.access.api import LiveApi, ReplayApi
        from ipa_diagnose.access.targets import TargetError, parse_targets

        if args.replay is not None and not os.path.isdir(args.replay):
            parser.error("--replay needs a directory of recorded evidence")
        args.access_api = ReplayApi(args.replay) if args.replay else LiveApi()
        try:
            args.access_targets = parse_targets(*args.access, args.access_api.context.domain,
                                                args.access_api.context.realm)
        except TargetError as e:
            parser.error(sanitize_text(str(e), 300))
    if args.preview and args.output:
        parser.error("--preview writes nothing, so --output does not apply")
    if args.replay is not None and not os.path.isdir(args.replay):
        # a bundle of nothing would be labelled correctly but is useless; say so instead
        return _refused(args, console, f"the replay directory {sanitize_text(args.replay, 200)!r} does not exist",
                        ["--replay needs a directory of recorded evidence (for example tests/fixtures/...)"])
    if os.name != "nt" and args.replay is None and os.geteuid() != 0:
        err.print("[yellow]Warning: not running as root - live evidence collection will likely be incomplete, and "
                  "the bundle will say so.[/yellow]\n")
    return _create(args, console, err)


def _forbidden(args: argparse.Namespace) -> List[str]:
    out = []
    if args.replay:
        out += [args.replay, os.path.abspath(args.replay)]
    home = os.path.expanduser("~")
    if home not in ("/", "/root", "~") and len(home) >= 4:
        out.append(home)
    return out


def _create(args: argparse.Namespace, console: Console, err: Console) -> int:
    from ipa_diagnose.bundle import archive, selftest
    from ipa_diagnose.bundle.build import EXCLUDED_CLASSES, BundleTooLarge, build
    from ipa_diagnose.cli import _collect_and_diagnose, _state_path
    from ipa_diagnose.verify import load_previous_report

    evidence, report = _collect_and_diagnose(args)
    previous = load_previous_report(_state_path(args))  # read-only; bundles never save a baseline
    try:
        built = build(evidence, report, previous=previous, access=_access_answer(args))
        selftest.check(built.members, built.sanitizer.originals(), _forbidden(args), built.sanitizer.secret_values)
    except selftest.LeakDetected as e:
        return _refused(args, console, "the leak self-test found content that must not leave this host",
                        [f"{m}: {c}" for m, c in e.problems])
    except BundleTooLarge as e:
        return _refused(args, console, "the bundle would exceed its size limits", [str(e)])
    created_at = built.manifest["created_at"]
    data = archive.make_archive(built.members, created_at)
    info = _summary(built, report)
    if args.preview:
        return _show_preview(args, console, built, info, len(data), EXCLUDED_CLASSES)
    path = archive.resolve_output(args.output, created_at)
    try:
        archive.write_new_file(path, data)
    except archive.OutputRefused as e:
        return _refused(args, console, "the output file was not created", [str(e)])
    except OSError as e:  # read-only filesystem, no permission, disk full: nothing was left behind
        return _refused(args, console, "the output file was not created", [f"{path}: {e.strerror or type(e).__name__}"])
    import hashlib

    digest = hashlib.sha256(data).hexdigest()
    if args.json:
        print(json.dumps(dict(info, created=True, path=str(path), bytes=len(data), sha256=digest), indent=2))
        return 0
    console.print(f"Support bundle written: {path}", markup=False, soft_wrap=True)
    console.print(f"  {len(data) / 1024:.1f} KiB, file mode 0600, SHA-256 {digest}", markup=False, soft_wrap=True)
    _print_summary(console, info)
    console.print()
    console.print(_REVIEW + " Nothing was uploaded; the file is not encrypted, so share it over a channel you trust.",
                  markup=False, soft_wrap=True)
    console.print(f"  List the files:  tar -tzf {path}", markup=False, soft_wrap=True)
    console.print(f"  Read one:        tar -xzOf {path} ipa-diagnose-bundle/report.json | less", markup=False, soft_wrap=True)
    console.print(f"  Check it:        ipa-diagnose bundle validate {path}", markup=False, soft_wrap=True)
    if os.name != "nt" and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        console.print("  The file belongs to root (created with sudo); copy it with sudo to share it.", markup=False, soft_wrap=True)
    return 0


def _access_answer(args: argparse.Namespace):
    """The `ipa-diagnose access` answer for --access USER HOST SERVICE, from the same source (LIVE or the same
    replay directory) as the rest of the bundle; None when not asked for. The targets were validated in run()."""

    if not args.access:
        return None
    from ipa_diagnose.access.evaluate import diagnose

    user, host, service = args.access
    return diagnose(args.access_api, args.access_targets, {"user": user, "host": host, "service": service})


def _summary(built, report) -> Dict[str, Any]:
    return {
        "source_mode": built.source_mode,
        "host": built.local_host,
        "overall_status": report.overall_status.value,
        "evidence_completeness": report.evidence_completeness.level,
        "counts": built.counts,
        "pseudonymized_identifiers": built.privacy["pseudonymized_identifiers"],
        "redacted_values": built.privacy["redacted_values"],
        "secret_named_fields_removed": built.privacy["secret_named_fields_removed"],
        "raw_output_fields_dropped": built.privacy["raw_output_fields_dropped"],
        "truncation": built.privacy["truncation"],
        "content_complete": built.manifest["content_complete"],
        "access_included": "access.json" in built.members,
        "leak_self_test": "passed",
    }


def _fmt(counts: Dict[str, int]) -> str:
    return ", ".join(f"{k.lower()} {v}" for k, v in counts.items()) or "none"


def _print_summary(console: Console, info: Dict[str, Any]) -> None:
    mode = ("LIVE diagnosis of this host" if info["source_mode"] == "LIVE" else
            "REPLAY of a recorded fixture (describes no live system)")
    console.print(f"  Source: {mode}, shown as {info['host'] or 'HOST-001'}; overall status {info['overall_status']}, "
                  f"evidence {info['evidence_completeness']}", markup=False, soft_wrap=True)
    c = info["counts"]
    console.print(f"  Contents: {c['diagnoses']} diagnoses, {c['resolutions']} resolutions, "
                  f"{c['undiagnosed_findings']} undiagnosed findings, {c['healthcheck_problems']} ipa-healthcheck "
                  f"problems ({c['healthcheck_findings']} results), {c['evidence_items']} evidence items, "
                  f"{c['collection_errors']} collection errors", markup=False, soft_wrap=True)
    console.print(f"  Pseudonymized: {_fmt(info['pseudonymized_identifiers'])}", markup=False, soft_wrap=True)
    red = sum(info["redacted_values"].values())
    cats = ", ".join(sorted(info["redacted_values"])) if red else ""
    console.print(f"  Redacted: {red} value(s){' (' + cats + ')' if cats else ''}; secret-named fields removed: "
                  f"{info['secret_named_fields_removed']}; raw output fields dropped: {info['raw_output_fields_dropped']}",
                  markup=False, soft_wrap=True)
    t = info["truncation"]
    if not info["content_complete"]:
        console.print(f"  Shortened to stay within limits: {t['strings_truncated']} text(s) truncated, "
                      f"{t['strings_omitted_as_too_large']} omitted as too large, entries dropped "
                      f"{t['entries_dropped_by_limits'] or 'none'}", markup=False, soft_wrap=True)
    if info.get("access_included"):
        console.print("  Access answer: included (access.json, pseudonymized, no commands)", markup=False,
                      soft_wrap=True)
    console.print("  Leak self-test: passed", markup=False, soft_wrap=True)


def _show_preview(args, console: Console, built, info: Dict[str, Any], size: int, excluded) -> int:
    members = [{"name": n, "bytes": len(d)} for n, d in built.members.items()]
    if args.json:
        print(json.dumps(dict(info, preview=True, written=False, estimated_bytes=size, members=members,
                              excluded_by_design=list(excluded)), indent=2))
        return 0
    console.print("Support bundle preview - nothing was written", markup=False, soft_wrap=True)
    _print_summary(console, info)
    console.print(f"  Estimated size: {size / 1024:.1f} KiB compressed", markup=False, soft_wrap=True)
    console.print("  Files:", markup=False, soft_wrap=True)
    for m in members:
        console.print(f"    {m['name']:<24} {m['bytes'] / 1024:8.1f} KiB", markup=False, soft_wrap=True)
    console.print("  Never included: " + "; ".join(excluded), markup=False, soft_wrap=True)
    console.print(_REVIEW, markup=False, soft_wrap=True)
    console.print("Create it with: ipa-diagnose bundle" + (f" --replay {args.replay}" if args.replay else "")
                  + " [--output PATH]", markup=False, soft_wrap=True)
    return 0


def _refused(args, console: Console, reason: str, problems: List[str]) -> int:
    if args.json:
        print(json.dumps({"created": False, "reason": reason, "problems": problems}, indent=2))
        return REFUSED
    console.print(f"No bundle was created: {reason}.", markup=False, soft_wrap=True)
    for p in problems:
        console.print(f"  - {sanitize_text(p, 300)}", markup=False, soft_wrap=True)
    console.print("Nothing was written.", markup=False, soft_wrap=True)
    return REFUSED


def _validate(args, console: Console) -> int:
    from ipa_diagnose.bundle.archive import validate

    v = validate(args.bundle)
    summary = {k: (sanitize_text(val, 80) if isinstance(val, str) else val) for k, val in v.summary.items()}
    if args.json:
        print(json.dumps({"valid": v.valid, "problems": v.problems, "warnings": v.warnings, "summary": summary,
                          "note": "Structure, checksum and content-pattern checks only. Checksums are not a signature; "
                                  "the content is recorded evidence from another system, never a live diagnosis."},
                         indent=2))
        return 0 if v.valid else REFUSED
    name = sanitize_text(pathlib.Path(args.bundle).name, 120)
    console.print(f"{name}: {'VALID' if v.valid else 'NOT VALID'}", markup=False, soft_wrap=True)
    for p in v.problems:
        console.print(f"  problem: {sanitize_text(p, 300)}", markup=False, soft_wrap=True)
    for w in v.warnings:
        console.print(f"  warning: {sanitize_text(w, 300)}", markup=False, soft_wrap=True)
    if summary:
        console.print(f"  created {summary.get('created_at')} by ipa-diagnose {summary.get('ipa_diagnose_version')}, "
                      f"source {summary.get('source_mode')}, overall status {summary.get('overall_status')}, "
                      f"evidence {summary.get('evidence_completeness')}", markup=False, soft_wrap=True)
    console.print("This checks structure, checksums and credential patterns only. Checksums are not a signature. The "
                  "content is recorded evidence of the system and time it was created on - never a live diagnosis of "
                  "this machine, and never something to run.", markup=False, soft_wrap=True)
    return 0 if v.valid else REFUSED
