"""Mechanical inventory of the checks in upstream freeipa-healthcheck.

Downloads the source tarball of each requested release from GitHub and, with the
`ast` module (no execution of upstream code, standard library only), extracts for
every check class registered with `@registry`:

  * source   - the `ipahealthcheck.<pkg>.<module>` a finding is reported under
  * check    - the class name (what `ipa-healthcheck` prints as "check")
  * levels   - the result levels the class can emit (constants.SUCCESS/WARNING/ERROR/CRITICAL)
  * kw       - the keyword-argument names passed to `Result(...)` (what `kw` may contain)
  * keys     - literal `key=` string values (the documented error codes, e.g. DSBLE0007)

Usage:
    python scripts/inventory_healthcheck.py OUT.json [TAG ...]   (default: every tag + master)

The result is the ground truth used by scripts/audit_healthcheck_coverage.py and
docs/healthcheck-coverage.md. It reads upstream source; it never runs it.
"""

from __future__ import annotations

import ast
import io
import json
import sys
import tarfile
import urllib.request

REPO = "freeipa/freeipa-healthcheck"
LEVELS = {"SUCCESS", "WARNING", "ERROR", "CRITICAL"}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ipa-diagnose-inventory"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https GitHub URLs
        return r.read()


def list_tags() -> list:
    data = json.loads(_get(f"https://api.github.com/repos/{REPO}/tags?per_page=100"))
    return [t["name"] for t in data]


def _is_registry(dec: ast.expr) -> bool:
    return (isinstance(dec, ast.Name) and dec.id == "registry") or (
        isinstance(dec, ast.Attribute) and dec.attr == "registry"
    )


def _level_of(node: ast.expr):
    # constants.ERROR / constants.WARNING / ...
    if isinstance(node, ast.Attribute) and node.attr in LEVELS:
        return node.attr
    if isinstance(node, ast.Name) and node.id in LEVELS:
        return node.id
    return None


def _analyse_class(cls: ast.ClassDef) -> dict:
    levels, kw, keys = set(), set(), set()
    for node in ast.walk(cls):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
            if name != "Result":
                continue
            if len(node.args) >= 2:
                lv = _level_of(node.args[1])
                if lv:
                    levels.add(lv)
            for k in node.keywords:
                if k.arg:
                    kw.add(k.arg)
                    if k.arg == "key" and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str):
                        keys.add(k.value.value)
    return {"levels": sorted(levels), "kw": sorted(kw), "keys": sorted(keys)}


def inventory_tarball(data: bytes) -> dict:
    checks = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile() or not m.name.endswith(".py"):
                continue
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if not rel.startswith("src/ipahealthcheck/"):
                continue
            module = rel[len("src/") : -3].replace("/", ".")
            if module.endswith(".__init__"):
                module = module[: -len(".__init__")]
            try:
                tree = ast.parse(tf.extractfile(m).read().decode("utf-8", "replace"))
            except SyntaxError:
                continue
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and any(_is_registry(d) for d in node.decorator_list):
                    info = _analyse_class(node)
                    info["module"] = module
                    checks[f"{module}.{node.name}"] = info
    return checks


def main(argv: list) -> int:
    out = argv[1] if len(argv) > 1 else "healthcheck_inventory.json"
    tags = argv[2:] or list_tags() + ["master"]
    result = {}
    for tag in tags:
        url = (
            f"https://github.com/{REPO}/archive/refs/heads/master.tar.gz"
            if tag == "master"
            else f"https://github.com/{REPO}/archive/refs/tags/{tag}.tar.gz"
        )
        try:
            result[tag] = inventory_tarball(_get(url))
            print(f"{tag}: {len(result[tag])} registered checks")
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"{tag}: FAILED {type(e).__name__}: {e}")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
