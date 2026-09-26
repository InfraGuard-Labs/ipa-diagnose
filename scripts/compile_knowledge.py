"""Compile knowledge/procedures/*.yaml into src/ipa_diagnose/resolution/procedures.json.

Build-time only (needs PyYAML, a dev dependency). The runtime reads the JSON and
never needs YAML. The loader is deliberately strict: it rejects YAML tags,
anchors/aliases and duplicate keys (a duplicated ``risk:`` would otherwise let a
reviewer see one value while the parser keeps another). The compiled catalogue
is validated with the same validator the runtime uses before it is written.

Usage:
    python scripts/compile_knowledge.py            # write the JSON
    python scripts/compile_knowledge.py --check    # fail if the JSON is out of date
"""

from __future__ import annotations

import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "knowledge" / "procedures"
OUT = ROOT / "src" / "ipa_diagnose" / "resolution" / "procedures.json"


class StrictLoader(yaml.SafeLoader):
    pass


def _no_alias(self, *args, **kwargs):  # noqa: ARG001
    raise yaml.constructor.ConstructorError(None, None, "anchors/aliases are not allowed in knowledge files")


def _mapping(loader, node, deep=False):
    keys = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in keys:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
        keys.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_file(path: pathlib.Path):
    text = path.read_text(encoding="utf-8")
    for event in yaml.parse(text, Loader=StrictLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise ValueError(f"{path.name}: anchors/aliases are not allowed")
        if isinstance(event, (yaml.ScalarEvent, yaml.MappingStartEvent, yaml.SequenceStartEvent)) and event.tag is not None:
            raise ValueError(f"{path.name}: explicit YAML tags are not allowed ({event.tag})")
    return yaml.load(text, Loader=StrictLoader)  # noqa: S506 - StrictLoader is a SafeLoader subclass


def compile_catalogue() -> str:
    sys.path.insert(0, str(ROOT / "src"))
    from ipa_diagnose.resolution.knowledge import validate_catalogue

    procedures = []
    for path in sorted(SRC_DIR.glob("*.yaml")):
        data = load_file(path)
        procedures.extend(data if isinstance(data, list) else [data])
    catalogue = {"schema": 1, "procedures": sorted(procedures, key=lambda p: p.get("id", ""))}
    validate_catalogue(catalogue)
    for p in procedures:  # provenance.tests must name regression tests that exist in this repository
        for t in (p.get("provenance") or {}).get("tests") or []:
            if not (ROOT / t).is_file():
                raise SystemExit(f"{p.get('id')}: provenance.tests names {t}, which does not exist")
    return json.dumps(catalogue, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv) -> int:
    text = compile_catalogue()
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("procedures.json is out of date: run scripts/compile_knowledge.py")
            return 1
        print("procedures.json is up to date")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(json.loads(text)['procedures'])} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
