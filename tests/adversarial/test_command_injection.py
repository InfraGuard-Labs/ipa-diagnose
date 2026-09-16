"""Command-injection guardrails.

Every collector shells out via subprocess.run() with an argument LIST, never
a shell string - this means even attacker-influenced data (e.g. a hostname)
passed as one argv element can't break out into a second command, because
there is no shell parsing it. This test statically enforces that invariant
so a future collector can't accidentally reintroduce shell=True.
"""

import pathlib
import re

COLLECTORS_DIR = pathlib.Path(__file__).parent.parent.parent / "src" / "ipa_diagnose" / "evidence" / "collectors"


def test_no_collector_uses_shell_true():
    offenders = []
    for path in COLLECTORS_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"shell\s*=\s*True", text):
            offenders.append(path.name)
    assert not offenders, f"collectors using shell=True (command-injection risk): {offenders}"


def test_no_collector_uses_os_system_or_popen_string():
    offenders = []
    for path in COLLECTORS_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"os\.system\(|os\.popen\(", text):
            offenders.append(path.name)
    assert not offenders, f"collectors using os.system/os.popen (command-injection risk): {offenders}"
