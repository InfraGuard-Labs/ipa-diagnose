"""Best-effort environment/version metadata collection.

This is safety context for --details/--json, not a compatibility engine:
ipa-diagnose does not branch its diagnostic logic on any of these values. It
exists because real FreeIPA generations differ (RHEL 8-era ipa-healthcheck
0.12 lacks checks that RHEL 9/10/Fedora's 0.19+ has), and knowing which
generation produced a given report makes both UNKNOWN outcomes and bug
reports meaningfully easier to reason about.

Every individual detection step is independently best-effort: a failure to
read /etc/os-release, run `rpm`, or find a binary never raises past this
module - it just leaves that one field None. Detecting the environment must
never be a reason a diagnosis fails to run.
"""

from __future__ import annotations

import json
import pathlib
import platform
import re
import shutil
import subprocess
from typing import Optional

from ipa_diagnose.evidence.model import EnvironmentInfo

_OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")
_RPM_TIMEOUT_SECONDS = 5.0


def detect_environment(*, fixture_path: Optional[pathlib.Path]) -> EnvironmentInfo:
    if fixture_path is not None:
        return _detect_from_fixture(fixture_path)
    return _detect_live()


def _detect_from_fixture(fixture_path: pathlib.Path) -> EnvironmentInfo:
    meta_file = fixture_path / "meta.json"
    env_data = {}
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if isinstance(meta, dict) and isinstance(meta.get("environment"), dict):
                env_data = meta["environment"]
        except (OSError, ValueError):
            env_data = {}
    return EnvironmentInfo(
        distro=env_data.get("distro"),
        distro_version=env_data.get("distro_version"),
        python_version=env_data.get("python_version"),
        freeipa_version=env_data.get("freeipa_version"),
        ipa_healthcheck_version=env_data.get("ipa_healthcheck_version"),
        directory_server_version=env_data.get("directory_server_version"),
        detected_live=False,
    )


def _detect_live() -> EnvironmentInfo:
    distro, distro_version = _read_os_release()
    return EnvironmentInfo(
        distro=distro,
        distro_version=distro_version,
        python_version=_safe(platform.python_version),
        freeipa_version=_rpm_version("freeipa-server"),
        ipa_healthcheck_version=_rpm_version("freeipa-healthcheck"),
        directory_server_version=_rpm_version("389-ds-base"),
        detected_live=True,
    )


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


_OS_RELEASE_LINE_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|(.*))$')


def _read_os_release() -> "tuple[Optional[str], Optional[str]]":
    for path in _OS_RELEASE_PATHS:
        p = pathlib.Path(path)
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        values = {}
        for line in text.splitlines():
            m = _OS_RELEASE_LINE_RE.match(line.strip())
            if m:
                key = m.group(1)
                value = m.group(2) if m.group(2) is not None else m.group(3)
                values[key] = value
        distro_id = values.get("ID")
        version_id = values.get("VERSION_ID")
        if distro_id or version_id:
            return distro_id, version_id
    return None, None


def _rpm_version(package: str) -> Optional[str]:
    if shutil.which("rpm") is None:
        return None
    try:
        proc = subprocess.run(
            ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", package],
            capture_output=True,
            text=True,
            timeout=_RPM_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    version = (proc.stdout or "").strip()
    return version or None
