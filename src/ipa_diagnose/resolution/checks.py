"""Closed registry of READ-ONLY checks the resolution engine may run automatically.

These are the only things the resolution framework ever executes. Every check:

* observes and never changes state (argv only, no shell, ``LC_ALL=C``, a fixed PATH);
* is bounded (timeout, output size) and never raises: failures become results;
* takes only typed, validated parameters (:mod:`ipa_diagnose.resolution.types`);
* sanitizes every string it returns (untrusted command output).

In ``--replay`` mode a :class:`ReplayRunner` answers from the fixture's
``resolution_checks.json`` instead; a check that was not recorded is ``NOT_RUN``,
which withholds any procedure that depends on it.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional

from ipa_diagnose.resolution import types as T
from ipa_diagnose.textsafe import sanitize_text

OK, FAILED, NOT_RUN, DENIED = "OK", "FAILED", "NOT_RUN", "DENIED"
_TIMEOUT = 10.0
_MAX_OUTPUT = 256 * 1024
_SAFE_ENV = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
_DIRSRV_ETC = pathlib.Path("/etc/dirsrv")


@dataclasses.dataclass
class CheckResult:
    check_id: str
    params: Dict[str, str]
    status: str
    fields: Dict[str, Any] = dataclasses.field(default_factory=dict)
    display: str = ""
    command: str = ""

    @property
    def ok(self) -> bool:
        return self.status == OK


@dataclasses.dataclass(frozen=True)
class CheckSpec:
    check_id: str
    params: Dict[str, str]
    """parameter name -> type name (types.VALIDATORS)."""
    describe: str
    run: Callable[[Dict[str, str]], CheckResult]


def _run(argv: List[str], timeout: float = _TIMEOUT) -> "tuple[Optional[int], str, str]":
    """Run argv (never a shell). Returns (returncode or None on timeout/error, stdout, stderr)."""

    if shutil.which(argv[0], path=_SAFE_ENV["PATH"]) is None:
        return None, "", f"{argv[0]}: not installed"
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv from a closed registry with validated parameters
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_SAFE_ENV, start_new_session=True, text=True, errors="replace",
        )
    except OSError as e:
        return None, "", f"{type(e).__name__}"
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            proc.kill()
        try:
            proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, ValueError):
            pass
        return None, "", f"timed out after {timeout:.0f}s"
    return proc.returncode, (out or "")[:_MAX_OUTPUT], (err or "")[:_MAX_OUTPUT]


def _res(check_id, params, status, fields=None, display="", command=""):
    return CheckResult(
        check_id=check_id, params=dict(params), status=status, fields=fields or {},
        display=sanitize_text(display, 240), command=sanitize_text(command, 240),
    )


# --------------------------------------------------------------------------- individual checks


def _privilege(params):
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    return _res("host.privilege", params, OK, {"is_root": is_root}, "running as root" if is_root else "not running as root",
                "(effective uid of this process)")


def _ds_instances() -> List[str]:
    try:
        entries = sorted(p.name for p in _DIRSRV_ETC.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return []
    out = []
    for name in entries:
        if name.startswith("slapd-") and not name.endswith(".removed"):
            inst = T.validate("ds_instance", name[len("slapd-"):])
            if inst:
                out.append(inst)
    return out


def _ds_instance(params):
    inst = _ds_instances()
    fields = {"count": len(inst), "instance": inst[0] if len(inst) == 1 else None}
    return _res("ds.instance", params, OK, fields,
                f"{len(inst)} Directory Server instance(s)" + (f": {inst[0]}" if len(inst) == 1 else ""),
                "ls /etc/dirsrv")


def _unit_for(service: str) -> "tuple[Optional[str], Optional[str]]":
    template, method = T.IPA_SERVICES[service]
    if "{instance}" in template:
        inst = _ds_instances()
        if len(inst) != 1:
            return None, method
        template = template.format(instance=inst[0])
    return T.validate("systemd_unit", template), method


def _systemd_unit(params):
    unit, method = _unit_for(params["service"])
    if unit is None:
        return _res("systemd.unit", params, FAILED, {}, "could not determine the systemd unit (Directory Server instance not unique)")
    argv = ["systemctl", "show", "--no-pager", "-p", "LoadState,ActiveState,SubState,UnitFileState,Result", unit]
    rc, out, err = _run(argv)
    if rc is None:
        return _res("systemd.unit", params, NOT_RUN, {}, err, shlex.join(argv))
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    fields = {
        "unit": unit, "start_method": method,
        "load_state": sanitize_text(props.get("LoadState", ""), 40),
        "active_state": sanitize_text(props.get("ActiveState", ""), 40),
        "sub_state": sanitize_text(props.get("SubState", ""), 40),
        "unit_file_state": sanitize_text(props.get("UnitFileState", ""), 40),
        "result": sanitize_text(props.get("Result", ""), 40),
    }
    if not fields["load_state"]:
        return _res("systemd.unit", params, FAILED, fields, "systemctl returned no unit state", shlex.join(argv))
    disp = f"{unit}: {fields['active_state']} ({fields['sub_state']})"
    if fields["result"] and fields["result"] != "success":
        disp += f", last result: {fields['result']}"
    if fields["load_state"] != "loaded":
        disp += f", load state: {fields['load_state']}"
    return _res("systemd.unit", params, OK, fields, disp, shlex.join(argv))


_LOG_SECRET = re.compile(
    r"(?i)(\b(?:pass(?:word|wd|phrase)?|pwd|secret|token|pin|api[_-]?key|credentials?)\b\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)")
_LOG_AUTH = re.compile(r"(?i)(\bauthorization\s*[:=]\s*)(?:basic|bearer|negotiate|digest)?\s*\S+")


def _redact_log_line(line: str) -> str:
    from ipa_diagnose.privacy.redact import redact_text

    line = _LOG_SECRET.sub(lambda m: m.group(1) + "[REDACTED:secret]", line)
    line = _LOG_AUTH.sub(lambda m: m.group(1) + "[REDACTED:authorization]", line)
    return redact_text(line).redacted_text


def _journal_tail(params):
    argv = ["journalctl", "--no-pager", "-o", "cat", "-n", "20", "-u", params["unit"]]
    rc, out, err = _run(argv)
    if rc is None:
        return _res("systemd.journal_tail", params, NOT_RUN, {}, err, shlex.join(argv))
    lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("-- ")]
    # Redact the whole line first (truncating first could shorten a secret below what the patterns recognise).
    last = sanitize_text(_redact_log_line(lines[-1][:4096]), 200) if lines else ""
    return _res("systemd.journal_tail", params, OK, {"lines": len(lines), "last_line": last},
                f"last log line: {last}" if last else "no recent log lines", shlex.join(argv))


CONTAINER_DATA_ROOT = "/data"


def _layout_ok(path: str) -> bool:
    """Every symlink met on the way to `path` (parents and the file itself) is a known PKI layout link leading
    exactly where it should, or a freeipa-container /data mirror of itself."""

    parts = [p for p in path.split("/") if p]
    for i in range(1, len(parts) + 1):
        prefix = "/" + "/".join(parts[:i])
        if not os.path.islink(prefix):
            continue
        real = os.path.realpath(prefix)
        known = T.IPA_LAYOUT_LINKS.get(prefix)
        if known is not None and real == os.path.realpath(known):
            continue
        if real == CONTAINER_DATA_ROOT + prefix:
            continue
        return False
    return True


def _command_target(real: str):
    """Path a command may act on for a file whose real location is `real`: (target, allowed, via_container_mirror).

    Allowed when the real file is itself in an IPA-managed location, or - the freeipa-container layout, where
    /etc/pki, /var/lib/ipa, ... are symlinks into the /data volume - when stripping /data gives an IPA-managed
    path that itself resolves to exactly this real file. Anything else resolves outside IPA and is refused.
    """

    if T.validate("ipa_path", real) is not None:
        return real, True, False
    root = CONTAINER_DATA_ROOT + "/"
    if real.startswith(root):
        standard = real[len(CONTAINER_DATA_ROOT):]
        if T.validate("ipa_path", standard) is not None and os.path.realpath(standard) == real:
            return standard, True, True
    return real, False, False


def _file_stat(params):
    path = params["path"]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return _res("file.stat", params, OK, {"exists": False}, f"{path}: does not exist", f"stat {path}")
    except OSError as e:
        return _res("file.stat", params, DENIED if isinstance(e, PermissionError) else FAILED, {}, f"{path}: {type(e).__name__}")
    import stat as _stat

    try:
        import grp
        import pwd

        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
    except (ImportError, KeyError):
        owner, group = f"uid:{st.st_uid}", f"gid:{st.st_gid}"
    real = os.path.realpath(path)
    target, allowed, mirror = _command_target(real)
    allowed = allowed and (_stat.S_ISLNK(st.st_mode) or _layout_ok(path))
    fields = {
        "exists": True, "is_symlink": _stat.S_ISLNK(st.st_mode), "is_regular": _stat.S_ISREG(st.st_mode),
        "is_dir": _stat.S_ISDIR(st.st_mode), "mode": "%04o" % (st.st_mode & 0o7777),
        # Real location (parent directories may be symlinks: on FreeIPA /var/lib/pki/pki-tomcat/conf -> /etc/pki/pki-tomcat).
        # Commands act on "target" (the real file, named by an IPA-managed path), and only if realpath_allowed.
        "canonical": real == path,
        "realpath": sanitize_text(real, 4096),
        "target": sanitize_text(target, 4096),
        "realpath_allowed": allowed,
        "container_data_mirror": mirror,
        "owner": sanitize_text(owner, 40), "group": sanitize_text(group, 40),
    }
    return _res("file.stat", params, OK, fields,
                f"{path}: mode {fields['mode']}, owner {fields['owner']}, group {fields['group']}", f"stat {path}")


def _account(kind):
    def run(params):
        name = params["name"]
        try:
            if kind == "user":
                import pwd

                pwd.getpwnam(name)
            else:
                import grp

                grp.getgrnam(name)
            exists = True
        except KeyError:
            exists = False
        except ImportError:
            return _res(f"account.{kind}", params, NOT_RUN, {}, "account database unavailable")
        return _res(f"account.{kind}", params, OK, {"exists": exists}, f"{kind} {name}: {'exists' if exists else 'does not exist'}")

    return run


_OFFSET_RE = re.compile(r"System time\s*:\s*([0-9.]+)\s+seconds\s+(fast|slow)", re.I)
_LEAP_RE = re.compile(r"Leap status\s*:\s*(.+)", re.I)
_REF_RE = re.compile(r"Reference ID\s*:\s*\S+\s*\(([^)]*)\)", re.I)


def _chrony_tracking(params):
    argv = ["chronyc", "-n", "tracking"]
    rc, out, err = _run(argv)
    if rc is None or rc != 0:
        return _res("chrony.tracking", params, NOT_RUN if rc is None else FAILED, {}, err.strip() or "chronyc failed", shlex.join(argv))
    m = _OFFSET_RE.search(out)
    leap = _LEAP_RE.search(out)
    ref = _REF_RE.search(out)
    if not m:
        return _res("chrony.tracking", params, FAILED, {}, "could not read the clock offset", shlex.join(argv))
    offset = float(m.group(1)) * (1 if m.group(2).lower() == "fast" else -1)
    leap_status = sanitize_text(leap.group(1).strip(), 40) if leap else ""
    fields = {"offset_seconds": offset, "offset_abs": round(abs(offset), 3),
              "direction": "ahead of" if offset >= 0 else "behind",
              "leap_status": leap_status, "synchronized": leap_status == "Normal",
              "reference": sanitize_text(ref.group(1), 80) if ref else ""}
    return _res("chrony.tracking", params, OK, fields,
                f"clock offset {offset:+.3f} s, leap status {leap_status or 'unknown'}", shlex.join(argv))


def _chrony_sources(params):
    argv = ["chronyc", "-n", "sources"]
    rc, out, err = _run(argv)
    if rc is None or rc != 0:
        return _res("chrony.sources", params, NOT_RUN if rc is None else FAILED, {}, err.strip() or "chronyc failed", shlex.join(argv))
    total = reachable = 0
    for line in out.splitlines():
        if len(line) > 2 and line[0] in "^=#" and line[1] in "*+-?x~ ":
            cols = line.split()
            if len(cols) >= 5:
                total += 1
                try:
                    if int(cols[4], 8) != 0:
                        reachable += 1
                except ValueError:
                    pass
    return _res("chrony.sources", params, OK, {"total": total, "reachable": reachable},
                f"{reachable} of {total} time source(s) reachable", shlex.join(argv))


def _days_left(not_after: str) -> Optional[int]:
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S %Z"):
        try:
            dt = datetime.datetime.strptime(not_after.strip(), fmt).replace(tzinfo=datetime.timezone.utc)
            return int((dt - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 86400)
        except ValueError:
            continue
    return None


def _certmonger_ds_cert(params):
    from ipa_diagnose.evidence.collectors.certmonger import _parse_getcert_list

    nssdb = f"/etc/dirsrv/slapd-{params['instance']}"
    argv = ["getcert", "list", "-d", nssdb, "-n", params["nickname"]]
    rc, out, err = _run(argv, timeout=15.0)
    if rc is None:
        return _res("certmonger.ds_cert", params, NOT_RUN, {}, err, shlex.join(argv))
    reqs = _parse_getcert_list(out)
    if not reqs:
        return _res("certmonger.ds_cert", params, OK, {"found": False}, "certmonger does not track this certificate", shlex.join(argv))
    if len(reqs) > 1:
        return _res("certmonger.ds_cert", params, FAILED, {"found": True, "count": len(reqs)}, "more than one tracking request", shlex.join(argv))
    r = reqs[0]
    request_id = T.validate("certmonger_request_id", r.get("request_id"))
    not_after = sanitize_text(r.get("not_valid_after", ""), 40)
    post_save = str(r.get("post_save", ""))
    fields = {
        "found": True, "request_id": request_id, "state": sanitize_text(r.get("state", ""), 40),
        "ca": sanitize_text(r.get("ca", ""), 40), "ca_error": sanitize_text(r.get("ca_error", ""), 200),
        "not_after": not_after, "days_left": _days_left(not_after),
        "post_save_restarts_dirsrv": "restart_dirsrv" in post_save,
    }
    return _res("certmonger.ds_cert", params, OK, fields,
                f"request {request_id}: {fields['state']}, CA {fields['ca'] or '?'}, expires {not_after or '?'}", shlex.join(argv))


_BINARIES = {"ipactl", "chronyc", "getcert", "systemctl"}


def _binary(params):
    name = params["name"]
    if name not in _BINARIES:
        return _res("binary.present", params, FAILED, {}, "not an allowed binary")
    present = shutil.which(name, path=_SAFE_ENV["PATH"]) is not None
    return _res("binary.present", params, OK, {"present": present}, f"{name}: {'installed' if present else 'not installed'}")


REGISTRY: Dict[str, CheckSpec] = {
    s.check_id: s
    for s in [
        CheckSpec("host.privilege", {}, "whether ipa-diagnose runs as root", _privilege),
        CheckSpec("ds.instance", {}, "Directory Server instances on this host", _ds_instance),
        CheckSpec("systemd.unit", {"service": "ipa_service"}, "systemd state of a service", _systemd_unit),
        CheckSpec("systemd.journal_tail", {"unit": "systemd_unit"}, "recent log lines of a unit", _journal_tail),
        CheckSpec("file.stat", {"path": "ipa_path"}, "owner, group and mode of a file", _file_stat),
        CheckSpec("account.user", {"name": "posix_name"}, "whether a local user exists", _account("user")),
        CheckSpec("account.group", {"name": "posix_name"}, "whether a local group exists", _account("group")),
        CheckSpec("chrony.tracking", {}, "this host's clock offset (chronyc tracking)", _chrony_tracking),
        CheckSpec("chrony.sources", {}, "reachable time sources (chronyc sources)", _chrony_sources),
        CheckSpec("certmonger.ds_cert", {"instance": "ds_instance", "nickname": "cert_nickname"},
                  "certmonger tracking of a Directory Server certificate", _certmonger_ds_cert),
        CheckSpec("binary.present", {"name": "posix_name"}, "whether a tool is installed", _binary),
    ]
}


def _key(check_id: str, params: Dict[str, str]) -> str:
    return check_id + "|" + ",".join(f"{k}={params[k]}" for k in sorted(params))


def _validated_params(spec: CheckSpec, params: Dict[str, Any]) -> Optional[Dict[str, str]]:
    if set(params) != set(spec.params):
        return None
    out = {}
    for name, type_name in spec.params.items():
        v = T.validate(type_name, params[name])
        if v is None:
            return None
        out[name] = v
    return out


class Runner:
    """Runs registry checks once per (check, params) - results are cached for the run."""

    replay = False

    def __init__(self) -> None:
        self._cache: Dict[str, CheckResult] = {}
        self.runs = 0

    def run(self, check_id: str, params: Dict[str, Any]) -> CheckResult:
        spec = REGISTRY.get(check_id)
        if spec is None:
            return _res(check_id, {}, FAILED, {}, "unknown check")
        vp = _validated_params(spec, params)
        if vp is None:
            return _res(check_id, {}, FAILED, {}, "parameters did not validate")
        key = _key(check_id, vp)
        if key not in self._cache:
            self.runs += 1
            self._cache[key] = self._execute(spec, vp)
        return self._cache[key]

    def _execute(self, spec: CheckSpec, params: Dict[str, str]) -> CheckResult:
        start = time.monotonic()
        try:
            result = spec.run(params)
        except Exception as e:  # noqa: BLE001 - a check must never crash the run
            result = _res(spec.check_id, params, FAILED, {}, f"check failed: {type(e).__name__}")
        result.fields.setdefault("_duration_s", round(time.monotonic() - start, 3))
        return result


class LiveRunner(Runner):
    pass


class ReplayRunner(Runner):
    """Answers from ``resolution_checks.json`` in a replay fixture directory."""

    replay = True

    def __init__(self, fixture_dir: Optional[str]) -> None:
        super().__init__()
        self._data: Dict[str, Any] = {}
        if fixture_dir:
            p = pathlib.Path(fixture_dir) / "resolution_checks.json"
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._data = raw
            except (OSError, ValueError, RecursionError):
                self._data = {}

    def _execute(self, spec: CheckSpec, params: Dict[str, str]) -> CheckResult:
        entry = self._data.get(_key(spec.check_id, params))
        if not isinstance(entry, dict):
            return _res(spec.check_id, params, NOT_RUN, {}, "not recorded in this replay fixture")
        fields = entry.get("fields") if isinstance(entry.get("fields"), dict) else {}
        fields = {str(k): (sanitize_text(v, 240) if isinstance(v, str) else v) for k, v in fields.items()}
        if "not_after_in_days" in fields and isinstance(fields["not_after_in_days"], int):
            fields["days_left"] = fields.pop("not_after_in_days")
        status = entry.get("status") if entry.get("status") in (OK, FAILED, NOT_RUN, DENIED) else FAILED
        return _res(spec.check_id, params, status, fields, str(entry.get("display", "")), str(entry.get("command", "")))
