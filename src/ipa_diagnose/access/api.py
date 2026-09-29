"""Read-only access to the FreeIPA API for `ipa-diagnose access`.

LIVE: JSON-RPC over HTTPS to the IPA server named in /etc/ipa/default.conf, authenticated with the CALLER's own
Kerberos ticket (``curl --negotiate``; FreeIPA clients and servers ship curl). The request body goes to curl on stdin
as JSON; the targets are JSON string values, so nothing is ever interpolated into a shell, a URL or an LDAP filter.
No root, no LDAPI, no host keytab: the answer is what the caller's own identity may read.

REPLAY: the same calls answered from a recorded ``access_api.json`` in a fixture directory. A call that was not
recorded is an explicit "not recorded" failure (never an empty success), so replay can never invent evidence.

Only these read-only API commands are ever sent (``ALLOWED_METHODS``); anything else is refused before it leaves.
"""

from __future__ import annotations

import configparser
import dataclasses
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from ipa_diagnose.textsafe import sanitize_text

ALLOWED_METHODS = frozenset({
    "user_show", "host_show", "hbacsvc_show", "hbacrule_show", "group_show", "hostgroup_show", "hbactest", "ping",
})
DEFAULT_CONF = "/etc/ipa/default.conf"
DEFAULT_CA = "/etc/ipa/ca.crt"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


@dataclasses.dataclass
class ApiError:
    kind: str
    """``api`` (FreeIPA answered with an error), ``not_found`` (FreeIPA's NotFound), ``denied`` (ACI/authorization),
    ``auth`` (no usable Kerberos ticket), ``unavailable`` (no server/curl/config), ``timeout``, ``malformed``,
    ``budget`` (call budget exhausted), ``not_recorded`` (replay has no answer)."""
    message: str
    name: Optional[str] = None
    code: Optional[int] = None


@dataclasses.dataclass
class ApiResponse:
    method: str
    args: List[str]
    result: Any = None
    error: Optional[ApiError] = None
    messages: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def entry(self) -> Dict[str, Any]:
        """The object of a *_show command (``result.result``), or {} when there is none."""
        inner = self.result.get("result") if isinstance(self.result, dict) else None
        return inner if isinstance(inner, dict) else {}


@dataclasses.dataclass
class ApiContext:
    mode: str  # LIVE | REPLAY
    server: Optional[str] = None
    domain: Optional[str] = None
    realm: Optional[str] = None
    principal: Optional[str] = None
    """The identity the server saw (JSON-RPC ``principal``): whose view of the directory the answer is."""
    api_version: Optional[str] = None
    unavailable: Optional[str] = None
    """Set when no API call can be made at all (no configuration, no curl, no ticket...)."""


def _clean(text: Any, limit: int = 300) -> str:
    return sanitize_text(text, limit)


def _error_kind(name: Optional[str], code: Optional[int]) -> str:
    if name == "NotFound" or code == 4001:
        return "not_found"
    if name in ("ACIError", "AuthorizationError") or code in (2100, 2101):
        return "denied"
    return "api"


def _from_jsonrpc(method: str, args: List[str], doc: Any, seconds: float) -> ApiResponse:
    if not isinstance(doc, dict):
        return ApiResponse(method, args, error=ApiError("malformed", "the API answer is not a JSON object"),
                           seconds=seconds)
    err = doc.get("error")
    if err:
        if not isinstance(err, dict):
            return ApiResponse(method, args, error=ApiError("malformed", "the API error is not a JSON object"),
                               seconds=seconds)
        name = err.get("name") if isinstance(err.get("name"), str) else None
        code = err.get("code") if isinstance(err.get("code"), int) and not isinstance(err.get("code"), bool) else None
        return ApiResponse(method, args, seconds=seconds, error=ApiError(
            _error_kind(name, code), _clean(err.get("message", "error"), 300), _clean(name or "", 60) or None, code))
    result = doc.get("result")
    if not isinstance(result, dict):
        return ApiResponse(method, args, error=ApiError("malformed", "the API answer has no result object"),
                           seconds=seconds)
    msgs = result.get("messages") if isinstance(result.get("messages"), list) else []
    # The command's whole output: for *_show commands the entry is under "result"; hbactest's verdict is at the top.
    return ApiResponse(method, args, result=result, seconds=seconds, messages=[m for m in msgs if isinstance(m, dict)])


class Api:
    """Common budget handling. Subclasses implement ``_call``."""

    def __init__(self, context: ApiContext, max_calls: int = 60, deadline_seconds: float = 120.0):
        self.context = context
        self.max_calls = max_calls
        self.calls_made = 0
        self.deadline_seconds = deadline_seconds
        self._deadline: Optional[float] = None  # starts with the first call, not at construction (a bundle builds
        # its diagnosis first, which can take minutes)
        self.log: List[ApiResponse] = []

    def call(self, method: str, args: Optional[List[str]] = None, options: Optional[Dict[str, Any]] = None) -> ApiResponse:
        args = list(args or [])
        if method not in ALLOWED_METHODS:
            raise ValueError(f"refusing a non-allowlisted API method: {method}")
        if not all(isinstance(a, str) for a in args):
            raise ValueError("API arguments must be strings")
        if self.context.unavailable:
            resp = ApiResponse(method, args, error=ApiError("unavailable", self.context.unavailable))
        elif self.calls_made >= self.max_calls or (
                self._deadline is not None and time.monotonic() > self._deadline):
            resp = ApiResponse(method, args, error=ApiError("budget", "the API call or time budget was used up"))
        else:
            if self._deadline is None:
                self._deadline = time.monotonic() + self.deadline_seconds
            self.calls_made += 1
            resp = self._call(method, args, dict(options or {}))
        self.log.append(resp)
        return resp

    def _call(self, method: str, args: List[str], options: Dict[str, Any]) -> ApiResponse:  # pragma: no cover
        raise NotImplementedError


# ---------------------------------------------------------------- LIVE


def read_ipa_conf(path: str = DEFAULT_CONF) -> Dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as f:
            parser.read_file(f)
    except (OSError, configparser.Error, UnicodeDecodeError):
        return {}
    if not parser.has_section("global"):
        return {}
    return {k: v.strip() for k, v in parser.items("global") if k in ("server", "xmlrpc_uri", "domain", "realm", "host")}


def _server_from_conf(conf: Dict[str, str]) -> Optional[str]:
    host = None
    uri = conf.get("xmlrpc_uri")
    if uri:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme == "https" and parsed.hostname:
            host = parsed.hostname
    host = host or conf.get("server")
    if host and _HOST_RE.fullmatch(host) and len(host) <= 253:
        return host.lower()
    return None


def _curl_has_negotiate(curl: str) -> bool:
    try:
        proc = subprocess.run([curl, "-V"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    features = " ".join(line for line in proc.stdout.splitlines() if line.lower().startswith("features"))
    return any(f in features.split() for f in ("SPNEGO", "GSS-API", "Kerberos"))


def _has_ticket(env: Optional[Dict[str, str]] = None) -> Optional[bool]:
    klist = shutil.which("klist")
    if klist is None:
        return None
    try:
        return subprocess.run([klist, "-s"], capture_output=True, timeout=5, check=False, env=env).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None


class LiveApi(Api):
    TIMEOUT = 20

    def __init__(self, conf_path: str = DEFAULT_CONF, ca_path: str = DEFAULT_CA, ccache: Optional[str] = None, **kw):
        # ccache: a private credential cache (client mode uses one filled from the host keytab); None = the caller's
        if ccache:  # a minimal environment, as for kinit: root's own proxy, trace or key-log variables do not apply
            from ipa_diagnose.resolution.checks import _SAFE_ENV

            self._env = dict(_SAFE_ENV, KRB5CCNAME=ccache)
        else:
            self._env = None
        conf = read_ipa_conf(conf_path)
        ctx = ApiContext(mode="LIVE", server=_server_from_conf(conf), domain=(conf.get("domain") or "").lower() or None,
                         realm=conf.get("realm") or None)
        self._curl = shutil.which("curl")
        self._ca = ca_path
        if not conf:
            ctx.unavailable = f"{conf_path} is missing or unreadable: this host is not an IPA server or client"
        elif ctx.server is None:
            ctx.unavailable = f"no usable IPA server name in {conf_path}"
        elif self._curl is None:
            ctx.unavailable = "curl is not installed, so the IPA API cannot be reached"
        elif not os.path.isfile(ca_path):
            ctx.unavailable = f"the IPA CA certificate {ca_path} is missing"
        elif not _curl_has_negotiate(self._curl):
            ctx.unavailable = "this curl cannot do Kerberos (SPNEGO) authentication"
        elif _has_ticket(self._env) is False:
            ctx.unavailable = ("no valid Kerberos ticket: run kinit as the IPA user whose view should be used "
                               "(for example: kinit admin), then run this again")
        super().__init__(ctx, **kw)

    def _call(self, method: str, args: List[str], options: Dict[str, Any]) -> ApiResponse:
        url = f"https://{self.context.server}/ipa/json"
        body = json.dumps({"method": method, "params": [args, options], "id": 0})
        # -q first: never read ~/.curlrc (it could add --insecure, a proxy or a trace file); HTTPS only; bounded size
        argv = [self._curl, "-q", "--proto", "=https", "--max-filesize", str(MAX_RESPONSE_BYTES),
                "--silent", "--show-error", "--negotiate", "--user", ":", "--cacert", self._ca,
                "--max-time", str(self.TIMEOUT), "--header", "Content-Type: application/json",
                "--header", "Accept: application/json", "--header", f"Referer: https://{self.context.server}/ipa",
                "--data-binary", "@-", "--write-out", "\n%{http_code}", url]
        start = time.monotonic()
        try:
            proc = subprocess.run(argv, input=body.encode("utf-8"), capture_output=True, timeout=self.TIMEOUT + 5,
                                  check=False, env=getattr(self, "_env", None))
        except subprocess.TimeoutExpired:
            return ApiResponse(method, args, error=ApiError("timeout", f"no answer within {self.TIMEOUT} s"),
                               seconds=time.monotonic() - start)
        except OSError as e:
            return ApiResponse(method, args, error=ApiError("unavailable", _clean(e)), seconds=time.monotonic() - start)
        seconds = time.monotonic() - start
        if proc.returncode == 28:
            return ApiResponse(method, args, error=ApiError("timeout", f"no answer within {self.TIMEOUT} s"),
                               seconds=seconds)
        if proc.returncode != 0:
            return ApiResponse(method, args, seconds=seconds, error=ApiError(
                "unavailable", f"curl exit {proc.returncode}: {_clean(proc.stderr.decode('utf-8', 'replace'), 200)}"))
        out = proc.stdout
        if len(out) > MAX_RESPONSE_BYTES:
            return ApiResponse(method, args, error=ApiError("malformed", "the API answer is too large"), seconds=seconds)
        text = out.decode("utf-8", "replace")
        body_text, _, status = text.rpartition("\n")
        if status.strip() == "401":
            return ApiResponse(method, args, seconds=seconds, error=ApiError(
                "auth", "the IPA server did not accept the Kerberos ticket (expired, or for another realm): run kinit"))
        if status.strip() != "200":
            return ApiResponse(method, args, seconds=seconds,
                               error=ApiError("unavailable", f"the IPA server answered HTTP {_clean(status, 10)}"))
        try:
            doc = json.loads(body_text)
        except (ValueError, RecursionError):
            return ApiResponse(method, args, error=ApiError("malformed", "the API answer is not JSON"), seconds=seconds)
        if isinstance(doc, dict):
            if isinstance(doc.get("principal"), str) and self.context.principal is None:
                self.context.principal = _clean(doc["principal"], 200)
            if isinstance(doc.get("version"), str) and self.context.api_version is None:
                self.context.api_version = _clean(doc["version"], 40)
        return _from_jsonrpc(method, args, doc, seconds)


# ---------------------------------------------------------------- REPLAY

REPLAY_FILE = "access_api.json"


_KEYED_OPTIONS = {"hbactest": ("user", "targethost", "service")}


def call_key(method: str, args: List[str], options: Optional[Dict[str, Any]] = None) -> str:
    """Replay key: the method and its arguments, plus - for hbactest - the exact user, host and service asked,
    so a replay can never answer a different (for example uncanonicalized) request."""

    keyed = {k: str((options or {}).get(k, "")) for k in _KEYED_OPTIONS.get(method, ())}
    return json.dumps([method, [a.lower() for a in args], keyed], sort_keys=True)


class ReplayApi(Api):
    """Answers recorded calls. The file is untrusted input: every value is validated where it is used."""

    def __init__(self, fixture_dir: str, **kw):
        path = pathlib.Path(fixture_dir) / REPLAY_FILE
        ctx = ApiContext(mode="REPLAY")
        self._answers: Dict[str, Any] = {}
        try:
            if path.stat().st_size > MAX_RESPONSE_BYTES:
                raise ValueError("too large")
            doc = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("not an object")
        except FileNotFoundError:
            ctx.unavailable = f"the replay directory has no recorded {REPLAY_FILE}"
            doc = {}
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            ctx.unavailable = f"the recorded {REPLAY_FILE} is unreadable or malformed"
            doc = {}
        meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}

        def s(key: str, limit: int = 200) -> Optional[str]:
            v = meta.get(key)
            return _clean(v, limit) if isinstance(v, str) and v else None

        ctx.server, ctx.principal, ctx.api_version = s("server"), s("principal"), s("api_version", 40)
        ctx.domain = (s("domain") or "").lower() or None
        ctx.realm = s("realm")
        if s("unavailable") and not ctx.unavailable:
            ctx.unavailable = s("unavailable")
        calls = doc.get("calls") if isinstance(doc.get("calls"), list) else []
        for c in calls:
            if not isinstance(c, dict) or not isinstance(c.get("method"), str):
                continue
            args = c.get("args") if isinstance(c.get("args"), list) else []
            if not all(isinstance(a, str) for a in args):
                continue
            opts = c.get("options") if isinstance(c.get("options"), dict) else {}
            self._answers[call_key(c["method"], args, opts)] = c
        super().__init__(ctx, **kw)

    def _call(self, method: str, args: List[str], options: Dict[str, Any]) -> ApiResponse:
        rec = self._answers.get(call_key(method, args, options))
        if rec is None:
            return ApiResponse(method, args, error=ApiError("not_recorded", "this call was not recorded in the replay"))
        if isinstance(rec.get("transport_error"), dict):
            te = rec["transport_error"]
            kind = te.get("kind") if te.get("kind") in ("auth", "unavailable", "timeout", "malformed") else "unavailable"
            return ApiResponse(method, args, error=ApiError(kind, _clean(te.get("message", kind), 300)))
        return _from_jsonrpc(method, args, rec.get("response"), 0.0)


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
