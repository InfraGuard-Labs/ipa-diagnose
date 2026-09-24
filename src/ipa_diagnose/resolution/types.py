"""Typed values that may appear in a printed command or a check parameter.

Every value that reaches a command line (``argv``) or a read-only check comes
from evidence that is *untrusted* (ipa-healthcheck output, command output). It
is accepted only if it validates as one of these types; anything else makes the
procedure withheld. There is no free-text type.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, Optional, Tuple

# ipa-healthcheck meta.services name -> (systemd unit template, how it is started).
# Only services whose start procedure is deterministic are listed. ipa-otpd is
# socket-activated and deliberately absent.
IPA_SERVICES: Dict[str, Tuple[str, str]] = {
    "dirsrv": ("dirsrv@{instance}.service", "ipactl"),
    "krb5kdc": ("krb5kdc.service", "ipactl"),
    "kadmin": ("kadmin.service", "ipactl"),
    "httpd": ("httpd.service", "ipactl"),
    "ipa-custodia": ("ipa-custodia.service", "ipactl"),
    "pki-tomcatd": ("pki-tomcatd@pki-tomcat.service", "ipactl"),
    "named": ("named.service", "ipactl"),
    "named-pkcs11": ("named-pkcs11.service", "ipactl"),
    "ipa-dnskeysyncd": ("ipa-dnskeysyncd.service", "ipactl"),
    "certmonger": ("certmonger.service", "systemctl"),
    "sssd": ("sssd.service", "systemctl"),
    "chronyd": ("chronyd.service", "systemctl"),
    "gssproxy": ("gssproxy.service", "systemctl"),
}

# File locations an IPA file-permission procedure may touch (ipa-healthcheck's
# IPAFileCheck / IPAFileNSSDBCheck / TomcatFileCheck only check paths under these).
IPA_PATH_PREFIXES = ("/etc/", "/var/lib/", "/var/log/", "/var/named/", "/var/kerberos/", "/usr/share/ipa/")

_PATH_RE = re.compile(r"^/[A-Za-z0-9._@+/-]{1,4095}$")
_MODE_RE = re.compile(r"^0[0-7]{3}$")
_POSIX_NAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
_NICKNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,126}\.service$")


def _ipa_service(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and v in IPA_SERVICES else None


def _abs_path(v: Any) -> Optional[str]:
    if not isinstance(v, str) or not _PATH_RE.fullmatch(v):
        return None
    if os.path.normpath(v) != v or "//" in v or "/../" in v or v.endswith("/..") or "/./" in v:
        return None
    if not v.startswith(IPA_PATH_PREFIXES):
        return None
    return v


def _mode(v: Any) -> Optional[str]:
    if isinstance(v, str) and len(v) == 3 and v.isdigit():
        v = "0" + v
    return v if isinstance(v, str) and _MODE_RE.fullmatch(v) else None


def _posix_name(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _POSIX_NAME_RE.fullmatch(v) else None


def _nickname(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _NICKNAME_RE.fullmatch(v) and not v.endswith(" ") else None


def _request_id(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _REQUEST_ID_RE.fullmatch(v) and not v.startswith("-") else None


def _instance(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _INSTANCE_RE.fullmatch(v) else None


def _unit(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _UNIT_RE.fullmatch(v) else None


def _perm_type(v: Any) -> Optional[str]:
    return v if v in ("mode", "owner", "group") else None


VALIDATORS: Dict[str, Callable[[Any], Optional[str]]] = {
    "ipa_service": _ipa_service,
    "ipa_path": _abs_path,
    "file_mode": _mode,
    "posix_name": _posix_name,
    "cert_nickname": _nickname,
    "certmonger_request_id": _request_id,
    "ds_instance": _instance,
    "systemd_unit": _unit,
    "permission_type": _perm_type,
}


def validate(type_name: str, value: Any) -> Optional[str]:
    """The validated (canonical) value, or None if it is not a safe value of that type."""

    fn = VALIDATORS.get(type_name)
    return fn(value) if fn else None
