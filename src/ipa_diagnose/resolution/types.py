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
    "ipa-dnskeysyncd": ("ipa-dnskeysyncd.service", "ipactl"),
    "certmonger": ("certmonger.service", "systemctl"),
    "sssd": ("sssd.service", "systemctl"),
    "chronyd": ("chronyd.service", "systemctl"),
    "gssproxy": ("gssproxy.service", "systemctl"),
}

# File locations an IPA file-permission procedure may touch: the IPA/PKI/389-DS/Kerberos/DNS locations
# ipa-healthcheck's IPAFileCheck / IPAFileNSSDBCheck / TomcatFileCheck verify. Anything else (for example
# /etc/shadow) never gets a printed command, whatever a healthcheck result says.
IPA_PATH_PREFIXES = (
    "/etc/ipa/", "/etc/pki/pki-tomcat/", "/var/lib/pki/", "/etc/dirsrv/", "/var/lib/ipa/",
    "/var/log/dirsrv/", "/var/log/pki/", "/var/log/httpd/", "/var/log/ipa/",
    "/etc/httpd/", "/var/named/", "/var/kerberos/krb5kdc/", "/etc/sssd/", "/etc/gssproxy/", "/usr/share/ipa/",
)
IPA_PATH_EXACT = ("/etc/named.conf", "/etc/named.keytab", "/etc/krb5.keytab", "/etc/krb5.conf",
                  "/var/log/krb5kdc.log", "/var/log/kadmind.log", "/var/log/ipaserver-install.log",
                  "/var/log/ipareplica-install.log", "/var/log/ipaclient-install.log", "/var/log/ipaupgrade.log")
# The only directory symlinks a file-permission fix may pass through: the ones PKI creates itself (link ->
# where it must lead). Any other symlink in the path (for example a service account swapping one of its
# directories for a link into another component) withholds the fix.
IPA_LAYOUT_LINKS = {
    "/var/lib/pki/pki-tomcat/conf": "/etc/pki/pki-tomcat",
    "/var/lib/pki/pki-tomcat/logs": "/var/log/pki/pki-tomcat",
    "/var/lib/pki/pki-tomcat/alias": "/etc/pki/pki-tomcat/alias",
    "/etc/pki/pki-tomcat/alias": "/var/lib/pki/pki-tomcat/alias",
    "/var/lib/pki/pki-tomcat/ca/conf": "/etc/pki/pki-tomcat/ca",
    "/var/lib/pki/pki-tomcat/ca/logs": "/var/log/pki/pki-tomcat/ca",
    "/var/lib/pki/pki-tomcat/ca/alias": "/var/lib/pki/pki-tomcat/alias",
    "/var/lib/pki/pki-tomcat/kra/conf": "/etc/pki/pki-tomcat/kra",
    "/var/lib/pki/pki-tomcat/kra/logs": "/var/log/pki/pki-tomcat/kra",
    "/var/lib/pki/pki-tomcat/kra/alias": "/var/lib/pki/pki-tomcat/alias",
}
# Which IPA component a location belongs to. A file-permission fix for a reported path may only act on a real
# file of the same component (so no chain of links can turn a PKI finding into a command on a DS file).
IPA_COMPONENTS = {
    "pki": ("/etc/pki/pki-tomcat/", "/var/lib/pki/", "/var/log/pki/"),
    "dirsrv": ("/etc/dirsrv/", "/var/log/dirsrv/"),
    "ipa": ("/etc/ipa/", "/var/lib/ipa/", "/var/log/ipa/", "/usr/share/ipa/", "/var/log/ipaserver-install.log",
            "/var/log/ipareplica-install.log", "/var/log/ipaclient-install.log", "/var/log/ipaupgrade.log"),
    "httpd": ("/etc/httpd/", "/var/log/httpd/"),
    "named": ("/var/named/", "/etc/named.conf", "/etc/named.keytab"),
    "kerberos": ("/var/kerberos/krb5kdc/", "/etc/krb5.keytab", "/etc/krb5.conf", "/var/log/krb5kdc.log",
                 "/var/log/kadmind.log"),
    "sssd": ("/etc/sssd/",),
    "gssproxy": ("/etc/gssproxy/",),
}
# Accounts ipa-healthcheck's file checks expect as owner/group (service accounts of IPA components).
IPA_ACCOUNTS = frozenset({"root", "dirsrv", "pkiuser", "named", "apache", "ipaapi", "kdcproxy", "sssd", "ods", "gssproxy"})

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
    if not (v.startswith(IPA_PATH_PREFIXES) or v in IPA_PATH_EXACT):
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


def _ipa_account(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and v in IPA_ACCOUNTS else None


_CHMOD_REMOVE_RE = re.compile(r"^[ugo]-[rwx]{1,3}(,[ugo]-[rwx]{1,3}){0,2}$")
_CHMOD_ADD_RE = re.compile(r"^[ugo]\+[rwx]{1,3}(,[ugo]\+[rwx]{1,3}){0,2}$")


def _chmod_remove(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _CHMOD_REMOVE_RE.fullmatch(v) else None


def _chmod_add(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and _CHMOD_ADD_RE.fullmatch(v) else None


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
    "ipa_account": _ipa_account,
    "chmod_remove": _chmod_remove,
    "chmod_add": _chmod_add,
}


def validate(type_name: str, value: Any) -> Optional[str]:
    """The validated (canonical) value, or None if it is not a safe value of that type."""

    fn = VALIDATORS.get(type_name)
    return fn(value) if fn else None
