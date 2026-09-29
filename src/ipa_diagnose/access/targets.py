"""Validation of the three targets an administrator types: USER, HOST, SERVICE.

They reach the FreeIPA API only as JSON string values (never a shell or an LDAP filter), but they are still checked
here, so that a mistyped or hostile argument is refused with a clear message instead of being evaluated:

- ``all`` is refused for every target: FreeIPA's hbactest treats the literal value ``all`` as "skip this side".
- USER is an IPA user name. ``name@DOMAIN`` / ``DOMAIN\\name`` forms are recognized as trusted-domain (AD) identities,
  which this version does not evaluate (reported as UNKNOWN, never guessed).
- HOST is a DNS host name; a short name gets the IPA domain appended, exactly as hbactest itself does.
- SERVICE is the PAM service name that SSSD maps to an HBAC service (``sshd``, ``login``, ``sudo``...), never a
  Kerberos service principal such as ``host/app.example.com``.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Optional

from ipa_diagnose.textsafe import sanitize_text

# IPA's own user-name pattern (ipaserver/plugins/baseuser.py PATTERN_GROUPUSER_NAME), without the length bound.
_USER_RE = re.compile(r"^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*[a-zA-Z0-9_.$-]?$")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
_NETBIOS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
_MAX_USER = 255
_SID_RE = re.compile(r"^S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}-\d{1,10}$", re.IGNORECASE)
SID_DOMAIN = "(SID)"


class TargetError(ValueError):
    """A target the command refuses to evaluate; the message is safe to print."""


@dataclasses.dataclass(frozen=True)
class Targets:
    user: str
    host: str
    service: str
    user_domain: Optional[str] = None
    """Set when USER was written as a trusted-domain identity (name@DOMAIN or DOMAIN\\name) of another domain."""
    host_completed: bool = False
    """True when HOST was a short name and the IPA domain was appended (as hbactest does)."""
    trusted_form: Optional[str] = None
    """A trusted-domain identity exactly as typed (name@domain, DOMAIN\\name or a SID): shown and printed as is."""

    @property
    def display_user(self) -> str:
        if self.trusted_form:
            return self.trusted_form
        if self.user_domain is None or self.user_domain == SID_DOMAIN:
            return self.user
        return f"{self.user}@{self.user_domain}"


def _show(value: str) -> str:
    return repr(sanitize_text(value, 80))


def parse_user(raw: str, ipa_domain: Optional[str], ipa_realm: Optional[str]) -> "tuple[str, Optional[str]]":
    """(name, trusted_domain or None)."""

    if not isinstance(raw, str) or not raw or len(raw) > _MAX_USER:
        raise TargetError("USER must be an IPA user name (1-255 characters)")
    if _SID_RE.fullmatch(raw):  # a trusted-domain security identifier, as hbactest accepts it
        return raw.upper(), SID_DOMAIN
    name, domain = raw, None
    if "\\" in raw:
        domain, _, name = raw.partition("\\")
        if not _NETBIOS_RE.fullmatch(domain):
            raise TargetError(f"USER {_show(raw)} is not a valid DOMAIN\\name identity")
    elif raw.count("@") == 1:
        name, _, domain = raw.partition("@")
        if not _DOMAIN_RE.fullmatch(domain):
            raise TargetError(f"USER {_show(raw)} is not a valid name@domain identity")
    if not name or not _USER_RE.fullmatch(name) or name.lower() == "all":
        raise TargetError(f"USER {_show(raw)} is not a valid IPA user name")
    if domain is not None:
        own = {d.lower() for d in (ipa_domain, ipa_realm) if d}
        if domain.lower() in own:
            domain = None  # the IPA domain's own users written with their realm: an ordinary IPA user
    return name, domain


def parse_host(raw: str, ipa_domain: Optional[str]) -> "tuple[str, bool]":
    if not isinstance(raw, str) or not raw:
        raise TargetError("HOST must be a host name")
    host = raw[:-1] if raw.endswith(".") else raw
    if len(host) > 253 or not _HOST_RE.fullmatch(host) or host.lower() == "all":
        raise TargetError(f"HOST {_show(raw)} is not a valid host name")
    completed = False
    if "." not in host:
        if not ipa_domain:
            raise TargetError(f"HOST {_show(raw)} is a short name and the IPA domain is not known; use the full name")
        host, completed = f"{host}.{ipa_domain}", True
    return host.lower(), completed


def parse_service(raw: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise TargetError("SERVICE must be a PAM/HBAC service name such as sshd")
    if "/" in raw or "@" in raw:
        raise TargetError(f"SERVICE {_show(raw)} looks like a Kerberos principal; give the PAM/HBAC service name "
                          "(for example sshd, login or sudo)")
    if not _SERVICE_RE.fullmatch(raw) or raw.lower() == "all":
        raise TargetError(f"SERVICE {_show(raw)} is not a valid PAM/HBAC service name")
    return raw


def parse_targets(user: str, host: str, service: str, ipa_domain: Optional[str],
                  ipa_realm: Optional[str]) -> Targets:
    name, domain = parse_user(user, ipa_domain, ipa_realm)
    h, completed = parse_host(host, ipa_domain)
    return Targets(user=name, host=h, service=parse_service(service), user_domain=domain, host_completed=completed,
                   trusted_form=(name if domain == SID_DOMAIN else user) if domain else None)
