"""Deterministic discriminators for a replication agreement's status (389 Directory Server).

389-DS records the outcome of an agreement's last session in ``nsds5replicaLastUpdateStatus`` (text) and, on
current versions, ``nsds5replicaLastUpdateStatusJSON``. The text has three shapes (389-ds-base,
``agmt_set_last_update_status``)::

    Error (0) Replica acquired successfully: Incremental update succeeded
    Error (<ldap rc>) Problem connecting to replica - LDAP error: <ldap error text> (<more>)
    Error (<repl rc>) Replication error acquiring replica: <message> (<protocol response text>)

and the initial ``Error (0) No replication sessions started since server startup``. The JSON form carries
``state`` (green / amber / red), ``ldap_rc``, ``repl_rc`` and ``message``.

The classes below are CLOSED. Each is decided by an explicit rule over the numeric codes first and then by
anchored phrases 389-DS, the Kerberos library or the SASL GSSAPI plugin write (not by loose keyword search).
Anything else is ``UNCLASSIFIED``: it is reported as it is and never promoted to a root cause.

The same phrase table classifies the error of ipa-diagnose's own GSSAPI test bind (``classify_bind_error``), so the
agreement's error and a fresh reproduction can be compared.
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Any, Dict, Optional, Tuple

from ipa_diagnose.textsafe import sanitize_text

# ---------------------------------------------------------------- closed classes

OK = "OK"
NO_SESSIONS = "NO_SESSIONS"
TRANSPORT = "TRANSPORT"                  # the peer did not answer at the network/LDAP level
TLS = "TLS"                              # the TLS layer of the connection failed
GSSAPI_SERVER_NOT_FOUND = "GSSAPI_SERVER_NOT_FOUND"  # the KDC has no ldap/<peer> service principal
GSSAPI_CLOCK_SKEW = "GSSAPI_CLOCK_SKEW"
GSSAPI_NO_KDC = "GSSAPI_NO_KDC"          # the supplier's Kerberos library reached no KDC
GSSAPI_CREDENTIALS = "GSSAPI_CREDENTIALS"  # the supplier has no usable credentials (keytab, key, principal)
GSSAPI_OTHER = "GSSAPI_OTHER"            # a GSSAPI failure none of the above explains
INVALID_CREDENTIALS = "INVALID_CREDENTIALS"  # LDAP 49
INSUFFICIENT_ACCESS = "INSUFFICIENT_ACCESS"  # LDAP 50 / replication "permission denied"
BUSY = "BUSY"                            # the consumer is being updated by another supplier
BACKOFF = "BACKOFF"                      # a transient error; the supplier backs off and retries by itself
CHANGELOG_PURGED = "CHANGELOG_PURGED"    # the changes the consumer needs are no longer in the changelog
GENERATION_MISMATCH = "GENERATION_MISMATCH"  # the consumer holds a different database generation
REPLICA_ID_CONFLICT = "REPLICA_ID_CONFLICT"
ADMIN_ACTION = "ADMIN_ACTION"            # 389-DS says the replica must be (re)initialized or similar
UNCLASSIFIED = "UNCLASSIFIED"

CLASSES = (OK, NO_SESSIONS, TRANSPORT, TLS, GSSAPI_SERVER_NOT_FOUND, GSSAPI_CLOCK_SKEW, GSSAPI_NO_KDC,
           GSSAPI_CREDENTIALS, GSSAPI_OTHER, INVALID_CREDENTIALS, INSUFFICIENT_ACCESS, BUSY, BACKOFF,
           CHANGELOG_PURGED, GENERATION_MISMATCH, REPLICA_ID_CONFLICT, ADMIN_ACTION, UNCLASSIFIED)

# transient: the supplier retries by itself; never a root cause on its own, never green either
TRANSIENT = (BUSY, BACKOFF, NO_SESSIONS)
# the replica's DATA needs an administrator (re-initialization and similar): ipa-diagnose never prints that fix
NEEDS_ADMIN = (CHANGELOG_PURGED, GENERATION_MISMATCH, REPLICA_ID_CONFLICT, ADMIN_ACTION)
GSSAPI = (GSSAPI_SERVER_NOT_FOUND, GSSAPI_CLOCK_SKEW, GSSAPI_NO_KDC, GSSAPI_CREDENTIALS, GSSAPI_OTHER)

# ---------------------------------------------------------------- phrase table (ordered: first match wins)
# Kerberos / GSSAPI minor-status texts come first: they appear INSIDE an LDAP -2 / 49 error and are more specific.
_PHRASES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    (GSSAPI_SERVER_NOT_FOUND, re.compile(r"(?i)server (?:\S{1,300} )?not found in kerberos database")),
    (GSSAPI_CLOCK_SKEW, re.compile(r"(?i)clock skew too great")),
    (GSSAPI_NO_KDC, re.compile(r"(?i)cannot contact any kdc|cannot find kdc for realm|unable to reach any kdc")),
    (GSSAPI_CREDENTIALS, re.compile(
        r"(?i)keytab contains no suitable keys|no key table entry found|key table entry not found|"
        r"preauthentication failed|password incorrect|client (?:\S{1,300} )?not found in kerberos database|"
        r"no kerberos credentials available|no credentials cache found|credentials cache file .{0,200} not found|"
        r"ticket expired|client'?s? credentials have been revoked|key version number for principal in key "
        r"table is incorrect|decrypt integrity check failed")),
    (GSSAPI_OTHER, re.compile(r"(?i)gssapi (?:error|failure)|unspecified gss failure|sasl\(-1\): generic failure")),
    (CHANGELOG_PURGED, re.compile(r"(?i)purged from the changelog|changelog (?:has been )?purged|"
                                  r"below (?:the )?purge ?point|csn below purge point")),
    (GENERATION_MISMATCH, re.compile(r"(?i)different (?:database )?generation id|generation id mismatch|"
                                     r"different data version")),
    (REPLICA_ID_CONFLICT, re.compile(r"(?i)duplicate replica id")),
    (ADMIN_ACTION, re.compile(r"(?i)(?:must|needs? to|should) be (?:re-?)?initiali[sz]ed|"
                              r"requires? (?:a )?(?:re-?)?initiali[sz]ation")),
    (BUSY, re.compile(r"(?i)replica busy|currently being updated by another supplier|can't acquire busy replica")),
    (BACKOFF, re.compile(r"(?i)\bbacking off\b|\bbackoff\b|transient error")),
    (INSUFFICIENT_ACCESS, re.compile(r"(?i)insufficient access|permission denied|does not have permission")),
    (INVALID_CREDENTIALS, re.compile(r"(?i)invalid credentials")),
    (TLS, re.compile(r"(?i)tls (?:negotiation|handshake|error)|ssl (?:handshake|error)|certificate verify failed|"
                     r"peer's certificate|tls: hostname does not match|unable to get local issuer")),
    (TRANSPORT, re.compile(r"(?i)can'?t contact ldap server|server is unavailable|connect(?:ion)? (?:error|refused)|"
                           r"timed out|timeout|server down|no route to host|network is unreachable")),
)

# LDAP result codes (OpenLDAP numbering; 389-DS reports the client library's code for connection failures)
_LDAP_RC = {
    -1: TRANSPORT, 81: TRANSPORT, 91: TRANSPORT, -11: TRANSPORT, -5: TRANSPORT, 85: TRANSPORT, 51: BUSY,
    49: INVALID_CREDENTIALS, 50: INSUFFICIENT_ACCESS,
}
_NO_SESSIONS = re.compile(r"(?i)no replication sessions started")
_SUCCESS = re.compile(r"(?i)replica acquired successfully|incremental update succeeded|incremental update has succeeded|"
                      r"total update succeeded|replication session successful")
_TEXT = re.compile(r"^\s*Error\s*\((-?\d{1,6})\)\s*(.*)$", re.S)


@dataclasses.dataclass(frozen=True)
class AgreementStatus:
    cls: str
    ldap_rc: Optional[int]
    repl_rc: Optional[int]
    state: str
    """green / amber / red from 389-DS JSON, or '' when only the text form exists."""
    message: str
    source: str
    """json | text | none"""

    @property
    def ok(self) -> bool:
        return self.cls == OK


def classify_text(text: str) -> str:
    """The closed class of an error text by its phrases (UNCLASSIFIED when nothing matches)."""

    t = (text or "")[:4096]
    for cls, rx in _PHRASES:
        if rx.search(t):
            return cls
    return UNCLASSIFIED


def _int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and re.fullmatch(r"-?\d{1,6}", v.strip()):
        return int(v.strip())
    return None


def parse_status(text: Optional[str], json_text: Optional[str] = None) -> AgreementStatus:
    """Classify an agreement's last update status. Never raises; malformed input is UNCLASSIFIED."""

    ldap_rc = repl_rc = None
    state = ""
    message = ""
    source = "none"
    if json_text:
        try:
            doc = json.loads(json_text[:8192])
        except (ValueError, RecursionError):
            doc = None
        if isinstance(doc, dict):
            source = "json"
            state = str(doc.get("state", ""))[:10].lower()
            ldap_rc, repl_rc = _int(doc.get("ldap_rc")), _int(doc.get("repl_rc"))
            message = " ".join(str(doc.get(k, "")) for k in ("message", "ldap_rc_text", "repl_rc_text"))
    if source == "none" and text:
        m = _TEXT.match(text[:4096])
        source = "text"
        message = text[:4096]
        if m:
            code = int(m.group(1))
            body = m.group(2)
            if "problem connecting to replica" in body.lower():
                ldap_rc = code
            elif "replication error acquiring replica" in body.lower():
                repl_rc = code
            elif code == 0:
                ldap_rc, repl_rc = 0, 0
            else:
                ldap_rc = code  # an unknown shape: the number is kept, the phrases decide below
    msg = sanitize_text(message, 600)
    if source == "none":
        return AgreementStatus(UNCLASSIFIED, None, None, "", "", "none")
    if _NO_SESSIONS.search(message):
        return AgreementStatus(NO_SESSIONS, ldap_rc, repl_rc, state, msg, source)
    phrase = classify_text(message)
    if (ldap_rc in (0, None) and repl_rc in (0, None) and phrase in (UNCLASSIFIED, OK)
            and (_SUCCESS.search(message) or state == "green")):
        return AgreementStatus(OK, ldap_rc, repl_rc, state, msg, source)
    if phrase != UNCLASSIFIED:
        return AgreementStatus(phrase, ldap_rc, repl_rc, state, msg, source)
    if ldap_rc in _LDAP_RC:
        return AgreementStatus(_LDAP_RC[ldap_rc], ldap_rc, repl_rc, state, msg, source)
    if ldap_rc == -2:  # "Local error": the client side (SASL/GSSAPI) failed without a recognizable detail
        return AgreementStatus(GSSAPI_OTHER, ldap_rc, repl_rc, state, msg, source)
    return AgreementStatus(UNCLASSIFIED, ldap_rc, repl_rc, state, msg, source)


def classify_bind_error(stderr: str, rc: Optional[int]) -> str:
    """The class of a failed ldapwhoami/ldapsearch (ipa-diagnose's own reproduction of the supplier's bind)."""

    phrase = classify_text(stderr)
    if phrase != UNCLASSIFIED:
        return phrase
    m = re.search(r"\((-?\d{1,4})\)", stderr or "")
    code = int(m.group(1)) if m else None
    if code in _LDAP_RC:
        return _LDAP_RC[code]
    if code == -2:
        return GSSAPI_OTHER
    if rc == 255:
        return TRANSPORT
    return UNCLASSIFIED


# Plain-language meaning of each class (what the evidence says, never more).
MEANING: Dict[str, str] = {
    OK: "the last session succeeded",
    NO_SESSIONS: "no replication session has run since the Directory Server started (not proof of health)",
    TRANSPORT: "the supplier could not connect to the consumer's Directory Server",
    TLS: "the TLS layer of the connection to the consumer failed",
    GSSAPI_SERVER_NOT_FOUND: "the KDC has no service principal for the consumer's LDAP server",
    GSSAPI_CLOCK_SKEW: "Kerberos refused the exchange because the clocks are too far apart",
    GSSAPI_NO_KDC: "the supplier's Kerberos library could not reach a KDC",
    GSSAPI_CREDENTIALS: "the supplier has no usable Kerberos credentials for its LDAP service principal",
    GSSAPI_OTHER: "the GSSAPI (Kerberos) bind failed without a recognizable reason",
    INVALID_CREDENTIALS: "the consumer rejected the supplier's credentials (LDAP 49)",
    INSUFFICIENT_ACCESS: "the consumer does not let the supplier's identity send updates (LDAP 50 / permission "
                         "denied)",
    BUSY: "the consumer was busy with another supplier (transient)",
    BACKOFF: "a transient error; the supplier backs off and retries by itself",
    CHANGELOG_PURGED: "the changes the consumer needs are no longer in the supplier's changelog",
    GENERATION_MISMATCH: "the consumer holds a different database generation than the supplier",
    REPLICA_ID_CONFLICT: "two servers use the same replica ID",
    ADMIN_ACTION: "389-DS reports the consumer needs administrator action (for example re-initialization)",
    UNCLASSIFIED: "an error ipa-diagnose does not recognize",
}
