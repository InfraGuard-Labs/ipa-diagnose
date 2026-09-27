"""Support-bundle sanitization.

Every string (and every mapping key) that goes into a bundle member passes through the same steps, in this order:

    clean (escapes, control/format characters, NFKC)  ->  redact secrets  ->  pseudonymize identities
    ->  bound (truncate)

Redaction always runs on the full, untruncated text, so truncation can never cut a secret marker in half and hide
the rest. Text too large to process safely is omitted entirely, never cut first and redacted afterwards.

Pseudonyms are bundle-local and sequential (HOST-001, HOST-002, ...), assigned in a fixed discovery order. They are
not derived from the real value (no hash, no salt), so they cannot be reversed by guessing, and two different real
values can never share a pseudonym. HOST-001 is always the host the bundle was created on. The mapping is kept in
memory only and is never written anywhere.

Secret detection is pattern-based and cannot be complete; the bundle's first line of defence is that it never
collects secret material at all (see build.py). This module is the second line, and the leak self-test
(selftest.py) the third.
"""

from __future__ import annotations

import collections
import ipaddress
import re
import time
import unicodedata
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

TEXT_LIMIT = 500
PROSE_LIMIT = 2000
KEY_LIMIT = 120
HARD_LIMIT = 65536
MAX_DICT_KEYS = 60
MAX_LIST_ITEMS = 200
MAX_DEPTH = 8

PROSE_KEYS = frozenset({
    "why", "impact", "limitations", "rationale", "description", "next_diagnostic_step", "verification_label",
    "note", "hint", "reason", "impact_note", "text", "summary", "message", "detail",
})

CLASSES = ("HOST", "DOMAIN", "REALM", "SUFFIX", "INSTANCE", "IP", "USER", "GROUP", "HOSTGROUP", "SERVICE", "EMAIL")
_PSEUDONYM_TOKEN = r"\b(?:" + "|".join(CLASSES) + r")-\d{3,}\b"
_PSEUDONYM_SHAPE = re.compile(r"\b(" + "|".join(CLASSES) + r")-(\d{3,})\b")

# --- constants that keep their technical meaning (never pseudonymized) -------------------------------------------
_RESERVED = {c.lower() for c in CLASSES} | {"redacted", "removed", "omitted", "truncated", "unknown", "none", "null"}
CONST_WORDS = _RESERVED | {
    "localhost", "localhost4", "localhost6", "localhost.localdomain", "ipa", "server", "master", "replica", "ldap",
    "ldaps", "dns", "kdc", "ca", "www", "mail", "dc", "ad", "host", "test", "lab", "node", "primary", "secondary",
    "idm", "freeipa", "auth", "id", "sso", "ns", "ipa-ca", "self",
}
CONST_ACCOUNTS = {
    "root", "bin", "daemon", "adm", "nobody", "dirsrv", "pkiuser", "named", "apache", "ipaapi", "kdcproxy", "ods",
    "sssd", "gssproxy", "chrony", "polkitd", "dbus", "systemd-network", "systemd-resolve", "systemd-journal", "tss",
    "certmonger", "tomcat", "memcached", "ipa", "admin", "admins", "ipausers", "wheel", "editors", "trust admins",
    "ipaservers", "default smb group", "krbtgt", "kadmin", "directory manager", "anonymous", "k", "m", "changepw",
}
CONST_SERVICES = {
    "host", "ldap", "http", "dns", "krbtgt", "kadmin", "k", "dogtag", "ipa-dnskeysyncd", "ipa-ods-exporter", "cifs",
    "nfs", "ipa", "imap", "smtp", "postgres", "ftp", "afs", "ipa-http", "ipa-ca", "pki-tomcat", "smb", "changepw",
    "ipa-hsm", "http-proxy", "ipa-kdcproxy",
}
_SERVICE_LABELS = {"ipa-ca", "ipa_ca_missing_server", "_kerberos", "_kerberos-master", "_kpasswd", "_ldap", "_ntp", "_tcp", "_udp", "_msdcs",
                   "_sites", "_dc", "_gc", "_uri"}
_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "local", "localdomain", "lan", "corp", "internal", "intranet",
    "private", "home", "test", "example", "invalid", "arpa", "priv", "dev", "cloud", "info", "biz", "site", "online",
    "tech", "app", "xyz", "top", "shop", "page", "link", "network", "systems", "company", "group", "global", "world",
    "services", "solutions", "digital", "agency", "center", "host", "domains", "email", "zone", "work", "science",
}
# every two-letter (country-code) top-level domain counts, except these that are far more often file extensions
_NOT_TLD2 = {"py", "sh", "md", "js", "rs", "go", "so", "pl", "pm", "rb", "ts", "cs", "db", "gz", "xz", "bz", "ko",
             "mo", "po", "el", "cc", "hh", "ps", "sb", "lo", "ok"}


def _is_tld(label: str) -> bool:
    label = label.lower()
    return label in _TLDS or (len(label) == 2 and label.isalpha() and label.isascii() and label not in _NOT_TLD2)
# public documentation/project domains cited by ipa-diagnose's own knowledge (never the user's infrastructure)
PUBLIC_DOMAINS = ("freeipa.org", "redhat.com", "fedoraproject.org", "port389.org", "github.com", "pagure.io",
                  "readthedocs.io", "mit.edu", "kerberos.org", "ietf.org", "rfc-editor.org", "python.org", "pypi.org",
                  "sssd.io", "almalinux.org", "rockylinux.org", "centos.org", "example.com", "example.org", "example.net")
_UNIT_SUFFIXES = {"service", "socket", "target", "timer", "mount", "path", "slice", "scope", "device", "swap",
                  "automount"}
# first labels of dotted names that are code (Python modules, Java packages), not hosts
_MODULE_ROOTS = {"ipahealthcheck", "ipalib", "ipaserver", "ipaclient", "ipaplatform", "ipapython", "ipatests", "lib389"}
_KEEP_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "::"}

# keys whose value is a secret regardless of what it looks like (matched on the key with camelCase split by "_")
_SECRET_KEY_RE = re.compile(
    r"(?i)(passw|passphrase|passcode|pwd|secret|token|apikey|api_key|api-key|bearer|private_?key|privkey|credential|"
    r"bindpw|bind_pw|rootpw|access_?key|cookie|authoriz|session_?key|ccache_data|keytab_data|ticket_data|"
    r"(?<![a-z0-9])(?:pw|pin|pass|otp|totp|hotp|psk)(?![a-z0-9]))")


def secret_key(key: str, normalize: bool = False) -> bool:
    if normalize:  # the key as it is written out (NFKC, no format characters) and with look-alike letters folded
        key = clean(key).translate(_FOLD)
    return bool(_SECRET_KEY_RE.search(re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)))
# keys whose value is raw unstructured tool output: never copied into a bundle
_RAW_KEYS = frozenset({"raw", "stdout", "stderr", "output", "raw_output", "environ", "environment_variables"})

_HOSTISH_KEYS = {"host", "hostname", "server", "master", "replica", "fqdn", "peer", "target", "ca_renewal_master",
                 "crlgen_master", "dns_server", "ipa_server", "server_hostname"}
_USER_KEYS = {"user", "uid", "username", "login", "owner", "expected_owner"}
_GROUP_KEYS = {"group", "groupname", "expected_group"}

# --- cleaning -----------------------------------------------------------------------------------------------------
_ESCAPES = [
    re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]"),
    re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"),
    re.compile(r"\x1b[P^_X][^\x1b]*(?:\x1b\\)?"),
    re.compile(r"\x1b[@-Z\\-_]"),
    re.compile(r"[\x80-\x9f]"),  # C1 controls (incl. 8-bit CSI)
]

# one-to-one confusable folding, used for detection only (spans map back to the original text)
_FOLD = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d",
    "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɑ": "a", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "Ѕ": "S", "І": "I", "Ј": "J", "α": "a", "ο": "o",
    "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E",
    "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})


def clean(text: str) -> str:
    """Terminal escapes and control characters removed, format characters (zero-width, bidi) deleted so they cannot
    split a keyword, compatibility forms normalized (NFKC). Newlines and tabs are kept for multi-line detection."""

    text = unicodedata.normalize("NFKC", text)
    for p in _ESCAPES:
        text = p.sub("", text)
    out = []
    for ch in text:
        if ch in "\n\t":
            out.append(ch)
            continue
        cat = unicodedata.category(ch)
        if cat == "Cf":
            continue
        if cat in ("Cc", "Cs", "Co", "Cn", "Zl", "Zp") or (cat == "Zs" and ch != " "):
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


# --- secret patterns ----------------------------------------------------------------------------------------------
_NOT_MARKER = r"(?!\s*\[RE(?:DACTED|MOVED))"  # also when the pattern backtracks over whitespace before a marker
# A quoted value ends at its quote; an unquoted one runs to the end of the line, because a passphrase may contain
# spaces, commas or semicolons (over-redaction is the safe side).
_VALUE_LINE = _NOT_MARKER + r"(?P<secret>\"[^\"\n]*\"|'[^'\n]*'|\S[^\n]*)"
_VALUE_ARG = _NOT_MARKER + r"(?P<secret>\"[^\"\n]*\"|'[^'\n]*'|\S+)"
# field names are bounded (a real key is short); unbounded [\w.-]* on both sides is quadratic on long runs
_SECRET_NAME = (r"[\w.-]{0,40}?(?:passw(?:or)?d|passphrase|passcode|pwd|secret|token|api[_-]?key|apikey|"
                r"access[_-]?key|private[_-]?key|privkey|client[_-]?secret|bindpw|rootpw|credentials?)[\w.-]{0,40}"
                r"|[\w.-]{0,40}?(?<![A-Za-z0-9])(?:pw|pin|pass|otp|psk)\b")
_SECRET_MARKER = re.compile(r"(?i)passw(?:or)?d|passphrase|passcode|pwd|secret|token|api[_-]?key|access[_-]?key|"
                            r"private[_-]?key|privkey|bindpw|rootpw|credentials?|(?<![a-z0-9])(?:pw|pin|pass|otp|psk)")
# command-line password flags of tools that take them (checked procedurally in find_secrets: a regex that looks
# back from a flag to the tool name backtracks super-linearly)
_FLAG_RE = re.compile(r"(?<!\S)-(?:w|W|p|P|a|u)\s*" + _NOT_MARKER + r"(?P<secret>[^\s-]\S*)")
_TOOL_RE = re.compile(r"(?i)\b(?:ldap(?:search|modify|add|delete|passwd|whoami|compare|modrdn)\b|dsconf\b|dsctl\b|"
                      r"ipa-[a-z]|pk12util\b|mysql\b|psql\b|curl\b)")
# words that, after the secret-ish part of a field name, say the value is metadata about a secret, not the secret
_NON_SECRET_TAIL = re.compile(r"(?i)file|path|dir|polic|expir|lifetime|histor|grace|attempt|failure|enabled|required|"
                              r"len|min|max|age|type|status|state|changed|time|date|count|prompt|hint")
_BOOLISH = {"true", "false", "none", "null", "yes", "no", "on", "off", ""}

Pattern = Tuple[str, "re.Pattern[str]"]
PATTERNS: List[Pattern] = [
    ("private_key_block", re.compile(
        r"(?i)-----BEGIN[ A-Z0-9]*PRIVATE KEY-----[\s\S]*?(?:-----END[ A-Z0-9]*PRIVATE KEY-----|\Z)")),
    ("pem_block", re.compile(r"(?i)-----BEGIN [A-Z0-9 ]{1,40}-----[\s\S]*?(?:-----END [A-Z0-9 ]{1,40}-----|\Z)")),
    ("private_key_marker", re.compile(
        r"(?<![A-Za-z])PRIVATE KEY(?![A-Za-z])|PuTTY-User-Key-File|\bssh-(?:rsa|ed25519|dss)\s+AAAA\S+")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}")),
    ("github_token", re.compile(r"\b(?:gh[oprsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("credential_url", re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://" + _NOT_MARKER + r"(?P<secret>[^\s/@:]+:[^\s/@]+)@")),
    ("authorization_header", re.compile(
        r"(?i)\b(?:proxy-)?authori[sz]ation[\"']?\s*[:=]\s*" + _NOT_MARKER + r"(?P<secret>[^\n]+)")),
    ("cookie", re.compile(r"(?i)\b(?:set-)?cookie[\"']?\s*[:=]\s*" + _NOT_MARKER + r"(?P<secret>[^\n]+)")),
    ("bearer_token", re.compile(r"(?i)\b(?:bearer|negotiate|basic)\s+" + _NOT_MARKER
                                + r"(?P<secret>[A-Za-z0-9\-_.=+/~]{12,})")),
    ("password_option", re.compile(
        r"(?i)(?<![\w-])--?[\w-]{0,40}?(?:passw(?:or)?d|passphrase|passcode|pin|secret|token|api-?key|otp)"
        r"[\w-]{0,20}(?:\s*=\s*|\s+)" + _VALUE_ARG)),
    ("password_assignment", re.compile(
        # starts only at the beginning of a word run: an unanchored [\w.-]* is quadratic on long runs
        r"(?i)(?<![\w.-])(?P<key>" + _SECRET_NAME + r")\\?[\"']?\s*(?::|=>|=)\s*" + _VALUE_LINE)),
    ("password_prose", re.compile(
        r"(?i)\b(?:password|passphrase|passwd|passcode|pin|secret|token)\s+"
        r"(?:(?:(?:is|was|has been)\s+)?(?:set|reset|changed)\s+to|is|was|of)\s+"
        + _NOT_MARKER + r"(?P<secret>[^\n]+)")),
    ("password_prompt", re.compile(  # e.g. kinit's "Password for admin@REALM: <typed secret>"
        r"(?i)\b(?:password|passphrase|pin)\s+for\s+\S{1,256}?\s*:\s*" + _VALUE_LINE)),
    ("keytab_material", re.compile(r"(?i)\bkeytab\S*[:=]\s*[0-9a-f]{32,}")),
    ("high_entropy_token", re.compile(r"(?<![\w+/=.-])(?P<secret>[A-Za-z0-9+/_\-]{40,}={0,2})(?![\w+/=-])")),
]


def _keep(name: str, m: "re.Match[str]") -> bool:
    """False when a match is not actually secret material."""

    if name == "password_assignment":
        key = m.group("key")
        first = re.split(r"[\s,;]", m.group("secret").strip())[0]
        val = first.strip("\"',;").lower()
        if re.match(r"_[\w-]+\.", key):
            return False  # a DNS record name such as _kpasswd._tcp.<domain>. or _kpasswd.<domain>., not a secret field
        markers = list(_SECRET_MARKER.finditer(key))
        tail = key[markers[-1].end():] if markers else ""
        return not (_NON_SECRET_TAIL.search(tail) or val in _BOOLISH)
    if name == "bearer_token":
        return any(c.isdigit() or c in "=+/_-." for c in m.group("secret"))
    if name == "high_entropy_token":
        val = m.group("secret")
        if val.startswith("/") or not (any(c.isdigit() for c in val) and any(c.isalpha() for c in val)):
            return False
        segments = [x for x in re.split(r"[/_.-]+", val) if x]
        wordy = [x for x in segments if re.fullmatch(r"[a-z]{2,}|[A-Z][a-z]+|[A-Z]{2,}|\d{1,4}", x)]
        # words joined by separators (a path, a file-check key, an identifier) - not a random token
        return not (len(segments) >= 3 and len(wordy) * 2 >= len(segments))
    return True


def _pem_tail(text: str) -> List[Tuple[int, int]]:
    """A PEM body whose BEGIN line was cut off earlier (by the tool that produced the text): base64 lines directly
    before an END marker. Walks backwards by hand - a regex for this is quadratic."""

    spans = []
    start = 0
    while True:
        i = text.find("-----END", start)
        if i < 0:
            return spans
        j = i
        while j > 0 and (text[j - 1].isalnum() or text[j - 1] in "+/=\n\r\t "):
            j -= 1
        end = text.find("-----", i + 8)
        end = len(text) if end < 0 else end + 5
        spans.append((j, end))
        start = end


def find_secrets(text: str) -> List[Tuple[str, int, int]]:
    """(category, start, end) of every secret-looking span, detected on a confusable-folded copy."""

    folded = text.translate(_FOLD)
    found = []
    for name, pat in PATTERNS:
        for m in pat.finditer(folded):
            if _keep(name, m):
                g = "secret" if "secret" in pat.groupindex and m.group("secret") is not None else 0
                found.append((name, m.start(g), m.end(g)))
    for m in _FLAG_RE.finditer(folded):  # "-w SECRET" counts only after one of the tools, on the same line
        line_start = folded.rfind("\n", 0, m.start()) + 1
        if _TOOL_RE.search(folded, max(line_start, m.start() - 300), m.start()):
            found.append(("password_flag", m.start("secret"), m.end("secret")))
    if "-----END" in folded:
        found += [("pem_block", a, b) for a, b in _pem_tail(folded)]
    return found


def redact(text: str, counts: Optional[collections.Counter] = None) -> str:
    """Replaces every detected secret span; overlapping spans are merged (the first category is reported)."""

    for _ in range(4):  # a replacement can expose a new match (e.g. an assignment behind a stripped PEM): repeat
        spans = sorted(find_secrets(text), key=lambda s: (s[1], -s[2]))
        if not spans:
            return text
        out, pos = [], 0
        for name, a, b in spans:
            if a < pos:
                continue
            out.append(text[pos:a])
            out.append(f"[REDACTED:{name}]")
            if counts is not None:
                counts[name] += 1
            pos = b
        out.append(text[pos:])
        text = "".join(out)
    return text


# --- identity patterns --------------------------------------------------------------------------------------------
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?"
_PRINCIPAL_RE = re.compile(
    r"(?<![\w.@/\\$-])(?P<primary>[A-Za-z0-9._$-]+)(?:/(?P<instance>[A-Za-z0-9._-]+))?(?:@|\\40)"
    r"(?P<realm>[A-Z0-9][A-Z0-9-]*(?:\.[A-Z0-9-]+)+)(?![\w.-])")
_EMAIL_RE = re.compile(r"(?i)(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?P<domain>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![\w-])")
_URL_HOST_RE = re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://(?:[^\s/@]{0,200}@)?\[?(?P<host>[^\s/:\]@\[]+)")
_UID_RE = re.compile(r"(?i)\buid=(?P<v>[^,+\s=\\]+)")
_FQDN_ATTR_RE = re.compile(r"(?i)\bfqdn=(?P<v>[^,+\s=\\]+)")
_GROUP_DN_RE = re.compile(r"(?i)\bcn=(?P<v>[^,+=\\]+),\s*cn=groups\b")
_HOSTGROUP_DN_RE = re.compile(r"(?i)\bcn=(?P<v>[^,+=\\]+),\s*cn=hostgroups\b")
_INSTANCE_RE = re.compile(r"(?i)(?:\bdirsrv@|\bslapd-)(?P<v>[A-Za-z0-9-]+)")
# LDAP suffix components, plain, LDAP-escaped (\3D \2C) or URL-encoded (%3D %2C)
_SUFFIX_DC = r"dc\s*(?:=|\\3D|%3D)\s*"
_SUFFIX_SEP = r"\s*(?:,|\\2C|%2C)\s*"
_SUFFIX_RE = re.compile(r"(?i)\b" + _SUFFIX_DC + r"(?P<first>[a-z0-9-]{1,63})(?P<rest>(?:" + _SUFFIX_SEP + _SUFFIX_DC
                        + r"[a-z0-9-]{1,63}){1,10})")
_SUFFIX_LABEL_RE = re.compile(r"(?i)" + _SUFFIX_DC + r"([a-z0-9-]{1,63})")
# a Windows/AD down-level logon name: NETBIOSDOMAIN\user (not an LDAP escape such as \2C)
_DOWNLEVEL_RE = re.compile(r"(?<![\w\\=])(?P<dom>[A-Z][A-Z0-9-]{1,14})\\(?![0-9A-Fa-f]{2}(?:[^A-Za-z0-9]|$))"
                           r"(?P<user>[A-Za-z0-9._$-]{2,64})(?![\w])")
_DOWNLEVEL_CONST = {"NT", "BUILTIN", "NT AUTHORITY", "NT SERVICE", "WORKGROUP"}
_HOME_RE = re.compile(r"/home/(?P<v>[^/\s:;,'\"]+)")
_FQDN_RE = re.compile(r"(?<![A-Za-z0-9_@./\\-])(?P<v>(?:" + _LABEL + r"\.)+[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9])"
                      r"(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4})"
                      r"(?![\w:])(?!\.\d)")
_AGREEMENT_PREFIX = re.compile(r"^(meTo|cloneAgreement\d+-)", re.IGNORECASE)
# a maximal dotted name (used to find hosts inside known domains in one linear pass)
_DOTTED_RE = re.compile(r"(?<![A-Za-z0-9_.-])(?:" + _LABEL + r"\.)+" + _LABEL)
_CHUNK = 1024  # identifier-dense text is replaced in chunks of about this size (keeps replacement linear)


def _canon_ip(text: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:  # ::ffff:10.1.2.3 is the same address as 10.1.2.3
        ip = ip.ipv4_mapped
    return None if ip.compressed in _KEEP_IPS or ip.is_loopback else ip.compressed


def _ip_pattern(form: str) -> str:
    esc = re.escape(form)
    if ":" not in form:  # IPv4: a port (10.1.2.3:389) or an IPv4-mapped prefix (::ffff:) around it is still the address
        return r"(?<![\w.])" + esc + r"(?!\d)(?!\.\d)"
    return r"(?i:(?<![\w.:])" + esc + r")(?![\w:])(?!\.\d)"


class SanitizeTimeout(Exception):
    pass


class Sanitizer:
    """Holds the identity mapping and the privacy counters for one bundle."""

    def __init__(self) -> None:
        self._map: Dict[Tuple[str, str], str] = {}  # (class, canonical original) -> pseudonym
        self._next: Dict[str, int] = collections.defaultdict(int)
        self._taken: Dict[str, set] = collections.defaultdict(set)  # pseudonym numbers already present in the input
        self._variants: Dict[Tuple[str, str], Tuple[str, str]] = {}  # (class, text form) -> map key
        self._domains: List[str] = []
        self._domain_set: set = set()
        self._probes: List[Tuple[str, Tuple[str, str], Tuple[str, str]]] = []
        self._regex: Optional[bool] = None  # None: the per-subset regex cache below must be rebuilt
        self._cache: Dict[Tuple[Tuple[Tuple[str, str], ...], Tuple[str, ...]], Any] = {}
        self.deadline: Optional[float] = None  # time.monotonic() limit for all processing (build sets it)
        self.redactions: collections.Counter = collections.Counter()
        self.removed_fields = 0
        self.raw_fields_dropped = 0
        self.truncated = 0
        self.omitted = 0
        self.structure_trimmed = 0
        self.pseudonym_shaped_input = 0
        self.heuristic_hosts = 0
        self.literals: List[Tuple[str, str]] = []  # (local text, replacement), e.g. the replay fixture path

    def add_literal(self, text: str, replacement: str) -> None:
        if text and len(text) >= 4 and (text, replacement) not in self.literals:
            self.literals.append((text, replacement))
            self.literals.sort(key=lambda x: -len(x[0]))

    def _apply_literals(self, text: str) -> str:
        for lit, rep in self.literals:
            if lit in text:
                text = text.replace(lit, rep)
        return text

    # -- registration -------------------------------------------------------------------------------------------
    def _alloc(self, cls: str) -> str:
        n = self._next[cls] + 1
        while n in self._taken[cls]:
            n += 1
        self._next[cls] = n
        return f"{cls}-{n:03d}"

    def _register(self, cls: str, canon: str, form: Optional[str] = None) -> Optional[str]:
        if not canon:
            return None
        key = (cls, canon)
        if key not in self._map:
            self._map[key] = self._alloc(cls)
            self._regex = None
        form = form if form is not None else canon
        if (cls, form) not in self._variants:
            self._variants[(cls, form)] = key
            self._regex = None
        return self._map[key]

    @staticmethod
    def _public(low: str) -> bool:
        return any(low == d or low.endswith("." + d) for d in PUBLIC_DOMAINS)

    def add_host(self, name: str, short: bool = True) -> None:
        name = name.strip().rstrip(".")
        low = name.lower()
        if (not name or low in CONST_WORDS or len(name) > 253 or _canon_ip(name) or self._public(low)
                or _PSEUDONYM_SHAPE.fullmatch(name)):
            return  # a name shaped like a pseudonym is never registered: its number is skipped instead
        if "." in low:
            labels = low.split(".")
            if labels[0] in _SERVICE_LABELS:
                return
            self._register("HOST", low)
            dom = ".".join(labels[1:])
            if "." in dom or _is_tld(dom):
                self.add_domain(dom)
            first = labels[0]
            if (short and len(first) >= 3 and first not in CONST_WORDS and not first.startswith("_")
                    and not _PSEUDONYM_SHAPE.fullmatch(first.upper())):
                self._register("HOST", low, first)  # the short name is the same host
        elif len(low) >= 3 and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", low):
            self._register("HOST", low)

    def add_domain(self, domain: str) -> None:
        low = domain.strip().strip(".").lower()
        if not low or _is_tld(low) or low in CONST_WORDS or "." not in low or self._public(low):
            return
        if low not in self._domain_set:
            self._domain_set.add(low)
            self._domains.append(low)
            self._regex = None
        self._register("DOMAIN", low)
        self._register("SUFFIX", low)  # the LDAP suffix dc=...,dc=... derived from it

    def add_realm(self, realm: str) -> None:
        realm = realm.strip()
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9.-]*\.[A-Z0-9-]+", realm):
            return
        self._register("REALM", realm)
        self.add_domain(realm.lower())
        self.add_instance(realm.replace(".", "-"))

    def add_instance(self, name: str) -> None:
        if len(name) >= 3 and name.lower() not in CONST_WORDS and name.lower() != "snmp":
            self._register("INSTANCE", name.upper(), name.upper())

    def add_ip(self, text: str) -> None:
        canon = _canon_ip(text)
        if canon:
            self._register("IP", canon, text)

    def _add_account(self, cls: str, name: str) -> None:
        low = name.strip().lower()
        if len(low) >= 3 and low not in CONST_ACCOUNTS and low not in CONST_WORDS and not _PSEUDONYM_SHAPE.fullmatch(
                name.strip()):
            self._register(cls, low)

    def add_user(self, name: str) -> None:
        self._add_account("USER", name)

    def add_group(self, name: str) -> None:
        self._add_account("GROUP", name)

    # -- discovery ----------------------------------------------------------------------------------------------
    def discover_text(self, text: str, key: str = "") -> None:
        self._check_time()
        text = self._apply_literals(clean(text))
        for m in _PSEUDONYM_SHAPE.finditer(text):
            self._taken[m.group(1)].add(int(m.group(2)))
            self.pseudonym_shaped_input += 1
        k = key.lower()
        token = text.strip()
        if k in _HOSTISH_KEYS and re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", token):
            self.add_host(token)
        if k in _USER_KEYS and re.fullmatch(r"[A-Za-z0-9_.$-]{1,64}", token):
            self.add_user(token)
        if k in _GROUP_KEYS and re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", token):
            self.add_group(token)
        for m in _PRINCIPAL_RE.finditer(text):
            self.add_realm(m.group("realm"))
            primary, inst = m.group("primary"), m.group("instance")
            if inst:
                if primary.lower() not in CONST_SERVICES:
                    self._add_account("SERVICE", primary)
                self.add_host(inst)
            else:
                self.add_user(primary)
        for m in _EMAIL_RE.finditer(text):
            dom = m.group("domain").lower()
            last = dom.rsplit(".", 1)[-1]
            in_known = any(dom == d or dom.endswith("." + d) for d in self._domains)
            if last in _UNIT_SUFFIXES or (not _is_tld(last) and not in_known) or self._public(dom):
                continue  # e.g. dirsrv@EXAMPLE-TEST.service is a systemd unit, not an address
            if m.start() > 0 and text[m.start() - 1] == ":" and "://" in text[max(0, m.start() - 200):m.start()]:
                continue  # user:password@host in a URL: the host is found by the URL rule, the rest is redacted
            if in_known and dom not in self._domains:
                self.add_host(dom)  # user@host.<ipa domain>: the part after @ is a host of this domain
            if not _PRINCIPAL_RE.search(m.group(0)):
                self._register("EMAIL", m.group(0).lower())
                self.add_domain(m.group("domain"))
        for m in _URL_HOST_RE.finditer(text):
            h = m.group("host")
            if _canon_ip(h):
                self.add_ip(h)
            elif "." in h and not h[-1].isdigit():
                self.add_host(h)
        for rx, fn in ((_UID_RE, self.add_user), (_FQDN_ATTR_RE, self.add_host), (_GROUP_DN_RE, self.add_group),
                       (_HOSTGROUP_DN_RE, lambda v: self._add_account("HOSTGROUP", v)), (_INSTANCE_RE, self.add_instance),
                       (_HOME_RE, self.add_user)):
            for m in rx.finditer(text):
                fn(m.group("v"))
        for m in _SUFFIX_RE.finditer(text):  # an LDAP suffix names a DNS domain even when the domain is unknown
            labels = [x.group(1) for x in _SUFFIX_LABEL_RE.finditer(m.group(0))]
            if len(labels) >= 2:
                self.add_domain(".".join(labels))
        for m in _DOWNLEVEL_RE.finditer(text):
            if m.group("dom") not in _DOWNLEVEL_CONST and m.group("dom").lower() not in CONST_WORDS:
                self._register("DOMAIN", m.group("dom").lower(), m.group("dom"))  # NetBIOS domain name
                self.add_user(m.group("user"))
        for m in _IPV4_RE.finditer(text):
            self.add_ip(m.group(0))
        for m in _IPV6_RE.finditer(text):
            if any(c.isdigit() or c.isalpha() for c in m.group(0)):
                self.add_ip(m.group(0))
        self._discover_in_domain(text)
        for m in _FQDN_RE.finditer(text):
            v = m.group("v")
            labels = v.lower().split(".")
            if (_is_tld(labels[-1]) and labels[0] not in _MODULE_ROOTS
                    and not any(v.lower() == d or v.lower().endswith("." + d) for d in self._domains)):
                if ("HOST", v.lower()) not in self._map and not self._public(v.lower()):
                    self.heuristic_hosts += 1
                self.add_host(v, short=False)  # a guess: its first label alone is not treated as a name

    _in_domain_cache: Dict[str, "re.Pattern[str]"] = {}

    @classmethod
    def _in_domain_re(cls, dom: str) -> "re.Pattern[str]":
        if dom not in cls._in_domain_cache:
            cls._in_domain_cache[dom] = re.compile(r"(?i)(?<![A-Za-z0-9_.-])(?:" + _LABEL + r"\.)+" + re.escape(dom)
                                                   + r"(?![A-Za-z0-9])(?!\.[A-Za-z0-9])")
        return cls._in_domain_cache[dom]

    def _discover_in_domain(self, text: str) -> None:
        """Every name that ends in a known domain is a host of that domain (meToipa02.example.test and
        cloneAgreement1-ipa02.example.test-pki-tomcat included). One pass over the dotted names, then set lookups."""

        if not self._domain_set:
            return
        for m in _DOTTED_RE.finditer(text):
            tok = m.group(0)
            low = tok.lower()
            last = low.rsplit(".", 1)[-1]
            base = len(low) - len(last)
            ends = [len(low)] + [base + i for i, c in enumerate(last) if c == "-"][:5]
            for e in ends:
                parts = low[:e].split(".")
                hit = next((".".join(parts[i:]) for i in range(max(1, len(parts) - 10), len(parts))
                            if ".".join(parts[i:]) in self._domain_set), None)
                if hit:
                    self._host_in_domain(tok[:e], hit)
                    break

    def _host_in_domain(self, text: str, dom: str) -> None:
        text = _AGREEMENT_PREFIX.sub("", text)
        labels = text.split(".")
        while labels and labels[0].lower() in _SERVICE_LABELS:
            labels = labels[1:]
        name = ".".join(labels)
        if name.lower() != dom:
            self.add_host(name)

    def discover(self, value: Any, key: str = "", depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            return
        # Exactly the same bounds as transform(): everything that can reach a member must have been discovered,
        # otherwise an identifier seen only there is neither pseudonymized nor known to the leak self-test.
        if isinstance(value, dict):
            items = list(value.items())
            for k, v in (items[:MAX_DICT_KEYS] if depth >= 1 else items):
                self.discover_text(str(k))
                self.discover(v, str(k), depth + 1)
        elif isinstance(value, (list, tuple)):
            seq = list(value)
            for v in (seq[:MAX_LIST_ITEMS] if depth >= 2 else seq):
                self.discover(v, key, depth + 1)
        elif isinstance(value, str) and len(value) <= HARD_LIMIT:
            self.discover_text(value, key)

    # -- pseudonymization ---------------------------------------------------------------------------------------
    def _check_time(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise SanitizeTimeout()

    @staticmethod
    def _probe(cls: str, form: str) -> str:
        """A lower-case literal that must occur in a text for this identifier form to be able to match there."""

        return form.split(".")[0].lower() if cls == "SUFFIX" else form.lower()

    def _build_regex(self, variants, domains, loose: bool = False):
        alts: List[Tuple[int, int, str, str, Tuple[str, str]]] = []
        for (cls, form), key in variants:
            esc = re.escape(form)
            if cls == "HOST":
                if "." in form:
                    pat = r"(?i:" + esc + r")(?![A-Za-z0-9])(?!\.[A-Za-z0-9])"
                else:
                    pat = r"(?i:(?<![A-Za-z0-9_.-])" + esc + r")(?![A-Za-z0-9_-])"
            elif cls == "REALM":
                pat = r"(?<![A-Za-z])" + esc + r"(?![A-Za-z0-9])"
            elif cls == "DOMAIN":
                pat = r"(?i:(?<![A-Za-z0-9_-])" + esc + r")(?![A-Za-z0-9])(?!\.[A-Za-z0-9])"
            elif cls == "SUFFIX":
                labels = form.split(".")
                pat = r"(?i:" + _SUFFIX_SEP.join(_SUFFIX_DC + re.escape(lb) for lb in labels) + r")(?![A-Za-z0-9-])"
            elif cls == "INSTANCE":
                pat = r"(?i:(?<![A-Za-z0-9])" + esc + r")(?![A-Za-z0-9-])"
            elif cls == "IP":
                pat = _ip_pattern(form)
            elif cls in ("EMAIL",):
                pat = r"(?i:" + esc + r")(?![A-Za-z0-9_-])"
            elif cls == "SERVICE":
                pat = r"(?i:(?<![A-Za-z0-9_.-])" + esc + r")(?=/)"
            else:  # USER, GROUP, HOSTGROUP
                pat = r"(?i:(?<![A-Za-z0-9_.-])" + esc + r")(?![A-Za-z0-9_-])"
            if loose:  # second pass: any remaining occurrence, even inside a longer unknown name
                pat = pat.replace(r"(?!\.[A-Za-z0-9])", "")
            prio = 0 if cls == "REALM" else 1  # a realm (case-sensitive) wins over the same-length domain
            alts.append((-len(form), prio, cls, pat, key))
        for dom in ([] if loose else domains):
            alts.append((-(len(dom) + 1), 2, "_INDOMAIN", r"(?i:(?<![A-Za-z0-9_.-])(?:" + _LABEL + r"\.)+"
                         + re.escape(dom) + r")(?![A-Za-z0-9])(?!\.[A-Za-z0-9])", ("_INDOMAIN", dom)))
        alts.sort(key=lambda a: (a[0], a[1]))
        groups = {f"g{i}": (a[2], a[4]) for i, a in enumerate(alts)}
        # first alternative: a pseudonym already in the text (assigned by the first pass, or an input literal whose
        # number is skipped) is kept as it is - a real name such as host-001 must never rewrite HOST-001. A
        # pseudonym-shaped label that starts a longer name (HOST-001.example.test) is a real name, not kept.
        rx = re.compile("(?P<keep>" + _PSEUDONYM_TOKEN + r"(?!\.[A-Za-z0-9]))|"
                        + "|".join(f"(?P<g{i}>{a[3]})" for i, a in enumerate(alts)))
        return rx, groups

    def _replace(self, m: "re.Match[str]", groups) -> str:
        if m.lastgroup == "keep":
            return m.group(0)
        cls, key = groups[m.lastgroup]
        if cls == "_INDOMAIN":
            text = m.group(0)
            prefix = ""
            pm = _AGREEMENT_PREFIX.match(text)
            if pm:
                prefix, text = pm.group(0), text[pm.end():]
            labels = text.split(".")
            keep = []
            while labels and labels[0].lower() in _SERVICE_LABELS:
                keep.append(labels.pop(0))
            rest = ".".join(labels)
            dom = key[1]
            if rest.lower() == dom:
                pseud = self._map[("DOMAIN", dom)]
            else:
                pseud = self._register("HOST", rest.lower().rstrip("."), rest.lower().rstrip(".")) or rest
            return prefix + ".".join(keep + [pseud])
        if cls == "SUFFIX":
            return self._map[key]
        return self._map[key]

    def pseudonymize(self, text: str) -> str:
        """Only the identifiers that can occur in this text take part in its regex (a cheap substring probe), so the
        cost does not grow with the number of identifiers known to the bundle."""

        self._check_time()
        if self._regex is None:
            self._cache.clear()
            self._probes = [(self._probe(*v), v, k) for v, k in self._variants.items()]
            self._regex = True
        low = text.lower()
        present = [(p, v, k) for p, v, k in self._probes if p in low]
        if not present:
            return text
        if len(text) <= 2 * _CHUNK or len(present) <= 32:
            return self._sub(text, [(v, k) for _p, v, k in present])
        # identifier-dense long text: each chunk only carries the identifiers that occur in it
        out = []
        for chunk in _chunks(text, _CHUNK):
            cl = chunk.lower()
            sub = [(v, k) for p, v, k in present if p in cl]
            out.append(self._sub(chunk, sub) if sub else chunk)
        return "".join(out)

    def _sub(self, text: str, present) -> str:
        variants = tuple(sorted(present))
        ck = tuple(v for v, _ in variants)
        if ck not in self._cache:
            if len(self._cache) > 4096:
                self._cache.clear()
            self._cache[ck] = (self._build_regex(variants, ()), self._build_regex(variants, (), loose=True))
        (strict, sg), (loose, lg) = self._cache[ck]
        # whole names first (a longer name wins), then any remaining occurrence of a known identifier
        out = strict.sub(lambda m: self._replace(m, sg), text)
        return loose.sub(lambda m: self._replace(m, lg), out)

    def reserve(self, value: Any) -> None:
        """Pseudonym numbers that already occur as text in the evidence are never assigned (called before the
        diagnosed host is registered, so a literal HOST-001 in the evidence cannot be confused with it)."""

        def visit(_key: str, text: str) -> None:
            if len(text) <= HARD_LIMIT:
                for m in _PSEUDONYM_SHAPE.finditer(clean(text)):
                    self._taken[m.group(1)].add(int(m.group(2)))

        walk_strings(value, visit)

    # -- the whole pipeline ---------------------------------------------------------------------------------------
    def text(self, value: str, limit: int = TEXT_LIMIT) -> str:
        if len(value) > HARD_LIMIT:
            self.omitted += 1
            return f"[OMITTED: text too large to process safely ({len(value)} characters)]"
        out = self._apply_literals(clean(value))
        out = redact(out, self.redactions)
        out = self.pseudonymize(out)
        out = " ".join(out.split())
        if len(out) > limit:
            self.truncated += 1
            out = out[: max(limit - 14, 0)].rstrip() + " [truncated]"
        return out

    def transform(self, value: Any, key: str = "", depth: int = 0) -> Any:
        """Sanitized deep copy: prohibited keys removed, strings redacted/pseudonymized/bounded, structure bounded."""

        if depth > MAX_DEPTH:
            self.structure_trimmed += 1
            return "[OMITTED: nested too deeply]"
        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            items = list(value.items())
            # a member's own top level and its record lists are capped explicitly in build.LIMITS (never silently)
            if len(items) > MAX_DICT_KEYS and depth >= 1:
                self.structure_trimmed += 1
                items = items[:MAX_DICT_KEYS]
            for k, v in items:
                k = str(k)
                if k.lower() in _RAW_KEYS:
                    self.raw_fields_dropped += 1
                    continue
                nk = self.text(k, KEY_LIMIT)
                while nk in out:
                    nk += "#"
                if secret_key(k, normalize=True) and not isinstance(v, bool) and v is not None:
                    self.removed_fields += 1
                    out[nk] = "[REMOVED]"
                    continue
                out[nk] = self.transform(v, k, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            seq = list(value)
            if len(seq) > MAX_LIST_ITEMS and depth >= 2:
                self.structure_trimmed += 1
                seq = seq[:MAX_LIST_ITEMS]
            return [self.transform(v, key, depth + 1) for v in seq]
        if isinstance(value, str):
            return self.text(value, PROSE_LIMIT if key in PROSE_KEYS else TEXT_LIMIT)
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return value if value == value and abs(value) != float("inf") else None
        return self.text(str(value))

    # -- reporting ------------------------------------------------------------------------------------------------
    def pseudonym_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {c: 0 for c in CLASSES}
        for (cls, _canon) in self._map:
            counts[cls] += 1
        return {c: n for c, n in counts.items() if n}

    def originals(self) -> List[Tuple[str, str]]:
        """(class, text form) of every real identifier seen - for the leak self-test only; never written out."""

        return sorted(set(self._variants))

    def local_host_pseudonym(self, hostname: str) -> Optional[str]:
        low = hostname.strip().rstrip(".").lower()
        return self._map.get(("HOST", low))


def _chunks(text: str, size: int) -> List[str]:
    """Pieces of about `size` characters, cut at whitespace that does not follow a comma (so an LDAP suffix
    written as "dc=a, dc=b" stays whole); a hard cut only when there is no such whitespace."""

    out, start = [], 0
    while len(text) - start > size:
        cut = -1
        for i in range(start + size, start + size // 2, -1):
            if text[i].isspace() and text[i - 1] != ",":
                cut = i
                break
        cut = cut if cut > start else start + size
        out.append(text[start:cut])
        start = cut
    out.append(text[start:])
    return out


def walk_strings(value: Any, visit: Callable[[str, str], None], key: str = "") -> None:
    """Calls visit(key, string) for every mapping key and string value."""

    if isinstance(value, dict):
        for k, v in value.items():
            visit("", str(k))
            walk_strings(v, visit, str(k))
    elif isinstance(value, (list, tuple)):
        for v in value:
            walk_strings(v, visit, key)
    elif isinstance(value, str):
        visit(key, value)


def iter_originals(items: Iterable[Tuple[str, str]]) -> Iterable[Tuple[str, "re.Pattern[str]", str]]:
    """Strict detectors for the leak self-test: a real identifier anywhere in the output is a leak. Each comes with
    a lower-case probe that must occur in a text before the detector can match (keeps the scan linear)."""

    for cls, form in items:
        esc = re.escape(form)
        probe = Sanitizer._probe(cls, form)
        if cls == "HOST" and "." in form:
            yield cls, re.compile(r"(?i)" + esc + r"(?![A-Za-z0-9])"), probe
        elif cls == "SUFFIX":
            labels = form.split(".")
            yield cls, re.compile(r"(?i)" + _SUFFIX_SEP.join(_SUFFIX_DC + re.escape(lb) for lb in labels)), probe
        elif cls == "IP":
            yield cls, re.compile(_ip_pattern(form)), probe
        elif cls == "REALM":
            yield cls, re.compile(r"(?<![A-Za-z])" + esc + r"(?![A-Za-z0-9])"), probe
        else:
            yield cls, re.compile(r"(?i)(?<![A-Za-z0-9])" + esc + r"(?![A-Za-z0-9])"), probe
