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

import bisect
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
    "idm", "freeipa", "auth", "id", "sso", "ns", "ipa-ca", "self", "api",
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
    "lab", "labs", "domain", "intern", "mgmt", "prod", "stage", "staging", "qa", "uat", "infra", "office", "cluster",
    "idm", "ipa", "lcl", "loc", "srv", "net1", "corp1",
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
_FILE_EXTS = {"pem", "crt", "cer", "key", "csr", "conf", "keytab", "log", "db", "p12", "pfx", "ldif", "json", "txt"}
_UNIT_SUFFIXES = {"service", "socket", "target", "timer", "mount", "path", "slice", "scope", "device", "swap",
                  "automount"}
# first labels of dotted names that are code (Python modules, Java packages), not hosts
_MODULE_ROOTS = {"ipahealthcheck", "ipalib", "ipaserver", "ipaclient", "ipaplatform", "ipapython", "ipatests", "lib389"}
_MODULE_SUBPACKAGES = {"ipa", "ds", "dogtag", "meta", "system", "install", "plugins", "util", "ipautil", "certdb",
                       "ipaldap", "dns", "config", "topology", "core", "ipa_certs", "certs", "files", "host", "kdc",
                       "replication", "ruv", "nss", "proxy", "roles", "trust", "idns", "dna", "backends", "encryption"}
_KEEP_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "::"}

# keys whose value is a secret regardless of what it looks like (matched on the key with camelCase split by "_")
_SECRET_KEY_RE = re.compile(
    r"(?i)(passw|passphrase|passcode|pwd|secret|token|apikey|api_key|api-key|bearer|private_?key|privkey|credential|"
    r"bindpw|bind_pw|rootpw|access_?key|cookie|authoriz|session_?key|session_?id|ccache_data|keytab_data|ticket_data|"
    r"pincode|kennwort|motdepasse|contrase|authtok|auth_tok|creds|basic_?auth|nt_?hash|lm_?hash|"
    r"(?<![a-z0-9])(?:pw|pin|pass|otp|totp|hotp|psk)(?![a-z0-9])|[a-z]pw(?![a-z0-9]))")


_SERIAL_KEY_RE = re.compile(r"(?i)serial")


def serial_key(key: str) -> bool:
    """A field holding a certificate serial number (serial, serial_number, cert_serial, ...): never included."""

    return bool(_SERIAL_KEY_RE.search(clean(key)))


def secret_key(key: str, normalize: bool = False) -> bool:
    if normalize:  # the key as it is written out (NFKC, no format characters) and with look-alike letters folded
        key = clean(key).translate(_FOLD)
    return bool(_SECRET_KEY_RE.search(re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)))
# keys whose value is raw unstructured tool output: never copied into a bundle
_RAW_KEYS = frozenset({"raw", "stdout", "stderr", "output", "raw_output", "environ", "environment_variables"})

_HOSTISH_KEYS = {"host", "hostname", "server", "master", "replica", "fqdn", "peer", "target", "ca_renewal_master",
                 "hosts", "servers", "masters", "replicas", "peers",
                 "crlgen_master", "dns_server", "ipa_server", "server_hostname"}
_USER_KEYS = {"user", "uid", "username", "login", "owner", "expected_owner", "users", "members", "member",
              "memberuid", "member_user"}
_GROUP_KEYS = {"group", "groupname", "expected_group", "groups", "member_group"}

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


# default-ignorable code points that render as nothing (they could split a keyword without being "format" chars)
_IGNORABLE = ([(0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
               (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
               (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
               (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF)])


def invisible(ch: str) -> bool:
    cp = ord(ch)
    return unicodedata.category(ch) in ("Cf", "Mn", "Me") or any(a <= cp <= b for a, b in _IGNORABLE)


def clean(text: str) -> str:
    """Terminal escapes and control characters removed, format characters (zero-width, bidi) deleted so they cannot
    split a keyword, compatibility forms normalized (NFKC). Newlines and tabs are kept for multi-line detection."""

    # combining marks are dropped after decomposition, so an accent cannot hide a keyword (pa\u0301ssword, p\u00e1ssword)
    text = unicodedata.normalize("NFKD", text)
    text = unicodedata.normalize("NFKC", "".join(c for c in text if not unicodedata.combining(c)))
    for p in _ESCAPES:
        text = p.sub("", text)
    out = []
    for ch in text:
        if ch in "\n\t":
            out.append(ch)
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Mn", "Me") or (ord(ch) > 0x7F and invisible(ch)):
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
_SHELL_WORD = r"(?:'[^'\n]*'|\"[^\"\n]*\"|\\.|[^\s'\"\\])+"
_VALUE_ARG = _NOT_MARKER + r"(?P<secret>" + _SHELL_WORD + r")"
# field names are bounded (a real key is short); unbounded [\w.-]* on both sides is quadratic on long runs
_PW = r"pass[\s_.-]?w(?:or)?d"  # password / passwd, also split by one separator (pass word, pass_word)
_SECRET_NAME = (r"[\w.-]{0,100}?(?:" + _PW + r"|passphrase|passcode|pwd|secret|token|api[_-]?key|apikey|creds|nthash|lmhash|"
                r"basic[_-]?auth|"
                r"access[_-]?key|private[_-]?key|privkey|client[_-]?secret|bindpw|rootpw|authtok|credentials?)[\w.-]{0,100}"
                r"|[\w.-]{0,100}?(?<![A-Za-z0-9])(?:pw|pin|pass|otp|psk)\b|[\w.-]{0,60}?[A-Za-z]pw\b")
_SECRET_MARKER = re.compile(r"(?i)" + _PW + r"|passphrase|passcode|pwd|secret|token|api[_-]?key|access[_-]?key|"
                            r"private[_-]?key|privkey|bindpw|rootpw|authtok|credentials?|"
                            r"(?<![a-z0-9])(?:pw|pin|pass|otp|psk)")
# command-line password flags of tools that take them (checked procedurally in find_secrets: a regex that looks
# back from a flag to the tool name backtracks super-linearly)
_FLAG_RE = re.compile(r"(?<!\S)-(?:[A-Za-z]{0,6}w|W|p|P|a|u)\s*" + _NOT_MARKER
                      + r"(?P<secret>(?=[^\s-])" + _SHELL_WORD + r")")
# a line-level backstop: after a secret keyword and a ':' or '=', the rest of the line is treated as secret, unless
# the keyword continues a word (IPAProxySecretCheck, passwords) or is followed by a word saying it is metadata
_LINE_KEYWORD_RE = re.compile(r"(?i)" + _PW + r"|passphrase|passcode|kennwort|bindpw|rootpw|authtok|secret|"
                              r"credentials?|api[\s_-]?key|access[\s_-]?key|pass[\s_-]?phrase|\bpin\b")
_META_TAIL_RE = re.compile(r"(?i)[A-Za-z]|[\s_.-]?(?:files?|paths?|dirs?|polic(?:y|ies)|expir\w*|lifetime|history|"
                           r"grace|attempts?|failures?|enabled|required|length|len|minimum|min|maximum|max|age|type|"
                           r"status|state|changed|time|timestamp|date|count|prompt|hint|reset|change|quality|strength|"
                           r"checks?)(?![A-Za-z])")
_TOOL_RE = re.compile(r"(?i)\b(?:ldap[a-z]{2,12}\b|dsconf\b|dsctl\b|dsidm\b|dscreate\b|"
                      r"ipa-[a-z]|pk12util\b|mysql\b|psql\b|curl\b|sshpass\b|redis-cli\b|kinit\b|kpasswd\b|passwd\b|"
                      r"certutil\b|chpasswd\b|ipa\b|kadmin(?:\.local)?\b|kdb5_util\b|pki\b|wbinfo\b)")
# a here-string fed to one of the tools (kinit admin <<< pw); checked procedurally like the flags
_YAML_BLOCK_RE = re.compile(r"[|>][-+0-9]{0,3}[ \t]*")
_HERESTR_RE = re.compile(r"<<<\s*" + _NOT_MARKER + r"(?P<secret>\S[^\n]*)")
# markers already in the text: nothing that starts inside one is a new secret
_MARKER_RE = re.compile(r"\[(?:REDACTED|REMOVED)[^\]\n]{0,60}\]")
# words that, after the secret-ish part of a field name, say the value is metadata about a secret, not the secret
_NON_SECRET_TAIL = re.compile(r"(?i)file|path|dir|polic|expir|lifetime|histor|grace|attempt|failure|enabled|required|"
                              r"len|min|max|age|type|status|state|changed|time|date|count|prompt|hint")
_BOOLISH = {"true", "false", "none", "null", "yes", "no", "on", "off", ""}
_TRIVIAL_VALUES = {"none", "null", "true", "false", "yes", "no", "on", "off", "n/a", "unknown", "empty", "default",
                   "unset", "redacted", "removed", "withheld", "***", "xxx"}


def secret_value_re(value: str) -> "re.Pattern[str]":
    """A tracked secret value: anywhere when long, as a whole token when short (a 4-digit PIN must not match inside
    a longer number or word)."""

    esc = re.escape(value)
    return re.compile(esc if len(value) >= 6 else r"(?<![A-Za-z0-9])" + esc + r"(?![A-Za-z0-9])")


_PROSE_START_RE = re.compile(
    r"(?i)(?:for|is|was|has|have|had|must|will|can|cannot|could|should|of|to|the|a|an|and|or|not|in|on|at|by|with|"
    r"expired|expires|expiration|policy|reset|change|changed|manager|required|incorrect|invalid|wrong|mismatch|"
    r"missing|empty|length|file|path|check|checks|history|age|attempts?|failures?|updated|update|now|set)\b")

Pattern = Tuple[str, "re.Pattern[str]"]
PATTERNS: List[Pattern] = [
    # certificate serial numbers are never included (not credentials, but an explicit exclusion):
    # the IPA RA agent description "2;<serial>;<issuer>;<subject>" (IPARAAgent expected/got) ...
    ("certificate_serial", re.compile(r"(?<![\w;])2;(?P<secret>(?:0x)?[0-9A-Fa-f]{1,64});")),
    # ... and "serial 12", "serial number: 0x1f", "Serial Number: 3a:4f:...", "SerialNumber=1234" in text
    ("certificate_serial", re.compile(
        r"(?i)\bserial[ _-]?(?:number|no\.?|num|#)?\s*(?:is\s+|[:=#]\s*|\(\s*)?"
        r"(?P<secret>(?:[0-9A-Fa-f]{1,2}:){2,}[0-9A-Fa-f]{1,2}|(?:0x)?[0-9A-Fa-f]*\d[0-9A-Fa-f]*)(?![\w:])")),
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
    ("slack_token", re.compile(r"\b(?:xox[abposr]|xapp)-[A-Za-z0-9-]{10,}")),
    ("camel_assignment", re.compile(  # adminPw=..., bindPass: ..., keystorePass="..."
        r"(?<![A-Za-z0-9_])[a-z][A-Za-z0-9]{0,60}(?:Pw|Pwd|Pass|Passwd|Password|Pin|Secret|Token|Authtok|Creds)"
        r"\\?[\"']?\s*(?::|=>|=)\s*" + _VALUE_LINE)),
    ("xml_secret", re.compile(
        r"(?i)<[\w:.-]{0,40}?(?:passw(?:or)?d|secret|token|pin|pwd|authtok|credentials?)\b[^>\n]{0,100}>"
        + _NOT_MARKER + r"(?P<secret>[^<\n]{1,512})</")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("credential_url", re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://" + _NOT_MARKER
                                  + r"(?P<secret>[^/@:\n]{0,128}:\S{0,256}?)@"
                                  + r"(?=[A-Za-z0-9.\[\]:-]+(?:[/\s?#)'\",;\]>]|$))")),
    ("authorization_header", re.compile(
        r"(?i)\b(?:proxy-)?authori[sz]ation[\"']?\s*[:=]\s*" + _NOT_MARKER + r"(?P<secret>[^\n]+)")),
    ("cookie", re.compile(r"(?i)\b(?:set-)?cookie[\"']?(?:\s*[:=]\s*|\s+(?=[^\s=]+=))" + _NOT_MARKER
                          + r"(?P<secret>\S[^\n]*)")),
    ("stdin_secret", re.compile(  # echo pw | kinit admin
        r"(?i)\b(?:echo|printf)(?:\s+-[neE]{1,3})*(?:\s+'[^']{0,20}%s[^']{0,20}'|\s+\"[^\"]{0,20}%s[^\"]{0,20}\")?\s+"
        + _NOT_MARKER + r"(?P<secret>\"[^\"\n]*\"|'[^'\n]*'|\S+)\s*\|\s*"
        r"(?:sudo\s+)?(?:kinit|kpasswd|passwd|ldap\w+|ipa\b|ipa-\w|dsconf|pk12util|certutil|chpasswd)")),
    ("bearer_token", re.compile(r"(?i)\b(?:bearer|negotiate|basic)(?:\s*:)?\s+" + _NOT_MARKER
                                + r"(?P<secret>[A-Za-z0-9\-_.=+/~]{12,})")),
    ("password_option", re.compile(
        r"(?i)(?<![\w-])--?[\w-]{0,40}?(?:passw(?:or)?d|passphrase|passcode|pin|secret|token|api-?key|otp|bindpw|"
        r"rootpw|pw|pass|psk)"
        r"[\w-]{0,20}(?:\s*=\s*|\s+)" + _VALUE_ARG)),
    ("password_assignment", re.compile(
        # starts only at the beginning of a word run: an unanchored [\w.-]* is quadratic on long runs
        r"(?i)(?<![\w.-])(?P<key>" + _SECRET_NAME + r")\\?[\"']?\s*(?::|=>|=)\s*" + _VALUE_LINE)),
    ("password_flag", re.compile(  # pk12util -K slot password, ldappasswd -s new password (anchored on the tool)
        r"(?i)\b(?:ldappasswd|pk12util|pki)\b[^\n]{0,300}?(?<!\S)-[sKc]\s*" + _NOT_MARKER
        + r"(?P<secret>(?=[^\s-])" + _SHELL_WORD + r")")),
    ("user_password", re.compile(r"(?i)\bwbinfo\b[^\n]{0,200}?(?<!\S)-a\s+['\"]?[^\s%'\"]{1,128}%(?P<secret>\S+)")),
    ("user_password", re.compile(  # curl -u/--user user:pw, smbclient/net -U user%pw
        r"(?<![\w-])(?:--[Uu]ser(?:name)?|-[uU])(?:\s*=\s*|\s*)" + _NOT_MARKER
        + r"['\"]?[^\s:%'\"]{1,128}[:%](?P<secret>\S+)")),
    ("config_secret", re.compile(  # ldap.conf / slapd.conf / sssd.conf style "bindpw value", "PASSWORD<TAB>value"
        r"(?im)^[ \t]*[\w.-]{0,60}(?:bindpw|rootpw|authtok|" + _PW + r"|passphrase|secret)[ \t]+" + _NOT_MARKER
        + r"(?P<secret>[^\s=:][^\n]*)")),
    ("config_secret", re.compile(  # the same, after upstream text cleaning collapsed it into a sentence
        r"(?i)(?<![A-Za-z])" + _PW + r"[ \t]+" + _NOT_MARKER + r"(?P<secret>'[^'\n]*'|\"[^\"\n]*\"|[^\s=:]\S*)")),
    ("config_secret", re.compile(  # space-separated token keywords: api_key X, access_token X, X-Api-Key X
        r"(?i)(?<![\w-])(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|x-api-key|client[_-]?secret|"
        r"[A-Za-z]{1,30}pw)[ \t]+" + _NOT_MARKER + r"(?P<secret>[^\s=:]\S*)")),
    ("config_secret", re.compile(  # a quoted value after the word: named.conf's key "x" { secret "..."; }
        r"(?i)(?<![\w-])(?:secret|pass\s?phrase)[ \t]+(?P<secret>\"[^\"\n]{1,1024}\"|'[^'\n]{1,1024}')")),
    ("password_positional", re.compile(r"(?i)\bipa\s+passwd\s+\S+\s+" + _NOT_MARKER + r"(?P<secret>\S+)")),
    ("config_secret", re.compile(r"(?i)(?<![\w-])(?:bindpw|rootpw|[\w-]{0,40}authtok)[ \t]+" + _NOT_MARKER
                                 + r"(?P<secret>[^\s=:][^\n]*)")),
    ("password_prose", re.compile(
        r"(?i)\b(?:" + _PW + r"|pass\s?phrase|passcode|pin|secret|token)s?(?:\s+for\s+[^\n]{1,80}?)?\s+"
        r"(?:(?:(?:is|was|are|were|has been|have been)\s+)?(?:set|reset|changed|updated)\s+to|is|was|are|were|of|now)\s+"
        + _NOT_MARKER + r"(?P<secret>[^\n]+)")),
    ("password_prompt", re.compile(  # e.g. kinit's "Password for admin@REALM: <typed secret>"
        r"(?i)\b(?:" + _PW + r"|passphrase|pin)\s+for\s+[^\n:\[]{1,256}?\s*:\s*" + _VALUE_LINE)),
    ("keytab_material", re.compile(r"(?i)\bkeytab\S*[:=]\s*[0-9a-f]{32,}")),
    # a key printed by klist -K / ktutil: "(0x<hex>)"
    ("keytab_material", re.compile(r"\(0x(?P<secret>[0-9A-Fa-f]{32,})\)")),
    # an LDAP/389-DS password value in its storage-scheme form ({SSHA512}..., {PBKDF2_SHA256}..., {AES-...}...)
    ("password_hash", re.compile(r"(?i)\{(?:S?SHA\d{0,3}|S?MD5|CRYPT|CLEAR|PBKDF2[\w-]{0,20}|ARGON2[\w-]{0,10}|"
                                 r"GOST_YESCRYPT|AES-[^}\s]{0,64})\}(?P<secret>\S+)")),
    # a keytab file itself, base64-encoded: the format starts with 0x05 0x02 ("BQ" in base64)
    ("keytab_material", re.compile(r"(?i)\bkeytab[^\n:=]{0,40}[:=]\s*(?P<secret>BQ[A-Za-z0-9+/]{6,}={0,2})")),
    ("high_entropy_token", re.compile(r"(?<![\w+/~-])(?P<secret>[A-Za-z0-9+/_~\-]{40,}={0,2})(?![\w+/=~-])")),
]


def _random_segment(seg: str) -> bool:
    if len(seg) >= 16 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
        return True
    if (len(seg) >= 10 and any(c.isdigit() for c in seg) and any(c.isupper() for c in seg)
            and any(c.islower() for c in seg)):
        return True  # shorter, but digits and both cases mixed together: not a word
    # letters only: random text changes case about every second character, CamelCase words far less often
    pairs = [(a, b) for a, b in zip(seg, seg[1:]) if a.isalpha() and b.isalpha()]
    changes = sum(1 for a, b in pairs if a.isupper() != b.isupper())
    return len(seg) >= 20 and len(pairs) >= 12 and changes >= 0.3 * len(pairs)


def _keep(name: str, m: "re.Match[str]") -> bool:
    """False when a match is not actually secret material."""

    if name == "password_assignment":
        key = m.group("key")
        val = m.group("secret").strip().strip("\"',;.").lower()  # only a value that is just a boolean is exempt
        if re.match(r"_[\w-]+\.", key):
            return False  # a DNS record name such as _kpasswd._tcp.<domain>. or _kpasswd.<domain>., not a secret field
        markers = list(_SECRET_MARKER.finditer(key))
        tail = key[markers[-1].end():] if markers else ""
        return not (_NON_SECRET_TAIL.match(tail.lstrip("_.-")) or val in _BOOLISH)
    if name == "config_secret":  # "Password expired for ...", "secret is not set": prose, not a config value
        if re.search(r"(?i)bindpw|rootpw|authtok", m.group(0)[: m.start("secret") - m.start()]):
            return True
        return not _PROSE_START_RE.match(m.group("secret"))
    if name == "bearer_token":
        return not m.group(0).lower().startswith("basic") or any(c.isdigit() or c in "=+/_-." for c in m.group("secret"))
    if name == "high_entropy_token":
        val = m.group("secret")
        if not (any(c.isdigit() for c in val) and any(c.isalpha() for c in val)) and not _random_segment(val):
            return False
        segments = [x for x in re.split(r"[/_.~-]+", val) if x]
        if any(_random_segment(x) for x in segments):
            return True  # one random-looking part is enough (sk_live_<random>, base64 with / + -)
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


_SCHEME_RE = re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,30}://")


def _url_userinfo(text: str) -> List[Tuple[str, int, int]]:
    """user:password@host in any URL, whatever follows the host: the authority ends at the first '/', '?', '#' or
    whitespace, and its userinfo runs to the last '@' in it (a password may contain '@')."""

    spans = []
    for m in _SCHEME_RE.finditer(text):
        start = m.end()
        end = start
        limit = min(len(text), start + 512)
        while end < limit and text[end] not in "/?#" and not text[end].isspace():
            end += 1
        at = text.rfind("@", start, end)
        if at < 0:
            colon = text.find(":", start, end)
            tail = text[colon + 1:end] if colon >= 0 else ""
            if (colon > start and tail and not tail.rstrip(".").isdigit() and not text.startswith("[", start)
                    and not text.startswith("[RE", colon + 1)):
                spans.append(("credential_url", colon + 1, end))  # user:password with its '@' cut off upstream
            continue
        colon = text.find(":", start, at)
        if colon >= 0 and not text.startswith("[RE", colon + 1) and at > colon + 1:
            spans.append(("credential_url", colon + 1, at))
        elif colon < 0 and not text.startswith("[RE", start) and _random_segment(text[start:at]):
            spans.append(("credential_url", start, at))  # a token used as the user name (https://<token>@host/...)
    return spans


def _secret_lines(text: str, covered: List[Tuple[int, int]]) -> List[Tuple[str, int, int]]:
    """Per line: the first secret keyword that is not metadata, then the first ':' or '=' after it; the rest of the
    line is secret. One keyword scan and one delimiter search per line (linear)."""

    spans = []
    pos, n = 0, len(text)
    while pos <= n:
        eol = text.find("\n", pos)
        eol = n if eol < 0 else eol
        for m in _LINE_KEYWORD_RE.finditer(text, pos, eol):
            if _META_TAIL_RE.match(text, m.end(), eol):
                continue
            w = m.start()
            while w > max(pos, m.start() - 64) and (text[w - 1].isalnum() or text[w - 1] in "_-"):
                w -= 1
            if text[w] == "_" or text.endswith("[REDACTED:", 0, w):
                continue  # a DNS service label such as _kpasswd._tcp, or the category inside a redaction marker
            k = bisect.bisect_right(covered, (m.start(), len(text))) - 1
            if k >= 0 and covered[k][0] <= m.start() < covered[k][1]:
                continue  # inside something another detector already redacts (e.g. a URL password)
            d = min((i for i in (text.find(":", m.end(), eol), text.find("=", m.end(), eol)) if i >= 0), default=-1)
            if d >= 0 and max(text.rfind("[REDACTED", m.end(), d), text.rfind("[REMOVED", m.end(), d)) < 0:
                j = d + 1
                while j < eol and text[j] in " \t\"'":
                    j += 1
                if j < eol and _YAML_BLOCK_RE.fullmatch(text, j, eol) and eol < n:
                    nxt = text.find("\n", eol + 1)
                    spans.append(("secret_line", j, n if nxt < 0 else nxt))  # YAML block: the value is on the next line
                elif j < eol and not text.startswith("[RE", j):
                    spans.append(("secret_line", j, eol))
            break
        pos = eol + 1
    return spans


def find_secrets(text: str) -> List[Tuple[str, int, int]]:
    """(category, start, end) of every secret-looking span, detected on a confusable-folded copy."""

    folded = text.translate(_FOLD)
    found = []
    for name, pat in PATTERNS:
        for m in pat.finditer(folded):
            if _keep(name, m):
                g = "secret" if "secret" in pat.groupindex and m.group("secret") is not None else 0
                found.append((name, m.start(g), m.end(g)))
    starts = [0] + [i + 1 for i, c in enumerate(folded) if c == "\n"]
    first_tool: Dict[int, int] = {}
    for m in _TOOL_RE.finditer(folded):
        ls = starts[bisect.bisect_right(starts, m.start()) - 1]
        first_tool.setdefault(ls, m.start())
    for rx, cat in ((_FLAG_RE, "password_flag"), (_HERESTR_RE, "stdin_secret")):
        for m in rx.finditer(folded):  # counts only after one of the tools, on the same line
            ls = starts[bisect.bisect_right(starts, m.start()) - 1]
            if first_tool.get(ls, len(folded)) < m.start():
                found.append((cat, m.start("secret"), m.end("secret")))
    covered = sorted((a, b) for _n, a, b in found)
    merged: List[Tuple[int, int]] = []
    for a, b in covered:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    found += _url_userinfo(folded)
    found += _secret_lines(folded, merged)
    if "-----END" in folded:
        found += [("pem_block", a, b) for a, b in _pem_tail(folded)]
    if "[RE" in folded:  # a span that starts inside an existing [REDACTED:...] / [REMOVED] marker is not a secret
        marks = [(m.start(), m.end()) for m in _MARKER_RE.finditer(folded)]
        starts = [a for a, _b in marks]
        keep = []
        for f in found:
            k = bisect.bisect_right(starts, f[1]) - 1
            if not (k >= 0 and marks[k][0] <= f[1] < marks[k][1]):
                keep.append(f)
        found = keep
    return found


def redact(text: str, counts: Optional[collections.Counter] = None) -> str:
    """Replaces every detected secret span; overlapping spans are merged (the first category is reported)."""

    for _ in range(4):  # a replacement can expose a new match (e.g. an assignment behind a stripped PEM): repeat
        spans = sorted(find_secrets(text), key=lambda s: (s[1], -s[2]))
        if not spans:
            return text
        merged: List[List[Any]] = []
        for name, a, b in spans:
            if merged and a < merged[-1][2]:  # overlaps the previous span: redact the union
                merged[-1][2] = max(merged[-1][2], b)
            else:
                merged.append([name, a, b])
        out, pos = [], 0
        for name, a, b in merged:
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
    r"(?P<realm>[A-Z0-9]+(?:-[A-Z0-9]+)*(?:\.[A-Z0-9]+(?:-[A-Z0-9]+)*)+)(?![A-Za-z0-9_])(?!\.[A-Za-z0-9])")
_EMAIL_RE = re.compile(r"(?i)(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?P<domain>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![\w-])")
_URL_HOST_RE = re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://(?:\S{0,256}@)?\[?(?P<host>[A-Za-z0-9._-]+)")
_UID_RE = re.compile(r"(?i)\b(?:uid|gid|user|login)\s*[=:]\s*['\"]?(?:\d+\()?(?P<v>[A-Za-z0-9_][A-Za-z0-9._$@-]{0,63})")
_FQDN_ATTR_RE = re.compile(r"(?i)\bfqdn=(?P<v>[^,+\s=\\]+)")
_GROUP_DN_RE = re.compile(r"(?i)\bcn=(?P<v>[^,+=\\]+)(?:\+[^,\n]{0,120})?,\s*cn=groups\b")
_HOSTGROUP_DN_RE = re.compile(r"(?i)\bcn=(?P<v>[^,+=\\]+)(?:\+[^,\n]{0,120})?,\s*cn=hostgroups\b")
_METO_RE = re.compile(r"\bmeTo(?P<v>[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,10})")
_SPN_RE = re.compile(r"(?<![\w/.@-])(?P<svc>[A-Za-z][\w-]{1,30})/(?P<host>[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,10})")
_INSTANCE_RE = re.compile(r"(?i)(?:\bdirsrv@|(?:\b|(?<=%2F))slapd-)(?P<v>[A-Za-z0-9-]+)")  # also ldapi://%2Frun%2Fslapd-X.socket
# LDAP suffix components, plain, LDAP-escaped (\3D \2C) or URL-encoded (%3D %2C)
_SUFFIX_DC = r"dc\s*(?:=|\\=|\\3D|%3D)\s*"
_SUFFIX_SEP = r"\s*(?:,|\\,|\\2C|%2C)\s*"
_SUFFIX_RE = re.compile(r"(?i)\b" + _SUFFIX_DC + r"(?P<first>[a-z0-9-]{1,63})(?P<rest>(?:" + _SUFFIX_SEP + _SUFFIX_DC
                        + r"[a-z0-9-]{1,63}){1,10})")
_SUFFIX_LABEL_RE = re.compile(r"(?i)" + _SUFFIX_DC + r"([a-z0-9-]{1,63})")
# a Windows/AD down-level logon name: NETBIOSDOMAIN\user (not an LDAP escape such as \2C)
_DOWNLEVEL_RE = re.compile(r"(?<![\w\\=])(?P<dom>[A-Za-z][A-Za-z0-9-]{1,14})\\(?![0-9A-Fa-f]{2}(?:[^A-Za-z0-9]|$))"
                           r"(?P<user>[A-Za-z0-9._$-]{2,64})(?![\w])")
_DOWNLEVEL_CONST = {"NT", "BUILTIN", "NT AUTHORITY", "NT SERVICE", "WORKGROUP"}
_HOME_RE = re.compile(r"/home/(?P<v>[A-Za-z0-9._$@-]{1,64})(?:/(?P<v2>[A-Za-z0-9._$@-]{1,64}))?")
# a relative record name in a FreeIPA DNS entry: idnsname=<host>,idnsname=<zone>.,cn=dns,...
# (a relative name can have several labels: ws1.dev in zone example.test is ws1.dev.example.test)
_IDNSNAME_RE = re.compile(r"(?i)\bidnsname=(?P<v>[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63}){0,10}),\s*"
                          r"idnsname=(?P<zone>[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63}){0,20})\.?(?=[,\s'\"]|$)")
_ENTERPRISE_RE = re.compile(r"(?<![\w.\\-])(?P<user>[A-Za-z0-9._$-]{1,64})\\@(?P<dom>[A-Za-z0-9.-]+\.[A-Za-z]{2,})@")
_USER_DN_RE = re.compile(r"(?i)\bcn=(?P<v>[^,+=\\]{1,128})(?:\+[^,\n]{0,120})?,\s*cn=users\b")
_IPV6_RUN_RE = re.compile(r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")
_FQDN_RE = re.compile(r"(?<![A-Za-z0-9_.\\-])(?P<v>(?:" + _LABEL + r"\.)+[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9])"
                      r"(?![A-Za-z0-9-])(?:(?!\.[A-Za-z0-9])|(?=\.(?:pem|crt|cer|key|csr|conf|keytab|log|db|p12|pfx|"
                      r"ldif|json|txt)(?![A-Za-z0-9])))")  # a host name may be followed by a file extension
_IPV4_RE = re.compile(r"(?<![0-9])(?<![0-9]\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4})"
                      r"(?![\w:])(?!\.\d)")
# an installer-made volume group <distro>_<short host name>: /dev/mapper/rhel_ipa01-root ('-' doubled), /dev/rhel_ipa01/
_VG_RE = re.compile(r"(?<=/dev/mapper/)(?P<pfx>[A-Za-z0-9.+]{1,32}_)(?P<name>(?:[A-Za-z0-9.+]|--){1,128}?)(?=-(?!-))"
                    r"|(?<=/dev/)(?P<pfx2>[A-Za-z0-9.+]{1,32}_)(?P<name2>[A-Za-z0-9.+-]{1,128})(?=/)")
_AGREEMENT_PREFIX = re.compile(r"^(meTo|cloneAgreement\d+-|masterAgreement\d+-)")
# a maximal dotted name (used to find hosts inside known domains in one linear pass)
_DOTTED_RE = re.compile(r"(?<![A-Za-z0-9_.-])(?:" + _LABEL + r"\.)+" + _LABEL)
_CHUNK = 1024  # identifier-dense text is replaced in chunks of about this size (keeps replacement linear)


def _canon_ip(text: str) -> Optional[str]:
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):  # leading zeros (010.001.002.003) are the same address
        octets = [int(x) for x in text.split(".")]
        if any(o > 255 for o in octets):
            return None
        text = ".".join(str(o) for o in octets)
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
        return r"(?<![0-9])(?<![0-9]\.)" + esc + r"(?!\d)(?!\.\d)"
    return r"(?i:(?<![0-9A-Fa-f.])(?<![0-9A-Fa-f]:)" + esc + r")(?![0-9A-Fa-f])(?!:[0-9A-Fa-f:])(?!\.\d)"


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
        self._owned: set = set()  # public-listed domains that are this deployment's own (see own_public_parent)
        self._probes: List[Tuple[str, Tuple[str, str], Tuple[str, str]]] = []
        self._regex: Optional[bool] = None  # None: the per-subset regex cache below must be rebuilt
        self._cache: Dict[Tuple[Tuple[Tuple[str, str], ...], Tuple[str, ...]], Any] = {}
        self.deadline: Optional[float] = None  # time.monotonic() limit for all processing (build sets it)
        self.redactions: collections.Counter = collections.Counter()
        self.removed_fields = 0
        self.raw_fields_dropped = 0
        self.serial_fields_removed = 0
        self.truncated = 0
        self.omitted = 0
        self.structure_trimmed = 0
        self.pseudonym_shaped_input = 0
        self.heuristic_hosts = 0
        self.literals: List[Tuple[str, str]] = []  # (local text, replacement), e.g. the replay fixture path
        # values found under secret-named fields: removed wherever else they appear (e.g. quoted in a diagnosis
        # text that was built before the bundle saw it) and searched for by the self-test
        self.secret_values: set = set()

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

    def _public(self, low: str) -> bool:
        return any((low == d or low.endswith("." + d)) and d not in self._owned for d in PUBLIC_DOMAINS)

    def own_public_parent(self, name: str) -> None:
        """When the diagnosed host lies inside a public-listed domain (Fedora, Red Hat, CentOS, ... run FreeIPA
        themselves), that whole domain is the deployment's own: every name in it is pseudonymized, including
        peers in other subdomains, the parent domain, its LDAP suffix and e-mail addresses."""

        low = name.strip().rstrip(".").lower()
        for d in PUBLIC_DOMAINS:
            if low == d or low.endswith("." + d):
                self._owned.add(d)
                self.add_domain(d, force=True)

    def _known(self, low: str) -> bool:
        parts = low.split(".")
        return any(".".join(parts[i:]) in self._domain_set for i in range(len(parts)))

    def add_host(self, name: str, short: bool = True, force: bool = False) -> None:
        name = name.strip().rstrip(".")
        low = name.lower()
        if (not name or low in CONST_WORDS or len(name) > 253 or _canon_ip(name)
                or (self._public(low) and not force and not self._known(low)) or _PSEUDONYM_SHAPE.fullmatch(name)):
            return  # a name shaped like a pseudonym is never registered: its number is skipped instead
        if "." in low:
            labels = low.split(".")
            if labels[0] in _SERVICE_LABELS:
                return
            self._register("HOST", low)
            dom = ".".join(labels[1:])
            if "." in dom or _is_tld(dom):
                self.add_domain(dom, force=force)
            first = labels[0]
            if (short and len(first) >= 3 and first not in CONST_WORDS and not first.startswith("_")
                    and not _PSEUDONYM_SHAPE.fullmatch(first.upper())):
                self._register("HOST", low, first)  # the short name is the same host
        elif len(low) >= 3 and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", low):
            self._register("HOST", low)

    def add_domain(self, domain: str, force: bool = False) -> None:
        low = domain.strip().strip(".").lower()
        if not low or _is_tld(low) or low in CONST_WORDS or "." not in low or (self._public(low) and not force):
            return
        if low not in self._domain_set:
            self._domain_set.add(low)
            self._domains.append(low)
            self._regex = None
        self._register("DOMAIN", low)
        self._register("DOMAIN", low, low.replace(".", "_"))  # e.g. SSSD's .../domain_realm_example_test
        self._register("SUFFIX", low)  # the LDAP suffix dc=...,dc=... derived from it

    def add_realm(self, realm: str, force: bool = False) -> None:
        realm = realm.strip()
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9.-]*\.[A-Z0-9-]+", realm):
            return
        self._register("REALM", realm)
        self.add_domain(realm.lower(), force=force)
        self.add_instance(realm.replace(".", "-"))

    def _add_record(self, rel: str, zone: str) -> None:
        """A DNS record DN idnsname=<rel>,idnsname=<zone>.: the host <rel>.<zone>, also written as just <rel>."""

        low, zone = rel.lower(), zone.lower().rstrip(".")
        if low.startswith("_") or zone.endswith(".arpa") or low == "@":
            return  # a service record (_ldap._tcp) or a reverse-zone entry (the address is found by the IP rules)
        if "." not in zone and not _is_tld(zone):
            if "." not in low:
                self.add_host(rel)
            return
        fqdn = low + "." + zone  # its first label is registered as the same host's short name
        self.add_host(fqdn)
        if "." in low and ("HOST", fqdn) in self._map:
            self._register("HOST", fqdn, low)  # the relative name as the DN writes it (ws1.dev)

    def add_instance(self, name: str) -> None:
        if len(name) >= 3 and name.lower() not in CONST_WORDS and name.lower() != "snmp":
            self._register("INSTANCE", name.upper(), name.upper())

    def add_ip(self, text: str) -> None:
        canon = _canon_ip(text)
        if canon:
            self._register("IP", canon, text)

    def _add_account(self, cls: str, name: str) -> None:
        name = name.strip().strip(".-_$@")
        if name.isdigit():
            return  # a numeric id (uid=1001) is not a name
        low = name.lower()
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
            if last in _UNIT_SUFFIXES or not (last.isalpha() and len(last) >= 2):
                continue  # e.g. dirsrv@EXAMPLE-TEST.service is a systemd unit, not an address
            k = text.rfind("://", max(0, m.start() - 200), m.start())
            if m.start() > 0 and text[m.start() - 1] == ":" and k >= 0 and not any(c.isspace() for c in text[k:m.start()]):
                continue  # user:password@host in a URL: the host is found by the URL rule, the rest is redacted
            if in_known and dom not in self._domains:
                self.add_host(dom)  # user@host.<ipa domain>: the part after @ is a host of this domain
            if not _PRINCIPAL_RE.search(m.group(0)):
                if in_known:
                    self.add_user(m.group(0).split("@", 1)[0])  # SSSD fully-qualified name user@domain
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
                       (_USER_DN_RE, self.add_user)):
            for m in rx.finditer(text):
                fn(m.group("v"))
        for m in _IDNSNAME_RE.finditer(text):
            self._add_record(m.group("v"), m.group("zone"))
        for m in _HOME_RE.finditer(text):  # /home/<user>, or SSSD's /home/<domain>/<user> for trusted-domain users
            if "." in m.group("v") and m.group("v2"):
                self.add_domain(m.group("v"))
                self.add_user(m.group("v2"))
            else:
                self.add_user(m.group("v"))
        for m in _METO_RE.finditer(text):  # a replication agreement names its peer, whatever its top-level label
            self.add_host(m.group("v"))
        for m in _SPN_RE.finditer(text):  # service/host without a realm, for a host of a known domain
            if self._known(m.group("host").lower()) and m.group("svc").lower() not in CONST_SERVICES:
                self._add_account("SERVICE", m.group("svc"))
        for m in _ENTERPRISE_RE.finditer(text):  # alice\@ad.example@REALM (enterprise principal)
            self.add_user(m.group("user"))
            self.add_domain(m.group("dom"))
        for m in _SUFFIX_RE.finditer(text):  # an LDAP suffix names a DNS domain even when the domain is unknown
            labels = [x.group(1) for x in _SUFFIX_LABEL_RE.finditer(m.group(0))]
            if len(labels) >= 2:
                self.add_domain(".".join(labels))
        for m in _DOWNLEVEL_RE.finditer(text):
            if m.group("dom").upper() not in _DOWNLEVEL_CONST and m.group("dom").lower() not in CONST_WORDS:
                self._register("DOMAIN", m.group("dom").lower(), m.group("dom"))  # NetBIOS domain name
                self.add_user(m.group("user"))
        for m in _IPV4_RE.finditer(text):
            self.add_ip(m.group(0))
        for m in _IPV6_RE.finditer(text):
            if any(c.isdigit() or c.isalpha() for c in m.group(0)):
                self.add_ip(m.group(0))
        for m in _IPV6_RUN_RE.finditer(text):  # also after ':' or '_' (address:fd00::5, host_fd00::7)
            run = m.group(0).strip(".")
            if run.endswith(":") and not run.endswith("::"):
                run = run[:-1]  # krb5kdc: "AS_REQ (...) 2001:db8::15: CLOCK_SKEW: ..." (the colon ends the address)
            for cand in (run, run.lstrip(":") if not run.startswith("::") else run, run.split(":", 1)[-1]):
                if cand.count(":") >= 2 and _canon_ip(cand):
                    self.add_ip(cand)
                    break
        for m in _FQDN_RE.finditer(text):
            v = _AGREEMENT_PREFIX.sub("", m.group("v"))
            labels = v.lower().split(".")
            service = [i for i, lb in enumerate(labels) if lb.startswith("_") or lb in ("ipa-ca", "ipa_ca_missing_server")]
            if service:  # _kerberos._udp.<domain>, _ldap._tcp.dc._msdcs.<domain>, ipa-ca.<domain>: the rest is a domain
                rest = labels[service[-1] + 1:]
                while rest and rest[0] in ("dc", "gc", "pdc", "domains", "_msdcs"):
                    rest = rest[1:]
                if len(rest) >= 2 and _is_tld(rest[-1]):
                    self.add_domain(".".join(rest))
                continue
            if len(labels) >= 3 and labels[-1] in _FILE_EXTS:  # host.example.com.pem: the host is before the extension
                v = v.rsplit(".", 1)[0]
                labels = labels[:-1]
            if "-" in labels[-1] and not _is_tld(labels[-1]):  # cloneAgreement1-<host>.<dom>.lan-pki-tomcat, -cert
                for i, c in enumerate(labels[-1]):
                    if c == "-" and _is_tld(labels[-1][:i]):
                        v = v[: len(v) - len(labels[-1]) + i]
                        labels[-1] = labels[-1][:i]
                        break
            if len(labels) >= 2 and self._known(v.lower()) and v.lower() not in self._domain_set:
                self.add_host(v)  # a host of a domain already known (whatever text is glued around it)
                continue
            tld = _is_tld(labels[-1]) or (labels[-1] in _NOT_TLD2 and len(labels) >= 3)
            code = (labels[0] in _MODULE_ROOTS and (len(labels) < 3 or labels[1] in _MODULE_SUBPACKAGES)
                    or (len(labels) == 3 and labels[:2] == ["api", "env"]))  # FreeIPA api.env.host: code, not a host
            if (tld and not code
                    and not any(v.lower() == d or v.lower().endswith("." + d) for d in self._domains)):
                if ("HOST", v.lower()) not in self._map and not self._public(v.lower()):
                    self.heuristic_hosts += 1
                self.add_host(v, short=False)  # a guess: its first label alone is not treated as a name
        # after the heuristic registered new domains: every other name in those domains, in this same text
        self._discover_in_domain(text)

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
            # the domain may also end before a later label (replica07.corp.test.pem)
            ends += [i for i, c in enumerate(low) if c in ".-"][::-1][:30]  # also before -cert.pem, -pki-tomcat
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
            kind = value.get("type")
            owner_kind = kind.strip().lower() if isinstance(kind, str) and kind.strip().lower() in (
                "owner", "group") else None
            for k, v in (items[:MAX_DICT_KEYS] if depth >= 1 else items):
                self.discover_text(str(k))
                if secret_key(str(k), normalize=True):
                    self._collect_secret(v)
                if owner_kind and str(k).lower() in ("got", "expected"):
                    self._discover_owner(owner_kind, v)
                self.discover(v, str(k), depth + 1)
        elif isinstance(value, (list, tuple)):
            seq = list(value)
            for v in (seq[:MAX_LIST_ITEMS] if depth >= 2 else seq):
                self.discover(v, key, depth + 1)
        elif isinstance(value, str) and len(value) <= HARD_LIMIT:
            self.discover_text(value, key)

    def _discover_owner(self, kind: str, value: Any) -> None:
        """The got/expected of an ipa-healthcheck ownership finding (IPAFileCheck, TomcatFileCheck, ...): one or
        several user or group names, e.g. "root" or "root,apache"."""

        names = value if isinstance(value, (list, tuple)) else [value]
        for n in names[:MAX_LIST_ITEMS]:
            if isinstance(n, str) and len(n) <= HARD_LIMIT:
                for part in re.split(r"[,\s]+", clean(n)):
                    if re.fullmatch(r"[A-Za-z0-9_.$-]{1,64}", part):
                        (self.add_user if kind == "owner" else self.add_group)(part)

    def track_secrets(self, value: Any, depth: int = 0) -> None:
        """Every value under a secret-named field anywhere in `value` is tracked (removed and self-tested)."""

        if depth > MAX_DEPTH:
            return
        if isinstance(value, dict):
            for k, v in list(value.items())[:10000]:
                if secret_key(str(k), normalize=True):
                    self._collect_secret(v)
                else:
                    self.track_secrets(v, depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in list(value)[:10000]:
                self.track_secrets(v, depth + 1)

    def _collect_secret(self, value: Any, depth: int = 0) -> None:
        if depth > MAX_DEPTH or isinstance(value, bool) or value is None:
            return
        if isinstance(value, dict):
            for v in value.values():
                self._collect_secret(v, depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in value:
                self._collect_secret(v, depth + 1)
        else:
            text = clean(str(value))[:HARD_LIMIT].strip()
            if len(text) >= 3 and text.lower() not in _TRIVIAL_VALUES and not _PSEUDONYM_SHAPE.fullmatch(text):
                self.secret_values.add(text)

    def _remove_secret_values(self, text: str) -> str:
        for v in sorted((v for v in self.secret_values if v in text), key=len, reverse=True):
            rx = secret_value_re(v)
            text, n = rx.subn("[REDACTED:secret_field_value]", text)
            self.redactions["secret_field_value"] += n
        return text

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
            elif cls == "DOMAIN" and "_" in form:
                pat = r"(?i:(?<![A-Za-z0-9-])" + esc + r")(?![A-Za-z0-9-])"
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
        out = self._remove_secret_values(out)
        if "/dev/" in out:
            out = _VG_RE.sub(self._vg_host, out)
        out = self.pseudonymize(out)
        out = " ".join(out.split())
        if len(out) > limit:
            self.truncated += 1
            out = out[: max(limit - 14, 0)].rstrip() + " [truncated]"
        return out

    def _vg_host(self, m: "re.Match") -> str:
        """The host short name in an installer-made LVM volume group (/dev/mapper/rhel_ipa01-root, /dev/rhel_ipa01/)."""

        name = m.group("name") or m.group("name2")
        key = self._variants.get(("HOST", name.replace("--", "-").lower()))
        if key is None:
            return m.group(0)
        return (m.group("pfx") or m.group("pfx2")) + self._map[key]

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
                if serial_key(k) and not isinstance(v, bool) and v is not None:
                    self.serial_fields_removed += 1
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
