# Evidence completeness, exit codes and the RUV limitation

`ipa-diagnose` never equates "could not verify" with "healthy". Every run
reports both **what it found** and **how much of the relevant evidence it could
actually collect**.

## Overall status

| Status | Meaning | Exit code |
|---|---|---|
| `HEALTHY` | Enough relevant evidence was collected **and** no problem was found. | 0 |
| `DEGRADED` | A supported problem was found (worst severity ERROR/WARNING). | 1 |
| `CRITICAL` | A supported problem was found at CRITICAL severity. | 2 |
| `UNKNOWN` | Not enough evidence to say anything is healthy (for example `ipa-healthcheck` could not run), or the primary problem could not be diagnosed. | 3 |
| `NOT_FULLY_VERIFIED` | No problem was found in the evidence that **was** collected, but some relevant evidence is missing, so health is not established. | 4 |

A found problem is never hidden by a collection gap: a `DEGRADED`/`CRITICAL`
result stays `DEGRADED`/`CRITICAL` even when evidence is also incomplete (the
gap is shown alongside it).

Exit code `4` is new. Wrapper scripts that only expect `0-3` should treat it as
"not verified".

## `evidence_completeness` (JSON) and the header block

`--json` adds `fully_verified` (bool) and an `evidence_completeness` object:

```json
"fully_verified": false,
"evidence_completeness": {
  "level": "partial",
  "healthcheck_collected": true,
  "ruv_state": "NOT_VERIFIED",
  "ruv_reason": "…",
  "unverified": [
    {"capability": "Replication agreements / RUV", "collector": "replication_agreements",
     "reason": "…", "permission_related": true}
  ]
}
```

* `level`: `complete`, `partial` (something relevant is unverified) or
  `insufficient` (`ipa-healthcheck` itself could not be collected).
* `collection_errors` is unchanged (a list of strings) but the text is now
  sanitised (terminal escapes and control characters removed, length bounded).
* In normal output a material gap is printed in the header, directly under
  `Overall:` - not only in the footer.

## RUV (replica update vector) state

| `ruv_state` | Meaning |
|---|---|
| `VERIFIED` | RUV entries were read. |
| `NONE_CONFIGURED` | The RUV was read as `cn=Directory Manager` (confirmed) and none exists: replication is not configured (single-server deployment). |
| `NOT_VERIFIED` | The RUV could not be read. **This is not a stale-RUV finding.** It means stale replica metadata could not be checked. |
| `NOT_COLLECTED` | Not attempted (for example a replayed fixture with no RUV evidence). |

### Why the Directory Manager password is never needed or used

`ipa-replica-manage list-ruv` asks for the Directory Manager password (observed
on FreeIPA 4.13.3 even with a valid admin Kerberos ticket). `ipa-diagnose`
never asks for, accepts, stores or passes that password. When `list-ruv` fails
and `ipa-diagnose` runs as **root**, it reads the same data with a single
read-only search over the local LDAPI socket (`ldapsearch -Y EXTERNAL`,
the mechanism `ipa-healthcheck`'s own RUV check uses), with no password. If that
is also unavailable the state stays `NOT_VERIFIED` and the reason is shown.

An empty search result is only interpreted as "no RUV exists" after
`ldapwhoami -Y EXTERNAL` confirms the identity is `cn=Directory Manager`; an
identity that merely cannot *see* the entry (observed live with an admin
GSSAPI bind) never yields "no RUV".

## Unexplained ipa-healthcheck findings

An `ipa-healthcheck` finding at ERROR/CRITICAL that no diagnostic rule explains
is never dropped. A `meta.services` "`<service>: not running`" finding is
reported as a diagnosed fact (the check itself states it; the *cause* is left
open with a read-only next step). Any other unexplained ERROR/CRITICAL finding
is grouped into one `UNKNOWN` diagnosis that quotes the raw finding and claims
no root cause.

## Validation status (be precise)

Validated live (real FreeIPA 4.13.3, Fedora 43, `ipa-healthcheck` 0.19,
389-ds 3.1.4, GitHub Actions runners): completeness states on healthy single
and two-node topologies, the LDAPI RUV read, missing-dependency behaviour, and
the stopped-service visibility fix. **Not validated live:** detection of a
genuine stale RUV. On FreeIPA 4.13 the topology plugin cleans the RUV
automatically when a server is removed, so a stale RUV could not be created in
a two-node lab; the stale-RUV *rule* is covered by fixtures only. See
[limitations.md](limitations.md).
