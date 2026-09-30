# Replication mode (`ipa-diagnose replication`)

```bash
sudo ipa-diagnose replication                  # every outbound agreement of this server
sudo ipa-diagnose replication --peer ipa02.example.test   # only the agreements towards one peer
sudo ipa-diagnose replication --details        # every check, why it ran or was skipped, its side effects
sudo ipa-diagnose replication --json           # machine-readable (replication_schema_version 1.0)
sudo ipa-diagnose replication --verify         # is the incident found last time really gone?
ipa-diagnose replication --replay DIR          # recorded evidence (development/testing; marked REPLAY)
```

The question it answers: **does replication to and from this IPA server work, per suffix and per direction, and if
not, what is the deepest cause the evidence proves?** Run it as root on an IPA server. It is read-only, uses no AI,
and never changes anything on this server or any other.

On a host that is not an IPA server it stops and says so (`NOT_AN_IPA_SERVER`, exit 4); nothing is guessed.

Exit codes: 0 every investigated agreement is green in both directions; 1 a problem was found; 4 nothing failing was
found but not everything could be checked (or not an IPA server); 2 usage error. With `--verify`: 0 resolved, 1 still
present or new, **3 PENDING**, 4 could not be verified.

## The replication model

Replication in FreeIPA is **directional and per suffix**. A relationship is identified by
`(supplier, consumer, suffix)`, written `domain:ipa01.example.test>ipa02.example.test`. The domain suffix
(`dc=example,dc=test`) and the CA suffix (`o=ipaca`) are separate relationships with separate agreements; a server
without a CA has no CA agreements. Two directions between the same pair are two relationships.

What one server can observe:

| Direction | How it is known | When it is not |
|---|---|---|
| this server -> peer (outbound) | this server's own agreement entry (`cn=mapping tree,cn=config`, read over LDAPI) | never inferred |
| peer -> this server (inbound) | the PEER's agreement entry, read from the peer read-only with **your** Kerberos ticket (the read `ipa-replica-manage list -v` makes) | no ticket, not permitted, or an empty answer: **UNKNOWN** and a handoff to the peer |

An empty answer from the peer is "not visible with this identity", never "no agreement". The reverse direction is
never derived from the outbound one.

Transport and bind method are read from each agreement (`nsDS5ReplicaTransportInfo`, `nsDS5ReplicaBindMethod`,
`nsDS5ReplicaPort`), never assumed. Topology-managed agreements normally use SASL/GSSAPI over LDAP on port 389; the
checks use whatever the agreement says. A SIMPLE-bind agreement's stored credential is never read, so its bind cannot
be reproduced (reported as such).

With GSSAPI, **the supplier gets its tickets from the KDC its own Kerberos configuration names** (on an IPA server:
normally itself). A stopped KDC on the peer therefore affects the peer's OUTBOUND direction (peer -> this server),
not this server's outbound one; ipa-diagnose does not assume the peer's KDC is needed for this server's direction.

## What it checks (closed registry, read-only)

Local prerequisites: this host is an IPA server (`/etc/ipa/default.conf`, `ipactl`, the realm's Directory Server
instance), the local Directory Server and KDC units, free space and read-only state of `/var/lib/dirsrv`, and the
Directory Server keytab `/etc/dirsrv/ds.keytab` (owner, mode, whether the `dirsrv` user can read it, its principals;
never keys; a symlinked or hard-linked keytab is not read at all).

Topology and roles (LDAPI, SASL EXTERNAL as root, confirmed as Directory Manager for completeness): `cn=masters`
(servers, enabled roles CA/KRA/DNS/DNSSEC/KDC/HTTP/ADTRUST, CA renewal master, DNSSEC key master, hidden servers) and
`cn=topology` (suffixes and segments). Agreements, replica configuration, the RUV of both suffixes and running RUV
clean tasks come from `cn=mapping tree,cn=config` and the RUV tombstones. `nsDS5ReplicaCredentials` is never
requested.

Per outbound agreement, bounded (at most 8 agreements; more are named, not investigated, and make the run PARTIAL):

| Step | Check | Side effect |
|---|---|---|
| peer name resolves (from this host) | `getent ahosts` | a DNS query |
| agreement port answers | TCP connect | one connection in the peer's logs |
| peer Directory Server answers, and its clock | anonymous base search of the peer's root DSE (`currentTime`) | one anonymous LDAP connection in the peer's access log |
| is the host up at all | TCP 443, only when the agreement port does not answer | one connection |
| the supplier's GSSAPI bind, reproduced | `kinit -k -t /etc/dirsrv/ds.keytab ldap/<this host>` into a private temporary cache, then `ldapwhoami -Y GSSAPI -N` to the agreement's host/port/transport; only when the agreement is failing (or this server's KDC is down) | Kerberos requests in the KDC log; one bind on the peer; the cache is removed at once |
| reverse direction | read-only search of the peer's agreements towards this server, with your own ticket | one service-ticket request, one search in the peer's access log |

Only when relevant: `ldap/` service principals and `cn=replication managers` (this server's copy of the directory),
and this host's NTP state (`chronyc tracking`) when a clock difference is in view.

Every command is a fixed argv (no shell), runs from `/` with a fixed environment and stdin closed (a tool that would
prompt, for example for the Directory Manager password, gets EOF and cannot hang), has a timeout, and its output is
bounded and sanitized.

## Cause chains

A diagnosis is a chain: symptom -> failing subsystem -> intermediate cause(s) -> deepest proven cause. Each link
records its claim, subject, capability, evidence and the **discriminator** that established it. The discriminators
form a closed registry (`replication/causal.py`) over a capability DAG; a link that no registered discriminator
establishes cannot be built. When the next link cannot be proven the chain **stops**, says why, and names the next
action. Examples (live and fixture rows: [truth/replication-truth-matrix.md](truth/replication-truth-matrix.md)):

- `ipa01 -> ipa02 fails: could not connect` -> `ipa02 is up (443 answers) but refuses connections on 389: its
  Directory Server is not accepting connections`. **Stops:** whether it is stopped, failed or listening elsewhere
  can only be seen on ipa02 -> handoff `On ipa02 run: sudo ipa-diagnose replication --peer ipa01`.
- `... fails: could not connect` -> `no LDAP answer` -> `ipa02 is unreachable from ipa01 at <time> (TCP 389 and 443
  time out)`. **Stops:** a host that is down and a path that blocks look the same from here; nothing says it is gone.
- `... GSSAPI bind fails: the supplier could not reach a KDC` -> `this server's krb5kdc is not running` (local,
  fixable here).
- `... Kerberos clock skew` -> `ipa01's clock is 900 s ahead of ipa02's (measured from ipa02's root DSE)`. **Stops:**
  which clock is wrong is not established from one server; the peer's time service is never claimed to be stopped.
- `... server not found in Kerberos database` -> the peer's `ldap/` principal is absent from this server's COMPLETE
  list of `ldap/` principals (otherwise the chain stops at Kerberos).
- LDAP 49 is never jumped to "keytab mismatch": the supplier's bind is reproduced; a key the KDC rejects is the local
  key, a ticket obtained but a bind rejected by the peer is the peer's side (handoff), a bind that succeeds now is
  reported as not reproduced.

Roles are assigned per diagnosis (and its subject): PRIMARY and INDEPENDENT roots (a cause on this server is
preferred as PRIMARY), RELATED symptoms (with the cause that explains them), UNDIAGNOSED, CONTRADICTING (for example
topology segments and agreements that disagree), WARNING. Several chains may share a root (one stopped KDC explains
both suffixes' agreements); independent causes stay separate chains.

Transient states (replica busy, backoff, "No replication sessions started since server startup") are never green and
never a root cause.

RUV: an RUV element of THIS server whose host is not a current server in a COMPLETE topology read, with no clean task
running, is reported as a **candidate** (warning) with the read-only `ipa-healthcheck --source ipahealthcheck.ds.ruv`
as next step. It is never a global fact and no clean-up is printed.

## Resolution: the Safety gate and the No-Google gate

A fix is printed only for a cause on **this** server and only when every machine-checked condition holds:

- the deepest chain link is ESTABLISHED and is this diagnosis; the role is PRIMARY or INDEPENDENT; confidence is HIGH;
  nothing is UNDIAGNOSED, CONTRADICTING or TRANSIENT; no contradiction anywhere in the run;
- the subject is `server:<this host>`: a peer's cause never gets a command (no remote mutation, no SSH);
- the evidence is LIVE and at most 300 s old; REPLAY evidence never offers a fix (the same procedure and argv are
  shown as a clearly labelled preview for parity only);
- the exact target is re-checked with a FRESH check (a service that started meanwhile withholds the fix);
- topology predicates a procedure declares (sole CA/KRA/DNS holder, renewal master, DNSSEC key master, articulation
  point) must be established as safe from a complete topology read;
- the procedure is on the Slice 5 allowlist, its programs are allowlisted (`systemctl start` and its rollback
  `systemctl stop`), nothing in it matches a forbidden operation; then the Slice 1 gates (applicability by FreeIPA
  version, prerequisites, `withhold_if`, typed arguments) apply unchanged.

In this version the only procedure a replication diagnosis can lead to is `proc.service.start-stopped-service`, for
this server's stopped Directory Server or KDC. Everything else is deliberately "no fix printed", with the reason:
keytab replacement or ownership changes, re-creating a principal, adding a replication manager, clock steps,
re-initialization, force-sync, RUV clean-up, server removal, topology segment changes, enabling or disabling an
agreement, renewal-master/CRL/DNSSEC role changes.

**No-Google** is claimed only when the printed fix names its target, gives the exact command, the host each step runs
on, prerequisites shown as met, what changes, the expected result, what to do if a step fails, the risk, a backup (or
a reason from a closed list), a rollback (or a reason from a closed list), verification criteria tied to the original
incident, AND the procedure has a LIVE record (inject, confirm independently, run blind, apply only the printed steps,
fresh verify RESOLVED) on this exact FreeIPA version and OS. Otherwise the fix is still shown with what is missing.

## Verification and PENDING

`--verify` re-runs everything with fresh evidence and compares with the saved result (`replication_last.json`, a
validated, untrusted record; nothing from it is executed). For each earlier failing agreement it requires a
**successful session that ended after the saved result**, no update in progress, and that its cause no longer fails;
a cause is resolved only when every agreement it explained is. A collector failure, an agreement that is no longer
visible, another host or another `--peer` scope is UNABLE_TO_VERIFY, never RESOLVED. A reverse direction that cannot
be observed is never reported as verified.

**PENDING** (exit 3, never 0): the failure is gone but no fresh successful session has happened yet (or the agreement
is busy / backing off / has no session yet). It carries a next recheck time and is bounded: 10 minutes from the first
PENDING, after which it becomes STILL_PRESENT (still transient) or UNABLE_TO_VERIFY (no fresh session).

Exact RUV equality is **not** required: active multi-master topologies keep changing, so unequal sequence numbers
while fresh sessions succeed are not a failure.

## JSON

`replication_schema_version` 1.0 (additive; the diagnosis v1, access and client contracts are unchanged): `subjects`,
`relationships` (suffix, supplier, consumer, direction, observed_from, source, transport, bind method, port, state,
last session), `cause_chains`, `diagnoses` (key = `CODE@subject`, role, scope, related_to, explains), `resolutions`
(with `safety_gate` and `no_google`), `handoffs`, `completeness`, `topology`, `environment_graph`, `trace` (every step
with its subject), `verification`, `limitations`.

`ipa-diagnose bundle --replication [--peer FQDN]` adds `replication.json` to a support bundle: pseudonymized,
structure only (states, codes, chain capabilities and discriminators, step outcomes), no status text, no commands, no
principals, no LDAP entries; the Slice 2 pipeline and leak self-test apply unchanged.

## Limits

- One server's view. The reverse direction needs your Kerberos ticket and read access on the peer; other servers'
  RUVs are not read; nothing runs on another server.
- DNS answers, reachability and clock offsets are observed FROM this server and may differ elsewhere.
- Clock skew between two containers of one host cannot be produced in the live lab (they share the kernel clock):
  clock-skew chains are fixture-verified only.
- Stale RUV, changelog purge, generation-ID mismatch and replica-ID conflicts are fixture-only (reproducing them would
  mean damaging 389-DS on purpose).
- Validated live only on the FreeIPA version and OS in the truth matrix; nothing is claimed for other versions,
  RHEL, or other topology shapes.
- Slow resolvers dominate run time when a peer's name does not resolve (bounded by the per-check timeouts, not
  increased).
