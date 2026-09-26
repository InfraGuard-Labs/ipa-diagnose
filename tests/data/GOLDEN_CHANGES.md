# Deliberate changes to the v0.1.3 compatibility goldens

`v1_json_golden.json` and `console_golden_v013.json` were captured from the unmodified v0.1.3 code. They are
never regenerated wholesale. An entry is changed only when a documented correctness fix changes that
fixture's output, and every such change is listed here.

| Fixture | Change | Why |
|---|---|---|
| `dns/named-down` | `dns.srv-autodiscovery` moves from SECONDARY_INDEPENDENT_PROBLEM to RELATED_SYMPTOM of "named failed to start" (`related_to_titles`, and the "Likely a downstream symptom" sentence in `why`/console) | Slice 1 hardening, fresh red-team finding: with this server's named stopped its records cannot be resolved at all, so "records broken" is a symptom of the stopped service, not an independent problem. v0.1.3 could only demote across packs (the fixture's own notes said so). |
| `real-freeipa-capture/healthy`, `real-freeipa-capture/dirsrv-down`, `real-freeipa-capture/dirsrv-stopped` | the `impact` of "File ownership/mode mismatch" for the CS.cfg 0664-vs-0660 finding (and its console IMPACT line) | Slice 1 hardening, live-lab truth review: a mode that is only too permissive cannot stop a service; v0.1.3 said "dirsrv ... can fail to start". It now says the file is exposed to more local users and that no service is stopped. Owner/group and too-restrictive modes keep the old impact text. |

Everything else in both files is still byte-for-byte v0.1.3 output.
