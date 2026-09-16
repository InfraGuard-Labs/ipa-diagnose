# Contributing

## Everything runs in Docker

Nothing is installed on your host. From the repo root:

```bash
docker compose build dev
docker compose run --rm test          # full suite
docker compose run --rm dev bash      # interactive shell
docker compose run --rm dev ipa-diagnose --replay tests/fixtures/replication/healthy diagnose
```

## Adding or changing a diagnostic rule

1. Read `src/ipa_diagnose/engine/packs/base.py` and `engine/model.py` first
   - the contract (return `None` when not applicable; `DIAGNOSED` requires
   HIGH/MEDIUM confidence, enforced at runtime; every `EvidenceRef` must
   point at real evidence in the bundle) is not optional.
2. Cite your sourcing. Every existing rule's `Confidence.rationale` states
   whether it's backed by primary documentation/source code (HIGH),
   community corroboration (MEDIUM/LOW-leaning), or a single source (LOW) -
   new rules should do the same, and a LOW-confidence rule should usually
   resolve to `UNKNOWN_INSUFFICIENT_EVIDENCE` rather than `DIAGNOSED`.
3. **Add a fixture with an expected outcome.** A new rule needs at least:
   a `healthy/`-style negative case (already exists per pack), one fixture
   per root cause it introduces, and one fixture demonstrating the case
   where it correctly refuses to guess. Fixture format: `healthcheck.json`
   (an `ipa-healthcheck`-shaped JSON array) + any collector fixture files
   your rule's collectors need + `meta.json` documenting
   `{hostname, scenario, expected_overall_status, expected_diagnoses, notes}`.
4. Add the fixture-driven test to `tests/packs/test_<pack>_pack.py`
   following the existing pattern (`collect_evidence(replay_dir=...)` →
   `run_diagnosis(bundle)` → assert against `meta.json`).
5. If your rule reads evidence a generic `journal_line`-style kind would
   ambiguously match another pack's collector, use a pack-specific kind name
   (see `dirsrv_journal_line`/`pki_journal_line`/`named_journal_line`/
   `krb5kdc_journal_line` for the pattern) - a shared generic kind was a
   real bug found during development (one pack's log lines corroborating
   another pack's rule).
6. Run `docker compose run --rm test` and confirm the **whole** suite is
   green, not just your new test.

## Adding a collector

Implement `evidence/collectors/base.py`'s `Collector` interface: both
`collect_live()` (a `subprocess.run()` call with an **argument list**, never
`shell=True` - enforced by `tests/adversarial/test_command_injection.py`)
and `collect_replay(fixture_dir)` (reads a fixture file you define the shape
of, documented in your collector's own docstring). Register it in
`evidence/collectors/registry.py`'s `module_names` list, and add your
collector's name to the relevant pack's `additional_collectors`.

## "I'm not sure" is a correct answer

A rule reaching `UNKNOWN_INSUFFICIENT_EVIDENCE` or
`UNKNOWN_CONFLICTING_EVIDENCE` (with a concrete, safe
`next_diagnostic_step`) is not a bug to fix - it's the intended behavior
when evidence genuinely doesn't support a confident call. A confident false
diagnosis is a much more serious defect than an honest "I don't know" one.
Review feedback that pushes a rule toward guessing more often is working
against this project's core design principle, not toward better UX.

## Code review expectations

- No new hard dependency for `--no-ai` mode. AI provider SDKs stay optional
  extras (see [docs/ai-configuration.md](ai-configuration.md) for why).
- Security-sensitive changes (redaction patterns, the AI sanitizer,
  anything touching `evidence/collect.py`'s staged collection) should come
  with a new adversarial test, not just a positive-path test.
- Don't set `Diagnosis.priority` from rule code - `engine/correlate.py` owns
  prioritization centrally, by design (see
  [docs/architecture.md](architecture.md#correlation-and-prioritization-enginecorrelatepy)).

## License

Apache-2.0 (see [LICENSE](../LICENSE)) - contributions are accepted under
the same license.
