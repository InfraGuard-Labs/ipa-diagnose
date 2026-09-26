"""Resolution framework (1.0 Slice 1).

Turns a *mature, deterministic* diagnosis into a versioned, applicability-checked,
risk-labelled and verifiable procedure - or says plainly that none applies.

Safety contract (see docs/resolution.md):

* Procedures are **data** (``knowledge/procedures/*.yaml`` compiled to
  ``procedures.json``), validated strictly at load time. Data never executes.
* ipa-diagnose only ever **runs read-only checks** (a closed registry in
  :mod:`ipa_diagnose.resolution.checks`). Every fix is **printed, never executed**.
* A procedure is shown only when the diagnosis is confident enough, its
  applicability is established from collected facts, no contradicting evidence
  was found, and every prerequisite was checked and met. Otherwise the report
  says why it was withheld.
* Command arguments come only from typed, validated values (never free text).
"""
