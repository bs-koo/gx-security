# Security credibility hardening implementation plan

> For agentic workers: implement the assigned independent ownership lanes, then review the integrated change. The user approved the audit remediation work; no further design approval is pending.

**Goal:** Prevent false remediation approval and missing framework checks, repair rule/workflow defects, and provide reproducible evaluation and usable operational instructions.

**Architecture:** Preserve the immutable scan and protected approval model. Absent SAST findings require current-source remediation evidence. Framework expectations add obligations to automatic detection. Existing engines and host skills remain the execution path.

**Tech stack:** Python 3.10+, pytest, Semgrep 1.172.0, PowerShell, Docker.

**Spec:** Internal 2026-11-10 credibility audit; public requirements are enumerated below without business source or findings.

## Constraints and review focus

- Keep source-only static checks isolated; never make missing evidence PASS.
- Preserve user changes, old runs, IDs, and exact engine pins. Keep business remediation findings in the framework repository, outside this public package.
- Do not equate synthetic precision with actual project accuracy, or agent-reviewed labels with independent organizational approval.
- Risk-preserving helper extraction must not close a previous finding.
- Required SEF inspection must survive naming/module changes or stay incomplete.
- Old reviews, source changes, malformed requirements, and incomplete checks must not authorize closure.
- Recheck instructions must preserve run ID, profile, source, and state in native and Docker workflows.
- Runtime preparation must retry only transient failures, verify hashes, and never silently fetch during a scan.

## Task 1: Remediation trust

Files: `src/gxsec/state.py`, `src/gxsec/policy.py`, relevant core/lifecycle tests.

- [x] Add failing risk-preserving disappearance, previous High, stale/untrusted review, partial scope, and valid-resolution tests.
- [x] Carry absent SAST as remediation-proposed with current result binding.
- [x] Accept explicit protected `remediation-validation` only with current input and independent roles; preserve evidenced SCA closure.
- [x] Run focused regression tests and retain red/green evidence.

## Task 2: Framework expectations

Files: `src/gxsec/framework.py`, `src/gxsec/config.py`, framework tests, `docs/SEF-CHECKS.md`.

- [x] Reproduce renamed/split SEF misses and expected-family absence.
- [x] Merge additive project and protected `framework.expected_family`/`required_contracts` obligations without weakening.
- [x] Examine inherited build/module evidence conservatively; missing required contracts remain incomplete.
- [x] Run focused generic/SEF/invalid-policy controls.

## Task 3: Individual rule and workflow accuracy

Files: access-control rule, rule metadata/evaluation artifacts, professional skills.

- [x] Add actual-engine positive/negative/reordered CORS tests; fix alternative logic.
- [x] Assign reviewable initial severity metadata without promoting candidates to verified findings.
- [x] Remove HTTP-status-only confirmation and credential-in-argv instructions.
- [x] Expand independently reviewed synthetic evaluation cases and expose unsupported/missed cases honestly.

## Task 4: Runtime and report handoff

Files: `scripts/gxsec.ps1`, `scripts/install-engines.py`, `src/gxsec/reporting.py`, CLI if needed, runtime tests and docs.

- [x] Test transient retry/hash failure, protected readonly policy/DB mounts, invalid paths, and scan isolation.
- [x] Add bounded download retries and optional verified cache for preparation.
- [x] Repair report recheck instructions for original run/state and concrete QA expectations.
- [x] Correct stale invocation/version docs and provide reproducible host registration instructions.

## Task 5: Framework remediation handoff (separate repository)

- [x] Read existing security documents and current public/private source.
- [x] Document only current source-backed problems with counterevidence, fix direction, acceptance scenarios, revision and scope.
- [x] Link historical security documents; preserve framework source and existing user changes for the requested follow-up fixes.

## Task 6: Integrated validation and delivery

- [x] Run the full regression suite once the integrated changes stabilize.
- [ ] Run pinned-engine regressions, build/packaging and isolated runtime smoke.
- [x] Review source/trust/operations changes independently and resolve material findings.
- [x] Update version, concise README/site/status/changelog consistently.
- [ ] Record measured coverage, remaining real-user/independent-review limits and framework handoff paths.

Review limits: independent model reviews are not organizational approval or human-labeled ground truth. The 28-case evaluation measures candidate detection expectations for 12/88 rules; five simple negative controls and conditional examples limit its interpretation. See `docs/RULE-QUALITY.md` and its label review. Host behavior fixtures are provided but have not been executed in actual user sessions. Supported remediation closure is currently limited to SAST/framework and SCA; other legacy closure markers remain incomplete.
