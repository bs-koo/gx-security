# First-pass reliability repair implementation plan

**Goal:** Repair the reproduced false completion, false verdict, evidence disclosure, scope accounting and execution-boundary defects, then verify the integrated code.

**Authorization:** The user explicitly requested implementation of the first-pass reliability repairs, incorporating the preceding audit and benchmarking, through tests and verification. No commit, push, deployment or third-party installation is requested.

**Baseline:** Public main `6cb2210b8241475e579d19af562dc10595f02734`; its tree equals the audited `c073bd7` tree. The preceding local baseline was 1,446 passed, 25 skipped and 337 subtests passed. Pinned/latest Linux scope tests have a separately reproduced incomplete runtime fixture.

**Architecture:** Preserve the current result model, protected policy, scope broker, immutable history and supported remediation approvals. Extend their conservative contracts to the affected specialist scripts. Missing evidence, unavailable support and failed requests must remain undetermined or incomplete. No new scanning engine is introduced.

**Technology:** Python 3.12; pytest; pinned offline Linux engines in the existing Docker runtime; loopback-only application fixtures.

## Acceptance and review focus

- JSON null is distinct from missing, invalid or unresolved pointers; missing evidence cannot satisfy an authorization oracle.
- Slow status/header/body I/O respects the absolute transport deadline and closes its connection; retries and redirects preserve existing budgets.
- SQL errors, file signatures, Location headers and OOB absence require their appropriate baseline/control/response evidence; absence is not a safe verdict.
- Response excerpts do not retain credentials or personal data in machine or human output. Upload evidence does not claim code execution or automatic cleanup; no deletion endpoint is guessed.
- Generic Kotlin scanning does not fulfill absent language-specific rule coverage. Non-interceptable method annotations do not suppress authorization review without an independently modeled applicable guard.
- The real-engine scope fixture includes the runtime dependencies required to start its approved executable without inheriting the host PATH or weakening production approval.
- Existing valid positive fixtures, defensive controls, source integrity, fail-closed scope and independent remediation approvals continue to work.

## Ownership and execution

### A. Integrated dynamic verification

Owner: dynamic worker. Files: `src/gxsec/dynamic.py`, `src/gxsec/transport.py` and their dedicated tests.

- [x] Add and observe failing null/missing and slow-header regression tests, including valid-null and ordinary response controls.
- [x] Implement the smallest correction, including error/timeout cleanup and type-safe oracle comparisons.
- [x] Run affected dynamic and transport tests; record red/green evidence.

### B. Specialist dynamic verdicts and evidence

Owner: specialist worker. Files: SQLi, SSRF and path/upload attack scripts, `tools/redaction.py`, `tools/dyn_session.py` only where required, and their dedicated tests.

- [x] Add and observe failing baseline/control, OOB absence, redirect status and evidence disclosure regressions.
- [x] Repair verdicts while retaining valid positives and authentication wiring.
- [x] Make upload observation and cleanup status honest; do not infer RCE or silently delete data.
- [x] Run specialist tests; record red/green evidence.

### C. Static coverage, framework applicability and Linux scope fixture

Owner: static worker. Files: `src/gxsec/adapters.py`, `src/gxsec/framework.py`, `tests/test_semgrep_scope.py`, and dedicated static/framework regressions.

- [x] Add and observe failing scanned-Kotlin and private/final authorization tests with positive applicable-guard controls.
- [x] Correct scope/applicability accounting and the approved Linux fixture dependencies.
- [x] Run relevant regressions; leave actual pinned-engine verification to integrated validation.

### D. Documentation, integration and independent review

Owner: coordinator. Files: affected skill/reference documentation, reporting text as needed, and this plan.

- [x] Align contradictory specialist verdicts, CLI examples and supported limits with the actual repaired behavior.
- [x] Obtain independent review, resolve material findings and rerun affected tests.
- [x] Run the full local regression suite and real pinned-engine checks, plus current-source offline runtime smoke.
- [x] Record exact outcomes, skipped/unverified scope and remaining second-phase work without claiming production certification.

## Executed validation

- Windows broad regression: **1,572 passed, 25 skipped, 337 subtests passed** in 769.24 seconds, using Python 3.12 / pytest 9.1.1 and `GXSEC_NO_SEMGREP=1`.
- The broad run started before the final retrieval-diagnostic and summary-wording repairs. The final affected specialist/session/reporting bundle was rerun against the final source: **256 passed** in 13.64 seconds. Counts overlap and are not added.
- Linux pinned-engine scope/rule/quality/golden/static regressions: **60 passed, 0 skipped**, Semgrep 1.172.0.
- Offline current-source integration: synthetic Kotlin remained incomplete despite being read; synthetic vulnerable dependency BLOCK became PASS/fixed-verified after changing its version. Semgrep 1.172.0, OSV-Scanner 2.7.0 and Gitleaks 8.30.1 completed their checks with networking disabled.
- Wheel built and installed into a disposable path, with **42 current-source core/tool/rule files** compared byte-for-byte. The specialist host skills are distributed through the plugin checkout, not this static-runtime wheel. Missing host setuptools was bypassed by using the existing fixed Linux build environment; no host package was installed.
- Independent code review findings were repaired and rechecked. Follow-up documentation review exposed residual summary and prerequisite-note promises; five regression scenarios first failed, then passed after correction. Full-host skill execution, a real business-project pilot and remote CI remain unverified.

Logs, JUnit XML, build verification scripts and RED/GREEN evidence are stored in `D:\Temp\gx-security-reliability-20261111-85b12715083d41a3b3d266c697b99c64`. The work remains local on `codex/reliability-first-pass`; it is not committed, pushed or deployed.

## Benchmark principles applied

Use baseline/test/control evidence as illustrated by [Burp BChecks](https://portswigger.net/burp/documentation/scanner/bchecks/worked-examples/log4shell); separate job completion from security coverage as in [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/); preserve known rule limitations as in [Semgrep rule testing](https://docs.semgrep.dev/writing-rules/testing-rules). Existing finding review packets and display-only grouping are retained, not rebuilt.

## Deferred scope

Full 88-rule ground-truth expansion, new Snyk/Sonar/CodeQL adapters, automatic browser/host rollout, organization-wide policy deployment and real-user pilots remain second-phase work. This repair does not claim those are complete.
