# Second-pass reliability implementation plan

**Goal:** Close reproduced reliability gaps in specialist request isolation, evaluation retention, CLI validation and CI/package evidence.

**Authorization:** The user's continuation follows the explicit request to implement audit/benchmark improvements through testing. Preserve the first-pass uncommitted changes and the existing isolated worktree. No commit, push, installation into user skill directories or deployment is requested.

**Architecture:** Reuse the current requests/session interface with explicit environment isolation; retain the current corpus with a separate reviewed baseline contract; verify a freshly built wheel in a temporary offline installation. Keep scanner execution, rule coverage, model/host behavior and organization approval distinct.

**Alternatives:** Adding an engine does not repair these reproduced defects. Expanding synthetic cases alone also leaves corpus shrinkage undetected. This iteration first protects the existing evidence and execution contracts, with targeted positive/negative controls. This is the coordinator's implementation choice within the continuing reliability task.

**Technology:** Python 3.12, Requests 2.34.2, pytest, existing hash-locked Linux runtime, official GitHub action revisions.

## A. Specialist request isolation

Owner: specialist worker. `tools/dyn_session.py`, SQLi request wiring and affected tests.

- [x] Reproduce environment proxy/netrc/CA inheritance and unvalidated remote proxy use.
- [x] Use sessions with `trust_env=False`, explicit TLS verification and validated literal-loopback Burp proxy configuration. Preserve intended cookies/authentication and disable redirects.
- [x] Route SQLi's remaining direct requests and XSS's anonymous urllib path through the common isolated request seam.
- [x] Prove environment proxy avoidance and explicit local proxy behavior with loopback servers, plus session/login/form regressions.

## B. Evaluation evidence retention

Owner: static worker. `scripts/evaluate-rule-quality.py`, `tests/test_gxsec_rule_quality.py`, baseline-contract fixture.

- [x] Reproduce successful evaluation after deleting baseline cases/negative controls.
- [x] Preserve the reviewed 28 cases, rule/label associations, source evidence and known limitations through an explicit baseline contract. Allow actual detector improvement without freezing TP/FP/FN totals.
- [x] Distinguish custom-corpus evaluation from the default baseline; retain explicit unevaluated rules.
- [x] Run contract regressions and the actual pinned-engine baseline without changing the labels to match the implementation.

## C. CI trust boundary

Owner: CI worker. `.github/workflows/ci.yml`, `deploy-pages.yml`, dedicated workflow checks.

- [x] Reproduce mutable action references, credential persistence and excessive default permissions.
- [x] Verify official action revisions and pin the existing major versions to full SHAs. Use read-only default permissions and job-scoped publication rights.
- [x] Keep triggers, experimental engine matrix and publication behavior unchanged; do not run or publish a remote workflow.

## D. CLI and distribution evidence

Owner: coordinator. `tools/scope_guard.py`, XSS instructions, historical audit banner, package verification script/tests and final documentation. Add the package CI step only after the CI worker finishes editing that workflow.

- [x] Reproduce unknown scope CLI arguments being silently accepted; reject unknown/abbreviated arguments and correct the XSS example.
- [x] Turn the previously manual wheel build/install/source-parity check into a reusable offline verification command and a CI gate. Test missing, modified and unexpected runtime files.
- [x] Mark historical v0.3 adoption claims as historical rather than current readiness evidence.
- [x] Independently review changes, run affected tests and the integrated regression, validate current source with real pinned engines, record exact results and limitations.

## Executed verification

- Final Windows regression, after freezing all production code and correcting the test fixture: **1,714 passed, 25 skipped, 337 subtests passed** in 830.91 seconds. `GXSEC_NO_SEMGREP=1`; actual engine execution is measured separately.
- Final affected bundle: **552 passed, 1 skipped, 61 subtests passed**. The subsequent test-order isolation repair is covered by the final broad run and the ordered 12-case rerun.
- Linux pinned-engine/rule/contract checks: **109 passed, 0 skipped**. Final Linux request/XSS/fixture-order regressions: **107 passed, 0 skipped**. These are overlapping scopes, not additive totals.
- Actual Semgrep 1.172.0 evaluation: baseline contract satisfied for the unchanged **28 cases / 12 of 88 rules**; TP 13, FP 1, FN 1, TN 13, no unscanned case. No detection-accuracy improvement is claimed.
- Wheel build, exact runtime/resources parity and isolated installation/import passed in a network-disabled read-only container: **69 files**. Unexpected top-level packages and unrelated distribution metadata are rejected as well as missing/stale files and duplicate ZIP entries.
- Catalog inspection: **22 skills**, **125 local references**, **16 CLI help calls** from an empty temporary consumer directory, all passed. One pure helper was not executed. This is not a host/model behavior evaluation.
- Independent reviews found and resolved login error conversion, owned form-session cleanup, extra-package rejection and test-environment restoration defects. No open actionable issue remains in the reviewed scope.
- The initial broad run found two loopback failures. Their cause was the new positive proxy-preflight test writing an environment variable after an unrecorded `monkeypatch.delenv` on an absent key. The identical sequence first reproduced **2 failed / 10 passed**, then passed **12/12** after recording and restoring key absence as well as its value. The intermediate rerun was stopped and its log retained. Only the subsequent clean broad run above is reported as the final broad result.
- A 229-file code/configuration/skill-contract snapshot was compared again after the final run; no input changed during verification. The report/operations prose was finalized separately.

The work remains local and uncommitted. CI configuration was inspected and its commands exercised locally; no remote CI execution, publishing, user skill registration or organization approval was performed.

## Scope and remaining work

The 22-skill catalog and its 16 Python entrypoint help commands were inspected as local contracts. This is not execution of 22 host/model behaviors. The existing eight host scenarios still require observed tool traces and actual host evaluation.

Legacy specialist DNS/IP pinning and absolute response/time budgets remain a separate transport integration requirement; environment isolation must not be described as solving those. The protected integrated transport remains the release-oriented dynamic path. Broader rule labels, real-business-project holdout/pilot data and organization approval are not invented by this iteration.

Evidence directory: `D:\Temp\gx-security-phase2-20261111-352c8905d25c49e2bad1d00a1c4c6cba`. First-pass hashes are retained as `first-pass-baseline.json`.

References: [Requests session API](https://requests.readthedocs.io/en/latest/api/#requests.Session.trust_env), [Requests proxies](https://requests.readthedocs.io/en/latest/user/advanced/#proxies), and the [first-pass benchmark principles](2026-11-11-first-pass-reliability.md#benchmark-principles-applied).
