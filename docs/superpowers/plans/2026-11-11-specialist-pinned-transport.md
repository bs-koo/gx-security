# Specialist pinned transport implementation plan

**Goal:** Apply approved numeric-IP connections and absolute wire/decoded response and operation budgets to every specialist HTTP path, then test the final code.

**Authorization:** The user explicitly requested this implementation and verification. Continue in the existing `codex/reliability-first-pass` worktree, preserving the previous 57 uncommitted files. No remote scan, commit, push, deployment or user-skill installation is requested.

**User checkpoint override:** The user subsequently explicitly requested stopping further third-pass work to commit, push and open a PR promptly because of remaining usage. Preserve all work in a draft PR. This authorizes commit/push/PR, not merge/deploy. Production editing was frozen. The third pass is incomplete and must not be represented as having passed the earlier 1,714-test broad run.

**Checkpoint validation:** core 72 passed; new integration 13 passed; independent TLS/CONNECT 5 passed; adjacent protected transport/scope 56 passed with 32 subtests. The affected legacy bundle has **22 failed / 313 passed / 36 subtests passed**. Remaining failures concern CONNECT proxy fixtures, old HTTPS-proxy expectations, fake hostname pin setup and verify-argument expectations. Full regression, rebuilt wheel and final independent review remain pending. Resume from `integration/affected-initial.txt` in the evidence directory; do not skip the failures or claim merge readiness.

**User resumption:** The user subsequently requested continuing the remaining third pass as far as possible. Inline implementation resumes from the existing checkpoint; earlier commit/push/PR authorization persists for PR #39, with no merge/deploy authorization. The checkpoint above is historical evidence, not the current failure count.

**Resume ledger (2026-11-11):** Reproduced 22 legacy fixture failures. The broader selected run reproduced 2 additional auth fixture failures (also observed in checkpoint CI), 559 passed and 61 subtests. Repaired only mock origin/proxy/verify expectations without bypassing scope. Five boundary cases reproduced TLS verification mutation, unsupported audit proxy preflight, and lost human-readable limit codes; all passed after fixes. Four further RED cases proved cleanup masking timeout/budget errors; preserving the original error while always closing the socket made them pass. Focused final fixes: **206 passed**; earlier core/integration/TLS group **104 passed** (overlapping, not additive). Test-only cryptography is explicit in CI so synthetic certificate tests are exercised. Full regression, final package and one fresh whole-branch review follow before claiming completion.

Resume evidence: `D:\Temp\gx-security-phase3-resume-20261111-6463c40c11854e928d4102e6a03dcf9a`.

**Final review:** One fresh read-only review covered 68 changed files. Its Important finding was fixed-code loss in SQLi/XSS/auth/access and login wrappers. `tests/test_specialist_limit_diagnostics.py` reproduced **30 failed** then **30 passed**; typed safe causes now survive the CLI boundaries with explicit undetermined state. The initial Linux full run was interrupted at 46% with exit 137 before this fix; its log is retained and is not a successful suite result. The final suites below run after the fix and a new source snapshot.

**Final: minor (deferred):** Direct `BoundedAdapter.send(stream=True)` currently returns a complete bounded buffered response instead of rejecting the option. The six CLI entrypoints reject streaming before dispatch; this does not bypass the response budgets.

**Final: minor (deferred):** The Burp skill's selection paragraph still says “sqlmap superiority”; automatic sqlmap execution remains explicitly unsupported by the SQLi implementation and its own skill. Correct that isolated wording in a later documentation pass.

**Review limits:** Rule accuracy across all 88 rules, actual host/AI evaluations, business-project pilot and deployment state remain outside this transport verification. Malicious arbitrary Python code inside the process is not a confinement boundary. The post-review fix is verified by regression tests, without a second reviewer pass.

**Architecture:** Keep Requests Session/PreparedRequest for query, JSON, multipart, auth and cookie preparation. Replace all network adapters with a bounded numeric-socket adapter in `tools/specialist_transport.py`. Separate a diagnostic operation's approval/budget context from temporary HTTP sessions. Do not loosen the protected release transport's canonical-path or approval contracts.

**Choice and tradeoffs:** A resolver preflight followed by ordinary Requests still permits DNS rebinding. Rewriting the prepared URL to an IP breaks Host/SNI and cookie provenance. The selected adapter preserves the original URL and connects directly to approved literal addresses without target DNS calls. Explicit origin-to-IP configuration is required for ordinary hostnames; literal targets and localhost have conservative defaults. Unsupported proxy routes fail before any connection.

## Public contract and defaults

- `canonical_origin(url)` returns exact scheme/IDNA host/effective port, rejecting userinfo, fragments, control characters and ambiguous authority, while preserving attack path/query payloads.
- `SECURITY_PLUGIN_TARGET_IPS` is a JSON object from canonical origin to arrays of approved literal IPs. It does not override existing hostname approvals or absolute IP prohibitions. The operation snapshots this input; later environment changes do not expand scope.
- `Limits`: 100 requests, 120 seconds per specialist invocation; 1 MiB wire and 1 MiB decoded per response; 8 MiB cumulative wire and 8 MiB cumulative decoded. Tests may lower limits. Environment variables do not grant unlimited increases.
- `OperationContext(target_urls, authorized_flag=False, target_ips=None, limits=None, proxy_url=None, ca_file=None)` owns immutable policy, lock, monotonic deadlines and counters.
- `BoundedAdapter(operation)` returns a complete bounded Requests response. Unsupported streams, malformed/incomplete framing, decode failures and limits return fixed errors, never partial successful bodies.
- Raw read accounting covers status, headers, chunk framing, CONNECT and payload. Incremental gzip/deflate decoding has an independent output cap and deadline. Unknown, stacked, truncated or concatenated encodings fail closed.
- Supported proxy routing is an explicitly approved literal-loopback HTTP proxy with numeric CONNECT tunnels for both HTTP and HTTPS targets. Original Host/SNI remain inside the tunnel. HTTPS proxy transport is explicitly unsupported in this iteration; there is no direct/hostname fallback.
- A cookie/auth session is bound to its first exact origin, including port. Cross-origin upload retrieval is rejected before upload/authentication until separate credential policy is supported. Redirects are not automatically followed.

## Ownership and execution

### A. Core adapter — core worker

Ownership: new `tools/specialist_transport.py`, new `tests/test_specialist_transport.py`.

- [x] Observe RED for missing boundary and reproduce DNS/limit defects with loopback and fake network objects.
- [x] Implement immutable approved endpoints, numeric socket/TLS/proxy routing, strict framing and bounded decoding/cleanup.
- [x] Run focused core tests and share API and supported routing matrix with integration worker.

### B. Specialist integration — integration worker

Ownership: `tools/dyn_session.py`, six attack CLI entrypoints and their affected tests, new integration tests.

- [x] Observe RED for context lifetime, auth-before-policy, exact-origin session binding and adapter bypass.
- [x] Open/reset one diagnostic context around every CLI's login and probes; keep anonymous and replacement sessions on the same budget.
- [x] Replace pre-existing longer-prefix adapters, preserve explicit auth/cookies/multipart and propagate fixed limit errors as undetermined.
- [x] Run all affected specialist/session tests without duplicating the final whole suite.

### C. Independent boundary proof and adjacent cleanup — coordinator

Ownership: new adversarial loopback/TLS/proxy tests, `src/gxsec/transport.py` and dedicated lifetime tests, `tools/scope_guard.py`, output diagnostics and documentation.

- [x] Reproduce protected transport lease rollback and cleanup masking; correct monotonic lease upper bound and always-close behavior without changing its path policy.
- [x] Reject absolute prohibited IPs even when listed and preserve ordinary approved loopback/private targets.
- [x] Independently verify real hostname Host/SNI/certificates, numeric CONNECT, multiple cookies, slow framing/body and gzip limits, cumulative accounting, no target DNS and no credential crossing.
- [ ] Review worker code and resolve material findings before freezing source and running broad Windows/Linux regressions.
- [ ] Verify a newly built wheel, current source parity and catalog/CLI help; record exact results, supported behavior and remaining limitations.

## Validation discipline

Only synthetic loopback endpoints, fake clocks/resolvers and local test certificates are used. Add failure cases before implementation; preserve normal responses, form data, SQL/XSS controls and cleanup observations. Freeze all source and test inputs before final broad execution. Record failed/interrupted attempts separately and do not add overlapping test totals.

Evidence directory: `D:\Temp\gx-security-phase3-20261111-1403a9a708f1401c8e4ccebcdc34eef5`.

Final Windows after review fix: **1,860 passed / 25 skipped / 337 subtests passed**, **923.97 seconds**, `GXSEC_NO_SEMGREP=1`; source/test/config/skill snapshot **247 files** unchanged. Linux full pinned-engine suite, current wheel and final help smoke are next. These counts supersede the historical checkpoint failures, not the remaining minor items or external pilot/evaluation limits.

Linux follow-up: the Windows bind-mount run waited in `p9_client_rpc` and was stopped (exit 137); a byte-verified, read-only native Linux copy was used instead. Its interrupted full run recorded **1 failed / 1,421 passed / 99 skipped** (exit 2), not a passing full suite. The failure was the framework identity fixture allowing real Gitleaks to create `.gxsec` inside the source between comparisons: observed exclusions changed, so scope correctly changed. Reconstructing the coverage payload exactly reproduces the recorded hashes (`f22db56f...` before state, `bd8996c9...` after state). The fixture now keeps its fingerprint state outside the source without changing production scope policy or weakening either assertion. The full related Windows file passed **25 tests** afterwards. This test fixture is the only input changed after the 1,860-test Windows run; production code is identical. A new 247-file baseline and a complete 319-file source archive were frozen for Linux verification. The selected Linux run includes all affected specialist/session/transport tests, the repaired framework fixture, pinned-engine goldens, rule-quality/ignore/scope contracts and workflow/wheel tests. Canonical full-platform coverage will also be checked in PR CI.

**Latest user endpoint override:** Stop further Linux verification; Windows evidence is sufficient for the requested checkpoint. Commit/push and update existing PR #39 now. The user will perform the business-project pilot later. This checkpoint ends at PR update; no merge, deployment, version bump or additional local Linux run is performed. Preserve unresolved results and keep the PR draft.

**Linux saved state:** affected run **1 failed / 498 passed**, 591.23 seconds. The repaired framework file contributed 25 passing cases. Remaining failure is the attested-ZAP bundle fixture in `tests/test_gxsec_dynamic.py`: collecting the selected files can load the checkout `gxsec.py` bridge as `gxsec`, whose module spec has no submodule search locations although `__path__` points at `src/gxsec`. The isolated case passes; collecting the same set with only that case selected reproduces **1 failed / 718 deselected**. `native-spec-probe.json` records the root shim origin and null spec locations. Runtime-closure implications and repair remain unverified; do not call this a passing Linux run or a resolved production issue. No new wheel was rebuilt after these third-pass changes. The 247-file frozen source remains unchanged after the test-only state-directory correction.

References: installed Requests 2.34.2 and urllib3 2.7.0 source; [Python 3.12 HTTPConnection](https://docs.python.org/3.12/library/http.client.html#http.client.HTTPConnection.set_tunnel); [AWS IMDS IPv4 and IPv6 endpoints](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html). This is transport verification, not an expansion of 88-rule accuracy, host/model evaluation or a business-project pilot.
