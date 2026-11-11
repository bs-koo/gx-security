# Specialist pinned transport implementation plan

**Goal:** Apply approved numeric-IP connections and absolute wire/decoded response and operation budgets to every specialist HTTP path, then test the final code.

**Authorization:** The user explicitly requested this implementation and verification. Continue in the existing `codex/reliability-first-pass` worktree, preserving the previous 57 uncommitted files. No remote scan, commit, push, deployment or user-skill installation is requested.

**User checkpoint override:** The user subsequently explicitly requested stopping further third-pass work to commit, push and open a PR promptly because of remaining usage. Preserve all work in a draft PR. This authorizes commit/push/PR, not merge/deploy. Production editing was frozen. The third pass is incomplete and must not be represented as having passed the earlier 1,714-test broad run.

**Checkpoint validation:** core 72 passed; new integration 13 passed; independent TLS/CONNECT 5 passed; adjacent protected transport/scope 56 passed with 32 subtests. The affected legacy bundle has **22 failed / 313 passed / 36 subtests passed**. Remaining failures concern CONNECT proxy fixtures, old HTTPS-proxy expectations, fake hostname pin setup and verify-argument expectations. Full regression, rebuilt wheel and final independent review remain pending. Resume from `integration/affected-initial.txt` in the evidence directory; do not skip the failures or claim merge readiness.

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

- [ ] Observe RED for missing boundary and reproduce DNS/limit defects with loopback and fake network objects.
- [ ] Implement immutable approved endpoints, numeric socket/TLS/proxy routing, strict framing and bounded decoding/cleanup.
- [ ] Run focused core tests and share API and supported routing matrix with integration worker.

### B. Specialist integration — integration worker

Ownership: `tools/dyn_session.py`, six attack CLI entrypoints and their affected tests, new integration tests.

- [ ] Observe RED for context lifetime, auth-before-policy, exact-origin session binding and adapter bypass.
- [ ] Open/reset one diagnostic context around every CLI's login and probes; keep anonymous and replacement sessions on the same budget.
- [ ] Replace pre-existing longer-prefix adapters, preserve explicit auth/cookies/multipart and propagate fixed limit errors as undetermined.
- [ ] Run all affected specialist/session tests without duplicating the final whole suite.

### C. Independent boundary proof and adjacent cleanup — coordinator

Ownership: new adversarial loopback/TLS/proxy tests, `src/gxsec/transport.py` and dedicated lifetime tests, `tools/scope_guard.py`, output diagnostics and documentation.

- [ ] Reproduce protected transport lease rollback and cleanup masking; correct monotonic lease upper bound and always-close behavior without changing its path policy.
- [ ] Reject absolute prohibited IPs even when listed and preserve ordinary approved loopback/private targets.
- [ ] Independently verify real hostname Host/SNI/certificates, numeric CONNECT, multiple cookies, slow framing/body and gzip limits, cumulative accounting, no target DNS and no credential crossing.
- [ ] Review worker code and resolve material findings before freezing source and running broad Windows/Linux regressions.
- [ ] Verify a newly built wheel, current source parity and catalog/CLI help; record exact results, supported behavior and remaining limitations.

## Validation discipline

Only synthetic loopback endpoints, fake clocks/resolvers and local test certificates are used. Add failure cases before implementation; preserve normal responses, form data, SQL/XSS controls and cleanup observations. Freeze all source and test inputs before final broad execution. Record failed/interrupted attempts separately and do not add overlapping test totals.

Evidence directory: `D:\Temp\gx-security-phase3-20261111-1403a9a708f1401c8e4ccebcdc34eef5`.

References: installed Requests 2.34.2 and urllib3 2.7.0 source; [Python 3.12 HTTPConnection](https://docs.python.org/3.12/library/http.client.html#http.client.HTTPConnection.set_tunnel); [AWS IMDS IPv4 and IPv6 endpoints](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html). This is transport verification, not an expansion of 88-rule accuracy, host/model evaluation or a business-project pilot.
