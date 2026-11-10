# Pilot recovery implementation plan

**Goal:** Diagnose actual engine failures, bound resource use, improve large Windows project execution, and verify representative framework variants and forked applications using preserved local evidence.

**Architecture:** Keep source identity, independent snapshots and conservative release decisions. Add bounded structured diagnostics and execution accounting first. Optimize only with byte identity and isolation preserved; execution completion is separate from release approval.

**Spec:** User-approved execution recovery: diagnose failures before changing engine behavior; preserve evidence and source integrity; bound resource use; record explicit scope choices; validate actual application runs separately from release approval.

## Constraints

- Do not change application source, fabricate approval or omit difficult inputs silently.
- Preserve previous results; record image, code, scope, duration and remaining gaps per new run.
- Do not publish business source or reports in the public plugin repository.
- Do not reduce snapshot integrity to mtime/size cache validation.

## Tasks

- [x] Reproduce nonzero-output diagnostic loss; preserve safe structured errors and partial findings without a passing gate (adapters/diagnostics tests).
- [x] Reproduce large-file memory allocation; stream snapshot hashes and preserve handle/race checks (snapshot tests).
- [x] Diagnose Git mirror and Semgrep with bounded small reproductions; fix demonstrated cause and add regression. Git ownership rejection was reproduced and fixed with a private exact-path trust configuration. Semgrep small-input reproductions completed; the old discarded exit-2 diagnostic cannot be reconstructed.
- [x] Add monotonic execution deadline, working-tree byte budgets, phase timings and heartbeat, with persisted INCOMPLETE reports on exhaustion (execution/source/CLI tests).
- [x] Add inexpensive input planning and integrated workflow guidance; record explicit choices and limits.
- [x] Measure bounded Windows input reads, remove redundant metadata work, and stream private-file hashing while preserving original-source correspondence. Repeated full integrity checks remain; OS-enforced immutable snapshot optimization is deferred until independently validated.
- [ ] Build image, run appropriate regression and independent review, then run actual public/private/KREB checks with comparable timings and full gap reporting.
- [ ] Update usage, result documents, existing PR and final evidence. No automatic merge.

## Review focus

- Failures before initial inventory must still produce a useful bounded result.
- Deadline and subprocess output limits cannot turn partial scans into clean results.
- Error paths must not expose secrets or unbounded output.
- Windows reparse paths and POSIX special files must not escape or hang collection.
- Actual application vulnerabilities and missing approvals remain visible after successful execution.
