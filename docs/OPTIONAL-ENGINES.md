# Optional Trivy, CodeQL and Nuclei engines

These adapters consume real engine-native reports or invoke the fixed reference
runner. They do not install scanners, acquire licenses, download databases or
templates, build a project, or provision network isolation. Missing prerequisites
produce `unsupported` or `incomplete`; zero findings alone never proves coverage.
All normalized findings remain candidates for review.

The automated tests use native-format fixtures and a subprocess boundary. They
do not constitute a live Trivy, licensed CodeQL, or Nuclei execution claim.

## Selection and trust

Project configuration can request an engine with
`tools.<engine>.enabled: true`, and can add `required: true`. Protected policy can
select it with `optional.<engine>.enabled` or `required`; project settings cannot
disable an organization-required check. With no selected optional engine the
adapter returns no optional checks.

Only the independently loaded `_trusted_policy` input supplies approvals and
execution inputs. A project report, path, approval name, or project-selected
command grants no execution or completion authority.

Each `optional.<engine>` entry provides **one** of `evidence` and `plan`. Both
records have the following fields:

| Field | Required meaning |
| --- | --- |
| `id` | Unique protected record identifier |
| `engine.name` | `trivy`, `codeql`, or `nuclei` |
| `engine.version` | Exact approved semantic version |
| `engine.digest` | `sha256:` followed by the scanner executable's 64 lowercase hex characters |
| `source_revision` | Current `collect_source(...)["revision"]`: clean commit or effective content revision |
| `source_hash` | Current `collect_source(...)["hash"]` |
| `scope_hash` | Current source inventory scope hash, also matching protected policy |
| `expires_at` | Future ISO-8601 timestamp with timezone |
| `coverage.eligible` | Nonempty array of exact eligible file names, image identity, or URL/template pairs |
| `coverage.scanned` | Same exact set, without duplicates |
| `coverage.complete` | `true`; no missing files, parse errors, or execution errors |
| `inputs` | Engine-specific protected inputs described below |

The top-level policy also supplies the matching `source_revision`, `scope_hash`,
and `trusted_approvals`. Scope hashes include the resolved checkout location;
prepare evidence for the same release workspace/mount mapping. A changed working
tree cannot reuse a clean commit's evidence.

An approval has `record_id`, `digest: content_hash(the_complete_record)`, `kind`,
and `roles`. `content_hash` is GXSEC's canonical sorted-key JSON SHA-256; it is not
the report file hash. An approval digest detects changes only because its policy
input is independently protected; a self-written digest is not authentication.

| Record | Approval kind | Required roles |
| --- | --- | --- |
| `evidence` | `scanner-evidence` | `protected-ci` |
| `plan` | `scanner-plan` | `protected-ci`, `security-owner` |
| CodeQL `inputs.use_rights` | `engine-use-rights` | `protected-ci`, `license-owner` |
| Each template's `signature_verification` | `template-signature` | `protected-ci`, `security-owner` |
| `confinement` | `network-confinement` | `protected-ci`, `security-owner` |

## Import an approved native report

An evidence record additionally requires `execution_status: complete` and
`artifact: {path: <absolute external path>, sha256: <file SHA-256>}`. Reports must
be regular files outside the inspected source, at most 16 MiB, with the approved
bytes. A report is read and hashed through the same open handle and parsed from
those immutable bytes; it is never reopened after digest verification. Import accepts:

- Trivy JSON schema version 2 with `ArtifactName`, `ArtifactType`, `Metadata`, and
  `Results`. Only vulnerability results for `lang-pkgs`/`os-pkgs` are supported.
- CodeQL SARIF 2.1.0 with CodeQL version provenance, successful invocations,
  exact approved query rule IDs, and source locations within eligible files.
- Nuclei JSONL with `type: http`, a reviewed `template-id`, and an exact approved
  `matched-at` URL. An empty JSONL report needs the same independently approved
  execution and URL/template coverage as a report containing findings.

Malformed output, a failed invocation, unknown location, changed database,
stale source, or an incomplete scope never becomes a complete clean result.
Code snippets and messages pass through shared redaction. Nuclei raw requests,
responses, extracted values, interactions, and encoded templates are discarded.

## Engine inputs

A protected directory manifest is
`{path: <absolute external directory>, files: {<relative name>: <file SHA-256>, ...},
sha256: content_hash(files)}`. The adapter validates the complete file set,
including unexpected files; symlinks and escaped junctions are rejected.
Execution copies directory inputs and complete tool distributions into private
scratch. Every copied file is hashed from the same handle that supplies its copy;
only verified snapshot bytes are used. Template/certificate parsing also uses
same-handle verified bytes. Changing an original path after its snapshot does not
replace the bytes consumed by a scanner. Snapshot copying has a disk byte budget.

**Trivy** requires `inputs.database`, a directory manifest containing
`db/trivy.db` and `db/metadata.json`, plus a future `expires_at`. CI is responsible
for approving the snapshot's freshness and advisory provenance. Updates happen
before the scan in a separate protected preparation step.

`inputs.target` is either `{kind: filesystem}` or
`{kind: image-archive, path: <absolute external archive>, sha256: <file SHA-256>}`.
Filesystem coverage lists exact source-relative files; image coverage is exactly
`["image-sha256:<archive SHA-256>"]`. Remote image references, Docker sockets, and
nonexistent archives are not accepted. This version implements vulnerability
scanning; it does not claim Trivy IaC/secret/license coverage.

**CodeQL** requires all of:

- `inputs.use_rights`: an independently approved record with `id`,
  `permitted: true`, `basis`, nonempty `evidence_refs`, exact `source_revision`,
  `scope_hash`, and future `expires_at`. Record actual applicable rights, rather
  than assuming the CLI can be used for private code.
- `inputs.database`: an external directory manifest with `prebuilt: true`, the
  exact `source_revision`, and `codeql-database.yml` containing `finalised: true`.
- `inputs.queries`: an external complete directory manifest with `suite`, a
  relative local `.qls` file present in `files`, and nonempty unique `rule_ids`
  covering exactly the query IDs expected in native SARIF. The suite explicitly
  lists local `.ql` files using `query` entries. `lockfile` names a manifested
  CodeQL pack lockfile.
- `inputs.runtime`: a complete CodeQL distribution directory manifest plus
  `entrypoint`, whose file digest equals `engine.digest`. For plans,
  `engine.executable` must name that entrypoint inside this bundle.
- `inputs.query_packs`: a complete directory manifest of resolved packs plus
  `resolved`, matching the lockfile's `dependencies` exactly. Each pack is an
  immediate subdirectory with a pinned `qlpack.yml` whose name/version agrees
  with `resolved`. Redirecting `.codeqlmanifest.json` bundles are rejected.

No database creation, autobuild, project build hooks, or query download runs.
Prebuild and approve the database separately. Execution snapshots the complete
distribution and resolved dependencies, uses only their approved search roots,
and has an empty private home and controlled runtime directory siblings.
Unapproved adjacent packs and the user's package cache are not search roots.
GitHub documents licensing availability in its [CLI setup
guide](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli).

**Nuclei** requires `inputs.templates`, an exact list of
`{id, path, sha256, reviewed: true, signature_verification: {...}}` records. Paths name individual
external template files, never directories or remote URLs. Templates must have a
verified signature, use only `id`/`info`/`http`, make one GET/HEAD request at
`{{BaseURL}}`, and use status/word/regex matchers. Flow, JavaScript, code, raw
requests, payload files, fuzzing, headless, redirects and interpolation in
matchers are excluded. A comment beginning `# digest:` or a `signed: true`
boolean does not prove a valid signature.

`signature_verification` requires `id`, `status: verified`, `template_sha256`,
`signer_id`, `certificate: {path, sha256}`, `verification_evidence_refs`, and
future `expires_at`. Its entire record needs the separate `template-signature`
approval above. Protected policy's `template_signers` maps each permitted signer
ID to the exact certificate file SHA-256. The verifier must cryptographically
check the template against that certificate before approval; this adapter trusts
the protected verification evidence and does not substitute a comment check.

The runner snapshots the same certificate and passes its verified public bytes
through `NUCLEI_USER_CERTIFICATE`; `-dut` also makes the actual scanner reject
unsigned/bad signatures. The [upstream verifier's certificate-loading
contract](https://github.com/projectdiscovery/nuclei/blob/main/pkg/templates/signer/handler.go)
documents that variable. No private signing key is passed to the scanner.

`inputs.target` supplies an exact `origin` without a trailing slash, `paths`, and
literal `allowed_ips`. Coverage lists every Cartesian pair as
`"<template-id>@<origin><path>"`. Every pair must complete, including pairs without
findings. A separately approved `confinement` record is required even for report
ingestion because these checks are active network operations.

## Reference runner deployment and protocol

Install `scripts/gxsec-optional-runner.py` and its pinned `gxsec` runtime outside
the inspected source. Supply a protected executable launcher as
`plan.runner: {path: <absolute launcher>, sha256: <launcher SHA-256>}` and
`plan.engine.executable` as the approved external scanner executable. On Windows,
use an approved executable launcher or confined Linux runner; selecting a Python
script as a project command is not a supported substitute.

Every plan additionally supplies `inputs.runtime` for its scanner, and
`runner.runtime` for its launcher: complete directory manifests plus relative
`entrypoint` fields. The corresponding entrypoint bytes must match the approved
executable digest. The adapter launches a verified private copy of the complete
runner bundle; the runner launches a verified private copy of the complete
scanner bundle. Distributions must use regular materialized files and work after
relocation; unmanifested adjacent code, symlinks, or host package caches cannot
serve as implicit runtime dependencies.

`plan.timeout_seconds` must be between 1 and 1200. The reference runner uses one
deadline across version probes and scanner subprocesses, isolated configuration
and home directories, no inherited credentials, and no shell. Pipe output is
drained while the process runs, with a shared hard capture cap and termination
on overflow. Native report files are monitored while the process runs and read
through bounded handles afterward. The host must enforce report-file/disk quotas
at the kernel or equivalent confinement boundary: size monitoring alone is not
a hard filesystem quota.

Every plan requires an independently approved `confinement` record containing:

- `id`, `status: verified`, exact `source_revision`, `scope_hash`, and future
  `expires_at`;
- `engine_digest`, `runner_digest`, `process_tree: true`,
  `filesystem: source-read-only`, and `firewall_evidence_refs`;
- `runtime_digests: {engine: <inputs.runtime SHA-256>, runner: <runner.runtime SHA-256>}`;
  CodeQL also binds `query_packs: <inputs.query_packs SHA-256>`;
- `limits_enforced: true`, `resource_evidence_refs`, and concrete integer
  `limits` for `cpu_seconds`, `memory_bytes`, `disk_bytes`, `pids`, `output_bytes`;
- `scope`, equal to `inputs.target` (an empty object for CodeQL);
- `network: deny-all` for Trivy/CodeQL, or `network: exact-scope` plus
  `broker_evidence_refs` for Nuclei.

For example, a host may attest `cpu_seconds: 30`, `memory_bytes: 536870912`,
`disk_bytes: 1073741824`, `pids: 16`, and `output_bytes: 1048576`. These values
must describe enforced process-tree CPU/memory/process limits, aggregate scratch
disk usage, and each native report/envelope file's hard output quota. Pipe output
also uses the declared byte cap. Maximum accepted values are 1200 CPU seconds,
16 GiB memory, 32 GiB disk, 64 processes and 16 MiB output. These are contract
ceilings, not a claim that this Python wrapper provisions host limits. Missing
numeric limits or independent enforcement evidence prevents launch.

Nuclei's protected broker/firewall must pin actual IP destinations, exact HTTP
routes and methods, block every other egress path, prevent DNS/redirect scope
changes, and supervise all descendant processes. CLI flags are not confinement.
The wrapper consumes host attestations; it does not implement or independently
audit the host's firewall. Bare local invocation does not create official evidence.
The launcher must terminate all descendants when any deadline or quota is hit.

The adapter passes `--gxsec-plan PLAN_JSON --gxsec-result RESULT_JSON`. The plan
contains the approved record plus `source` and an `approval_context` copied from
the protected policy. The runner rechecks it, probes the actual version, and runs:

- Trivy `filesystem` for each exact file, or `image --input` for the verified
  archive, with an isolated config/ignore file, a private offline DB copy,
  `--scanners vuln`, offline mode, telemetry disabled, and DB/Java DB/version updates disabled.
  See the [official filesystem CLI
  reference](https://trivy.dev/docs/dev/references/configuration/cli/trivy_filesystem/).
- CodeQL `database analyze` on a private copy of the prebuilt database with the
  reviewed local suite, `--format=sarifv2.1.0`, `--no-download`, one worker, bounded
  RAM/disk cache, explicit approved pack search roots, and database-supplied
  extensions/threat models disabled. See the [official
  analyze reference](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-analyze).
- Nuclei separately for each exact template/URL with unsigned templates,
  automatic updates, Interactsh, redirects and HTTP probing disabled; concurrency
  and request rate are one. Native completion counters must show one loaded
  template, host, request and total, zero errors, and 100 percent. Missing or
  incompatible counters remain incomplete. See the [official flag
  reference](https://github.com/projectdiscovery/nuclei#command-line-flags) and
  [native progress implementation](https://github.com/projectdiscovery/nuclei/blob/main/pkg/progress/progress.go).

The result binds `plan_digest`, engine provenance, source revision/hash/scope,
exact coverage, and `confinement_record_id`, and includes redacted native data.
The adapter revalidates native structure and source stability before marking the
check complete. The isolated runner binds the approved source revision only after
the exact source content hash and scope match, and rechecks those bytes afterward.
It exports normalized findings and compact
provenance, not arbitrary scanner logs.
