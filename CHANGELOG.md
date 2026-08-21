# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [semantic](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Corrected

- **The `v0.1.0` broker-overhead figure was wrong.** It was published as
  0.15 ms mean per call. The loop that produced it ran 2200 calls against a
  1000-call cap, so **1200 of its 2000 samples were `budget_exhausted`
  refusals** — a shorter path that skips the approval lookup and the ledger
  debit — measured and published as the cost of *authorising* a call.

  Corrected figure: **0.1309 ms mean** per authorised `fs.read`, over 5 repeats
  of 2000 iterations, with the per-repeat spread published alongside. The
  overhead loop now runs under unreachable caps, raises if any sample was
  refused, and the E2E tier asserts that flag — the defect is closed by a test,
  not by having noticed it once.

  The `v0.1.0` tag still carries the wrong number in its message. It is left
  standing: the tag was never distributed, and rewriting it to hide an
  incorrect published figure is the behaviour this project's own benchmark
  rules exist to prevent.

### Added

- **Pipeline hardening.** Every action pinned to a commit SHA with its tag in a
  mandatory comment, enforced by a check that fails the build
  (`ADR-0007`); `persist-credentials: false` on every checkout; per-job
  `permissions:`; egress audit on every job; `dependency-review` on pull
  requests; Dependabot for actions and Python dependencies.
- **A benign corpus with different provenance** — 141 tasks derived
  mechanically from the tool schemas at a fixed seed, reported *beside* the
  hand-written 25 rather than replacing them.
- **Per-guard overhead attribution.** Path confinement is 80% of an `fs.read`
  authorisation; a call with no path argument costs about five times less.
- Rendered trust-boundary diagram, a reproducible capture of the audit viewer,
  and an installation guide whose commands were each run against a clean clone.

### Known defects found by the generated corpus, not yet fixed

- `EgressGuard` refuses a fully qualified host spelled with its trailing root
  dot (`docs.internal.` against an allowlist of `docs.internal`). Same host;
  the request would have succeeded. A real false refusal.
- The reference catalogue declares `maxLength: 4096` for path arguments, a
  bound the filesystem does not honour — the OS fails with `ENAMETOOLONG` and
  the guard correctly fails closed. The schema is the defect, not the guard.

Both are published here before being fixed, because a defect found by a
measurement and quietly repaired before anyone sees it makes the measurement
look better than it was.

## [0.1.0] — 2026-08-20

First release. The broker, its guards, the ingest path, the MCP transport, the
adversarial corpus, the audit viewer, and the benchmark harness.

### Added

- **Deterministic tool-call broker** (`agentboundary.broker`). Resolves the
  tool in the task's scope, validates arguments, then runs the guards in order.
  No model, no heuristic, and no read of the agent's context anywhere on the
  authorisation path.
- **Per-task tool scoping** (I1). An out-of-scope tool is absent from the
  dispatch table and from the schema the model sees; there is no call-time
  allowlist check because there is no reachable handle to check.
- **Argument schema validation** with zero dependencies. `additionalProperties`
  defaults to `false` and unknown keywords raise — both inverted relative to
  JSON Schema, deliberately, for an authorisation boundary.
- **Path and egress confinement** (I4) by component-wise resolution.
- **Budget accounting** (I3) across call count, cost, and wall-clock, failing
  closed and staying closed.
- **Irreversibility classification and out-of-band approval** (I3), bound to a
  digest of the validated arguments so an approval cannot be replayed with
  different ones.
- **Ingest** (I2): normalisation, active-content stripping, nonce-delimited
  envelopes, provenance tagging. No exported function returns a raw tool result.
- **Append-only audit trace**, `O_APPEND` and fsync per record, no mutation path.
- **Reference MCP server** plus a `python -m agentboundary` drop-in entry point.
- **Indirect-injection corpus**: 36 payloads, 9 carriers, attack rows A1–A9,
  blocking in CI under a guard that fails the build on zero collection or a skip.
- **Read-only audit-trace viewer** with a Playwright GUI tier.
- **Offline benchmark harness** publishing every figure with its conditions.

### Measured

On the reference machine, offline, synthetic corpora — see
[`benchmarks/results.json`](benchmarks/results.json):

- Injection corpus: 36/36 blocked across 9 carrier types.
- False refusals: 0/25 on a benign corpus **written by the same author as the
  controls**; read that as "no benign task the author thought of was refused".
- Broker overhead: 0.15 ms mean, 0.47 ms p99, authorisation only.
- Caps fail closed and stay closed.

### Known limitations

Unchanged from the threat model's accepted residual risk: the allowlist bounds
the blast radius but does not make a dangerous tool safe; composition of
in-scope tools is bounded by attribution and approval rather than prevented;
data labelling reduces a rate and does not bound it; an allowlisted egress host
that accepts attacker-readable content is an exfiltration channel; there is no
defence against a malicious operator; concurrent tasks sharing a budget pool
are unsupported; no third-party review.

[0.1.0]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.1.0
