# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [semantic](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-08-21

### Security

- **The reference MCP transport was broken, not merely untested.**
  `agentboundary/mcp/stdio.py` used `@app.list_tools()` / `@app.call_tool()`,
  a decorator form the MCP SDK removed in 2.0 — the version `uv.lock`
  resolves. `mcp.server.Server` has no `call_tool` attribute at all, so
  `run_stdio` would have raised `AttributeError` on an operator's first call.

  It shipped in `v0.1.0` as "the supported way to use this", with 0% coverage
  and no test importing it, while `tests/e2e/README.md` claimed the tier drove
  a real broker process over the wire. Nothing crossed a wire. The `mcp` extra
  floor moves from `>=1.2` to `>=2.0`: the two APIs are not interchangeable, so
  the old floor claimed a compatibility that would have failed on first use.

- **The adversarial guard could be defeated from the command line.** It counted
  inside `pytest_collection_modifyitems`, which runs *before* pytest applies
  `-k`, `-m` and `--deselect` — so it counted what was discovered, not what
  would run. `pytest tests/adversarial --adversarial-guard -k TestCorpusCoverage`
  deselected all 125 payloads, ran four meta-tests, and exited 0 with the guard
  armed. Verified against `v0.1.0` before the fix. Counting moved to
  `pytest_collection_finish`; ADR-0006 carries the amendment.

- **A trailing DNS root label disarmed the loopback and link-local check in
  `EgressGuard`.** `ipaddress.ip_address("169.254.169.254.")` raises, so the
  literal test had nothing to judge and the decision fell through to the
  allowlist comparison, which matched. An operator whose allowlist entry
  carried the qualified spelling — a plausible copy from resolver output — had
  a free pass to the cloud metadata endpoint and to loopback.

  Present in `v0.1.0`. Reachable only through operator configuration, so it is
  not exploitable by the adversary the threat model names on its own — but it
  turned a control the operator believed they had into one they did not.

  Found by the generated benign corpus while investigating a *false refusal*,
  not by review and not by the injection corpus. Closed by normalising the root
  label on both sides of the comparison before the literal check. Near-miss
  hosts are asserted still refused, and three payloads (`A5-error-04`,
  `A5-error-05`, `A5-html-07`) were added so it cannot return silently.

### Corrected

- **The `v0.1.0` broker-overhead figure was wrong.** It was published as
  0.15 ms mean per call. The loop that produced it ran 2200 calls against a
  1000-call cap, so **1200 of its 2000 samples were `budget_exhausted`
  refusals** — a shorter path that skips the approval lookup and the ledger
  debit — measured and published as the cost of *authorising* a call.

  Corrected figure: **0.129 ms mean** per authorised `fs.read`, with the
  per-repeat spread published alongside. It was first corrected to 0.1309 ms,
  then re-measured at 0.129 ms after the egress fix below changed that guard's
  cost — two moves, both named, because a single number quietly settling on its
  final value hides which change caused which. The
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

### Added (continued)

- **A real transport test.** `tests/e2e/test_stdio_transport.py` launches
  `python -m agentboundary` as a separate OS process and drives it with the
  SDK's own client over stdio pipes — 25 tests asserting the invariants survive
  the transport, refusals first. `stdio.py` coverage 0% → 100%, which required
  arming subprocess coverage; without it the number would have read 25% while
  the code was fully exercised.
- **Collection guards on the end-to-end and GUI tiers**, not only the
  adversarial one, each with its own flag and floor. A tier emptied for any
  reason now fails the build instead of reporting success.

### Measured

Offline, synthetic corpora, on the reference machine — see
[`benchmarks/results.json`](benchmarks/results.json):

- Injection corpus: **39/39** blocked across 9 carrier types, rows A1–A9.
- False refusals: **0/25** hand-written, **2/141** generated. Both corpora are
  synthetic; the generated one exists to remove the hand-picking bias in the
  first, and it is what found the egress bypass above.
- Broker overhead: **0.129 ms** mean per authorised `fs.read`, p99 0.1457 ms,
  authorisation only — excludes ingest and the handler's own work. Path
  confinement is roughly 80% of it.
- Caps fail closed and stay closed.

### Still not true

- No third-party review.
- No CI run has ever executed. Every workflow change in this release is
  verified statically and by the local gate; the first real run happens on
  publication.
- Both benign corpora are written by the author of the controls, directly or
  through a generator. Neither is recorded traffic.

### Fixed

- `EgressGuard` now authorises a host spelled with its trailing DNS root label
  against an allowlist without it — the same host. The generated false-refusal
  rate falls from 8/141 (5.7%) to 2/141 (1.4%).
- The reference catalogue declared `maxLength: 4096` for path arguments, a
  bound no filesystem honours as a single component. Now 255, derived from
  `NAME_MAX` and asserted at test time against the running platform's
  `pathconf`, so a port to a tighter filesystem fails CI rather than failing
  closed at run time. **The guard is unchanged**: an unresolvable path stays
  undecidable and undecidable stays a refusal.

Both were published as open defects before being fixed, and the rate that found
them is published at both values. A defect found by a measurement and quietly
repaired before anyone sees it makes the measurement look better than it was.

### Still refused, deliberately

An address literal carrying a trailing root label (`10.1.2.3.`) is refused
rather than normalised. A WHATWG URL parser drops the empty final label and
connects to `10.1.2.3`; `getaddrinfo` fails `inet_pton` on the dot and asks a
resolver for the *name* `10.1.2.3.`. One string, two destinations — the broker
authorises neither. That costs 2 of the 141 generated tasks, published rather
than hidden.

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
  **This figure was wrong** — see Unreleased → Corrected. It is left here as
  published rather than edited, because this section records what `v0.1.0`
  claimed, not what later turned out to be true.
- Caps fail closed and stay closed.

### Known limitations

Unchanged from the threat model's accepted residual risk: the allowlist bounds
the blast radius but does not make a dangerous tool safe; composition of
in-scope tools is bounded by attribution and approval rather than prevented;
data labelling reduces a rate and does not bound it; an allowlisted egress host
that accepts attacker-readable content is an exfiltration channel; there is no
defence against a malicious operator; concurrent tasks sharing a budget pool
are unsupported; no third-party review.

[0.2.0]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.2.0
[0.1.0]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.1.0
