# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [semantic](https://semver.org/spec/v2.0.0.html).

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
