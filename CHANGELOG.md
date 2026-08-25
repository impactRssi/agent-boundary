# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [semantic](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-08-25

**This release makes the boundary structural inside an agent session, and says
which half of that is proven.** Until now the broker bounded the calls that
went *through* it, while whatever ran it kept its own filesystem and shell.
Routing some calls through a broker while a second route to the same disk stays
open demonstrates nothing about the broker — which is `ADR-0002`'s own argument,
and it applied to this repository. `agent-boundary[runner]` closes it: the
session's tool surface is derived from the broker's `tools/list`, and a built-in
tool is *unrepresentable* rather than filtered out.

The part that is not proven is stated in README §7 item 3 and repeated here
under "Still not true", because a release that ships a new integration and
mentions only its guarantees is the kind of release this project exists to
argue against.

### Added — a session whose only tools are the broker's

- **`agent-boundary[runner]`** (`python -m agentboundary.runner`). `SessionSpec`
  has no field in which a built-in tool could be requested, and every name it
  carries must be a qualified tool of this session's own brokered server. There
  is no representable spec containing `Bash`. The list of native tool families
  in the module is documentation and a test fixture — never a blocklist
  consulted on the way to a decision, which would be the call-time filter
  `ADR-0002` rejects.
- **The surface is derived, not declared.** Reading `tool_scope` from the task
  file would be cheaper and offline, and wrong twice: a second source of truth
  for what the session may reach, and one that disagrees with the broker the
  moment a tool lease widens scope. The runner asks the broker over the
  transport the session will use.
- **`--dry-run`** resolves and prints the whole surface — spawn command, brokered
  names, built-ins, settings sources — without calling a model. Offline and
  free; run it after every task edit.
- **`strict_mcp_config` and no settings sources**, so a native tool or a second
  MCP server cannot reappear from ambient project configuration.

### Added — evidence scaffolding

- **`ADR-0009`: model-in-the-loop evidence is not a benchmark.** Two artifact
  classes that never share a file. Benchmarks stay offline, deterministic and
  blocking. An evidence run lives under `evidence/`, carries `n`, model id, date
  and cost in the same block as any rate, publishes the samples that refute it,
  and never gates a build. No evidence figure is averaged into a benchmark one.
- **`evidence/workspaces/planted-carrier/`** — a disposable checkout with genuine
  work (an open issue, a failing test, a one-line fix) in which the
  `dependency_readme` carrier is live rather than quoted, realising A1 against
  I1. It is refused before a single file is written unless every address every
  declared sink resolves to is loopback: userinfo confusion, `0.0.0.0`, mapped
  IPv6, decimal/octal/hex encodings, trailing root labels, punycode, and the
  DNS-rebinding shape are each refused with a case. The default resolver
  resolves nothing, so the check performs no network I/O.

### Fixed

- **The documented install pinned the release the README warns against.** The
  status notice said `v0.1.0` "should not be used — it shipped a broken MCP
  transport, an egress bypass, and a defeatable test guard", and the
  getting-started command in both `README.md` and `docs/INSTALL.md` pinned
  `@v0.1.0`. Two releases shipped without the pin moving. A reader following the
  instructions installed the known-broken transport. Both pins now track the
  release and a test asserts they match `[project] version` and are never a
  superseded tag.
- **`SECURITY.md` said there was no backport policy "until `v0.1.0` is tagged".**
  It had been tagged for three releases; the sentence had stopped meaning
  anything.
- **The version lived in two files with nothing checking they agree.** `v0.2.2`
  was tagged while `pyproject.toml` still said `0.2.1`, and the fix at the time
  was a check at *tag* time. The drift itself is now a unit test, so it fails on
  the branch rather than in the release workflow.

### Corrected — what the wall-clock cap measures

- **`max_wall_clock_s` bounds the task's span, not its work.** `BudgetLedger`
  stamps its start in the constructor, so the cap counts model latency and
  operator idle time. The `Caps` docstring justified it as bounding "a slow
  endpoint polled in a loop", which is a different quantity, and FR-012 said
  only "wall-clock time". Found by pointing the broker at a real project: a task
  capped at 300 s refused at 350 s having spent about two seconds inside the
  broker. The refusal was correct and the configuration was not, and nothing the
  operator had read would have told them so. Behaviour is unchanged — bounding
  the span is what limits how long a steered agent keeps acting, which a sum of
  call durations does not — but the code, FR-012 and `docs/INSTALL.md` now say
  it, with batch-versus-interactive guidance whose numbers are marked as chosen
  rather than measured.
- **A secret inside `fs_root` is disclosed by a correctly authorised read.** The
  root bounds *which* file, never what is inside it; ingest strips active content
  and is not a redaction layer. Now README §7 item 2 and residual risk 24, after
  a real read returned a plaintext credential under `"removed": []` — specified
  behaviour that nothing had written down.

### Measured

- 1423 tests across four blocking tiers on Python 3.11, 3.12 and 3.13; 95.47%
  coverage against an 80% floor.
- The injection corpus, the overhead figure and both benign corpora are
  unchanged from `0.3.0` and carry the same caveats: 46/46 blocked across nine
  carriers, 0.10 ms mean overhead under the conditions recorded in
  `benchmarks/results.json` and nowhere else, 0/25 hand-written and 2/141
  generated false refusals reported side by side and never averaged.

### Still not true

- **The runner's live path has never run.** `run_session` is the only uncovered
  path in the package: covering it would put a model on the gate, which
  `ADR-0009` forbids. Concretely unverified — this broker names its tools
  `fs.read`, so the runner qualifies them as `mcp__agentboundary__fs.read`, and
  whether a dot survives the runtime's own tool-name matching has not been
  checked against a live session. The failure direction is fail-closed: a tool
  that asks for permission instead of running, never one that runs unbrokered.
- **No evidence run has been recorded.** `evidence/` holds the workspace an
  evidence run is given and nothing else. The two arms that would show whether a
  real model emits the out-of-scope call are not built, so the injection corpus
  still has no counterfactual and 46/46 still says a locked door is locked.
- **Neither benign corpus is independent**, and there is still **no third-party
  security review**.

## [0.3.0] — 2026-08-23

**This release adds a mechanism that deliberately widens the invariants.** That
is the point of it and it is the first thing to say. A permission lease lets an
operator open a hole on purpose — three days of access to a credential
directory so an automation can run — and while that lease is in force, the
invariant it widens **does not hold for its subject**. Everything below is
about making that hole bounded, attributable, and visible rather than
pretending it is not a hole.

### Added — permission leases

- **Leases bounded by construction, not by policy.** A lease carries kind
  (`tool`/`path`/`host`), subject, grantee, a required reason, and an expiry.
  An unbounded lease is *unrepresentable*: `expires_at` has no default, `inf`
  and `nan` are refused, and a per-class maximum duration caps it — credential
  7 days, sensitive 14, routine 30. The cap is the actual teeth. Without one,
  "forever" is just a large integer and nothing objects. Only the 7-day figure
  has a stated derivation; 14 and 30 are ordering choices and `ADR-0008` says
  so rather than inventing a rationale.
- **Path and host leases resolve at call time; tool leases resolve at task
  construction time.** This asymmetry is load-bearing. I1 is the property that
  an out-of-scope tool has *no handle*, and a tool appearing in the dispatch
  table mid-session would convert I1 into a call-time filter — which is what
  `ADR-0002` exists to reject. The consequence is stated, not mitigated: a tool
  lease that expires mid-task keeps its handle until the task ends.
- **A refusal ledger that grants nothing.** Refusals are aggregated by subject
  with reason, count, and first/last seen. The record type has no approval
  field and no method that produces one. It renders its own caveat every time:
  a ledger entry cannot distinguish a legitimate workflow from a payload that
  steered the agent.
- **An operator interface where bulk approval is unrepresentable**, not merely
  absent. No option accumulates or takes multiple values; no signature accepts
  a sequence; no module holds both a refusal and a lease in scope, so
  "promote this row" cannot be written as a local change; and `refusals` prints
  no row number, id, or digest to select by. `LeaseStore` has no `grant` — the
  CLI writes the file out of band, and no `agentboundary.operator` module loads
  in a serving process.
- **Unconditional rotation advice** when a credential lease expires. The audit
  trace records what was *authorised*, not what was *read*, so "nothing looked
  wrong" is not evidence.
- Leases, lapses and owed rotations are visible in the audit viewer. An
  operator who cannot see what is granted cannot revoke it.

### Fixed

- `build_from_config` selected handlers from the unleased scope while
  `build_server` widened it, so a tool lease killed the entry point by naming
  the tool the operator had just granted. The serve banner now prints the
  server's real scope, so a tool lease cannot make it understate what the agent
  holds.
- `LeaseKind` subclasses `str`, so `"path" == LeaseKind.PATH` is true while the
  guards dispatch on identity. A lease built with a string kind was accepted,
  stored, reported as active — and applied to nothing. It failed closed, which
  is what made it dangerous: an operator who granted access, saw the call
  refused anyway, and concluded the lease was too narrow would reach for a
  broader one.

### Measured

Offline, synthetic corpora, Python 3.13 on Darwin/arm64 at load average 3.8 —
see [`benchmarks/results.json`](benchmarks/results.json). **Timings are not
comparable with `v0.2.x`**, which was measured at load average 9.02; nothing on
the authorisation path changed between the runs.

- Injection corpus: **46/46** blocked across 9 carriers, rows A1–A9,
  0 blocked by a control other than the one under test.
- **The harness now measures the counterfactual instead of asserting it.** Six
  payloads declare a lease; each is run again with no store attached and the
  refusal reasons compared. All six refuse identically either way — "a lease
  can only widen" is now a measurement.
- False refusals: **0/25** hand-written, **2/141** generated. Both synthetic;
  the hand-written one is still authored by the author of the controls and is
  still the weakest number here.
- Broker overhead: **0.1042 ms** mean per authorised `fs.read`, authorisation only.
- **A measured regression, published:** attaching a lease store costs
  **+0.00094 ms** per authorised `http.get` — about 19% of that guard's stage
  and 4.4% of the call — agreed in sign by all five repeats at ~4.7× their
  spread. The path guard's delta is **not distinguishable from noise** on this
  machine and is reported as unmeasurable rather than as zero. A deployment
  that attaches no store pays neither, and no store is the default.

### Still not true

- No third-party review.
- `FileLeaseStore` re-reads and re-parses its file on every lookup. Its
  overhead is **not measured** and no number for it should be quoted.
- Both benign corpora are authored by the same hand as the controls, directly
  or through a generator. Neither is recorded traffic.
- Not on PyPI. Install from the repository.

## [0.2.3] — 2026-08-21

**Use this one.** Same broker code as `v0.2.1`; what changed is the release
pipeline, which took three tags to get right and is now checked rather than
trusted.

### Fixed

- The release workflow built its SBOM path from the tag name (`v0.2.1`) rather
  than the package version (`0.2.1`), and failed on the first tag that reached
  it. It now resolves the artefact that was actually built.
- `v0.2.2` was tagged while `pyproject.toml` still said `0.2.1`, so that
  release carries artefacts named for a different version than the tag that
  produced them. Nothing checked, so nothing complained. The release workflow
  now refuses to publish when the tag and the package version disagree.

### Release history, stated plainly

`v0.1.0` shipped three defects. `v0.2.0` was cut before CI had ever run and its
commit is red. `v0.2.1` is green but its release workflow failed. `v0.2.2`
carries mislabelled artefacts. None of them is deleted or moved: the tags
record what was actually published at each point, and a tag quietly relocated
to a better commit is the same dishonesty as an edited benchmark.

## [0.2.1] — 2026-08-21

**Use this instead of `v0.2.0`.** That tag is published but its commit does not
pass CI — it was cut before CI had ever run, and the first run found three
things nothing local could have caught. The tag is left where it is rather than
moved, because a published tag quietly relocated to a greener commit is the
same dishonesty as an edited benchmark.

This is the first release whose commit has a green CI run behind it, on Python
3.11, 3.12 and 3.13.

### Fixed

- **A symlink loop reported the wrong refusal reason on Linux.** CPython raises
  `OSError(ELOOP)` on macOS and `RuntimeError` on Linux for the same condition.
  `PathConfinementGuard` caught only the former, so on Linux the loop escaped
  it and was refused by the broker's catch-all with `task_construction_failed`
  instead of `path_outside_root`. It failed closed either way — but reported
  the wrong control, and `SECURITY.md` counts a misreported refusal reason as a
  vulnerability, because that string is what an operator triages on.

  Found by the first CI run on Linux, in a test written and passing on macOS.
  Both types are now normalised at the resolution boundary.

- **The CI workflow never ran.** The `gate` job used
  `join(needs.*.result, " ")`. GitHub expressions accept only single-quoted
  string literals, so the file was rejected at dispatch and the very first run
  ever — on publication — failed in zero seconds with no jobs at all. Present
  since the first CI commit.

  Every local check parsed `ci.yml` as YAML, which it validly is, and none
  parsed the expressions inside it — GitHub validates those server-side.
  `actionlint` now runs in the gate and in CI, fails closed when absent, and
  was confirmed to reject the original expression before being wired in.

  This is the concrete cost of the "no CI run has ever executed" caveat that
  `v0.2.0` published. It was not a formality.

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

[0.4.0]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.4.0
[0.3.0]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.3.0
[0.2.3]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.2.3
[0.2.1]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.2.1
[0.2.0]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.2.0
[0.1.0]: https://github.com/impactRssi/agent-boundary/releases/tag/v0.1.0
