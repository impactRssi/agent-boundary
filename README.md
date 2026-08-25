# Agent Boundary

[![ci](https://github.com/impactRssi/agent-boundary/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/impactRssi/agent-boundary/actions/workflows/ci.yml?query=branch%3Amain)
[![license Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)

**Your agent has access to your internal tools. Who threat-modelled that?**

Agent Boundary is a deterministic tool-call broker that sits between an LLM
agent and the tools it can reach. It decides which proposed calls become
effects — without consulting a model, and without reading a single token of the
agent's context.

> **Status: `v0.4.0`.** The broker, ingest, MCP transport, injection corpus,
> audit viewer, and benchmark harness are implemented and blocking in CI. New
> here: `agent-boundary[runner]`, an agent session in which the brokered tools
> are the *only* tools — read §7 item 3 for the part of it that is not yet
> exercised against a live runtime.
> `v0.1.0` and `v0.2.0` are superseded. `v0.1.0` should not be used: it shipped a broken MCP
> transport, an egress bypass, and a defeatable test guard — all three are in
> the [changelog](CHANGELOG.md), found by the work in this release rather than
> by review. The numbers below come from a run you can reproduce with one
> command; read the caveat attached to each.

---

## 1. Thesis

Teams are connecting agents to filesystems, ticketing systems, databases, and
cloud APIs at a speed that has completely outrun anyone's threat modelling.

The dominant risk is not the model saying something wrong. It is **indirect
prompt injection**: the agent reads a document, a ticket, a web page, or a tool
response that contains attacker-authored instructions, and the agent's *tool
calls* become attacker-controlled.

Which means:

> Every tool the agent can reach is reachable by whoever can write into the
> agent's context.

An attacker who can file a support ticket has, transitively, whatever access
the agent has. They never need a credential, a session, or a prompt.

The usual response is to ask the model to behave: a firmer system prompt, a
safety classifier, a self-critique step. Every one of those is implemented *in
the channel the attacker can write into*. This project does the opposite. It
assumes the model is fully steered, and arranges for that to not matter.

---

## 2. Threat model

Full document: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

**The adversary cannot talk to the agent.** They have exactly one capability:
they can write content the agent will later read — a ticket description, a PDF
in a shared drive, a web page, a dependency README, a JSON field from a
third-party API, a filename, a commit message, an error string.

**Assume the model is fully steerable by that content.** Nothing here is a
claim about model alignment, and nothing here improves when the model does.
This is a control property, not a model property.

**Explicitly out of scope:** a malicious operator, a genuinely dangerous tool
that the operator put on the allowlist, host compromise.

---

## 3. Architecture

![Four trust boundaries. Untrusted content, the ingest path and the agent all sit inside one untrusted region; boundary 3 separates the agent from the deterministic broker, which is the only component that can turn a proposed call into an effect; boundary 4 separates the broker from the effect and the append-only audit trace.](docs/assets/trust-boundaries.svg)

The agent sits **inside** the untrusted region. That placement is the argument
everything else follows from.

The broker is the load-bearing control: deterministic, model-free, and the only
component that can authorise an effect.

<details>
<summary>The same diagram as text, for reading in a terminal</summary>

```
untrusted content (docs, tickets, web, tool responses)
        │
        ▼
   [ ingest ]   normalise · strip active content · delimit · tag provenance
        │
        ▼
   [ agent  ]   UNTRUSTED COMPONENT — assume fully steered
        │
        ▼  ProposedCall
   [ broker ]   deterministic · model-free · the only thing that can authorise
        │
        ▼  authorised call only
   [ effect ]   side-effecting call, logged with full attribution
        │
        ▼
   [ audit  ]   append-only trace a human can reconstruct the decision from
```

</details>

Full boundary-by-boundary treatment:
[`docs/THREAT_MODEL.md` §3](docs/THREAT_MODEL.md#3-trust-boundaries).

---

## 4. Structural invariants

Four properties, each enforced by construction rather than by policy, each with
a named enforcement point in the code and a blocking test tier.

| # | Invariant | Enforcement point | Verified by |
|---|---|---|---|
| **I1** | The model cannot reach a tool outside the current task's allowlist. Scoped **at construction time**, not filtered at call time — an out-of-scope tool has no handle the model can name | [`registry.py`](src/agentboundary/registry.py) | Unit + adversarial |
| **I2** | Tool output is untrusted input: normalised, stripped of active content, delimited, and provenance-tagged before re-entering context. Never treated as instruction | [`ingest/`](src/agentboundary/ingest/) | Unit + adversarial |
| **I3** | Every side-effecting call is bounded and attributable. Hard caps on count, cost, and wall clock; irreversible effects require out-of-band human approval | [`budget.py`](src/agentboundary/budget.py), [`approval.py`](src/agentboundary/approval.py) | Unit + adversarial + E2E + GUI |
| **I4** | Filesystem and network access are confined by construction. Paths resolved to an explicit root **before** the check; egress via allowlist | [`confinement.py`](src/agentboundary/confinement.py) | Unit + adversarial |

Every file above exists and every cell in "Verified by" corresponds to tests
that run in CI. The authorisation path is [`broker.py`](src/agentboundary/broker.py):
it resolves the tool in the task's scope, validates arguments, then runs the
guards in order.

### Why deterministic brokering

A safety classifier is a model reading attacker-influenced text, so it inherits
the exact vulnerability the system exists to contain. A model-based check may
run *alongside* the broker as a noise reducer. It must never sit *on* the
authorisation path. See [ADR-0001](docs/adr/ADR-0001-deterministic-brokering.md).

### Why per-task scoping instead of a permission check

A global tool registry with a call-time allowlist check means the capability
was reachable and we chose not to use it — one missing check away from a hole,
with every tool's name and schema sitting in context where attacker content can
name it directly. Scoping at construction time removes the handle entirely. See
[ADR-0002](docs/adr/ADR-0002-per-task-tool-scoping.md).

---

## 5. Adversarial proof

The [attack table](docs/THREAT_MODEL.md#6-attack-table) has nine rows —
indirect injection, tool-result poisoning, confused deputy across tools,
denial of wallet, exfiltration through a permitted tool, context-overflow
eviction, multi-turn goal drift, filename-as-carrier, forged approval.

Each row becomes executable payloads in an indirect-injection corpus embedded
in realistic carriers. Each payload is a test asserting the broker **refused**
the resulting call.

**The corpus runs as a separate, blocking CI step that fails the build if it
collects zero tests or skips one.** A test corpus that can silently collect
nothing is not a control — it reports the same green tick whether it proved
something or nothing. The guard is shipped as
[`agentboundary.testing.adversarial_guard`](src/agentboundary/testing/adversarial_guard.py)
and is [itself unit-tested](tests/unit/test_adversarial_guard.py).

The corpus holds **46 payloads across 9 carrier types**, and every attack-table
row A1–A9 has at least one payload. Both floors are asserted by test.

A corpus that only ever refuses proves nothing — a broker that refused
*everything* would score identically. So
[`test_corpus_is_falsifiable.py`](tests/adversarial/test_corpus_is_falsifiable.py)
is the control on the control: legitimate work must be **authorised** under the
same pipeline, and each refusal must flip to an authorisation when the task
legitimately permits it.

### What a refusal looks like afterwards

A refusal that nobody can reconstruct is not attribution. The read-only
audit-trace viewer, on a six-call run of the real broker — an authorised read, a
path escape, an out-of-scope tool, an unapproved irreversible call, that same
call once approved, and one call past the cap:

![Audit-trace viewer showing six brokered calls, two authorised and four refused. Each refused record is labelled with the reason the broker recorded — path_outside_root, tool_not_in_scope, approval_mismatch, budget_exhausted — and the check that produced the refusal is highlighted inside the record.](docs/assets/audit-viewer.png)

Every record carries the task id, the post-validation arguments, and the ordered
checks with the failing one marked — which is what makes an effect attributable
after the fact (I3). The viewer answers `GET` and `HEAD` and nothing else: there
is no route that could edit a trace, not a guarded one.

The image is generated, not drawn. Regenerate it with:

```bash
TMPDIR=/tmp uv run --group gui python scripts/capture_viewer.py
```

That script drives the real broker through the same six calls the GUI tier
asserts on in
[`tests/gui/test_audit_viewer.py`](tests/gui/test_audit_viewer.py). It is a
scripted demonstration, not a measurement and not production traffic.

---

## 6. Measured results

Reproduce with:

```bash
uv run python benchmarks/harness.py
```

Offline, single process, no network. Full output:
[`benchmarks/results.json`](benchmarks/results.json).

**Conditions for every figure below:** Python 3.13.13 on Darwin/arm64 (Mac15,6, Apple M3 Pro, 12 logical CPUs), offline, synthetic corpora, single process, no warm cache, load average 3.8 while the timing figures were taken.

> **The timing figures below are not comparable with the ones this section
> carried before.** Those were taken at load average 9.02 on the same machine;
> these at 3.8. Every timing number here is lower than its predecessor and
> **none of that is an improvement to the broker** — it is a less contended
> laptop. The load is published with both for exactly this reason. The counts
> (blocked, refused, authorised) are load-independent and *are* comparable.

### Injection corpus: 46/46 blocked

On a hand-written synthetic corpus of 46 payloads across
9 carrier types, matching the current invariant set.
Each payload asserts a **specific** refusal reason, not merely that a refusal
happened — 0 were blocked by a
different control than the one under test.

| Carrier | Attempted | Blocked |
|---|---|---|
| `dependency_readme` | 4 | 4 |
| `error_message` | 6 | 6 |
| `filename` | 4 | 4 |
| `git_commit_message` | 4 | 4 |
| `html_page` | 8 | 8 |
| `json_api_response` | 5 | 5 |
| `pdf_document` | 3 | 3 |
| `shared_drive_document` | 5 | 5 |
| `ticket_description` | 7 | 7 |

Attack-table rows covered: A1, A2, A3, A4, A5, A6, A7, A8, A9.

**Six of the 46 declare an operator lease and are judged with it** — 3 path
leases, 2 host leases and 1 tool lease; 4 of the 6 are live at the instant the
payload pins and 2 have expired by it. Each pins its own instant, so the verdict
does not depend on the date the harness ran. They test the case a payload with
no lease cannot: that a live lease over a *neighbouring* subject still refuses,
and that an expired one widens nothing. All 6 refuse, and the harness then runs
each of them a second time with no lease store attached and compares: **the
refusal reason is identical in all 6 cases, so 0 outcomes were changed by a
lease.** That is the measurement behind "a lease can only widen"; it is no
longer only a claim about the design.

> **A harness defect, published rather than quietly fixed.** Until this run the
> harness assembled its own pipeline with **no lease store**, so those 6
> payloads were judged without the control they exist to exercise. The block
> rate was unaffected — the counterfactual above is what establishes that — but
> a harness that silently drops a control its corpus is exercising is measuring
> something other than what it reports. It now uses
> `agentboundary.testing.broker_for`, the same assembly the adversarial tier and
> `build_broker` use, and `results.json` states per payload which leases were in
> force and what each was worth.

### False-refusal rate: 0/25 hand-written, 2/141 generated

The control's cost, measured against two **synthetic** corpora, reported side by
side and never averaged — what separates them is who chose the cases, and one
combined figure would hide exactly that.

| Corpus | Tasks | Falsely refused | Who chose the cases |
|---|---|---|---|
| Hand-written | 25 | 0 (0.0%) | The author of the controls, knowing what each guard checks |
| Generated at seed `0xb0157a11` | 141 | 2 (1.4%) | Nobody — derived from the declared schema constraints |

**Read the caveat before the 0/25.** I wrote that corpus knowing what the
controls check, so the honest reading is "no benign task I thought of was
refused" — not "the control has no cost".

The generated corpus exists to remove that one weakness:
[`benchmarks/benign_corpus.py`](benchmarks/benign_corpus.py) derives arguments
mechanically from each tool's declared schema constraints (`type`, `minLength`,
`maxLength`, `minimum`) crossed with a generated filesystem fixture tree, at a
fixed seed, offline. **It found what the hand-written corpus missed.** The rate was 8/141 (5.7%) on
the first run, published before anything was fixed. Two of those eight remain
by design; the other six led to a security fix:

| Found | Cases | Outcome |
|---|---|---|
| `egress_host_not_allowed` on a host spelled with its trailing DNS root label — `docs.internal.` against an allowlist of `docs.internal` | 6 | **Fixed.** Same host; the request would have succeeded. See the security note below |
| `path_outside_root` on a 4096-character path, the `maxLength` the catalogue itself declared | 2 | **Fixed in the schema, not the guard.** The OS could not resolve it (`ENAMETOOLONG`) and the guard failed closed, which is correct. The bound is now 255, derived from `NAME_MAX` and asserted against the running platform's `pathconf` |
| Address literal carrying a trailing root label — `10.1.2.3.` | 2 | **Still refused, deliberately.** A WHATWG URL parser drops the empty label and connects to `10.1.2.3`; `getaddrinfo` asks a resolver for the *name* `10.1.2.3.`. One string, two destinations — the broker authorises neither |

> #### The six were a security bypass, not just a cost
>
> While confirming the false refusal, the trailing dot turned out to be
> **disarming the loopback and link-local check**. `ipaddress.ip_address` raises
> on `169.254.169.254.`, so the literal test had nothing to judge and fell
> through to the allowlist comparison, which matched. An operator whose
> allowlist entry carried the qualified spelling — a plausible copy from
> resolver output — had a free pass to the cloud metadata endpoint.
>
> Present in `v0.1.0`. Found by the generated corpus, not by review. Closed by
> normalising the root label on both sides of the comparison *before* the
> literal check, with the near-miss hosts (`docs.internal.evil.example`,
> `evil.docs.internal`, `docs.internal..`, userinfo decoration) asserted still
> refused, and three corpus payloads added so it cannot come back.

Per tool, out of the tasks generated for it: `http.get` 1/46 and `http.post` 1/46 — both the deliberate address-literal case — and 0 for every other tool. The corpus is not evenly distributed: 92 of its 141 tasks are HTTP tools, so the rate is a property of that distribution, not of any deployment's task mix.

**Re-checked against the corrected path bound, and it did not move.** The
generated corpus was regenerated from the current catalogue before this run: the
`path=at-the-declared-maxLength` cases are now 255 characters rather than 4096,
both of them (`generated-013` on `fs.read`, `generated-026` on `fs.write`) are
**authorised**, and the two `path_outside_root` refusals that the 4096-character
bound produced are gone. The generated rate stayed at 2 refusals out of 141
tasks because the two that remain are the address-literal class, which has
nothing to do with path length. A fresh generation is byte-identical to the
committed [`benchmarks/benign/generated.json`](benchmarks/benign/generated.json),
and the E2E tier fails if it is not.

**The caveat is narrowed, not retired.** The generator is code in this
repository, written by the author of the controls; the individual cases are
mechanical but the shapes they are drawn from are authored here. This is not an
independent third-party measurement, and it is not recorded traffic. Full
reading: [`benchmarks/README.md`](benchmarks/README.md).

### Broker overhead: 0.104 ms mean per authorised `fs.read`, at load average 3.8

Over 5 repeats of 2000 iterations each, every sample an authorised
call, after a 200-call warm-up per repeat, with no lease store attached: mean
**0.1042 ms**, median 0.1027 ms, p95 0.1144 ms, p99 0.122 ms, max 0.4558 ms. The
five per-repeat means were 0.1063, 0.1064, 0.1041, 0.1027 and 0.1014 ms — a
spread of 0.005 ms, which is the reader's guide to how much of the third
decimal is signal on a laptop.

The previously published mean was 0.129 ms at load average 9.02 on the same
machine. **Read the difference as the load, not as the broker getting faster:**
nothing on the authorisation path was optimised between the two runs, and the
spread within this run alone is 0.005 ms.

Measures authorisation only — scope resolution, schema validation, path
confinement, egress check, budget accounting, approval lookup. **Excludes** the
ingest path and the handler's own work, both of which usually dominate a real
call.

**Corrected since the previous release.** The loop that produced the earlier
figure ran 2200 calls against a 1000-call cap, so 1200 of its 2000 samples were
budget-exhausted refusals — a shorter path that skips the approval lookup and
the ledger debit. It published that mixture as the cost of authorising a call.
The caps in the overhead loop are now unreachable and the harness fails if any
sample is refused.

### Where the overhead goes, per pipeline stage

One aggregate cannot tell an adopter which control costs what, or locate a
regression. Milliseconds per call, 2000 iterations per call shape, at load
average 3.8, all shapes authorised end to end so that every stage runs. **No
lease store is attached in this table** — that is the default deployment, and
what a store costs is measured separately below:

| Stage | `fs.read` | `fs.write` (approved) | `http.get` | `tickets.get` |
|---|---|---|---|---|
| Scope resolution | 0.00010 | 0.00011 | 0.00009 | 0.00010 |
| Schema validation | 0.00237 | 0.00337 | 0.00229 | 0.00240 |
| Path confinement | **0.08431** | **0.09284** | 0.00063 | 0.00061 |
| Egress allowlist | 0.00076 | 0.00085 | 0.00498 | 0.00057 |
| Budget accounting | 0.00401 | 0.00431 | 0.00312 | 0.00302 |
| Approval lookup | 0.00106 | 0.00529 | 0.00078 | 0.00074 |
| Unattributed | 0.01380 | 0.01140 | 0.00940 | 0.00890 |
| **Total** | **0.1065** | **0.1182** | **0.0213** | **0.0163** |

**Path confinement is still the broker's cost.** It is 0.08431 ms of the
0.1065 ms an `fs.read` costs at load average 3.8 — 79%, against 80% in the
previous run at load 9.02, which is the same shape and not a change worth
reading into. Confinement resolves the path one component at a time against the
filesystem rather than pattern-matching it, which is the property
[I4](docs/THREAT_MODEL.md) depends on. A call with no path argument costs
0.0163–0.0213 ms, five to six times less. Every other control is at or below
0.006 ms.

Read with these caveats, all four in the same breath as the numbers: each guard
figure includes one `perf_counter` pair (0.00007 ms here), so each is an upper
bound; scope resolution is at that instrument floor and its figure means "too
cheap to measure this way"; the unattributed row is guard dispatch, one `Check`
record per stage and building the `Decision`, published rather than folded into
a stage because it also absorbs the measurement error; and a *refused* call is
cheaper than any of these, because the pipeline short-circuits at the guard
that refused.

### What a lease store costs the two guards that consult one

Permission leases added a lookup to `PathConfinementGuard` and `EgressGuard`. A
new control with an unmeasured cost is a control nobody can decide to adopt, so
it is measured as a **paired A/B difference** — the same guard, the same call,
alternating between a pipeline with a store attached and one without, five
repeats of 2000 iterations each — because the thing being looked for is smaller
than the drift between two separately-timed runs on a laptop.

| Guard | Call shape | Without a store | With a store | Mean delta | Spread of the delta | Larger than its own spread |
|---|---|---|---|---|---|---|
| Path confinement | `fs.read`, path inside the root | 0.08276 ms | 0.08288 ms | +0.00012 ms | 0.00605 ms | **No** |
| Egress allowlist | `http.get`, allowlisted host | 0.00487 ms | 0.00581 ms | +0.00094 ms | 0.00020 ms | **Yes** |

* **Path confinement: no measurable cost, and the sign flips between repeats**
  (−0.00031, +0.00301, +0.00153, −0.00057, −0.00304 ms). Structurally that is
  expected — the guard consults the store only *after* a path has already fallen
  outside the root, so a call that is authorised by the root never reads it —
  but the figure above is the measurement, and it says the difference is not
  distinguishable from noise on this machine, which is not the same as saying it
  is zero.
* **Egress: a consistent +0.00094 ms**, agreed in sign by all five repeats
  (+0.00083, +0.00098, +0.00096, +0.00103, +0.00088 ms) and about 4.7× its own
  spread. Attaching an in-memory store holding two leases raises the egress
  stage of an authorised `http.get` from 0.00487 ms to 0.00581 ms, a 19%
  increase on that stage and 4.4% of the 0.0213 ms an authorised `http.get`
  costs end to end, both measured at load average 3.8 over 5×2000 paired
  iterations. The guard reads the store on every URL argument, so a call
  carrying a URL pays for the lookup whether or not any lease of the operator's
  applies. **That is a regression for any deployment that attaches a store, and
  it is published as one** rather than folded into the aggregate.

Both figures are for a store holding two leases, in memory. A `FileLeaseStore`
re-reads and re-parses its file on every lookup and will cost more; that is not
measured here, and until it is, no number for it should be quoted. **A
deployment that attaches no lease store pays none of this** — which is the
default, and is what the table above this one measures.

### Budget exhaustion fails closed

With `max_calls=3` and 10 attempts: 3 authorised, then 7 refusals, all
`budget_exhausted`. Same shape for the cost cap. Once refused, every subsequent
call is refused — a cap that let a later call through would be a rate limiter,
not a bound.

## 7. Limitations

Read this section. It is the one that tells you whether this is useful to you.

1. **The allowlist bounds the blast radius; it does not make a dangerous tool
   safe.** If you scope a tool that can delete production data, a steered agent
   can delete production data within its budget. The broker bounds *which* tool
   and *with what arguments* — never what a permitted tool does internally.
2. **The root bounds which file, never what is inside it.** A credential sitting
   in a file inside `fs_root` is in scope by construction: the tool is
   allowlisted, the path resolves inside the root, and the broker returns the
   contents. Ingest strips active content — scripts, event handlers, dangerous
   URI schemes — and tags provenance; it does **not** redact secrets, and a
   reader who watches an API key come back under `"removed": []` is seeing the
   design work as specified rather than fail. Your levers are `fs_root` — the
   narrowest directory the task actually needs, not the repository it happens to
   sit in — and keeping secrets out of that directory. Nothing downstream of a
   read can un-disclose what it returned.
3. **The brokered runner's live path is not exercised.** `agent-boundary[runner]`
   builds a session whose only tools are the broker's, and the offline half of
   that is proven: the surface is derived from the broker's own `tools/list`
   over a real transport, a built-in tool is unrepresentable rather than
   filtered out, and `--dry-run` prints the whole surface without a model. What
   has never run in CI is the model call itself — `run_session` is the only
   uncovered path in the package, because covering it would put a model on the
   gate, which `ADR-0009` forbids. Concretely unverified: this broker names its
   tools `fs.read`, so the runner qualifies them as `mcp__agentboundary__fs.read`,
   and whether a dot survives the runtime's own tool-name matching has not been
   checked against a live session. The failure direction is fail-closed — a tool
   that asks for permission instead of running, never one that runs unbrokered —
   but treat the runner as new until you have run it once yourself.
4. **Composition of in-scope tools is not analysed.** Two individually harmless
   tools — read an internal document, file a public ticket — compose into an
   exfiltration path. That is bounded by attribution and approval, not
   prevented. Detecting it is unsolved here.
5. **Data labelling is mitigation, not proof.** Delimiting and provenance
   tagging reduce the rate at which payloads steer the model. They do not bound
   it, and the design does not depend on them holding — which is why
   authorisation lives in the broker rather than in the labelling.
6. **An allowlisted egress host can be an exfiltration channel** if it accepts
   attacker-readable content. Narrowing the allowlist is your lever.
7. **No defence against a malicious operator**, by design. Whoever configures
   the task, the allowlist, and the approval policy is trusted.
8. **No claim about model alignment.** The design assumes the model is hostile.
9. **A permission lease is a hole you opened on purpose, and while it is open
   the boundary is not there.** An operator can widen a task to one extra path,
   host, or tool for a stated period. **A leased path is an unbounded path for
   the duration** — during the window, the invariant the lease widens does not
   hold for its subject. What bounds it is construction, not policy: a lease
   with no expiry cannot be expressed, and the window is capped per sensitivity
   class at 7 days for `credential`, 14 for `sensitive`, and 30 for `routine` —
   caps we chose so that "forever" cannot be spelled as a large integer, not
   numbers derived from any measurement. Tool leases are asymmetric and it
   matters: they resolve at task construction, so one that expires mid-task
   keeps its handle until the task ends. Nothing grants a lease from the
   refusal ledger — a list an attacker can add to by steering the agent — and
   granting requires the subject to be typed rather than picked from it. See
   [`ADR-0008`](docs/adr/ADR-0008-permission-leases-are-bounded-by-construction.md)
   and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §7, items 15–23.
10. **Both benign-task corpora are synthetic, and neither is independent.** The
   hand-written one I wrote knowing what the controls check, so its 0/25 reads
   as "no benign task I thought of was refused". The generated one removes the
   hand-picking but not the provenance — I wrote the generator too. Both are
   materially weaker than a rate measured against traffic someone else
   generated, and the generated corpus already refuses 8 of its 141 tasks (§6).
11. **Concurrent tasks sharing a budget pool are not supported.**
12. **No third-party security review** at time of writing.

### What would falsify this design

Stated so the claim is testable rather than rhetorical — any of these is a
vulnerability under [`SECURITY.md`](SECURITY.md), not a feature request:

- An effect outside the task's tool scope, without operator misconfiguration.
- A path that resolves outside the configured root after confinement.
- Egress to a host absent from the allowlist.
- A task that exceeds its cap without failing closed.
- An effect that occurred and cannot be attributed from the audit trace.

---

## 8. Getting started

Full guide: [`docs/INSTALL.md`](docs/INSTALL.md).

### See it refuse a real attack

```bash
uv sync --group dev
uv run python examples/support_triage.py
```

An agent triages a support ticket written by an attacker who has no session and
no API key — they filed a ticket, which is the entire capability the threat
model grants them. Everything they wrote is read by the agent; nothing they
wrote reaches an effect:

```
AUTHORISED     legitimate: read the runbook
AUTHORISED     legitimate: read the ticket
REFUSED [path_outside_root]     steered by the ticket: read /etc/passwd
REFUSED [approval_mismatch]     steered by the ticket: publish it
REFUSED [tool_not_in_scope]     out of scope entirely
AUTHORISED     approved comment
```

### Wire it to your agent

Not on PyPI yet — install from the repository:

```bash
uv pip install "agent-boundary[mcp] @ git+https://github.com/impactRssi/agent-boundary@v0.4.0"
python -m agentboundary --task task.json --dry-run
```

The task file is the security configuration: scope, filesystem root, egress
allowlist, caps. `--dry-run` prints what it resolved to and exits. See
[`examples/dropin/`](examples/dropin/) for a worked configuration and the two
file placements that carry security weight.

### Develop on it

```bash
uv sync --group dev --group gui --extra mcp
uv run playwright install chromium
make check
```

`make check` is the whole gate in CI order — format, lint, types, unit,
adversarial, e2e, gui, coverage, SAST, dependency audit, secret scan. All
blocking. `uv sync --group dev` alone is **not** enough: `mypy` type-checks the
MCP adapter and the GUI tier.

## 9. Documentation

| Document | What is in it |
|---|---|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | STRIDE over the agent loop, trust boundaries, attack table, accepted residual risk |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Installing it, using it, and developing on it |
| [`docs/SPEC.md`](docs/SPEC.md) | Normative requirements, each traced to an invariant or an ADR |
| [`docs/WORKING_METHODS.md`](docs/WORKING_METHODS.md) | Graph-based decomposition, branch policy, the three test tiers |
| [`docs/adr/`](docs/adr/) | The load-bearing decisions, each naming what was rejected and why |
| [`ROADMAP.md`](ROADMAP.md) | The work graph: nodes with dependencies, exit conditions, and required test tiers |
| [`CHANGELOG.md`](CHANGELOG.md) | What shipped, what was measured, what is still missing |
| [`SECURITY.md`](SECURITY.md) | Disclosure policy, and what is explicitly *not* a vulnerability here |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | What will get a pull request rejected, and why |
| [`corpus/`](corpus/) | The 36 injection payloads, in the clear |
| [`benchmarks/`](benchmarks/) | The harness, and the caveat on the false-refusal rate |
| [`examples/dropin/`](examples/dropin/) | A worked task file and the placement rules that matter |

---

## 10. License

[Apache-2.0](LICENSE). Chosen over MIT for the patent grant, which matters for
security tooling other organisations will run inside their own pipelines.
