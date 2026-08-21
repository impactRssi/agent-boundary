# Agent Boundary

**Your agent has access to your internal tools. Who threat-modelled that?**

Agent Boundary is a deterministic tool-call broker that sits between an LLM
agent and the tools it can reach. It decides which proposed calls become
effects — without consulting a model, and without reading a single token of the
agent's context.

> **Status: `v0.1.0`.** The broker, the ingest path, the MCP server, the
> indirect-injection corpus, the audit-trace viewer, and the benchmark harness
> are implemented and blocking in CI. The numbers in
> [Measured results](#6-measured-results) come from a run you can reproduce
> with one command; read the caveat attached to each one.

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

The agent sits **inside** the untrusted region. That placement is the argument
everything else follows from.

The broker is the load-bearing control: deterministic, model-free, and the only
component that can authorise an effect.

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

The corpus holds **36 payloads across 9 carrier types**, and every attack-table
row A1–A9 has at least one payload. Both floors are asserted by test.

A corpus that only ever refuses proves nothing — a broker that refused
*everything* would score identically. So
[`test_corpus_is_falsifiable.py`](tests/adversarial/test_corpus_is_falsifiable.py)
is the control on the control: legitimate work must be **authorised** under the
same pipeline, and each refusal must flip to an authorisation when the task
legitimately permits it.

---

## 6. Measured results

Reproduce with:

```bash
uv run python benchmarks/harness.py
```

Offline, single process, no network. Full output:
[`benchmarks/results.json`](benchmarks/results.json).

**Conditions for every figure below:** Python 3.13.13 on Darwin/arm64, offline, synthetic corpora, single process, no warm cache.

### Injection corpus: 36/36 blocked

On a hand-written synthetic corpus of 36 payloads across
9 carrier types, matching the current invariant set.
Each payload asserts a **specific** refusal reason, not merely that a refusal
happened — 0 were blocked by a
different control than the one under test.

| Carrier | Attempted | Blocked |
|---|---|---|
| `dependency_readme` | 3 | 3 |
| `error_message` | 3 | 3 |
| `filename` | 4 | 4 |
| `git_commit_message` | 3 | 3 |
| `html_page` | 6 | 6 |
| `json_api_response` | 4 | 4 |
| `pdf_document` | 3 | 3 |
| `shared_drive_document` | 4 | 4 |
| `ticket_description` | 6 | 6 |

Attack-table rows covered: A1, A2, A3, A4, A5, A6, A7, A8, A9.

### False-refusal rate: 0/25 hand-written, 8/141 generated

The control's cost, measured against two **synthetic** corpora, reported side by
side and never averaged — what separates them is who chose the cases, and one
combined figure would hide exactly that.

| Corpus | Tasks | Falsely refused | Who chose the cases |
|---|---|---|---|
| Hand-written | 25 | 0 (0.0%) | The author of the controls, knowing what each guard checks |
| Generated at seed `0xb0157a11` | 141 | 8 (5.7%) | Nobody — derived from the declared schema constraints |

**Read the caveat before the 0/25.** I wrote that corpus knowing what the
controls check, so the honest reading is "no benign task I thought of was
refused" — not "the control has no cost".

The generated corpus exists to remove that one weakness:
[`benchmarks/benign_corpus.py`](benchmarks/benign_corpus.py) derives arguments
mechanically from each tool's declared schema constraints (`type`, `minLength`,
`maxLength`, `minimum`) crossed with a generated filesystem fixture tree, at a
fixed seed, offline. **It found refusals the hand-written corpus missed, and
they are published rather than fixed first:**

| Refusal reason | Cases | What was submitted |
|---|---|---|
| `egress_host_not_allowed` | 6 | A host allowlisted as `docs.internal`, spelled `docs.internal.` — the fully qualified name with its trailing root dot. A real false refusal: same host, request would have succeeded. |
| `path_outside_root` | 2 | A path of exactly 4096 characters, the `maxLength` the catalogue's own schema declares. The OS could not resolve it (`ENAMETOOLONG`) and the guard failed closed, which is correct; the schema declaring a bound the filesystem will not honour is the defect. |

Per tool, out of the tasks generated for it: `fs.read` 1/13, `fs.write` 1/13,
`http.get` 3/46, `http.post` 3/46, `tickets.comment` 0/12, `tickets.get` 0/5,
`tickets.delete` 0/5, `tickets.list` 0/1. The corpus is not evenly distributed —
92 of its 141 tasks are HTTP tools — so the 5.7% is a property of that
distribution, not of any deployment's task mix.

**The caveat is narrowed, not retired.** The generator is code in this
repository, written by the author of the controls; the individual cases are
mechanical but the shapes they are drawn from are authored here. This is not an
independent third-party measurement, and it is not recorded traffic. Full
reading: [`benchmarks/README.md`](benchmarks/README.md).

### Broker overhead: 0.1463 ms mean per call

Over 2000 iterations after a 200-call warm-up:
mean **0.1463 ms**, median 0.1269 ms, p95 0.2922 ms,
p99 0.4287 ms.

Measures authorisation only — scope resolution, schema validation, path
confinement, egress check, budget accounting, approval lookup. **Excludes** the
ingest path and the handler's own work, both of which usually dominate a real
call.

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
2. **Composition of in-scope tools is not analysed.** Two individually harmless
   tools — read an internal document, file a public ticket — compose into an
   exfiltration path. That is bounded by attribution and approval, not
   prevented. Detecting it is unsolved here.
3. **Data labelling is mitigation, not proof.** Delimiting and provenance
   tagging reduce the rate at which payloads steer the model. They do not bound
   it, and the design does not depend on them holding — which is why
   authorisation lives in the broker rather than in the labelling.
4. **An allowlisted egress host can be an exfiltration channel** if it accepts
   attacker-readable content. Narrowing the allowlist is your lever.
5. **No defence against a malicious operator**, by design. Whoever configures
   the task, the allowlist, and the approval policy is trusted.
6. **No claim about model alignment.** The design assumes the model is hostile.
7. **Both benign-task corpora are synthetic, and neither is independent.** The
   hand-written one I wrote knowing what the controls check, so its 0/25 reads
   as "no benign task I thought of was refused". The generated one removes the
   hand-picking but not the provenance — I wrote the generator too. Both are
   materially weaker than a rate measured against traffic someone else
   generated, and the generated corpus already refuses 8 of its 141 tasks (§6).
8. **Concurrent tasks sharing a budget pool are not supported** in v0.1.0.
9. **No third-party security review** at time of writing.

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
uv pip install "agent-boundary[mcp] @ git+https://github.com/impactRssi/agent-boundary@v0.1.0"
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
| [`ROADMAP.md`](ROADMAP.md) | The work graph: 26 nodes with dependencies and exit conditions |
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
