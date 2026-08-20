# Agent Boundary

**Your agent has access to your internal tools. Who threat-modelled that?**

Agent Boundary is a deterministic tool-call broker that sits between an LLM
agent and the tools it can reach. It decides which proposed calls become
effects — without consulting a model, and without reading a single token of the
agent's context.

> **Status: pre-release (`v0.1.0.dev0`).** The threat model, specification, work
> graph, and blocking CI gate are in place. The broker itself is being built
> across nodes N-05 to N-13. **No benchmark numbers are published yet, because
> none have been measured.** See [Measured results](#measured-results) and
> [Limitations](#limitations) — both say so explicitly rather than implying
> otherwise.

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
| **I1** | The model cannot reach a tool outside the current task's allowlist. Scoped **at construction time**, not filtered at call time — an out-of-scope tool has no handle the model can name | `agentboundary/broker/registry.py` *(N-06)* | Unit + adversarial |
| **I2** | Tool output is untrusted input: normalised, stripped of active content, delimited, and provenance-tagged before re-entering context. Never treated as instruction | `agentboundary/ingest/` *(N-14, N-15)* | Unit + adversarial |
| **I3** | Every side-effecting call is bounded and attributable. Hard caps on count, cost, and wall clock; irreversible effects require out-of-band human approval | `agentboundary/broker/budget.py`, `approval.py` *(N-12, N-13)* | Unit + adversarial + E2E + GUI |
| **I4** | Filesystem and network access are confined by construction. Paths resolved to an explicit root **before** the check; egress via allowlist | `agentboundary/broker/confinement.py` *(N-10, N-11)* | Unit + adversarial |

Node references in *(italics)* point at [`ROADMAP.md`](ROADMAP.md). Files marked
with a node that has not merged do not exist yet — stated here rather than
implied, so this table can be checked against the tree at any commit.

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

**Current state:** the guard is implemented and blocking. The corpus is node
N-17 and contains one placeholder payload. Target: 30+ payloads across 7+
carrier types.

---

## 6. Measured results

**Nothing has been measured yet.** This section is a contract about what will
be published, not a report.

When the harness lands (N-23, N-24), each of the following is published with
the conditions it was measured under, in the same sentence — the caveat is what
makes the number credible:

| Metric | Status |
|---|---|
| Injection corpus: attempted / blocked, broken down by carrier type | Not yet measured |
| False-refusal rate on a benign task corpus — the control's cost, stated honestly | Not yet measured |
| Broker overhead per tool call, in milliseconds | Not yet measured |
| Budget-exhaustion behaviour at the cap, and that it fails closed | Not yet measured |

A bare percentage will not appear here. Neither will a number whose corpus is
not described.

---

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
7. **The benign-task corpus will be synthetic**, and the false-refusal rate
   will be reported as such. That is a weaker claim than one measured against
   production traffic.
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

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --group dev
make check
```

`make check` runs the same gate CI runs: format, lint, type check, unit tests
with coverage, the adversarial suite under its guard, SAST, dependency audit,
and secret scan. All blocking.

There is no usable API yet. Node N-18 ships the reference MCP server; N-19 the
worked example wiring an agent to a filesystem tool, an HTTP tool, and a
ticketing tool; N-20 the installable package and drop-in runtime config.

---

## 9. Documentation

| Document | What is in it |
|---|---|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | STRIDE over the agent loop, trust boundaries, attack table, accepted residual risk |
| [`docs/SPEC.md`](docs/SPEC.md) | Normative requirements, each traced to an invariant or an ADR |
| [`docs/WORKING_METHODS.md`](docs/WORKING_METHODS.md) | Graph-based decomposition, branch policy, the three test tiers |
| [`docs/adr/`](docs/adr/) | The load-bearing decisions, each naming what was rejected and why |
| [`ROADMAP.md`](ROADMAP.md) | The work graph: 26 nodes with dependencies and exit conditions |
| [`SECURITY.md`](SECURITY.md) | Disclosure policy, and what is explicitly *not* a vulnerability here |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | What will get a pull request rejected, and why |

---

## 10. License

[Apache-2.0](LICENSE). Chosen over MIT for the patent grant, which matters for
security tooling other organisations will run inside their own pipelines.
