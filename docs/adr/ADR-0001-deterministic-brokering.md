# ADR-0001 — Deterministic brokering over model self-restraint

- **Status:** Accepted
- **Date:** 2026-08-20
- **Upholds:** I1, I3

## Context

An agent with tool access needs some mechanism deciding which calls are
permitted. Two families are available.

The first asks the model to restrain itself: system prompts that forbid
certain actions, a second model classifying calls as safe or unsafe,
constitutional rules in context, self-critique before acting.

The second removes the decision from the model entirely and gives it to
deterministic code.

Our adversary can write content the agent reads (see `docs/THREAT_MODEL.md`
§2). Every mechanism in the first family shares one property: it is
implemented *in the same channel the attacker can write into*. A system prompt
is text. A classifier is a model reading attacker-influenced input. A
self-critique step is the steered component grading itself.

## Decision

Authorisation is performed by a deterministic, model-free broker. It reads no
natural language, consults no model, and takes no input from the agent's
context. Its inputs are the task construction (fixed before the loop starts)
and the proposed call. Its output is authorise or refuse, with a reason.

No probabilistic component sits on the authorisation path.

## Consequences

**Accepted.**

- The security claim reduces to a claim about ordinary code, which is
  reviewable, testable, and does not change when the model is swapped.
- The controls hold against a fully steered model, which is what the threat
  model assumes.
- The broker cannot make nuanced judgements. It cannot decide that a call is
  fine "in this context" — it only knows scope, schema, confinement, and
  budget. This produces false refusals, and the false-refusal rate is a
  published cost of the control rather than a defect to hide.
- Expressiveness moves to task construction. Getting a task's scope right
  becomes an operator responsibility, and a bad scope is a bad control. This is
  a deliberate trade: an operator error is visible in configuration, whereas a
  model lapse is visible nowhere.

**Rejected: a model-based safety classifier.** It would handle nuance the
broker cannot, but it fails against the primary adversary — it is a model
reading attacker-influenced text, so it inherits the exact vulnerability the
system exists to contain. It could be added *in addition* as a noise reducer.
It must never be *on* the authorisation path.
