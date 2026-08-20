# ADR-0003 — Tool output is never re-interpreted as instruction

- **Status:** Accepted
- **Date:** 2026-08-20
- **Upholds:** I2

## Context

Agent runtimes typically append tool results into the conversation as message
content, structurally indistinguishable from an operator instruction. Once
appended, a ticket body, an HTTP response, or an error string is just more
tokens in the same channel the system prompt occupies.

That is the delivery mechanism for indirect prompt injection. Attackers do not
need to reach the operator's input; they only need to reach any tool result.

## Decision

Every tool result passes through an ingest stage before it re-enters the
context. Ingest:

1. **Normalises** the encoding and unicode form, rejecting or folding forms
   whose only purpose is to evade inspection (bidirectional overrides,
   zero-width joiners, homoglyph confusables in machine-read fields).
2. **Strips active content** — script blocks, embedded HTML event handlers,
   macro payloads, and PDF actions.
3. **Wraps** the result in explicit data delimiters that mark where untrusted
   content begins and ends.
4. **Tags provenance** — which tool returned it, from which source, at which
   time — so a downstream reader can attribute any content in the window.

No code path appends a tool result to the context without going through
ingest. This is enforced by construction: the raw result is not returned to the
loop, only the ingested envelope is.

## Consequences

**Accepted.**

- Any content in the window can be attributed to a source, which is what makes
  an incident reconstructible after the fact.
- The rate at which payloads successfully steer the model drops.
- **The design does not depend on this holding.** Delimiting is a mitigation,
  not a proof. A payload inside a correctly labelled data block may still steer
  the model, and we assume it does. That assumption is exactly why
  authorisation lives in the broker (ADR-0001) rather than in the labelling.
  We claim a reduced rate, and refuse to claim a bound.
- Ingest is lossy. Stripping active content changes documents, and an agent
  summarising a PDF sees a stripped PDF. Where that matters, the provenance tag
  records what was removed.
- Ingest sits on the hot path for every tool result, so its cost is included in
  the published per-call overhead.

**Rejected: trusting the model to distinguish data from instruction when
asked.** It works most of the time, which is the worst property a security
control can have.
