# ADR-0002 — Per-task tool scoping over a global registry

- **Status:** Accepted
- **Date:** 2026-08-20
- **Upholds:** I1

## Context

The common pattern is a global tool registry: the agent is given every tool the
deployment supports, and a permission check runs inside each handler when the
tool is invoked.

That shape has two properties we consider defects:

1. **The capability is reachable.** The model holds a handle to a tool it must
   not use. Safety depends on a check firing, and every check is a place a
   check can be missed, mis-scoped, or regressed.
2. **The model knows the tool exists.** Its name and schema are in context, so
   attacker content can name it directly. The attack surface includes every
   tool the *deployment* supports, not every tool the *task* needs.

## Decision

Tool availability is resolved **per task, at construction time**. The task
declares its scope; the broker builds a dispatch table and a tool schema
containing only those tools. Out-of-scope tools are absent from both.

The model is never given a handle it is not permitted to use. There is no
call-time allowlist check, because there is no call to check.

## Consequences

**Accepted.**

- A whole class of bug disappears: a missing or misordered permission check
  cannot expose a tool that was never constructed.
- The prompt-injection surface shrinks to the task's actual scope. Attacker
  content naming an out-of-scope tool produces a name the runtime cannot
  resolve — a refusal, logged, with no effect.
- Tasks must declare scope up front. Agents that discover mid-run that they
  need a tool cannot acquire it; they fail closed and the operator re-scopes.
  We accept the ergonomic cost. Dynamic capability acquisition driven by a
  steered model is the thing we are preventing.
- Task construction becomes security-relevant configuration and is treated as
  such: reviewed, versioned, and logged with each run.

**Rejected: global registry with call-time filtering.** Simpler to wire, and
compatible with more existing runtimes, but it makes the control procedural
rather than structural. "The capability does not exist in this task" is a
stronger sentence than "the check would have caught it".
