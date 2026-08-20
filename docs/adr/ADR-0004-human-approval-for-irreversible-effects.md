# ADR-0004 — Out-of-band human approval for irreversible effects

- **Status:** Accepted
- **Date:** 2026-08-20
- **Upholds:** I3

## Context

Bounding calls by count, cost, and scope limits how *much* damage a steered
agent can do. It does not distinguish a call that can be undone from one that
cannot. Reading a file, deleting a production table, and wiring money all cost
one call.

Budget is the wrong axis for irreversibility. Something else has to carry it.

## Decision

Every tool declares an **irreversibility class** at registration:

| Class | Meaning | Gate |
|---|---|---|
| `read` | No state change | Scope, schema, confinement, budget |
| `reversible` | State change with a defined, tested undo | The above, and the undo is recorded in the audit trace |
| `irreversible` | No undo, or the undo is out of the system's control | The above, **and** an out-of-band human approval |

Approval for an `irreversible` call is requested through a channel the agent
does not participate in. The broker blocks on an approval **record**, not on a
message in the conversation. The model cannot produce, forge, forward, or
satisfy an approval from within the loop, because the approval never enters the
loop — a claim in context that approval was granted is inert, since the broker
does not read context.

Absent or expired approval, the call is refused and the task fails closed.

## Consequences

**Accepted.**

- The forged-approval attack (A9) is not mitigated but structurally
  unavailable: the artifact the broker checks cannot be produced by anything
  inside the blast radius.
- Irreversible effects gain a human decision point, which is where
  accountability actually needs to sit.
- Classification is a manual judgement per tool and can be wrong. A tool
  misclassified as `reversible` loses its gate. Classification is therefore
  reviewed like security configuration, and defaults to `irreversible` when the
  registering author does not state a class — the unsafe default is the one we
  refuse to make convenient.
- Fully unattended operation is impossible for tasks containing irreversible
  effects. That is the intended reading of the control, not a limitation of it.
- Approval fatigue is real. An operator who approves without reading has
  removed the control themselves; that is out of scope (threat model §2) and is
  stated rather than engineered around.

**Rejected: a confirmation turn inside the conversation.** It is the obvious
implementation and it is worthless here — it puts the approval in the channel
the attacker can write into.
