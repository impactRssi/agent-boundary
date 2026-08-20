# Architecture decision records

Short records of the decisions that constrain future work. One decision per
file, numbered, never rewritten — a decision that changes gets a new ADR that
supersedes the old one, and the old one stays in the history with its status
updated.

An ADR is required when a change weakens a structural invariant, introduces a
heavy dependency, or picks between options that a reviewer would reasonably
expect to have been argued.

| ADR | Decision | Status |
|---|---|---|
| [0001](ADR-0001-deterministic-brokering.md) | Deterministic brokering over model self-restraint | Accepted |
| [0002](ADR-0002-per-task-tool-scoping.md) | Per-task tool scoping over a global registry | Accepted |
| [0003](ADR-0003-tool-output-is-data.md) | Tool output is never re-interpreted as instruction | Accepted |
| [0004](ADR-0004-human-approval-for-irreversible-effects.md) | Out-of-band human approval for irreversible effects | Accepted |
