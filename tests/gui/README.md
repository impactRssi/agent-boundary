# GUI tier

Playwright against the audit-trace viewer, in a real browser, asserting on what
an operator can actually see during an incident:

- A refused call reads as refused, with its reason.
- Every effect shows its attribution.
- Budget exhaustion and pending approval are visible as **distinct** states —
  an operator must not have to guess which one stopped the task.
- No interaction mutates a trace. The store is append-only and the interface
  exposes no write path.

Empty until nodes N-21 and N-22. Nodes with no interface record the GUI tier as
`n/a` **with a reason** in `ROADMAP.md`; absence is always a decision on the
record, never an omission.

Selected by the `gui` marker. Run with `make test-gui`.
