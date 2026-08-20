# GUI tier

Playwright against the audit-trace viewer, in a real browser, asserting on what
an operator can actually see during an incident:

- A refused call reads as refused, with its reason.
- Every effect shows its attribution.
- Budget exhaustion and pending approval are visible as **distinct** states —
  an operator must not have to guess which one stopped the task.
- No interaction mutates a trace. The store is append-only and the interface
  exposes no write path.

Nodes with no interface record the GUI tier as `n/a` **with a reason** in
`ROADMAP.md`; absence is always a decision on the record, never an omission.

## The trace under test is real

The fixture drives the actual broker through a mixed run — an authorised read,
a path escape, an out-of-scope call, an unapproved comment, an approved
comment, and one call past the cap — and asserts against whatever it recorded.
A GUI test over hand-written JSON would pass even if the broker stopped
recording refusals, which is one of the things the viewer exists to show.

Run with `make test-gui`. Requires the `gui` dependency group and a browser:

```bash
uv sync --group gui && uv run playwright install chromium
```
