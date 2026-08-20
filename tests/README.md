# Tests

Three blocking tiers. See `docs/WORKING_METHODS.md` §5 for the full rules.

| Directory | Tier | Run with |
|---|---|---|
| `unit/` | Deterministic, offline, one module per source module | `make test-unit` |
| `adversarial/` | One payload per attack, asserting the broker **refused** | `make test-adversarial` |
| `e2e/` | The assembled system over a real transport, no mocks at the boundary under test | `make test-e2e` |
| `gui/` | Playwright against the audit-trace viewer in a real browser | `make test-gui` |

## The adversarial tier is not an ordinary suite

It runs as a **separate CI step** with `--adversarial-guard`, which fails the
build if the suite collected zero payloads or skipped one. A suite that can
silently collect nothing reports the same green tick whether it proved
something or nothing.

The guard lives in `tests/conftest.py`, not in `tests/adversarial/`, because a
conftest inside the corpus directory would not load if that directory went
missing — which is the exact case being guarded. Its logic is shipped in
`agentboundary.testing.adversarial_guard` and is itself unit-tested.

The `security` marker is applied **by location**, not by hand. A payload
dropped into `tests/adversarial/` is counted whether or not its author
remembered to decorate it.

## Order of writing

Refusal paths first. The refusal is the product; the success path is the
control's cost.
