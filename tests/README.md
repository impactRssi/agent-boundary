# Tests

Three blocking tiers. See `docs/WORKING_METHODS.md` §5 for the full rules.

| Directory | Tier | Run with |
|---|---|---|
| `unit/` | Deterministic, offline, one module per source module | `make test-unit` |
| `adversarial/` | One payload per attack, asserting the broker **refused** | `make test-adversarial` |
| `e2e/` | The assembled system over a real transport, no mocks at the boundary under test | `make test-e2e` |
| `gui/` | Playwright against the audit-trace viewer in a real browser | `make test-gui` |

## No tier can pass by collecting nothing

Each tier runs under its own collection guard, which fails the build if the
tier collected fewer items than its floor or skipped one. A suite that can
silently collect nothing reports the same green tick whether it proved
something or nothing.

| Tier | Flag | Floor |
|---|---|---|
| `adversarial/` | `--adversarial-guard` | 30 payloads |
| `e2e/` | `--e2e-guard` | 40 tests |
| `gui/` | `--gui-guard` | 10 tests |

The floors are against catastrophic loss — a moved directory, a broken marker,
a bad `testpaths` edit, an absent optional dependency — not measures of
breadth. Breadth is asserted separately and precisely: SPEC.md TR-002 and
TR-003 for the corpus, and the tier's own tests elsewhere.

The adversarial corpus was guarded from ADR-0006. Node N-31 extended the same
guard to the other two rather than adding a second one: `make test-e2e`
reported success on a tier whose MCP SDK was not installed, which is the same
failure mode one tier over, and two implementations of one control drift apart.

The guard lives in `tests/conftest.py`, not in the tier directories, because a
conftest inside a directory would not load if that directory went missing —
which is the exact case being guarded. Its logic is shipped in
`agentboundary.testing.adversarial_guard` and is itself unit-tested.

`make guards-fail-closed` arms each guard against a tier containing nothing and
asserts the process still exits non-zero. The guards are self-referential — a
regression in one would suppress its own alarm — so the assertion has to come
from outside. It runs in the gate and in CI, and CI invokes the same make
target rather than restating it, because two copies of a control drift.

It covers two ways a tier goes empty. One is the tier disappearing — a moved
directory, a bad `testpaths`, an uninstalled extra. The other is subtler: `-k`,
`-m` and `--deselect` all filter inside `pytest_collection_modifyitems`, where
a conftest's implementation is called *before* them, so counting there counts
what was discovered rather than what will run. The guards count in
`pytest_collection_finish` instead, after every plugin has finished filtering.

Markers are applied **by location**, not by hand: `security` in
`tests/adversarial/`, `e2e` in `tests/e2e/`, `gui` in `tests/gui/`. A file
dropped into a tier directory is counted whether or not its author remembered
to decorate it.

Skips are prohibited on every guarded tier. A flaky test is fixed or removed in
a reviewed diff, never quarantined.

## Order of writing

Refusal paths first. The refusal is the product; the success path is the
control's cost.
