# Contributing

Agent Boundary is a security control. The contribution rules are stricter than
they would be for an application, because a defect here is not a bug in a
feature — it is a hole in the thing that is supposed to hold.

Read [`docs/WORKING_METHODS.md`](docs/WORKING_METHODS.md) first. It is
normative and this file assumes it.

---

## Before you open a pull request

### Scope

One pull request implements one work node from `ROADMAP.md`. If your change
touches a second concern, split it. "While I was in there" is how invariants
get quietly weakened.

If your change does not correspond to an existing node, open an issue that
proposes the node — its dependencies, its exit condition, and which invariant
it upholds — before writing code.

### Branch

```
feature/<feature-name>
```

Branch from `main`, and only from a node whose dependencies are already merged.

### Local gate

```bash
make check
```

This runs, in order: format check, lint, type check, unit tests with coverage,
the adversarial suite, SAST, dependency audit, and secret scan. It is the same
gate CI runs. If it fails locally it will fail in CI, and CI is blocking.

---

## What will get your pull request rejected

These are not style opinions. Each one has a reason attached.

**Weakening an invariant without an ADR.** The four structural invariants in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) are the product. If your change
makes one of them conditional, configurable, or overridable, it needs an
accepted ADR recording the residual risk and who accepted it. The security
role holds a blocking veto here.

**Treating tool output as instruction.** Anything returned by a tool is
untrusted data. It is sanitised, delimited, and labelled before it re-enters
the context. Code that concatenates a tool result into a prompt without going
through the ingest path will be rejected on sight.

**Filtering at call time instead of scoping at construction time.** A tool that
is out of scope for a task must not exist as a handle the model can name.
Checking an allowlist inside the call handler is the wrong shape: it means the
capability was reachable and we chose not to use it.

**A control that can be turned off by configuration.** Prefer controls that
cannot be disabled by an operator, a config change, or a forgotten flag.
"Structural over procedural" is the standing preference.

**A number without its caveat.** Benchmarks are published with the conditions
they were measured under, in the same sentence. A bare percentage will be sent
back.

**Tests that can pass by collecting nothing.** A suite that silently collects
zero tests, or skips, is a broken control. The adversarial step fails the build
in that case, and any new suite must be wired the same way.

**A new dependency without justification.** Heavy dependencies need an ADR
covering what it does, why the standard library is insufficient, its
maintenance status, and its transitive footprint.

**A secret in the diff.** Every secret is referenced in `.env.example` and
valued nowhere. The secret scan is blocking; do not ask for an exception.

---

## Tests

Three tiers, all blocking. See §5 of the working methods for the full rules.

| Tier | Location | What it proves |
|---|---|---|
| Unit | `tests/unit/` | Each branch of the authorisation path behaves as specified, refusals included |
| Adversarial | `tests/adversarial/` | A concrete attack payload was attempted and the broker refused it |
| E2E / GUI | `tests/e2e/`, `tests/gui/` | The assembled system, and the operator's view of it, behave as documented |

Refusal paths are tested before success paths. The refusal is the feature.

If a node has no interface and therefore no GUI coverage, record that in
`ROADMAP.md` as "GUI: n/a" with the reason. Absence must be a decision on the
record, not an omission.

---

## Commits

Conventional Commits, imperative, English. The body explains *why*; the diff
already covers *what*. Security-relevant commits name the invariant they touch.

```
feat(broker): reject tool calls whose arguments fail schema validation

Validation happens before the call is attributed and before budget is
debited, so a malformed call cannot consume budget. Upholds invariant 3.
```

---

## Reporting a vulnerability

Do not open a public issue. Follow [`SECURITY.md`](SECURITY.md).

---

## Language

All artifacts — code, comments, docstrings, logs, documentation, commit
messages, and pull request descriptions — are written in English.
