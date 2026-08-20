# ADR-0006 — The adversarial suite is a separate, guarded, blocking job

- **Status:** Accepted
- **Date:** 2026-08-20
- **Upholds:** the verifiability of I1–I4

## Context

The project's central claim is that a corpus of attacks was attempted and
provably failed. That claim is carried entirely by a CI status.

A test suite has a failure mode that a green tick cannot distinguish from
success: **collecting nothing**. A renamed directory, a mistyped marker, a
`testpaths` edit, a refactor that moves the corpus — and the suite passes
having asserted nothing at all. The same applies to a skip: a payload that
skips is an attack that was not shown to be refused, and the run still reports
success.

Folding the corpus into the general test run makes this worse. The corpus
result gets averaged into a number nobody reads per-tier.

## Decision

Three parts, all required together:

1. **A separate CI job.** The adversarial corpus runs in its own job, so a
   reader can look at a commit and see whether the attacks passed, as a
   distinct answer.
2. **A guard that fails the run on zero-collect or on any skip.** Implemented
   in `agentboundary.testing.adversarial_guard`, wired through
   `tests/conftest.py`, and unit-tested in its own right.
3. **A meta-check that the guard still fails closed.** CI arms the guard
   against a directory containing no payloads and asserts the process exits
   non-zero.

The guard lives in `tests/conftest.py` — an *initial* conftest — and not in
`tests/adversarial/`. A conftest inside the corpus directory is only registered
once pytest collects that directory, so if the directory went missing the guard
would go missing with it. Putting it where it always loads means it runs even
when the corpus does not exist, which is the case it exists to catch.

The `security` marker is applied **by file location**, not by decorator. A
decorator can be forgotten; a directory cannot.

## Consequences

**Accepted.**

- The corpus cannot silently stop being evidence. The three named failure modes
  — zero collection, a skip, and a disabled guard — each fail the build.
- Part 3 exists because parts 1 and 2 are self-referential: a regression in the
  guard would suppress its own alarm. An external assertion is the only thing
  that catches that, and it is cheap.
- Developers running `pytest tests/unit` are not told the corpus is missing:
  the guard is opt-in via `--adversarial-guard`, and CI always passes the flag.
  This is a deliberate hole in local ergonomics' favour, and it is why part 3
  runs in CI rather than relying on habit.
- Quarantining a flaky payload is impossible by design. It must be fixed or
  removed from the corpus explicitly, in a reviewed diff. A payload cannot
  quietly stop asserting.
- `MINIMUM_PAYLOADS` is 1 until node N-17 lands, then rises to the corpus floor
  of 30 (SPEC.md TR-003). Stated here so the current low value reads as a
  scheduled step rather than a weak control.
