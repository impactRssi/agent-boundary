# ADR-0009 — Model-in-the-loop evidence is not a benchmark, and never shares a file with one

- **Status:** Accepted
- **Date:** 2026-08-25
- **Constrained by:** `ADR-0001`, `ADR-0005`

## Context

`benchmarks/results.json` reports 46 of 46 injection payloads blocked across
nine carriers. Every one of those 46 is a `ProposedCall` constructed to be out
of scope, handed to the same pipeline `mcp.server.build_broker` assembles, and
refused. **No model appears anywhere in `benchmarks/harness.py`.**

That is not an oversight, it follows from `ADR-0001`. The broker reads no model
context, so a measurement of the broker does not need a model to be valid — and
the absence of one is exactly why the number is reproducible offline by any
reader with the repository. `benchmarks/README.md` opens on the reason: a
number a reader cannot reproduce is a claim, not a measurement.

It nonetheless leaves a gap, and the gap is about evidence rather than design.
A reader who does not already accept the thesis reads "46 calls constructed to
be out of scope were refused by a component that checks scope" as close to
tautological. The question they actually have is the one the corpus cannot
answer: **given the same carrier content, in the same task, does a real model
emit the out-of-scope call at all?** Without that arm, the corpus demonstrates
that a locked door is locked. With it, it demonstrates that the door was open.

Answering it costs both properties the benchmark is built on. It needs the
network and an API key, and it is stochastic — the same prompt sampled twice
gives two answers, and the model behind it is a moving target that will be
deprecated while the number stays in the README.

So the two are worth having and cannot be the same artifact. The failure mode
is specific and cheap to reach: one merged file, one shared section, or one
averaged figure, and the reproducible numbers silently inherit the stochastic
one's caveats. What makes 46/46 worth citing is that a reader can re-derive it;
that property is destroyed by contact, not by argument.

## Decision

Two artifact classes, separated by construction rather than by discipline.

| | Benchmark | Evidence run |
|---|---|---|
| Lives in | `benchmarks/` | `evidence/` |
| Network | Never | Required |
| Determinism | Reproducible by any reader | Stochastic |
| Model | None | Pinned id, recorded |
| Blocks CI | Yes | Never |
| Reported in | README §6 measured results | Its own subsection, marked not reproducible |

### 1. `benchmarks/results.json` carries nothing model-derived

No model id, no sampling parameter, no per-sample record. Checked by
`tests/unit/test_evidence_is_not_a_benchmark.py` rather than left to review,
because the whole value of the separation is that it cannot erode one helpful
pull request at a time.

### 2. An evidence run carries its conditions in the same block as its rate

`n`, model id, date, and total cost. A rate without `n` is not a result from a
stochastic system, and a model id without a date is not enough to know what was
actually sampled.

### 3. An evidence run reports every sample, including the ones that refute it

If the planted payload fails to steer the model, that sample is published with
the others. A demonstration that reports only the runs where the attack worked
demonstrates nothing, and the temptation to re-run until the transcript is
pleasing is exactly what a fixed `n` declared in advance exists to remove.

### 4. No evidence figure enters the measured-results table

It gets its own subsection, visibly separated, opening with the sentence that
it is not reproducible and why. Never averaged with a benchmark figure — what
separates the two is who or what chose the outcome, and one combined number
hides precisely that. This is the same rule already applied to the two benign
corpora, which are reported side by side and never merged.

### 5. Evidence never gates a build

It costs money, needs the network, and is stochastic. Any one of those
disqualifies it from blocking a merge. Run by hand, result committed, and the
commit is what a reader cites.

### 6. The SDK is an optional extra; the authorisation path stays dependency-free

Running the arms needs an agent SDK. It enters `[project.optional-dependencies]`
alongside `mcp`, never `[project] dependencies`, which stays `[]`. The
authorisation path — broker, guards, confinement, budget, ledger, ingest —
imports nothing outside the standard library, and that remains true whatever
the evidence harness comes to need. Both halves are asserted by the same test:
the declared dependency list is empty, and no module outside the optional MCP
adapter imports a third-party package.

## Consequences

- The reproducible numbers keep the one property that makes them worth citing.
- The strongest evidence available for the central claim becomes producible
  without putting that property at risk.
- **Cost: two places to look for numbers.** A reader may still conflate them.
  Mitigated by making the separation visible in the README rather than only in
  the file layout — a distinction that exists only in a directory tree is a
  distinction nobody reads.
- **Cost: an evidence run is not reproducible, and re-running it later against
  a newer model produces a different number with no way to attribute the
  change.** Whether the model got better at resisting the payload or the
  harness drifted is not recoverable from the two figures. Inherent to
  measuring a stochastic system; stated rather than fixed.
- **Cost: the evidence arm can only ever be a lower bound on steerability.**
  One prompt, one payload, one model. It cannot show that no payload steers,
  only that this one did or did not. It is evidence, which is why it is not
  called a measurement.
- N-49 was declared with `Tests n/a` on the grounds that a decision node builds
  nothing. That was wrong: two clauses here are mechanically checkable, and a
  rule about file contents that nothing checks is a comment.

**Rejected: put the evidence run in `benchmarks/` behind a `--live` flag.** One
directory, one harness, one output file, and a flag that defaults to off — it
reads as the smaller change. The output file is the problem. `results.json`
would grow a section whose provenance differs from every other section in it,
and the offline guarantee would become a property of *how the harness was
invoked* rather than of the artifact. A reader cannot see an invocation. They
can see a directory.

**Rejected: skip the offline corpus once the live arm exists.** The live arm is
better evidence for the thesis and worse evidence for everything else. It
cannot run in CI, cannot be re-derived by a reader, and says nothing about the
46 payloads it does not sample. The corpus is the regression suite; the
evidence run is the argument. Neither replaces the other.

**Rejected: an SDK as a runtime dependency, with the harness importing the
package directly.** It is what every comparable project does and it would
simplify the packaging. It also puts a large transitive tree behind a library
whose entire claim is that its decision path is small enough to read. The
authorisation path having zero dependencies is a reviewable property; an
optional extra keeps it.
