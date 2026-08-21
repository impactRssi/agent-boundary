# Benchmarks

Reproducible and **offline by default**. A benchmark that needs the network is
a benchmark whose numbers cannot be reproduced by a reader, and a number a
reader cannot reproduce is a claim, not a measurement.

```bash
uv run python benchmarks/harness.py
uv run python benchmarks/harness.py --json benchmarks/results.json
uv run python benchmarks/benign_corpus.py --write   # regenerate the benign corpus
```

Latest committed run: [`results.json`](results.json). The measured figures are
reproduced in the [README](../README.md#6-measured-results) with their caveats.

## The false-refusal rate — read this section before the number

The false-refusal rate is the control's cost. It is reported against **two
corpora, side by side and never averaged**, because what separates them is who
chose the cases, and one combined figure would hide exactly that.

| Corpus | Tasks | Falsely refused | Who chose the cases |
|---|---|---|---|
| Hand-written ([`benign/tasks.json`](benign/tasks.json)) | 25 | **0** | The author of the controls, knowing what each guard checks |
| Generated ([`benign/generated.json`](benign/generated.json)) | 141 | **8** | Nobody — derived from the declared schema constraints at seed `0xb0157a11` |

Both figures were measured on Python 3.13.13 on Darwin/arm64, offline, single
process. Both corpora are **synthetic**.

### The hand-written corpus: 0 refusals out of 25 tasks

A zero is exactly the kind of number that should make a reader suspicious.
**I wrote that corpus, and I wrote it knowing what the controls check.** The
honest reading of 0/25 is "no benign task I thought of was refused", not "the
control has no cost". It deliberately includes cases near a boundary — a path
that dips through `..` and returns inside the root, an allowlisted host on a
non-default port, a filename containing a `..` substring that is not a
traversal, uppercase hosts, unicode filenames — because a rate measured only on
obviously-safe calls measures nothing. It is still a corpus of my own
construction.

### The generated corpus: 8 refusals out of 141 tasks (5.7%)

[`benign_corpus.py`](benign_corpus.py) derives arguments from each tool's
declared schema constraints in `agentboundary.testing.catalogue` — `type`,
`minLength`, `maxLength`, `minimum`, `maximum` — crossed with a generated
filesystem fixture tree of 14 directories, 20 files, and 2 internal symlinks.
Nobody picked the individual cases: the combinations, the boundary values, and
the fixture names fall out of the schemas and a fixed seed. The PRNG is a
SplitMix64 written out in the file rather than `random`, so the corpus is
byte-identical on any Python version and any platform, and the E2E tier fails
if the committed artifact drifts from a fresh generation.

**It found refusals the hand-written corpus missed. That is the result.**

| Refusal reason | Cases | What the generator submitted |
|---|---|---|
| `egress_host_not_allowed` | 6 | `https://docs.internal./runbook` — the host allowlisted as `docs.internal`, spelled as a fully qualified name with the trailing root dot |
| `path_outside_root` | 2 | A path of exactly 4096 characters, the `maxLength` the catalogue's own schema declares for `path` |

Per tool, out of the tasks generated for it: `fs.read` 1/13, `fs.write` 1/13,
`http.get` 3/46, `http.post` 3/46, `tickets.comment` 0/12, `tickets.get` 0/5,
`tickets.delete` 0/5, `tickets.list` 0/1.

Reading the two classes honestly, because they do not cost the same:

* **The trailing-dot host is a real false refusal with a real cost.**
  `docs.internal.` and `docs.internal` are the same host; the request would
  have succeeded, and `EgressGuard` compares the allowlist to `urlsplit`'s
  hostname without normalising the root label. 4 of the 6 are DNS names, where
  the trailing dot is the standard fully qualified spelling. The other 2 are a
  trailing dot after the IPv4 literal `10.1.2.3`, where "the same host" is a
  weaker claim — discount those two if you disagree, and the class is 4.
* **The 4096-character path is a refusal whose practical cost is low but
  which is still a defect.** The OS refused to resolve the path
  (`ENAMETOOLONG`, errno 63 on this machine), the guard could not decide, and
  it failed closed — which is the correct behaviour for an undecidable path.
  The read would have failed regardless. What the generated corpus actually
  found here is that the reference catalogue declares `maxLength: 4096` for a
  path bound no filesystem in the test environment will honour. It is counted
  as a refusal rather than argued away, because a corpus that discards its
  unflattering cases is the corpus that produced the 0.

Neither class was fixed before publishing this number, and the generator was
not adjusted after seeing it. Tuning a generator until the rate looks good
reproduces exactly the bias the generated corpus exists to remove.

### What the generated corpus is not

* **Not independent.** The generator is code in this repository, written by the
  author of the controls. The *shapes* it draws from — the path spellings, the
  URL spellings, the free-text pool — are authored here even though the
  individual cases are not. This narrows the corpus caveat; it does not retire
  it, and a corpus written by someone who has never read the guards, or
  recorded from real agent traffic, would still be a stronger measurement.
* **Not evenly distributed.** Enumerating spellings gives a URL-shaped tool 46
  cases and a no-argument tool 1, so 92 of the 141 tasks are `http.get` or
  `http.post`. The aggregate 5.7% is a property of that distribution, not of
  any deployment's task mix. Use the per-tool breakdown.
* **Not complete over the schema language.** The catalogue declares only
  `type`, `properties`, `required`, `minLength`, `maxLength` and `minimum`, so
  the corpus exercises no `enum`, `const`, `pattern`, `maximum`, `items`,
  `minItems`, `maxItems`, or explicit `additionalProperties`. The harness
  publishes that census alongside the rate so an absent keyword does not read
  as a covered one.

## The overhead figure — attributed, and corrected

Published as one mean it says what the broker costs; it does not say which
control charged it, and it cannot locate a regression. The harness now measures
each pipeline stage separately, over four call shapes, because which control
does real work depends on the arguments: a path argument exercises confinement
and leaves the egress check with nothing to do, and the reverse.

Milliseconds per call, 2000 iterations per shape, Python 3.13.13 on Darwin/arm64
(Mac15,6, 12 logical CPUs, load average 9.02 during the run), offline, all four
shapes authorised end to end so every stage runs:

| Stage | `fs.read` | `fs.write` (approved) | `http.get` | `tickets.get` |
|---|---|---|---|---|
| Scope resolution | 0.00013 | 0.00013 | 0.00013 | 0.00013 |
| Schema validation | 0.00317 | 0.00421 | 0.00329 | 0.00324 |
| Path confinement | 0.10154 | 0.11369 | 0.00085 | 0.00090 |
| Egress allowlist | 0.00103 | 0.00114 | 0.00455 | 0.00081 |
| Budget accounting | 0.00552 | 0.00594 | 0.00434 | 0.00453 |
| Approval lookup | 0.00147 | 0.00720 | 0.00112 | 0.00114 |
| Unattributed | 0.01450 | 0.01960 | 0.01290 | 0.01200 |
| **Total** | **0.1273** | **0.1519** | **0.0271** | **0.0227** |

Path confinement is 80% of the cost of authorising an `fs.read`, and that is
the expected shape rather than a defect: confinement resolves the path one
component at a time against the filesystem instead of pattern-matching it,
which is exactly the property I4 rests on. Budget accounting is charged twice
per authorised call — consult, then debit — and both halves are counted here.

Caveats that belong next to those numbers:

* Each guard figure includes one `perf_counter` pair, measured at 0.00009 ms on
  this machine, so each is an upper bound.
* Scope resolution sits at that instrument floor. Its figure means "too cheap
  to measure this way", not "0.00013 ms".
* The unattributed row is guard dispatch, one `Check` record per stage and
  building the `Decision`. It is published rather than folded into a stage
  because it also absorbs the measurement error — a small negative value there
  would mean the attribution had reached the clock's resolution, not that the
  broker is free.
* The total is measured on a *clean* pipeline. Timing wrappers inflate the
  instrumented one, and publishing an instrumented total as the headline would
  overstate what an adopter pays.
* A refused call is cheaper than every figure above, because the pipeline
  short-circuits at the guard that refused.
* Ingest and the handler's own work are excluded, and both usually dominate a
  real call.

**A correction, published rather than quietly fixed.** The loop behind the
previously published overhead figure ran 2200 calls against a 1000-call cap, so
1200 of its 2000 samples were budget-exhausted refusals — the shorter path,
which skips the approval lookup and the ledger debit. It published that mixture
as the per-call cost of authorisation. The overhead loop now runs under caps it
cannot reach, the harness raises if any sample comes back refused, and the E2E
tier asserts the flag that says so.

Run-to-run spread is published with the headline for the same reason: five
repeats of 2000 iterations gave means of 0.1255, 0.1309, 0.1287, 0.1391 and
0.1304 ms. A single mean on a laptop reads as more precise than it is.

## Rules

- No bare percentage. Ever.
- Both benign-task corpora are synthetic and are reported as synthetic every
  time a rate derived from them appears.
- A metric that regressed is published having regressed. Deleting a number
  because it got worse is the failure mode this file exists to prevent.
