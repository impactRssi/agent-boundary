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

## The lease store, and what the harness does with it

Six of the 46 injection payloads declare a permission lease the operator had
already granted when the payload arrived. **They are judged with those leases**,
through `agentboundary.testing.broker_for` — the same pipeline assembly the
adversarial tier and `mcp.server.build_broker` use.

Until the run recorded in the current `results.json`, they were not. The harness
built its own pipeline with **no lease store**, so a payload declaring a lease
was measured without the control it exists to exercise. The block rate was
unaffected, which is why it went unnoticed: a lease can only widen, and every
one of those six is refused either way. That is not a reason to leave it — a
harness that silently drops a control its corpus exercises reports a number
about a system nobody runs.

Rather than assert "a lease can only widen", the harness now measures it. Each
lease-declaring payload is run twice, once with the store its declaration builds
and once with none, and both refusal reasons are recorded in `results.json`
under `injection_corpus.leases.payloads`. In the committed run all six produce
the identical reason both ways, and `outcome_changed_by_a_lease` is empty.

Every lease-declaring payload pins its own instant (`lease_now`), so whether a
lease is live is a property of the corpus and not of the date the harness ran.
Four of the six are live at their instant and two have expired by it; an expired
lease widening nothing is as much of a result as a live one failing to admit a
neighbouring subject.

Everything else the harness measures — both benign corpora, the headline
overhead, the per-stage breakdown, the cap behaviour — runs with **no lease
store attached**, because that is the default deployment. The one place a store
is attached deliberately is the paired A/B measurement below.

## The false-refusal rate — read this section before the number

The false-refusal rate is the control's cost. It is reported against **two
corpora, side by side and never averaged**, because what separates them is who
chose the cases, and one combined figure would hide exactly that.

| Corpus | Tasks | Falsely refused | Who chose the cases |
|---|---|---|---|
| Hand-written ([`benign/tasks.json`](benign/tasks.json)) | 25 | **0** | The author of the controls, knowing what each guard checks |
| Generated ([`benign/generated.json`](benign/generated.json)) | 141 | **2** now, **8** on the first run | Nobody — derived from the declared schema constraints at seed `0xb0157a11` |

Both values of the generated figure are kept: the 8 that found two defects, and
the 2 that remain after both were closed. Deleting the first because the second
is smaller is the failure mode this file exists to prevent.

Both figures were measured on Python 3.13.13 on Darwin/arm64, offline, single
process, with no lease store attached. Both corpora are **synthetic**.

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

### The generated corpus: 2 refusals out of 141 tasks (1.4%)

It was 8/141 (5.7%) on the first run, published at that value before anything
was fixed. Six of those eight were one defect — a host spelled with its
trailing DNS root label — which turned out to also be disarming the loopback
and link-local check. Both values are kept here: the rate that found the
defect and the rate after it was closed.

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
| `path_outside_root` | 2 | A path of exactly 4096 (since corrected to 255) characters, the `maxLength` the catalogue's own schema declares for `path` |

Per tool, out of the tasks generated for it: `fs.read` 1/13, `fs.write` 1/13,
`http.get` 3/46, `http.post` 3/46, `tickets.comment` 0/12, `tickets.get` 0/5,
`tickets.delete` 0/5, `tickets.list` 0/1.

**Where the path-length class went.** The catalogue's `maxLength` for `path` is
now 255, so the corpus regenerates `path=at-the-declared-maxLength` at 255
characters instead of 4096. Both of those tasks — `generated-013` on `fs.read`
and `generated-026` on `fs.write` — are authorised in the current run, and the
2 `path_outside_root` refusals that class produced are gone. The rate did not
move as a result: it was already 2 out of 141 tasks before this re-measurement,
and the 2 that remain are the address-literal class, which has nothing to do
with path length. Per tool in the current run: `http.get` 1/46, `http.post`
1/46, and 0 refused out of the tasks generated for every other tool.

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
  `http.post`. The aggregate 1.4% is a property of that distribution, not of
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
(Mac15,6, Apple M3 Pro, 12 logical CPUs, load average 3.8 during the run),
offline, no lease store attached, all shapes authorised end to end so every
stage runs:

| Stage | `fs.read` | `fs.write` (approved) | `http.get` | `tickets.get` |
|---|---|---|---|---|
| Scope resolution | 0.00010 | 0.00011 | 0.00009 | 0.00010 |
| Schema validation | 0.00237 | 0.00337 | 0.00229 | 0.00240 |
| Path confinement | 0.08431 | 0.09284 | 0.00063 | 0.00061 |
| Egress allowlist | 0.00076 | 0.00085 | 0.00498 | 0.00057 |
| Budget accounting | 0.00401 | 0.00431 | 0.00312 | 0.00302 |
| Approval lookup | 0.00106 | 0.00529 | 0.00078 | 0.00074 |
| Unattributed | 0.01380 | 0.01140 | 0.00940 | 0.00890 |
| **Total** | **0.1065** | **0.1182** | **0.0213** | **0.0163** |

**The previous run of this table is kept in git, not restated here as a
comparison, because it is not one.** It was taken on the same machine at load
average 9.02; this one at 3.8. Every figure moved down and none of it is an
improvement to the broker — nothing on the authorisation path changed between
the two runs. Comparing timing across two runs at different loads is the error
the load average is recorded to prevent.

Path confinement is 79% of the cost of authorising an `fs.read` at load
average 3.8, and that is the expected shape rather than a defect: confinement
resolves the path one component at a time against the filesystem instead of
pattern-matching it, which is exactly the property I4 rests on. Budget
accounting is charged twice per authorised call — consult, then debit — and both
halves are counted here.

### What attaching a lease store costs, paired A/B

Permission leases added a lookup to `PathConfinementGuard` and `EgressGuard`.
Measured as a **paired difference**, alternating the two pipelines inside each
repeat, over 5 repeats of 2000 iterations, at load average 3.8, against an
in-memory store holding two leases:

| Guard | Call shape | Without a store | With a store | Mean delta | Spread of the delta | Larger than its own spread |
|---|---|---|---|---|---|---|
| Path confinement | `fs.read`, path inside the root | 0.08276 | 0.08288 | +0.00012 | 0.00605 | No |
| Egress allowlist | `http.get`, allowlisted host | 0.00487 | 0.00581 | +0.00094 | 0.00020 | Yes |

Paired and alternated because the difference being looked for is smaller than
the drift between two separately-timed runs on a laptop; comparing one leased
figure against one unleased figure would report that drift as the price of a
feature. Every repeat's delta is published, not only their mean: path
confinement's five deltas were −0.00031, +0.00301, +0.00153, −0.00057 and
−0.00304 ms — a sign that flips, which is what noise looks like — while egress's
were +0.00083, +0.00098, +0.00096, +0.00103 and +0.00088 ms.

The asymmetry is structural, not a measurement artefact. The path guard consults
the store only after a path has already fallen outside the root, so a call
authorised by the root never reads it; the egress guard reads the store on every
URL argument, so a call carrying a URL pays for the lookup whether or not any
lease applies. Two figures, therefore, and never one.

A store that is not attached costs nothing, and not attaching one is the
default. A `FileLeaseStore` re-reads and re-parses its file on every lookup and
will cost more than the in-memory store measured here; that is **not yet
measured**, and no number for it should be quoted until it is.

Caveats that belong next to the per-stage table and the lease deltas alike:

* Each guard figure includes one `perf_counter` pair, measured at 0.00007 ms on
  this machine during this run, so each is an upper bound.
* Scope resolution sits at that instrument floor. Its figure means "too cheap
  to measure this way", not "0.00010 ms".
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

Run-to-run spread is published with the headline for the same reason: in the
current run, five repeats of 2000 iterations at load average 3.8 gave means of
0.1063, 0.1064, 0.1041, 0.1027 and 0.1014 ms, a spread of 0.005 ms. A single
mean on a laptop reads as more precise than it is.

## Rules

- No bare percentage. Ever.
- Both benign-task corpora are synthetic and are reported as synthetic every
  time a rate derived from them appears.
- A metric that regressed is published having regressed. Deleting a number
  because it got worse is the failure mode this file exists to prevent.
