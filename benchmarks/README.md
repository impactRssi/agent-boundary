# Benchmarks

Reproducible and **offline by default**. A benchmark that needs the network is
a benchmark whose numbers cannot be reproduced by a reader, and a number a
reader cannot reproduce is a claim, not a measurement.

```bash
uv run python benchmarks/harness.py
uv run python benchmarks/harness.py --json benchmarks/results.json
```

Latest committed run: [`results.json`](results.json). The measured figures are
reproduced in the [README](../README.md#6-measured-results) with their caveats.

## The caveat on the false-refusal rate — read this one

The measured false-refusal rate is **0/25**, and a zero is exactly the kind of
number that should make a reader suspicious.

**I wrote the benign corpus, and I wrote it knowing what the controls check.**
That is a materially weaker claim than a rate measured against traffic someone
else generated, and weaker again than one measured against production. The
honest reading of 0/25 is "no benign task I thought of was refused", not "the
control has no cost".

The corpus deliberately includes cases near a boundary — a path that dips
through `..` and returns inside the root, an allowlisted host on a non-default
port, a filename containing a `..` substring that is not a traversal, uppercase
hosts, unicode filenames — because a rate measured only on obviously-safe calls
measures nothing. It is still a corpus of my own construction.

Reported here rather than buried: this is the number most likely to move once
someone points the broker at real work.

## Rules

- No bare percentage. Ever.
- The benign-task corpus is synthetic and is reported as synthetic.
- A metric that regressed is published having regressed. Deleting a number
  because it got worse is the failure mode this file exists to prevent.
