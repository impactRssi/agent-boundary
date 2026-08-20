# Benchmarks

Reproducible and **offline by default**. A benchmark that needs the network is
a benchmark whose numbers cannot be reproduced by a reader, and a number a
reader cannot reproduce is a claim, not a measurement.

Empty until nodes N-23 and N-24.

## What will be published

Each metric is published with the conditions it was measured under, **in the
same sentence**. The caveat is what makes the number credible — "100% blocked
on a hand-curated synthetic corpus of 30 payloads across 7 carrier types" is a
stronger signal than "100% blocked".

| Metric | Node |
|---|---|
| Injection corpus: attempted / blocked, by carrier type | N-17, reported by N-23 |
| False-refusal rate on the benign-task corpus — the control's cost | N-24 |
| Broker overhead per tool call, in milliseconds | N-23 |
| Budget-exhaustion behaviour at the cap, and that it fails closed | N-23 |

## Rules

- No bare percentage. Ever.
- The benign-task corpus is synthetic and is reported as synthetic.
- A metric that regressed is published having regressed. Deleting a number
  because it got worse is the failure mode this file exists to prevent.
