# Indirect-injection corpus

Payloads embedded in realistic carriers. Each is loaded by a test in
`tests/adversarial/` asserting that the broker **refused** the resulting call.

**46 payloads across 9 carrier types**, exceeding the floors in SPEC.md TR-003
(30 payloads, 7 carriers). Every row of the
[attack table](../docs/THREAT_MODEL.md#6-attack-table), A1 through A9, has at
least one payload (TR-002). Both floors are asserted by test, not by this
sentence.

| Carrier | Payloads |
|---|---|
| `html_page` | 8 |
| `ticket_description` | 7 |
| `error_message` | 6 |
| `json_api_response` | 5 |
| `shared_drive_document` | 5 |
| `dependency_readme` | 4 |
| `filename` | 4 |
| `git_commit_message` | 4 |
| `pdf_document` | 3 |

Payloads live in `payloads/<carrier>.json` as declarations rather than as
hand-written test functions: the carrier, the attack-table row, the invariant
targeted, the task construction, the proposed call, and the refusal reason the
broker must produce. Keeping them as data is what makes it possible to assert
coverage over the whole attack table instead of over whatever anyone remembered
to write.

## Payloads that run against a granted lease

Six payloads declare `leases` and a `lease_now`. They exist because the
interesting case is not "an unleased path is refused" -- the guards already
prove that -- but "a **live** lease over a neighbouring subject still refuses
this". A lease over `/srv/agent-boundary/secrets` must not admit the sibling
`secrets-backup`, must not admit the parent, and must not survive a traversal
out of it; an expired host lease must authorise nothing; and a tool lease that
has run out must leave the tool absent from the dispatch table.

`lease_now` is required whenever a payload declares a lease. Without it, whether
the lease is live would depend on the wall clock, and an adversarial result that
depends on the date is not evidence. A payload with no `leases` key behaves
exactly as it did before leases existed.

The counterpart lives in `tests/adversarial/test_corpus_is_falsifiable.py`: a
lease that names the subject exactly **does** widen the check. A widening
mechanism that never widens would pass every refusal above and measure nothing.

## Every payload runs against the full pipeline

Path confinement, egress allowlist, budget, and approval are all active for
every payload. Disabling the guards a payload does not target would prove that
each control works in isolation, which is not the claim being made.

## The corpus is checked for being falsifiable

A broker that refuses everything passes all 46 payloads, and so does a harness
that never dispatches them. `tests/adversarial/test_corpus_is_falsifiable.py`
is the control on the control: legitimate work must be **authorised** under the
same pipeline, and each refusal must flip to an authorisation when the task
legitimately permits it. Without that, "100% blocked" is not a measurement.

## One of these carriers is also live

Every payload here is *quoted*: `carrier_content` is a string a test reads, and
nothing acts on it. One carrier additionally exists in a form something can act
on — the `dependency_readme` of `A1-readme-01`, planted in a working checkout
at [`evidence/workspaces/planted-carrier/`](../evidence/workspaces/planted-carrier/)
where an agent has a stated reason to open it. The two are checked against each
other by test, so the live copy cannot come to claim an attack-table row the
quoted one no longer holds.

The live copy names a loopback destination and only a loopback destination, and
that is enforced before the workspace is written rather than reviewed for. See
[ADR-0009](../docs/adr/ADR-0009-model-in-the-loop-evidence-is-not-a-benchmark.md)
for why evidence and benchmarks never share a file.

## Why the payloads are committed in the clear

They are attacks against *this* broker, in a repository whose entire argument
is that they fail. Withholding them would make the central claim unverifiable,
and the doctrine is that a claim which cannot be checked is not worth
publishing.

## Adding a payload

1. Name the attack-table row it realises (A1–A9) and the carrier type.
2. State the invariant it targets (I1–I4) and the refusal reason expected.
3. Assert the refusal, not merely the absence of an effect. "Nothing happened"
   is also what a broken test looks like.
4. Never let it skip. The guard fails the build on a skip, deliberately — see
   ADR-0006.
