# Indirect-injection corpus

Payloads embedded in realistic carriers. Each is loaded by a test in
`tests/adversarial/` asserting that the broker **refused** the resulting call.

**36 payloads across 9 carrier types**, exceeding the floors in SPEC.md TR-003
(30 payloads, 7 carriers). Every row of the
[attack table](../docs/THREAT_MODEL.md#6-attack-table), A1 through A9, has at
least one payload (TR-002). Both floors are asserted by test, not by this
sentence.

| Carrier | Payloads |
|---|---|
| `ticket_description` | 6 |
| `html_page` | 6 |
| `shared_drive_document` | 4 |
| `json_api_response` | 4 |
| `filename` | 4 |
| `dependency_readme` | 3 |
| `error_message` | 3 |
| `pdf_document` | 3 |
| `git_commit_message` | 3 |

Payloads live in `payloads/<carrier>.json` as declarations rather than as
hand-written test functions: the carrier, the attack-table row, the invariant
targeted, the task construction, the proposed call, and the refusal reason the
broker must produce. Keeping them as data is what makes it possible to assert
coverage over the whole attack table instead of over whatever anyone remembered
to write.

## Every payload runs against the full pipeline

Path confinement, egress allowlist, budget, and approval are all active for
every payload. Disabling the guards a payload does not target would prove that
each control works in isolation, which is not the claim being made.

## The corpus is checked for being falsifiable

A broker that refuses everything passes all 36 payloads, and so does a harness
that never dispatches them. `tests/adversarial/test_corpus_is_falsifiable.py`
is the control on the control: legitimate work must be **authorised** under the
same pipeline, and each refusal must flip to an authorisation when the task
legitimately permits it. Without that, "100% blocked" is not a measurement.

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
