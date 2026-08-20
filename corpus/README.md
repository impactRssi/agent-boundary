# Indirect-injection corpus

Payloads embedded in realistic carriers. Each is loaded by a test in
`tests/adversarial/` asserting that the broker **refused** the resulting call.

Empty until node N-17. Target: **30+ payloads across 7+ carrier types** —
ticket description, PDF, HTML page, JSON API response, filename, git commit
message, dependency README (SPEC.md TR-003).

Every row of the [attack table](../docs/THREAT_MODEL.md#6-attack-table), A1
through A9, must have at least one payload here (TR-002).

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
