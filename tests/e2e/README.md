# End-to-end tier

Drives a real MCP client against a real broker process over a real transport,
with real tool handlers pointed at throwaway fixtures. **No mocks at the
boundary under test** — an E2E test that mocks the broker is a unit test wearing
a costume.

Selected by the `e2e` marker. Run with `make test-e2e`.

## What "over the wire" means here, precisely

`test_stdio_transport.py` launches `python -m agentboundary` as a **separate OS
process** and speaks MCP to it over stdio pipes using the SDK's own client. The
broker, the handlers, the audit sink, the JSON-RPC framing and the client are
all the shipped ones. Nothing in that path is substituted.

The other modules in this directory exercise `BrokeredServer` in-process. That
is the right shape for the authorisation logic — the class is transport-agnostic
by design — but it is *not* a transport test, and this README used to claim
otherwise for the whole tier. Until node N-30, `src/agentboundary/mcp/stdio.py`
sat at 0% coverage with no test importing it, and had drifted far enough from
the SDK it targets that it would have raised `AttributeError` on an operator's
first call. The claim came before the evidence; the fix was to supply the
evidence, not to soften the claim.

The transport is where a second, weaker authorisation path would appear — the
failure mode where one transport quietly skips a check another performs — so it
is asserted directly:

- an out-of-scope tool is **absent** from `list_tools`, and naming it anyway is
  refused rather than dispatched;
- a refusal crosses as a **tool result** carrying its machine-readable reason,
  not as an exception and not as an empty result;
- an authorised result crosses as an ingested, delimited, provenance-tagged
  envelope;
- the child process writes the audit trace itself, so attribution survives the
  process boundary;
- caps refuse over the wire and **stay** refused.

## Coverage of a child process

coverage.py measures the process it starts in. The subprocess under test is a
child, so `test_stdio_transport.py` arms coverage.py's documented
`COVERAGE_PROCESS_START` hook — only when the parent is itself measuring — and
`[tool.coverage.run] parallel = true` combines the child's data file into the
report. Without it the transport would read as dead code while being fully
exercised, which understates the evidence in exactly the direction this tier
exists to correct.

## Determinism

No network: stdio pipes only. No randomness, no clock assertion. Caps in the
scripted transcripts sit far above what those transcripts consume, so a cap is
never what ends a run unless a test says it should. The one timeout present is a
failsafe against a deadlocked child, generous enough that it cannot fire on a
healthy run, and no assertion depends on it.

## Requires the `mcp` extra

```bash
uv sync --group dev --extra mcp
```

Without it the transport module cannot be imported and this tier's central
evidence is absent. `make test-e2e` passes `--e2e-guard`, so that absence now
fails the build rather than reporting success on the 50 in-process tests that
remain — which is precisely what it did before node N-31.
