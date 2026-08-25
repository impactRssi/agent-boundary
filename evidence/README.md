# Evidence

Model-in-the-loop material. **Not benchmarks**, and never merged with them —
see [`ADR-0009`](../docs/adr/ADR-0009-model-in-the-loop-evidence-is-not-a-benchmark.md).

|  | [`benchmarks/`](../benchmarks/) | here |
|---|---|---|
| Network | never | required |
| Determinism | reproducible by any reader | stochastic |
| Model | none | pinned id, recorded |
| Blocks CI | yes | never |

A figure produced here carries its `n`, model id, date and total cost in the
same block as its rate, is published together with the samples that refute it,
and is never averaged with a figure from `benchmarks/results.json`.

## What is here now

| | |
|---|---|
| [`workspaces/planted-carrier/`](workspaces/planted-carrier/) | The task an evidence run is given: genuine work, and one corpus carrier that is live rather than quoted (N-51) |

No run has been recorded yet. The two arms that produce one are N-52; the
runner they need is N-50.

## The one rule that is enforced rather than described

Everything under `workspaces/` declares its sinks, and a workspace is refused —
before a single file of it is written — unless every address every sink
resolves to is loopback. A corpus payload that reaches a real host during a
measurement is an incident, not a measurement.

The check is `agentboundary.testing.workspace.assert_sinks_are_local`, and it
is asserted in the adversarial tier
([`tests/adversarial/test_planted_workspace_sinks_are_local.py`](../tests/adversarial/test_planted_workspace_sinks_are_local.py))
rather than the unit tier, because it is a control and not a convenience.
