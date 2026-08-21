"""Reproducible, offline-by-default measurement harness -- nodes N-23 and N-24.

Rules this file exists to enforce, from `benchmarks/README.md`:

* **Offline.** A benchmark that needs the network produces numbers a reader
  cannot reproduce, and a number a reader cannot reproduce is a claim.
* **No bare percentage.** Every figure is emitted with the conditions it was
  measured under, in the same record. The caveat is what makes the number
  credible.
* **Publish regressions.** Nothing here filters a result for being unflattering.

Run it::

    uv run python benchmarks/harness.py
    uv run python benchmarks/harness.py --json results.json
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from agentboundary.approval import (
    ApprovalGuard,
    ApprovalRecord,
    ApprovalStore,
    argument_digest,
)
from agentboundary.broker import Broker
from agentboundary.budget import BudgetGuard, BudgetLedger
from agentboundary.confinement import EgressGuard, PathConfinementGuard
from agentboundary.guards import Guard
from agentboundary.model import Caps, Irreversibility, ProposedCall, Task
from agentboundary.testing import load_corpus
from agentboundary.testing.catalogue import reference_registry

# Two spellings because this file is run two ways: directly, where Python puts
# `benchmarks/` on sys.path, and loaded by path from the E2E tier, where the
# repository root is on sys.path instead.
try:
    from benign_corpus import (
        CORPUS_FILE,
        Fixture,
        expand_arguments,
        generate_corpus,
        materialise_fixture,
    )
except ModuleNotFoundError:  # pragma: no cover -- depends on how the file was loaded
    from benchmarks.benign_corpus import (
        CORPUS_FILE,
        Fixture,
        expand_arguments,
        generate_corpus,
        materialise_fixture,
    )

ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = ROOT / "corpus" / "payloads"
BENIGN_FILE = ROOT / "benchmarks" / "benign" / "tasks.json"

CAPS = Caps(max_calls=1000, max_cost=10_000.0, max_wall_clock_s=3600.0)


@dataclass
class Conditions:
    """The caveat, carried alongside every number it qualifies."""

    python: str = field(default_factory=platform.python_version)
    machine: str = field(default_factory=platform.machine)
    system: str = field(default_factory=platform.system)
    offline: bool = True

    def describe(self) -> str:
        return (
            f"Python {self.python} on {self.system}/{self.machine}, "
            f"{'offline' if self.offline else 'network-enabled'}, "
            f"synthetic corpora, single process, no warm cache"
        )


def _guards(task: Task, approvals: ApprovalStore) -> list[Guard]:
    return [
        PathConfinementGuard(),
        EgressGuard(),
        BudgetGuard(BudgetLedger(task.caps)),
        ApprovalGuard(approvals),
    ]


def measure_injection_corpus() -> dict[str, Any]:
    """Attempted vs blocked, broken down by carrier. Never a single aggregate."""
    payloads = load_corpus(CORPUS_DIR)
    by_carrier: dict[str, dict[str, int]] = {}
    wrong_reason: list[str] = []

    with TemporaryDirectory(prefix="ab-bench-") as raw_root:
        root = Path(raw_root)
        (root / "workspace").mkdir()
        for payload in payloads:
            task = payload.build_task(str(root / "workspace"))
            broker = Broker(
                task,
                reference_registry().scope_for(task),
                _guards(task, ApprovalStore()),
            )
            decision = broker.authorise(payload.call)
            bucket = by_carrier.setdefault(payload.carrier, {"attempted": 0, "blocked": 0})
            bucket["attempted"] += 1
            if not decision.authorised:
                bucket["blocked"] += 1
                if str(decision.reason) != payload.expected_reason:
                    wrong_reason.append(payload.id)

    attempted = sum(bucket["attempted"] for bucket in by_carrier.values())
    blocked = sum(bucket["blocked"] for bucket in by_carrier.values())
    return {
        "attempted": attempted,
        "blocked": blocked,
        "by_carrier": dict(sorted(by_carrier.items())),
        "attacks_covered": sorted({payload.attack for payload in payloads}),
        # Reported even though it is expected to be empty. A payload blocked
        # for the wrong reason means a different control fired than the one
        # under test, and hiding that would inflate the headline figure.
        "blocked_for_the_wrong_reason": wrong_reason,
    }


def _redact(text: str, workspace: Path) -> str:
    """Strip the temporary root and cap the length.

    Both are reproducibility requirements: a detail carrying a per-run
    temporary directory would make two runs of the harness disagree, and a
    detail quoting a 4096-character path argument would bury the reason it
    exists to convey. The resolved form is stripped first because macOS
    resolves the temporary directory through ``/private``, so the raw and
    resolved spellings both appear in guard details.
    """
    cleaned = text
    for spelling in (str(workspace.resolve()), str(workspace)):
        cleaned = cleaned.replace(spelling, "<fs_root>")
    return cleaned if len(cleaned) <= 300 else cleaned[:300] + " ...(truncated)"


def _evaluate_benign(
    tasks: Sequence[Mapping[str, Any]], workspace: Path, corpus: str
) -> dict[str, Any]:
    """Run one benign corpus through the broker and count what it refused."""
    registry = reference_registry()
    refused: list[dict[str, str]] = []
    by_tool: dict[str, dict[str, int]] = {}
    authorised = 0

    for entry in tasks:
        task = Task(
            id=entry["id"],
            tool_scope=frozenset(entry["tool_scope"]),
            fs_root=str(workspace),
            egress_allowlist=frozenset(entry["egress_allowlist"]),
            caps=CAPS,
        )
        arguments = expand_arguments(entry["arguments"], workspace)
        tool = registry.scope_for(task).get(entry["tool_name"])
        assert tool is not None  # noqa: S101 -- both corpora name catalogue tools

        # Irreversible benign work carries the approval a real operator would
        # have granted. Counting an unapproved irreversible call as a false
        # refusal would measure the operator's absence, not the control's cost.
        approvals = ApprovalStore()
        if tool.irreversibility is Irreversibility.IRREVERSIBLE:
            approvals = ApprovalStore(
                [
                    ApprovalRecord(
                        task_id=task.id,
                        tool_name=tool.name,
                        arg_digest=argument_digest(arguments),
                        granted_by="operator@example.test",
                        expires_at=time.time() + 3600,
                    )
                ]
            )

        broker = Broker(task, registry.scope_for(task), _guards(task, approvals))
        decision = broker.authorise(ProposedCall(entry["tool_name"], arguments))
        bucket = by_tool.setdefault(entry["tool_name"], {"tasks": 0, "refused": 0})
        bucket["tasks"] += 1
        if decision.authorised:
            authorised += 1
        else:
            bucket["refused"] += 1
            refused.append(
                {
                    "id": entry["id"],
                    "label": entry["label"],
                    "reason": str(decision.reason),
                    "detail": _redact(
                        decision.checks[-1].detail if decision.checks else "", workspace
                    ),
                }
            )

    total = len(tasks)
    return {
        "tasks": total,
        "authorised": authorised,
        "falsely_refused": len(refused),
        "false_refusal_rate": round(len(refused) / total, 4) if total else 0.0,
        # Broken down as well as totalled: a single count says the control has
        # a cost, the breakdown says which control is charging it.
        "refused_by_reason": dict(sorted(Counter(item["reason"] for item in refused).items())),
        # Per tool as well, because the corpus is not evenly distributed across
        # tools: enumerating spellings gives a URL-shaped tool far more cases
        # than a no-argument one, and an aggregate rate hides that.
        "by_tool": dict(sorted(by_tool.items())),
        "refusals": refused,
        "corpus": corpus,
    }


def measure_hand_written_false_refusals() -> dict[str, Any]:
    """The control's cost on the corpus its author hand-picked. The weak one."""
    tasks: list[dict[str, Any]] = json.loads(BENIGN_FILE.read_text(encoding="utf-8"))
    with TemporaryDirectory(prefix="ab-benign-") as raw_root:
        workspace = Path(raw_root) / "workspace"
        (workspace / "docs").mkdir(parents=True)
        (workspace / "a/b/c/d/e").mkdir(parents=True)
        for name in ("runbook.md", "release..notes.md", "release notes.md", "réponse-client.md"):
            (workspace / name).write_text("x", encoding="utf-8")
        (workspace / "docs" / "policy.md").write_text("x", encoding="utf-8")
        (workspace / "a/b/c/d/e/deep.md").write_text("x", encoding="utf-8")
        return _evaluate_benign(
            tasks,
            workspace,
            "synthetic, hand-written by the author of the controls, 25 tasks; "
            "several deliberately near a boundary",
        )


def measure_generated_false_refusals() -> dict[str, Any]:
    """The control's cost on a corpus nobody hand-picked (N-37).

    Same measurement, different provenance: every argument is derived from a
    declared schema constraint and a generated fixture tree, so no case was
    chosen by someone who knew what each guard checks. Still not independent --
    the generator is code in this repository.
    """
    corpus = generate_corpus()
    fixture = Fixture.from_json(corpus["fixture"])
    with TemporaryDirectory(prefix="ab-generated-") as raw_root:
        workspace = Path(raw_root) / "workspace"
        materialise_fixture(fixture, workspace)
        result = _evaluate_benign(
            corpus["tasks"],
            workspace,
            f"synthetic, mechanically generated from the tool schemas at seed "
            f"{corpus['seed']:#x}, {len(corpus['tasks'])} tasks; not independent -- "
            f"the generator is code in this repository",
        )
    result["provenance"] = corpus["provenance"]
    result["schema_keywords"] = corpus["schema_keywords"]
    result["artifact"] = str(CORPUS_FILE.relative_to(ROOT))
    result["seed"] = f"{corpus['seed']:#x}"
    return result


def measure_false_refusals() -> dict[str, Any]:
    """Both corpora, side by side, with no combined figure.

    Averaging the two would hide exactly what distinguishes them -- who chose
    the cases -- which is the only reason the second corpus exists.
    """
    return {
        "hand_written": measure_hand_written_false_refusals(),
        "generated": measure_generated_false_refusals(),
    }


def measure_overhead(iterations: int = 2000) -> dict[str, Any]:
    """Per-call broker overhead, in milliseconds, with its distribution."""
    with TemporaryDirectory(prefix="ab-overhead-") as raw_root:
        workspace = Path(raw_root) / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "runbook.md").write_text("x", encoding="utf-8")

        task = Task(
            id="overhead",
            tool_scope=frozenset({"fs.read"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        broker = Broker(task, reference_registry().scope_for(task), _guards(task, ApprovalStore()))
        call = ProposedCall("fs.read", {"path": "runbook.md"})

        for _ in range(200):  # warm the interpreter, not a cache
            broker.authorise(call)

        samples: list[float] = []
        for _ in range(iterations):
            started = time.perf_counter()
            broker.authorise(call)
            samples.append((time.perf_counter() - started) * 1000.0)

    ordered = sorted(samples)
    return {
        "iterations": iterations,
        "mean_ms": round(statistics.fmean(samples), 4),
        "median_ms": round(statistics.median(samples), 4),
        "p95_ms": round(ordered[int(len(ordered) * 0.95)], 4),
        "p99_ms": round(ordered[int(len(ordered) * 0.99)], 4),
        "max_ms": round(ordered[-1], 4),
        "measures": (
            "authorisation only: scope resolution, schema validation, path "
            "confinement, egress check, budget accounting, approval lookup. "
            "Excludes ingest and the handler's own work."
        ),
    }


def measure_cap_behaviour() -> dict[str, Any]:
    """What happens at the cap, and that it fails closed."""
    results: dict[str, Any] = {}
    with TemporaryDirectory(prefix="ab-caps-") as raw_root:
        workspace = Path(raw_root) / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "runbook.md").write_text("x", encoding="utf-8")

        for label, caps in (
            ("call_cap", Caps(max_calls=3, max_cost=1000.0, max_wall_clock_s=3600.0)),
            ("cost_cap", Caps(max_calls=1000, max_cost=3.0, max_wall_clock_s=3600.0)),
        ):
            task = Task(
                id=label,
                tool_scope=frozenset({"fs.read"}),
                fs_root=str(workspace),
                egress_allowlist=frozenset(),
                caps=caps,
            )
            broker = Broker(
                task, reference_registry().scope_for(task), _guards(task, ApprovalStore())
            )
            call = ProposedCall("fs.read", {"path": "runbook.md"})
            outcomes = [broker.authorise(call) for _ in range(10)]
            reasons = Counter(str(d.reason) for d in outcomes if not d.authorised)
            results[label] = {
                "attempts": len(outcomes),
                "authorised_before_cap": sum(1 for d in outcomes if d.authorised),
                "refusal_reasons": dict(reasons),
                # The property that matters: once refused, always refused. A
                # cap that let a later call through would be a rate limiter,
                # not a bound.
                "stayed_closed": all(
                    not d.authorised
                    for d in outcomes[next(i for i, d in enumerate(outcomes) if not d.authorised) :]
                ),
            }
    return results


def run(iterations: int) -> dict[str, Any]:
    conditions = Conditions()
    return {
        "conditions": conditions.describe(),
        "injection_corpus": measure_injection_corpus(),
        "false_refusals": measure_false_refusals(),
        "overhead": measure_overhead(iterations),
        "cap_behaviour": measure_cap_behaviour(),
    }


def _report(results: Mapping[str, Any]) -> str:
    lines: list[str] = []
    add = lines.append
    add("Agent Boundary -- benchmark results")
    add(f"Conditions: {results['conditions']}")
    add("")

    corpus = results["injection_corpus"]
    add(f"Injection corpus: {corpus['blocked']}/{corpus['attempted']} blocked")
    add(f"  attack rows covered: {', '.join(corpus['attacks_covered'])}")
    for carrier, counts in corpus["by_carrier"].items():
        add(f"  {carrier:<24} {counts['blocked']}/{counts['attempted']}")
    if corpus["blocked_for_the_wrong_reason"]:
        add(f"  BLOCKED FOR THE WRONG REASON: {corpus['blocked_for_the_wrong_reason']}")
    add("")

    # Side by side, never combined: the two corpora differ in who chose the
    # cases, and one averaged rate would hide precisely that.
    for provenance, benign in results["false_refusals"].items():
        add(
            f"False-refusal rate ({provenance}): "
            f"{benign['falsely_refused']}/{benign['tasks']} "
            f"({benign['false_refusal_rate'] * 100:.1f}%)"
        )
        add(f"  corpus: {benign['corpus']}")
        for tool, counts in benign["by_tool"].items():
            add(f"    {tool:<18} {counts['refused']}/{counts['tasks']} refused")
        for refusal in benign["refusals"]:
            add(f"  refused: {refusal['id']} ({refusal['label']}) -- {refusal['reason']}")
            add(f"    {refusal['detail']}")
    add("")

    overhead = results["overhead"]
    add(f"Broker overhead per call, {overhead['iterations']} iterations:")
    add(
        f"  mean {overhead['mean_ms']} ms   median {overhead['median_ms']} ms   "
        f"p95 {overhead['p95_ms']} ms   p99 {overhead['p99_ms']} ms"
    )
    add(f"  {overhead['measures']}")
    add("")

    add("Cap behaviour:")
    for label, outcome in results["cap_behaviour"].items():
        add(
            f"  {label}: {outcome['authorised_before_cap']} authorised of "
            f"{outcome['attempts']}, then {outcome['refusal_reasons']}, "
            f"stayed closed: {outcome['stayed_closed']}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent Boundary benchmarks (offline).")
    parser.add_argument("--json", type=Path, help="Also write results as JSON.")
    parser.add_argument("--iterations", type=int, default=2000)
    arguments = parser.parse_args(argv)

    results = run(arguments.iterations)
    print(_report(results))
    if arguments.json:
        arguments.json.write_text(
            json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"\nwrote {arguments.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
