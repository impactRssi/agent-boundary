"""Loader for the indirect-injection corpus.

A payload is a declaration, not a script: the carrier it arrives in, the attack
it realises, the invariant it targets, the task it runs against, and the
refusal reason the broker must produce. Keeping payloads as data rather than as
hand-written test functions is what makes it possible to assert coverage over
the whole attack table instead of over whatever anyone remembered to write.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentboundary.approval import ApprovalGuard, ApprovalStore
from agentboundary.broker import Broker
from agentboundary.budget import BudgetGuard, BudgetLedger
from agentboundary.confinement import EgressGuard, PathConfinementGuard
from agentboundary.guards import Guard
from agentboundary.model import Caps, ProposedCall, Task
from agentboundary.registry import ToolRegistry
from agentboundary.testing.catalogue import reference_registry

__all__ = ["Payload", "broker_for", "load_corpus"]


@dataclass(frozen=True, slots=True)
class Payload:
    """One attack, embedded in a realistic carrier."""

    id: str
    attack: str
    carrier: str
    invariant: str
    expected_reason: str
    description: str
    carrier_content: str
    task: Mapping[str, Any]
    proposed_call: Mapping[str, Any]

    @property
    def call(self) -> ProposedCall:
        return ProposedCall(
            tool_name=str(self.proposed_call["tool_name"]),
            arguments=dict(self.proposed_call.get("arguments", {})),
        )

    def build_task(self, fs_root: str | None = None) -> Task:
        caps = self.task.get("caps", {})
        declared_root = self.task.get("fs_root")
        return Task(
            id=self.id,
            tool_scope=frozenset(self.task.get("tool_scope", [])),
            # A payload may pin its own root (to test a task with none at all);
            # otherwise the harness supplies a throwaway directory.
            fs_root=fs_root if declared_root is None else str(declared_root),
            egress_allowlist=frozenset(self.task.get("egress_allowlist", [])),
            caps=Caps(
                max_calls=int(caps.get("max_calls", 10)),
                max_cost=float(caps.get("max_cost", 10.0)),
                max_wall_clock_s=float(caps.get("max_wall_clock_s", 60.0)),
            ),
        )


def load_corpus(directory: Path) -> tuple[Payload, ...]:
    """Load every payload under ``directory``, sorted by id.

    Sorted so a parametrised run is deterministic and its output diffable.
    Raises rather than returning empty: an unreadable corpus must not present
    as a corpus with nothing in it, which is the exact failure the adversarial
    guard exists to catch.
    """
    if not directory.is_dir():
        msg = f"corpus directory {directory} does not exist"
        raise FileNotFoundError(msg)
    payloads = sorted(_read(directory), key=lambda payload: payload.id)
    identifiers = [payload.id for payload in payloads]
    duplicates = sorted({name for name in identifiers if identifiers.count(name) > 1})
    if duplicates:
        msg = f"duplicate payload id(s) in corpus: {', '.join(duplicates)}"
        raise ValueError(msg)
    return tuple(payloads)


def _read(directory: Path) -> Iterator[Payload]:
    for path in sorted(directory.rglob("*.json")):
        entries = json.loads(path.read_text(encoding="utf-8"))
        for entry in entries:
            yield Payload(
                id=entry["id"],
                attack=entry["attack"],
                carrier=entry["carrier"],
                invariant=entry["invariant"],
                expected_reason=entry["expected_reason"],
                description=entry["description"],
                carrier_content=entry["carrier_content"],
                task=entry["task"],
                proposed_call=entry["proposed_call"],
            )


def broker_for(
    payload: Payload,
    fs_root: str | None = None,
    approvals: ApprovalStore | None = None,
    registry: ToolRegistry | None = None,
) -> Broker:
    """Assemble the full guard pipeline for one payload.

    Every payload runs against the complete pipeline, not a subset chosen to
    suit it. A corpus that quietly disables the guards a payload does not
    target would prove that each control works in isolation, which is not the
    claim being made.
    """
    # `is None`, not `or`: ToolRegistry defines __len__, so a deliberately
    # empty registry is falsy and would be replaced by the full reference
    # catalogue -- widening the very scope a payload is testing.
    catalogue = registry if registry is not None else reference_registry()
    task = payload.build_task(fs_root)
    guards: list[Guard] = [
        PathConfinementGuard(),
        EgressGuard(),
        BudgetGuard(BudgetLedger(task.caps)),
        ApprovalGuard(approvals if approvals is not None else ApprovalStore()),
    ]
    return Broker(task, catalogue.scope_for(task), guards)
